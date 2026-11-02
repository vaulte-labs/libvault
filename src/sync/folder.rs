//! Backup folders. A folder holds what any peer holds: logs of ciphertext and public
//! keys. It can store them and cannot read them, so it can be iCloud Drive, Dropbox or a USB drive.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ids::{DeviceId, VaultId};
use crate::record::Body;
use crate::state::{Anchor, Problem};
use crate::store::log;
use crate::store::{self, Logs, MAX_LOG_FILE};
use crate::store::{private_dir, write_private};
use crate::sync::merge::{Compared, compare};
use crate::vault::Vault;
use crate::{Error, Result};

const FOLDER_PREFIX: &str = "vaulty-";
const CONFIG_FILE: &str = "backups.json";
/// Each file being a sane size says nothing about how many there are.
const MAX_FOLDER: u64 = 2 << 30;

/// A folder's backup status, for showing in an interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupInfo {
    pub path: PathBuf,
    pub last_ok_ms: Option<u64>,
    pub problem: Option<String>,
}

/// What verifying a backup found. `current` is false when the copy has fallen behind this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupReport {
    pub devices: usize,
    pub entries: u64,
    pub current: bool,
    pub problems: Vec<String>,
}

/// iCloud Drive's folder on this Mac, when it is in use.
pub fn icloud_drive() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let folder = Path::new(&home).join("Library/Mobile Documents/com~apple~CloudDocs");
    folder.is_dir().then_some(folder)
}

/// A vault's own folder inside a backup location, so one location can hold several vaults.
pub(crate) fn vault_folder(root: &Path, vault: VaultId) -> PathBuf {
    root.join(format!("{FOLDER_PREFIX}{vault}"))
}

/// Reads a log from a folder others may write to, where only a plain file of a sane size counts.
/// A link could point anywhere, and a pipe or a device would hang or flood whoever reads it.
fn read_foreign(path: &Path) -> Option<Vec<u8>> {
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_LOG_FILE {
        return None;
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    Some(bytes)
}

/// Whether nothing in a vault folder's path is a link, as far as the path exists.
fn check_no_links(folder: &Path) -> Result<()> {
    for path in [folder, &folder.join("log")] {
        if fs::symlink_metadata(path).is_ok_and(|metadata| !metadata.is_dir()) {
            return Err(Error::Invalid("the backup folder has been replaced by something that is not a folder"));
        }
    }
    Ok(())
}

/// Reads the logs in a vault folder. Done with no lock held, since a cloud folder can stall.
pub(crate) fn read_logs(folder: &Path) -> Result<Logs> {
    check_no_links(folder)?;
    let mut logs = Logs::new();
    let entries = match fs::read_dir(folder.join("log")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(logs),
        Err(error) => return Err(error.into()),
    };
    let mut found = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if let Some(device) = log::device_from_path(&path) {
            found.push((device, path));
        }
    }
    // Added up first, so that a folder holding too much costs nothing to turn down. One file past
    // what a log can be is passed over below, and must not cost the rest of the folder.
    let sizes = found.iter().filter_map(|(_, path)| fs::symlink_metadata(path).ok()).map(|metadata| metadata.len());
    let total: u64 = sizes.filter(|size| *size <= MAX_LOG_FILE).sum();
    if total > MAX_FOLDER {
        return Err(Error::Invalid("the backup folder holds far more than a vault could"));
    }
    for (device, path) in found {
        if let Some(bytes) = read_foreign(&path) {
            logs.insert(device, bytes);
        }
    }
    Ok(logs)
}

/// Copies this vault's logs into a folder. Writes only copies that extend what is there: a folder
/// holding something newer is fine, and one holding something else keeps it, so one bad log never
/// stops the others from being backed up, unless a removal has `settled` which history counts.
/// Returns an error at the end if a log could not be saved.
pub(crate) fn write_logs(folder: &Path, home: &Path, settled: &BTreeSet<DeviceId>) -> Result<()> {
    check_no_links(folder)?;
    private_dir(&folder.join("log"))?;
    let mut contradicted = false;
    for (device, ours) in store::read_logs(home)? {
        let path = log::path_for(folder, &device);
        // Nothing readable is the same as nothing there: the write replaces it, and a stray tail
        // says nothing about the entries in front of it.
        let theirs = read_foreign(&path).unwrap_or_default();
        match compare(&theirs[..log::parse(&theirs).valid_len], &ours) {
            Compared::Ahead => write_private(&path, &ours)?,
            Compared::Same | Compared::Behind => {}
            Compared::Diverged if settled.contains(&device) => write_private(&path, &ours)?,
            Compared::Diverged => contradicted = true,
        }
    }
    if contradicted { Err(Error::Invalid("the backup holds a log that contradicts this device")) } else { Ok(()) }
}

/// Every vault copy found at `source`: an archive, a vault folder, or a location holding several.
pub(crate) fn read_source(source: &Path) -> Result<Vec<Logs>> {
    if source.is_file() {
        return Ok(vec![store::decode_archive(&fs::read(source)?)?]);
    }
    if source.join("log").is_dir() {
        return Ok(vec![read_logs(source)?]);
    }
    let mut copies = Vec::new();
    let mut unreadable = None;
    for entry in fs::read_dir(source)? {
        let path = entry?.path();
        if path.file_name().is_some_and(|name| name.to_string_lossy().starts_with(FOLDER_PREFIX)) {
            match read_logs(&path) {
                Ok(logs) => copies.push(logs),
                Err(error) => unreadable = Some(error),
            }
        }
    }
    match unreadable {
        Some(error) if copies.is_empty() => Err(error),
        _ => Ok(copies),
    }
}

/// The logs of each vault in a copy. Anyone can drop a file in a folder, so a first entry from some
/// other vault must not stop this one being read.
pub(crate) fn each_vault(logs: Logs) -> Vec<Logs> {
    let starts_a_vault = |device: &DeviceId, bytes: &[u8]| {
        log::parse(bytes).entries.first().is_some_and(|entry| entry.kind == Body::GENESIS && entry.device == *device)
    };
    let starts: Vec<DeviceId> = logs.iter().filter(|(device, bytes)| starts_a_vault(device, bytes)).map(|(device, _)| *device).collect();
    if starts.len() < 2 {
        return vec![logs];
    }
    starts
        .iter()
        .map(|start| {
            logs.iter()
                .filter(|(device, bytes)| *device == start || !starts_a_vault(device, bytes))
                .map(|(device, bytes)| (*device, bytes.clone()))
                .collect()
        })
        .collect()
}

impl Vault {
    fn config_path(&self) -> PathBuf {
        self.home.join("local").join(CONFIG_FILE)
    }

    pub(crate) fn backup_roots(&self) -> Result<Vec<PathBuf>> {
        match fs::read(self.config_path()) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt("the backup list is damaged")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(error) => Err(error.into()),
        }
    }

    fn write_backup_roots(&self, roots: &[PathBuf]) -> Result<()> {
        write_private(&self.config_path(), &serde_json::to_vec(roots).map_err(|_| Error::Corrupt("the backup list could not be saved"))?)
    }

    /// Whether this is the only copy there is, going by what can be reached right now. A folder
    /// that has gone does not count, however recently it was written.
    pub(crate) fn is_last_copy(&self) -> bool {
        let backed_up = self.backup_roots().unwrap_or_default().iter().any(|root| vault_folder(root, self.state.vault).join("log").is_dir());
        self.device_count() < 2 && !backed_up
    }

    /// Adds a backup location. Adding one twice changes nothing.
    pub(crate) fn add_backup(&self, root: &Path) -> Result<()> {
        if !root.is_dir() {
            return Err(Error::Invalid("that folder does not exist"));
        }
        let mut roots = self.backup_roots()?;
        if !roots.iter().any(|existing| existing == root) {
            roots.push(root.to_path_buf());
            self.write_backup_roots(&roots)?;
        }
        Ok(())
    }

    pub(crate) fn remove_backup(&self, root: &Path) -> Result<()> {
        let mut roots = self.backup_roots()?;
        let before = roots.len();
        roots.retain(|existing| existing != root);
        if roots.len() == before {
            return Err(Error::NotFound(format!("backup {}", root.display())));
        }
        self.write_backup_roots(&roots)
    }

    /// Reads a backup back and compares it with this vault, without trusting anything in it.
    pub(crate) fn verify_copy(&self, logs: &Logs) -> Result<BackupReport> {
        let copy = store::replay(logs, &Anchor::Nothing)?;
        let mut problems: Vec<String> = copy.problems.iter().map(|Problem { device, reason, .. }| format!("{device}: {reason}")).collect();
        if copy.genesis != self.state.genesis {
            problems.push("this backup belongs to a different vault".to_owned());
        }
        let current = self.state.heads.iter().all(|(device, head)| copy.heads.get(device).is_some_and(|theirs| theirs.seq >= head.seq));
        let recovery = copy.recovery.id();
        if !copy.wraps.iter().any(|wrap| matches!(&wrap.sealed, crate::record::Sealed::Recovery(id, _) if *id == recovery)) {
            problems.push("this backup has nothing the recovery key can open".to_owned());
        }
        Ok(BackupReport { devices: copy.members.len(), entries: copy.heads.values().map(|head| head.seq + 1).sum(), current, problems })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_holding_more_than_a_vault_could_is_turned_down_unread() {
        let folder = tempfile::tempdir().unwrap();
        fs::create_dir(folder.path().join("log")).unwrap();
        for byte in 0..3u8 {
            let file = fs::File::create(log::path_for(folder.path(), &[byte; 16].into())).unwrap();
            file.set_len(MAX_LOG_FILE).unwrap();
        }
        assert!(matches!(read_logs(folder.path()), Err(Error::Invalid(_))));
    }
}
