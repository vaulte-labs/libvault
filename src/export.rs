//! Getting everything out. There is no lock-in: the encrypted archive opens with the recovery key,
//! and the plaintext export is plain JSON.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use serde::Serialize;
use zeroize::Zeroizing;

use crate::ids::{ItemId, SpaceId};
use crate::item::{Meta, Secret};
use crate::store::encode_archive;
use crate::vault::Vault;
use crate::{Error, Result};

#[derive(Serialize)]
struct ExportedItem<'a> {
    space: &'a str,
    #[serde(flatten)]
    meta: &'a Meta,
    secret: &'a Secret,
    /// A removal cut this: the device that wrote it was removed by one that had not heard. It does
    /// not count in the vault, and a person may still want it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    cut: bool,
}

/// Writes a new file only this user can read, and refuses to replace anything.
#[cfg(unix)]
pub(crate) fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::AlreadyExists => Error::Exists(path.display().to_string()),
        _ => Error::Io(error),
    })?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

impl Vault {
    /// Writes an archive of this vault's logs, which only the recovery key can open.
    pub(crate) fn export_archive(&self, path: &Path) -> Result<()> {
        write_new(path, &encode_archive(&self.all_logs()?))
    }

    /// Writes every item in the clear, as JSON. That includes what a removal cut, marked as cut,
    /// so that nothing a device holds is out of its person's reach: what a removed device wrote in
    /// its last hours may be on a device that had heard it, and on none that removed it. A device
    /// that was itself removed goes by everything in its logs.
    pub(crate) fn export_plaintext(&mut self, path: &Path) -> Result<()> {
        let whole = self.logs_with_nothing_cut().ok();
        let counted: BTreeSet<(SpaceId, ItemId)> = self.state.items.keys().copied().collect();
        let mut written = Zeroizing::new(Vec::new());
        let current = whole.map(|whole| std::mem::replace(&mut self.state, whole));
        let collected = self.collect_plaintext(&counted, &mut written);
        if let Some(current) = current {
            self.state = current;
        }
        collected?;
        write_new(path, &written)
    }

    fn collect_plaintext(&self, counted: &BTreeSet<(SpaceId, ItemId)>, json: &mut Vec<u8>) -> Result<()> {
        json.push(b'[');
        let mut first = true;
        for space in self.spaces()? {
            for item in self.items(&space.id)? {
                let Ok(secret) = self.secret(&space.id, &item.id) else { continue };
                if !first {
                    json.push(b',');
                }
                first = false;
                let cut = !counted.contains(&(space.id, item.id));
                serde_json::to_writer(&mut *json, &ExportedItem { space: &space.name, meta: &item.meta, secret: &secret, cut })
                    .map_err(|_| Error::Corrupt("item could not be exported"))?;
            }
        }
        json.push(b']');
        Ok(())
    }
}
