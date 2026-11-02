//! What a vault keeps on disk. Logs travel between this folder, backup folders, peers and archives
//! in one shape: each device's log as raw bytes, one per device.

pub(crate) mod log;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Duration;

use crate::crypto;
use crate::ids::DeviceId;
use crate::state::{Anchor, State};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};
use log::Parsed;

/// Each device's log, as raw bytes. One per device, so two histories of a device never travel
/// together and replay as a fork.
pub(crate) type Logs = BTreeMap<DeviceId, Vec<u8>>;

/// More than any real log, and little enough to read into memory.
pub(crate) const MAX_LOG_FILE: u64 = 1 << 30;
const ARCHIVE_MAGIC: &[u8; 8] = b"VAULTY01";

#[cfg(unix)]
pub(crate) fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().recursive(true).mode(0o700).create(path)?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    Ok(())
}

/// Writes through a temp file and a rename, so a crash leaves the old file or the new one. The
/// temp name is fresh and must not exist, because a backup folder can be written by others: it
/// cannot be a link they planted, and two devices sharing a folder cannot write over each other.
#[cfg(unix)]
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temp = path.with_extension(format!("{}.tmp", log::hex(&crypto::random::<8>())));
    let mut file = fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&temp)?;
    let written = file.write_all(bytes).and_then(|()| file.sync_all()).and_then(|()| fs::rename(&temp, path));
    if written.is_err() {
        let _ = fs::remove_file(&temp);
    }
    Ok(written?)
}

#[cfg(not(unix))]
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

/// How many times the logs here have grown, by a write of this device's or by taking in another's,
/// so a thread can wait for the next time instead of looking.
#[derive(Debug, Default)]
pub(crate) struct Growth {
    count: Mutex<u64>,
    grew: Condvar,
}

impl Growth {
    pub fn count(&self) -> u64 {
        *self.count.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn note(&self) {
        *self.count.lock().unwrap_or_else(PoisonError::into_inner) += 1;
        self.grew.notify_all();
    }

    /// The count once it has moved past `seen`, or after `timeout`, whichever comes first.
    pub fn wait_past(&self, seen: u64, timeout: Duration) -> u64 {
        let count = self.count.lock().unwrap_or_else(PoisonError::into_inner);
        let waited = self.grew.wait_timeout_while(count, timeout, |count| *count == seen);
        *waited.unwrap_or_else(PoisonError::into_inner).0
    }
}

/// Every log in a vault's own folder.
pub(crate) fn read_logs(home: &Path) -> Result<Logs> {
    let mut logs = Logs::new();
    for entry in fs::read_dir(home.join("log"))? {
        let path = entry?.path();
        if let Some(device) = log::device_from_path(&path) {
            logs.insert(device, fs::read(&path)?);
        }
    }
    Ok(logs)
}

pub(crate) fn parse_all(logs: &Logs) -> Vec<(DeviceId, Parsed)> {
    logs.iter().map(|(device, bytes)| (*device, log::parse(bytes))).collect()
}

pub(crate) fn replay(logs: &Logs, anchor: &Anchor) -> Result<State> {
    State::from_logs_as(&parse_all(logs), anchor)
}

/// Lays out a new vault folder holding `logs`, with nothing of this device's own in it yet.
pub(crate) fn create(home: &Path, logs: &Logs) -> Result<()> {
    for folder in ["log", "local", "run"] {
        private_dir(&home.join(folder))?;
    }
    for (device, bytes) in logs {
        write_private(&log::path_for(home, device), bytes)?;
    }
    Ok(())
}

pub(crate) fn encode_archive(logs: &Logs) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(ARCHIVE_MAGIC);
    w.u32(u32::try_from(logs.len()).expect("devices are few"));
    for (device, bytes) in logs {
        w.array(device.as_bytes());
        w.bytes(bytes);
    }
    w.finish()
}

pub(crate) fn decode_archive(bytes: &[u8]) -> Result<Logs> {
    let mut r = Reader::new(bytes);
    if r.array::<8>()? != *ARCHIVE_MAGIC {
        return Err(Error::Invalid("that file is not a Vaulty archive"));
    }
    let mut logs = Logs::new();
    for _ in 0..r.u32()? {
        let device = r.id()?;
        if logs.insert(device, r.bytes()?.to_vec()).is_some() {
            return Err(Error::Invalid("that archive holds two logs for one device"));
        }
    }
    r.finish()?;
    Ok(logs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_waiter_wakes_when_the_logs_grow_and_not_before() {
        let growth = std::sync::Arc::new(Growth::default());
        assert_eq!(growth.wait_past(0, Duration::from_millis(20)), 0, "nothing grew, so it waits it out");
        let noting = std::sync::Arc::clone(&growth);
        let started = std::time::Instant::now();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            noting.note();
        });
        assert_eq!(growth.wait_past(0, Duration::from_secs(10)), 1);
        assert!(started.elapsed() < Duration::from_secs(5), "woken by the growth, not the timeout");
        assert_eq!(growth.wait_past(0, Duration::from_secs(10)), 1, "growth already past what was seen returns at once");
    }

    #[test]
    fn an_archive_round_trips_and_a_foreign_file_is_refused() {
        let logs = Logs::from([(DeviceId::from([1; 16]), vec![1, 2, 3]), (DeviceId::from([2; 16]), vec![4])]);
        assert_eq!(decode_archive(&encode_archive(&logs)).unwrap(), logs);
        assert!(decode_archive(b"not an archive at all").is_err());
    }

    #[test]
    fn an_archive_holds_one_log_per_device() {
        let device = DeviceId::from([1; 16]);
        let mut w = Writer::new();
        w.array(ARCHIVE_MAGIC);
        w.u32(2);
        for byte in [1, 2] {
            w.array(device.as_bytes());
            w.bytes(&[byte]);
        }
        assert!(decode_archive(&w.finish()).is_err(), "two logs for one device would replay as a fork");
    }

    #[test]
    fn a_truncated_archive_is_refused_without_panicking() {
        let bytes = encode_archive(&Logs::from([(DeviceId::from([1; 16]), vec![1, 2, 3])]));
        for length in 0..bytes.len() {
            assert!(decode_archive(&bytes[..length]).is_err());
        }
    }
}
