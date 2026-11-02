//! Copies of the vault somewhere else: exports and backups.

use std::path::Path;

use super::{Client, UNEXPECTED, absolute};
use crate::Result;
use crate::protocol::{Request, Response};
use crate::sync::folder::BackupReport;
use crate::view::SyncReport;

impl Client {
    /// Writes an encrypted archive that only the recovery key opens, after a touch.
    pub fn export_archive(&mut self, path: &Path) -> Result<()> {
        self.call(Request::Export { path: absolute(path)?, recovery: None, plaintext: false }).map(drop)
    }

    /// Writes everything in the clear, as JSON only this user can read, after a touch. With two
    /// or more devices this needs the recovery key too.
    pub fn export_plaintext(&mut self, path: &Path, recovery_words: Option<&str>) -> Result<()> {
        self.call(Request::Export { path: absolute(path)?, recovery: recovery_words.map(str::to_owned), plaintext: true }).map(drop)
    }

    /// Keeps an encrypted copy of the vault in `folder`, such as iCloud Drive or a USB drive.
    pub fn add_backup(&mut self, folder: &Path) -> Result<()> {
        self.call(Request::BackupAdd { path: absolute(folder)? }).map(drop)
    }

    pub fn remove_backup(&mut self, folder: &Path) -> Result<()> {
        self.call(Request::BackupRemove { path: absolute(folder)? }).map(drop)
    }

    /// Reads a backup back and compares it with this vault.
    pub fn verify_backup(&mut self, folder: &Path) -> Result<BackupReport> {
        match self.call(Request::BackupVerify { path: absolute(folder)? })? {
            Response::Verified(report) => Ok(report),
            _ => Err(UNEXPECTED),
        }
    }

    /// Exchanges logs with every backup folder and known device now, and says how that went.
    pub fn sync_now(&mut self) -> Result<SyncReport> {
        match self.call(Request::SyncNow)? {
            Response::Synced(report) => Ok(report),
            _ => Err(UNEXPECTED),
        }
    }
}
