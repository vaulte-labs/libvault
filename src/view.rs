//! What interfaces are shown. Each of these holds nothing secret.

use serde::{Deserialize, Serialize};

use crate::item::Meta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemInfo {
    pub space: String,
    #[serde(flatten)]
    pub meta: Meta,
    /// The other spaces this same item is in, when the caller may know of them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_in: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantInfo {
    pub id: String,
    pub agent: String,
    pub space: String,
    pub seconds_left: u64,
}

/// When another device was last heard from. A device that has gone quiet may simply be off, or
/// someone may be keeping it from this one, so that it never hears of a removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactInfo {
    /// Its name while the vault is unlocked, and its id while it is not.
    pub device: String,
    /// Since this broker started.
    pub last_ok_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools, reason = "each answers its own question an interface shows")]
pub struct StatusInfo {
    pub unlocked: bool,
    pub hardware: bool,
    pub device_count: usize,
    /// The port other devices reach this one on. None while it is the only device.
    pub sync_port: Option<u16>,
    pub backups: Vec<crate::BackupInfo>,
    pub contacts: Vec<ContactInfo>,
    /// Nothing else holds this vault: no other device, and no backup that can be reached now.
    pub last_copy: bool,
    pub problems: Vec<String>,
    /// Whether this connection is one of the vault's own apps, signed and unchanged, so everyday use
    /// needs no touch while the vault is open.
    #[serde(default)]
    pub trusted: bool,
    /// Which code the broker is, so one left over from an upgrade can be replaced, and after a
    /// `+` the team that signed it, as `1.0.0-164b9dc4c14d67bc+TEAM`.
    pub build: String,
    /// A new value whenever the vault changes, from any caller or another device, so an interface
    /// showing items knows to read them again. Only whether it changed means anything.
    #[serde(default)]
    pub revision: u64,
}

/// What a sync actually did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncReport {
    pub peers_reached: usize,
    pub peers_missed: usize,
    pub backup_problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryInfo {
    pub at_ms: u64,
    pub deleted: bool,
}
