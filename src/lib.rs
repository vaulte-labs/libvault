//! A local secrets vault whose keys are bound to the device's secure hardware.
//!
//! Interfaces use [`Client`], which talks to the broker that holds the keys and enforces the
//! policy, plus [`Setup`] to create a vault and [`run`](run::run) to launch programs. Nothing
//! else can reach a secret, so no interface can skip an approval.

// An interface without the `broker` feature keeps `Setup` and `Client`, and the vault code only
// the broker runs goes unused.
#![cfg_attr(not(feature = "broker"), allow(dead_code, unused_imports))]

#[cfg(all(feature = "test-hooks", not(debug_assertions)))]
compile_error!("test-hooks stands in for a person, so it can never be part of a release build");
#[cfg(all(feature = "fuzz", not(fuzzing), not(debug_assertions)))]
compile_error!("fuzz exposes internals, so it can never be part of a release build");

mod audit;
mod binding;
#[cfg(feature = "broker")]
pub mod broker;
mod client;
mod crypto;
mod device;
mod devices;
mod digest;
mod env_file;
mod error;
mod expiry;
mod export;
pub mod fill;
#[cfg(feature = "fuzz")]
pub mod fuzzing;
pub mod generate;
#[cfg(feature = "broker")]
mod icon;
mod icon_image;
mod ids;
mod import;
pub mod item;
mod items;
mod known;
mod links;
mod listing;
mod locking;
mod net;
#[cfg(feature = "broker")]
mod passkey;
mod profile;
mod project;
mod protocol;
mod record;
mod recover;
mod recovery;
mod rescue;
mod roster;
pub mod run;
mod scrub;
mod setup;
mod space;
mod state;
mod store;
mod sync;
mod sys;
#[cfg(test)]
mod tests;
mod totp;
mod unlock;
mod vault;
mod view;
mod wire;

pub use audit::Event;
pub use client::{AskPassphrase, Client, Connect, MAX_GRANT};
pub use device::software::Cost;
pub use error::{Error, ErrorCode, Result};
pub use icon_image::Icon;
pub use import::{ImportFile, Imported};
pub use locking::{LockSettings, StayUnlocked};
pub use net::pair::{Join, PendingJoin};
pub use net::relay;
pub use project::{EnvFileInfo, Linked, device_name, find_env_files, link_folder, linked_space};
pub use protocol::RelayIssuer;
pub use protocol::{AutofillIdentity, CurrentCode, FillOption, Filled, LoginInto, SignUpWith};
pub use protocol::{NewPasskey, PasskeyAssertion, PasskeyOption, PasskeyRequest, SpaceCode};
pub use recover::{History, Recovery};
pub use recovery::{RecoveryDraft, is_recovery_word};
pub use run::RunOptions;
pub use setup::{FIRST_SPACE, Setup, has_secure_hardware};
pub use sync::folder::{BackupInfo, BackupReport, icloud_drive};
pub use totp::Totp;
pub use vault::{DeviceInfo, default_home, exists, needs_passphrase};
pub use view::{ContactInfo, GrantInfo, Granted, HistoryInfo, ItemInfo, StatusInfo, SyncReport};

pub(crate) use known::known_hosts;
pub(crate) use vault::Vault;
