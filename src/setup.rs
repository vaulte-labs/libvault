//! Creating a vault. Split in two so the recovery key can be shown and confirmed before anything
//! exists: dropping a `Setup` leaves no trace, and a crash mid-way leaves only a staging folder
//! that the next attempt removes.

use std::fs;
use std::path::Path;
use std::sync::Arc;

use aws_lc_rs::agreement::{self, X25519};
use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroizing;

use crate::binding::{Binding, Recipient};
use crate::crypto::{self, Key};
use crate::device::Device;
use crate::device::software::{Cost, Software};
use crate::ids::{DeviceId, Generation, SpaceId, VaultId};
use crate::record::{Body, DeviceRecord, Sealed};
use crate::recovery::RecoveryDraft;
use crate::state::{epoch_commitment, genesis_digest};
use crate::store::log::{self, Chain, Clock, now_ms};
use crate::store::{private_dir, write_private};
use crate::vault::{self, LOG_KEY_FILE, SYNC_KEY_FILE, Vault, encode_wrapped, label_body, store_device};
use crate::{Error, Result, space};

/// Whether this device has secure hardware to hold its keys.
pub fn has_secure_hardware() -> bool {
    #[cfg(target_os = "macos")]
    return crate::device::enclave::available();
    #[cfg(not(target_os = "macos"))]
    false
}

/// The first space every vault starts with.
pub const FIRST_SPACE: &str = "Personal";

pub(crate) const STAGING_PREFIX: &str = ".lv-setup-";

/// Device material that exists before the device joins a vault.
impl std::fmt::Debug for NewDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NewDevice(..)")
    }
}

pub(crate) struct NewDevice {
    pub record: DeviceRecord,
    pub log_seed: Key,
    pub sync_seed: Zeroizing<[u8; 32]>,
}

pub(crate) fn new_device(device: &dyn Device) -> Result<NewDevice> {
    let failed = |_| Error::Hardware("key generation failed");
    let log_seed = Key::generate();
    let log = Ed25519KeyPair::from_seed_unchecked(log_seed.as_bytes()).map_err(|_| Error::Hardware("key generation failed"))?;
    let sync_seed: Zeroizing<[u8; 32]> = Zeroizing::new(crypto::random());
    let sync_key = agreement::PrivateKey::from_private_key(&X25519, sync_seed.as_ref()).map_err(|_| Error::Hardware("key generation failed"))?;
    let sync = sync_key.compute_public_key().map_err(failed)?;
    let record = DeviceRecord {
        keys: device.public().clone(),
        log: log.public_key().as_ref().try_into().expect("Ed25519 public key is 32 bytes"),
        sync: sync.as_ref().try_into().expect("X25519 public key is 32 bytes"),
    };
    Ok(NewDevice { record, log_seed, sync_seed })
}

/// The steps of creating a vault, shared by every interface: show `recovery_words`, confirm with
/// `confirmation_positions` and `check_word`, then `finish`.
#[derive(Debug)]
pub struct Setup {
    device: Arc<dyn Device>,
    recovery: RecoveryDraft,
}

impl Setup {
    pub(crate) fn new(device: impl Device + 'static) -> Self {
        Self { device: Arc::new(device), recovery: RecoveryDraft::new() }
    }

    /// Uses this device's secure hardware, or reports that it has none.
    pub fn with_hardware() -> Result<Self> {
        #[cfg(target_os = "macos")]
        if crate::device::enclave::available() {
            return Ok(Self::new(crate::device::enclave::Enclave::generate()?));
        }
        Err(Error::NoHardware)
    }

    /// For a device with no secure hardware. Weaker by nature, and reported as such.
    pub fn with_passphrase(passphrase: &str, cost: Cost) -> Result<Self> {
        Ok(Self::new(Software::generate(passphrase, cost)?))
    }

    /// The recovery key to show and confirm before calling `finish`.
    pub fn recovery(&self) -> &RecoveryDraft {
        &self.recovery
    }

    /// Asks the person, then creates the vault in one atomic step. `home` must not hold one.
    pub fn finish(self, home: &Path, device_name: &str) -> Result<()> {
        self.create(home, device_name).map(drop)
    }

    pub(crate) fn create(self, home: &Path, device_name: &str) -> Result<Vault> {
        if vault::exists(home) {
            return Err(Error::VaultExists);
        }
        let parent = home.parent().ok_or(Error::NoVault)?;
        private_dir(parent)?;
        remove_stale_staging(parent);
        let staging = parent.join(format!("{STAGING_PREFIX}{}", log::hex(&crypto::random::<8>())));
        let result = self.build(&staging, device_name).and_then(|()| {
            if home.exists() {
                fs::remove_dir(home).map_err(|_| Error::VaultExists)?;
            }
            fs::rename(&staging, home)?;
            Ok(())
        });
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
        Vault::with_device(home, self.device)
    }

    fn build(&self, home: &Path, device_name: &str) -> Result<()> {
        crate::store::create(home, &crate::store::Logs::new())?;

        let vault = VaultId::random();
        let fresh = new_device(self.device.as_ref())?;
        let id: DeviceId = fresh.record.id();
        let log_key = Ed25519KeyPair::from_seed_unchecked(fresh.log_seed.as_bytes()).map_err(|_| Error::Hardware("key generation failed"))?;
        let epoch_key = Key::generate();

        let recovery = self.recovery.0.new_public(vault)?;
        let epoch = Generation::first(id);
        let first_epoch = epoch_commitment(&vault, epoch, &epoch_key);
        let digest = genesis_digest(&vault, &fresh.record, &recovery, &first_epoch);
        let device_signature = self.device.authorize("create your vault")?.sign(&digest)?;

        let device_wrap =
            crypto::wrap(self.device.public().wrap_to(), &Binding::Epoch { vault, epoch, recipient: Recipient::Device(id) }, &epoch_key)?;
        let recovery_wrap = crypto::wrap(recovery.wrap_to(), &Binding::Epoch { vault, epoch, recipient: Recipient::Recovery }, &epoch_key)?;
        let recovery_id = recovery.id();
        let bodies = [
            Body::Genesis {
                vault,
                recovery,
                device: fresh.record.clone(),
                first_epoch,
                device_signature,
                recovery_signature: self.recovery.0.sign(&digest)?,
            },
            Body::Wrap { epoch, sealed: Sealed::Device(id, device_wrap) },
            Body::Wrap { epoch, sealed: Sealed::Recovery(recovery_id, recovery_wrap) },
            space::body(vault, epoch, &epoch_key, SpaceId::random(), Generation::first(id), FIRST_SPACE, &Key::generate())?,
            label_body(vault, epoch, &epoch_key, id, device_name)?,
        ];

        let mut clock = Clock::default();
        let mut chain = Chain { device: id, seq: 0, prev: [0; 32] };
        let bytes: Vec<u8> = bodies.iter().flat_map(|body| chain.next(clock.tick(now_ms()), body, &log_key).encode()).collect();

        write_device_files(home, self.device.as_ref(), vault, &fresh)?;
        write_private(&log::path_for(home, &id), &bytes)?;
        Ok(())
    }
}

/// Writes what stays on this device and is never synced.
pub(crate) fn write_device_files(home: &Path, device: &dyn Device, vault: VaultId, fresh: &NewDevice) -> Result<()> {
    let local = home.join("local");
    store_device(&local, device)?;
    let log_key = crypto::wrap(device.public().wrap_to(), &Binding::LogKey { vault, device: fresh.record.id() }, &fresh.log_seed)?;
    write_private(&local.join(LOG_KEY_FILE), &encode_wrapped(&log_key))?;
    write_private(&local.join(SYNC_KEY_FILE), fresh.sync_seed.as_ref())
}

/// A staging folder can only be left by a crash, so any that exist are stale.
pub(crate) fn remove_stale_staging(parent: &Path) {
    let Ok(entries) = fs::read_dir(parent) else { return };
    for entry in entries.flatten() {
        if entry.file_name().to_string_lossy().starts_with(STAGING_PREFIX) {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}
