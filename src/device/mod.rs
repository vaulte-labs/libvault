//! Secure hardware behind one small interface, so the vault never sees private keys.

#[cfg(target_os = "macos")]
pub mod enclave;
pub mod server;
pub mod software;

use std::sync::atomic::AtomicBool;

use zeroize::Zeroizing;

use crate::Result;
use crate::crypto::{HybridSignature, P256_PUBLIC_LEN, PublicKeys};

/// A device's long-term keys.
pub trait Device: Send + Sync + std::fmt::Debug {
    fn public(&self) -> &PublicKeys;

    /// Asks the person, naming what they are approving. One approval covers every use
    /// of the returned value, which should be dropped as soon as the work is done.
    fn authorize(&self, reason: &str) -> Result<Box<dyn Authorized + '_>>;

    /// Opens the keys to unlock the vault. Where a person sits, that is a touch like any other. A
    /// server opens them by itself, as its keys sit in a file anyway, and approves nothing else.
    fn authorize_unlock(&self, reason: &str) -> Result<Box<dyn Authorized + '_>> {
        self.authorize(reason)
    }

    /// As `authorize`, but the prompt goes away once `cancelled` is set, as when the person has
    /// already answered on another device. Software keys show no prompt here to take away.
    fn authorize_unless(&self, reason: &str, _cancelled: &AtomicBool) -> Result<Box<dyn Authorized + '_>> {
        self.authorize(reason)
    }

    /// Bytes to keep in `local/`. Never holds a usable private key.
    fn to_stored(&self) -> Vec<u8>;

    /// False when keys live in software, which `vlt status` reports.
    fn is_hardware(&self) -> bool;

    /// False on a server, where nobody is ever at hand to approve anything.
    fn has_person(&self) -> bool {
        true
    }
}

/// A device the person has just approved.
pub trait Authorized {
    /// Returns the P-256 shared secret followed by the ML-KEM shared secret.
    fn agree(&self, ephemeral: &[u8; P256_PUBLIC_LEN], ciphertext: &[u8]) -> Result<Zeroizing<[u8; 64]>>;

    fn sign(&self, message: &[u8]) -> Result<HybridSignature>;
}
