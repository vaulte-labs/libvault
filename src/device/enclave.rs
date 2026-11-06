//! macOS Secure Enclave, through the Swift bridge in `enclave/Enclave.swift`.
//!
//! The stored blobs are handles, not secrets: only this Mac's enclave can use them, and
//! every key is created gated on user presence, so a blob alone gives an attacker nothing.
#![allow(unsafe_code)]

use std::ffi::{CString, c_void};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use zeroize::Zeroizing;

use super::{Authorized, Device};
use crate::crypto::{HybridSignature, MLDSA_PUBLIC_LEN, MLDSA_SIGNATURE_LEN, MLKEM_PUBLIC_LEN, P256_PUBLIC_LEN, P256_SIGNATURE_LEN, PublicKeys};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

const OK: i32 = 0;
const UNAVAILABLE: i32 = 1;
const CANCELLED: i32 = 2;
const TIMED_OUT: i32 = 4;

unsafe extern "C" {
    #[cfg(target_os = "macos")]
    fn lv_peer_is_app(token: *const u8, length: usize, identifiers: *const std::ffi::c_char) -> bool;
    #[cfg(target_os = "macos")]
    fn lv_own_team(out: *mut u8, capacity: usize) -> usize;
    #[cfg(target_os = "macos")]
    fn lv_group_container(group: *const std::ffi::c_char, out: *mut u8, capacity: usize) -> usize;
    fn lv_enclave_available() -> bool;
    #[cfg(target_os = "macos")]
    fn lv_screen_locked() -> bool;
    fn lv_enclave_generate(out: *mut u8, capacity: usize, written: *mut usize) -> i32;
    fn lv_enclave_authenticate(
        reason: *const std::ffi::c_char,
        timeout_seconds: f64,
        stop: extern "C" fn(*const c_void) -> bool,
        flag: *const c_void,
        status: *mut i32,
    ) -> *mut c_void;
    fn lv_enclave_release(context: *mut c_void);
    fn lv_enclave_agree(
        context: *mut c_void,
        agreement_blob: *const u8,
        agreement_blob_len: usize,
        kem_blob: *const u8,
        kem_blob_len: usize,
        ephemeral: *const u8,
        ephemeral_len: usize,
        ciphertext: *const u8,
        ciphertext_len: usize,
        out: *mut u8,
    ) -> i32;
    fn lv_enclave_sign(
        context: *mut c_void,
        signing_blob: *const u8,
        signing_blob_len: usize,
        dsa_blob: *const u8,
        dsa_blob_len: usize,
        message: *const u8,
        message_len: usize,
        out: *mut u8,
    ) -> i32;
}

/// How long a person gets to answer a touch prompt.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

/// How the bridge reads a cancellation flag, so it is read as the atomic it is.
extern "C" fn is_set(flag: *const c_void) -> bool {
    // SAFETY: `flag` is the `AtomicBool` that `authorize_unless` passed, alive for the whole call.
    unsafe { &*flag.cast::<AtomicBool>() }.load(Ordering::Acquire)
}

fn check(status: i32) -> Result<()> {
    match status {
        OK => Ok(()),
        UNAVAILABLE => Err(Error::NoHardware),
        CANCELLED => Err(Error::Cancelled),
        TIMED_OUT => Err(Error::TimedOut),
        // Keys are only usable while the Mac is unlocked, and the bridge cannot tell this apart.
        _ if screen_locked() => Err(Error::Hardware("this Mac is locked. Unlock it and try again")),
        _ => Err(Error::Hardware("the Secure Enclave refused the operation")),
    }
}

/// True on a Mac or iPhone with a Secure Enclave.
pub fn available() -> bool {
    // SAFETY: takes no arguments and has no preconditions.
    unsafe { lv_enclave_available() }
}

#[cfg(target_os = "macos")]
/// Whether the process behind `token` is signed as one of `identifiers` by the team that signed
/// this one, and is unchanged since.
pub fn peer_is_app(token: &[u8; 32], identifiers: &std::ffi::CStr) -> bool {
    // SAFETY: both pointers are valid for the call, and `identifiers` ends in a NUL.
    unsafe { lv_peer_is_app(token.as_ptr(), token.len(), identifiers.as_ptr()) }
}

#[cfg(target_os = "macos")]
/// The team that signed this process, if any.
pub fn own_team() -> Option<String> {
    let mut team = [0u8; 64];
    // SAFETY: `team` is valid for `capacity` bytes, and the bridge writes no more than that.
    let length = unsafe { lv_own_team(team.as_mut_ptr(), team.len()) };
    String::from_utf8(team.get(..length)?.to_vec()).ok().filter(|team| !team.is_empty())
}

#[cfg(target_os = "macos")]
/// The app group's container for `group`, created the way the system expects, when this process
/// is entitled to it.
pub fn group_container(group: &str) -> Option<std::path::PathBuf> {
    let group = CString::new(group).ok()?;
    let mut path = [0u8; 1024];
    // SAFETY: `group` ends in a NUL, and `path` is valid for `capacity` bytes, which is all the
    // bridge writes.
    let length = unsafe { lv_group_container(group.as_ptr(), path.as_mut_ptr(), path.len()) };
    let path = String::from_utf8(path.get(..length)?.to_vec()).ok().filter(|path| !path.is_empty())?;
    Some(path.into())
}

/// True while the login screen is up, or when no GUI session exists. An iPhone app runs only while
/// its phone is unlocked.
pub fn screen_locked() -> bool {
    // SAFETY: takes no arguments and has no preconditions.
    #[cfg(target_os = "macos")]
    return unsafe { lv_screen_locked() };
    #[cfg(not(target_os = "macos"))]
    false
}

#[derive(Debug)]
pub struct Enclave {
    agreement: Vec<u8>,
    kem: Vec<u8>,
    signing: Vec<u8>,
    dsa: Vec<u8>,
    public: PublicKeys,
}

impl Enclave {
    pub fn generate() -> Result<Self> {
        let mut out = vec![0u8; 16 * 1024];
        let mut written = 0usize;
        // SAFETY: `out` is valid for `out.len()` bytes and `written` is a valid pointer.
        check(unsafe { lv_enclave_generate(out.as_mut_ptr(), out.len(), &raw mut written) })?;
        let mut reader = Reader::new(&out[..written]);
        let mut field = || -> Result<Vec<u8>> {
            let len = reader.u32()? as usize;
            reader.take(len).map(<[u8]>::to_vec)
        };
        let (agreement, agreement_public) = (field()?, field()?);
        let (kem, kem_public) = (field()?, field()?);
        let (signing, signing_public) = (field()?, field()?);
        let (dsa, dsa_public) = (field()?, field()?);
        Self::from_parts(agreement, agreement_public, kem, kem_public, signing, signing_public, dsa, dsa_public)
    }

    pub fn from_stored(stored: &[u8]) -> Result<Self> {
        let mut r = Reader::new(stored);
        let mut field = || r.bytes().map(<[u8]>::to_vec);
        let (agreement, agreement_public) = (field()?, field()?);
        let (kem, kem_public) = (field()?, field()?);
        let (signing, signing_public) = (field()?, field()?);
        let (dsa, dsa_public) = (field()?, field()?);
        Self::from_parts(agreement, agreement_public, kem, kem_public, signing, signing_public, dsa, dsa_public)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        agreement: Vec<u8>,
        agreement_public: Vec<u8>,
        kem: Vec<u8>,
        kem_public: Vec<u8>,
        signing: Vec<u8>,
        signing_public: Vec<u8>,
        dsa: Vec<u8>,
        dsa_public: Vec<u8>,
    ) -> Result<Self> {
        let bad = |_| Error::Hardware("unexpected public key from the Secure Enclave");
        let agreement_public: [u8; P256_PUBLIC_LEN] = agreement_public.try_into().map_err(bad)?;
        let signing_public: [u8; P256_PUBLIC_LEN] = signing_public.try_into().map_err(bad)?;
        if kem_public.len() != MLKEM_PUBLIC_LEN || dsa_public.len() != MLDSA_PUBLIC_LEN {
            return Err(Error::Hardware("unexpected public key from the Secure Enclave"));
        }
        let public = PublicKeys { agreement: agreement_public, kem: kem_public, signing: signing_public, dsa: dsa_public };
        Ok(Self { agreement, kem, signing, dsa, public })
    }
}

impl Device for Enclave {
    fn public(&self) -> &PublicKeys {
        &self.public
    }

    fn authorize(&self, reason: &str) -> Result<Box<dyn Authorized + '_>> {
        self.authorize_unless(reason, &AtomicBool::new(false))
    }

    fn authorize_unless(&self, reason: &str, cancelled: &AtomicBool) -> Result<Box<dyn Authorized + '_>> {
        let reason = CString::new(reason.replace('\0', " ")).map_err(|_| Error::Hardware("invalid prompt"))?;
        let mut status = 0;
        let flag = std::ptr::from_ref(cancelled).cast::<c_void>();
        // SAFETY: `reason` is NUL-terminated, and it and `cancelled` outlive the call, which blocks
        // until answered. The bridge reads the flag only through `is_set`.
        let context = unsafe { lv_enclave_authenticate(reason.as_ptr(), APPROVAL_TIMEOUT.as_secs_f64(), is_set, flag, &raw mut status) };
        check(status)?;
        let context = NonNull::new(context).ok_or(Error::Hardware("no authentication context"))?;
        Ok(Box::new(Approved { enclave: self, context }))
    }

    fn to_stored(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(&self.agreement);
        w.bytes(&self.public.agreement);
        w.bytes(&self.kem);
        w.bytes(&self.public.kem);
        w.bytes(&self.signing);
        w.bytes(&self.public.signing);
        w.bytes(&self.dsa);
        w.bytes(&self.public.dsa);
        w.finish()
    }

    fn is_hardware(&self) -> bool {
        true
    }
}

struct Approved<'a> {
    enclave: &'a Enclave,
    context: NonNull<c_void>,
}

impl Drop for Approved<'_> {
    fn drop(&mut self) {
        // SAFETY: `context` came from `lv_enclave_authenticate` and is released only here.
        unsafe { lv_enclave_release(self.context.as_ptr()) }
    }
}

impl Authorized for Approved<'_> {
    fn agree(&self, ephemeral: &[u8; P256_PUBLIC_LEN], ciphertext: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
        let mut out = Zeroizing::new([0u8; 64]);
        let e = self.enclave;
        // SAFETY: every pointer is valid for its paired length and `out` holds 64 bytes.
        check(unsafe {
            lv_enclave_agree(
                self.context.as_ptr(),
                e.agreement.as_ptr(),
                e.agreement.len(),
                e.kem.as_ptr(),
                e.kem.len(),
                ephemeral.as_ptr(),
                ephemeral.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                out.as_mut_ptr(),
            )
        })?;
        Ok(out)
    }

    fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        let mut out = vec![0u8; P256_SIGNATURE_LEN + MLDSA_SIGNATURE_LEN];
        let e = self.enclave;
        // SAFETY: every pointer is valid for its paired length and `out` is large enough.
        check(unsafe {
            lv_enclave_sign(
                self.context.as_ptr(),
                e.signing.as_ptr(),
                e.signing.len(),
                e.dsa.as_ptr(),
                e.dsa.len(),
                message.as_ptr(),
                message.len(),
                out.as_mut_ptr(),
            )
        })?;
        let pq = out.split_off(P256_SIGNATURE_LEN);
        let ec: [u8; P256_SIGNATURE_LEN] = out.try_into().map_err(|_| Error::Hardware("bad signature length"))?;
        Ok(HybridSignature { ec, pq })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::Binding;
    use crate::crypto::{self, Key};
    use crate::ids::VaultId;

    /// The outside judge for the hybrid: aws-lc wraps in software, the enclave opens it, and
    /// aws-lc verifies what the enclave signed. Needs a person, so run it with
    /// `cargo test -p libvault enclave -- --ignored`.
    /// Shows a real prompt for a moment, then takes it away as another device's answer would.
    #[test]
    #[ignore = "shows a Touch ID prompt"]
    fn a_prompt_goes_away_when_the_person_answered_elsewhere() {
        let enclave = Enclave::generate().unwrap();
        let cancelled = AtomicBool::new(false);
        let started = std::time::Instant::now();
        let outcome = std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(1500));
                cancelled.store(true, Ordering::Release);
            });
            enclave.authorize_unless("libvault test: this goes away by itself", &cancelled).map(drop)
        });
        assert!(matches!(outcome, Err(Error::Cancelled)), "{outcome:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(3), "{:?}", started.elapsed());
    }

    #[test]
    #[ignore = "needs Touch ID"]
    fn enclave_interoperates_with_software_crypto_on_one_touch() {
        let enclave = Enclave::generate().unwrap();
        let key = Key::generate();
        let binding = Binding::Audit { vault: VaultId::random() };
        let wrapped = crypto::wrap(enclave.public().wrap_to(), &binding, &key).unwrap();

        let reloaded = Enclave::from_stored(&enclave.to_stored()).unwrap();
        let approved = reloaded.authorize("libvault test: unwrap and sign").unwrap();
        let shared = approved.agree(&wrapped.ephemeral, &wrapped.ciphertext).unwrap();
        assert_eq!(crypto::unwrap(&shared, reloaded.public().wrap_to(), &binding, &wrapped).unwrap(), key);

        let public = reloaded.public();
        let signature = approved.sign(b"message").unwrap();
        signature.verify(&public.signing, &public.dsa, b"message").unwrap();
        assert!(signature.verify(&public.signing, &public.dsa, b"tampered").is_err());
    }
}
