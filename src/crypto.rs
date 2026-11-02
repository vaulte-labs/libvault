//! The primitives every other module is built on. aws-lc supplies the public-key
//! algorithms and hashes; XChaCha20-Poly1305 comes from `RustCrypto` because a 192-bit
//! nonce can be random without any bookkeeping across devices.

use aws_lc_rs::agreement::{self, ECDH_P256, UnparsedPublicKey};
use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::kem::{EncapsulationKey, ML_KEM_1024};
use aws_lc_rs::signature::{self, ECDSA_P256_SHA256_FIXED, ED25519, ML_DSA_87};
use aws_lc_rs::{digest, hkdf, rand};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::sys::Locked;

use crate::binding::Binding;
use crate::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const COMMITMENT_LEN: usize = 32;
pub const TAG_LEN: usize = 16;
pub const HASH_LEN: usize = 32;
pub const P256_PUBLIC_LEN: usize = 65;
pub const P256_SIGNATURE_LEN: usize = 64;
pub const MLKEM_PUBLIC_LEN: usize = 1568;
pub const MLDSA_PUBLIC_LEN: usize = 2592;
pub const MLDSA_SIGNATURE_LEN: usize = 4627;

pub type Hash = [u8; HASH_LEN];

/// A 256-bit symmetric key, held in memory locked out of swap and erased on drop.
#[derive(Clone)]
pub struct Key(Locked);

impl Key {
    /// Made in place, so the key is never anywhere but locked memory.
    pub fn generate() -> Self {
        let mut locked = Locked::new([0; KEY_LEN]);
        rand::fill(locked.get_mut()).expect("system RNG failed");
        Self(locked)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(Locked::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        self.0.get()
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Key {}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(..)")
    }
}

/// Fills an array from the system RNG. A failing RNG is unrecoverable, so it panics.
pub(crate) fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::fill(&mut bytes).expect("system RNG failed");
    bytes
}

pub(crate) fn hash(parts: &[&[u8]]) -> Hash {
    let mut context = digest::Context::new(&digest::SHA256);
    for part in parts {
        context.update(part);
    }
    context.finish().as_ref().try_into().expect("SHA-256 is 32 bytes")
}

struct HkdfLen(usize);

impl hkdf::KeyType for HkdfLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// HKDF-SHA-256 into `out`. `info` parts are joined with no separator, so callers
/// must only pass fixed-length or length-prefixed values.
pub(crate) fn derive_into(out: &mut [u8], ikm: &[u8], salt: &[u8], info: &[&[u8]]) {
    hkdf::Salt::new(hkdf::HKDF_SHA256, salt)
        .extract(ikm)
        .expand(info, HkdfLen(out.len()))
        .and_then(|okm| okm.fill(out))
        .expect("HKDF output length is in range");
}

pub(crate) fn derive(ikm: &[u8], salt: &[u8], info: &[&[u8]]) -> Key {
    let mut key = Locked::new([0; KEY_LEN]);
    derive_into(key.get_mut(), ikm, salt, info);
    Key(key)
}

/// The key that encrypts one value, and a commitment to that key, the nonce and what it is for.
/// XChaCha20-Poly1305 alone commits to none of them: Poly1305 is linear, so anyone holding two keys
/// can solve for one ciphertext that opens under both, and two devices would read different
/// secrets from one log entry with nothing to show for it.
fn seal_keys(key: &Key, nonce: &[u8], ad: &[u8]) -> (Key, [u8; COMMITMENT_LEN]) {
    let mut derived = Zeroizing::new([0u8; KEY_LEN + COMMITMENT_LEN]);
    derive_into(derived.as_mut(), key.as_bytes(), nonce, &[b"lv.seal.v2", ad]);
    let (subkey, commitment) = derived.split_at(KEY_LEN);
    let mut key = Locked::new([0; KEY_LEN]);
    key.get_mut().copy_from_slice(subkey);
    (Key(key), commitment.try_into().expect("the rest is the commitment"))
}

/// Encrypts to `nonce || commitment || ciphertext || tag`.
pub(crate) fn seal(key: &Key, binding: &Binding, plaintext: &[u8]) -> Vec<u8> {
    let ad = binding.encode();
    let nonce: [u8; NONCE_LEN] = random();
    let (subkey, commitment) = seal_keys(key, &nonce, &ad);
    let cipher = XChaCha20Poly1305::new(subkey.as_bytes().into());
    let sealed = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &ad }).expect("plaintext is within the AEAD limit");
    [&nonce[..], &commitment, &sealed].concat()
}

pub(crate) fn open(key: &Key, binding: &Binding, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < NONCE_LEN + COMMITMENT_LEN + TAG_LEN {
        return Err(Error::Decrypt);
    }
    let ad = binding.encode();
    let (nonce, rest) = sealed.split_at(NONCE_LEN);
    let (commitment, ciphertext) = rest.split_at(COMMITMENT_LEN);
    let (subkey, expected) = seal_keys(key, nonce, &ad);
    verify_slices_are_equal(commitment, &expected).map_err(|_| Error::Decrypt)?;
    let cipher = XChaCha20Poly1305::new(subkey.as_bytes().into());
    cipher.decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad: &ad }).map(Zeroizing::new).map_err(|_| Error::Decrypt)
}

/// A key wrapped to a device's public keys. Anyone can create one in software;
/// only the recipient's secure hardware can open it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wrapped {
    pub ephemeral: [u8; P256_PUBLIC_LEN],
    pub ciphertext: Vec<u8>,
    pub sealed: Vec<u8>,
}

/// The public half of a device's enclave keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeys {
    pub agreement: [u8; P256_PUBLIC_LEN],
    pub kem: Vec<u8>,
    pub signing: [u8; P256_PUBLIC_LEN],
    pub dsa: Vec<u8>,
}

/// Who a key can be wrapped to: anyone with a P-256 and an ML-KEM public key.
#[derive(Debug, Clone, Copy)]
pub struct WrapTo<'a> {
    pub agreement: &'a [u8; P256_PUBLIC_LEN],
    pub kem: &'a [u8],
}

impl PublicKeys {
    pub fn wrap_to(&self) -> WrapTo<'_> {
        WrapTo { agreement: &self.agreement, kem: &self.kem }
    }
}

/// Binds the derived key to both public keys and both ciphertexts, so neither half
/// of the hybrid can be swapped out.
fn wrap_key(shared: &[u8; 64], to: WrapTo<'_>, ephemeral: &[u8], ciphertext: &[u8], binding: &Binding) -> Key {
    let transcript = hash(&[to.agreement, to.kem, ephemeral, ciphertext]);
    derive(shared, &binding.encode(), &[b"lv.wrap.v1", &transcript])
}

/// Wraps `key` to a device.
pub(crate) fn wrap(to: WrapTo<'_>, binding: &Binding, key: &Key) -> Result<Wrapped> {
    let mut shared = Zeroizing::new([0u8; 64]);

    let ephemeral = agreement::PrivateKey::generate(&ECDH_P256).map_err(|_| Error::Hardware("key generation failed"))?;
    let public = ephemeral.compute_public_key().map_err(|_| Error::Hardware("key generation failed"))?;
    let peer = UnparsedPublicKey::new(&ECDH_P256, *to.agreement);
    agreement::agree(&ephemeral, peer, Error::Corrupt("bad recipient key"), |secret| {
        shared[..32].copy_from_slice(secret);
        Ok(())
    })?;

    let kem = EncapsulationKey::new(&ML_KEM_1024, to.kem).map_err(|_| Error::Corrupt("bad recipient key"))?;
    let (ciphertext, secret) = kem.encapsulate().map_err(|_| Error::Corrupt("bad recipient key"))?;
    shared[32..].copy_from_slice(secret.as_ref());

    let ephemeral: [u8; P256_PUBLIC_LEN] = public.as_ref().try_into().map_err(|_| Error::Corrupt("bad public key"))?;
    let ciphertext = ciphertext.as_ref().to_vec();
    let wrapping = wrap_key(&shared, to, &ephemeral, &ciphertext, binding);
    Ok(Wrapped { sealed: seal(&wrapping, binding, key.as_bytes()), ephemeral, ciphertext })
}

/// Opens a wrapped key with the shared secrets returned by a device's hardware.
pub(crate) fn unwrap(shared: &[u8; 64], to: WrapTo<'_>, binding: &Binding, wrapped: &Wrapped) -> Result<Key> {
    let wrapping = wrap_key(shared, to, &wrapped.ephemeral, &wrapped.ciphertext, binding);
    let plaintext = open(&wrapping, binding, &wrapped.sealed)?;
    if plaintext.len() != KEY_LEN {
        return Err(Error::Decrypt);
    }
    let mut key = Locked::new([0; KEY_LEN]);
    key.get_mut().copy_from_slice(&plaintext);
    Ok(Key(key))
}

/// Both a classical and a post-quantum signature. Both must verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridSignature {
    pub ec: [u8; P256_SIGNATURE_LEN],
    pub pq: Vec<u8>,
}

impl HybridSignature {
    pub fn verify(&self, signing: &[u8; P256_PUBLIC_LEN], dsa: &[u8], message: &[u8]) -> Result<()> {
        if cfg!(fuzzing) {
            return Ok(());
        }
        signature::UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, signing)
            .verify(message, &self.ec)
            .map_err(|_| Error::Corrupt("bad signature"))?;
        verify_ml_dsa(dsa, message, &self.pq)
    }
}

pub(crate) fn verify_ml_dsa(public: &[u8], message: &[u8], sig: &[u8]) -> Result<()> {
    if cfg!(fuzzing) {
        return Ok(());
    }
    signature::UnparsedPublicKey::new(&ML_DSA_87, public).verify(message, sig).map_err(|_| Error::Corrupt("bad signature"))
}

pub(crate) fn verify_ed25519(public: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> Result<()> {
    if cfg!(fuzzing) {
        return Ok(());
    }
    signature::UnparsedPublicKey::new(&ED25519, public).verify(message, sig).map_err(|_| Error::Corrupt("bad signature"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::VaultId;

    fn audit() -> Binding {
        Binding::Audit { vault: VaultId::random() }
    }

    #[test]
    fn sealed_data_is_bound_to_what_it_is_for() {
        let key = Key::generate();
        let (right, wrong) = (audit(), audit());
        let sealed = seal(&key, &right, b"secret");
        assert_eq!(open(&key, &right, &sealed).unwrap().as_slice(), b"secret");
        assert!(matches!(open(&key, &wrong, &sealed), Err(Error::Decrypt)));
    }

    #[test]
    fn an_empty_plaintext_round_trips() {
        let key = Key::generate();
        let binding = audit();
        assert_eq!(open(&key, &binding, &seal(&key, &binding, b"")).unwrap().as_slice(), b"");
    }

    #[test]
    fn any_flipped_bit_fails_to_open() {
        let key = Key::generate();
        let binding = audit();
        let sealed = seal(&key, &binding, b"secret");
        for at in [0, NONCE_LEN, NONCE_LEN + COMMITMENT_LEN, sealed.len() - 1] {
            let mut tampered = sealed.clone();
            tampered[at] ^= 1;
            assert!(open(&key, &binding, &tampered).is_err());
        }
    }

    #[test]
    fn truncated_ciphertext_is_rejected_without_panicking() {
        let key = Key::generate();
        for len in 0..NONCE_LEN + COMMITMENT_LEN + TAG_LEN {
            assert!(open(&key, &audit(), &vec![0; len]).is_err());
        }
    }

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len() / 2).map(|at| u8::from_str_radix(&hex[at * 2..at * 2 + 2], 16).unwrap()).collect()
    }

    // Solved from the linear system in Albertini et al., "How to Abuse and Fix Authenticated
    // Encryption Without Key Commitment": one ciphertext that authenticates under the subkeys of
    // both keys. If `seal_keys` changes, this has to be solved again.
    #[test]
    fn a_ciphertext_crafted_to_open_under_two_keys_opens_under_one() {
        let nonce = bytes("333333333333333333333333333333333333333333330400");
        let forged = bytes("99fa1d0cfdb90a35c5b9e09aa41dc32b030dee9ca9f59994bbaabecb3726518d");
        let (first, second) = (Key::from_bytes([0x11; KEY_LEN]), Key::from_bytes([0x22; KEY_LEN]));
        let binding = Binding::SoftwareKeys;
        let ad = binding.encode();

        for key in [&first, &second] {
            let cipher = XChaCha20Poly1305::new(seal_keys(key, &nonce, &ad).0.as_bytes().into());
            assert!(cipher.decrypt(XNonce::from_slice(&nonce), Payload { msg: &forged, aad: &ad }).is_ok(), "the forgery must be real");
        }

        let (_, commitment) = seal_keys(&first, &nonce, &ad);
        let sealed = [&nonce[..], &commitment, &forged].concat();
        assert!(open(&first, &binding, &sealed).is_ok());
        assert!(matches!(open(&second, &binding, &sealed), Err(Error::Decrypt)));
    }

    #[test]
    fn a_seal_commits_to_what_it_is_for() {
        let (key, nonce) = (Key::generate(), [1; NONCE_LEN]);
        assert_ne!(seal_keys(&key, &nonce, b"one").1, seal_keys(&key, &nonce, b"two").1);
        assert_ne!(seal_keys(&key, &nonce, b"one").1, seal_keys(&key, &[2; NONCE_LEN], b"one").1);
        assert_ne!(seal_keys(&key, &nonce, b"one").1, seal_keys(&Key::generate(), &nonce, b"one").1);
    }

    // RFC 5869 appendix A, test case 1.
    #[test]
    fn hkdf_matches_rfc_5869() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut out = [0u8; 42];
        derive_into(&mut out, &ikm, &salt, &[&info]);
        let expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
        assert_eq!(crate::store::log::hex(&out), expected);
    }
}
