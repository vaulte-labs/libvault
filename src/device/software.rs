//! Keys held in software, sealed under a passphrase. For machines with no secure hardware,
//! and for tests. Weaker than hardware by nature: `vlt status` says so.

use std::cell::RefCell;

use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::agreement::{self, ECDH_P256, UnparsedPublicKey};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, ML_KEM_1024};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair, ML_DSA_87_SIGNING, PqdsaKeyPair};
use zeroize::Zeroizing;

use super::{Authorized, Device};
use crate::binding::Binding;
use crate::crypto::{self, HybridSignature, Key, MLDSA_SIGNATURE_LEN, P256_PUBLIC_LEN, P256_SIGNATURE_LEN, PublicKeys};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

/// Argon2id work factors, stored with the keys so they can be raised later.
#[derive(Debug, Clone, Copy)]
pub struct Cost {
    pub memory_kib: u32,
    pub iterations: u32,
}

impl Cost {
    /// RFC 9106's second recommended option.
    pub const STRONG: Self = Self { memory_kib: 64 * 1024, iterations: 3 };
    /// For tests, and for a random secret, which needs no stretching.
    pub const FAST: Self = Self { memory_kib: 8, iterations: 1 };
}

fn stretch(passphrase: &str, salt: &[u8; 16], cost: Cost) -> Result<Key> {
    let params = Params::new(cost.memory_kib, cost.iterations, 1, Some(32)).map_err(|_| Error::Corrupt("bad key parameters"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
        .map_err(|_| Error::Corrupt("bad key parameters"))?;
    Ok(Key::from_bytes(*key))
}

thread_local! {
    /// What the person handed over with the request this thread is working on.
    static PRESENTED: RefCell<Option<Zeroizing<String>>> = const { RefCell::new(None) };
}

/// Holds a person's passphrase for one request. On this backend the passphrase is the touch, so
/// it is used for that request and gone when this drops, and a broker keeps none of its own.
#[derive(Debug)]
pub(crate) struct Presented;

pub(crate) fn present(passphrase: Option<Zeroizing<String>>) -> Presented {
    PRESENTED.with(|presented| *presented.borrow_mut() = passphrase);
    Presented
}

impl Drop for Presented {
    fn drop(&mut self) {
        PRESENTED.with(|presented| presented.borrow_mut().take());
    }
}

#[derive(Debug)]
pub struct Software {
    public: PublicKeys,
    salt: [u8; 16],
    cost: Cost,
    sealed: Vec<u8>,
    /// Only where a person is right here, such as during setup. A broker has none.
    passphrase: Option<Zeroizing<String>>,
}

fn generation_failed<E>(_: E) -> Error {
    Error::Hardware("key generation failed")
}

impl Software {
    pub fn generate(passphrase: &str, cost: Cost) -> Result<Self> {
        let agreement: Zeroizing<[u8; 32]> = Zeroizing::new(crypto::random());
        let agreement_key = agreement::PrivateKey::from_private_key(&ECDH_P256, agreement.as_ref()).map_err(generation_failed)?;
        let agreement_public: [u8; P256_PUBLIC_LEN] =
            agreement_key.compute_public_key().map_err(generation_failed)?.as_ref().try_into().map_err(generation_failed)?;

        let kem = DecapsulationKey::generate(&ML_KEM_1024).map_err(generation_failed)?;
        let kem_public = kem.encapsulation_key().and_then(|key| key.key_bytes()).map_err(generation_failed)?;
        let kem_private = Zeroizing::new(kem.key_bytes().map_err(generation_failed)?.as_ref().to_vec());

        let signing = Zeroizing::new(
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new()).map_err(generation_failed)?.as_ref().to_vec(),
        );
        let signing_key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &signing).map_err(generation_failed)?;
        let signing_public: [u8; P256_PUBLIC_LEN] = signing_key.public_key().as_ref().try_into().map_err(generation_failed)?;

        let dsa_seed: Zeroizing<[u8; 32]> = Zeroizing::new(crypto::random());
        let dsa = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, dsa_seed.as_ref()).map_err(generation_failed)?;

        let mut secrets = Writer::new();
        secrets.bytes(agreement.as_ref());
        secrets.bytes(&kem_private);
        secrets.bytes(&signing);
        secrets.bytes(dsa_seed.as_ref());
        let secrets = Zeroizing::new(secrets.finish());

        let salt = crypto::random();
        let sealed = crypto::seal(&stretch(passphrase, &salt, cost)?, &Binding::SoftwareKeys, &secrets);
        let public = PublicKeys {
            agreement: agreement_public,
            kem: kem_public.as_ref().to_vec(),
            signing: signing_public,
            dsa: dsa.public_key().as_ref().to_vec(),
        };
        Ok(Self { public, salt, cost, sealed, passphrase: Some(Zeroizing::new(passphrase.to_owned())) })
    }

    pub fn from_stored(stored: &[u8], passphrase: Option<&str>) -> Result<Self> {
        let mut r = Reader::new(stored);
        let agreement = r.array()?;
        let kem = r.bytes()?.to_vec();
        let signing = r.array()?;
        let dsa = r.bytes()?.to_vec();
        let salt = r.array()?;
        let cost = Cost { memory_kib: r.u32()?, iterations: r.u32()? };
        let sealed = r.bytes()?.to_vec();
        let public = PublicKeys { agreement, kem, signing, dsa };
        Ok(Self { public, salt, cost, sealed, passphrase: passphrase.map(|passphrase| Zeroizing::new(passphrase.to_owned())) })
    }
}

impl Device for Software {
    fn public(&self) -> &PublicKeys {
        &self.public
    }

    fn authorize(&self, _reason: &str) -> Result<Box<dyn Authorized + '_>> {
        let presented = PRESENTED.with(|presented| presented.borrow().clone());
        let passphrase = self.passphrase.clone().or(presented).ok_or(Error::PassphraseNeeded)?;
        let key = stretch(&passphrase, &self.salt, self.cost)?;
        let secrets = crypto::open(&key, &Binding::SoftwareKeys, &self.sealed).map_err(|_| Error::WrongPassphrase)?;
        let mut r = Reader::new(&secrets);
        let agreement = Zeroizing::new(r.bytes()?.to_vec());
        let kem = DecapsulationKey::new(&ML_KEM_1024, r.bytes()?).map_err(|_| Error::Corrupt("bad device key"))?;
        let signing = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, r.bytes()?).map_err(|_| Error::Corrupt("bad device key"))?;
        let dsa = PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, r.bytes()?).map_err(|_| Error::Corrupt("bad device key"))?;
        Ok(Box::new(Unsealed { agreement, kem, signing, dsa }))
    }

    fn to_stored(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(&self.public.agreement);
        w.bytes(&self.public.kem);
        w.array(&self.public.signing);
        w.bytes(&self.public.dsa);
        w.array(&self.salt);
        w.u32(self.cost.memory_kib);
        w.u32(self.cost.iterations);
        w.bytes(&self.sealed);
        w.finish()
    }

    fn is_hardware(&self) -> bool {
        false
    }
}

/// The hybrid agreement for keys held in memory, returning both shared secrets.
pub(crate) fn agree_in_software(
    agreement: &[u8],
    kem: &DecapsulationKey,
    ephemeral: &[u8; P256_PUBLIC_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; 64]>> {
    let mut out = Zeroizing::new([0u8; 64]);
    let private = agreement::PrivateKey::from_private_key(&ECDH_P256, agreement).map_err(|_| Error::Decrypt)?;
    let peer = UnparsedPublicKey::new(&ECDH_P256, ephemeral);
    agreement::agree(&private, peer, Error::Decrypt, |secret| {
        out[..32].copy_from_slice(secret);
        Ok(())
    })?;
    let secret = kem.decapsulate(Ciphertext::from(ciphertext)).map_err(|_| Error::Decrypt)?;
    out[32..].copy_from_slice(secret.as_ref());
    Ok(out)
}

struct Unsealed {
    agreement: Zeroizing<Vec<u8>>,
    kem: DecapsulationKey,
    signing: EcdsaKeyPair,
    dsa: PqdsaKeyPair,
}

impl Authorized for Unsealed {
    fn agree(&self, ephemeral: &[u8; P256_PUBLIC_LEN], ciphertext: &[u8]) -> Result<Zeroizing<[u8; 64]>> {
        agree_in_software(&self.agreement, &self.kem, ephemeral, ciphertext)
    }

    fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        let failed = |_| Error::Hardware("signing failed");
        let ec: [u8; P256_SIGNATURE_LEN] =
            self.signing.sign(&SystemRandom::new(), message).map_err(failed)?.as_ref().try_into().map_err(|_| Error::Hardware("signing failed"))?;
        let mut pq = vec![0u8; MLDSA_SIGNATURE_LEN];
        let written = self.dsa.sign(message, &mut pq).map_err(failed)?;
        pq.truncate(written);
        Ok(HybridSignature { ec, pq })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::VaultId;

    #[test]
    fn wrong_passphrase_is_reported_as_such() {
        let device = Software::generate("right", Cost::FAST).unwrap();
        let stored = device.to_stored();
        let wrong = Software::from_stored(&stored, Some("wrong")).unwrap();
        assert!(matches!(wrong.authorize("test").err(), Some(Error::WrongPassphrase)));
    }

    #[test]
    fn with_no_passphrase_to_hand_nothing_is_approved() {
        let device = Software::generate("right", Cost::FAST).unwrap();
        let held = Software::from_stored(&device.to_stored(), None).unwrap();
        assert!(matches!(held.authorize("test").err(), Some(Error::PassphraseNeeded)));

        let presented = present(Some(Zeroizing::new("right".to_owned())));
        assert!(held.authorize("test").is_ok(), "a person handed it over for this request");
        drop(presented);
        assert!(matches!(held.authorize("test").err(), Some(Error::PassphraseNeeded)), "and it must end with the request");
    }

    #[test]
    fn wrapped_key_survives_a_round_trip_through_stored_form() {
        let device = Software::generate("pass", Cost::FAST).unwrap();
        let key = Key::generate();
        let binding = Binding::Audit { vault: VaultId::random() };
        let other = Binding::Audit { vault: VaultId::random() };
        let wrapped = crypto::wrap(device.public().wrap_to(), &binding, &key).unwrap();

        let reloaded = Software::from_stored(&device.to_stored(), Some("pass")).unwrap();
        let approved = reloaded.authorize("test").unwrap();
        let shared = approved.agree(&wrapped.ephemeral, &wrapped.ciphertext).unwrap();
        assert_eq!(crypto::unwrap(&shared, reloaded.public().wrap_to(), &binding, &wrapped).unwrap(), key);
        assert!(crypto::unwrap(&shared, reloaded.public().wrap_to(), &other, &wrapped).is_err());
    }

    #[test]
    fn hybrid_signature_needs_both_halves_valid() {
        let device = Software::generate("pass", Cost::FAST).unwrap();
        let public = device.public().clone();
        let signature = device.authorize("test").unwrap().sign(b"message").unwrap();
        signature.verify(&public.signing, &public.dsa, b"message").unwrap();
        assert!(signature.verify(&public.signing, &public.dsa, b"other").is_err());

        let mut classical_broken = signature.clone();
        classical_broken.ec[0] ^= 1;
        assert!(classical_broken.verify(&public.signing, &public.dsa, b"message").is_err());

        let mut quantum_broken = signature;
        quantum_broken.pq[0] ^= 1;
        assert!(quantum_broken.verify(&public.signing, &public.dsa, b"message").is_err());
    }
}
