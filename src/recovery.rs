//! The recovery key: 256 bits written down as 24 words. It wraps the epoch key directly and
//! derives an authority that can override the roster, so losing a second device never means
//! losing the vault.

use aws_lc_rs::agreement::{self, ECDH_P256};
use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_1024};
use aws_lc_rs::signature::{ED25519_PUBLIC_KEY_LEN, Ed25519KeyPair, KeyPair, ML_DSA_87_SIGNING, PqdsaKeyPair};
use bip39::Mnemonic;
use zeroize::Zeroizing;

use crate::binding::Binding;
use crate::crypto::{self, HybridSignature, Key, MLDSA_SIGNATURE_LEN, Wrapped};
use crate::device::software::agree_in_software;
use crate::ids::VaultId;
use crate::record::RecoveryPublic;
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

const SALT: &[u8] = b"lv.recovery.v1";

/// Whether `word` is one a recovery key can hold, so a typo can be asked again on its own.
pub fn is_recovery_word(word: &str) -> bool {
    bip39::Language::English.find_word(&word.to_lowercase()).is_some()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryKey(Key);

impl RecoveryKey {
    pub fn generate() -> Self {
        Self(Key::generate())
    }

    /// Accepts any whitespace and letter case, and reports which word is wrong when it can.
    pub fn parse(words: &str) -> Result<Self> {
        let normalized = Zeroizing::new(words.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase());
        let mnemonic = Mnemonic::parse_normalized(&normalized).map_err(|error| {
            Error::BadRecoveryKey(match error {
                bip39::Error::UnknownWord(index) => format!("word {} is not on the list", index + 1),
                bip39::Error::BadWordCount(count) => format!("expected 24 words, got {count}"),
                bip39::Error::InvalidChecksum => "the words are valid but the checksum fails, so one is wrong or out of order".to_owned(),
                _ => "the words could not be read".to_owned(),
            })
        })?;
        let entropy = Zeroizing::new(mnemonic.to_entropy());
        let bytes: [u8; 32] = entropy.as_slice().try_into().map_err(|_| Error::BadRecoveryKey("expected 24 words".to_owned()))?;
        Ok(Self(Key::from_bytes(bytes)))
    }

    pub fn words(&self) -> Zeroizing<String> {
        let mnemonic = Mnemonic::from_entropy(self.0.as_bytes()).expect("32 bytes is valid BIP-39 entropy");
        Zeroizing::new(mnemonic.to_string())
    }

    fn seal_key(&self) -> Key {
        crypto::derive(self.0.as_bytes(), SALT, &[b"wrap"])
    }

    fn signers(&self) -> Result<(Ed25519KeyPair, PqdsaKeyPair)> {
        let failed = |_| Error::Hardware("recovery key derivation failed");
        let ed25519 = crypto::derive(self.0.as_bytes(), SALT, &[b"ed25519"]);
        let dsa = crypto::derive(self.0.as_bytes(), SALT, &[b"ml-dsa-87"]);
        Ok((
            Ed25519KeyPair::from_seed_unchecked(ed25519.as_bytes()).map_err(failed)?,
            PqdsaKeyPair::from_seed(&ML_DSA_87_SIGNING, dsa.as_bytes()).map_err(failed)?,
        ))
    }

    fn signing_public(&self) -> Result<([u8; ED25519_PUBLIC_KEY_LEN], Vec<u8>)> {
        let (ed25519, dsa) = self.signers()?;
        Ok((ed25519.public_key().as_ref().try_into().expect("Ed25519 public key is 32 bytes"), dsa.public_key().as_ref().to_vec()))
    }

    /// Creates the public half for a new vault, with fresh wrap keys sealed under the words.
    pub fn new_public(&self, vault: VaultId) -> Result<RecoveryPublic> {
        let failed = |_| Error::Hardware("recovery key generation failed");
        let agreement_private: Zeroizing<[u8; 32]> = Zeroizing::new(crypto::random());
        let agreement_key = agreement::PrivateKey::from_private_key(&ECDH_P256, agreement_private.as_ref())
            .map_err(|_| Error::Hardware("recovery key generation failed"))?;
        let agreement: [u8; 65] = agreement_key.compute_public_key().map_err(failed)?.as_ref().try_into().expect("P-256 public key is 65 bytes");
        let kem = DecapsulationKey::generate(&ML_KEM_1024).map_err(failed)?;
        let kem_public = kem.encapsulation_key().and_then(|key| key.key_bytes()).map_err(failed)?.as_ref().to_vec();

        let mut private = Writer::new();
        private.bytes(agreement_private.as_ref());
        private.bytes(kem.key_bytes().map_err(failed)?.as_ref());
        let private = Zeroizing::new(private.finish());
        let sealed_private = crypto::seal(&self.seal_key(), &Binding::RecoveryKeys { vault }, &private);

        let (ed25519, dsa) = self.signing_public()?;
        Ok(RecoveryPublic { ed25519, dsa, agreement, kem: kem_public, sealed_private })
    }

    /// Whether these words are the ones this vault was created with.
    pub fn matches(&self, public: &RecoveryPublic) -> Result<bool> {
        let (ed25519, dsa) = self.signing_public()?;
        Ok(ed25519 == public.ed25519 && dsa == public.dsa)
    }

    /// Opens a key wrapped to recovery.
    pub fn unwrap(&self, vault: VaultId, public: &RecoveryPublic, binding: &Binding, wrapped: &Wrapped) -> Result<Key> {
        let private =
            crypto::open(&self.seal_key(), &Binding::RecoveryKeys { vault }, &public.sealed_private).map_err(|_| Error::WrongRecoveryKey)?;
        let mut r = Reader::new(&private);
        let agreement = r.bytes()?;
        let kem = DecapsulationKey::new(&ML_KEM_1024, r.bytes()?).map_err(|_| Error::Corrupt("bad recovery key"))?;
        let shared = agree_in_software(agreement, &kem, &wrapped.ephemeral, &wrapped.ciphertext)?;
        crypto::unwrap(&shared, public.wrap_to(), binding, wrapped)
    }

    pub fn sign(&self, message: &[u8]) -> Result<HybridSignature> {
        let (ed25519, dsa) = self.signers()?;
        let ec = ed25519.sign(message).as_ref().try_into().expect("Ed25519 signature is 64 bytes");
        let mut pq = vec![0u8; MLDSA_SIGNATURE_LEN];
        let written = dsa.sign(message, &mut pq).map_err(|_| Error::Hardware("signing failed"))?;
        pq.truncate(written);
        Ok(HybridSignature { ec, pq })
    }
}

/// A new recovery key, before anything depends on it. Every interface walks the same steps: show
/// `words`, confirm with `confirmation_positions` and `check_word`, then commit.
#[derive(Debug)]
pub struct RecoveryDraft(pub(crate) RecoveryKey);

impl RecoveryDraft {
    pub fn new() -> Self {
        Self(RecoveryKey::generate())
    }

    /// The 24 words to show the person. They are never stored.
    pub fn words(&self) -> Zeroizing<String> {
        self.0.words()
    }

    /// Three distinct word positions (zero-based) to ask for, proving the key was written down.
    pub fn confirmation_positions(&self) -> [usize; 3] {
        let mut positions: [usize; 24] = std::array::from_fn(|position| position);
        for picked in 0..3 {
            positions.swap(picked, picked + usize::from(crypto::random::<1>()[0]) % (24 - picked));
        }
        [positions[0], positions[1], positions[2]]
    }

    /// Whether `answer` is the word at `position`.
    pub fn check_word(&self, position: usize, answer: &str) -> bool {
        self.0.words().split(' ').nth(position).is_some_and(|word| word.eq_ignore_ascii_case(answer.trim()))
    }
}

impl Default for RecoveryDraft {
    fn default() -> Self {
        Self::new()
    }
}

/// Recovery signatures use Ed25519 as the classical half, since its key derives from a seed.
pub fn verify(public: &RecoveryPublic, message: &[u8], signature: &HybridSignature) -> Result<()> {
    crypto::verify_ed25519(&public.ed25519, message, &signature.ec)?;
    crypto::verify_ml_dsa(&public.dsa, message, &signature.pq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_round_trip_through_messy_input() {
        let key = RecoveryKey::generate();
        let words = key.words();
        assert_eq!(words.split(' ').count(), 24);
        let messy = format!("  {}\n", words.replace(' ', "\n  ").to_uppercase());
        assert_eq!(RecoveryKey::parse(&messy).unwrap(), key);
    }

    #[test]
    fn a_typo_names_the_word() {
        let words = RecoveryKey::generate().words();
        let mut split: Vec<&str> = words.split(' ').collect();
        split[6] = "notaword";
        let error = RecoveryKey::parse(&split.join(" ")).unwrap_err();
        assert!(error.to_string().contains("word 7"), "{error}");
    }

    #[test]
    fn swapped_words_fail_the_checksum() {
        // The checksum is eight bits, so one swap in 256 gets through.
        let swap_is_caught = |_: &u8| {
            let words = RecoveryKey::generate().words();
            let mut split: Vec<&str> = words.split(' ').collect();
            let different = (1..24).find(|&i| split[i] != split[0]).unwrap();
            split.swap(0, different);
            RecoveryKey::parse(&split.join(" ")).is_err()
        };
        assert!((0..64u8).filter(swap_is_caught).count() >= 60);
    }

    #[test]
    fn a_device_can_wrap_to_recovery_without_the_words_and_only_the_words_open_it() {
        let vault = VaultId::random();
        let key = RecoveryKey::generate();
        let public = key.new_public(vault).unwrap();
        let binding = Binding::Audit { vault };
        let secret = Key::generate();
        // Only public data here, as on any device.
        let wrapped = crypto::wrap(public.wrap_to(), &binding, &secret).unwrap();

        assert_eq!(key.unwrap(vault, &public, &binding, &wrapped).unwrap(), secret);
        let other = RecoveryKey::generate();
        assert!(matches!(other.unwrap(vault, &public, &binding, &wrapped), Err(Error::WrongRecoveryKey)));
        assert!(key.matches(&public).unwrap());
        assert!(!other.matches(&public).unwrap());
    }

    #[test]
    fn matching_needs_both_signing_keys() {
        let vault = VaultId::random();
        let key = RecoveryKey::generate();
        let real = key.new_public(vault).unwrap();
        let other = RecoveryKey::generate().new_public(vault).unwrap();
        assert!(!key.matches(&RecoveryPublic { ed25519: other.ed25519, ..real.clone() }).unwrap());
        assert!(!key.matches(&RecoveryPublic { dsa: other.dsa, ..real }).unwrap());
    }

    #[test]
    fn errors_say_what_is_wrong_with_the_words() {
        let words = RecoveryKey::generate().words();
        let split: Vec<&str> = words.split(' ').collect();
        let short = RecoveryKey::parse(&split[..5].join(" ")).unwrap_err();
        assert!(short.to_string().contains("expected 24 words, got 5"), "{short}");

        // One swap in 256 passes the eight-bit checksum, so take the first that does not.
        let swapped = (1..24)
            .find_map(|i| {
                let mut swapped = split.clone();
                swapped.swap(0, i);
                RecoveryKey::parse(&swapped.join(" ")).err()
            })
            .unwrap();
        assert!(swapped.to_string().contains("checksum"), "{swapped}");
    }

    #[test]
    fn confirmation_asks_for_three_different_words() {
        let draft = RecoveryDraft::new();
        for _ in 0..200 {
            let [first, second, third] = draft.confirmation_positions();
            assert!(first != second && second != third && first != third);
        }
    }

    #[test]
    fn confirmation_can_ask_for_any_word() {
        let draft = RecoveryDraft::new();
        for question in 0..3 {
            let asked: std::collections::BTreeSet<usize> = (0..200).map(|_| draft.confirmation_positions()[question]).collect();
            assert!(asked.iter().all(|position| *position < 24));
            assert!(asked.len() > 15, "question {question} only ever asked for {asked:?}");
        }
    }

    #[test]
    fn signatures_verify_only_for_the_signed_message() {
        let key = RecoveryKey::generate();
        let public = key.new_public(VaultId::random()).unwrap();
        let signature = key.sign(b"message").unwrap();
        verify(&public, b"message", &signature).unwrap();
        assert!(verify(&public, b"other", &signature).is_err());
    }
}
