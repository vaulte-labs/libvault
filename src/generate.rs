//! Making new passwords and secrets, from the system's random source.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto;
use crate::{Error, Result};

/// Leaves out characters that are easy to confuse: 0, O, 1, l and I.
const LETTERS_AND_DIGITS: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const WITH_SYMBOLS: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789-_.!@#$%&*+=?";
const SHORTEST_PASSWORD: usize = 12;
const LONGEST_PASSWORD: usize = 128;

/// What a generated password looks like. The default is strong anywhere that takes symbols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordRules {
    pub length: usize,
    pub symbols: bool,
}

impl Default for PasswordRules {
    fn default() -> Self {
        Self { length: 28, symbols: true }
    }
}

/// How much randomness a secret holds. These are the sizes keys and tokens come in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretSize {
    Bytes32,
    Bytes64,
}

/// One character, equally likely. Rejection sampling, because `byte % len` alone favors the start
/// of the alphabet.
fn random_character(alphabet: &[u8]) -> char {
    let limit = 256 - 256 % alphabet.len();
    loop {
        let byte = usize::from(crypto::random::<1>()[0]);
        if byte < limit {
            return char::from(alphabet[byte % alphabet.len()]);
        }
    }
}

fn has_every_kind(password: &str, symbols: bool) -> bool {
    password.contains(|c: char| c.is_ascii_lowercase())
        && password.contains(|c: char| c.is_ascii_uppercase())
        && password.contains(|c: char| c.is_ascii_digit())
        && (!symbols || password.contains(|c: char| c.is_ascii_punctuation()))
}

/// A random password. It holds at least one of each kind of character, because sites refuse
/// passwords without them. Drawing again keeps every password that qualifies equally likely.
pub fn password(rules: PasswordRules) -> Result<Zeroizing<String>> {
    if !(SHORTEST_PASSWORD..=LONGEST_PASSWORD).contains(&rules.length) {
        return Err(Error::Invalid("a password is 12 to 128 characters"));
    }
    let alphabet = if rules.symbols { WITH_SYMBOLS } else { LETTERS_AND_DIGITS };
    loop {
        let mut password = Zeroizing::new(String::with_capacity(rules.length));
        for _ in 0..rules.length {
            password.push(random_character(alphabet));
        }
        if has_every_kind(&password, rules.symbols) {
            return Ok(password);
        }
    }
}

fn hex(bytes: &[u8]) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(bytes.len() * 2));
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).expect("a nibble is a hex digit"));
        text.push(char::from_digit(u32::from(byte & 0xf), 16).expect("a nibble is a hex digit"));
    }
    text
}

/// A random secret in hex, the same as `openssl rand -hex 32`, so 32 bytes is 64 characters.
pub fn secret(size: SecretSize) -> Zeroizing<String> {
    match size {
        SecretSize::Bytes32 => hex(&Zeroizing::new(crypto::random::<32>())[..]),
        SecretSize::Bytes64 => hex(&Zeroizing::new(crypto::random::<64>())[..]),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn a_password_is_as_long_as_asked() {
        for length in [12, 28, 128] {
            assert_eq!(password(PasswordRules { length, symbols: true }).unwrap().len(), length);
        }
    }

    #[test]
    fn a_length_out_of_range_is_refused() {
        for length in [0, 11, 129] {
            assert!(password(PasswordRules { length, symbols: true }).is_err(), "{length}");
        }
    }

    #[test]
    fn every_password_holds_every_kind_of_character() {
        let holds = |password: &str, kind: fn(&u8) -> bool| password.as_bytes().iter().any(kind);
        // At 12 characters about one draw in four misses a digit, so these see plenty of misses.
        for _ in 0..2_000 {
            let drawn = password(PasswordRules { length: 12, symbols: true }).unwrap();
            for kind in [u8::is_ascii_lowercase, u8::is_ascii_uppercase, u8::is_ascii_digit, u8::is_ascii_punctuation] {
                assert!(holds(&drawn, kind), "{}", drawn.as_str());
            }
            let plain = password(PasswordRules { length: 12, symbols: false }).unwrap();
            for kind in [u8::is_ascii_lowercase, u8::is_ascii_uppercase, u8::is_ascii_digit] {
                assert!(holds(&plain, kind), "{}", plain.as_str());
            }
            assert!(plain.chars().all(|c| c.is_ascii_alphanumeric()), "no symbols were asked for");
        }
    }

    #[test]
    fn nothing_easily_confused_appears() {
        let drawn = password(PasswordRules { length: 128, symbols: false }).unwrap();
        assert!(!drawn.contains(['0', 'O', '1', 'l', 'I']), "{}", drawn.as_str());
    }

    #[test]
    fn every_character_can_appear_and_none_is_favored() {
        const DRAWS_PER_CHARACTER: usize = 2_000;
        let mut counts = [0usize; 256];
        for _ in 0..WITH_SYMBOLS.len() * DRAWS_PER_CHARACTER {
            counts[random_character(WITH_SYMBOLS) as usize] += 1;
        }
        for &character in WITH_SYMBOLS {
            let count = counts[usize::from(character)];
            // Four standard deviations, so this fails about once in 15,000 runs per character.
            assert!(count.abs_diff(DRAWS_PER_CHARACTER) < 180, "{} came up {count} times", char::from(character));
        }
    }

    #[test]
    fn a_secret_is_lowercase_hex_of_its_size() {
        for (size, length) in [(SecretSize::Bytes32, 64), (SecretSize::Bytes64, 128)] {
            let drawn = secret(size);
            assert_eq!(drawn.len(), length);
            assert!(drawn.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)), "{}", drawn.as_str());
        }
    }

    #[test]
    fn hex_keeps_both_halves_of_each_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xf0, 0xff, 0x2a]).as_str(), "000ff0ff2a");
    }

    #[test]
    fn no_two_are_the_same() {
        let drawn: BTreeSet<String> = (0..1_000).map(|_| secret(SecretSize::Bytes32).to_string()).collect();
        assert_eq!(drawn.len(), 1_000);
    }
}
