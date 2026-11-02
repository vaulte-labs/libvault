//! What a device shows the relay Vaulte hosts, to say someone has paid without saying who.
//!
//! Each month the account service makes a new RSA key, and a long-lived root key vouches for it. A
//! device blinds a fresh message, the account service signs it for an account that has paid, and
//! the device unblinds it, so the pass it then shows cannot be linked to the account that asked,
//! by the relay or by the account service. A pass lasts as long as its month does.

use crate::wire::{Reader, Writer};
use crate::{Error, Result};

/// What every pass signs, after the random 32 bytes that make each one unique (RFC 9474's
/// randomized RSABSSA-SHA384-PSS).
pub const MESSAGE: &[u8] = b"vaulte.relay.pass.v1";
const KEY_LABEL: &[u8] = b"vaulte.relay.key.v1";
/// A 4096-bit key's `SubjectPublicKeyInfo` is 550 bytes, and its signature 512.
const MAX_KEY: usize = 600;
const MAX_SIGNATURE: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pass {
    /// Months since January 1970, the month its key works in.
    pub month: u32,
    /// That month's RSA key, as `SubjectPublicKeyInfo`.
    pub key: Vec<u8>,
    /// The root key's signature over `key_statement(month, key)`.
    pub cert: [u8; 64],
    pub randomizer: [u8; 32],
    pub signature: Vec<u8>,
}

impl Pass {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(self.month);
        w.bytes(&self.key);
        w.array(&self.cert);
        w.array(&self.randomizer);
        w.bytes(&self.signature);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let month = r.u32()?;
        let key = r.bytes()?.to_vec();
        let (cert, randomizer) = (r.array()?, r.array()?);
        let signature = r.bytes()?.to_vec();
        r.finish()?;
        if key.len() > MAX_KEY || signature.len() > MAX_SIGNATURE {
            return Err(Error::Corrupt("a pass that size is not one"));
        }
        Ok(Self { month, key, cert, randomizer, signature })
    }
}

/// What the root key signs to vouch for a month's key.
pub fn key_statement(month: u32, key: &[u8]) -> Vec<u8> {
    [KEY_LABEL, &month.to_be_bytes(), key].concat()
}

/// A day, as passes count time: months since January 1970, and the day of that month, in UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Month {
    pub month: u32,
    pub day: u32,
}

impl Month {
    pub fn now() -> Self {
        Self::at(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |since| since.as_secs()))
    }

    /// By the civil calendar, after Howard Hinnant's `civil_from_days`.
    pub fn at(unix_seconds: u64) -> Self {
        let z = i64::try_from(unix_seconds / 86_400).unwrap_or(i64::MAX / 2) + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let day = doy - (153 * mp + 2) / 5 + 1;
        let month = if mp < 10 { mp + 3 } else { mp - 9 };
        let year = yoe + era * 400 + i64::from(month <= 2);
        let months = (year - 1970) * 12 + month - 1;
        Self { month: u32::try_from(months).unwrap_or(0), day: u32::try_from(day).unwrap_or(1) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOVEMBER_2026: u32 = 56 * 12 + 10;

    #[test]
    fn months_are_counted_by_the_calendar() {
        assert_eq!(Month::at(0), Month { month: 0, day: 1 });
        assert_eq!(Month::at(1_793_577_600), Month { month: NOVEMBER_2026, day: 2 }, "2026-11-02");
        assert_eq!(Month::at(951_782_400), Month { month: 30 * 12 + 1, day: 29 }, "2000-02-29");
        assert_eq!(Month::at(1_798_761_599), Month { month: NOVEMBER_2026 + 1, day: 31 }, "2026-12-31, its last second");
    }

    #[test]
    fn a_pass_reads_back_whole_and_only_whole() {
        let pass = Pass { month: NOVEMBER_2026, key: vec![1; 294], cert: [2; 64], randomizer: [3; 32], signature: vec![4; 256] };
        let encoded = pass.encode();
        assert_eq!(Pass::decode(&encoded).unwrap(), pass);
        assert!(Pass::decode(&[encoded.as_slice(), &[0]].concat()).is_err(), "trailing bytes");
        assert!(Pass::decode(&encoded[..encoded.len() - 1]).is_err(), "cut short");
    }
}
