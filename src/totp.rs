//! Two-factor codes, per RFC 6238. A saved code is either an `otpauth://` URI or a bare base32
//! secret, as sites show them.

use aws_lc_rs::hmac;
use zeroize::Zeroizing;

use crate::{Error, Result};

const INVALID: Error = Error::Invalid("that is not a two-factor secret");
const MIN_SEED: usize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A parsed two-factor secret.
#[derive(Debug)]
pub struct Totp {
    secret: Zeroizing<Vec<u8>>,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
}

fn decode_base32(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    let (mut buffer, mut bits) = (0u64, 0u32);
    for c in text.bytes().filter(|c| !matches!(c, b' ' | b'-' | b'=')) {
        let value = match c.to_ascii_uppercase() {
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u64::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    // Shorter than any real seed: this is a mistake, such as a password in the code field.
    (out.len() >= MIN_SEED).then_some(out)
}

impl Totp {
    pub fn parse(text: &str) -> Result<Self> {
        let Some(rest) = text.trim().strip_prefix("otpauth://totp/") else {
            return Ok(Self { secret: decode_base32(text).ok_or(INVALID)?, algorithm: Algorithm::Sha1, digits: 6, period: 30 });
        };
        let (_, query) = rest.split_once('?').ok_or(INVALID)?;
        let mut parsed = Self { secret: Zeroizing::new(Vec::new()), algorithm: Algorithm::Sha1, digits: 6, period: 30 };
        for pair in query.split('&') {
            let (name, value) = pair.split_once('=').ok_or(INVALID)?;
            match (name.to_ascii_lowercase().as_str(), value) {
                ("secret", value) => parsed.secret = decode_base32(value).ok_or(INVALID)?,
                ("digits", value) => parsed.digits = value.parse().map_err(|_| INVALID)?,
                ("period", value) => parsed.period = value.parse().map_err(|_| INVALID)?,
                // Steam's codes are another algorithm, and these would look right and fail.
                ("encoder", _) => return Err(INVALID),
                ("algorithm", value) => {
                    parsed.algorithm = match value.to_ascii_uppercase().as_str() {
                        "SHA1" => Algorithm::Sha1,
                        "SHA256" => Algorithm::Sha256,
                        "SHA512" => Algorithm::Sha512,
                        _ => return Err(INVALID),
                    }
                }
                _ => {}
            }
        }
        if parsed.secret.is_empty() || !(6..=8).contains(&parsed.digits) || parsed.period == 0 {
            return Err(INVALID);
        }
        Ok(parsed)
    }

    /// The code for a moment, in seconds since the Unix epoch.
    pub fn code(&self, unix_seconds: u64) -> String {
        let algorithm = match self.algorithm {
            Algorithm::Sha1 => hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
            Algorithm::Sha256 => hmac::HMAC_SHA256,
            Algorithm::Sha512 => hmac::HMAC_SHA512,
        };
        let counter = (unix_seconds / self.period).to_be_bytes();
        let tag = hmac::sign(&hmac::Key::new(algorithm, &self.secret), &counter);
        let tag = tag.as_ref();
        let offset = usize::from(tag[tag.len() - 1] & 0x0f);
        let truncated = u32::from_be_bytes(tag[offset..offset + 4].try_into().expect("four bytes")) & 0x7fff_ffff;
        format!("{:0width$}", truncated % 10u32.pow(self.digits), width = self.digits as usize)
    }

    /// The code for right now.
    pub fn now(&self) -> String {
        self.code(crate::store::log::now_ms() / 1000)
    }

    /// How much longer the code for `unix_seconds` stays good.
    pub fn seconds_left(&self, unix_seconds: u64) -> u64 {
        self.period - unix_seconds % self.period
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(secret: &[u8]) -> String {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let (mut out, mut buffer, mut bits) = (String::new(), 0u32, 0u32);
        for byte in secret {
            buffer = (buffer << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
            }
            buffer &= (1 << bits) - 1;
        }
        if bits > 0 {
            out.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
        }
        out
    }

    // RFC 6238 appendix B, 8 digits. Each algorithm has its own test secret.
    #[test]
    fn matches_every_rfc_6238_test_vector() {
        let sha1 = format!("otpauth://totp/a?secret={}&digits=8", encoded(b"12345678901234567890"));
        let sha256 = format!("otpauth://totp/a?secret={}&digits=8&algorithm=SHA256", encoded(b"12345678901234567890123456789012"));
        let sha512 = format!(
            "otpauth://totp/a?secret={}&digits=8&algorithm=SHA512",
            encoded(b"1234567890123456789012345678901234567890123456789012345678901234")
        );
        let vectors: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ];
        let (sha1, sha256, sha512) = (Totp::parse(&sha1).unwrap(), Totp::parse(&sha256).unwrap(), Totp::parse(&sha512).unwrap());
        for (time, one, two, five) in vectors {
            assert_eq!(sha1.code(time), one, "SHA1 at {time}");
            assert_eq!(sha256.code(time), two, "SHA256 at {time}");
            assert_eq!(sha512.code(time), five, "SHA512 at {time}");
        }
    }

    #[test]
    fn a_bare_secret_uses_the_usual_settings_and_tolerates_how_sites_print_it() {
        let totp = Totp::parse("JBSW Y3DP-EHPK 3PXP").unwrap();
        assert_eq!(totp.code(59).len(), 6);
        assert_eq!(totp.code(59), Totp::parse("jbswy3dpehpk3pxp").unwrap().code(59));
    }

    #[test]
    fn a_setting_counts_however_it_is_capitalised() {
        let totp = Totp::parse("otpauth://totp/a?Secret=JBSWY3DPEHPK3PXP&Digits=8&PERIOD=60").unwrap();
        assert_eq!((totp.digits, totp.period), (8, 60));
    }

    #[test]
    fn what_would_give_wrong_codes_is_refused() {
        assert!(Totp::parse("password").is_err());
        assert!(Totp::parse("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&encoder=steam").is_err());
    }

    #[test]
    fn a_short_code_keeps_its_leading_zeros() {
        let totp = Totp::parse(&format!("otpauth://totp/a?secret={}&digits=8", encoded(b"12345678901234567890"))).unwrap();
        assert_eq!(totp.code(1_111_111_109), "07081804");
    }

    #[test]
    fn nonsense_is_refused() {
        for bad in [
            "",
            "not base32 !!!",
            "otpauth://totp/a",
            "otpauth://totp/a?digits=6",
            "otpauth://totp/a?secret=JBSWY3DP&digits=20",
            "otpauth://totp/a?secret=JBSWY3DP&period=0",
            "otpauth://totp/a?secret=JBSWY3DP&algorithm=MD5",
        ] {
            assert!(Totp::parse(bad).is_err(), "{bad}");
        }
    }
}
