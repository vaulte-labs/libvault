//! What the vault stores. `Meta` can be listed without touching a secret, and is still
//! encrypted at rest. `Secret` is decrypted only when something uses it.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub use crate::profile::Profile;
use crate::{Error, Result};

const BUCKET: usize = 256;
const MAX_TEXT: usize = 512;
/// The 802.11 limit on an SSID.
const LONGEST_NETWORK_NAME: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Login,
    Card,
    Env,
    Note,
    Ssh,
    Passkey,
    Wifi,
    /// A person's details for forms. Listed by its own name alone.
    Profile,
    /// A website's icon. Never listed. See `icon`.
    Icon,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub kind: Kind,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Sites a login may fill on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// Hosts an env var may be sent to through the proxy.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
    /// Safe to show in lists, such as a card's brand and last four digits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Whether this login keeps a two-factor secret, so a list can say so without a touch.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub two_factor: bool,
    /// When a card runs out, as `2030-12`, so nobody needs a touch to be warned about it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
}

impl Meta {
    pub fn new(kind: Kind, name: impl Into<String>) -> Self {
        Self { kind, name: name.into(), username: None, urls: Vec::new(), hosts: Vec::new(), hint: None, two_factor: false, expires: None }
    }

    /// An env var, with its allowed hosts filled in when the name is well known.
    pub fn env(name: impl Into<String>) -> Self {
        let name = name.into();
        let hosts = crate::known_hosts(&name);
        Self { hosts, ..Self::new(Kind::Env, name) }
    }

    /// A login. A name that looks like a domain becomes its first fill site.
    pub fn login(name: impl Into<String>) -> Self {
        let name = name.into();
        let urls = if name.contains('.') && !name.contains(char::is_whitespace) { vec![format!("https://{name}")] } else { Vec::new() };
        Self { urls, ..Self::new(Kind::Login, name) }
    }
}

/// Keeps text that came from outside from carrying terminal escapes or fake lines into a list.
pub(crate) fn printable(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { ' ' } else { c }).take(MAX_TEXT).collect::<String>().trim().to_owned()
}

/// Rejects text that could spoof a terminal or a list.
pub(crate) fn validate_text(text: &str) -> Result<()> {
    if text.is_empty() || text.chars().count() > MAX_TEXT || text.chars().any(char::is_control) {
        return Err(Error::Invalid("names and addresses must be short, with no control characters"));
    }
    Ok(())
}

/// Rejects anything but a host name. The proxy compares hosts exactly, so a URL here would be
/// accepted and then never match, which reads as allowed and does nothing.
pub(crate) fn validate_host(host: &str) -> Result<()> {
    validate_text(host)?;
    if host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.')) {
        Ok(())
    } else {
        Err(Error::Invalid("give a host name on its own, like api.example.com"))
    }
}

/// Variables that change what a program runs or trusts. A stored variable reaches a program a
/// person started, and adding one takes no touch, so one of these would be a way into that program.
const NOT_FOR_STORING: &[&str] = &[
    "BASH_ENV",
    "CDPATH",
    "ENV",
    "GIT_ASKPASS",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "HOME",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "IFS",
    "JAVA_TOOL_OPTIONS",
    "NODE_EXTRA_CA_CERTS",
    "NODE_OPTIONS",
    "NODE_PATH",
    "NO_PROXY",
    "PATH",
    "PERL5LIB",
    "PERL5OPT",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "REQUESTS_CA_BUNDLE",
    "RUBYLIB",
    "RUBYOPT",
    "SHELL",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "ZDOTDIR",
    "_JAVA_OPTIONS",
];

fn is_safe_variable(name: &str) -> bool {
    let plain = name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && !name.starts_with(|c: char| c.is_ascii_digit());
    let upper = name.to_ascii_uppercase();
    plain && !upper.starts_with("LD_") && !upper.starts_with("DYLD_") && !NOT_FOR_STORING.contains(&upper.as_str())
}

/// Rejects a listing that could not have come from an honest interface.
pub(crate) fn validate(meta: &Meta) -> Result<()> {
    if meta.kind == Kind::Env && !is_safe_variable(&meta.name) {
        return Err(Error::Invalid("that variable changes how programs run, so it cannot be stored"));
    }
    if meta.kind == Kind::Wifi && meta.name.len() > LONGEST_NETWORK_NAME {
        return Err(Error::Invalid("a Wi-Fi network name is at most 32 bytes"));
    }
    [&meta.name].into_iter().chain(&meta.username).chain(&meta.urls).chain(&meta.hosts).chain(&meta.hint).try_for_each(|field| validate_text(field))
}

fn kind_of(secret: &Secret) -> Kind {
    match secret {
        Secret::Login { .. } => Kind::Login,
        Secret::Card { .. } => Kind::Card,
        Secret::Env { .. } => Kind::Env,
        Secret::Note { .. } => Kind::Note,
        Secret::Ssh { .. } => Kind::Ssh,
        Secret::Wifi { .. } => Kind::Wifi,
        Secret::Profile(_) => Kind::Profile,
        Secret::Icon { .. } => Kind::Icon,
        Secret::Passkey { .. } => Kind::Passkey,
    }
}

/// Rejects an item no honest interface would write. The broker runs this on every add, edit and
/// import, before anyone is asked to approve it. Writes of what is already stored skip it, so an
/// item kept from before a rule cannot stop a restore or a rescue.
pub(crate) fn check(meta: &Meta, secret: &Secret) -> Result<()> {
    validate(meta)?;
    if kind_of(secret) != meta.kind {
        return Err(Error::Invalid("that secret is not this kind of item"));
    }
    match secret {
        Secret::Card { number, .. } if !valid_card_number(number) => Err(Error::InvalidCard),
        Secret::Card { expiry, .. } if crate::expiry::normalized(expiry).is_none() => {
            Err(Error::Invalid("give the expiry as a month and year, like 12/30"))
        }
        Secret::Profile(profile) => profile.check(),
        // Its key is made in the broker for the site that asks, never handed in from outside.
        Secret::Passkey { .. } => Err(Error::Invalid("a passkey is made for the site that asks for one")),
        _ => Ok(()),
    }
}

/// `meta` with what its secret implies filled in. Lists must not need a touch, so what they say
/// about a secret travels with the metadata. Every write passes through here, so no interface can
/// forget it or get it wrong.
pub(crate) fn derived(meta: &Meta, secret: &Secret) -> Meta {
    let two_factor = matches!(secret, Secret::Login { totp: Some(_), .. });
    let expires = if let Secret::Card { expiry, .. } = secret { crate::expiry::normalized(expiry) } else { None };
    let hint = match secret {
        Secret::Card { number, .. } if valid_card_number(number) => Some(format!("{} {}", card_brand(number), &number[number.len() - 4..])),
        // Lists reach agents, and these details are the person's alone.
        Secret::Profile(_) => None,
        _ => meta.hint.clone(),
    };
    Meta { hint, two_factor, expires, ..meta.clone() }
}

/// A card from what a person typed, checked before anything is stored.
pub fn card(name: impl Into<String>, number: &str, expiry: String, cvc: String, holder: String) -> Result<(Meta, Secret)> {
    let number = number.chars().filter(char::is_ascii_digit).collect();
    let (meta, secret) = (Meta::new(Kind::Card, name), Secret::Card { number, expiry, cvc, holder });
    check(&meta, &secret)?;
    Ok((derived(&meta, &secret), secret))
}

fn valid_card_number(number: &str) -> bool {
    if !(12..=19).contains(&number.len()) || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    let sum: u32 = number
        .bytes()
        .rev()
        .enumerate()
        .map(|(index, byte)| {
            let digit = u32::from(byte - b'0');
            if index % 2 == 1 { if digit > 4 { digit * 2 - 9 } else { digit * 2 } } else { digit }
        })
        .sum();
    sum.is_multiple_of(10)
}

fn card_brand(number: &str) -> &'static str {
    match number.as_bytes() {
        [b'4', ..] => "Visa",
        [b'5', b'1'..=b'5', ..] | [b'2', b'2'..=b'7', ..] => "Mastercard",
        [b'3', b'4' | b'7', ..] => "Amex",
        _ => "Card",
    }
}

/// Secret material, erased on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Secret {
    Login {
        password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        totp: Option<String>,
    },
    Card {
        number: String,
        expiry: String,
        cvc: String,
        holder: String,
    },
    Env {
        value: String,
    },
    Note {
        body: String,
    },
    Ssh {
        private_key: String,
    },
    /// The network's name is the item's name.
    Wifi {
        password: String,
    },
    Profile(Profile),
    /// In base64, because this is stored as JSON. Checked as far as its header, never decoded.
    Icon {
        png: String,
    },
    Passkey {
        rp_id: String,
        user_handle: String,
        credential_id: String,
        private_key: String,
    },
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// Hides plaintext length to the nearest bucket, so logs reveal little beyond "a small item".
pub(crate) fn pad(json: &[u8]) -> Zeroizing<Vec<u8>> {
    let total = (4 + json.len()).div_ceil(BUCKET) * BUCKET;
    let mut padded = Zeroizing::new(Vec::with_capacity(total));
    padded.extend_from_slice(&u32::try_from(json.len()).expect("items are small").to_le_bytes());
    padded.extend_from_slice(json);
    padded.resize(total, 0);
    padded
}

pub(crate) fn unpad(padded: &[u8]) -> Result<&[u8]> {
    let (length, rest) = padded.split_first_chunk::<4>().ok_or(Error::Corrupt("bad padding"))?;
    rest.get(..u32::from_le_bytes(*length) as usize).ok_or(Error::Corrupt("bad padding"))
}

pub(crate) fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    // Reserved up front so growth does not leave copies of plaintext behind on the heap.
    let mut json = Zeroizing::new(Vec::with_capacity(64 * 1024));
    serde_json::to_writer(&mut *json, value).map_err(|_| Error::Corrupt("item could not be encoded"))?;
    Ok(pad(&json))
}

pub(crate) fn decode<T: for<'de> Deserialize<'de>>(padded: &[u8]) -> Result<T> {
    serde_json::from_slice(unpad(padded)?).map_err(|_| Error::Corrupt("item could not be read"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_hides_length_within_a_bucket() {
        assert_eq!(pad(&[1; 10]).len(), pad(&[1; 200]).len());
        assert_eq!(pad(&[1; 252]).len(), BUCKET);
        assert_eq!(pad(&[1; 253]).len(), 2 * BUCKET);
        assert_eq!(unpad(&pad(b"value")).unwrap(), b"value");
    }

    #[test]
    fn a_length_past_the_buffer_is_rejected() {
        let mut padded = pad(b"value").to_vec();
        padded[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(unpad(&padded).is_err());
    }

    #[test]
    fn a_variable_that_changes_how_programs_run_cannot_be_stored() {
        for name in ["DYLD_INSERT_LIBRARIES", "LD_PRELOAD", "NODE_OPTIONS", "PATH", "https_proxy", "SSL_CERT_FILE", "1BAD", "A B", "A=B"] {
            assert!(validate(&Meta::new(Kind::Env, name)).is_err(), "{name}");
        }
        for name in ["OPENAI_API_KEY", "DATABASE_URL", "my_token", "PATHLESS"] {
            assert!(validate(&Meta::new(Kind::Env, name)).is_ok(), "{name}");
        }
    }

    #[test]
    fn listings_cannot_carry_terminal_escapes() {
        assert!(validate(&Meta::new(Kind::Env, "\u{1b}[2Jfake")).is_err());
        assert!(validate(&Meta::new(Kind::Env, "two\nlines")).is_err());
        assert!(validate(&Meta::new(Kind::Env, "")).is_err());
        assert!(validate(&Meta::new(Kind::Env, "GOOD_NAME")).is_ok());
        assert_eq!(printable("a\u{1b}[2Jb\n"), "a [2Jb");
    }

    #[test]
    fn card_numbers_are_checked_and_only_the_last_four_are_listed() {
        let holder = || "A Person".to_owned();
        let (meta, _) = card("Visa", "4242 4242 4242 4242", "12/30".to_owned(), "123".to_owned(), holder()).unwrap();
        assert_eq!(meta.hint.as_deref(), Some("Visa 4242"));
        assert!(matches!(card("Typo", "4242 4242 4242 4241", String::new(), String::new(), holder()), Err(Error::InvalidCard)));
        assert!(matches!(card("Short", "42", String::new(), String::new(), holder()), Err(Error::InvalidCard)));
    }

    #[test]
    fn debug_output_never_contains_a_secret() {
        let secret = Secret::Env { value: "sk-live".to_owned() };
        assert!(!format!("{secret:?}").contains("sk-live"));
    }
}
