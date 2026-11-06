//! Joining from another network. The joining device waits at a relay under a tag only its code
//! gives, and shows the code. Typed on a device that has the vault, in place of an address, it
//! dials that tag, and the pairing runs as on a local network, words and all. The code only brings
//! the two together: a stranger who learns it reaches a pairing whose words then differ.

use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use super::relay::{self, Tag, Waiting};
use crate::{Result, crypto};

/// About 40 bits: nobody stumbles on a code while it lasts, and it is quick to type on a phone.
const DIGITS: usize = 12;
/// Well inside how long the relay waits to hear from a device before it lets it go.
const RENEW_EVERY: Duration = Duration::from_secs(10);

/// A fresh code's digits.
pub(crate) fn new_code() -> String {
    let random = u64::from_le_bytes(crypto::random()) % 10u64.pow(12);
    format!("{random:012}")
}

/// The digits as a person reads and types them: 4821-7730-1956.
pub(crate) fn shown(digits: &str) -> String {
    [&digits[..4], &digits[4..8], &digits[8..]].join("-")
}

/// The digits, if `text` is a code however it was spaced or dashed, rather than an address.
pub(crate) fn parse(text: &str) -> Option<String> {
    let digits: String = text.chars().filter(|c| !matches!(c, ' ' | '-')).collect();
    (digits.len() == DIGITS && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

fn tag(digits: &str) -> Tag {
    crypto::hash(&[b"vaulte.relay.join.v1", digits.as_bytes()])
}

/// Waits at `relay` under the code's tag until `stop`, handing on each device that dials it. A
/// device that is joining has no pass, and a relay that asks for them lets it wait briefly anyway.
pub(crate) fn wait(relay: &str, digits: &str, stop: Arc<AtomicBool>) -> Result<mpsc::Receiver<TcpStream>> {
    let tag = tag(digits);
    let mut waiting = Waiting::open(relay, &[tag], &[])?;
    let (arrived, relayed) = mpsc::channel();
    std::thread::spawn(move || {
        let mut renewed = Instant::now();
        while !stop.load(Ordering::Relaxed) {
            if renewed.elapsed() >= RENEW_EVERY {
                if waiting.renew(&[tag]).is_err() {
                    return;
                }
                renewed = Instant::now();
            }
            match waiting.next(Duration::from_secs(1)) {
                Ok(Some(stream)) => {
                    if arrived.send(stream).is_err() {
                        return;
                    }
                }
                Ok(None) => {}
                // Joining goes on on this network, and the person can give an address.
                Err(_) => return,
            }
        }
    });
    Ok(relayed)
}

/// Reaches the device waiting under the code at `relay`.
pub(crate) fn dial(relay: &str, digits: &str, pass: &[u8]) -> Result<TcpStream> {
    relay::dial(relay, &tag(digits), pass)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_reads_back_however_it_is_typed_and_an_address_is_not_one() {
        let digits = new_code();
        assert_eq!(digits.len(), DIGITS);
        assert_eq!(parse(&shown(&digits)).as_deref(), Some(digits.as_str()));
        assert_eq!(parse("4821 7730 1956").as_deref(), Some("482177301956"));
        assert_eq!(parse("127.0.0.1:41083"), None);
        assert_eq!(parse("4821-7730-195"), None, "one digit short");
    }
}
