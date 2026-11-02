//! Keys for a machine nobody sits at, such as a server running agents. They sit in a file only
//! this user can read, so the vault opens by itself, and nothing here stands in for a person:
//! every approval comes from another device.

use zeroize::Zeroizing;

use super::software::{Cost, Software};
use super::{Authorized, Device};
use crate::crypto::{self, PublicKeys};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

const NOBODY_HERE: Error = Error::NeedsPerson("nobody is at this server to approve that. Approve it on another device");

/// Software keys sealed under a random secret kept beside them. Sealing them protects nothing a
/// read of the file would not get, and it keeps one way of holding keys in software.
#[derive(Debug)]
pub struct Server {
    keys: Software,
    secret: Zeroizing<String>,
}

impl Server {
    pub fn generate() -> Result<Self> {
        let secret = Zeroizing::new(crate::store::log::hex(&crypto::random::<32>()));
        // Stretching is for a passphrase a person chose. This is 256 random bits.
        Ok(Self { keys: Software::generate(&secret, Cost::FAST)?, secret })
    }

    pub fn from_stored(stored: &[u8]) -> Result<Self> {
        let mut r = Reader::new(stored);
        let secret = Zeroizing::new(String::from_utf8(r.bytes()?.to_vec()).map_err(|_| Error::Corrupt("bad device key"))?);
        let keys = Software::from_stored(r.bytes()?, Some(&secret))?;
        r.finish()?;
        Ok(Self { keys, secret })
    }
}

impl Device for Server {
    fn public(&self) -> &PublicKeys {
        self.keys.public()
    }

    fn authorize(&self, _reason: &str) -> Result<Box<dyn Authorized + '_>> {
        Err(NOBODY_HERE)
    }

    fn authorize_unlock(&self, reason: &str) -> Result<Box<dyn Authorized + '_>> {
        self.keys.authorize(reason)
    }

    fn to_stored(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.bytes(self.secret.as_bytes());
        w.bytes(&self.keys.to_stored());
        w.finish()
    }

    fn is_hardware(&self) -> bool {
        false
    }

    fn has_person(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_opens_its_keys_by_itself_and_approves_nothing() {
        let server = Server::from_stored(&Server::generate().unwrap().to_stored()).unwrap();
        assert!(server.authorize_unlock("unlock").is_ok());
        assert!(matches!(server.authorize("approve something").map(drop), Err(Error::NeedsPerson(_))));
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        assert!(server.authorize_unless("approve something", &cancelled).is_err());
    }
}
