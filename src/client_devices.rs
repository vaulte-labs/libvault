//! What concerns this device and the others: who is in the vault, adding and removing devices,
//! and when this one locks by itself.

use super::{Client, UNEXPECTED};
use crate::protocol::{RelayIssuer, Request, Response};
use crate::{DeviceInfo, LockSettings, Result};

impl Client {
    pub fn devices(&mut self) -> Result<Vec<DeviceInfo>> {
        match self.call(Request::Devices)? {
            Response::Devices { devices } => Ok(devices),
            _ => Err(UNEXPECTED),
        }
    }

    /// Removes a device and rotates every key, after a touch. With two or more devices this
    /// needs the recovery key too. Returns the names of everything that device could read,
    /// because those secrets should be changed where they are used.
    pub fn remove_device(&mut self, name: &str, recovery_words: Option<&str>) -> Result<Vec<String>> {
        match self.call(Request::DeviceRemove { name: name.to_owned(), recovery: recovery_words.map(str::to_owned) })? {
            Response::Removed { exposed } => Ok(exposed),
            _ => Err(UNEXPECTED),
        }
    }

    /// Starts adding a device, at `address` or found on the local network, and returns the words
    /// both screens should show. Dropping this client abandons it.
    pub fn begin_pairing(&mut self, address: Option<&str>) -> Result<[String; 3]> {
        match self.call(Request::PairBegin { address: address.map(str::to_owned) })? {
            Response::Pairing { words } => Ok(words),
            _ => Err(UNEXPECTED),
        }
    }

    /// The person says the words match. Adds the device after a touch, and returns its name. With
    /// two or more devices this needs another device's approval, or the recovery key.
    pub fn confirm_pairing(&mut self, recovery_words: Option<&str>) -> Result<String> {
        self.confirm_pairing_holding(recovery_words, None)
    }

    /// As `confirm_pairing`, for a server that holds only `spaces`, by name.
    pub fn confirm_pairing_holding(&mut self, recovery_words: Option<&str>, spaces: Option<&[&str]>) -> Result<String> {
        let spaces = spaces.map(|spaces| spaces.iter().map(|space| (*space).to_owned()).collect());
        match self.call(Request::PairConfirm { recovery: recovery_words.map(str::to_owned), spaces })? {
            Response::Paired { name } => Ok(name),
            _ => Err(UNEXPECTED),
        }
    }

    /// Starts the subscription, which the relay asks for, with an account made here first if this
    /// device has none.
    /// Returns the account number, which the person keeps, and where to pay. `issuer` is for a
    /// relay someone runs themselves; none is the one Vaulte hosts.
    pub fn relay_subscribe(&mut self, email: Option<&str>, issuer: Option<RelayIssuer>) -> Result<(String, String)> {
        match self.call(Request::RelaySubscribe { email: email.map(str::to_owned), issuer })? {
            Response::Checkout { account, url } => Ok((account, url)),
            _ => Err(UNEXPECTED),
        }
    }

    /// Uses an account this person already has, as on a second device.
    pub fn use_relay_account(&mut self, number: &str, issuer: Option<RelayIssuer>) -> Result<()> {
        self.call(Request::RelayAccount { number: number.to_owned(), issuer }).map(drop)
    }

    /// The account this device uses for a relay, if any, and until when it is paid, in seconds
    /// since 1970, when the account service could be asked.
    pub fn relay_status(&mut self) -> Result<Option<(String, Option<u64>)>> {
        match self.call(Request::RelayStatus)? {
            Response::RelayAccount { account, paid_until } => Ok(account.map(|account| (account, paid_until))),
            _ => Err(UNEXPECTED),
        }
    }

    /// Remembers where another device is, for one that network discovery cannot reach.
    pub fn add_peer(&mut self, address: &str) -> Result<()> {
        self.call(Request::PeerAdd { address: address.to_owned() }).map(drop)
    }

    /// When this device's vault locks by itself.
    pub fn lock_settings(&mut self) -> Result<LockSettings> {
        match self.call(Request::LockSettings)? {
            Response::LockSettings(settings) => Ok(settings),
            _ => Err(UNEXPECTED),
        }
    }

    /// Changes when this device's vault locks by itself, after a touch. Other devices keep theirs.
    pub fn set_lock_settings(&mut self, settings: LockSettings) -> Result<()> {
        self.call(Request::SetLockSettings { settings }).map(drop)
    }
}
