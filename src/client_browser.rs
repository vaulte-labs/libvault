//! What a browser or the system's autofill asks of the vault: sign-ins, fills, and the logins it
//! may suggest.

use std::os::unix::net::UnixStream;
use std::path::Path;

use zeroize::Zeroizing;

use super::{Client, Connect, SHARED_SOCKET, UNEXPECTED};
use crate::protocol::{
    AutofillIdentity, FillOption, Filled, LoginInto, NewPasskey, PasskeyAssertion, PasskeyOption, PasskeyRequest, Request, Response,
};
use crate::{Error, Result};

const LONGEST_SOCKET_PATH: usize = 103;

impl Client {
    /// Connects through the vault's shared folder, for its own sandboxed code, such as an autofill
    /// extension, which can neither see the vault's folder nor start a broker. Only a broker that
    /// is already running answers there.
    pub fn connect_shared(folder: &Path, options: Connect<'_>) -> Result<Self> {
        let socket = folder.join(SHARED_SOCKET);
        // A socket's path holds 103 bytes. Past that, saying the broker is not running would send
        // a person looking for the wrong problem.
        if socket.as_os_str().len() > LONGEST_SOCKET_PATH {
            return Err(Error::BrokerUnavailable("the shared folder's path is too long for a socket"));
        }
        let stream = UnixStream::connect(socket).map_err(|_| Error::BrokerUnavailable("it is not running. Open Vaulty and try again"))?;
        let passphrase = options.passphrase.map(|passphrase| Zeroizing::new(passphrase.to_owned()));
        // A sandbox cannot start a broker, so it can replace none.
        Ok(Self { stream, session: options.session.map(str::to_owned), passphrase, upgrade: None })
    }

    /// Signs in with a saved login in a browser nothing else can reach, and hands over only the
    /// session. Returns how many cookies it carried. Needs a touch, unless a session covers it.
    pub fn login(&mut self, space: Option<&str>, name: &str, into: LoginInto) -> Result<usize> {
        match self.call(Request::Login { space: space.map(str::to_owned), name: name.to_owned(), into })? {
            Response::LoggedIn { cookies } => Ok(cookies),
            _ => Err(UNEXPECTED),
        }
    }

    /// Lists what could fill on the page at `origin`, which the browser reports, not the page.
    pub fn fill_options(&mut self, origin: &str) -> Result<Vec<FillOption>> {
        match self.call(Request::FillOptions { origin: origin.to_owned() })? {
            Response::FillOptions { options } => Ok(options),
            _ => Err(UNEXPECTED),
        }
    }

    /// Each login's sites and username, for the system's autofill to suggest. Never a secret, and
    /// never to a session.
    pub fn autofill_identities(&mut self) -> Result<Vec<AutofillIdentity>> {
        match self.call(Request::AutofillIdentities)? {
            Response::AutofillIdentities { identities } => Ok(identities),
            _ => Err(UNEXPECTED),
        }
    }

    /// The passkeys that fit `origin`, or only those of `allow` when the site names its own. Never
    /// a prompt, and never to a session.
    pub fn passkey_options(&mut self, origin: &str, allow: Vec<Vec<u8>>) -> Result<Vec<PasskeyOption>> {
        match self.call(Request::PasskeyOptions { origin: origin.to_owned(), allow })? {
            Response::PasskeyOptions { options } => Ok(options),
            _ => Err(UNEXPECTED),
        }
    }

    /// Makes and saves a passkey for the site that asks, after a touch naming the site.
    pub fn create_passkey(&mut self, request: PasskeyRequest) -> Result<NewPasskey> {
        match self.call(Request::CreatePasskey(request))? {
            Response::NewPasskey(created) => Ok(created),
            _ => Err(UNEXPECTED),
        }
    }

    /// Signs a sign-in on `origin` with the passkey `name`, after a touch naming it and the site.
    /// `client_data_hash` is the SHA-256 of the client data the browser built for the page.
    pub fn sign_passkey(&mut self, space: &str, name: &str, origin: &str, client_data_hash: &[u8]) -> Result<PasskeyAssertion> {
        let request = Request::SignPasskey {
            space: space.to_owned(),
            name: name.to_owned(),
            origin: origin.to_owned(),
            client_data_hash: client_data_hash.to_vec(),
        };
        match self.call(request)? {
            Response::PasskeyAssertion(assertion) => Ok(assertion),
            _ => Err(UNEXPECTED),
        }
    }

    /// Returns what to put on the page, after a touch naming the item and the page.
    pub fn fill(&mut self, space: &str, name: &str, origin: &str) -> Result<Filled> {
        match self.call(Request::Fill { space: space.to_owned(), name: name.to_owned(), origin: origin.to_owned() })? {
            Response::Filled(filled) => Ok(*filled),
            _ => Err(UNEXPECTED),
        }
    }
}
