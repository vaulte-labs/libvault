//! The relay Vaulte hosts lets in only those who show a pass. Each month this device asks the
//! account service for one with the person's account number, blinded, so the pass it shows the
//! relay cannot be traced back to that account, by the relay or by the account service.

use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use blind_rsa_signatures::{BlindSignature, DefaultRng, PublicKeySha384PSSRandomized};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::Broker;
use super::policy::{Action, Caller};
use crate::net::relay::pass::{MESSAGE, Month, Pass, key_statement};
use crate::protocol::{RelayIssuer, Response};
use crate::store::write_private;
use crate::{Error, Result, crypto};

/// The account service Vaulte runs, and the root key that vouches for its passes.
const HOSTED_ISSUER: &str = "https://vaulte-accounts.caeser.workers.dev";
const HOSTED_ROOT: &str = "7b05bb2bb80b90172d4d39ddc9904c438b0a32ab16e02958280c0aeb1c080a30";
/// The relay Vaulte hosts, which every device with an account from Vaulte's service syncs through.
const HOSTED_RELAY: &str = "relay:vaulte-relay.fly.dev:443";

const ACCOUNT_FILE: &str = "relay-account.json";
const PASS_FILE: &str = "relay-pass";
/// After a failed fetch, so a device that cannot reach the account service, or whose person has
/// not paid yet, does not ask on every dial. Short, because someone who just paid is waiting.
const RETRY: Duration = Duration::from_mins(1);
const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_REPLY: usize = 64 * 1024;

static LAST_TRY: Mutex<Option<Instant>> = Mutex::new(None);

/// Where this device gets passes, and the root key its passes must be vouched for by.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Account {
    pub issuer: String,
    pub number: String,
    /// Ed25519, in hex.
    pub root: String,
}

impl Account {
    pub fn read(home: &Path) -> Option<Self> {
        serde_json::from_slice(&std::fs::read(home.join("local").join(ACCOUNT_FILE)).ok()?).ok()
    }

    pub fn write(&self, home: &Path) -> Result<()> {
        let bytes = serde_json::to_vec(self).map_err(|_| Error::Corrupt("the account could not be saved"))?;
        write_private(&home.join("local").join(ACCOUNT_FILE), &bytes)
    }

    fn root(&self) -> Result<[u8; 32]> {
        let bytes: Option<Vec<u8>> = (0..self.root.len()).step_by(2).map(|at| u8::from_str_radix(self.root.get(at..at + 2)?, 16).ok()).collect();
        bytes.and_then(|bytes| bytes.try_into().ok()).ok_or(Error::Corrupt("the account's root key is damaged"))
    }
}

/// The account service a request names, or Vaulte's.
fn issuer_or_hosted(issuer: Option<RelayIssuer>) -> RelayIssuer {
    issuer.unwrap_or_else(|| RelayIssuer { url: HOSTED_ISSUER.to_owned(), root: HOSTED_ROOT.to_owned() })
}

impl Broker {
    /// Syncs through Vaulte's relay once the account is from Vaulte's service, so every app that
    /// subscribes gets the relay it paid for without having to know where it is.
    fn use_hosted_relay(&self, account: &Account) -> Result<()> {
        if account.issuer == HOSTED_ISSUER { self.add_place(HOSTED_RELAY) } else { Ok(()) }
    }

    /// Where to pay, with an account made first if this device has none. The number is the
    /// person's to keep: it is the account, and it names nobody.
    pub(super) fn relay_subscribe(&self, caller: &Caller, email: Option<&str>, issuer: Option<RelayIssuer>) -> Result<Response> {
        self.check(caller, Action::ManageGrants)?;
        let account = if let Some(account) = Account::read(&self.home) {
            account
        } else {
            let RelayIssuer { url, root } = issuer_or_hosted(issuer);
            let asked = email.map_or_else(|| json!({}), |email| json!({ "email": email }));
            let made = self.ask_issuer(&url, "/accounts", Some(asked))?;
            let number = made["account"].as_str().ok_or(BAD_REPLY)?.to_owned();
            let account = Account { issuer: url, number, root };
            account.write(&self.home)?;
            account
        };
        self.use_hosted_relay(&account)?;
        let checkout = self.ask_issuer(&account.issuer, "/checkout", Some(json!({ "account": account.number })))?;
        let url = checkout["url"].as_str().ok_or(BAD_REPLY)?.to_owned();
        Ok(Response::Checkout { account: account.number, url })
    }

    /// Stripe's page for the account this device uses, where its person cancels, changes their
    /// card or gets invoices.
    pub(super) fn relay_billing(&self, caller: &Caller) -> Result<Response> {
        self.check(caller, Action::ManageGrants)?;
        let account = Account::read(&self.home).ok_or_else(|| Error::NotFound("a relay account on this device".to_owned()))?;
        let page = self.ask_issuer(&account.issuer, "/portal", Some(json!({ "account": account.number })))?;
        let url = page["url"].as_str().ok_or(BAD_REPLY)?.to_owned();
        Ok(Response::Checkout { account: account.number, url })
    }

    /// Uses an account this person already has, and drops any pass another one paid for.
    pub(super) fn use_relay_account(&self, caller: &Caller, number: &str, issuer: Option<RelayIssuer>) -> Result<Response> {
        self.check(caller, Action::ManageGrants)?;
        if number.chars().filter(char::is_ascii_digit).count() != 16 || !number.chars().all(|c| c.is_ascii_digit() || c == ' ' || c == '-') {
            return Err(Error::Invalid("an account number is sixteen digits"));
        }
        let RelayIssuer { url, root } = issuer_or_hosted(issuer);
        let account = Account { issuer: url, number: number.to_owned(), root };
        account.write(&self.home)?;
        self.use_hosted_relay(&account)?;
        let _ = std::fs::remove_file(self.home.join("local").join(PASS_FILE));
        if let Ok(mut last) = LAST_TRY.lock() {
            *last = None;
        }
        Ok(Response::Ok)
    }

    /// The account this device uses, and until when it is paid, when the account service says.
    pub(super) fn relay_status(&self, caller: &Caller) -> Result<Response> {
        self.check(caller, Action::Read)?;
        let Some(account) = Account::read(&self.home) else { return Ok(Response::RelayAccount { account: None, paid_until: None }) };
        let paid_until = self
            .ask_issuer(&account.issuer, "/status", Some(json!({ "account": account.number })))
            .ok()
            .and_then(|reply| reply["paid_until"].as_u64());
        Ok(Response::RelayAccount { account: Some(account.number), paid_until })
    }

    /// This month's pass, fetched once and kept. With none to be had, last month's, which a relay
    /// still takes for the first days of a month, or none at all, which a relay that asks for
    /// none takes.
    pub(super) fn relay_pass(&self) -> Vec<u8> {
        let path = self.home.join("local").join(PASS_FILE);
        let kept = std::fs::read(&path).ok();
        let now = Month::now();
        if let Some(pass) = kept.as_ref().filter(|bytes| Pass::decode(bytes).is_ok_and(|pass| pass.month == now.month)) {
            return pass.clone();
        }
        let due = LAST_TRY.lock().is_ok_and(|mut last| {
            let due = last.is_none_or(|last| last.elapsed() >= RETRY);
            if due {
                *last = Some(Instant::now());
            }
            due
        });
        if due
            && let Some(account) = Account::read(&self.home)
            && let Ok(pass) = self.fetch_pass(&account)
            && write_private(&path, &pass).is_ok()
        {
            return pass;
        }
        kept.unwrap_or_default()
    }

    /// Asks for the month's key, checks the root vouched for it, so this device gets the key
    /// everyone does, and has a fresh message signed blind.
    fn fetch_pass(&self, account: &Account) -> Result<Vec<u8>> {
        let key = self.ask_issuer(&account.issuer, "/key", None)?;
        let month = key["month"].as_u64().and_then(|month| u32::try_from(month).ok()).ok_or(BAD_REPLY)?;
        let spki = decode(&key["key"])?;
        let cert: [u8; 64] = decode(&key["cert"])?.try_into().map_err(|_| BAD_REPLY)?;
        crypto::verify_ed25519(&account.root()?, &key_statement(month, &spki), &cert).map_err(|_| BAD_REPLY)?;

        let public = PublicKeySha384PSSRandomized::from_der(&spki).map_err(|_| BAD_REPLY)?;
        let blinding = public.blind(&mut DefaultRng, MESSAGE).map_err(|_| BAD_REPLY)?;
        let asked = json!({ "account": account.number, "month": month, "blinded": STANDARD.encode(&blinding.blind_message.0) });
        let signed = self.ask_issuer(&account.issuer, "/passes", Some(asked))?;
        let blind_signature = BlindSignature(decode(&signed["signature"])?);
        let signature = public.finalize(&blind_signature, &blinding, MESSAGE).map_err(|_| BAD_REPLY)?;
        let randomizer = blinding.msg_randomizer.ok_or(BAD_REPLY)?.0;
        Ok(Pass { month, key: spki, cert, randomizer, signature: signature.0 }.encode())
    }

    /// One request to the account service, which is HTTPS but for one on this machine in tests.
    pub(super) fn ask_issuer(&self, issuer: &str, path: &str, body: Option<Value>) -> Result<Value> {
        let uri: hyper::Uri = issuer.parse().map_err(|_| Error::Invalid("that account service address is not one"))?;
        let host = uri.host().ok_or(Error::Invalid("that account service address has no host"))?.to_owned();
        let plain = uri.scheme_str() == Some("http") && cfg!(feature = "test-hooks") && host == "127.0.0.1";
        if uri.scheme_str() != Some("https") && !plain {
            return Err(Error::Invalid("the account service must be reached over HTTPS"));
        }
        let port = uri.port_u16().unwrap_or(443);
        let request = hyper::Request::builder()
            .method(if body.is_some() { "POST" } else { "GET" })
            .uri(path)
            .header(hyper::header::HOST, &host)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.map(|body| body.to_string()).unwrap_or_default())))
            .map_err(|_| BAD_REPLY)?;
        self.runtime.block_on(async {
            let exchange = async {
                let stream = tokio::net::TcpStream::connect((host.as_str(), port)).await?;
                let (status, body) = if plain {
                    send(TokioIo::new(stream), request).await?
                } else {
                    let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| BAD_REPLY)?;
                    let tls = tokio_rustls::TlsConnector::from(super::proxy::upstream_tls(None)?).connect(name, stream).await?;
                    send(TokioIo::new(tls), request).await?
                };
                match status {
                    200 => serde_json::from_slice(&body).map_err(|_| BAD_REPLY),
                    402 => Err(Error::NotApproved("this relay account has not paid for this month")),
                    404 => Err(Error::NotFound("that relay account".to_owned())),
                    _ => Err(Error::Peer("the account service refused that")),
                }
            };
            tokio::time::timeout(TIMEOUT, exchange).await.unwrap_or(Err(Error::Peer("the account service did not answer")))
        })
    }
}

const BAD_REPLY: Error = Error::Peer("the account service sent something unexpected");

fn decode(value: &Value) -> Result<Vec<u8>> {
    STANDARD.decode(value.as_str().ok_or(BAD_REPLY)?).map_err(|_| BAD_REPLY)
}

async fn send<T>(io: TokioIo<T>, request: hyper::Request<Full<Bytes>>) -> Result<(u16, Vec<u8>)>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await.map_err(|_| BAD_REPLY)?;
    tokio::spawn(connection);
    let response = sender.send_request(request).await.map_err(|_| BAD_REPLY)?;
    let status = response.status().as_u16();
    let body = http_body_util::Limited::new(response.into_body(), MAX_REPLY).collect().await.map_err(|_| BAD_REPLY)?.to_bytes();
    Ok((status, body.to_vec()))
}
