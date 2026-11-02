//! Messages between `vlt` and its broker: length-prefixed JSON over a private Unix socket.

use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::DeviceInfo;
use crate::audit::Event;
use crate::error::ErrorCode;
use crate::item::{Meta, Secret};
use crate::sync::folder::BackupReport;
use crate::view::{GrantInfo, HistoryInfo, ItemInfo, StatusInfo};

/// Refuses absurd frames from a confused or hostile peer.
const MAX_FRAME: usize = 1 << 26;

/// Where a signed-in session goes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginInto {
    /// A local debugging address, such as `http://127.0.0.1:9222`.
    Browser(String),
    /// A Playwright storage state file, which must not exist yet.
    StateFile(PathBuf),
}

/// How a new account will prove who signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignUpWith {
    Password,
    Passkey,
}

/// A login as the system's autofill may suggest it, even while the vault is locked: a site and a
/// username, never a secret. Picking one still goes through `fill` and its touch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutofillIdentity {
    pub site: String,
    pub username: Option<String>,
    pub space: String,
    pub name: String,
}

/// A site asking for a new passkey. `origin` comes from the browser, not the page, and `exclude`
/// lists the site's own credentials for this person, so that none is made twice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyRequest {
    pub space: Option<String>,
    pub origin: String,
    pub rp_id: String,
    pub user_name: String,
    pub user_handle: Vec<u8>,
    #[serde(default)]
    pub exclude: Vec<Vec<u8>>,
}

/// A passkey that could sign in on a page. Holds nothing secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyOption {
    pub space: String,
    pub name: String,
    pub user_name: Option<String>,
}

/// What a site is sent back when a passkey is made for it. The private key stays in the broker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewPasskey {
    /// The item it was saved as.
    pub name: String,
    pub credential_id: Vec<u8>,
    /// DER, as a browser's `getPublicKey()` gives it.
    pub public_key: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub attestation_object: Vec<u8>,
}

/// A passkey's signature for one sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyAssertion {
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    /// ES256, in DER.
    pub signature: Vec<u8>,
}

/// Something that could fill on a page. Holds nothing secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillOption {
    pub space: String,
    pub name: String,
    pub kind: crate::item::Kind,
    pub username: Option<String>,
    pub hint: Option<String>,
}

/// A login's two-factor code as it stands. The secret behind it stays in the broker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentCode {
    pub code: String,
    pub seconds_left: u64,
}

/// One login's code, and where it is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceCode {
    pub space: String,
    pub name: String,
    #[serde(flatten)]
    pub code: CurrentCode,
}

/// What to put on a page. A login carries a current code instead of its two-factor secret.
#[derive(Debug, Serialize, Deserialize)]
pub struct Filled {
    pub username: Option<String>,
    pub secret: Secret,
    pub code: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub session: Option<String>,
    /// On a vault with no secure hardware, what stands in for a touch on this request.
    pub passphrase: Option<Zeroizing<String>>,
    pub request: Request,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    Unlock,
    Lock,
    Stop,
    Spaces,
    SpaceAdd {
        name: String,
    },
    List {
        space: Option<String>,
    },
    Show {
        space: Option<String>,
        name: String,
    },
    Add {
        space: Option<String>,
        meta: Meta,
        secret: Secret,
        replace: bool,
    },
    Import {
        space: Option<String>,
        items: Vec<(Meta, Secret)>,
    },
    /// Each item by its space and name, removed as one change.
    Remove {
        items: Vec<(Option<String>, String)>,
    },
    Undo,
    History {
        space: Option<String>,
        name: String,
    },
    Restore {
        space: Option<String>,
        name: String,
        version: usize,
    },
    Reveal {
        space: Option<String>,
        name: String,
    },
    Code {
        space: Option<String>,
        name: String,
    },
    Codes {
        space: Option<String>,
    },
    RemoveCode {
        space: Option<String>,
        name: String,
    },
    Expiring,
    Icon {
        space: Option<String>,
        url: String,
    },
    SaveIcon {
        space: Option<String>,
        url: String,
        png: Vec<u8>,
    },
    Edit {
        space: Option<String>,
        name: String,
        meta: Meta,
        secret: Option<Secret>,
    },
    Link {
        space: Option<String>,
        name: String,
        to: String,
    },
    Move {
        space: Option<String>,
        name: String,
        to: String,
    },
    Allow {
        space: Option<String>,
        name: String,
        host: String,
    },
    Run {
        space: Option<String>,
        command: String,
        env: Vec<String>,
        env_all: bool,
    },
    Grant {
        space: Option<String>,
        agent: String,
        seconds: u64,
        reason: Option<String>,
    },
    Grants,
    GrantRevoke {
        id: String,
    },
    Audit,
    Devices,
    DeviceRemove {
        name: String,
        recovery: Option<String>,
    },
    RecoveryRotate {
        new_words: String,
        recovery: Option<String>,
    },
    Export {
        path: PathBuf,
        recovery: Option<String>,
        plaintext: bool,
    },
    BackupAdd {
        path: PathBuf,
    },
    BackupRemove {
        path: PathBuf,
    },
    BackupVerify {
        path: PathBuf,
    },
    Login {
        space: Option<String>,
        name: String,
        into: LoginInto,
    },
    /// `into` is the local debugging address of the browser holding the sign-up page.
    SignUp {
        space: Option<String>,
        site: String,
        into: String,
        with: SignUpWith,
    },
    FillOptions {
        origin: String,
    },
    Fill {
        space: String,
        name: String,
        origin: String,
    },
    AutofillIdentities,
    PasskeyOptions {
        origin: String,
        allow: Vec<Vec<u8>>,
    },
    CreatePasskey(PasskeyRequest),
    SignPasskey {
        space: String,
        name: String,
        origin: String,
        client_data_hash: Vec<u8>,
    },
    LockSettings,
    SetLockSettings {
        settings: crate::LockSettings,
    },
    SyncNow,
    PeerAdd {
        address: String,
    },
    PairBegin {
        address: Option<String>,
    },
    /// `spaces` are what a server joining may hold. None is the whole vault.
    PairConfirm {
        recovery: Option<String>,
        spaces: Option<Vec<String>>,
    },
    ResolveConflict {
        words: String,
    },
    Wipe {
        device_name: String,
    },
    /// Starts paying for a relay, making an account if this device has none. No `issuer` is the
    /// relay Vaulte hosts.
    RelaySubscribe {
        email: Option<String>,
        issuer: Option<RelayIssuer>,
    },
    /// Uses an account the person already has, as on a second device.
    RelayAccount {
        number: String,
        issuer: Option<RelayIssuer>,
    },
    RelayStatus,
}

/// An account service other than the one Vaulte runs, for a relay someone runs themselves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayIssuer {
    pub url: String,
    /// The root's Ed25519 public key, in hex.
    pub root: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Status(StatusInfo),
    Spaces { spaces: Vec<String> },
    Items { items: Vec<ItemInfo> },
    Item { item: ItemInfo },
    Secret { secret: Secret },
    Code(CurrentCode),
    Codes { codes: Vec<SpaceCode> },
    Icon { png: Option<Vec<u8>> },
    Granted { token: String, id: String, seconds: u64 },
    Grants { grants: Vec<GrantInfo> },
    Undone { names: Vec<String> },
    Devices { devices: Vec<DeviceInfo> },
    Removed { exposed: Vec<String> },
    Verified(BackupReport),
    LoggedIn { cookies: usize },
    SignedUp { name: String },
    FillOptions { options: Vec<FillOption> },
    AutofillIdentities { identities: Vec<AutofillIdentity> },
    PasskeyOptions { options: Vec<PasskeyOption> },
    NewPasskey(NewPasskey),
    PasskeyAssertion(PasskeyAssertion),
    LockSettings(crate::LockSettings),
    Filled(Box<Filled>),
    Pairing { words: [String; 3] },
    Paired { name: String },
    Wiped,
    Synced(crate::view::SyncReport),
    Settled { devices_updated: usize },
    Run { env: Vec<(String, String)>, scrub: Vec<String> },
    Imported(crate::import::Imported),
    History { versions: Vec<HistoryInfo> },
    Audit { events: Vec<Event> },
    Checkout { account: String, url: String },
    RelayAccount { account: Option<String>, paid_until: Option<u64> },
    Error { code: ErrorCode, message: String },
}

pub fn write_frame<T: Serialize>(stream: &mut impl Write, message: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(message)?;
    let length = u32::try_from(bytes.len()).map_err(|_| io::Error::other("message too large"))?;
    stream.write_all(&length.to_le_bytes())?;
    stream.write_all(&bytes)
}

pub fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut impl Read) -> io::Result<T> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(io::Error::other("message too large"));
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes)?;
    Ok(serde_json::from_slice(&bytes)?)
}
