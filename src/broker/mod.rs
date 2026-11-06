//! The per-user process that holds keys. Interfaces ask it to do things, and apart from an
//! approved `reveal`, plaintext never leaves it.
//!
//! All mutable state lives in one `Core` behind one lock, which is never held while waiting for
//! a person. So there is no lock order to get wrong, locking is atomic, and `status` always
//! answers quickly, which is how a client tells a busy broker from a wedged one.

mod accounts;
mod agent_browser;
mod agent_passkeys;
mod asking;
mod asks;
mod browser;
mod codes;
mod fill_requests;
mod grants;
mod handlers;
mod history;
mod linking;
mod login;
mod manage;
mod passkeys;
mod peers;
mod policy;
mod proxy;
mod runs;
mod shared_socket;
mod signup;
mod spaces;
mod sync;

use std::collections::HashSet;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use crate::client::{pid_path, socket_path};
use crate::device::Device;
use crate::locking::LockSettings;
use crate::store::log::now_ms;
use zeroize::Zeroizing;

#[cfg(feature = "fuzz")]
pub(crate) use asks::fuzz_ask;

use crate::net::channel::Channel;
use crate::protocol::{Envelope, Request, Response, read_frame, write_frame};
use crate::{Error, Result, Vault};
use grants::Grants;

const UNLOCK_REASON: &str = "unlock your vault";

/// Everything that changes. Grants exist only while unlocked: `lock` is the one way out.
#[derive(Debug)]
struct Core {
    vault: Vault,
    grants: Grants,
    /// By the wall clock. `Instant` stops while a Mac sleeps, so with it a laptop opened the next
    /// morning would still count as recently used.
    last_used: u64,
    /// When this device's vault locks by itself, as its person chose.
    settings: LockSettings,
    places: sync::Places,
    runs: Vec<runs::LiveRun>,
    /// How many times this has locked, so an unlock can tell if one landed during its prompt.
    locks: u64,
    /// What the vault's own app has been shown codes for since this unlocked. See `current_codes`.
    codes_shown: HashSet<String>,
}

impl Core {
    fn lock(&mut self) {
        self.locks += 1;
        self.vault.lock();
        self.grants.clear();
        self.codes_shown.clear();
        self.end_runs(|_| true);
    }

    /// Stops every run whose grant `ended` says is over, and forgets runs that have finished. A
    /// run that outlived its access would go on using secrets that were meant to be dropped.
    fn end_runs(&mut self, ended: impl Fn(Option<&str>) -> bool) {
        self.runs.retain(|run| match run.proxy.upgrade() {
            Some(proxy) if ended(run.grant.as_deref()) => {
                proxy.stop();
                false
            }
            Some(_) => true,
            None => false,
        });
    }

    /// Ends runs under grants that have expired. A program using secrets counts as using the vault.
    fn check_runs(&mut self) {
        let live: Vec<String> = self.grants.list().into_iter().map(|grant| grant.id).collect();
        self.end_runs(|grant| grant.is_some_and(|id| !live.iter().any(|live| live == id)));
        if !self.runs.is_empty() {
            self.last_used = now_ms();
        }
    }

    fn is_due_to_lock(&self, screen_locked: bool, now: u64) -> bool {
        self.vault.is_unlocked() && self.settings.is_due(self.last_used, now, screen_locked)
    }
}

#[derive(Debug)]
pub struct Broker {
    core: Mutex<Core>,
    /// Held across an unlock prompt, so concurrent clients share one prompt. Always taken before
    /// `core`, never after.
    unlocking: Mutex<()>,
    device: Arc<dyn Device>,
    home: PathBuf,
    runtime: tokio::runtime::Runtime,
    /// Works while locked: sync moves only ciphertext, and this proves only which device it is.
    sync_key: Zeroizing<[u8; 32]>,
    sync_port: OnceLock<u16>,
    asks: asks::AskGate,
}

/// What belongs to one client's connection, and ends with it.
#[derive(Debug, Default)]
pub(crate) struct Connection {
    /// Whether the other end is one of the vault's own apps, signed and unchanged.
    app: bool,
    runs: Vec<runs::Run>,
    /// A pairing and the words its person is comparing.
    pairing: Option<(Channel, [String; 3])>,
}

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic aborts in release builds, so a poisoned lock holds no half-done work.
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Removes what a crashed broker left. Run folders hold only trust files for dead proxies.
fn clear_stale_runs(home: &Path) {
    let Ok(entries) = std::fs::read_dir(home.join("run")) else { return };
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// Runs the broker until asked to stop. Interfaces reach this through `lvd`, which
/// `Client::connect` starts on demand.
/// What `lvd --build` prints and status reports, for a client to tell whether starting this
/// broker would change anything. A test can stand in another build.
pub fn build() -> String {
    #[cfg(feature = "test-hooks")]
    if let Some(build) = std::env::var_os("LV_TEST_BUILD") {
        return build.to_string_lossy().into_owned();
    }
    match signed_by() {
        Some(team) => format!("{}+{team}", crate::client::BUILD),
        None => crate::client::BUILD.to_owned(),
    }
}

#[cfg(target_os = "macos")]
fn signed_by() -> Option<String> {
    crate::device::enclave::own_team()
}

#[cfg(not(target_os = "macos"))]
fn signed_by() -> Option<String> {
    None
}

pub fn run(home: &Path) -> Result<()> {
    crate::sys::harden_process();
    let vault = Vault::open(home, None)?;
    clear_stale_runs(home);

    let socket = socket_path(home);
    let _ = std::fs::remove_file(&socket);
    // Restored or copied folders can arrive with looser modes than they were made with.
    std::fs::set_permissions(socket.parent().ok_or(Error::NoVault)?, Permissions::from_mode(0o700))?;
    let listener = UnixListener::bind(&socket)?;
    std::fs::set_permissions(&socket, Permissions::from_mode(0o600))?;
    std::fs::write(pid_path(home), std::process::id().to_string())?;

    let sync_key = std::fs::read(home.join("local").join(crate::vault::SYNC_KEY_FILE))?;
    let sync_key: Zeroizing<[u8; 32]> = Zeroizing::new(sync_key.as_slice().try_into().map_err(|_| Error::Corrupt("bad sync key"))?);

    let now = now_ms();
    let broker = Arc::new(Broker {
        device: vault.device(),
        core: Mutex::new(Core {
            vault,
            grants: Grants::default(),
            last_used: now,
            settings: LockSettings::read(home),
            places: sync::Places::default(),
            runs: Vec::new(),
            locks: 0,
            codes_shown: HashSet::new(),
        }),
        unlocking: Mutex::new(()),
        home: home.to_path_buf(),
        runtime: tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?,
        sync_key,
        sync_port: OnceLock::new(),
        asks: asks::AskGate::new(),
    });

    let watcher = Arc::clone(&broker);
    std::thread::spawn(move || watcher.watch_for_lock());
    let syncer = Arc::clone(&broker);
    std::thread::spawn(move || syncer.keep_backups_current());
    let peers = Arc::clone(&broker);
    std::thread::spawn(move || peers.keep_peers_current());

    shared_socket::listen(&broker, home);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let broker = Arc::clone(&broker);
        std::thread::spawn(move || {
            let _ = broker.serve(stream);
        });
    }
    Ok(())
}

impl Broker {
    fn core(&self) -> MutexGuard<'_, Core> {
        guard(&self.core)
    }

    /// The core, if the vault is open. Anything after a prompt uses this and not `unlocked`: a lock
    /// always wins, so a step that has been waiting on a person must not quietly reopen the vault.
    fn open_core(&self) -> Result<MutexGuard<'_, Core>> {
        let core = self.core();
        if core.vault.is_unlocked() { Ok(core) } else { Err(Error::Locked) }
    }

    /// Returns the core, asking the person first if the vault is locked. The core is not held
    /// during the prompt, and a lock that lands during it cancels this unlock.
    fn unlocked(&self) -> Result<MutexGuard<'_, Core>> {
        let core = self.core();
        if core.vault.is_unlocked() {
            return Ok(core);
        }
        drop(core);

        let _one_prompt = guard(&self.unlocking);
        let core = self.core();
        if core.vault.is_unlocked() {
            return Ok(core);
        }
        let request = core.vault.unlock_request()?;
        let locks = core.locks;
        drop(core);

        self.before_prompt()?;
        let opened = request.open(UNLOCK_REASON)?;

        let mut core = self.core();
        if core.locks != locks {
            return Err(Error::Locked);
        }
        core.vault.install(opened)?;
        core.vault.repair()?;
        core.last_used = now_ms();
        Ok(core)
    }

    /// Lets end-to-end tests stand in for a person who refuses or is slow to answer.
    fn before_prompt(&self) -> Result<()> {
        self.before_prompt_unless(&std::sync::atomic::AtomicBool::new(false))
    }

    fn serve(&self, mut stream: UnixStream) -> Result<()> {
        // The folder already keeps other users out. This holds even if that folder is wrong.
        if crate::sys::peer_user(&stream) != Some(crate::sys::this_user()) {
            return Ok(());
        }
        // Dropped with the connection, so a run's proxy can never outlive the client that asked.
        let mut connection = Connection { app: self.is_own_app(&stream), ..Connection::default() };
        loop {
            let envelope: Envelope = match read_frame(&mut stream) {
                Ok(envelope) => envelope,
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                // A whole frame that is no request this broker knows, from a newer program, which
                // can replace it once it hears so.
                Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
                    let message = "this broker is older than the program asking, and does not know that request".to_owned();
                    write_frame(&mut stream, &Response::Error { code: crate::ErrorCode::Outdated, message })?;
                    continue;
                }
                Err(error) => return Err(Error::Io(error)),
            };
            let stop = matches!(envelope.request, Request::Stop);
            let response = self.handle(envelope, &mut connection);
            let exiting = (stop && matches!(response, Response::Ok)) || matches!(response, Response::Wiped);
            if exiting {
                // Off the path before the reply, so nothing that hears it can still connect: the
                // listener closes only as the process ends, after this connection may have.
                let _ = std::fs::remove_file(socket_path(&self.home));
            }
            write_frame(&mut stream, &response)?;
            if exiting {
                std::process::exit(0);
            }
        }
    }

    /// Tests cannot sign themselves as the app, so they say when to count a caller as one.
    fn is_own_app(&self, stream: &UnixStream) -> bool {
        if cfg!(feature = "test-hooks") && self.home.join("trust-callers").exists() {
            return true;
        }
        own_app(stream)
    }

    /// Tests set this themselves, so they do not depend on whether anyone is at the Mac.
    fn screen_is_locked(&self) -> bool {
        if cfg!(feature = "test-hooks") {
            return self.home.join("screen-locked").exists();
        }
        screen_locked()
    }

    fn watch_for_lock(&self) {
        loop {
            std::thread::sleep(Duration::from_secs(2));
            let screen_locked = self.screen_is_locked();
            let mut core = self.core();
            // Nobody can reach a broker whose socket has gone, as when its vault was deleted, so it
            // ends, and the keys it held go with it instead of staying in memory for good.
            if !socket_path(&self.home).exists() {
                core.lock();
                std::process::exit(0);
            }
            core.check_runs();
            // A server opens again by itself, so locking it would only end its agents' grants.
            if self.device.has_person() && core.is_due_to_lock(screen_locked, now_ms()) {
                core.lock();
            }
        }
    }
}

/// The vault's own apps, which may use it once it is unlocked without a touch for every use.
#[cfg(target_os = "macos")]
const OWN_APPS: &std::ffi::CStr = c"dev.vaulty.mac,dev.vaulty.mac.autofill";

#[cfg(target_os = "macos")]
fn own_app(stream: &UnixStream) -> bool {
    crate::sys::peer_audit_token(stream).is_some_and(|token| crate::device::enclave::peer_is_app(&token, OWN_APPS))
}

/// No signature to check, so no caller is trusted beyond its user.
#[cfg(not(target_os = "macos"))]
fn own_app(_stream: &UnixStream) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn screen_locked() -> bool {
    crate::device::enclave::screen_locked()
}

#[cfg(not(target_os = "macos"))]
fn screen_locked() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::software::{Cost, Software};

    fn core_unlocked_at(now: u64) -> (tempfile::TempDir, Core) {
        let dir = tempfile::tempdir().unwrap();
        let setup = crate::Setup::new(Software::generate("p", Cost::FAST).unwrap());
        let mut vault = setup.create(&dir.path().join("vault"), "Mac").unwrap();
        vault.unlock("test").unwrap();
        let core = Core {
            vault,
            grants: Grants::default(),
            last_used: now,
            settings: LockSettings::default(),
            places: sync::Places::default(),
            runs: Vec::new(),
            locks: 0,
            codes_shown: HashSet::new(),
        };
        (dir, core)
    }

    #[test]
    fn a_vault_locks_by_the_clock_however_long_the_machine_slept() {
        let (_dir, core) = core_unlocked_at(1_000_000);
        let hour = 60 * 60 * 1000;
        assert!(!core.is_due_to_lock(false, 1_000_000 + hour));
        assert!(core.is_due_to_lock(false, 1_000_000 + hour + 1));
    }

    #[test]
    fn a_locked_vault_is_never_due() {
        let (_dir, mut core) = core_unlocked_at(1_000_000);
        core.lock();
        assert!(!core.is_due_to_lock(true, u64::MAX));
    }
}
