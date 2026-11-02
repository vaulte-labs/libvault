//! The interface every front end uses: the CLI, the desktop apps and the SDKs. It talks to the
//! broker, starting `lvd` when needed, and offers each operation as a typed call.

use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::audit::Event;
use crate::icon_image::{self, Icon};
use crate::import::Imported;
use crate::item::{Meta, Secret};
use crate::protocol::{CurrentCode, Envelope, Request, Response, SpaceCode, read_frame, write_frame};
use crate::recovery::RecoveryDraft;
use crate::sync::folder::BackupReport;
use crate::view::{GrantInfo, HistoryInfo, ItemInfo, StatusInfo, SyncReport};
use crate::{Error, ErrorCode, Result};
use zeroize::Zeroizing;

/// A healthy broker answers `status` at once, even during a touch prompt.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

pub(crate) fn socket_path(home: &Path) -> PathBuf {
    home.join("run").join("lv.sock")
}

/// The socket in a shared folder, for the vault's own sandboxed code.
pub(crate) const SHARED_SOCKET: &str = "lv.sock";

pub(crate) fn pid_path(home: &Path) -> PathBuf {
    home.join("run").join("lvd.pid")
}

/// Which code this is, so a broker left over from an upgrade can be told from one that is fine.
/// Not a path: two install folders holding one build are the same build.
pub(crate) const BUILD: &str = env!("LV_BUILD");

/// A program's environment, and real values to scrub from its output.
pub(crate) type RunEnvironment = (Vec<(String, String)>, Vec<String>);

/// How to reach a vault. The default suits a hardware vault with `lvd` installed.
#[derive(Debug, Default, Clone, Copy)]
pub struct Connect<'a> {
    /// For a vault with no secure hardware, what the person typed. It goes with every request and
    /// the broker keeps none of it, so anything that would need a touch needs this instead, and
    /// fails with `PassphraseNeeded` until an interface asks for it.
    pub passphrase: Option<&'a str>,
    /// A session from [`Client::grant`], limiting this client to that session's space.
    pub session: Option<&'a str>,
    /// Where `lvd` is, for an interface that bundles its own.
    pub daemon: Option<&'a Path>,
}

#[derive(Debug)]
pub struct Client {
    stream: UnixStream,
    session: Option<String>,
    passphrase: Option<Zeroizing<String>>,
    /// How to replace a broker that turns out not to know a request, once.
    upgrade: Option<Upgrade>,
}

impl Client {
    /// Connects to the vault at `home`, starting or replacing the broker if needed.
    pub fn connect(home: &Path, options: Connect<'_>) -> Result<Self> {
        if !crate::exists(home) {
            return Err(Error::NoVault);
        }
        let session = options.session.map(str::to_owned);
        let passphrase = options.passphrase.map(|passphrase| Zeroizing::new(passphrase.to_owned()));
        let socket = socket_path(home);
        let daemon = options.daemon.map(Path::to_path_buf).or_else(find_daemon);
        if let Ok(stream) = UnixStream::connect(&socket) {
            stream.set_read_timeout(Some(PROBE_TIMEOUT))?;
            // The probe carries no session, so an expired token can never look like a dead broker.
            let mut client = Self { stream, session: None, passphrase: None, upgrade: None };
            match client.status() {
                // A broker holds keys, and other interfaces may be using it, so only one that ranks
                // higher replaces it: a newer release, left over from an upgrade, or a signed build
                // for an unsigned one. Builds that rank the same have no order, and two interfaces
                // that each replaced the other would cut each other off.
                Ok(status) if !is_settled(&status.build) && daemon.as_deref().is_some_and(|daemon| outranks(daemon, &status.build)) => {
                    let _ = client.stop();
                    wait_for_exit(&socket);
                }
                Ok(status) => {
                    client.stream.set_read_timeout(None)?;
                    client.session = session;
                    client.passphrase = passphrase;
                    client.upgrade = daemon.map(|daemon| Upgrade { home: home.to_path_buf(), daemon, running: status.build });
                    return Ok(client);
                }
                // It accepted us but will not answer, so it can never recover by itself.
                Err(_) => kill_broker(home),
            }
        }
        let stream =
            start(home, &daemon.ok_or(Error::BrokerUnavailable("Vaulte's broker could not be found; is it installed beside this program?"))?)?;
        Ok(Self { stream, session, passphrase, upgrade: None })
    }

    /// Sends `request`. A broker that does not know it is older than this program, and is
    /// replaced once with this program's own `lvd` before the request goes again.
    fn call(&mut self, request: Request) -> Result<Response> {
        let mut reply = self.exchange(request.clone())?;
        if matches!(reply, Response::Error { code: ErrorCode::Outdated, .. }) && self.replace_outdated()? {
            reply = self.exchange(request)?;
        }
        match reply {
            Response::Error { code: ErrorCode::NeedsPassphrase, .. } => Err(Error::PassphraseNeeded),
            Response::Error { code, message } => Err(Error::Broker { code, message }),
            response => Ok(response),
        }
    }

    fn exchange(&mut self, request: Request) -> Result<Response> {
        let envelope = Envelope { session: self.session.clone(), passphrase: self.passphrase.clone(), request };
        write_frame(&mut self.stream, &envelope).and_then(|()| read_frame(&mut self.stream)).map_err(|error| match error.kind() {
            // A broker that went away took its keys with it. The next connection starts a new one.
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof => {
                Error::BrokerUnavailable("it stopped, which locked the vault. Try again")
            }
            _ => Error::Io(error),
        })
    }

    pub fn status(&mut self) -> Result<StatusInfo> {
        match self.call(Request::Status)? {
            Response::Status(status) => Ok(status),
            _ => Err(UNEXPECTED),
        }
    }

    pub fn unlock(&mut self) -> Result<()> {
        self.call(Request::Unlock).map(drop)
    }

    /// Locks now, ending every session.
    pub fn lock(&mut self) -> Result<()> {
        self.call(Request::Lock).map(drop)
    }

    /// Stops the broker, returning once it has gone: its reply comes first, and connecting in that
    /// gap would reach a broker about to exit.
    pub fn stop(&mut self) -> Result<()> {
        self.call(Request::Stop)?;
        // Either of these failing means it has already gone, which is what this is waiting for.
        let _ = self.stream.set_read_timeout(Some(PROBE_TIMEOUT));
        let _ = self.stream.read(&mut [0u8; 1]);
        Ok(())
    }

    pub fn spaces(&mut self) -> Result<Vec<String>> {
        match self.call(Request::Spaces)? {
            Response::Spaces { spaces } => Ok(spaces),
            _ => Err(UNEXPECTED),
        }
    }

    pub fn create_space(&mut self, name: &str) -> Result<()> {
        self.call(Request::SpaceAdd { name: name.to_owned() }).map(drop)
    }

    pub fn items(&mut self, space: Option<&str>) -> Result<Vec<ItemInfo>> {
        match self.call(Request::List { space: space.map(str::to_owned) })? {
            Response::Items { items } => Ok(items),
            _ => Err(UNEXPECTED),
        }
    }

    pub fn item(&mut self, space: Option<&str>, name: &str) -> Result<ItemInfo> {
        match self.call(Request::Show { space: space.map(str::to_owned), name: name.to_owned() })? {
            Response::Item { item } => Ok(item),
            _ => Err(UNEXPECTED),
        }
    }

    /// Adds an item. With `replace`, an existing one is replaced after a touch.
    pub fn add(&mut self, space: Option<&str>, meta: Meta, secret: Secret, replace: bool) -> Result<()> {
        self.call(Request::Add { space: space.map(str::to_owned), meta, secret, replace }).map(drop)
    }

    /// Imports items as one batch, after a touch. Never overwrites anything.
    pub fn import(&mut self, space: Option<&str>, items: Vec<(Meta, Secret)>) -> Result<Imported> {
        match self.call(Request::Import { space: space.map(str::to_owned), items })? {
            Response::Imported(imported) => Ok(imported),
            _ => Err(UNEXPECTED),
        }
    }

    pub fn remove(&mut self, space: Option<&str>, name: &str) -> Result<()> {
        self.remove_all(&[(space, name)])
    }

    /// Removes each item, by its space and name, as one change that one `undo` reverses.
    pub fn remove_all(&mut self, items: &[(Option<&str>, &str)]) -> Result<()> {
        let items = items.iter().map(|(space, name)| (space.map(str::to_owned), (*name).to_owned())).collect();
        self.call(Request::Remove { items }).map(drop)
    }

    /// Reverses this device's last change, returning how many items changed.
    pub fn undo(&mut self) -> Result<usize> {
        match self.call(Request::Undo)? {
            Response::Undone { count } => Ok(count),
            _ => Err(UNEXPECTED),
        }
    }

    pub fn history(&mut self, space: Option<&str>, name: &str) -> Result<Vec<HistoryInfo>> {
        match self.call(Request::History { space: space.map(str::to_owned), name: name.to_owned() })? {
            Response::History { versions } => Ok(versions),
            _ => Err(UNEXPECTED),
        }
    }

    /// Makes one of the versions `history` listed current again, after a touch. Works on a deleted
    /// item, and whatever came after that version stays in history.
    pub fn restore(&mut self, space: Option<&str>, name: &str, version: usize) -> Result<()> {
        self.call(Request::Restore { space: space.map(str::to_owned), name: name.to_owned(), version }).map(drop)
    }

    /// Returns plaintext. Needs a touch every time, even with a session.
    pub fn reveal(&mut self, space: Option<&str>, name: &str) -> Result<Secret> {
        match self.call(Request::Reveal { space: space.map(str::to_owned), name: name.to_owned() })? {
            Response::Secret { secret } => Ok(secret),
            _ => Err(UNEXPECTED),
        }
    }

    /// A login's current two-factor code, after a touch. The secret behind it never leaves the
    /// broker, so an interface can show codes without being able to make them.
    pub fn code(&mut self, space: Option<&str>, name: &str) -> Result<CurrentCode> {
        match self.call(Request::Code { space: space.map(str::to_owned), name: name.to_owned() })? {
            Response::Code(code) => Ok(code),
            _ => Err(UNEXPECTED),
        }
    }

    /// A site's saved icon as plain pixels, so an interface can draw it with no image decoder:
    /// any enrolled device can write an icon, and pixels need no parsing. `None` means there is
    /// none to show, so an interface draws a letter. Fails with `Locked` rather than asking anyone.
    pub fn icon(&mut self, space: Option<&str>, url: &str) -> Result<Option<Icon>> {
        match self.call(Request::Icon { space: space.map(str::to_owned), url: url.to_owned() })? {
            Response::Icon { png } => Ok(png.as_deref().and_then(icon_image::saved)),
            _ => Err(UNEXPECTED),
        }
    }

    /// Saves a site's icon for every device, from a PNG of at most 512 pixels as it came from the
    /// site. It is decoded here, in safe code, and drawn fresh at a small size, so an interface
    /// never has to decode what a website sent. A site that has an icon keeps it. Fails with
    /// `Locked` rather than asking anyone.
    pub fn save_icon(&mut self, space: Option<&str>, url: &str, image: &[u8]) -> Result<()> {
        let png = icon_image::prepare(image)?;
        self.call(Request::SaveIcon { space: space.map(str::to_owned), url: url.to_owned(), png }).map(drop)
    }

    /// Cards that have run out or soon will. Fails with `Locked` rather than asking anyone,
    /// because this is for checking in the background.
    pub fn expiring(&mut self) -> Result<Vec<ItemInfo>> {
        match self.call(Request::Expiring)? {
            Response::Items { items } => Ok(items),
            _ => Err(UNEXPECTED),
        }
    }

    /// Changes an item in place, after a touch, and its history keeps what it was. `meta` can
    /// rename it. With no `secret`, the current one stays. A login's setup key never reaches an
    /// interface, so a login secret with none keeps the one stored; `remove_code` takes it off.
    pub fn edit(&mut self, space: Option<&str>, name: &str, meta: Meta, secret: Option<Secret>) -> Result<()> {
        self.call(Request::Edit { space: space.map(str::to_owned), name: name.to_owned(), meta, secret }).map(drop)
    }

    /// Every login's current two-factor code, in `space` or every space, after one touch.
    pub fn codes(&mut self, space: Option<&str>) -> Result<Vec<SpaceCode>> {
        match self.call(Request::Codes { space: space.map(str::to_owned) })? {
            Response::Codes { codes } => Ok(codes),
            _ => Err(UNEXPECTED),
        }
    }

    /// Shows an item in the space `to` as well, after a touch. Every later change reaches both, and
    /// `remove` in either space takes it out of that one alone.
    pub fn link(&mut self, space: Option<&str>, name: &str, to: &str) -> Result<()> {
        self.call(Request::Link { space: space.map(str::to_owned), name: name.to_owned(), to: to.to_owned() }).map(drop)
    }

    /// Takes an item out of its space and into `to`, after a touch, as one change `undo` takes back.
    pub fn move_item(&mut self, space: Option<&str>, name: &str, to: &str) -> Result<()> {
        self.call(Request::Move { space: space.map(str::to_owned), name: name.to_owned(), to: to.to_owned() }).map(drop)
    }

    /// Takes two-factor off a login, after a touch. Its history keeps the setup key.
    pub fn remove_code(&mut self, space: Option<&str>, name: &str) -> Result<()> {
        self.call(Request::RemoveCode { space: space.map(str::to_owned), name: name.to_owned() }).map(drop)
    }

    /// Lets an env var be sent to `host` through the proxy.
    pub fn allow(&mut self, space: Option<&str>, name: &str, host: &str) -> Result<()> {
        self.call(Request::Allow { space: space.map(str::to_owned), name: name.to_owned(), host: host.to_owned() }).map(drop)
    }

    /// Prepares to run a program, returning its environment and any real values it was given,
    /// which must be scrubbed from its output. Lasts as long as this connection.
    pub(crate) fn start_run(&mut self, space: Option<&str>, command: &str, env: &[String], env_all: bool) -> Result<RunEnvironment> {
        let request = Request::Run { space: space.map(str::to_owned), command: command.to_owned(), env: env.to_vec(), env_all };
        match self.call(request)? {
            Response::Run { env, scrub } => Ok((env, scrub)),
            _ => Err(UNEXPECTED),
        }
    }

    /// Gives `agent` one space for `lifetime`, once the person approves on this device or any
    /// other. `reason` is the agent's own words, shown after the facts. Returns the token and id.
    pub fn grant(&mut self, space: Option<&str>, agent: &str, lifetime: Duration, reason: Option<&str>) -> Result<(String, String)> {
        let request = Request::Grant {
            space: space.map(str::to_owned),
            agent: agent.to_owned(),
            seconds: lifetime.as_secs(),
            reason: reason.map(str::to_owned),
        };
        match self.call(request)? {
            Response::Granted { token, id, .. } => Ok((token, id)),
            _ => Err(UNEXPECTED),
        }
    }

    pub fn grants(&mut self) -> Result<Vec<GrantInfo>> {
        match self.call(Request::Grants)? {
            Response::Grants { grants } => Ok(grants),
            _ => Err(UNEXPECTED),
        }
    }

    pub fn end_grant(&mut self, id: &str) -> Result<()> {
        self.call(Request::GrantRevoke { id: id.to_owned() }).map(drop)
    }

    /// Replaces the recovery key with `draft`, which should be confirmed first, and rotates every
    /// key. With two or more devices this needs the current recovery key too.
    pub fn rotate_recovery(&mut self, draft: &RecoveryDraft, recovery_words: Option<&str>) -> Result<()> {
        self.call(Request::RecoveryRotate { new_words: draft.words().to_string(), recovery: recovery_words.map(str::to_owned) }).map(drop)
    }

    /// Writes an encrypted archive that only the recovery key opens, after a touch.
    pub fn export_archive(&mut self, path: &Path) -> Result<()> {
        self.call(Request::Export { path: absolute(path)?, recovery: None, plaintext: false }).map(drop)
    }

    /// Writes everything in the clear, as JSON only this user can read, after a touch. With two
    /// or more devices this needs the recovery key too.
    pub fn export_plaintext(&mut self, path: &Path, recovery_words: Option<&str>) -> Result<()> {
        self.call(Request::Export { path: absolute(path)?, recovery: recovery_words.map(str::to_owned), plaintext: true }).map(drop)
    }

    /// Keeps an encrypted copy of the vault in `folder`, such as iCloud Drive or a USB drive.
    pub fn add_backup(&mut self, folder: &Path) -> Result<()> {
        self.call(Request::BackupAdd { path: absolute(folder)? }).map(drop)
    }

    pub fn remove_backup(&mut self, folder: &Path) -> Result<()> {
        self.call(Request::BackupRemove { path: absolute(folder)? }).map(drop)
    }

    /// Reads a backup back and compares it with this vault.
    pub fn verify_backup(&mut self, folder: &Path) -> Result<BackupReport> {
        match self.call(Request::BackupVerify { path: absolute(folder)? })? {
            Response::Verified(report) => Ok(report),
            _ => Err(UNEXPECTED),
        }
    }

    /// Exchanges logs with every backup folder and known device now, and says how that went.
    pub fn sync_now(&mut self) -> Result<SyncReport> {
        match self.call(Request::SyncNow)? {
            Response::Synced(report) => Ok(report),
            _ => Err(UNEXPECTED),
        }
    }

    /// Settles a conflict from two devices changing the roster at once, by accepting the side
    /// that `words` belong to. Needed only when `status` reports one. Returns how many devices'
    /// logs that brought in, which is none if there was nothing to settle.
    pub fn resolve_conflict(&mut self, words: &str) -> Result<usize> {
        match self.call(Request::ResolveConflict { words: words.to_owned() })? {
            Response::Settled { devices_updated } => Ok(devices_updated),
            _ => Err(UNEXPECTED),
        }
    }

    /// Erases this device's keys and data, after a touch. `device_name` must match this device's
    /// name, so it cannot happen by accident. Other devices and backups are untouched.
    pub fn wipe(&mut self, device_name: &str) -> Result<()> {
        match self.call(Request::Wipe { device_name: device_name.to_owned() })? {
            Response::Wiped => Ok(()),
            _ => Err(UNEXPECTED),
        }
    }

    pub fn audit(&mut self) -> Result<Vec<Event>> {
        match self.call(Request::Audit)? {
            Response::Audit { events } => Ok(events),
            _ => Err(UNEXPECTED),
        }
    }
}

fn absolute(path: &Path) -> Result<PathBuf> {
    Ok(if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir()?.join(path) })
}

const UNEXPECTED: Error = Error::BrokerUnavailable("it sent an unexpected reply");

fn kill_broker(home: &Path) {
    if let Ok(pid) = std::fs::read_to_string(pid_path(home)) {
        let _ = Command::new("/bin/kill").args(["-KILL", pid.trim()]).status();
    }
    wait_for_exit(&socket_path(home));
}

fn wait_for_exit(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while UnixStream::connect(socket).is_ok() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Starts `daemon` for `home` and connects once it listens.
fn start(home: &Path, daemon: &Path) -> Result<UnixStream> {
    wait_for_release(home);
    spawn(home, daemon)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Ok(stream) = UnixStream::connect(socket_path(home)) {
            return Ok(stream);
        }
        if Instant::now() > deadline {
            return Err(Error::BrokerUnavailable("it did not start"));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// Waits for a broker that is shutting down to let go of the vault, which it does only as its
/// process ends, after its socket has gone. A new one started before then could not open it.
fn wait_for_release(home: &Path) {
    let Ok(lock) = std::fs::OpenOptions::new().write(true).create(true).truncate(false).open(home.join("local").join("lock")) else { return };
    let deadline = Instant::now() + Duration::from_secs(2);
    while lock.try_lock().is_err() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn spawn(home: &Path, daemon: &Path) -> Result<()> {
    // The broker outlives whoever happened to start it, so it takes nothing from them.
    let mut command = Command::new(daemon);
    // Its own process group, so Ctrl-C in whoever started it stops that and not this. And not their
    // folder, which it would otherwise hold open for as long as it runs.
    command.env_clear().env("LV_HOME", home).process_group(0).current_dir("/");
    let kept: &[&str] = if cfg!(feature = "test-hooks") { &["HOME", "LV_DISCOVERY_PORT", "LV_TEST_PASSPHRASE"] } else { &["HOME"] };
    for name in kept {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::BrokerUnavailable("lvd could not be started; is it installed beside this program?"))?;
    Ok(())
}

#[path = "client_browser.rs"]
mod browser;

#[path = "client_devices.rs"]
mod devices;

#[path = "client_builds.rs"]
mod builds;
use builds::{Upgrade, find_daemon, is_settled, outranks};
