//! A real vault and a real `lvd`, driven only through the public API. If a flow cannot be written
//! here, an interface could not do it either.
#![allow(dead_code, reason = "each test file uses part of this")]
#![allow(unsafe_code, reason = "setting an environment variable once, before any broker starts")]

pub mod chrome;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Once;
use std::time::Duration;

use libvault::item::{Meta, Secret};
use libvault::{Client, Connect, Cost, ErrorCode, Recovery, Setup};
use tempfile::TempDir;

pub const PASSPHRASE: &str = "test passphrase";
/// In every test's environment, to show what does and does not reach a broker.
pub const CANARY: &str = "LV_TEST_CANARY";
pub const LVD: &str = env!("CARGO_BIN_EXE_lvd");

pub struct Vault {
    pub dir: TempDir,
    pub home: PathBuf,
    pub words: String,
}

/// Gives this test binary its own discovery port, so that test runs on one machine, as under
/// cargo-mutants, do not hear each other's devices.
fn private_discovery_port() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let port = 20_000 + std::process::id() % 40_000;
        // SAFETY: `Once` runs this before this binary starts any broker, and nothing here reads
        // the environment at the same moment.
        unsafe { std::env::set_var("LV_DISCOVERY_PORT", port.to_string()) };
        // SAFETY: as above.
        unsafe { std::env::set_var(CANARY, "1") };
        // SAFETY: as above. Stands in for a person at another device, who cannot be asked here.
        unsafe { std::env::set_var("LV_TEST_PASSPHRASE", PASSPHRASE) };
    });
}

pub fn options(session: Option<&str>) -> Connect<'_> {
    private_discovery_port();
    Connect { passphrase: Some(PASSPHRASE), session, daemon: Some(Path::new(LVD)) }
}

pub fn env(value: &str) -> Secret {
    Secret::Env { value: value.to_owned() }
}

pub fn code<T: std::fmt::Debug>(result: libvault::Result<T>) -> ErrorCode {
    result.expect_err("expected a refusal").code()
}

impl Vault {
    pub fn new() -> Self {
        private_discovery_port();
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("vault");
        let setup = Setup::with_passphrase(PASSPHRASE, Cost::FAST).unwrap();
        let words = setup.recovery().words().to_string();
        setup.finish(&home, "Test Mac").unwrap();
        Self { dir, home, words }
    }

    /// Starts the broker the way a hostile process could, with whatever environment it likes.
    /// A broker just told to stop can hold the vault a moment longer, and one started then refuses
    /// to run, so this waits until the broker running is the one it started.
    pub fn start_broker_with_env(&self, name: &str, value: &Path) {
        for _ in 0..200 {
            let mut child = Command::new(LVD).env("LV_HOME", &self.home).env(name, value).stdin(Stdio::null()).spawn().unwrap();
            let pid = child.id().to_string();
            while child.try_wait().unwrap().is_none() {
                if fs::read_to_string(self.home.join("run/lvd.pid")).is_ok_and(|running| running == pid) {
                    std::thread::spawn(move || child.wait());
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the broker never started");
    }

    pub fn client(&self) -> Client {
        Client::connect(&self.home, options(None)).unwrap()
    }

    pub fn session_client(&self, token: &str) -> Client {
        Client::connect(&self.home, options(Some(token))).unwrap()
    }

    pub fn add_env(&self, name: &str, value: &str, space: Option<&str>) {
        self.client().add(space, Meta::env(name), env(value), false).unwrap();
    }

    pub fn space(&self, name: &str) {
        self.client().create_space(name).unwrap();
    }

    pub fn session(&self, space: &str, agent: &str) -> String {
        self.client().grant(Some(space), agent, std::time::Duration::from_secs(3600), None).unwrap().0
    }

    /// Cuts direct contact with other devices, as if out of range. Brokers otherwise find each
    /// other by themselves, including in tests.
    pub fn go_offline(&self) {
        fs::write(self.home.join("offline"), "").unwrap();
    }

    pub fn deny_touches(&self) {
        fs::write(self.home.join("deny"), "").unwrap();
    }

    pub fn allow_touches(&self) {
        fs::remove_file(self.home.join("deny")).unwrap();
    }

    pub fn file(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.dir.path().join(name);
        fs::write(&path, contents).unwrap();
        path
    }
}

/// A second device: this vault restored from `source` on another machine.
pub fn restored(source: &Path, words: &str, name: &str) -> Vault {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    Recovery::open(source, words).unwrap().finish_with_passphrase(PASSPHRASE, Cost::FAST, &home, name).unwrap();
    let vault = Vault { dir, home, words: words.to_owned() };
    vault.go_offline();
    vault
}

/// The one log file in a device's home that holds `device`-agnostic bytes, for tampering.
pub fn backup_logs(root: &Path) -> Vec<PathBuf> {
    let folder = fs::read_dir(root).unwrap().flatten().find(|entry| entry.file_name().to_string_lossy().starts_with("vaulty-")).unwrap().path();
    // A sync in the background may be halfway through writing one, under a temporary name.
    let logs = fs::read_dir(folder.join("log")).unwrap().flatten().map(|entry| entry.path());
    logs.filter(|path| path.extension().is_some_and(|extension| extension == "lvl")).collect()
}

impl Drop for Vault {
    fn drop(&mut self) {
        if let Ok(mut client) = Client::connect(&self.home, options(None)) {
            let _ = client.stop();
        }
    }
}
