//! Which broker build serves a vault, and replacing one that is left over. A broker holds keys,
//! and other interfaces may be using it, so it is replaced only by one that ranks higher, or, once,
//! when it turns out not to know a request this program sends.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use super::{BUILD, Client, socket_path, start, wait_for_exit};
use crate::Result;

/// The broker as installed. The system names a program by its file when it asks about it, as a
/// firewall does, so this is the name people see. Cargo still builds it as `lvd`.
const DAEMON: &str = "Vaulte";

/// The broker an installed program starts, or none. Always an absolute path, because a relative
/// one would mean something different to a broker running from `/`.
pub(super) fn find_daemon() -> Option<PathBuf> {
    installed_daemon(&std::env::current_exe().ok()?, std::env::var_os("PATH").as_deref())
}

/// Where an app bundle keeps its helpers, then beside this executable, then on `PATH`. An app
/// whose own executable has the broker's name must never start itself instead.
fn installed_daemon(exe: &Path, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let folder = exe.parent();
    let helpers = folder.and_then(Path::parent).map(|contents| contents.join("Helpers").join(DAEMON));
    let itself = exe.file_name().is_some_and(|name| name.eq_ignore_ascii_case(DAEMON));
    let sibling = folder.filter(|_| !itself).map(|folder| folder.join(DAEMON));
    let on_path = path.iter().flat_map(std::env::split_paths).map(|folder| folder.join(DAEMON));
    helpers.into_iter().chain(sibling).chain(on_path).find(|path| path.is_absolute() && path.is_file())
}

/// What a client needs to replace its broker with its own `lvd` later.
#[derive(Debug)]
pub(super) struct Upgrade {
    pub home: PathBuf,
    pub daemon: PathBuf,
    /// The build the broker reported when this client connected.
    pub running: String,
}

/// A build's release, as `[1, 0, 0]` from `1.0.0-164b9dc4c14d67bc`.
pub(super) fn release_of(build: &str) -> Option<[u64; 3]> {
    let mut numbers = build.split('-').next()?.split('.').map(|number| number.parse().ok());
    Some([numbers.next()??, numbers.next()??, numbers.next()??])
}

/// A build's code, without the team that signed it: `1.0.0-164b9dc4c14d67bc+TEAM` is this code.
fn code_of(build: &str) -> &str {
    build.split_once('+').map_or(build, |(code, _)| code)
}

/// The release first, then whether a team signed it, since only a signed broker can open the
/// shared socket that sandboxed callers need.
fn rank(build: &str) -> Option<([u64; 3], bool)> {
    Some((release_of(build)?, build.contains('+')))
}

/// A broker of this very code, signed, which nothing of this release can outrank, so no `lvd`
/// needs asking.
pub(super) fn is_settled(running: &str) -> bool {
    code_of(running) == BUILD && running.contains('+')
}

/// Whether starting `daemon` would bring something that outranks the broker running `running`.
pub(super) fn outranks(daemon: &Path, running: &str) -> bool {
    let theirs = build_of(daemon).as_deref().and_then(rank);
    theirs.zip(rank(running)).is_some_and(|(theirs, running)| theirs > running)
}

/// The build `daemon` would start. A home that cannot exist keeps an `lvd` from before `--build`
/// from starting a broker, so it fails and counts as unknown.
fn build_of(daemon: &Path) -> Option<String> {
    let output = Command::new(daemon)
        .arg("--build")
        .env_clear()
        .env("LV_HOME", "/dev/null/no-vault")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

impl Client {
    /// Replaces a broker that did not know a request with this program's own `lvd`, once. Not with
    /// one that ranks lower, such as an unsigned build for a signed one, which would only trade one
    /// gap for another.
    pub(super) fn replace_outdated(&mut self) -> Result<bool> {
        let Some(Upgrade { home, daemon, running }) = self.upgrade.take() else { return Ok(false) };
        let ranks_lower = build_of(&daemon).as_deref().and_then(rank).zip(rank(&running)).is_none_or(|(theirs, running)| theirs < running);
        if ranks_lower {
            return Ok(false);
        }
        let _ = self.stop();
        wait_for_exit(&socket_path(&home));
        self.stream = start(&home, &daemon)?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn installed(root: &Path, at: &str) -> PathBuf {
        let path = root.join(at);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "").unwrap();
        path
    }

    #[test]
    fn an_app_bundles_helper_comes_first_and_an_app_never_starts_itself() {
        let root = tempfile::tempdir().unwrap();
        let app = installed(root.path(), "Vaulte.app/Contents/MacOS/Vaulte");
        let on_path = installed(root.path(), "bin/Vaulte");
        let path = root.path().join("bin");
        assert_eq!(installed_daemon(&app, Some(path.as_os_str())), Some(on_path), "not the app itself");
        let helper = installed(root.path(), "Vaulte.app/Contents/Helpers/Vaulte");
        assert_eq!(installed_daemon(&app, Some(path.as_os_str())), Some(helper));
    }

    #[test]
    fn a_command_line_finds_it_beside_itself_past_places_that_hold_none() {
        let root = tempfile::tempdir().unwrap();
        let tool = installed(root.path(), "opt/vaulte/vlt");
        let beside = installed(root.path(), "opt/vaulte/Vaulte");
        assert_eq!(installed_daemon(&tool, None), Some(beside));
        assert_eq!(installed_daemon(&root.path().join("elsewhere/vlt"), None), None);
    }

    #[test]
    fn only_a_signed_broker_of_this_very_code_goes_unasked() {
        assert!(is_settled(&format!("{BUILD}+TEAM")));
        assert!(!is_settled(BUILD), "a signed one would outrank it");
        assert!(!is_settled("0.0.1-0000000000000000+TEAM"), "another code");
    }
}
