//! A second way in for the vault's own sandboxed code, such as the autofill extension, which can
//! neither reach the vault's folder nor start a broker. It sits in the app group's container,
//! which only the vault's own apps may enter. A caller coming through it is checked exactly as at
//! the main socket.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::Broker;
use crate::client::SHARED_SOCKET;

/// The app group, after the team that signed the broker: `TEAM.dev.vaulty`.
#[cfg(any(target_os = "macos", test))]
const APP_GROUP: &str = "dev.vaulty";

/// Only the broker for the vault in its usual place opens the shared socket. One socket serves
/// every sandboxed caller, so a broker for a test vault elsewhere would take it from the real one.
#[cfg(any(target_os = "macos", test))]
fn app_group(home: &Path, usual_home: &Path, team: Option<&str>) -> Option<String> {
    (home == usual_home).then(|| team.map(|team| format!("{team}.{APP_GROUP}")))?
}

/// The system makes the container, because one made by hand may not be the group's.
#[cfg(target_os = "macos")]
fn folder(home: &Path) -> Option<PathBuf> {
    if cfg!(feature = "test-hooks") {
        return Some(home.join("shared")).filter(|folder| folder.exists());
    }
    let usual_home = PathBuf::from(std::env::var_os("HOME")?).join("Library/Application Support/libvault");
    let group = app_group(home, &usual_home, crate::device::enclave::own_team().as_deref())?;
    crate::device::enclave::group_container(&group)
}

/// Nothing outside macOS needs it yet.
#[cfg(not(target_os = "macos"))]
fn folder(_home: &Path) -> Option<PathBuf> {
    None
}

/// Listens in the shared folder too, when this broker may. Without it, only sandboxed callers go
/// without, and they say the broker is not running.
pub(super) fn listen(broker: &Arc<Broker>, home: &Path) {
    let Some(folder) = folder(home) else { return };
    let socket = folder.join(SHARED_SOCKET);
    let _ = std::fs::remove_file(&socket);
    let bound = UnixListener::bind(&socket).and_then(|listener| {
        std::fs::set_permissions(&socket, PermissionsExt::from_mode(0o600))?;
        Ok(listener)
    });
    let Ok(listener) = bound else { return };
    let broker = Arc::clone(broker);
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let broker = Arc::clone(&broker);
            std::thread::spawn(move || {
                let _ = broker.serve(stream);
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_vault_in_its_usual_place_opens_the_shared_socket_and_only_when_signed() {
        let usual = Path::new("/Users/a/Library/Application Support/libvault");
        assert_eq!(app_group(usual, usual, Some("TEAM")), Some(format!("TEAM.{APP_GROUP}")));
        assert_eq!(app_group(Path::new("/tmp/test-vault"), usual, Some("TEAM")), None);
        assert_eq!(app_group(usual, usual, None), None, "an unsigned broker has no group");
    }
}
