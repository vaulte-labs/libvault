//! The broker inside an iPhone app, which iOS gives no other process, and putting it to sleep there.

#[cfg(target_os = "ios")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "ios")]
use std::path::Path;
use std::sync::Arc;
#[cfg(target_os = "ios")]
use std::sync::Mutex;
use std::sync::atomic::Ordering;

use super::Broker;
#[cfg(target_os = "ios")]
use super::{guard, open};
use crate::{Result, Vault};

/// The broker an iPhone app holds itself, since iOS starts no other process.
#[cfg(target_os = "ios")]
static IN_PROCESS: Mutex<Option<Arc<Broker>>> = Mutex::new(None);

/// Connects to the broker in this process, opening it first if none is. Each client gets one end of
/// a socket pair, so there is no socket file, and nothing outside this process can reach it.
#[cfg(target_os = "ios")]
pub fn connect_in_process(home: &Path) -> Result<UnixStream> {
    let mut running = guard(&IN_PROCESS);
    let broker = match running.as_ref() {
        Some(broker) => Arc::clone(broker),
        None => Arc::clone(running.insert(open(home)?)),
    };
    drop(running);
    let (ours, theirs) = UnixStream::pair()?;
    std::thread::spawn(move || {
        let _ = broker.serve(theirs);
    });
    Ok(ours)
}

/// Locks the vault and lets go of its folder, for an app about to be suspended: iOS ends one that
/// holds a file lock then, and the autofill extension must open the vault in its own process. The
/// next request opens the vault again, from whatever is on disk by then.
#[cfg(target_os = "ios")]
pub fn sleep_in_process() {
    if let Some(broker) = guard(&IN_PROCESS).as_ref() {
        broker.sleep();
    }
}

impl Broker {
    pub(super) fn is_asleep(&self) -> bool {
        self.asleep.load(Ordering::Acquire)
    }

    /// Locks the vault and lets go of its folder, so another process can open it.
    #[cfg_attr(not(target_os = "ios"), allow(dead_code))]
    pub(super) fn sleep(&self) {
        let mut core = self.core();
        core.lock();
        core.vault.release();
        self.asleep.store(true, Ordering::Release);
    }

    /// Opens the vault again after `sleep`, as it now is on disk, where another process may have
    /// written to it meanwhile.
    pub(super) fn wake(&self) -> Result<()> {
        if !self.is_asleep() {
            return Ok(());
        }
        let mut core = self.core();
        if self.is_asleep() {
            let mut vault = Vault::open(&self.home, None)?;
            // Sync waits on this, and must go on hearing of every write.
            vault.growth = Arc::clone(&core.vault.growth);
            core.vault = vault;
            self.asleep.store(false, Ordering::Release);
        }
        Ok(())
    }

    /// Ends the broker, and the keys it held with it.
    #[cfg(not(target_os = "ios"))]
    #[allow(clippy::unused_self, reason = "the iOS broker needs itself to end")]
    pub(super) fn exit(&self) {
        std::process::exit(0);
    }

    /// The app's own process goes on, so the broker sleeps and is forgotten. The next client opens
    /// a new one, which matters after a wipe, when a new vault may be made in its place.
    #[cfg(target_os = "ios")]
    pub(super) fn exit(&self) {
        self.sleep();
        let mut running = guard(&IN_PROCESS);
        if running.as_ref().is_some_and(|broker| std::ptr::eq(Arc::as_ptr(broker), self)) {
            *running = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Broker;
    use crate::device::software::{Cost, Software};
    use crate::{Error, Vault};

    #[test]
    fn a_sleeping_broker_lets_another_process_write_and_wakes_to_what_it_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("vault");
        drop(crate::Setup::new(Software::generate("p", Cost::FAST).unwrap()).create(&home, "iPhone").unwrap());
        let broker = Broker::new(&home).unwrap();
        assert!(matches!(Vault::open(&home, Some("p")), Err(Error::Busy)), "one writer while awake");
        let before = broker.core().vault.state.revision();

        broker.sleep();
        let mut autofill = Vault::open(&home, Some("p")).unwrap();
        autofill.unlock("test").unwrap();
        autofill.create_space("Written while asleep").unwrap();
        drop(autofill);

        broker.wake().unwrap();
        assert!(matches!(Vault::open(&home, Some("p")), Err(Error::Busy)), "the broker holds the vault again");
        assert_ne!(broker.core().vault.state.revision(), before, "it read what was written meanwhile");
    }
}
