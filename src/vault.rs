//! The vault itself. Private to this crate: every interface goes through `Client`, so the only
//! way to reach a secret from outside passes the broker's policy.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_lc_rs::signature::Ed25519KeyPair;

use crate::binding::Binding;
use crate::crypto::{self, Key, Wrapped};
use crate::device::Device;
use crate::device::software::Software;
use crate::ids::{DeviceId, Generation, SpaceId, VaultId};
use crate::item;
use crate::listing::Listing;
use crate::record::Body;
use crate::state::{Anchor, Problem, State, UNKNOWN_KEY, root};
use crate::store::log::{self, Appender, Chain, Clock};
use crate::store::write_private;
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

const ENCLAVE: u8 = 0;
const SOFTWARE: u8 = 1;
const SERVER: u8 = 2;
const DEVICE_FILE: &str = "device.bin";
pub(crate) const LOG_KEY_FILE: &str = "log.key";
pub(crate) const SYNC_KEY_FILE: &str = "sync.key";
const SETTLED_FILE: &str = "settled";

/// Where the vault lives unless `LV_HOME` says otherwise.
pub fn default_home() -> PathBuf {
    if let Some(home) = std::env::var_os("LV_HOME") {
        return home.into();
    }
    let user = std::env::var_os("HOME").map_or_else(|| PathBuf::from("."), PathBuf::from);
    if cfg!(target_os = "macos") {
        user.join("Library/Application Support/libvault")
    } else if let Some(data) = std::env::var_os("XDG_DATA_HOME") {
        PathBuf::from(data).join("libvault")
    } else {
        user.join(".local/share/libvault")
    }
}

/// Whether a vault exists at `home`.
pub fn exists(home: &Path) -> bool {
    home.join("log").is_dir()
}

pub(crate) fn store_device(local: &Path, device: &dyn Device) -> Result<()> {
    let kind = match (device.is_hardware(), device.has_person()) {
        (true, _) => ENCLAVE,
        (false, true) => SOFTWARE,
        (false, false) => SERVER,
    };
    let mut stored = vec![kind];
    stored.extend_from_slice(&device.to_stored());
    write_private(&local.join(DEVICE_FILE), &stored)
}

/// Whether this home needs a passphrase, so an interface knows before asking for one.
pub fn needs_passphrase(home: &Path) -> Result<bool> {
    let stored = fs::read(home.join("local").join(DEVICE_FILE)).map_err(|_| Error::NoVault)?;
    Ok(stored.first() == Some(&SOFTWARE))
}

fn load_device(home: &Path, passphrase: Option<&str>) -> Result<Arc<dyn Device>> {
    let stored = fs::read(home.join("local").join(DEVICE_FILE)).map_err(|_| Error::NoVault)?;
    let (kind, rest) = stored.split_first().ok_or(Error::Corrupt("empty device file"))?;
    match *kind {
        #[cfg(target_vendor = "apple")]
        ENCLAVE => Ok(Arc::new(crate::device::enclave::Enclave::from_stored(rest)?)),
        SOFTWARE => Ok(Arc::new(Software::from_stored(rest, passphrase)?)),
        SERVER => Ok(Arc::new(crate::device::server::Server::from_stored(rest)?)),
        _ => Err(Error::NoHardware),
    }
}

pub(crate) fn encode_wrapped(wrapped: &Wrapped) -> Vec<u8> {
    let mut w = Writer::new();
    w.array(&wrapped.ephemeral);
    w.bytes(&wrapped.ciphertext);
    w.bytes(&wrapped.sealed);
    w.finish()
}

pub(crate) fn decode_wrapped(bytes: &[u8]) -> Result<Wrapped> {
    let mut r = Reader::new(bytes);
    let wrapped = Wrapped { ephemeral: r.array()?, ciphertext: r.bytes()?.to_vec(), sealed: r.bytes()?.to_vec() };
    r.finish()?;
    Ok(wrapped)
}

/// A name for a device, kept out of plaintext logs: a backup folder should not say whose laptop
/// it is.
pub(crate) fn label_body(vault: VaultId, epoch: Generation, epoch_key: &Key, device: DeviceId, name: &str) -> Result<Body> {
    let sealed = crypto::seal(epoch_key, &Binding::Label { vault, device }, &item::encode(&name)?);
    Ok(Body::Label { device, epoch, sealed })
}

/// `name`, or with a number added if a device already has it.
pub(crate) fn unused_name(name: &str, taken: &[String]) -> String {
    let mut unique = name.to_owned();
    let mut suffix = 1;
    while taken.contains(&unique) {
        suffix += 1;
        unique = format!("{name} {suffix}");
    }
    unique
}

/// An enrolled device.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub is_this_device: bool,
    /// When this device last wrote anything this one has, by that device's own clock, so a
    /// person can see which of their devices changed something last.
    pub last_change_ms: u64,
}

/// Keys held while unlocked, and what they have opened. Dropping this locks the vault.
#[derive(Debug)]
pub(crate) struct Keys {
    pub epochs: BTreeMap<Generation, Key>,
    /// A server's keys for the versions of the spaces it holds, with their names. A server holding
    /// chosen spaces has these and no epochs.
    pub spaces: BTreeMap<(SpaceId, Generation), (String, Key)>,
    /// Generations wrapped to this device that would not open, so they are not worth a new touch.
    pub unreadable: BTreeSet<Generation>,
    pub log: Ed25519KeyPair,
    /// Interior, because reading a list must not need the vault to be mutable.
    pub listing: RefCell<Listing>,
}

#[cfg(test)]
impl Keys {
    pub fn newest_epoch(&self) -> Result<(Generation, &Key)> {
        self.epochs.iter().next_back().map(|(epoch, key)| (*epoch, key)).ok_or(Error::Locked)
    }
}

/// An open vault. Holds an exclusive lock on its home, so there is one writer per device.
#[derive(Debug)]
pub struct Vault {
    pub(crate) home: PathBuf,
    pub(crate) device: Arc<dyn Device>,
    pub(crate) me: DeviceId,
    pub(crate) state: State,
    pub(crate) keys: Option<Keys>,
    clock: Clock,
    appender: Appender,
    /// When each device last sent this one back to its person, by making a generation.
    pub(crate) last_asked: BTreeMap<DeviceId, u64>,
    /// A signed copy of this device's own log says something else, so this device was restored
    /// from an old copy of itself and has written since. Nothing more it wrote would reach anyone.
    pub(crate) diverged: bool,
    /// What came in and was turned away, which no replay of the logs here shows. It stands until
    /// that device's log is taken.
    pub(crate) refused: Vec<Problem>,
    /// The roster change this device's person settled a conflict on.
    pub(crate) settled: Option<crypto::Hash>,
    /// Shared with whoever waits to sync, which a growth wakes.
    pub(crate) growth: Arc<crate::store::Growth>,
    lock: File,
}

impl Vault {
    /// Opens a vault without unlocking it. A passphrase is needed only on software devices.
    pub fn open(home: &Path, passphrase: Option<&str>) -> Result<Self> {
        if !exists(home) {
            return Err(Error::NoVault);
        }
        Self::with_device(home, load_device(home, passphrase)?)
    }

    pub(crate) fn with_device(home: &Path, device: Arc<dyn Device>) -> Result<Self> {
        let lock = File::create(home.join("local").join("lock"))?;
        lock.try_lock().map_err(|_| Error::Busy)?;
        let settled = fs::read(home.join("local").join(SETTLED_FILE)).ok().and_then(|bytes| crypto::Hash::try_from(bytes).ok());
        let state = State::from_logs_as(
            &crate::store::parse_all(&crate::store::read_logs(home)?),
            &Anchor::Device { keys: device.public(), settled: settled.as_ref() },
        )?;
        let me = state
            .members
            .iter()
            .find(|(_, member)| member.record.keys == *device.public())
            .map(|(id, _)| *id)
            .ok_or(Error::Corrupt("this device is not enrolled in the vault"))?;
        let mut clock = Clock::default();
        clock.observe(state.clock);
        let appender = Appender::open(&log::path_for(home, &me))?;
        Ok(Self {
            home: home.to_path_buf(),
            device,
            me,
            state,
            keys: None,
            clock,
            appender,
            last_asked: BTreeMap::new(),
            refused: Vec::new(),
            diverged: false,
            settled,
            growth: Arc::default(),
            lock,
        })
    }

    pub fn is_unlocked(&self) -> bool {
        self.keys.is_some()
    }

    pub fn is_hardware(&self) -> bool {
        self.device.is_hardware()
    }

    /// The device, for asking the person without holding the vault.
    pub fn device(&self) -> Arc<dyn Device> {
        Arc::clone(&self.device)
    }

    /// How many devices can open this vault.
    pub fn device_count(&self) -> usize {
        self.state.active_devices().count()
    }

    pub(crate) fn vault_id(&self) -> VaultId {
        self.state.vault
    }

    pub(crate) fn genesis(&self) -> crypto::Hash {
        self.state.genesis
    }

    pub(crate) fn roster_head(&self) -> crypto::Hash {
        self.state.roster_head()
    }

    /// Every other enrolled device.
    pub(crate) fn peer_ids(&self) -> Vec<DeviceId> {
        self.state.active_devices().map(|(id, _)| *id).filter(|id| *id != self.me).collect()
    }

    /// The sync keys of every other enrolled device.
    pub(crate) fn peer_sync_keys(&self) -> Vec<[u8; 32]> {
        self.state.active_devices().filter(|(id, _)| **id != self.me).map(|(_, member)| member.record.sync).collect()
    }

    /// How many of a device's entries this device holds, and the hash of the last.
    pub(crate) fn held_log(&self, device: &DeviceId) -> (u64, crypto::Hash) {
        self.state.heads.get(device).map_or((0, [0; 32]), |head| (head.seq + 1, head.hash))
    }

    /// Whether this device is still in the vault.
    pub(crate) fn is_enrolled(&self) -> bool {
        self.is_active(&self.me)
    }

    /// Whether a device is enrolled and still counts.
    pub(crate) fn is_active(&self, device: &DeviceId) -> bool {
        self.state.active_devices().any(|(id, _)| id == device)
    }

    /// The enrolled device with this sync key, if any.
    pub(crate) fn active_peer(&self, sync_key: &[u8; 32]) -> Option<DeviceId> {
        self.state.active_devices().find(|(id, member)| member.record.sync == *sync_key && **id != self.me).map(|(id, _)| *id)
    }

    /// Every log held here, which is what a new device needs.
    pub(crate) fn all_logs(&self) -> Result<crate::store::Logs> {
        crate::store::read_logs(&self.home)
    }

    /// What this device knows about which history is its own.
    pub(crate) fn anchor(&self) -> Anchor<'_> {
        Anchor::Device { keys: self.device.public(), settled: self.settled.as_ref() }
    }

    /// Remembers the roster change a person settled a conflict on, so that the next replay comes
    /// back here rather than to a default. It stays on this device: it is that person's say.
    pub(crate) fn settle_on(&mut self, head: crypto::Hash) -> Result<()> {
        write_private(&self.home.join("local").join(SETTLED_FILE), &head)?;
        self.settled = Some(head);
        Ok(())
    }

    /// Picks up this device's own log again, after a copy of it has replaced the file.
    pub(crate) fn reopen_own_log(&mut self) -> Result<()> {
        self.appender = Appender::open(&log::path_for(&self.home, &self.me))?;
        Ok(())
    }

    /// Replaying brought in newer entries, so the next one written must come after them.
    pub(crate) fn observe_clock(&mut self) {
        self.clock.observe(self.state.clock);
    }

    /// Problems found in logs. An entry of this device's own that was skipped is only worth saying
    /// while what it held has not been written again.
    pub fn problems(&self) -> impl Iterator<Item = &Problem> {
        let rescued = self.lost_items().is_empty();
        self.state
            .problems
            .iter()
            .chain(&self.refused)
            .chain(&self.state.conflicts)
            .filter(move |problem| !(rescued && problem.device == self.me && problem.reason == UNKNOWN_KEY))
    }

    pub fn lock(&mut self) {
        self.keys = None;
    }

    /// Lets another process open this home. Nothing here may write after this, because the other
    /// process may write too: the only way on is to open the vault again.
    #[cfg_attr(not(target_os = "ios"), allow(dead_code))]
    pub(crate) fn release(&self) {
        let _ = self.lock.unlock();
    }

    /// The newest generation held here that is safe to seal something new under.
    pub(crate) fn writing_epoch(&self, clean: &BTreeSet<Generation>) -> Option<(Generation, &Key)> {
        self.keys.as_ref()?.epochs.iter().rev().find(|(epoch, _)| clean.contains(epoch)).map(|(epoch, key)| (*epoch, key))
    }

    /// Generations held here that this vault has a record of. Memory can hold one a removal has
    /// since cut, and an entry naming that would not apply.
    pub(crate) fn known_epochs(&self) -> impl DoubleEndedIterator<Item = (&Generation, &Key)> {
        self.keys.iter().flat_map(|keys| keys.epochs.iter()).filter(|(epoch, _)| self.state.epochs.contains_key(epoch))
    }

    /// The key for a name or an audit event, which must not stop when a sync has left this device
    /// holding only keys that have been replaced.
    pub(crate) fn key_for_records(&self) -> Result<(Generation, &Key)> {
        match self.writing_epoch(&self.state.clean_epochs()) {
            Some(found) => Ok(found),
            None => self.known_epochs().next_back().map(|(epoch, key)| (*epoch, key)).ok_or(Error::Locked),
        }
    }

    /// Writes entries to disk in one call, then applies them.
    pub(crate) fn commit(&mut self, bodies: &[Body]) -> Result<()> {
        if self.diverged {
            return Err(Error::Invalid("this device was restored from an older copy of itself and the others refuse it. Recover it from a backup"));
        }
        let keys = self.keys.as_ref().ok_or(Error::Locked)?;
        let mut chain = match self.state.heads.get(&self.me) {
            Some(head) => Chain { device: self.me, seq: head.seq + 1, prev: head.hash },
            None => Chain { device: self.me, seq: 0, prev: root(&self.state.genesis, &self.me) },
        };
        // Entries that were written and could not be applied would otherwise be written over.
        if chain.seq != self.appender.entries() {
            return Err(Error::Corrupt("this device's log has entries it cannot read, so nothing was saved"));
        }
        let listed = self.listing_is_current();
        let entries: Vec<_> = bodies.iter().map(|body| chain.next(self.clock.tick(log::now_ms()), body, &keys.log)).collect();
        // Past this the entry could not be read back, and everything after it would be lost.
        if entries.iter().any(|entry| entry.body.len() > log::MAX_BODY) {
            return Err(Error::Invalid("that is too large to store"));
        }
        self.appender.append_all(&entries)?;
        self.growth.note();
        for entry in &entries {
            self.state.apply(entry).map_err(|_| Error::Corrupt("this device wrote an entry it cannot apply"))?;
        }
        if listed {
            self.carry_listing_over(bodies);
        }
        Ok(())
    }

    /// Writes entries that have to land together as one, so a crash leaves all of them or none.
    pub(crate) fn commit_together(&mut self, bodies: Vec<Body>) -> Result<()> {
        self.commit(&[Body::Batch { bodies }])
    }

    /// Spaces that exist, for callers that must not re-derive them per item.
    pub(crate) fn space_ids(&self) -> BTreeSet<SpaceId> {
        self.state.spaces.keys().copied().collect()
    }
}
