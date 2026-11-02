//! Opening a vault with a person's approval. Everything here assumes any enrolled device may have
//! written what it reads, so nothing counts until it opens and matches what was committed to.

use std::cell::RefCell;
use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::sync::Arc;

use aws_lc_rs::signature::Ed25519KeyPair;

use crate::binding::{Binding, Recipient};
use crate::crypto::{self, Key, WrapTo, Wrapped};
use crate::device::{Authorized, Device};
use crate::ids::{DeviceId, Generation, ItemId, SpaceId, VaultId};
use crate::record::Sealed;
use crate::state::{Change, SpaceWrap, State, Wrap, epoch_commitment};
use crate::store::log;
use crate::vault::{Keys, LOG_KEY_FILE, Vault, decode_wrapped};
use crate::{Error, Result};

/// What opening a vault needs from the person. Asking takes as long as they take, so this holds
/// no reference to the vault: other work continues while the prompt is up.
pub(crate) struct UnlockRequest {
    device: Arc<dyn Device>,
    wrapped: Vec<(Generation, Wrapped)>,
    /// For a server holding chosen spaces, which has no epoch key, what it holds instead.
    spaces: Vec<SpaceWrap>,
    commitments: Vec<BTreeMap<Generation, crypto::Hash>>,
    log_key: Wrapped,
    vault: VaultId,
    me: DeviceId,
}

pub(crate) struct Opened {
    keys: BTreeMap<Generation, Key>,
    spaces: BTreeMap<(SpaceId, Generation), (String, Key)>,
    unreadable: BTreeSet<Generation>,
    log_seed: Key,
}

impl UnlockRequest {
    /// Asks the person, naming `reason`, and opens the keys. One approval covers them all. Opens
    /// every generation wrapped to this device, because rotations can race and any enrolled device
    /// can add a wrap: a key counts only if it matches what its generation committed to.
    pub fn open(self, reason: &str) -> Result<Opened> {
        let approved = self.device.authorize_unlock(reason)?;
        let public = self.device.public().wrap_to();
        let mut keys = BTreeMap::new();
        let mut unreadable: BTreeSet<Generation> = self.wrapped.iter().map(|(epoch, _)| *epoch).collect();
        for (epoch, wrapped) in &self.wrapped {
            if keys.contains_key(epoch) {
                continue;
            }
            let binding = Binding::Epoch { vault: self.vault, epoch: *epoch, recipient: Recipient::Device(self.me) };
            let opened =
                approved.agree(&wrapped.ephemeral, &wrapped.ciphertext).and_then(|shared| crypto::unwrap(&shared, public, &binding, wrapped));
            let matches = |key: &Key| self.commitments.iter().any(|known| known.get(epoch) == Some(&epoch_commitment(&self.vault, *epoch, key)));
            if let Some(key) = opened.ok().filter(matches) {
                keys.insert(*epoch, key);
                unreadable.remove(epoch);
            }
        }
        let spaces = self.open_spaces(approved.as_ref(), public);
        if keys.is_empty() && spaces.is_empty() {
            return Err(Error::Corrupt("no key wrapped to this device opens"));
        }
        let shared = approved.agree(&self.log_key.ephemeral, &self.log_key.ciphertext)?;
        let log_seed = crypto::unwrap(&shared, public, &Binding::LogKey { vault: self.vault, device: self.me }, &self.log_key)?;
        Ok(Opened { keys, spaces, unreadable, log_seed })
    }

    /// The versions of spaces wrapped to a server, each with its name. One that does not open, or
    /// names itself with something no name may hold, is passed over.
    fn open_spaces(&self, approved: &dyn Authorized, public: WrapTo<'_>) -> BTreeMap<(SpaceId, Generation), (String, Key)> {
        let mut spaces = BTreeMap::new();
        for wrap in &self.spaces {
            let (vault, space, version) = (self.vault, wrap.space, wrap.version);
            let binding = Binding::SpaceKey { vault, space, version, device: self.me };
            let opened = approved
                .agree(&wrap.wrapped.ephemeral, &wrap.wrapped.ciphertext)
                .and_then(|shared| crypto::unwrap(&shared, public, &binding, &wrap.wrapped));
            let Ok(key) = opened else { continue };
            let name = crypto::open(&key, &Binding::SpaceName { vault, space, version }, &wrap.name)
                .ok()
                .and_then(|name| String::from_utf8(name.to_vec()).ok());
            if let Some(name) = name.filter(|name| crate::item::validate_text(name).is_ok()) {
                spaces.entry((space, version)).or_insert((name, key));
            }
        }
        spaces
    }
}

/// Follows epoch links back from `epochs`, adding every key reachable from them. A link that does
/// not open ends that path and no other.
pub(crate) fn walk_links(state: &State, epochs: &mut BTreeMap<Generation, Key>) {
    let mut pending: Vec<Generation> = epochs.keys().copied().collect();
    while let Some(epoch) = pending.pop() {
        for (previous, key) in opened_links(state, epoch, &epochs[&epoch]) {
            if let Entry::Vacant(slot) = epochs.entry(previous) {
                slot.insert(key);
                pending.push(previous);
            }
        }
    }
}

/// What a generation really reaches. A link on record proves nothing until it opens and gives the
/// key its target committed to, because anyone can write one that does not.
pub(crate) fn opened_links(state: &State, epoch: Generation, key: &Key) -> Vec<(Generation, Key)> {
    let open = |(previous, sealed): &(Generation, Vec<u8>)| {
        let bytes = crypto::open(key, &Binding::EpochLink { vault: state.vault, epoch }, sealed).ok()?;
        let reached = Key::from_bytes(<[u8; 32]>::try_from(bytes.as_slice()).ok()?);
        (state.epochs.get(previous) == Some(&epoch_commitment(&state.vault, *previous, &reached))).then_some((*previous, reached))
    };
    state.links.get(&epoch).into_iter().flatten().filter_map(open).collect()
}

const MAX_WRAPS_FROM_REMOVED: usize = 64;

impl Vault {
    /// A replay that kept what removals cut, for when something is lost to one or this device was
    /// removed itself, which are the only times it is worth reaching for. It holds what a removal
    /// replaced too, because something may be built on that.
    pub(crate) fn state_with_nothing_cut(&self) -> Option<State> {
        if self.lost_items().is_empty() && self.is_active(&self.me) {
            return None;
        }
        self.logs_with_nothing_cut().ok()
    }

    pub(crate) fn logs_with_nothing_cut(&self) -> Result<State> {
        let mut logs = crate::store::parse_all(&self.all_logs()?);
        for (device, parsed) in &mut logs {
            if let Ok(bytes) = fs::read(log::displaced_path(&self.home, device)) {
                *parsed = log::parse(&bytes);
            }
        }
        State::with_nothing_cut(&logs, &self.anchor())
    }

    /// Every generation wrapped to this device that is worth a try, newest first.
    pub(crate) fn my_wraps(&self) -> Vec<(Generation, Wrapped)> {
        self.wraps_in(&self.state, &BTreeSet::new())
    }

    /// Opening a wrap costs the hardware a key agreement, so what a removed device wrote is tried
    /// last and only so far, or a pile of junk it left would slow every unlock for good. What
    /// something lost needs is tried whoever wrote it.
    fn wraps_in(&self, state: &State, needed: &BTreeSet<Generation>) -> Vec<(Generation, Wrapped)> {
        let mine = |wrap: &Wrap| match &wrap.sealed {
            Sealed::Device(device, wrapped) if *device == self.me => Some((wrap.by, wrap.epoch, wrapped.clone())),
            Sealed::Device(..) | Sealed::Recovery(..) => None,
        };
        let (mut trusted, mut others): (Vec<_>, Vec<_>) = state.wraps.iter().filter_map(mine).partition(|(by, ..)| self.is_active(by));
        let newest_first = |wraps: &mut Vec<(DeviceId, Generation, Wrapped)>| wraps.sort_by_key(|(_, epoch, _)| std::cmp::Reverse(*epoch));
        newest_first(&mut trusted);
        newest_first(&mut others);
        let (wanted, rest): (Vec<_>, Vec<_>) = others.into_iter().partition(|(_, epoch, _)| needed.contains(epoch));
        trusted.into_iter().chain(wanted).chain(rest.into_iter().take(MAX_WRAPS_FROM_REMOVED)).map(|(_, epoch, wrapped)| (epoch, wrapped)).collect()
    }

    /// The generations that items lost to a removal were written under.
    fn generations_lost_items_need(&self, whole: &State) -> BTreeSet<Generation> {
        let version_of = |(device, space, item): (DeviceId, SpaceId, ItemId)| {
            whole.items.get(&(space, item))?.iter().rev().find_map(|entry| match &entry.change {
                Change::Put { version, .. } if entry.device == device => Some((space, *version)),
                _ => None,
            })
        };
        self.lost_items()
            .into_iter()
            .filter_map(version_of)
            .filter_map(|(space, version)| Some(whole.spaces.get(&space)?.get(&version)?.epoch))
            .collect()
    }

    #[cfg(test)]
    pub fn wraps_tried_for_tests(&self) -> usize {
        self.unlock_request().unwrap().wrapped.len()
    }

    /// Prepares an unlock, without asking anyone yet. With something lost to a removal, it reaches
    /// for what was cut as well. What counts now goes first, and each is held to its own record: an
    /// id can be used again.
    pub(crate) fn unlock_request(&self) -> Result<UnlockRequest> {
        let mut wrapped = self.my_wraps();
        let mut commitments = vec![self.state.epochs.clone()];
        if let Some(whole) = self.state_with_nothing_cut() {
            let needed = self.generations_lost_items_need(&whole);
            let tried: BTreeSet<Generation> = wrapped.iter().map(|(epoch, _)| *epoch).collect();
            wrapped.extend(self.wraps_in(&whole, &needed).into_iter().filter(|(epoch, _)| needed.contains(epoch) || !tried.contains(epoch)));
            commitments.push(whole.epochs);
        }
        let spaces: Vec<SpaceWrap> =
            self.state.space_wraps.iter().filter(|wrap| wrap.device == self.me && self.is_active(&wrap.by)).cloned().collect();
        if wrapped.is_empty() && spaces.is_empty() {
            return Err(Error::Corrupt("no key has been wrapped to this device"));
        }
        let log_key = decode_wrapped(&fs::read(self.home.join("local").join(LOG_KEY_FILE))?)?;
        Ok(UnlockRequest { device: Arc::clone(&self.device), wrapped, spaces, commitments, log_key, vault: self.state.vault, me: self.me })
    }

    /// Installs keys opened by an approved request.
    pub(crate) fn install(&mut self, opened: Opened) -> Result<()> {
        let log = Ed25519KeyPair::from_seed_unchecked(opened.log_seed.as_bytes()).map_err(|_| Error::Corrupt("bad log key"))?;
        let mut epochs = opened.keys;
        walk_links(&self.state, &mut epochs);
        if let Some(whole) = self.state_with_nothing_cut() {
            walk_links(&whole, &mut epochs);
        }
        self.keys = Some(Keys { epochs, spaces: opened.spaces, unreadable: opened.unreadable, log, listing: RefCell::default() });
        Ok(())
    }

    /// Asks the person, then loads the keys.
    #[cfg(test)]
    pub fn unlock(&mut self, reason: &str) -> Result<()> {
        let opened = self.unlock_request()?.open(reason)?;
        self.install(opened)
    }
}
