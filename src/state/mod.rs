//! Replays every log into the current vault. Nothing here needs a key, so a locked device can
//! verify what it receives. Rules run on replay, so every device enforces them independently
//! and a hostile peer cannot get a bad entry accepted by writing it to a file.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::{self, Hash};
pub use crate::digest::{add_digest, epoch_commitment, genesis_digest, revoke_digest, root, rotate_digest};
use crate::ids::{BatchId, DeviceId, Generation, ItemId, SpaceId, VaultId};
use crate::record::{Body, RecoveryPublic, Sealed};
use crate::store::log::{Entry, Parsed};
use crate::{Error, Result, recovery};
pub use members::{Holds, Member, SpaceWrap, Standing};
pub use rules::Anchor;
use vouching::Vouch;

/// A generation's key wrapped to someone, and which device wrote that.
#[derive(Debug, Clone)]
pub struct Wrap {
    pub epoch: Generation,
    pub sealed: Sealed,
    pub by: DeviceId,
}

#[derive(Debug, Clone)]
pub struct SpaceVersion {
    pub epoch: Generation,
    pub sealed: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum Change {
    Put { version: Generation, meta: Vec<u8>, secret: Vec<u8> },
    Delete,
}

#[derive(Debug, Clone)]
pub struct Version {
    pub clock: u64,
    pub device: DeviceId,
    pub batch: BatchId,
    pub change: Change,
}

#[derive(Debug, Clone, Copy)]
pub struct Head {
    pub seq: u64,
    pub hash: Hash,
    /// When its writer says it wrote it, as a hybrid clock reading.
    pub clock: u64,
}

/// Something wrong with a peer's log. Local data is unaffected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Problem {
    pub device: DeviceId,
    pub seq: u64,
    pub reason: &'static str,
}

/// Why an entry was not applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The log cannot be trusted past this entry.
    Stop(&'static str),
    /// This roster change does not count, but the device's other entries still do. Two devices
    /// changing the roster at once must not cost either one the rest of its work.
    Skip(&'static str),
}

/// A new value each time, so no two different states ever share a revision.
fn next_revision() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone)]
pub struct State {
    /// Changes with every replay and applied entry, so equal revisions mean nothing has changed.
    revision: u64,
    pub vault: VaultId,
    pub genesis: Hash,
    pub recovery: RecoveryPublic,
    pub members: BTreeMap<DeviceId, Member>,
    pub wraps: Vec<Wrap>,
    pub space_wraps: Vec<SpaceWrap>,
    /// What each generation's key must match, which is also how a generation comes to exist.
    pub epochs: BTreeMap<Generation, Hash>,
    /// The roster change each generation was made after.
    made_after: BTreeMap<Generation, Hash>,
    /// Where in `roster` someone last left: a device, or the words. Everyone in the vault until
    /// then could hold anything made before it.
    last_departure: usize,
    /// What each epoch reaches: a generation, and its key sealed under this epoch's key.
    pub links: BTreeMap<Generation, Vec<(Generation, Vec<u8>)>>,
    pub spaces: BTreeMap<SpaceId, BTreeMap<Generation, SpaceVersion>>,
    /// Versions are kept in clock order; the last one is current.
    pub items: BTreeMap<(SpaceId, ItemId), Vec<Version>>,
    pub audit: Vec<(Generation, Vec<u8>)>,
    pub heads: BTreeMap<DeviceId, Head>,
    pub clock: u64,
    pub problems: Vec<Problem>,
    /// Roster changes that were refused. The device's other entries still count.
    pub conflicts: Vec<Problem>,
    /// Every applied roster change in order, ending at the current head. Each one names the one
    /// before it, so the order is fixed by what its approvers saw, not by a clock a writer sets.
    pub roster: Vec<Hash>,
    /// The last roster change each device wrote that counted.
    roster_writes: BTreeMap<DeviceId, u64>,
    /// Entries whose roster change `settle_roster` applied, so replay does not do it again.
    settled: BTreeSet<Hash>,
    /// The hash of the last entry each removal kept.
    kept_heads: BTreeMap<DeviceId, Hash>,
    /// The last roster change each device wrote or approved.
    vouched: BTreeMap<DeviceId, Hash>,
    /// Roster changes that lost a fork to the clock alone, which a writer sets.
    pub lost_ties: BTreeSet<Hash>,
    /// Roster changes where someone left: a device, or the words.
    pub departures: BTreeSet<Hash>,
    /// Generations made together with a roster change that did not count. If that was a removal,
    /// these were made to keep out a device this history still has, so they go no further.
    pub set_apart: BTreeSet<Generation>,
    /// Items written under a key that is not on record, which a removal may have cut, and when.
    pub orphans: BTreeMap<(DeviceId, SpaceId, ItemId), u64>,
    /// Replaying as if no removal had cut anything, to get back what was built on what it cut.
    uncut: bool,
    /// This stops at the last point some recovery words were current, and they were replaced.
    pub replaced_words: bool,
}

const FORGED_GENERATION: &str = "a key generation that is not its author's to write";
const LOST_POSITION: &str = "changed the roster at the same time as another device";
const LOST_DEPARTURE: &str = "removed a device or replaced the words on a history that did not count";
pub const PAST_THE_CUT: &str = "past what that device's removal kept";
pub const UNKNOWN_KEY: &str = "names a key this vault has no record of";

fn verify_entry(key: &[u8; 32], entry: &Entry) -> Result<(), Refusal> {
    #[cfg(test)]
    vouching::SIGNATURES_CHECKED.with(|checked| checked.set(checked.get() + 1));
    crypto::verify_ed25519(key, &entry.signed_bytes(), &entry.signature).map_err(|_| Refusal::Stop("bad entry signature"))
}

impl State {
    pub fn from_logs(logs: &[(DeviceId, Parsed)]) -> Result<Self> {
        Self::from_logs_as(logs, &Anchor::Nothing)
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Replays logs for a reader who knows something the logs cannot show.
    pub fn from_logs_as(logs: &[(DeviceId, Parsed)], anchor: &Anchor) -> Result<Self> {
        Self::replayed(logs, anchor, false)
    }

    /// The same, with everything a removal cut left in. Nothing here is true of the vault. It holds
    /// the keys and values that were cut, for a device to take back what it wrote on top of them.
    pub fn with_nothing_cut(logs: &[(DeviceId, Parsed)], anchor: &Anchor) -> Result<Self> {
        Self::replayed(logs, anchor, true)
    }

    fn replayed(logs: &[(DeviceId, Parsed)], anchor: &Anchor, uncut: bool) -> Result<Self> {
        Self::replayed_vouching(logs, anchor, uncut, Self::chains_signed_at_their_tips)
    }

    /// `vouch` says which entries need no signature check of their own. See [`vouching`].
    fn replayed_vouching(logs: &[(DeviceId, Parsed)], anchor: &Anchor, uncut: bool, vouch: Vouch) -> Result<Self> {
        if logs.iter().any(|(_, parsed)| parsed.newer) {
            return Err(Error::Newer);
        }
        let mut genesis = None;
        for (device, parsed) in logs {
            // A copy under another device's name is just a stray file.
            if let Some(entry) = parsed.entries.first().filter(|entry| entry.kind == Body::GENESIS && entry.device == *device)
                && genesis.replace(entry).is_some()
            {
                return Err(Error::Corrupt("this folder holds two different vaults"));
            }
        }
        let genesis = genesis.ok_or(Error::NoVault)?;
        let mut state = Self::from_genesis(genesis)?;

        let mut ordered: Vec<&Entry> = Vec::new();
        let mut tips: Vec<&Entry> = Vec::new();
        for (device, parsed) in logs {
            let valid = state.valid_chain(device, parsed);
            ordered.extend(&parsed.entries[..valid]);
            tips.extend(parsed.entries[..valid].last());
        }
        ordered.sort_by_key(|entry| (entry.clock, entry.device, entry.seq));

        // The roster first, then everything else against it. Replay order comes from a clock the
        // writer sets, so nothing about who may write can depend on it: anything a removed device
        // dates to before its removal is cut off all the same.
        state.settle_roster(&ordered, anchor);
        state.uncut = uncut;
        let forked = if uncut { BTreeSet::new() } else { state.forked_past_removal(logs) };
        let signed_through = vouch(&state, &tips);
        state.replay(&ordered, forked, &signed_through);
        state.revision = next_revision();
        Ok(state)
    }

    fn from_genesis(entry: &Entry) -> Result<Self> {
        let Body::Genesis { vault, recovery, device, first_epoch, device_signature, recovery_signature } = Body::decode(entry.kind, &entry.body)?
        else {
            return Err(Error::Corrupt("not a genesis entry"));
        };
        let id = device.id();
        if id != entry.device || entry.seq != 0 || entry.prev != [0; 32] {
            return Err(Error::Corrupt("bad genesis entry"));
        }
        let digest = genesis_digest(&vault, &device, &recovery, &first_epoch);
        device_signature.verify(&device.keys.signing, &device.keys.dsa, &digest)?;
        recovery::verify(&recovery, &digest, &recovery_signature)?;
        crypto::verify_ed25519(&device.log, &entry.signed_bytes(), &entry.signature)?;

        let hash = entry.hash();
        let member = Member { record: device, standing: Standing::Active, label: None, added_by: id, server: None };
        Ok(Self {
            revision: next_revision(),
            vault,
            genesis: hash,
            recovery,
            members: BTreeMap::from([(id, member)]),
            wraps: Vec::new(),
            space_wraps: Vec::new(),
            epochs: BTreeMap::from([(Generation::first(id), first_epoch)]),
            made_after: BTreeMap::from([(Generation::first(id), hash)]),
            last_departure: 0,
            links: BTreeMap::new(),
            spaces: BTreeMap::new(),
            items: BTreeMap::new(),
            audit: Vec::new(),
            heads: BTreeMap::from([(id, Head { seq: 0, hash, clock: entry.clock })]),
            clock: entry.clock,
            problems: Vec::new(),
            conflicts: Vec::new(),
            roster: vec![hash],
            roster_writes: BTreeMap::new(),
            settled: BTreeSet::new(),
            kept_heads: BTreeMap::new(),
            vouched: BTreeMap::new(),
            lost_ties: BTreeSet::new(),
            departures: BTreeSet::new(),
            set_apart: BTreeSet::new(),
            orphans: BTreeMap::new(),
            uncut: false,
            replaced_words: false,
        })
    }

    /// Returns how many leading entries form an unbroken chain, reporting the first break.
    fn valid_chain(&mut self, device: &DeviceId, parsed: &Parsed) -> usize {
        let mut prev = root(&self.genesis, device);
        let mut clock = 0;
        for (index, entry) in parsed.entries.iter().enumerate() {
            let expected = if entry.kind == Body::GENESIS && index == 0 { [0; 32] } else { prev };
            let reason = if entry.device != *device {
                Some("entry in the wrong device's log")
            } else if entry.seq != index as u64 {
                Some("a sequence number is out of order")
            } else if entry.prev != expected {
                Some("the hash chain is broken")
            } else if index > 0 && entry.clock <= clock {
                Some("the clock went backwards")
            } else {
                None
            };
            if let Some(reason) = reason {
                self.problems.push(Problem { device: *device, seq: index as u64, reason });
                return index;
            }
            prev = entry.hash();
            clock = entry.clock;
        }
        parsed.entries.len()
    }

    fn apply_body(&mut self, entry: &Entry, body: Body) -> Result<(), Refusal> {
        match body {
            Body::Genesis { .. } => return Err(Refusal::Stop("a second genesis entry")),
            Body::DeviceAdd { .. } | Body::ServerAdd { .. } | Body::DeviceRevoke { .. } | Body::RecoveryRotate { .. } => {
                // The change that replaced the words follows where this stops, and must not apply.
                if !self.settled.contains(&entry.hash()) {
                    return if self.replaced_words { Err(Refusal::Skip(LOST_POSITION)) } else { self.roster_step(entry, body) };
                }
            }
            Body::Wrap { epoch, sealed } => {
                self.require_epoch(&epoch)?;
                self.wraps.push(Wrap { epoch, sealed, by: entry.device });
            }
            Body::SpaceWrap { space, version, device, wrapped, name } => {
                self.apply_space_wrap(SpaceWrap { space, version, device, wrapped, name, by: entry.device })?;
            }
            Body::EpochLink { epoch, previous, commitment, roster, sealed } => {
                // With nothing cut this can meet an id its author used again, as it was free to.
                if self.uncut && self.epochs.contains_key(&epoch) {
                    return Err(Refusal::Skip(UNKNOWN_KEY));
                }
                if epoch.author != entry.device || self.epochs.contains_key(&epoch) || previous.number >= epoch.number {
                    return Err(Refusal::Stop(FORGED_GENERATION));
                }
                // One above a generation on record, as a space version is. Which ones are on record
                // depends on other logs, so this skips rather than stops.
                if !self.epochs.keys().any(|known| known.number.checked_add(1) == Some(epoch.number)) {
                    return Err(Refusal::Skip(UNKNOWN_KEY));
                }
                self.require_epoch(&previous)?;
                self.epochs.insert(epoch, commitment);
                // Written with a roster change, it comes after that change, not the one before.
                self.made_after.insert(epoch, if self.roster.contains(&entry.hash()) { entry.hash() } else { roster });
                self.links.insert(epoch, vec![(previous, sealed)]);
            }
            Body::ExtraLink { epoch, previous, sealed } => {
                if epoch.author != entry.device {
                    return Err(Refusal::Stop(FORGED_GENERATION));
                }
                self.require_epoch(&epoch)?;
                self.require_epoch(&previous)?;
                self.links.entry(epoch).or_default().push((previous, sealed));
            }
            Body::Space { space, version, epoch, sealed } => {
                self.check_space_version(entry, &space, version)?;
                self.require_epoch(&epoch)?;
                self.spaces.entry(space).or_default().insert(version, SpaceVersion { epoch, sealed });
            }
            Body::ItemPut { space, item, version, batch, meta, secret } => {
                if !self.spaces.get(&space).is_some_and(|versions| versions.contains_key(&version)) {
                    self.orphans.insert((entry.device, space, item), entry.clock);
                    return Err(Refusal::Skip(UNKNOWN_KEY));
                }
                self.push_version(space, item, entry, batch, Change::Put { version, meta, secret });
            }
            Body::ItemDelete { space, item, batch } => self.push_version(space, item, entry, batch, Change::Delete),
            Body::Audit { epoch, sealed } => self.audit.push((epoch, sealed)),
            Body::Label { device, epoch, sealed } => {
                if let Some(target) = self.members.get_mut(&device) {
                    // A name comes from the device itself, or from the one that added it until it
                    // has one. Anyone else, or that device later, could point `remove` at the
                    // wrong device.
                    let adder_may = entry.device == target.added_by && target.label.is_none();
                    if entry.device != device && !adder_may {
                        return Err(Refusal::Skip("names a device it has no say over"));
                    }
                    target.label = Some((epoch, sealed));
                }
            }
            Body::Batch { bodies } => {
                // A roster change that loses a race does not stop what came with it, and neither
                // is a device stopped for it.
                let change = bodies.iter().any(|body| body.approvals().is_some());
                let made: Vec<Generation> =
                    bodies.iter().filter_map(|body| if let Body::EpochLink { epoch, .. } = body { Some(*epoch) } else { None }).collect();
                let mut skipped = Ok(());
                for body in bodies {
                    match self.apply_body(entry, body) {
                        Err(Refusal::Stop(reason)) => return Err(Refusal::Stop(reason)),
                        Err(refusal) => skipped = Err(refusal),
                        Ok(()) => {}
                    }
                }
                if change && !self.roster.contains(&entry.hash()) {
                    for epoch in made {
                        self.made_after.remove(&epoch);
                        self.set_apart.insert(epoch);
                    }
                }
                return skipped;
            }
        }
        Ok(())
    }

    /// A generation counts only if a link leads to it from the vault's first one, so numbers grow
    /// by one and a device cannot jump to the end of the range. A missing key may only mean an
    /// entry has not arrived, or was cut off with a removed device, so this skips and goes on.
    fn require_epoch(&self, epoch: &Generation) -> Result<(), Refusal> {
        if self.epochs.contains_key(epoch) { Ok(()) } else { Err(Refusal::Skip(UNKNOWN_KEY)) }
    }

    /// `Stop` is only for what is wrong on its face, whoever else wrote what. Anything that depends
    /// on another device's entry skips, or that device could date one to stop this one for good.
    fn check_space_version(&self, entry: &Entry, space: &SpaceId, version: Generation) -> Result<(), Refusal> {
        let versions = self.spaces.get(space);
        let taken = versions.is_some_and(|versions| versions.contains_key(&version));
        if self.uncut && taken {
            return Err(Refusal::Skip(UNKNOWN_KEY));
        }
        if version.author != entry.device || taken {
            return Err(Refusal::Stop(FORGED_GENERATION));
        }
        let follows = versions.is_some_and(|versions| versions.keys().any(|known| known.number.checked_add(1) == Some(version.number)));
        if version.number == 0 || follows { Ok(()) } else { Err(Refusal::Skip(UNKNOWN_KEY)) }
    }

    /// The key an entry must be signed with, if its author may write it.
    fn author_key(&self, entry: &Entry, body: &Body) -> Result<[u8; 32], Refusal> {
        match (self.members.get(&entry.device), body) {
            (Some(member), _) if !member.accepts(entry.seq) && !self.uncut => Err(Refusal::Stop(PAST_THE_CUT)),
            (Some(member), _) => Ok(member.record.log),
            // A device can enroll itself, as a recovering one must, but only with approvals,
            // which are checked like any other roster change.
            (None, Body::DeviceAdd { device, .. } | Body::ServerAdd { device, .. }) if device.id() == entry.device => Ok(device.log),
            (None, _) => Err(Refusal::Stop("written by a device that is not enrolled")),
        }
    }

    /// Applies one entry after checking its author and signature.
    pub fn apply(&mut self, entry: &Entry) -> Result<(), Refusal> {
        self.apply_checked(entry, false)
    }

    /// The author is always checked. The signature is skipped only for an entry a later signature
    /// in the same chain has already vouched for.
    fn apply_checked(&mut self, entry: &Entry, vouched_for: bool) -> Result<(), Refusal> {
        self.revision = next_revision();
        let body = Body::decode(entry.kind, &entry.body).map_err(|error| match error {
            Error::Newer => Refusal::Stop("written by a newer version of Vaulte"),
            _ => Refusal::Stop("unreadable entry"),
        })?;
        let key = self.author_key(entry, &body)?;
        if !vouched_for {
            verify_entry(&key, entry)?;
        }

        let enrolled = self.members.contains_key(&entry.device);
        let outcome = match self.apply_body(entry, body) {
            // Going on past a refused change is for devices that belong here. For anyone else it
            // would keep and pass on a log from nobody at all.
            Err(Refusal::Skip(reason)) if !enrolled => Err(Refusal::Stop(reason)),
            outcome => outcome,
        };
        if !matches!(outcome, Err(Refusal::Stop(_))) {
            self.heads.insert(entry.device, Head { seq: entry.seq, hash: entry.hash(), clock: entry.clock });
            self.clock = self.clock.max(entry.clock);
        }
        outcome
    }

    fn push_version(&mut self, space: SpaceId, item: ItemId, entry: &Entry, batch: BatchId, change: Change) {
        let versions = self.items.entry((space, item)).or_default();
        // Replay and live commits are both nearly always newest, so this is nearly always the end.
        let at = versions.partition_point(|version| (version.clock, version.device) <= (entry.clock, entry.device));
        versions.insert(at, Version { clock: entry.clock, device: entry.device, batch, change });
    }
}

#[cfg(test)]
#[path = "attacks_tests.rs"]
mod attacks;
#[cfg(test)]
#[path = "audit_tests.rs"]
mod audit;
mod members;
mod rules;
#[cfg(test)]
#[path = "space_tests.rs"]
mod state_space;
#[cfg(test)]
mod tests;
mod vouching;
