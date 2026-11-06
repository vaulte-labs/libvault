//! Restoring a vault on a new machine from a copy of its logs and the 24 words. The new device
//! enrolls itself, with the recovery key as its approval, so no other device has to exist.

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use aws_lc_rs::signature::Ed25519KeyPair;
use serde::Serialize;

use crate::binding::{Binding, Part, Recipient};
use crate::crypto::{self, Key};
use crate::device::Device;
use crate::device::software::{Cost, Software};
use crate::ids::{DeviceId, Generation};
use crate::item::{self, Meta};
use crate::record::{Approval, Approver, Body, Sealed};
use crate::recovery::RecoveryKey;
use crate::setup::{STAGING_PREFIX, new_device, remove_stale_staging, write_device_files};
use crate::space::space_record;
use crate::state::{Anchor, Change, State, add_digest, epoch_commitment, root};
use crate::store::log::{self, Chain, Clock, now_ms};
use crate::store::{self, Logs};
use crate::store::{private_dir, write_private};
use crate::sync::folder::{each_vault, read_source};
use crate::unlock::walk_links;
use crate::vault::{exists, label_body, unused_name};
use crate::{Error, Result};

/// A copy of a vault that these words open, ready to become a vault on this device.
#[derive(Debug)]
pub struct Recovery {
    logs: Logs,
    state: State,
    key: RecoveryKey,
    /// Entries dated too far ahead of this machine to believe, which may only mean its clock is slow.
    left_out: usize,
    /// Other histories in this copy that signatures cannot separate from `state`, each one these
    /// words open, until a person chooses.
    rivals: Vec<State>,
}

/// How many of the newest items a history shows.
const NEWEST_SHOWN: usize = 5;

/// One of the histories in a copy, as a person can tell it apart: the devices in it, and the
/// newest items the words open there. A stolen device can name its devices after the person's,
/// and write items of its own, but not what the person wrote after the two histories split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct History {
    pub devices: Vec<String>,
    pub newest_items: Vec<String>,
}

/// A log as far as it can be believed: whole entries, up to any dated too far ahead of this device.
fn believable_entries(bytes: &[u8]) -> Vec<u8> {
    let now = now_ms();
    log::parse(bytes).entries.iter().take_while(|entry| log::is_plausible(entry.clock, now)).flat_map(log::Entry::encode).collect()
}

fn names_in_use(state: &State, keys: &BTreeMap<Generation, Key>) -> Vec<String> {
    let name = |(id, member): (&DeviceId, &crate::state::Member)| {
        let (epoch, sealed) = member.label.as_ref()?;
        let opened = crypto::open(keys.get(epoch)?, &Binding::Label { vault: state.vault, device: *id }, sealed).ok()?;
        crate::item::decode::<String>(&opened).ok()
    };
    state.active_devices().filter_map(name).filter(|name| item::validate_text(name).is_ok()).collect()
}

/// The names of the newest items these keys open, newest first.
fn newest_items(state: &State, keys: &BTreeMap<Generation, Key>) -> Vec<String> {
    let mut newest: Vec<_> = state.items.iter().filter_map(|(at, versions)| Some((at, versions.last()?))).collect();
    newest.sort_by_key(|(_, version)| Reverse((version.clock, version.device)));
    let name = |((space, item), version): (&(_, _), &crate::state::Version)| {
        let Change::Put { version, meta, .. } = &version.change else { return None };
        let (_, key) = space_record(state, keys, space, *version).ok()?;
        let binding = Binding::Item { vault: state.vault, space: *space, item: *item, version: *version, part: Part::Meta };
        let meta: Meta = item::decode(&crypto::open(&key, &binding, meta).ok()?).ok()?;
        item::validate(&meta).is_ok().then_some(meta.name)
    };
    newest.into_iter().filter_map(name).take(NEWEST_SHOWN).collect()
}

impl Recovery {
    /// Opens `source`, an archive or backup folder, with the 24 words. Nothing is written.
    pub fn open(source: &Path, words: &str) -> Result<Self> {
        let key = RecoveryKey::parse(words)?;
        Self::open_as(source, key, |key| Anchor::Words(key))
    }

    /// Opens `source` with words that were replaced, as the vault stood until then, for an owner
    /// whose words `open` turned away. A stolen device can replace the words if it was the only
    /// one, and this is how the owner gets back in. `problems` says what this copy leaves out.
    pub fn open_as_it_stood(source: &Path, words: &str) -> Result<Self> {
        let key = RecoveryKey::parse(words)?;
        Self::open_as(source, key, |key| Anchor::WordsAsTheyStood(key))
    }

    fn open_as(source: &Path, key: RecoveryKey, anchor: impl for<'a> Fn(&'a RecoveryKey) -> Anchor<'a>) -> Result<Self> {
        let copies = read_source(source)?;
        if copies.iter().all(Logs::is_empty) {
            return Err(Error::NoCopy);
        }
        // One bad copy beside a good one must not stop anything, so an error is only the last word.
        let mut failed = Error::WrongRecoveryKey;
        for logs in copies.into_iter().flat_map(each_vault) {
            if logs.is_empty() {
                continue;
            }
            // Whole entries, believably dated. A stray tail must not stop this, or come along to
            // contradict every peer later.
            let whole_entries: usize = logs.values().map(|bytes| log::parse(bytes).entries.len()).sum();
            let logs: Logs = logs.into_iter().map(|(device, bytes)| (device, believable_entries(&bytes))).collect();
            let left_out = whole_entries - logs.values().map(|bytes| log::parse(bytes).entries.len()).sum::<usize>();
            match store::replay(&logs, &anchor(&key)) {
                Ok(state) if key.matches(&state.recovery)? => {
                    let mut recovery = Self { logs, state, key, left_out, rivals: Vec::new() };
                    recovery.rivals = recovery.find_rivals();
                    return Ok(recovery);
                }
                Ok(_) => {}
                Err(error) => failed = error,
            }
        }
        Err(failed)
    }

    /// What is wrong with this copy, for showing before it is trusted. A new machine has nothing
    /// to compare a copy with, so only a person can weigh this.
    pub fn problems(&self) -> Vec<String> {
        let tied =
            (!self.rivals.is_empty()).then_some("this copy holds more than one history of who is in the vault, and no signature tells them apart");
        let replaced = self.state.replaced_words.then_some("these words were replaced later, so this is the vault as it stood until then");
        let found = self.state.problems.iter().chain(&self.state.conflicts).map(|problem| format!("{}: {}", problem.device, problem.reason));
        let dated = (self.left_out > 0)
            .then(|| format!("{} entries are dated too far ahead of this machine and were left out. Check its clock", self.left_out));
        tied.into_iter().chain(replaced).map(str::to_owned).chain(dated).chain(found).collect()
    }

    #[cfg(test)]
    pub fn clock_is_believable(&self) -> bool {
        log::is_plausible(self.state.clock, now_ms())
    }

    /// The histories in this copy that signatures cannot separate, with the one on offer first. A
    /// stolen device that was once alone can write a rival nothing but a date tells apart, and it
    /// sets the date, so only the person can say which is theirs.
    pub fn histories(&self) -> Vec<History> {
        std::iter::once(&self.state).chain(&self.rivals).map(|state| self.describe(state)).collect()
    }

    /// Goes with one of `histories`, which a copy holding more than one has to before it can finish.
    /// A wrong index changes nothing, so the person can choose again.
    pub fn choose_history(&mut self, index: usize) -> Result<()> {
        if index > self.rivals.len() {
            return Err(Error::Invalid("this copy has no such history"));
        }
        if index > 0 {
            self.state = self.rivals.swap_remove(index - 1);
        }
        self.rivals.clear();
        Ok(())
    }

    /// Each history a tie leaves that these words open. A tie inside a branch nothing follows, or
    /// one whose loser these words cannot open, is no choice at all.
    fn find_rivals(&self) -> Vec<State> {
        let rival = |change: &crypto::Hash| {
            let rival = store::replay(&self.logs, &Anchor::Through { words: &self.key, change }).ok()?;
            (rival.roster.contains(change) && self.key.matches(&rival.recovery).unwrap_or(false)).then_some(rival)
        };
        self.state.lost_ties.iter().filter_map(rival).collect()
    }

    /// Finishes on this device's secure hardware, or reports that it has none.
    pub fn finish_with_hardware(self, home: &Path, device_name: &str) -> Result<()> {
        #[cfg(target_vendor = "apple")]
        if crate::device::enclave::available() {
            return self.finish(&crate::device::enclave::Enclave::generate()?, home, device_name);
        }
        let _ = (home, device_name);
        Err(Error::NoHardware)
    }

    /// Finishes on a device with no secure hardware.
    pub fn finish_with_passphrase(self, passphrase: &str, cost: Cost, home: &Path, device_name: &str) -> Result<()> {
        self.finish(&Software::generate(passphrase, cost)?, home, device_name)
    }

    /// Every epoch key the recovery key can open, including under generations a removal cut, which
    /// something the vault still needs may have been written under. Any device can wrap to it from
    /// public keys alone, so a key counts only if it matches what its generation committed to.
    fn epoch_keys(&self, chosen: &State) -> BTreeMap<Generation, Key> {
        let (vault, current) = (chosen.vault, chosen.recovery.id());
        let whole = State::with_nothing_cut(&store::parse_all(&self.logs), &Anchor::Words(&self.key)).unwrap_or_else(|_| chosen.clone());
        let mut keys = BTreeMap::new();
        // What counts now goes first, and each is held to its own record: an id can be used again.
        for state in [chosen, &whole] {
            for wrap in &state.wraps {
                let (epoch, Sealed::Recovery(id, wrapped)) = (&wrap.epoch, &wrap.sealed) else { continue };
                if *id != current || keys.contains_key(epoch) {
                    continue;
                }
                let binding = Binding::Epoch { vault, epoch: *epoch, recipient: Recipient::Recovery };
                let opened = self.key.unwrap(vault, &chosen.recovery, &binding, wrapped);
                if let Some(key) = opened.ok().filter(|key| state.epochs.get(epoch) == Some(&epoch_commitment(&vault, *epoch, key))) {
                    keys.insert(*epoch, key);
                }
            }
        }
        keys
    }

    fn describe(&self, state: &State) -> History {
        let mut keys = self.epoch_keys(state);
        walk_links(state, &mut keys);
        let mut devices = names_in_use(state, &keys);
        devices.extend(std::iter::repeat_n("Unnamed device".to_owned(), state.active_devices().count().saturating_sub(devices.len())));
        History { devices, newest_items: newest_items(state, &keys) }
    }

    fn finish(self, device: &dyn Device, home: &Path, device_name: &str) -> Result<()> {
        if exists(home) {
            return Err(Error::VaultExists);
        }
        if !self.rivals.is_empty() {
            return Err(Error::Invalid("this copy holds more than one history of who is in the vault. Choose one"));
        }
        let parent = home.parent().ok_or(Error::NoVault)?;
        private_dir(parent)?;
        remove_stale_staging(parent);
        let staging = parent.join(format!("{STAGING_PREFIX}{}", log::hex(&crypto::random::<8>())));
        let result = self.build(device, &staging, device_name).and_then(|()| {
            if home.exists() {
                fs::remove_dir(home).map_err(|_| Error::VaultExists)?;
            }
            fs::rename(&staging, home)?;
            Ok(())
        });
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    fn build(&self, device: &dyn Device, home: &Path, device_name: &str) -> Result<()> {
        // Anyone can put a file in a folder. Only devices this history enrolled come along.
        let enrolled: Logs = self.logs.iter().filter(|(id, _)| self.state.members.contains_key(id)).map(|(id, bytes)| (*id, bytes.clone())).collect();
        store::create(home, &enrolled)?;

        let vault = self.state.vault;
        let mut keys = self.epoch_keys(&self.state);
        let fresh = new_device(device)?;
        let id = fresh.record.id();
        let after = self.state.roster_head();
        let digest = add_digest(&vault, &after, &id, &fresh.record);
        let approvals = vec![Approval { by: Approver::Recovery, signature: self.key.sign(&digest)? }];

        let mut bodies = vec![Body::DeviceAdd { after, device: fresh.record.clone(), approvals }];
        for (epoch, key) in &keys {
            let binding = Binding::Epoch { vault, epoch: *epoch, recipient: Recipient::Device(id) };
            bodies.push(Body::Wrap { epoch: *epoch, sealed: Sealed::Device(id, crypto::wrap(device.public().wrap_to(), &binding, key)?) });
        }
        walk_links(&self.state, &mut keys);
        let known = keys.iter().rev().find(|(epoch, _)| self.state.epochs.contains_key(epoch));
        let (epoch, key) = known.ok_or(Error::Corrupt("nothing is wrapped to the recovery key"))?;
        bodies.push(label_body(vault, *epoch, key, id, &unused_name(device_name, &names_in_use(&self.state, &keys)))?);

        let log_key = Ed25519KeyPair::from_seed_unchecked(fresh.log_seed.as_bytes()).map_err(|_| Error::Hardware("key generation failed"))?;
        let mut clock = Clock::default();
        clock.observe(self.state.clock);
        let mut chain = Chain { device: id, seq: 0, prev: root(&self.state.genesis, &id) };
        let bytes: Vec<u8> = bodies.iter().flat_map(|body| chain.next(clock.tick(now_ms()), body, &log_key).encode()).collect();

        write_device_files(home, device, vault, &fresh)?;
        write_private(&log::path_for(home, &id), &bytes)
    }
}
