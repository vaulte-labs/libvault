//! Whole logs forged by someone holding real keys and choosing every clock, then replayed through
//! `State::from_logs`, because that is all a hostile peer or a stolen device can hand a vault.

use std::collections::BTreeMap;

use super::tests::{Actor, Fixture};
use super::*;
use crate::crypto::Wrapped;
use crate::device::Device;
use crate::ids::VaultId;
use crate::item::{Kind, Meta, Secret};
use crate::record::{Approval, Approver, Body};
use crate::recovery::{RecoveryDraft, RecoveryKey};
use crate::store::Logs;
use crate::store::log::{self, Chain, MAX_CLOCK_LEAD_MS, now_ms};
use crate::vault::label_body;

/// Writes each device's log by hand. Entries are chained and signed honestly; only the clock is
/// the attacker's choice, as it is for anyone holding a log key.
#[derive(Clone)]
pub(super) struct Forge {
    pub recovery: RecoveryKey,
    pub vault: VaultId,
    pub logs: BTreeMap<DeviceId, Vec<Entry>>,
    genesis: Hash,
    pub first_device: DeviceId,
}

impl Forge {
    /// A vault and the device that created it.
    pub fn new() -> (Self, Actor) {
        let owner = Actor::new();
        let recovery = RecoveryKey::generate();
        let vault = VaultId::random();
        let public = recovery.new_public(vault).unwrap();
        let first_epoch = [5; 32];
        let digest = genesis_digest(&vault, &owner.fresh.record, &public, &first_epoch);
        let body = Body::Genesis {
            vault,
            recovery: public,
            device: owner.fresh.record.clone(),
            first_epoch,
            device_signature: owner.device.authorize("test").unwrap().sign(&digest).unwrap(),
            recovery_signature: recovery.sign(&digest).unwrap(),
        };
        let entry = Chain { device: owner.id(), seq: 0, prev: [0; 32] }.next(1, &body, &owner.log);
        let genesis = entry.hash();
        (Self { recovery, vault, logs: BTreeMap::from([(owner.id(), vec![entry])]), genesis, first_device: owner.id() }, owner)
    }

    /// Appends to `actor`'s log, whatever the rules say about it.
    pub fn write(&mut self, actor: &Actor, clock: u64, body: &Body) {
        let log = self.logs.entry(actor.id()).or_default();
        let (seq, prev) = log.last().map_or((0, root(&self.genesis, &actor.id())), |last| (last.seq + 1, last.hash()));
        log.push(Chain { device: actor.id(), seq, prev }.next(clock, body, &actor.log));
    }

    pub fn state(&self) -> State {
        let logs: Vec<(DeviceId, Parsed)> =
            self.logs.iter().map(|(device, entries)| (*device, Parsed { entries: entries.clone(), ..Parsed::default() })).collect();
        State::from_logs(&logs).unwrap()
    }

    pub fn approved_by_recovery(&self, digest: &Hash) -> Vec<Approval> {
        vec![Approval { by: Approver::Recovery, signature: self.recovery.sign(digest).unwrap() }]
    }

    /// Enrolls `actor` the way a recovering device does.
    pub fn enroll(&mut self, actor: &Actor, clock: u64) {
        let after = self.state().roster_head();
        let digest = add_digest(&self.vault, &after, &actor.id(), &actor.fresh.record);
        let body = Body::DeviceAdd { after, device: actor.fresh.record.clone(), approvals: self.approved_by_recovery(&digest) };
        self.write(actor, clock, &body);
    }

    /// A new space, returning what an item in it would name.
    pub fn space(&mut self, actor: &Actor, clock: u64) -> (SpaceId, Generation) {
        let (space, version) = (SpaceId::random(), Generation::first(actor.id()));
        self.write(actor, clock, &Body::Space { space, version, epoch: Generation::first(self.first_device), sealed: vec![1] });
        (space, version)
    }

    /// Removes `target`, keeping as much of its log as `by` has seen.
    pub fn remove(&mut self, by: &Actor, target: &Actor, clock: u64) {
        let after = self.state().roster_head();
        let log = &self.logs[&target.id()];
        let (entries_kept, last_kept) = (log.len() as u64, log.last().map_or([0; 32], Entry::hash));
        let digest = revoke_digest(&self.vault, &after, &by.id(), &target.id(), entries_kept, &last_kept);
        let body = Body::DeviceRevoke { after, device: target.id(), entries_kept, last_kept, approvals: self.approved_by_recovery(&digest) };
        self.write(by, clock, &body);
    }
}

fn put((space, version): (SpaceId, Generation), item: ItemId) -> Body {
    Body::ItemPut { space, item, version, batch: BatchId::random(), meta: vec![1], secret: vec![2] }
}

// The removed device: everything it writes after being cut off, in the past or the future.

#[test]
fn a_removed_device_cannot_backdate_an_entry_to_before_its_removal() {
    let (mut forge, owner) = Forge::new();
    let removed = Actor::new();
    forge.enroll(&removed, 20);
    let space = forge.space(&owner, 30);
    forge.remove(&owner, &removed, 1000);

    // Its clock only has to beat its own last entry, and the removal is far ahead of that.
    let item = ItemId::random();
    forge.write(&removed, 40, &put(space, item));

    let state = forge.state();
    assert!(!state.items.contains_key(&(space.0, item)), "an entry written after removal took effect");
    assert!(state.problems.iter().any(|problem| problem.device == removed.id()), "the attempt must be reported");
}

#[test]
fn a_removal_is_the_same_whatever_order_the_clocks_put_it_in() {
    let (mut forge, owner) = Forge::new();
    let removed = Actor::new();
    forge.enroll(&removed, 20);
    let space = forge.space(&owner, 25);
    let item = ItemId::random();
    forge.write(&removed, 30, &put(space, item));
    forge.remove(&owner, &removed, 40);

    let state = forge.state();
    assert!(state.items.contains_key(&(space.0, item)), "an entry the remover had seen must survive");
    assert_eq!(state.members[&removed.id()].standing, Standing::Removed { entries_kept: 2 });
}

#[test]
fn a_removal_cannot_cut_off_a_roster_change_that_already_counted() {
    let (mut forge, owner) = Forge::new();
    let (target, newcomer) = (Actor::new(), Actor::new());
    forge.enroll(&target, 20);
    forge.enroll(&newcomer, 30);

    let after = forge.state().roster_head();
    let digest = revoke_digest(&forge.vault, &after, &owner.id(), &target.id(), 0, &[0; 32]);
    let body = Body::DeviceRevoke { after, device: target.id(), entries_kept: 0, last_kept: [0; 32], approvals: forge.approved_by_recovery(&digest) };
    forge.write(&owner, 40, &body);

    let state = forge.state();
    assert_eq!(state.members[&target.id()].standing, Standing::Active, "the roster would differ between replay rounds");
    assert!(state.conflicts.iter().any(|problem| problem.reason == "cuts off a roster change it follows"));
}

#[test]
fn a_removal_is_final() {
    let (mut forge, owner) = Forge::new();
    let removed = Actor::new();
    forge.enroll(&removed, 20);
    let space = forge.space(&owner, 25);
    forge.remove(&owner, &removed, 30);
    let item = ItemId::random();
    forge.write(&removed, 40, &put(space, item));

    // A second removal would keep what it wrote after the first.
    forge.remove(&owner, &removed, 50);
    let state = forge.state();
    assert_eq!(state.members[&removed.id()].standing, Standing::Removed { entries_kept: 1 }, "the cutoff moved");
    assert!(!state.items.contains_key(&(space.0, item)));
}

#[test]
fn a_removed_device_cannot_be_enrolled_again_with_the_same_keys() {
    let (mut forge, owner) = Forge::new();
    let removed = Actor::new();
    forge.enroll(&removed, 20);
    forge.remove(&owner, &removed, 30);
    let head = forge.state().roster_head();

    let digest = add_digest(&forge.vault, &head, &owner.id(), &removed.fresh.record);
    let body = Body::DeviceAdd { after: head, device: removed.fresh.record.clone(), approvals: forge.approved_by_recovery(&digest) };
    forge.write(&owner, 40, &body);

    let state = forge.state();
    assert_eq!(state.roster_head(), head, "a change that changes nothing must not move the roster");
    assert_ne!(state.members[&removed.id()].standing, Standing::Active);
}

#[test]
fn a_first_entry_cannot_have_its_wrap_keys_swapped() {
    let owner = Actor::new();
    let recovery = RecoveryKey::generate();
    let vault = VaultId::random();
    let honest = recovery.new_public(vault).unwrap();
    let first_epoch = [5; 32];
    let digest = genesis_digest(&vault, &owner.fresh.record, &honest, &first_epoch);
    let attacker = RecoveryKey::generate().new_public(vault).unwrap();
    let swapped = RecoveryPublic { agreement: attacker.agreement, kem: attacker.kem, sealed_private: attacker.sealed_private, ..honest };
    let body = Body::Genesis {
        vault,
        recovery: swapped,
        device: owner.fresh.record.clone(),
        first_epoch,
        device_signature: owner.device.authorize("test").unwrap().sign(&digest).unwrap(),
        recovery_signature: recovery.sign(&digest).unwrap(),
    };
    let entry = Chain { device: owner.id(), seq: 0, prev: [0; 32] }.next(1, &body, &owner.log);
    let logs = [(owner.id(), Parsed { entries: vec![entry], ..Parsed::default() })];
    assert!(State::from_logs(&logs).is_err(), "signatures made for one set of wrap keys carried another");
}

// A retired recovery key: the old words must not outlive their rotation.

#[test]
fn an_approved_recovery_key_cannot_have_its_wrap_keys_swapped() {
    let (mut forge, _) = Forge::new();
    let writer = Actor::new();
    forge.enroll(&writer, 10);

    let draft = RecoveryDraft::new();
    let intended = draft.0.new_public(forge.vault).unwrap();
    let attacker = RecoveryDraft::new().0.new_public(forge.vault).unwrap();
    let after = forge.state().roster_head();
    let digest = rotate_digest(&forge.vault, &after, &writer.id(), &intended);
    let mut approvals = forge.approved_by_recovery(&digest);
    approvals.push(writer.approve(&digest));
    let proof = draft.0.sign(&digest).unwrap();

    // Same signing keys, so it still looks approved, but every future wrap goes to the attacker.
    let swapped = RecoveryPublic { agreement: attacker.agreement, kem: attacker.kem, sealed_private: attacker.sealed_private, ..intended };
    forge.write(&writer, 20, &Body::RecoveryRotate { after, recovery: swapped.clone(), proof, approvals });

    assert_ne!(forge.state().recovery, swapped, "the writer chose where every future key is wrapped");
}

// Key generations: identified by number and author, so both have to be earned.

fn epoch(forge: &Forge) -> Generation {
    Generation::first(forge.first_device)
}

fn junk() -> Wrapped {
    Wrapped { ephemeral: [1; 65], ciphertext: vec![2], sealed: vec![3] }
}

fn junk_wrap(to: DeviceId) -> Sealed {
    Sealed::Device(to, junk())
}

#[test]
fn a_device_cannot_skip_ahead_to_the_last_generation() {
    let (mut forge, owner) = Forge::new();
    let hostile = Actor::new();
    forge.enroll(&hostile, 10);
    // From here, `after` overflows, and a rotation would never again be the newest generation.
    let last = Generation { number: u32::MAX, author: hostile.id() };
    forge.write(&hostile, 20, &Body::Wrap { epoch: last, sealed: junk_wrap(owner.id()) });
    forge.write(&hostile, 30, &Body::EpochLink { epoch: last, previous: epoch(&forge), commitment: [0; 32], roster: [0; 32], sealed: vec![1] });

    let state = forge.state();
    assert!(state.wraps.iter().all(|wrap| wrap.epoch.number != u32::MAX), "a generation nothing leads to was accepted");
    assert!(state.links.is_empty());
}

/// Two removals race with two signatures each, so signatures are even. One was signed by the device
/// the other removes, and that counts for less whatever the dates say.
#[test]
fn a_removal_signed_by_the_device_its_rival_removes_counts_for_less() {
    let (mut forge, a) = Forge::new();
    let (b, c, d) = (Actor::new(), Actor::new(), Actor::new());
    for (actor, clock) in [(&b, 10), (&c, 11), (&d, 12)] {
        forge.enroll(actor, clock);
    }
    let after = forge.state().roster_head();
    let removal = |by: &Actor, target: &Actor, second: &Actor| {
        let log = &forge.logs[&target.id()];
        let (entries_kept, last_kept) = (log.len() as u64, log.last().map_or([0; 32], Entry::hash));
        let digest = revoke_digest(&forge.vault, &after, &by.id(), &target.id(), entries_kept, &last_kept);
        let approvals = vec![by.approve(&digest), second.approve(&digest)];
        Body::DeviceRevoke { after, device: target.id(), entries_kept, last_kept, approvals }
    };
    let (of_d, of_a) = (removal(&a, &d, &b), removal(&b, &a, &c));
    forge.write(&a, 20, &of_d);
    forge.write(&b, 30, &of_a);
    let state = forge.state();
    assert_ne!(state.members[&a.id()].standing, Standing::Active, "the earlier date won");
    assert_eq!(state.members[&d.id()].standing, Standing::Active);
}

#[test]
fn a_generation_numbered_at_or_below_the_one_it_follows_stops_its_author() {
    let (mut forge, _) = Forge::new();
    let hostile = Actor::new();
    forge.enroll(&hostile, 10);
    let link = |epoch, previous| Body::EpochLink { epoch, previous, commitment: [0; 32], roster: [0; 32], sealed: vec![1] };
    let first = epoch(&forge);
    let made = Generation { number: first.number + 1, author: hostile.id() };
    forge.write(&hostile, 20, &link(made, first));
    forge.write(&hostile, 30, &link(Generation { number: first.number, author: hostile.id() }, made));
    let after = Generation { number: made.number + 1, author: hostile.id() };
    forge.write(&hostile, 40, &link(after, made));
    assert!(!forge.state().epochs.contains_key(&after), "a device went on writing after going backwards");
}

#[test]
fn a_generation_belongs_to_the_device_that_made_it() {
    let (mut forge, owner) = Forge::new();
    let hostile = Actor::new();
    forge.enroll(&hostile, 10);
    let claimed = Generation { number: 1, author: owner.id() };
    forge.write(&hostile, 20, &Body::EpochLink { epoch: claimed, previous: epoch(&forge), commitment: [0; 32], roster: [0; 32], sealed: vec![1] });
    assert!(forge.state().links.is_empty(), "a device made a generation in another's name");
}

#[test]
fn a_space_version_cannot_be_written_over_or_claimed_for_another_device() {
    let (mut forge, owner) = Forge::new();
    let hostile = Actor::new();
    forge.enroll(&hostile, 10);
    let (space, version) = forge.space(&owner, 20);

    let body = Body::Space { space, version, epoch: epoch(&forge), sealed: vec![9] };
    forge.write(&hostile, 30, &body);
    assert_eq!(forge.state().spaces[&space][&version].sealed, vec![1], "another device replaced this version");

    let (mut forge, owner) = Forge::new();
    let (space, version) = forge.space(&owner, 20);
    forge.write(&owner, 30, &Body::Space { space, version, epoch: epoch(&forge), sealed: vec![9] });
    assert_eq!(forge.state().spaces[&space][&version].sealed, vec![1], "a version was written twice");
}

#[test]
fn a_space_version_must_follow_one_that_exists() {
    let (mut forge, owner) = Forge::new();
    let (space, version) = forge.space(&owner, 20);
    let far = Generation { number: version.number + 2, author: owner.id() };
    forge.write(&owner, 30, &Body::Space { space, version: far, epoch: epoch(&forge), sealed: vec![1] });
    let state = forge.state();
    assert!(!state.spaces[&space].contains_key(&far));
    assert!(state.conflicts.iter().any(|problem| problem.device == owner.id()), "the skipped entry must be reported");
}

#[test]
fn an_item_must_name_a_key_this_vault_knows() {
    let (mut forge, owner) = Forge::new();
    let (space, _) = forge.space(&owner, 20);
    let item = ItemId::random();
    forge.write(&owner, 30, &put((space, Generation { number: 7, author: owner.id() }), item));
    assert!(!forge.state().items.contains_key(&(space, item)));
}

#[test]
fn an_entry_that_depends_on_a_missing_one_does_not_stop_its_author() {
    let (mut forge, owner) = Forge::new();
    let (space, version) = forge.space(&owner, 20);
    let after = ItemId::random();
    forge.write(&owner, 30, &put((space, Generation { number: 7, author: owner.id() }), ItemId::random()));
    forge.write(&owner, 40, &put((space, version), after));
    let state = forge.state();
    assert!(state.items.contains_key(&(space, after)), "a device must not lose later work to one skipped entry");
    assert!(state.problems.is_empty(), "{:?}", state.problems);
}

// Poison: an enrolled device writes things nobody can open. All it should cost is the entry.

struct Poisoned {
    fixture: Fixture,
    hostile: Actor,
    space: SpaceId,
    item: ItemId,
    secret: Secret,
}

fn poisoned() -> Poisoned {
    let mut fixture = Fixture::new();
    let space = fixture.vault.space(crate::FIRST_SPACE).unwrap().id;
    let secret = Secret::Env { value: "value".to_owned() };
    let item = fixture.vault.add(&space, Meta::new(Kind::Env, "KEY"), &secret).unwrap();
    let (hostile, bystander) = (Actor::new(), Actor::new());
    fixture.enroll(&hostile);
    fixture.enroll(&bystander);
    let me = fixture.vault.me;

    let (epoch, key) = {
        let (epoch, key) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
        (epoch, key.clone())
    };
    let vault = fixture.vault.state.vault;
    let (version, _) = fixture.vault.newest_space_key(&space).unwrap();
    let next_epoch = epoch.after(hostile.id());
    let bad_put = |item| Body::ItemPut { space, item, version, batch: BatchId::random(), meta: vec![9; 40], secret: vec![9; 40] };
    let bodies = [
        label_body(vault, epoch, &key, hostile.id(), "Hostile").unwrap(),
        Body::Space { space, version: version.after(hostile.id()), epoch, sealed: vec![9; 40] },
        Body::Space { space: SpaceId::random(), version: Generation::first(hostile.id()), epoch, sealed: vec![9; 40] },
        bad_put(ItemId::random()),
        bad_put(item),
        Body::Audit { epoch, sealed: vec![9; 40] },
        Body::EpochLink { epoch: next_epoch, previous: epoch, commitment: [0; 32], roster: [0; 32], sealed: vec![9; 40] },
        Body::Wrap { epoch: next_epoch, sealed: junk_wrap(me) },
        Body::Wrap { epoch: next_epoch, sealed: Sealed::Recovery(fixture.vault.state.recovery.id(), junk()) },
    ];
    for body in &bodies {
        let entry = hostile.entry(&fixture.vault.state, body);
        fixture.vault.state.apply(&entry).unwrap();
    }
    let junk_name = Body::Label { device: bystander.id(), epoch, sealed: vec![9; 40] };
    let entry = bystander.entry(&fixture.vault.state, &junk_name);
    fixture.vault.state.apply(&entry).unwrap();
    Poisoned { fixture, hostile, space, item, secret }
}

#[test]
fn junk_from_an_enrolled_device_leaves_every_read_working() {
    let Poisoned { mut fixture, space, item, secret, .. } = poisoned();
    let vault = &mut fixture.vault;
    assert_eq!(vault.spaces().unwrap().len(), 1, "a space nobody can open must not break the list");
    let items = vault.items(&space).unwrap();
    assert_eq!(items.iter().map(|item| item.meta.name.as_str()).collect::<Vec<_>>(), ["KEY"]);
    assert_eq!(vault.secret(&space, &item).unwrap(), secret, "junk must not displace the last readable value");
    assert_eq!(vault.devices().unwrap().len(), 3);
    assert!(vault.audit().is_ok());
}

#[test]
fn junk_cannot_stop_a_device_unlocking() {
    let Poisoned { mut fixture, space, item, secret, .. } = poisoned();
    fixture.vault.lock();
    fixture.vault.unlock("test").unwrap();
    assert_eq!(fixture.vault.secret(&space, &item).unwrap(), secret);
}

#[test]
fn the_device_that_wrote_junk_can_still_be_removed() {
    let Poisoned { mut fixture, hostile, space, item, secret } = poisoned();
    let removal = fixture.vault.prepare_removal("Hostile").unwrap();
    let approvals = fixture.recovery_approval(&removal.digest);
    fixture.vault.remove_device(&removal, approvals).unwrap();
    assert_ne!(fixture.vault.state.members[&hostile.id()].standing, Standing::Active);
    assert_eq!(fixture.vault.secret(&space, &item).unwrap(), secret);
}

#[test]
fn junk_does_not_make_every_sync_lock_the_vault() {
    let Poisoned { mut fixture, .. } = poisoned();
    fixture.vault.lock();
    fixture.vault.unlock("test").unwrap();
    assert!(!fixture.vault.keys_are_stale(), "a key nothing can open is not a newer key");
}

#[test]
fn a_listing_from_another_device_cannot_carry_terminal_escapes() {
    let mut fixture = Fixture::new();
    let space = fixture.vault.space(crate::FIRST_SPACE).unwrap().id;
    let hostile = Actor::new();
    fixture.enroll(&hostile);
    let key = fixture.vault.newest_space_key(&space).unwrap();
    let meta = Meta::new(Kind::Env, "\u{1b}[2Jspoofed");
    let body = fixture.vault.put_body(&key, space, ItemId::random(), BatchId::random(), &meta, &Secret::Env { value: "v".to_owned() }).unwrap();
    let entry = hostile.entry(&fixture.vault.state, &body);
    fixture.vault.state.apply(&entry).unwrap();
    assert_eq!(fixture.vault.items(&space).unwrap(), Vec::new());
}

// Clocks: a real log key can sign any time at all, and the newest write wins.

/// `actor`'s log, enrolled and then one more entry at `clock`.
fn log_ending_at(fixture: &mut Fixture, actor: &Actor, clock: u64) -> Vec<u8> {
    let after = fixture.vault.state.roster_head();
    let digest = add_digest(&fixture.vault.state.vault, &after, &actor.id(), &actor.fresh.record);
    let enroll = Body::DeviceAdd { after, device: actor.fresh.record.clone(), approvals: fixture.recovery_approval(&digest) };
    let first = actor.entry(&fixture.vault.state, &enroll);
    let body = Body::Audit { epoch: Generation::first(fixture.vault.me), sealed: vec![1] };
    let second = Chain { device: actor.id(), seq: 1, prev: first.hash() }.next(clock, &body, &actor.log);
    [first.encode(), second.encode()].concat()
}

#[test]
fn a_log_dated_far_ahead_of_this_device_waits_and_is_reported() {
    let mut fixture = Fixture::new();
    let hostile = Actor::new();
    let far_ahead = (now_ms() + 2 * MAX_CLOCK_LEAD_MS) << 16;
    let bytes = log_ending_at(&mut fixture, &hostile, far_ahead);

    fixture.vault.merge_logs(Logs::from([(hostile.id(), bytes)]), None).unwrap();

    assert!(fixture.vault.state.clock < far_ahead, "this device's clock was dragged into the future");
    assert!(fixture.vault.problems().any(|problem| problem.device == hostile.id()), "the refusal must be reported");
    assert_eq!(fixture.vault.state.heads[&hostile.id()].seq, 0, "what came before it is taken, and nothing after");
}

#[test]
fn a_tail_this_device_never_signed_cannot_claim_it_was_rolled_back() {
    let mut fixture = Fixture::new();
    let me = fixture.vault.me;
    let ours = std::fs::read(log::path_for(&fixture.vault.home, &me)).unwrap();
    let last = log::parse(&ours).entries.pop().unwrap();
    let body = Body::Audit { epoch: Generation::first(me), sealed: vec![1] };
    let forged = Chain { device: me, seq: last.seq + 1, prev: last.hash() }.next(last.clock + 1, &body, &Actor::new().log);

    fixture.vault.merge_logs(Logs::from([(me, [ours, forged.encode()].concat())]), None).unwrap();

    assert_eq!(fixture.vault.problems().count(), 0, "anyone can write to a folder, so an alarm has to be earned");
}

#[test]
fn a_log_a_little_ahead_of_this_device_is_taken() {
    let mut fixture = Fixture::new();
    let device = Actor::new();
    let bytes = log_ending_at(&mut fixture, &device, (now_ms() + MAX_CLOCK_LEAD_MS / 2) << 16);
    fixture.vault.merge_logs(Logs::from([(device.id(), bytes)]), None).unwrap();
    assert!(fixture.vault.state.members.contains_key(&device.id()), "honest clocks disagree by this much");
}

#[test]
fn recovery_leaves_out_what_is_dated_far_in_the_future_and_carries_on() {
    let mut fixture = Fixture::new();
    let hostile = Actor::new();
    let bytes = log_ending_at(&mut fixture, &hostile, u64::MAX);
    std::fs::write(crate::store::log::path_for(&fixture.vault.home, &hostile.id()), bytes).unwrap();
    let words = fixture.recovery.words();
    let opened = crate::Recovery::open(&fixture.vault.home, &words).expect("one planted file must not stop a recovery");
    assert!(opened.clock_is_believable(), "this clock would be every later entry's");
}

// An outsider: no keys anyone gave it, and write access to a folder.

#[test]
fn a_log_from_a_device_nobody_approved_is_refused_and_not_kept() {
    let mut fixture = Fixture::new();
    let outsider = Actor::new();
    let after = fixture.vault.state.roster_head();
    let body = Body::DeviceAdd { after, device: outsider.fresh.record.clone(), approvals: vec![] };
    let entry = outsider.entry(&fixture.vault.state, &body);
    let bytes = entry.encode();

    fixture.vault.merge_logs(Logs::from([(outsider.id(), bytes)]), None).unwrap();

    assert!(!crate::store::log::path_for(&fixture.vault.home, &outsider.id()).exists(), "the log would be copied onward to every device");
    assert!(!fixture.vault.state.heads.contains_key(&outsider.id()));
}

// A crash in the middle of a change: everything that protects secrets has to land together.

#[test]
fn a_removal_and_the_keys_that_replace_what_it_ended_land_as_one() {
    let mut fixture = Fixture::new();
    let space = fixture.vault.space(crate::FIRST_SPACE).unwrap().id;
    fixture.vault.add(&space, Meta::new(Kind::Env, "KEY"), &Secret::Env { value: "v".to_owned() }).unwrap();
    let (staying, leaving) = (Actor::new(), Actor::new());
    fixture.enroll(&staying);
    fixture.enroll(&leaving);
    let (epoch, key) = {
        let (epoch, key) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
        (epoch, key.clone())
    };
    let label = label_body(fixture.vault.state.vault, epoch, &key, leaving.id(), "Leaving").unwrap();
    let entry = leaving.entry(&fixture.vault.state, &label);
    fixture.vault.state.apply(&entry).unwrap();
    drop(staying);

    let removal = fixture.vault.prepare_removal("Leaving").unwrap();
    let approvals = fixture.recovery_approval(&removal.digest);
    fixture.vault.remove_device(&removal, approvals).unwrap();

    let mine = log::parse(&fixture.vault.all_logs().unwrap()[&fixture.vault.me]);
    let batches: Vec<Vec<Body>> = mine
        .entries
        .iter()
        .filter_map(|entry| match Body::decode(entry.kind, &entry.body).unwrap() {
            Body::Batch { bodies } => Some(bodies),
            _ => None,
        })
        .collect();
    let [batch] = batches.as_slice() else { panic!("one entry should hold the removal: {}", batches.len()) };
    assert!(batch.iter().any(|body| matches!(body, Body::DeviceRevoke { .. })), "the removal");
    assert!(batch.iter().any(|body| matches!(body, Body::EpochLink { .. })), "the new epoch");
    assert!(batch.iter().filter(|body| matches!(body, Body::Wrap { .. })).count() >= 2, "the wraps");
}

// Retired words: a rotation by a device that had not heard they were retired.

#[test]
fn a_rotation_wrapped_to_retired_words_is_rotated_again() {
    let mut fixture = Fixture::new();
    let space = fixture.vault.space(crate::FIRST_SPACE).unwrap().id;
    fixture.vault.add(&space, Meta::new(Kind::Env, "KEY"), &Secret::Env { value: "v".to_owned() }).unwrap();
    let unaware = Actor::new();
    fixture.enroll(&unaware);

    let old_recovery = fixture.vault.state.recovery.clone();
    let heard = fixture.vault.state.roster_head();
    let draft = RecoveryDraft::new();
    let rotation = fixture.vault.prepare_recovery_rotation(&draft.0).unwrap();
    let approvals = fixture.both_approvals(&rotation.digest);
    fixture.vault.rotate_recovery(rotation, approvals).unwrap();

    // Another device rotated at the same number, not having heard, so it wrapped to the old words.
    let (epoch, key) = {
        let (epoch, key) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
        (epoch, key.clone())
    };
    let previous = fixture.vault.state.links[&epoch][0].0;
    let parallel = previous.after(unaware.id());
    let vault = fixture.vault.state.vault;
    let link =
        Body::EpochLink { epoch: parallel, previous, commitment: epoch_commitment(&vault, parallel, &key), roster: heard, sealed: vec![0; 80] };
    let binding = crate::binding::Binding::Epoch { vault, epoch: parallel, recipient: crate::binding::Recipient::Recovery };
    let wrapped = crate::crypto::wrap(old_recovery.wrap_to(), &binding, &key).unwrap();
    let to_old_words = Body::Wrap { epoch: parallel, sealed: Sealed::Recovery(old_recovery.id(), wrapped) };
    for body in [&link, &to_old_words] {
        let entry = unaware.entry(&fixture.vault.state, body);
        fixture.vault.state.apply(&entry).unwrap();
    }
    let binding = crate::binding::Binding::Epoch { vault, epoch: parallel, recipient: crate::binding::Recipient::Device(fixture.vault.me) };
    let me = fixture.vault.state.members[&fixture.vault.me].record.keys.clone();
    let mine = Body::Wrap { epoch: parallel, sealed: Sealed::Device(fixture.vault.me, crate::crypto::wrap(me.wrap_to(), &binding, &key).unwrap()) };
    let entry = unaware.entry(&fixture.vault.state, &mine);
    fixture.vault.state.apply(&entry).unwrap();

    fixture.vault.lock();
    fixture.vault.unlock("test").unwrap();
    fixture.vault.repair().unwrap();

    assert!(!fixture.vault.state.clean_epochs().contains(&parallel), "the retired words could hold that");
    let item = fixture.vault.add(&space, Meta::new(Kind::Env, "NEW"), &Secret::Env { value: "v".to_owned() }).unwrap();
    let Change::Put { version, .. } = fixture.vault.state.items[&(space, item)].last().unwrap().change else { panic!("a put") };
    assert_ne!(fixture.vault.state.spaces[&space][&version].epoch, parallel, "a new secret went under a key the retired words open");
}

// Fork choice: who is on the roster must not come down to a clock someone chose.

#[test]
fn the_recovery_key_outranks_a_lone_device_whatever_the_clocks_say() {
    let (mut forge, lost) = Forge::new();
    let head = forge.state().roster_head();
    let (recovered, planted) = (Actor::new(), Actor::new());

    // The device that was lost approves a device of its own, at the head it last saw, dated first.
    let digest = add_digest(&forge.vault, &head, &planted.id(), &planted.fresh.record);
    let approvals = vec![lost.approve(&digest)];
    forge.write(&planted, 2, &Body::DeviceAdd { after: head, device: planted.fresh.record.clone(), approvals });

    // Later by the clock, the person recovers with the words at the same position.
    let digest = add_digest(&forge.vault, &head, &recovered.id(), &recovered.fresh.record);
    let approvals = forge.approved_by_recovery(&digest);
    forge.write(&recovered, 500, &Body::DeviceAdd { after: head, device: recovered.fresh.record.clone(), approvals });

    let state = forge.state();
    assert!(state.members.contains_key(&recovered.id()), "the words lost to a clock");
    assert!(!state.members.contains_key(&planted.id()));
}

#[test]
fn a_chain_of_changes_is_followed_whatever_order_its_clocks_are_in() {
    let (mut forge, owner) = Forge::new();
    let (first, second) = (Actor::new(), Actor::new());
    let head = forge.state().roster_head();
    let digest = add_digest(&forge.vault, &head, &first.id(), &first.fresh.record);
    let approvals = forge.approved_by_recovery(&digest);
    forge.write(&first, 900, &Body::DeviceAdd { after: head, device: first.fresh.record.clone(), approvals });
    let head = forge.state().roster_head();

    // Dated before the change it follows, which only a writer with a wrong clock would do.
    let digest = add_digest(&forge.vault, &head, &second.id(), &second.fresh.record);
    let approvals = forge.approved_by_recovery(&digest);
    forge.write(&second, 5, &Body::DeviceAdd { after: head, device: second.fresh.record.clone(), approvals });

    let state = forge.state();
    assert_eq!(state.roster.len(), 3, "a change was lost to its own clock");
    assert!(state.members.contains_key(&second.id()));
    assert!(state.members.contains_key(&owner.id()));
}

#[test]
fn a_batch_holds_one_roster_change() {
    let owner = Actor::new();
    let add = Body::DeviceAdd { after: [0; 32], device: owner.fresh.record.clone(), approvals: vec![] };
    let batch = Body::Batch { bodies: vec![add.clone(), add] };
    assert!(Body::decode(batch.kind(), &batch.encode()).is_err());
}

// Names: a removal by name must reach the device it names.

#[test]
fn a_device_cannot_rename_another() {
    let mut fixture = Fixture::new();
    let hostile = Actor::new();
    fixture.enroll(&hostile);
    let me = fixture.vault.me;
    let (epoch, key) = {
        let (epoch, key) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
        (epoch, key.clone())
    };
    let label = label_body(fixture.vault.state.vault, epoch, &key, me, "Stolen Mac").unwrap();
    let entry = hostile.entry(&fixture.vault.state, &label);
    assert!(fixture.vault.state.apply(&entry).is_err());
    assert_eq!(fixture.vault.device_label(&me).as_deref(), Some("Owner"));
}

#[test]
fn a_device_hiding_behind_a_junk_name_can_still_be_removed() {
    let mut fixture = Fixture::new();
    let hostile = Actor::new();
    fixture.enroll(&hostile);
    let (epoch, _) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
    let entry = hostile.entry(&fixture.vault.state, &Body::Label { device: hostile.id(), epoch, sealed: vec![9; 80] });
    fixture.vault.state.apply(&entry).unwrap();
    let shown = fixture.vault.devices().unwrap().into_iter().find(|device| !device.is_this_device).unwrap().name;
    assert_eq!(fixture.vault.prepare_removal(&shown).unwrap().device, hostile.id());
}

#[test]
fn removing_by_a_name_two_devices_share_never_picks_this_one_and_never_guesses() {
    let mut fixture = Fixture::new();
    let (first, second) = (Actor::new(), Actor::new());
    fixture.enroll(&first);
    let (epoch, key) = {
        let (epoch, key) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
        (epoch, key.clone())
    };
    let vault = fixture.vault.state.vault;
    let label = label_body(vault, epoch, &key, first.id(), "Owner").unwrap();
    let entry = first.entry(&fixture.vault.state, &label);
    fixture.vault.state.apply(&entry).unwrap();
    assert_eq!(fixture.vault.prepare_removal("Owner").unwrap().device, first.id(), "this device shares the name, and must not be the one chosen");

    fixture.enroll(&second);
    let label = label_body(vault, epoch, &key, second.id(), "Owner").unwrap();
    let entry = second.entry(&fixture.vault.state, &label);
    fixture.vault.state.apply(&entry).unwrap();
    assert!(fixture.vault.prepare_removal("Owner").is_err(), "two others share it, so this must not guess");
}

#[test]
fn settling_a_conflict_cannot_drop_this_device() {
    let mut fixture = Fixture::new();
    let vault_id = fixture.vault.state.vault;
    let fork_point = fixture.vault.state.roster_head();

    // This device moves the roster on, by adding another.
    let other = Actor::new();
    let enrollment = fixture.vault.prepare_enrollment(other.fresh.record.clone(), "Other").unwrap();
    let approvals = fixture.recovery_approval(&enrollment.digest);
    fixture.vault.enroll(&enrollment, approvals).unwrap();

    // The other side of a fork from before that, which removes this device, dated first.
    let hostile = Actor::new();
    let genesis = fixture.vault.state.genesis;
    let mut chain = Chain { device: hostile.id(), seq: 0, prev: root(&genesis, &hostile.id()) };
    let digest = add_digest(&vault_id, &fork_point, &hostile.id(), &hostile.fresh.record);
    let add = Body::DeviceAdd { after: fork_point, device: hostile.fresh.record.clone(), approvals: fixture.recovery_approval(&digest) };
    let first = chain.next(2, &add, &hostile.log);
    let digest = revoke_digest(&vault_id, &first.hash(), &hostile.id(), &fixture.vault.me, 5, &[0; 32]);
    let revoke = Body::DeviceRevoke {
        after: first.hash(),
        device: fixture.vault.me,
        entries_kept: 5,
        last_kept: [0; 32],
        approvals: fixture.recovery_approval(&digest),
    };
    let second = chain.next(3, &revoke, &hostile.log);
    let bytes = [first.encode(), second.encode()].concat();

    let words = fixture.recovery.clone();
    fixture.vault.merge_logs(Logs::from([(hostile.id(), bytes)]), Some(&words)).unwrap();
    assert_eq!(fixture.vault.state.members[&fixture.vault.me].standing, Standing::Active, "the override removed the device using it");
    assert!(!fixture.vault.state.members.contains_key(&hostile.id()));
}

// What the protocol audit proved against the code before these rules.

fn relocked(fixture: &mut Fixture) {
    fixture.vault.lock();
    fixture.vault.unlock("test").unwrap();
}

/// A vault with one item, and a hostile device enrolled in it.
fn with_hostile() -> (Fixture, Actor, SpaceId, ItemId, Secret) {
    let mut fixture = Fixture::new();
    let space = fixture.vault.space(crate::FIRST_SPACE).unwrap().id;
    let secret = Secret::Env { value: "value".to_owned() };
    let item = fixture.vault.add(&space, Meta::new(Kind::Env, "KEY"), &secret).unwrap();
    let hostile = Actor::new();
    fixture.enroll(&hostile);
    (fixture, hostile, space, item, secret)
}

#[test]
fn a_wrap_of_the_wrong_key_for_a_generation_changes_nothing() {
    let (mut fixture, hostile, space, item, secret) = with_hostile();
    let (epoch, _) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
    let (vault, me) = (fixture.vault.state.vault, fixture.vault.me);
    let binding = crate::binding::Binding::Epoch { vault, epoch, recipient: crate::binding::Recipient::Device(me) };
    let keys = fixture.vault.state.members[&me].record.keys.clone();
    // It opens. It is just not the key this generation committed to.
    let wrapped = crate::crypto::wrap(keys.wrap_to(), &binding, &crate::crypto::Key::generate()).unwrap();
    let entry = hostile.entry(&fixture.vault.state, &Body::Wrap { epoch, sealed: Sealed::Device(me, wrapped) });
    fixture.vault.state.apply(&entry).unwrap();

    relocked(&mut fixture);
    assert_eq!(fixture.vault.secret(&space, &item).unwrap(), secret, "one wrap emptied the vault");
}

#[test]
fn a_generation_opens_only_with_the_key_it_committed_to() {
    let (mut fixture, hostile, ..) = with_hostile();
    let (epoch, _) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
    let (vault, me) = (fixture.vault.state.vault, fixture.vault.me);
    let next = epoch.after(hostile.id());
    let binding = crate::binding::Binding::Epoch { vault, epoch: next, recipient: crate::binding::Recipient::Device(me) };
    let keys = fixture.vault.state.members[&me].record.keys.clone();
    let committed = crate::crypto::Key::generate();
    let bodies = [
        Body::EpochLink {
            epoch: next,
            previous: epoch,
            commitment: epoch_commitment(&vault, next, &committed),
            roster: fixture.vault.state.roster_head(),
            sealed: vec![9; 80],
        },
        Body::Wrap {
            epoch: next,
            sealed: Sealed::Device(me, crate::crypto::wrap(keys.wrap_to(), &binding, &crate::crypto::Key::generate()).unwrap()),
        },
    ];
    for body in &bodies {
        let entry = hostile.entry(&fixture.vault.state, body);
        fixture.vault.state.apply(&entry).unwrap();
    }
    relocked(&mut fixture);
    assert_eq!(fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap().0, epoch, "readers would each hold a different key");
}

#[test]
fn a_new_generation_with_a_link_that_leads_nowhere_costs_nothing() {
    let (mut fixture, hostile, space, item, secret) = with_hostile();
    let (epoch, _) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
    let (vault, me) = (fixture.vault.state.vault, fixture.vault.me);
    let next = epoch.after(hostile.id());
    let key = crate::crypto::Key::generate();
    let binding = crate::binding::Binding::Epoch { vault, epoch: next, recipient: crate::binding::Recipient::Device(me) };
    let keys = fixture.vault.state.members[&me].record.keys.clone();
    let bodies = [
        Body::EpochLink {
            epoch: next,
            previous: epoch,
            commitment: epoch_commitment(&vault, next, &key),
            roster: fixture.vault.state.roster_head(),
            sealed: vec![9; 80],
        },
        Body::Wrap { epoch: next, sealed: Sealed::Device(me, crate::crypto::wrap(keys.wrap_to(), &binding, &key).unwrap()) },
    ];
    for body in &bodies {
        let entry = hostile.entry(&fixture.vault.state, body);
        fixture.vault.state.apply(&entry).unwrap();
    }
    relocked(&mut fixture);
    assert_eq!(fixture.vault.secret(&space, &item).unwrap(), secret, "a real key on a dead link hid everything older");
}

#[test]
fn a_rotation_is_seen_whatever_higher_generation_sits_above_it() {
    let (mut fixture, hostile, ..) = with_hostile();
    let (epoch, key) = {
        let (epoch, key) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
        (epoch, key.clone())
    };
    let (vault, me) = (fixture.vault.state.vault, fixture.vault.me);
    let (one, two) = (epoch.after(hostile.id()), epoch.after(hostile.id()).after(hostile.id()));
    for (generation, previous) in [(one, epoch), (two, one)] {
        let body = Body::EpochLink {
            epoch: generation,
            previous,
            commitment: epoch_commitment(&vault, generation, &key),
            roster: fixture.vault.state.roster_head(),
            sealed: vec![9; 80],
        };
        let entry = hostile.entry(&fixture.vault.state, &body);
        fixture.vault.state.apply(&entry).unwrap();
    }
    let entry = hostile.entry(&fixture.vault.state, &Body::Wrap { epoch: two, sealed: junk_wrap(me) });
    fixture.vault.state.apply(&entry).unwrap();
    relocked(&mut fixture);
    assert!(!fixture.vault.keys_are_stale());

    // A real wrap at a lower number than the junk one, which a newest-only check would never see.
    let entry = hostile.entry(&fixture.vault.state, &Body::Wrap { epoch: one, sealed: junk_wrap(me) });
    fixture.vault.state.apply(&entry).unwrap();
    assert!(fixture.vault.keys_are_stale(), "a generation this device has not tried must count");
}

#[test]
fn only_another_enrolled_device_can_give_a_second_approval() {
    let (fixture, hostile, ..) = with_hostile();
    let digest = [7; 32];
    let vault = &fixture.vault;
    vault.verify_peer_approval(&digest, &hostile.approve(&digest), None).unwrap();

    assert!(vault.verify_peer_approval(&[8; 32], &hostile.approve(&digest), None).is_err(), "it signed something else");
    assert!(vault.verify_peer_approval(&digest, &Actor::new().approve(&digest), None).is_err(), "a stranger is nobody");
    assert!(vault.verify_peer_approval(&digest, &hostile.approve(&digest), Some(&hostile.id())).is_err(), "it has no say in its own removal");
    let recovery = fixture.recovery_approval(&digest).remove(0);
    assert!(fixture.vault.verify_peer_approval(&digest, &recovery, None).is_err(), "the words are not a device");
}

#[test]
fn an_approval_cannot_be_copied_into_another_device_s_log() {
    let (mut forge, owner) = Forge::new();
    let (copier, joining) = (Actor::new(), Actor::new());
    forge.enroll(&copier, 10);

    let after = forge.state().roster_head();
    let digest = add_digest(&forge.vault, &after, &owner.id(), &joining.fresh.record);
    let body = Body::DeviceAdd { after, device: joining.fresh.record.clone(), approvals: forge.approved_by_recovery(&digest) };
    forge.write(&owner, 100, &body);
    let honest = forge.state().roster_head();

    // The same change, in another log, dated earlier so that it would take the position.
    forge.write(&copier, 11, &body);
    assert_eq!(forge.state().roster_head(), honest, "a copy took the position, and every later change would have missed it");
}

#[test]
fn a_rotation_of_the_recovery_key_beats_retired_words_at_the_same_position() {
    let (mut forge, owner) = Forge::new();
    let planted = Actor::new();
    let after = forge.state().roster_head();

    let draft = RecoveryDraft::new();
    let recovery = draft.0.new_public(forge.vault).unwrap();
    let digest = rotate_digest(&forge.vault, &after, &owner.id(), &recovery);
    let (proof, approvals) = (draft.0.sign(&digest).unwrap(), vec![owner.approve(&digest)]);
    forge.write(&owner, 500, &Body::RecoveryRotate { after, recovery: recovery.clone(), proof, approvals });

    // Signed with the old words, at the position before they were retired, and dated first.
    let digest = add_digest(&forge.vault, &after, &planted.id(), &planted.fresh.record);
    let body = Body::DeviceAdd { after, device: planted.fresh.record.clone(), approvals: forge.approved_by_recovery(&digest) };
    forge.write(&planted, 2, &body);

    let state = forge.state();
    assert_eq!(state.recovery, recovery, "retired words beat the rotation that retired them");
    assert!(!state.members.contains_key(&planted.id()));
}

#[test]
fn two_devices_outrank_retired_words_at_the_same_position() {
    let (mut forge, owner) = Forge::new();
    let (second, third, planted) = (Actor::new(), Actor::new(), Actor::new());
    forge.enroll(&second, 10);
    let after = forge.state().roster_head();

    let digest = add_digest(&forge.vault, &after, &owner.id(), &third.fresh.record);
    let approvals = vec![owner.approve(&digest), second.approve(&digest)];
    forge.write(&owner, 500, &Body::DeviceAdd { after, device: third.fresh.record.clone(), approvals });

    let digest = add_digest(&forge.vault, &after, &planted.id(), &planted.fresh.record);
    let body = Body::DeviceAdd { after, device: planted.fresh.record.clone(), approvals: forge.approved_by_recovery(&digest) };
    forge.write(&planted, 11, &body);

    let state = forge.state();
    assert!(state.members.contains_key(&third.id()));
    assert!(!state.members.contains_key(&planted.id()), "one set of words beat two devices");
}

#[test]
fn a_recovery_key_cannot_be_named_without_its_own_signature() {
    let (mut forge, owner) = Forge::new();
    // Public in every log, so anyone can read it and try to make the owner's words open a vault.
    let victim = RecoveryDraft::new().0.new_public(forge.vault).unwrap();
    let after = forge.state().roster_head();
    let digest = rotate_digest(&forge.vault, &after, &owner.id(), &victim);
    let approvals = vec![owner.approve(&digest)];
    let proof = forge.recovery.sign(&digest).unwrap();
    forge.write(&owner, 10, &Body::RecoveryRotate { after, recovery: victim.clone(), proof, approvals });
    assert_ne!(forge.state().recovery, victim, "someone else's words now open this vault");
}

#[test]
fn the_words_alone_cannot_replace_themselves() {
    let (mut forge, owner) = Forge::new();
    let draft = RecoveryDraft::new();
    let recovery = draft.0.new_public(forge.vault).unwrap();
    let after = forge.state().roster_head();
    let digest = rotate_digest(&forge.vault, &after, &owner.id(), &recovery);
    let (proof, approvals) = (draft.0.sign(&digest).unwrap(), forge.approved_by_recovery(&digest));
    forge.write(&owner, 10, &Body::RecoveryRotate { after, recovery: recovery.clone(), proof, approvals });
    assert_ne!(forge.state().recovery, recovery, "leaked words could lock everyone out for good");
}

#[test]
fn a_first_version_from_another_device_does_not_stop_the_device_that_made_the_space() {
    let (mut forge, owner) = Forge::new();
    let hostile = Actor::new();
    forge.enroll(&hostile, 10);
    let (space, version) = (SpaceId::random(), Generation::first(owner.id()));
    forge.write(&hostile, 11, &Body::Space { space, version: Generation::first(hostile.id()), epoch: epoch(&forge), sealed: vec![9] });
    forge.write(&owner, 20, &Body::Space { space, version, epoch: epoch(&forge), sealed: vec![1] });
    let later = forge.space(&owner, 30);
    let state = forge.state();
    assert!(state.problems.iter().all(|problem| problem.device != owner.id()), "one dated entry stopped an honest device: {:?}", state.problems);
    assert!(state.spaces.contains_key(&later.0));
    assert!(state.spaces[&space].contains_key(&version));
}

#[test]
fn a_different_history_inside_a_removal_s_cutoff_does_not_count() {
    let (mut forge, owner) = Forge::new();
    let removed = Actor::new();
    forge.enroll(&removed, 20);
    let space = forge.space(&owner, 25);
    let honest = ItemId::random();
    forge.write(&removed, 30, &put(space, honest));
    forge.remove(&owner, &removed, 40);

    // A second history of the same length, with a different last entry.
    let forged = ItemId::random();
    forge.logs.get_mut(&removed.id()).unwrap().pop();
    forge.write(&removed, 50, &put(space, forged));

    let state = forge.state();
    assert!(!state.items.contains_key(&(space.0, forged)), "a removed device rewrote what its removal kept");
    let last = forge.logs[&removed.id()].last().unwrap().seq;
    assert!(state.problems.iter().any(|problem| problem.reason == "contradicts what its removal kept" && problem.seq == last));
}

#[test]
fn a_wrap_someone_else_made_does_not_set_off_a_rotation() {
    let (mut fixture, hostile, space, ..) = with_hostile();
    let removed = Actor::new();
    fixture.enroll(&removed);
    let name = fixture.vault.device_name(&removed.id());
    let removal = fixture.vault.prepare_removal(&name).unwrap();
    let approvals = fixture.recovery_approval(&removal.digest);
    fixture.vault.remove_device(&removal, approvals).unwrap();
    let (epoch, _) = fixture.vault.keys.as_ref().unwrap().newest_epoch().unwrap();
    let entry = hostile.entry(&fixture.vault.state, &Body::Wrap { epoch, sealed: junk_wrap(removed.id()) });
    fixture.vault.state.apply(&entry).unwrap();

    let versions = fixture.vault.state.spaces[&space].len();
    fixture.vault.repair().unwrap();
    assert_eq!(fixture.vault.state.spaces[&space].len(), versions, "one junk entry made this device rekey every space");
}

#[test]
fn a_rotation_never_writes_an_older_value_over_a_newer_one() {
    let (mut fixture, hostile, space, item, _) = with_hostile();
    let key = fixture.vault.newest_space_key(&space).unwrap();
    let newer = Secret::Env { value: "changed".to_owned() };
    let body = fixture.vault.put_body(&key, space, item, BatchId::random(), &Meta::new(Kind::Env, "KEY"), &newer).unwrap();
    let Body::ItemPut { batch, meta, version, .. } = body else { panic!("a put") };
    // It lists, but this device cannot open the value, as if its key had not reached here yet.
    let unreadable = Body::ItemPut { space, item, version, batch, meta, secret: vec![9; 80] };
    let entry = hostile.entry(&fixture.vault.state, &unreadable);
    fixture.vault.state.apply(&entry).unwrap();

    let draft = RecoveryDraft::new();
    let rotation = fixture.vault.prepare_recovery_rotation(&draft.0).unwrap();
    let mut approvals = fixture.recovery_approval(&rotation.digest);
    approvals.push(hostile.approve(&rotation.digest));
    fixture.vault.rotate_recovery(rotation, approvals).unwrap();

    let versions = &fixture.vault.state.items[&(space, item)];
    assert!(
        matches!(versions.last().unwrap().change, Change::Put { secret: ref written, .. } if *written == vec![9; 80]),
        "the old value was written back as newest"
    );
}

#[test]
fn logs_from_invented_devices_cost_one_sync_a_limited_amount() {
    let mut fixture = Fixture::new();
    let genesis = fixture.vault.state.genesis;
    let actor = Actor::new();
    let body = Body::DeviceAdd { after: genesis, device: actor.fresh.record.clone(), approvals: vec![] };
    let entry = |device: DeviceId| Chain { device, seq: 0, prev: root(&genesis, &device) }.next(1, &body, &actor.log).encode();
    let invented: Logs = (0..200u8).map(|n| ([n; 16].into(), entry([n; 16].into()))).collect();
    fixture.vault.merge_logs(invented, None).unwrap();
    let turned_away = fixture.vault.problems().filter(|problem| problem.reason == "more new devices than one sync can hold").count();
    assert_eq!(turned_away, 200 - crate::sync::merge::tests::tests_new_device_limit());
}

#[test]
fn an_entry_from_a_newer_version_is_named_as_that_not_as_tampering() {
    let (mut forge, _) = Forge::new();
    let device = Actor::new();
    forge.enroll(&device, 10);
    let log = forge.logs.get_mut(&device.id()).unwrap();
    let last = log.last().unwrap();
    let mut chain = Chain { device: device.id(), seq: last.seq + 1, prev: last.hash() };
    let mut entry = chain.next(20, &Body::Batch { bodies: vec![] }, &device.log);
    entry.kind = 200;
    entry.signature = device.log.sign(&entry.signed_bytes()).as_ref().try_into().unwrap();
    log.push(entry);
    assert!(forge.state().problems.iter().any(|problem| problem.reason == "written by a newer version of Vaulte"));
}
