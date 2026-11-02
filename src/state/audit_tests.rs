//! What the final audit proved, each as the attack with its outcome turned around. Hostile devices
//! here write their logs by hand, so nothing limits them but what replay enforces.

use std::path::Path;

use super::attacks::Forge;
use super::tests::{Actor, Fixture};
use super::*;
use crate::binding::{Binding, Part, Recipient};
use crate::crypto::{self, Key};
use crate::device::software::{Cost, Software};
use crate::item::{Kind, Meta, Secret};
use crate::record::{Approval, Approver, Body};
use crate::recovery::{RecoveryDraft, RecoveryKey};
use crate::store::Logs;
use crate::store::log::{self, Chain, now_ms};
use crate::sync::folder::write_logs;
use crate::vault::Vault;
use crate::{FIRST_SPACE, Recovery, space};

fn second_device(home: &Path, words: &str, at: &Path, name: &str) -> Vault {
    Recovery::open(home, words).unwrap().finish_with_passphrase("pass", Cost::FAST, at, name).unwrap();
    let mut vault = Vault::open(at, Some("pass")).unwrap();
    vault.unlock("test").unwrap();
    vault
}

/// A hostile device holding its own keys, writing its own log by hand.
struct Bad {
    actor: Actor,
    genesis: Hash,
    entries: Vec<Entry>,
}

impl Bad {
    /// Enrolled at this vault's head, approved by the words.
    fn enroll(vault: &Vault, words: &RecoveryKey) -> Self {
        let actor = Actor::new();
        let after = vault.state.roster_head();
        let digest = add_digest(&vault.state.vault, &after, &actor.id(), &actor.fresh.record);
        let approvals = vec![Approval { by: Approver::Recovery, signature: words.sign(&digest).unwrap() }];
        let mut bad = Self { actor, genesis: vault.state.genesis, entries: Vec::new() };
        let record = bad.actor.fresh.record.clone();
        bad.write(vault.state.clock + 1, &Body::DeviceAdd { after, device: record, approvals });
        bad
    }

    fn id(&self) -> DeviceId {
        self.actor.id()
    }

    fn write(&mut self, clock: u64, body: &Body) {
        let (seq, prev) = self.entries.last().map_or((0, root(&self.genesis, &self.id())), |last| (last.seq + 1, last.hash()));
        let last = self.entries.last().map_or(0, |entry| entry.clock);
        let clock = clock.max(last + 1).max(now_ms() << 16);
        self.entries.push(Chain { device: self.id(), seq, prev }.next(clock, body, &self.actor.log));
    }

    fn bytes(&self) -> Vec<u8> {
        self.entries.iter().flat_map(Entry::encode).collect()
    }

    fn log(&self) -> crate::store::Logs {
        crate::store::Logs::from([(self.id(), self.bytes())])
    }
}

fn newest_epoch(vault: &Vault) -> (Generation, Key) {
    let (epoch, key) = vault.keys.as_ref().unwrap().newest_epoch().unwrap();
    (epoch, key.clone())
}

fn wrap_to(vault: &Vault, device: DeviceId, epoch: Generation, key: &Key) -> Body {
    let binding = Binding::Epoch { vault: vault.state.vault, epoch, recipient: Recipient::Device(device) };
    let keys = vault.state.members[&device].record.keys.clone();
    Body::Wrap { epoch, sealed: Sealed::Device(device, crypto::wrap(keys.wrap_to(), &binding, key).unwrap()) }
}

fn is_removed(vault: &Vault, device: DeviceId) -> bool {
    vault.state.members[&device].standing != Standing::Active
}

fn env(value: &str) -> Secret {
    Secret::Env { value: value.to_owned() }
}

#[test]
fn a_removed_device_cannot_rewrite_its_history_by_making_it_shorter() {
    let (mut forge, owner) = Forge::new();
    let removed = Actor::new();
    forge.enroll(&removed, 20);
    let (space, version) = forge.space(&owner, 25);
    for clock in [30, 31, 32] {
        forge.write(&removed, clock, &Body::Audit { epoch: Generation::first(forge.first_device), sealed: vec![1] });
    }
    forge.remove(&owner, &removed, 40);
    assert_eq!(forge.state().problems, Vec::new());

    let item = ItemId::random();
    forge.logs.get_mut(&removed.id()).unwrap().truncate(2);
    forge.write(&removed, 10_000, &Body::ItemPut { space, item, version, batch: BatchId::random(), meta: vec![1], secret: vec![2] });

    let state = forge.state();
    assert!(!state.items.contains_key(&(space, item)), "written after the removal, and it counted");
    assert!(state.problems.iter().any(|problem| problem.device == removed.id()), "and nothing said so");
}

#[test]
fn what_a_removed_device_planted_before_a_device_heard_stops_counting_once_it_has() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let space = a.vault.space(FIRST_SPACE).unwrap().id;
    let item = a.vault.add(&space, Meta::new(Kind::Env, "DB_URL"), &env("postgres://real")).unwrap();
    let mut c = second_device(&a.vault.home.clone(), &words, &dir.path().join("c"), "C");
    a.vault.merge_logs(c.all_logs().unwrap(), None).unwrap();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r.log(), None).unwrap();
    c.merge_logs(r.log(), None).unwrap();
    c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    let enrolled = r.entries.clone();

    let (epoch, _) = newest_epoch(&a.vault);
    for _ in 0..3 {
        r.write(a.vault.state.clock + 1, &Body::Audit { epoch, sealed: vec![1] });
    }
    a.vault.merge_logs(r.log(), None).unwrap();
    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();

    // A shorter history with a value of its own, reaching C before the removal does.
    let (version, key) = c.newest_space_key(&space).unwrap();
    r.entries = enrolled;
    let meta = Meta::new(Kind::Env, "DB_URL");
    let body = c.put_body(&(version, key), space, item, BatchId::random(), &meta, &env("postgres://attacker")).unwrap();
    r.write(a.vault.state.clock + 1, &body);
    c.merge_logs(r.log(), None).unwrap();
    c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();

    assert!(is_removed(&c, r.id()));
    c.lock();
    c.unlock("test").unwrap();
    c.repair().unwrap();
    assert_eq!(c.secret(&space, &item).unwrap(), env("postgres://real"), "it still used what the removed device wrote");
}

#[test]
fn a_record_with_another_device_s_keys_is_not_enrolled() {
    let mut a = Fixture::new();
    let me = a.vault.me;
    let twin = Actor::new();
    let mut record = twin.fresh.record.clone();
    record.keys = a.vault.state.members[&me].record.keys.clone();
    let after = a.vault.state.roster_head();
    let digest = add_digest(&a.vault.state.vault, &after, &record.id(), &record);
    let body = Body::DeviceAdd { after, device: record.clone(), approvals: a.recovery_approval(&digest) };
    let entry =
        Chain { device: record.id(), seq: 0, prev: root(&a.vault.state.genesis, &record.id()) }.next(a.vault.state.clock + 1, &body, &twin.log);
    a.vault.merge_logs(Logs::from([(record.id(), entry.encode())]), None).unwrap();
    assert!(!a.vault.state.members.contains_key(&record.id()));
}

#[test]
fn versions_of_an_item_stay_in_clock_order_whatever_order_they_arrive() {
    let (mut forge, owner) = Forge::new();
    let (space, version) = forge.space(&owner, 25);
    let item = ItemId::random();
    let put = |value: u8| Body::ItemPut { space, item, version, batch: BatchId::random(), meta: vec![value], secret: vec![value] };
    let second = Actor::new();
    forge.enroll(&second, 26);
    forge.write(&owner, 100, &put(1));
    forge.write(&second, 50, &put(2));
    forge.write(&owner, 200, &put(3));
    forge.write(&second, 150, &put(4));
    let state = forge.state();
    let clocks: Vec<u64> = state.items[&(space, item)].iter().map(|version| version.clock).collect();
    assert!(clocks.windows(2).all(|pair| pair[0] <= pair[1]), "{clocks:?}");
    assert!(matches!(&state.items[&(space, item)].last().unwrap().change, Change::Put { meta, .. } if meta == &vec![3]));
}

/// A second device paired the normal way: one approval, because the vault has one device.
fn paired(a: &mut Fixture, at: &Path, name: &str) -> Vault {
    let device = Software::generate("pass", Cost::FAST).unwrap();
    let fresh = crate::setup::new_device(&device).unwrap();
    let enrollment = a.vault.prepare_enrollment(fresh.record.clone(), name).unwrap();
    let own = Approval { by: Approver::Device(a.vault.me), signature: a.vault.device().authorize("test").unwrap().sign(&enrollment.digest).unwrap() };
    a.vault.enroll(&enrollment, vec![own]).unwrap();
    for folder in ["log", "local", "run"] {
        crate::store::private_dir(&at.join(folder)).unwrap();
    }
    for (id, bytes) in a.vault.all_logs().unwrap() {
        crate::store::write_private(&log::path_for(at, &id), &bytes).unwrap();
    }
    crate::setup::write_device_files(at, &device, a.vault.state.vault, &fresh).unwrap();
    let mut vault = Vault::open(at, Some("pass")).unwrap();
    vault.unlock("test").unwrap();
    vault
}

fn folder_of(forge: &Forge) -> tempfile::TempDir {
    let folder = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(folder.path().join("log")).unwrap();
    for (device, entries) in &forge.logs {
        let bytes: Vec<u8> = entries.iter().flat_map(Entry::encode).collect();
        std::fs::write(log::path_for(folder.path(), device), bytes).unwrap();
    }
    folder
}

#[test]
fn a_removed_first_device_cannot_undo_its_removal_on_a_fresh_copy() {
    let (mut forge, first) = Forge::new();
    let (second, planted) = (Actor::new(), Actor::new());
    let genesis_head = forge.state().roster_head();

    // Pairing the second device takes one approval, because the vault has one device.
    let digest = add_digest(&forge.vault, &genesis_head, &first.id(), &second.fresh.record);
    let approvals = vec![first.approve(&digest)];
    forge.write(&first, 100, &Body::DeviceAdd { after: genesis_head, device: second.fresh.record.clone(), approvals });

    // Later the first device is stolen: the second removes it with the words, then replaces them.
    let after = forge.state().roster_head();
    let log = &forge.logs[&first.id()];
    let (kept, last) = (log.len() as u64, log.last().unwrap().hash());
    let digest = revoke_digest(&forge.vault, &after, &second.id(), &first.id(), kept, &last);
    let approvals = vec![forge.approved_by_recovery(&digest).remove(0), second.approve(&digest)];
    forge.write(&second, 200, &Body::DeviceRevoke { after, device: first.id(), entries_kept: kept, last_kept: last, approvals });
    let after = forge.state().roster_head();
    let draft = RecoveryDraft::new();
    let new_public = draft.0.new_public(forge.vault).unwrap();
    let digest = rotate_digest(&forge.vault, &after, &second.id(), &new_public);
    let (proof, approvals) = (draft.0.sign(&digest).unwrap(), vec![forge.approved_by_recovery(&digest).remove(0), second.approve(&digest)]);
    forge.write(&second, 300, &Body::RecoveryRotate { after, recovery: new_public.clone(), proof, approvals });

    // The stolen device signs a device of its own at the position it held alone, dated earlier.
    let digest = add_digest(&forge.vault, &genesis_head, &planted.id(), &planted.fresh.record);
    let approvals = vec![first.approve(&digest)];
    forge.write(&planted, 50, &Body::DeviceAdd { after: genesis_head, device: planted.fresh.record.clone(), approvals });

    let state = forge.state();
    assert_eq!(state.members[&first.id()].standing, Standing::Removed { entries_kept: kept }, "the removal did not survive");
    assert!(!state.members.contains_key(&planted.id()));
    assert_eq!(state.recovery, new_public, "the rotation did not survive");

    let folder = folder_of(&forge);
    assert!(Recovery::open(folder.path(), &draft.0.words()).is_ok(), "the owner's words stopped working");
}

#[test]
fn a_stolen_device_that_also_holds_the_old_words_still_loses_to_the_owner_s_words() {
    let (mut forge, first) = Forge::new();
    let (second, planted) = (Actor::new(), Actor::new());
    let genesis_head = forge.state().roster_head();
    let digest = add_digest(&forge.vault, &genesis_head, &first.id(), &second.fresh.record);
    let approvals = vec![first.approve(&digest), forge.approved_by_recovery(&digest).remove(0)];
    forge.write(&first, 100, &Body::DeviceAdd { after: genesis_head, device: second.fresh.record.clone(), approvals });

    let after = forge.state().roster_head();
    let draft = RecoveryDraft::new();
    let new_public = draft.0.new_public(forge.vault).unwrap();
    let digest = rotate_digest(&forge.vault, &after, &second.id(), &new_public);
    let (proof, approvals) = (draft.0.sign(&digest).unwrap(), vec![forge.approved_by_recovery(&digest).remove(0), second.approve(&digest)]);
    forge.write(&second, 200, &Body::RecoveryRotate { after, recovery: new_public, proof, approvals });

    // Everything that could sign at the first position signs a rival, so signatures cannot decide.
    let attacker = RecoveryDraft::new();
    let digest = add_digest(&forge.vault, &genesis_head, &planted.id(), &planted.fresh.record);
    let approvals = vec![first.approve(&digest), forge.approved_by_recovery(&digest).remove(0)];
    forge.write(&planted, 50, &Body::DeviceAdd { after: genesis_head, device: planted.fresh.record.clone(), approvals });
    let after = forge.state().roster_head();
    assert_ne!(after, genesis_head, "the fork has to win on its dates for this to mean anything");
    let public = attacker.0.new_public(forge.vault).unwrap();
    let digest = rotate_digest(&forge.vault, &after, &planted.id(), &public);
    let (proof, approvals) =
        (attacker.0.sign(&digest).unwrap(), vec![forge.approved_by_recovery(&digest).remove(0), planted.approve(&digest), first.approve(&digest)]);
    forge.write(&planted, 60, &Body::RecoveryRotate { after, recovery: public, proof, approvals });

    let folder = folder_of(&forge);
    let opened = Recovery::open(folder.path(), &draft.0.words()).expect("words that are current somewhere must find that history");
    assert!(!opened.problems().is_empty(), "two histories this close have to be shown");
}

#[test]
fn recovery_with_the_right_words_leaves_a_removed_device_out() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    a.vault.add(&space_id, Meta::new(Kind::Env, "OLD"), &env("old")).unwrap();
    let genesis_head = a.vault.state.roster_head();
    let mut b = paired(&mut a, &dir.path().join("b"), "B");

    let name = b.device_name(&a.vault.me);
    let removal = b.prepare_removal(&name).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    b.remove_device(&removal, approvals).unwrap();
    b.add(&space_id, Meta::new(Kind::Env, "AFTER_REMOVAL"), &env("v")).unwrap();
    let backup = dir.path().join("backup");
    crate::sync::folder::write_logs(&backup, &b.home, &BTreeSet::new()).unwrap();

    // One new file from the stolen device, at the position it held alone, dated before the honest
    // change there.
    let planted = Actor::new();
    let digest = add_digest(&a.vault.state.vault, &genesis_head, &planted.id(), &planted.fresh.record);
    let approval = Approval { by: Approver::Device(a.vault.me), signature: a.vault.device().authorize("test").unwrap().sign(&digest).unwrap() };
    let body = Body::DeviceAdd { after: genesis_head, device: planted.fresh.record.clone(), approvals: vec![approval] };
    let entry =
        Chain { device: planted.id(), seq: 0, prev: root(&a.vault.state.genesis, &planted.id()) }.next(a.vault.state.clock - 1, &body, &planted.log);
    std::fs::write(log::path_for(&backup, &planted.id()), entry.encode()).unwrap();

    let opened = Recovery::open(&backup, &words).unwrap();
    let at = dir.path().join("new");
    opened.finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();

    assert_ne!(new.state.members[&a.vault.me].standing, Standing::Active, "the removal is gone");
    assert!(!new.state.members.contains_key(&planted.id()), "and the planted device is in");
    assert!(new.state.members.contains_key(&b.me), "and the device that removed it is out");
    assert!(new.find(&space_id, "AFTER_REMOVAL").is_ok(), "and what came after is gone");
}

#[test]
fn retired_words_cannot_turn_the_current_ones_away() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let genesis_head = a.vault.state.roster_head();
    let old_words = a.recovery.clone();
    drop(paired(&mut a, &dir.path().join("b"), "B"));
    let draft = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&draft.0).unwrap();
    let approvals = a.both_approvals(&rotation.digest);
    a.vault.rotate_recovery(rotation, approvals).unwrap();
    let backup = dir.path().join("backup");
    crate::sync::folder::write_logs(&backup, &a.vault.home, &BTreeSet::new()).unwrap();

    let planted = Actor::new();
    let digest = add_digest(&a.vault.state.vault, &genesis_head, &planted.id(), &planted.fresh.record);
    let approvals = vec![Approval { by: Approver::Recovery, signature: old_words.sign(&digest).unwrap() }];
    let body = Body::DeviceAdd { after: genesis_head, device: planted.fresh.record.clone(), approvals };
    let entry = Chain { device: planted.id(), seq: 0, prev: root(&a.vault.state.genesis, &planted.id()) }.next(now_ms() << 16, &body, &planted.log);
    std::fs::write(log::path_for(&backup, &planted.id()), entry.encode()).unwrap();

    assert!(Recovery::open(&backup, &draft.0.words()).is_ok(), "the current words were refused");
}

#[test]
fn a_device_that_missed_a_rotation_still_takes_the_real_vault_after_retired_words_reach_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let old_words = a.recovery.clone();
    let mut d = second_device(&a.vault.home.clone(), &old_words.words(), &dir.path().join("d"), "D");
    a.vault.merge_logs(d.all_logs().unwrap(), None).unwrap();

    let draft = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&draft.0).unwrap();
    let approvals = a.both_approvals(&rotation.digest);
    a.vault.rotate_recovery(rotation, approvals).unwrap();

    let planted = Bad::enroll(&d, &old_words);
    d.merge_logs(planted.log(), None).unwrap();
    assert!(d.state.members.contains_key(&planted.id()), "D has no way to know yet");

    d.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert_eq!(d.state.recovery, a.vault.state.recovery, "D refused the real vault");
    assert!(!d.state.members.contains_key(&planted.id()));
}

#[test]
fn an_approval_nobody_checked_is_not_counted() {
    let (mut forge, owner) = Forge::new();
    let (second, third, victim) = (Actor::new(), Actor::new(), Actor::new());
    forge.enroll(&second, 10);
    forge.enroll(&victim, 15);
    let after = forge.state().roster_head();

    let digest = add_digest(&forge.vault, &after, &owner.id(), &third.fresh.record);
    let approvals = vec![owner.approve(&digest), second.approve(&digest)];
    forge.write(&owner, 500, &Body::DeviceAdd { after, device: third.fresh.record.clone(), approvals });
    let honest = forge.state().roster_head();

    // The words at the same position, naming the target as a second approver with a signature that
    // is not a signature of anything.
    let log = &forge.logs[&victim.id()];
    let (kept, last) = (log.len() as u64, log.last().unwrap().hash());
    let digest = revoke_digest(&forge.vault, &after, &second.id(), &victim.id(), kept, &last);
    let mut approvals = forge.approved_by_recovery(&digest);
    approvals.push(Approval { by: Approver::Device(victim.id()), signature: victim.approve(&[9; 32]).signature });
    forge.write(&second, 900, &Body::DeviceRevoke { after, device: victim.id(), entries_kept: kept, last_kept: last, approvals });

    assert_eq!(forge.state().roster_head(), honest, "two devices were outranked");
}

/// What a removed device can do with what it held: whether it can open what `vault` sealed last.
fn removed_device_reads(vault: &Vault, space: SpaceId, item: ItemId, space_key: &Key) -> bool {
    let Change::Put { version, secret, .. } = &vault.state.items[&(space, item)].last().unwrap().change else { panic!("a put") };
    let binding = Binding::Item { vault: vault.state.vault, space, item, version: *version, part: Part::Secret };
    crypto::open(space_key, &binding, secret).is_ok()
}

#[test]
fn a_removed_device_reads_nothing_through_a_version_the_remover_could_not_open() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    a.vault.add(&space_id, Meta::new(Kind::Env, "OLD"), &env("old")).unwrap();
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();

    // A generation wrapped to B alone, and two space versions under it, above anything A will write.
    let vault = a.vault.state.vault;
    let (epoch, _) = newest_epoch(&a.vault);
    let (top, _) = a.vault.newest_space_key(&space_id).unwrap();
    let (r_epoch, r_key) = (epoch.after(r.id()), Key::generate());
    let (first, second) = (top.after(r.id()), top.after(r.id()).after(r.id()));
    let r_space_key = Key::generate();
    let clock = a.vault.state.clock;
    r.write(
        clock + 1,
        &Body::EpochLink {
            epoch: r_epoch,
            previous: epoch,
            commitment: epoch_commitment(&vault, r_epoch, &r_key),
            roster: a.vault.state.roster_head(),
            sealed: vec![9; 80],
        },
    );
    r.write(clock + 2, &wrap_to(&b, b.me, r_epoch, &r_key));
    r.write(clock + 3, &space::body(vault, r_epoch, &r_key, space_id, first, FIRST_SPACE, &Key::generate()).unwrap());
    r.write(clock + 4, &space::body(vault, r_epoch, &r_key, space_id, second, FIRST_SPACE, &r_space_key).unwrap());

    a.vault.merge_logs(r.log(), None).unwrap();
    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();

    assert!(b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap().must_lock);
    b.lock();
    b.unlock("test").unwrap();
    b.repair().unwrap();

    let item = b.add(&space_id, Meta::new(Kind::Env, "NEW"), &env("written-after-removal")).unwrap();
    assert!(!removed_device_reads(&b, space_id, item, &r_space_key), "B wrote under the removed device's key");
    let held = b.state.items[&(space_id, item)].last().unwrap().clone();
    let Change::Put { version, .. } = held.change else { panic!("a put") };
    assert!(b.state.clean_epochs().contains(&b.state.spaces[&space_id][&version].epoch));
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    a.vault.lock();
    a.vault.unlock("test").unwrap();
    assert_eq!(a.vault.secret(&space_id, &item).unwrap(), env("written-after-removal"), "and the remover has to be able to read it");
}

#[test]
fn a_space_created_during_a_removal_is_rekeyed_before_anything_new_goes_in_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let r = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    let old_epoch = newest_epoch(&a.vault).0;

    let work = b.create_space("Work").unwrap();
    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();

    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();
    b.repair().unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    a.vault.lock();
    a.vault.unlock("test").unwrap();
    a.vault.repair().unwrap();

    let item = a.vault.add(&work.id, Meta::new(Kind::Env, "WORK_KEY"), &env("after-removal")).unwrap();
    let Change::Put { version, .. } = a.vault.state.items[&(work.id, item)].last().unwrap().change else { panic!("a put") };
    assert_ne!(a.vault.state.spaces[&work.id][&version].epoch, old_epoch, "the space is still under the epoch the removal retired");
}

#[test]
fn a_rotation_that_stopped_partway_is_finished_before_a_write_goes_under_an_old_key() {
    let mut a = Fixture::new();
    let space = a.vault.space(FIRST_SPACE).unwrap().id;
    let r = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r.log(), None).unwrap();
    let old_epoch = newest_epoch(&a.vault).0;
    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    let revoke = Body::DeviceRevoke {
        after: removal.after,
        device: removal.device,
        entries_kept: removal.entries_kept,
        last_kept: removal.last_kept,
        approvals,
    };

    // The removal lands and nothing after it: no epoch, no space versions.
    a.vault.commit(&[revoke]).unwrap();
    let item = a.vault.add(&space, Meta::new(Kind::Env, "NEW"), &env("v")).unwrap();
    let Change::Put { version, .. } = a.vault.state.items[&(space, item)].last().unwrap().change else { panic!("a put") };
    assert_ne!(a.vault.state.spaces[&space][&version].epoch, old_epoch);
}

#[test]
fn nothing_about_how_many_spaces_a_device_made_goes_in_the_batch_that_removes_it() {
    let mut a = Fixture::new();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    let (epoch, key) = newest_epoch(&a.vault);
    let vault = a.vault.state.vault;
    let bodies: Vec<Body> = (0..40)
        .map(|n| space::body(vault, epoch, &key, SpaceId::random(), Generation::first(r.id()), &format!("s{n}"), &Key::generate()).unwrap())
        .collect();
    r.write(a.vault.state.clock + 1, &Body::Batch { bodies });
    a.vault.merge_logs(r.log(), None).unwrap();

    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();

    let logs = crate::sync::folder::read_logs(&a.vault.home).unwrap();
    let entries = log::parse(&logs[&a.vault.me]).entries;
    let batch = entries.iter().rev().find(|entry| entry.kind == Body::Batch { bodies: Vec::new() }.kind()).unwrap();
    let Body::Batch { bodies } = Body::decode(batch.kind, &batch.body).unwrap() else { panic!("a batch") };
    assert!(!bodies.iter().any(|body| matches!(body, Body::Space { .. })), "a device could make enough of these to stop its own removal");
    assert!(a.vault.spaces().unwrap().len() >= 41);
}

#[test]
#[ignore = "takes a minute, run by hand"]
fn a_device_with_enough_spaces_to_fill_a_batch_can_still_be_removed() {
    let mut a = Fixture::new();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    let (epoch, key) = newest_epoch(&a.vault);
    let vault = a.vault.state.vault;
    for chunk in 0..3 {
        let bodies: Vec<Body> = (0..16_000)
            .map(|n| {
                space::body(vault, epoch, &key, SpaceId::random(), Generation::first(r.id()), &format!("s{chunk}-{n}"), &Key::generate()).unwrap()
            })
            .collect();
        r.write(a.vault.state.clock + 1, &Body::Batch { bodies });
    }
    a.vault.merge_logs(r.log(), None).unwrap();
    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
    assert!(is_removed(&a.vault, r.id()));
}

#[test]
fn a_device_cannot_void_recovery_with_a_wrap_that_opens_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    a.vault.add(&space_id, Meta::new(Kind::Env, "OLD"), &env("old")).unwrap();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r.log(), None).unwrap();

    // An ordinary rotation by R, except that its wrap to the words opens nothing.
    let vault = a.vault.state.vault;
    let (epoch, key) = newest_epoch(&a.vault);
    let (top, _) = a.vault.newest_space_key(&space_id).unwrap();
    let (next, next_key) = (epoch.after(r.id()), Key::generate());
    let recovery = a.vault.state.recovery.clone();
    let link = crypto::seal(&next_key, &Binding::EpochLink { vault, epoch: next }, key.as_bytes());
    let junk = crypto::wrap(recovery.wrap_to(), &Binding::Epoch { vault, epoch: next, recipient: Recipient::Recovery }, &Key::generate()).unwrap();
    let clock = a.vault.state.clock;
    r.write(
        clock + 1,
        &Body::EpochLink {
            epoch: next,
            previous: epoch,
            commitment: epoch_commitment(&vault, next, &next_key),
            roster: a.vault.state.roster_head(),
            sealed: link,
        },
    );
    r.write(clock + 2, &wrap_to(&a.vault, a.vault.me, next, &next_key));
    r.write(clock + 3, &Body::Wrap { epoch: next, sealed: Sealed::Recovery(recovery.id(), junk) });
    r.write(clock + 4, &space::body(vault, next, &next_key, space_id, top.after(r.id()), FIRST_SPACE, &Key::generate()).unwrap());
    a.vault.merge_logs(r.log(), None).unwrap();
    a.vault.lock();
    a.vault.unlock("test").unwrap();
    a.vault.repair().unwrap();
    let new = a.vault.add(&space_id, Meta::new(Kind::Env, "NEW"), &env("new")).unwrap();

    let mut restored = second_device(&a.vault.home.clone(), &words, &dir.path().join("restored"), "Restored");
    restored.repair().unwrap();
    let space_after = restored.space(FIRST_SPACE).unwrap().id;
    assert!(restored.find(&space_after, "OLD").is_ok());
    assert!(restored.find(&space_after, "NEW").is_ok(), "the new item is gone");
    assert_eq!(restored.secret(&space_after, &new).unwrap(), env("new"));
}

#[test]
fn a_device_can_lock_another_with_a_new_generation_once_and_no_more() {
    let mut a = Fixture::new();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r.log(), None).unwrap();
    let vault = a.vault.state.vault;
    let mut previous = newest_epoch(&a.vault).0;
    for round in 0..4 {
        let next = previous.after(r.id());
        let clock = a.vault.state.clock;
        r.write(
            clock + 1,
            &Body::EpochLink {
                epoch: next,
                previous,
                commitment: epoch_commitment(&vault, next, &Key::generate()),
                roster: a.vault.state.roster_head(),
                sealed: vec![9; 80],
            },
        );
        r.write(
            clock + 2,
            &Body::Wrap {
                epoch: next,
                sealed: Sealed::Device(a.vault.me, crypto::Wrapped { ephemeral: [1; 65], ciphertext: vec![2], sealed: vec![3] }),
            },
        );
        assert_eq!(a.vault.merge_logs(r.log(), None).unwrap().must_lock, round == 0, "round {round}");
        previous = next;
    }
}

#[test]
fn a_wrap_of_keys_this_device_already_holds_does_not_lock_it() {
    let mut a = Fixture::new();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    assert!(!a.vault.merge_logs(r.log(), None).unwrap().must_lock);
    let (epoch, epoch_key) = newest_epoch(&a.vault);
    r.write(a.vault.state.clock + 1, &wrap_to(&a.vault, a.vault.me, epoch, &epoch_key));
    assert!(!a.vault.merge_logs(r.log(), None).unwrap().must_lock);
}

#[test]
fn removing_a_device_nobody_has_says_so() {
    let a = Fixture::new();
    assert!(matches!(a.vault.device_named("Nobody"), Err(Error::NotFound(_))));
}

#[test]
fn a_rotation_does_not_revert_an_edit_it_never_saw() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    let item = a.vault.add(&space_id, Meta::new(Kind::Env, "DB_PASSWORD"), &env("old-password")).unwrap();
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();

    b.replace(&space_id, &item, &Meta::new(Kind::Env, "DB_PASSWORD"), &env("new-password")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));

    let draft = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&draft.0).unwrap();
    let approvals = a.both_approvals(&rotation.digest);
    a.vault.rotate_recovery(rotation, approvals).unwrap();

    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();
    assert_eq!(b.secret(&space_id, &item).unwrap(), env("new-password"));
    assert_eq!(a.vault.secret(&space_id, &item).unwrap(), env("new-password"));
}

#[test]
fn a_device_added_after_a_race_reads_what_either_side_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();

    // Each rotates without hearing the other, and writes under its own key.
    let new_words = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&new_words.0).unwrap();
    let approvals = a.both_approvals(&rotation.digest);
    a.vault.rotate_recovery(rotation, approvals).unwrap();
    let from_a = a.vault.add(&space_id, Meta::new(Kind::Env, "FROM_A"), &env("a")).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();
    b.repair().unwrap();
    let from_b = b.add(&space_id, Meta::new(Kind::Env, "FROM_B"), &env("b")).unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    a.vault.lock();
    a.vault.unlock("test").unwrap();
    assert_eq!(a.vault.secret(&space_id, &from_b).unwrap(), env("b"));

    let mut c = second_device(&a.vault.home.clone(), new_words.0.words().as_ref(), &dir.path().join("c"), "C");
    c.repair().unwrap();
    assert_eq!(c.secret(&space_id, &from_a).unwrap(), env("a"));
    assert_eq!(c.secret(&space_id, &from_b).unwrap(), env("b"));
}

#[test]
fn a_device_copying_a_lost_device_s_name_can_still_be_told_apart_and_removed() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let lost = second_device(&a.vault.home.clone(), &words, &dir.path().join("lost"), "Phone");
    a.vault.merge_logs(lost.all_logs().unwrap(), None).unwrap();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    let (epoch, key) = newest_epoch(&a.vault);
    r.write(a.vault.state.clock + 1, &crate::vault::label_body(a.vault.state.vault, epoch, &key, r.id(), "Phone").unwrap());
    a.vault.merge_logs(r.log(), None).unwrap();

    let names: Vec<String> = a.vault.devices().unwrap().into_iter().map(|device| device.name).collect();
    assert_eq!(names.iter().collect::<BTreeSet<_>>().len(), 3, "the list must say which is which: {names:?}");
    assert!(a.vault.prepare_removal("Phone").is_err(), "a bare name two devices share is not a guess worth making");

    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    assert_eq!(removal.device, r.id());
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
    assert!(is_removed(&a.vault, r.id()));
}

#[test]
fn a_name_cannot_pose_as_another_device_s_id() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let target = second_device(&a.vault.home.clone(), &words, &dir.path().join("target"), "Tablet");
    a.vault.merge_logs(target.all_logs().unwrap(), None).unwrap();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    let id = target.me.to_string();
    let (epoch, key) = newest_epoch(&a.vault);
    r.write(a.vault.state.clock + 1, &crate::vault::label_body(a.vault.state.vault, epoch, &key, r.id(), &id[..16]).unwrap());
    a.vault.merge_logs(r.log(), None).unwrap();
    assert_eq!(a.vault.device_named(&id[..16]).unwrap(), target.me);
}

#[test]
fn a_device_gets_back_what_it_built_on_a_tail_a_removal_cut() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();

    // R gives B, and only B, a new version of the space. B works normally.
    let vault = a.vault.state.vault;
    let (epoch, epoch_key) = newest_epoch(&a.vault);
    let (top, _) = a.vault.newest_space_key(&space_id).unwrap();
    r.write(b.state.clock + 1, &space::body(vault, epoch, &epoch_key, space_id, top.after(r.id()), FIRST_SPACE, &Key::generate()).unwrap());
    b.merge_logs(r.log(), None).unwrap();
    let item = b.add(&space_id, Meta::new(Kind::Env, "ONLY_COPY_ON_B"), &env("honest-work")).unwrap();

    // A, which never saw that tail, removes R, and B hears.
    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();
    b.repair().unwrap();

    assert_eq!(b.secret(&space_id, &item).unwrap(), env("honest-work"), "the only copy of this person's secret is gone");
    assert!(!b.problems().any(|problem| problem.device == b.me), "what was put right is not a problem");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    a.vault.lock();
    a.vault.unlock("test").unwrap();
    assert_eq!(a.vault.secret(&space_id, &item).unwrap(), env("honest-work"));

    // Doing it again changes nothing, and neither does starting over.
    let length = b.state.heads[&b.me].seq;
    b.repair().unwrap();
    assert_eq!(b.state.heads[&b.me].seq, length);
}

#[test]
fn removing_a_lost_device_leaves_what_another_device_put_in_its_space() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let home = a.vault.home.clone();
    let mut b = second_device(&home, &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let mut lost = second_device(&home, &words, &dir.path().join("lost"), "Lost");
    a.vault.merge_logs(lost.all_logs().unwrap(), None).unwrap();
    b.merge_logs(lost.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    lost.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    lost.lock();
    lost.unlock("test").unwrap();

    let work = lost.create_space("Work").unwrap();
    b.merge_logs(lost.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();
    let item = b.add(&work.id, Meta::new(Kind::Env, "WORK_KEY"), &env("b-wrote-this")).unwrap();

    let removal = a.vault.prepare_removal("Lost").unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();
    b.repair().unwrap();

    assert_eq!(b.space("Work").unwrap().id, work.id);
    assert_eq!(b.secret(&work.id, &item).unwrap(), env("b-wrote-this"));
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    a.vault.lock();
    a.vault.unlock("test").unwrap();
    assert_eq!(a.vault.secret(&work.id, &item).unwrap(), env("b-wrote-this"));
}

#[test]
fn a_file_from_another_vault_does_not_stop_recovery() {
    let dir = tempfile::tempdir().unwrap();
    let a = Fixture::new();
    let backup = dir.path().join("backup");
    crate::sync::folder::write_logs(&backup, &a.vault.home, &BTreeSet::new()).unwrap();

    let stranger = Fixture::new();
    let bytes = std::fs::read(log::path_for(&stranger.vault.home, &stranger.vault.me)).unwrap();
    std::fs::write(log::path_for(&backup, &stranger.vault.me), bytes).unwrap();
    assert!(Recovery::open(&backup, &a.recovery.words()).is_ok());
    assert!(Recovery::open(&backup, &stranger.recovery.words()).is_ok(), "either vault can be the one being recovered");
}

// The second audit. These all start from a device that went bad, or from two honest devices racing.

/// A, B and a hostile R, all level with each other.
fn three(dir: &Path) -> (Fixture, Vault, Bad) {
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let r = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    a.vault.lock();
    a.vault.unlock("test").unwrap();
    b.lock();
    b.unlock("test").unwrap();
    (a, b, r)
}

/// A removes R with what A has seen of it, and the words.
fn remove_r(a: &mut Fixture, r: &Bad) {
    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
}

/// Signs `digest` with a device's own hardware key, as its person's touch would.
fn signed_by(vault: &Vault, digest: &Hash) -> Approval {
    Approval { by: Approver::Device(vault.me), signature: vault.device().authorize("test").unwrap().sign(digest).unwrap() }
}

/// Lays out a new device's home from `from`'s logs, the way pairing does.
fn joined(from: &Vault, device: &Software, fresh: &crate::setup::NewDevice, at: &Path) -> Vault {
    for folder in ["log", "local", "run"] {
        crate::store::private_dir(&at.join(folder)).unwrap();
    }
    for (id, bytes) in from.all_logs().unwrap() {
        crate::store::write_private(&log::path_for(at, &id), &bytes).unwrap();
    }
    crate::setup::write_device_files(at, device, from.state.vault, fresh).unwrap();
    let mut vault = Vault::open(at, Some("pass")).unwrap();
    vault.unlock("test").unwrap();
    vault
}

fn add_with(adder: &mut Vault, approvals: impl Fn(&Vault, &Hash) -> Vec<Approval>, at: &Path, name: &str) -> Vault {
    let device = Software::generate("pass", Cost::FAST).unwrap();
    let fresh = crate::setup::new_device(&device).unwrap();
    let enrollment = adder.prepare_enrollment(fresh.record.clone(), name).unwrap();
    let approvals = approvals(adder, &enrollment.digest);
    adder.enroll(&enrollment, approvals).unwrap();
    joined(adder, &device, &fresh, at)
}

fn no_settled() -> BTreeSet<DeviceId> {
    BTreeSet::new()
}

#[test]
fn a_space_with_a_junk_first_version_does_not_send_repair_and_rescue_round_for_ever() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let (epoch, epoch_key) = newest_epoch(&a.vault);

    // Version 0 of a new space opens for nobody, and everyone keeps it.
    let work = SpaceId::random();
    let v0 = Generation::first(r.id());
    r.write(a.vault.state.clock + 1, &Body::Space { space: work, version: v0, epoch, sealed: vec![9; 80] });
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();

    // Version 1 opens, and only B sees it. B's person puts something in the space.
    r.write(b.state.clock + 1, &space::body(vault, epoch, &epoch_key, work, v0.after(r.id()), "Work", &Key::generate()).unwrap());
    b.merge_logs(r.log(), None).unwrap();
    let work = b.space("Work").unwrap().id;
    let item = b.add(&work, Meta::new(Kind::Env, "IN_WORK"), &env("honest")).unwrap();

    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();
    b.repair().unwrap();
    assert_eq!(b.secret(&work, &item).unwrap(), env("honest"));
}

#[test]
fn an_edit_on_a_cut_key_comes_back() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    let item = a.vault.add(&space_id, Meta::new(Kind::Env, "DB_PASSWORD"), &env("old-password")).unwrap();
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();

    let (epoch, epoch_key) = newest_epoch(&a.vault);
    let (top, _) = a.vault.newest_space_key(&space_id).unwrap();
    r.write(b.state.clock + 1, &space::body(vault, epoch, &epoch_key, space_id, top.after(r.id()), FIRST_SPACE, &Key::generate()).unwrap());
    b.merge_logs(r.log(), None).unwrap();
    b.replace(&space_id, &item, &Meta::new(Kind::Env, "DB_PASSWORD"), &env("new-password")).unwrap();

    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();
    b.repair().unwrap();
    assert_eq!(b.secret(&space_id, &item).unwrap(), env("new-password"), "the person's edit is gone");
    assert_eq!(b.lost_items(), Vec::new());
}

#[test]
fn what_was_written_under_a_cut_generation_comes_back_too() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let (epoch, epoch_key) = newest_epoch(&a.vault);
    let (next, next_key) = (epoch.after(r.id()), Key::generate());
    let link = crypto::seal(&next_key, &Binding::EpochLink { vault, epoch: next }, epoch_key.as_bytes());
    let clock = b.state.clock;
    let commitment = epoch_commitment(&vault, next, &next_key);
    r.write(clock + 1, &Body::EpochLink { epoch: next, previous: epoch, commitment, roster: b.state.roster_head(), sealed: link });
    r.write(clock + 2, &wrap_to(&b, b.me, next, &next_key));
    b.merge_logs(r.log(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();

    let work = b.create_space("Work").unwrap();
    let item = b.add(&work.id, Meta::new(Kind::Env, "ONLY_ON_B"), &env("honest-work")).unwrap();
    assert_eq!(b.state.spaces[&work.id].values().next().unwrap().epoch, next, "this has to be the generation that gets cut");

    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();
    b.repair().unwrap();
    assert_eq!(b.secret(&work.id, &item).unwrap(), env("honest-work"));
    assert_eq!(b.lost_items(), Vec::new());
}

#[test]
fn a_removal_settles_which_of_a_device_s_two_histories_counts() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let home = a.vault.home.clone();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let years_of_work = a.vault.add(&personal, Meta::new(Kind::Env, "FROM_FIRST"), &env("the person's secret")).unwrap();
    let mut b = second_device(&home, &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let mut c = second_device(&a.vault.home.clone(), &words, &dir.path().join("c"), "C");
    a.vault.merge_logs(c.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();
    c.lock();
    c.unlock("test").unwrap();

    // Two entries at one position, each a valid continuation by a real log key.
    let me = a.vault.me;
    let base = std::fs::read(log::path_for(&home, &me)).unwrap();
    let last = log::parse(&base).entries.pop().unwrap();
    let key = &a.vault.keys.as_ref().unwrap().log;
    let tail = |sealed: u8| {
        let body = Body::Audit { epoch: Generation::first(me), sealed: vec![sealed] };
        Chain { device: me, seq: last.seq + 1, prev: last.hash() }.next(last.clock.max(now_ms() << 16) + 1, &body, key).encode()
    };
    c.merge_logs(Logs::from([(me, [base.clone(), tail(1)].concat())]), None).unwrap();
    b.merge_logs(Logs::from([(me, [base.clone(), tail(2)].concat())]), None).unwrap();

    // C removes it with the words, keeping what C holds.
    let removal = c.prepare_removal(&c.device_name(&me)).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    c.remove_device(&removal, approvals).unwrap();
    let after = c.add(&personal, Meta::new(Kind::Env, "AFTER_REMOVAL"), &env("c-wrote-this")).unwrap();

    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &no_settled()).unwrap();
    for _ in 0..2 {
        b.merge_logs(c.all_logs().unwrap(), None).unwrap();
        c.merge_logs(b.all_logs().unwrap(), None).unwrap();
    }
    b.lock();
    b.unlock("test").unwrap();
    b.repair().unwrap();
    assert_eq!(b.secret(&personal, &years_of_work).unwrap(), env("the person's secret"));
    assert_eq!(b.secret(&personal, &after).unwrap(), env("c-wrote-this"));
    assert!(!b.state.problems.iter().any(|problem| problem.reason == "contradicts what its removal kept"));

    // The folder held the other history, and gets the true one.
    write_logs(&backup, &b.home, &b.logs_removals_kept()).unwrap();
    let at = dir.path().join("new");
    Recovery::open(&backup, &words).unwrap().finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    assert_eq!(new.secret(&personal, &years_of_work).unwrap(), env("the person's secret"));
}

#[test]
fn a_removed_first_device_cannot_win_a_fresh_copy_by_its_date_when_two_devices_removed_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let genesis_head = a.vault.state.roster_head();

    let mut b = add_with(&mut a.vault, |vault, digest| vec![signed_by(vault, digest)], &dir.path().join("b"), "B");
    let mut c = {
        let device = Software::generate("pass", Cost::FAST).unwrap();
        let fresh = crate::setup::new_device(&device).unwrap();
        let enrollment = a.vault.prepare_enrollment(fresh.record.clone(), "C").unwrap();
        let approvals = vec![signed_by(&a.vault, &enrollment.digest), signed_by(&b, &enrollment.digest)];
        a.vault.enroll(&enrollment, approvals).unwrap();
        joined(&a.vault, &device, &fresh, &dir.path().join("c"))
    };
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();

    let removal = b.prepare_removal(&b.device_name(&a.vault.me)).unwrap();
    let approvals = vec![signed_by(&b, &removal.digest), signed_by(&c, &removal.digest)];
    b.remove_device(&removal, approvals).unwrap();
    b.add(&personal, Meta::new(Kind::Env, "AFTER_REMOVAL"), &env("v")).unwrap();
    c.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &no_settled()).unwrap();

    let planted = Actor::new();
    let digest = add_digest(&a.vault.state.vault, &genesis_head, &planted.id(), &planted.fresh.record);
    let body = Body::DeviceAdd { after: genesis_head, device: planted.fresh.record.clone(), approvals: vec![signed_by(&a.vault, &digest)] };
    let entry = Chain { device: planted.id(), seq: 0, prev: root(&a.vault.state.genesis, &planted.id()) }.next(2, &body, &planted.log);
    std::fs::write(log::path_for(&backup, &planted.id()), entry.encode()).unwrap();

    let at = dir.path().join("new");
    let mut opened = Recovery::open(&backup, &words).unwrap();
    opened.choose_history(0).unwrap();
    opened.finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();
    assert!(is_removed(&new, a.vault.me), "the removed device is back in");
    assert!(!new.state.members.contains_key(&planted.id()));
    assert!(new.find(&personal, "AFTER_REMOVAL").is_ok(), "and what came after is gone");
}

#[test]
fn a_paired_device_never_merges_itself_out_of_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let home = a.vault.home.clone();
    let mut b = second_device(&home, &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let c = second_device(&a.vault.home.clone(), &words, &dir.path().join("c"), "C");
    a.vault.merge_logs(c.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();

    // A is on a plane, and pairs P with the words standing in for a second device.
    let recovery = a.recovery.clone();
    let p_home = dir.path().join("p");
    let with_words = |recovery: RecoveryKey| {
        move |vault: &Vault, digest: &Hash| {
            vec![signed_by(vault, digest), Approval { by: Approver::Recovery, signature: recovery.sign(digest).unwrap() }]
        }
    };
    let mut p = add_with(&mut a.vault, with_words(recovery.clone()), &p_home, "P");
    let personal = p.space(FIRST_SPACE).unwrap().id;
    let only_on_p = p.add(&personal, Meta::new(Kind::Env, "ONLY_ON_P"), &env("written on P")).unwrap();

    // Meanwhile B and C pair Q, and B pairs another with the words: a stronger branch.
    let device = Software::generate("pass", Cost::FAST).unwrap();
    let fresh = crate::setup::new_device(&device).unwrap();
    let enrollment = b.prepare_enrollment(fresh.record.clone(), "Q").unwrap();
    let approvals = vec![signed_by(&b, &enrollment.digest), signed_by(&c, &enrollment.digest)];
    b.enroll(&enrollment, approvals).unwrap();
    drop(joined(&b, &device, &fresh, &dir.path().join("q")));
    drop(add_with(&mut b, with_words(recovery), &dir.path().join("z"), "Z"));

    p.merge_logs(b.all_logs().unwrap(), None).unwrap();
    assert!(p.state.members.contains_key(&p.me), "P left itself out of the vault it is running");
    assert_eq!(p.secret(&personal, &only_on_p).unwrap(), env("written on P"));
    drop(p);
    assert!(Vault::open(&p_home, Some("pass")).is_ok(), "and it would not open again");
}

#[test]
fn a_planted_file_does_not_merge_a_paired_device_out_of_the_vault() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let old_words = a.recovery.clone();
    let before_rotation = a.vault.state.roster_head();
    let draft = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&draft.0).unwrap();
    let approvals = vec![signed_by(&a.vault, &rotation.digest)];
    a.vault.rotate_recovery(rotation, approvals).unwrap();
    let current = draft.0.words().to_string();
    let mut n = second_device(&a.vault.home.clone(), &current, &dir.path().join("n"), "N");
    n.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    let removal = n.prepare_removal(&n.device_name(&a.vault.me)).unwrap();
    let approvals = vec![n.recovery_approval(&current, &removal.digest).unwrap()];
    n.remove_device(&removal, approvals).unwrap();

    let p_home = dir.path().join("p");
    let mut p = add_with(&mut n, |vault, digest| vec![signed_by(vault, digest)], &p_home, "P");

    let planted = Actor::new();
    let digest = add_digest(&a.vault.state.vault, &before_rotation, &planted.id(), &planted.fresh.record);
    let approvals = vec![signed_by(&a.vault, &digest), Approval { by: Approver::Recovery, signature: old_words.sign(&digest).unwrap() }];
    let body = Body::DeviceAdd { after: before_rotation, device: planted.fresh.record.clone(), approvals };
    let entry = Chain { device: planted.id(), seq: 0, prev: root(&a.vault.state.genesis, &planted.id()) }.next(now_ms() << 16, &body, &planted.log);

    p.merge_logs(Logs::from([(planted.id(), entry.encode())]), None).unwrap();
    assert!(is_removed(&p, a.vault.me), "the stolen device came back on this device");
    drop(p);
    assert!(Vault::open(&p_home, Some("pass")).is_ok());
}

#[test]
fn a_stolen_device_and_retired_words_do_not_turn_the_owner_s_words_away() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let old_words = a.recovery.clone();
    let before_rotation = a.vault.state.roster_head();
    let draft = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&draft.0).unwrap();
    let approvals = vec![signed_by(&a.vault, &rotation.digest)];
    a.vault.rotate_recovery(rotation, approvals).unwrap();
    let current = draft.0.words().to_string();

    let mut n = second_device(&a.vault.home.clone(), &current, &dir.path().join("n"), "N");
    n.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    let removal = n.prepare_removal(&n.device_name(&a.vault.me)).unwrap();
    let approvals = vec![n.recovery_approval(&current, &removal.digest).unwrap()];
    n.remove_device(&removal, approvals).unwrap();
    let backup = dir.path().join("backup");
    write_logs(&backup, &n.home, &no_settled()).unwrap();

    let planted = Actor::new();
    let digest = add_digest(&a.vault.state.vault, &before_rotation, &planted.id(), &planted.fresh.record);
    let approvals = vec![signed_by(&a.vault, &digest), Approval { by: Approver::Recovery, signature: old_words.sign(&digest).unwrap() }];
    let body = Body::DeviceAdd { after: before_rotation, device: planted.fresh.record.clone(), approvals };
    let entry = Chain { device: planted.id(), seq: 0, prev: root(&a.vault.state.genesis, &planted.id()) }.next(now_ms() << 16, &body, &planted.log);
    std::fs::write(log::path_for(&backup, &planted.id()), entry.encode()).unwrap();

    assert!(Recovery::open(&backup, &current).is_ok(), "the owner's words were turned away");
}

#[test]
fn words_a_stolen_lone_device_replaced_still_open_the_vault_as_it_stood() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let owner = a.recovery.words().to_string();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let item = a.vault.add(&personal, Meta::new(Kind::Env, "OWNERS"), &env("the owner's")).unwrap();
    let draft = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&draft.0).unwrap();
    let approvals = vec![signed_by(&a.vault, &rotation.digest)];
    a.vault.rotate_recovery(rotation, approvals).unwrap();
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();

    assert!(matches!(Recovery::open(&backup, &owner), Err(crate::Error::WrongRecoveryKey)), "words that were replaced say so first");
    let opened = Recovery::open_as_it_stood(&backup, &owner).unwrap();
    assert!(opened.problems().iter().any(|problem| problem.contains("replaced")));
    let at = dir.path().join("new");
    opened.finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();
    assert_eq!(new.secret(&personal, &item).unwrap(), env("the owner's"));
    assert!(a.recovery.matches(&new.state.recovery).unwrap(), "these are the words it answers to now");
    assert!(
        matches!(Recovery::open_as_it_stood(&backup, &RecoveryDraft::new().0.words()), Err(crate::Error::WrongRecoveryKey)),
        "only words that were once current"
    );
}

#[test]
fn a_stray_byte_in_a_folder_does_not_stop_a_log_being_backed_up() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();
    let path = log::path_for(&backup, &a.vault.me);
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.push(0xff);
    std::fs::write(&path, &bytes).unwrap();

    a.vault.add(&personal, Meta::new(Kind::Env, "NEW"), &env("v")).unwrap();
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), std::fs::read(log::path_for(&a.vault.home, &a.vault.me)).unwrap());
}

#[test]
fn a_device_restored_from_an_old_copy_takes_its_own_log_back() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    let own = log::path_for(&b.home, &b.me);
    let snapshot = std::fs::read(&own).unwrap();
    let home = b.home.clone();

    let before = b.add(&personal, Meta::new(Kind::Env, "BEFORE_RESTORE"), &env("synced")).unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    drop(b);
    std::fs::write(&own, &snapshot).unwrap();

    let mut b = Vault::open(&home, Some("pass")).unwrap();
    b.unlock("test").unwrap();
    assert!(b.secret(&personal, &before).is_err(), "this has to start rolled back");
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(b.problems().any(|problem| problem.reason.contains("rolled back")));
    assert_eq!(b.secret(&personal, &before).unwrap(), env("synced"));

    // And it carries on as if nothing had happened, from the end of what it took back.
    let after = b.add(&personal, Meta::new(Kind::Env, "AFTER"), &env("v")).unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    assert_eq!(a.vault.secret(&personal, &after).unwrap(), env("v"));
}

#[test]
fn a_device_that_forked_itself_stops_rather_than_writing_what_nobody_will_take() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    let own = log::path_for(&b.home, &b.me);
    let snapshot = std::fs::read(&own).unwrap();
    let home = b.home.clone();

    b.add(&personal, Meta::new(Kind::Env, "BEFORE_RESTORE"), &env("synced")).unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    drop(b);
    std::fs::write(&own, &snapshot).unwrap();

    let mut b = Vault::open(&home, Some("pass")).unwrap();
    b.unlock("test").unwrap();
    b.add(&personal, Meta::new(Kind::Env, "AFTER_RESTORE"), &env("written after the restore")).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(b.problems().any(|problem| problem.reason.contains("rolled back")), "the device must hear of it");
    assert!(b.add(&personal, Meta::new(Kind::Env, "AND_LATER"), &env("v")).is_err(), "nothing it writes now would reach anyone");
}

#[test]
fn a_device_left_out_of_a_race_keeps_its_work_and_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let home = a.vault.home.clone();
    let mut one = second_device(&home, &words, &dir.path().join("one"), "One");
    std::thread::sleep(std::time::Duration::from_millis(5));
    let mut two = second_device(&home, &words, &dir.path().join("two"), "Two");
    let from_two = two.add(&personal, Meta::new(Kind::Env, "ON_TWO"), &env("written on the second restore")).unwrap();
    for _ in 0..2 {
        a.vault.merge_logs(one.all_logs().unwrap(), None).unwrap();
        a.vault.merge_logs(two.all_logs().unwrap(), None).unwrap();
        one.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        two.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    }
    assert!(two.problems().next().is_some(), "it has to be told");
    assert_eq!(two.secret(&personal, &from_two).unwrap(), env("written on the second restore"));
    let export = dir.path().join("export.json");
    two.export_plaintext(&export).unwrap();
    assert!(std::fs::read_to_string(&export).unwrap().contains("written on the second restore"), "and it has to be able to take it out");
}

#[test]
fn a_device_removed_while_offline_can_still_take_out_what_it_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.add(&personal, Meta::new(Kind::Env, "ONLY_ON_B"), &env("written offline")).unwrap();

    let removal = a.vault.prepare_removal(&a.vault.device_name(&b.me)).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();

    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    let export = dir.path().join("export.json");
    b.export_plaintext(&export).unwrap();
    assert!(std::fs::read_to_string(&export).unwrap().contains("written offline"), "an export has to hold it");
}

#[test]
fn a_link_that_opens_nothing_cuts_nothing_off() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let old = a.vault.add(&personal, Meta::new(Kind::Env, "OLD"), &env("years of secrets")).unwrap();
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r.log(), None).unwrap();

    let vault = a.vault.state.vault;
    let (epoch, _) = newest_epoch(&a.vault);
    let (next, next_key) = (epoch.after(r.id()), Key::generate());
    let clock = a.vault.state.clock;
    let commitment = epoch_commitment(&vault, next, &next_key);
    r.write(clock + 1, &Body::EpochLink { epoch: next, previous: epoch, commitment, roster: a.vault.state.roster_head(), sealed: vec![9; 80] });
    r.write(clock + 2, &wrap_to(&a.vault, a.vault.me, next, &next_key));
    a.vault.merge_logs(r.log(), None).unwrap();
    a.vault.lock();
    a.vault.unlock("test").unwrap();
    a.vault.repair().unwrap();

    remove_r(&mut a, &r);
    let draft = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&draft.0).unwrap();
    let approvals = a.both_approvals(&rotation.digest);
    a.vault.rotate_recovery(rotation, approvals).unwrap();
    a.vault.repair().unwrap();

    let mut p = add_with(&mut a.vault, |vault, digest| vec![signed_by(vault, digest)], &dir.path().join("p"), "P");
    p.repair().unwrap();
    assert_eq!(p.secret(&personal, &old).unwrap(), env("years of secrets"), "a new device does not get the old data");

    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();
    let at = dir.path().join("restored");
    Recovery::open(&backup, &draft.0.words()).unwrap().finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();
    assert_eq!(new.secret(&personal, &old).unwrap(), env("years of secrets"), "the words do not reach the old data");
}

#[test]
fn one_oversized_file_does_not_cost_a_good_folder() {
    let dir = tempfile::tempdir().unwrap();
    let a = Fixture::new();
    let words = a.recovery.words().to_string();
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();
    let file = std::fs::File::create(log::path_for(&backup, &DeviceId::from([0xee; 16]))).unwrap();
    file.set_len(3 << 30).unwrap();
    assert!(Recovery::open(&backup, &words).is_ok());
    assert!(crate::sync::folder::read_logs(&backup).is_ok());
}

#[test]
fn a_cut_key_held_in_memory_does_not_count_as_clean() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let (epoch, epoch_key) = newest_epoch(&a.vault);
    let (next, next_key) = (epoch.after(r.id()), Key::generate());
    let link = crypto::seal(&next_key, &Binding::EpochLink { vault, epoch: next }, epoch_key.as_bytes());
    let clock = b.state.clock;
    let commitment = epoch_commitment(&vault, next, &next_key);
    r.write(clock + 1, &Body::EpochLink { epoch: next, previous: epoch, commitment, roster: b.state.roster_head(), sealed: link });
    r.write(clock + 2, &wrap_to(&b, b.me, next, &next_key));
    b.merge_logs(r.log(), None).unwrap();
    b.lock();
    b.unlock("test").unwrap();

    remove_r(&mut a, &r);
    b.last_asked.insert(a.vault.me, now_ms());
    assert!(b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap().must_lock, "nothing it holds is safe now");
    assert_eq!(b.writing_epoch(&b.state.clean_epochs()).map(|(found, _)| found), None);
    b.lock();
    b.unlock("test").unwrap();
    b.repair().unwrap();
    b.add(&personal, Meta::new(Kind::Env, "NEW"), &env("v")).unwrap();
    b.record("reveal", "DB_PASSWORD", "this user").unwrap();
    assert_ne!(b.state.audit.last().unwrap().0, next, "the audit trail went under a key R can read");
}

// The third audit. Where someone holds as much authority as the owner, signatures have run out, so
// these are about what a reader does then.

fn words_approval(words: &RecoveryKey, digest: &Hash) -> Approval {
    Approval { by: Approver::Recovery, signature: words.sign(digest).unwrap() }
}

fn relock(vault: &mut Vault) {
    vault.lock();
    vault.unlock("test").unwrap();
}

/// A forged copy of a log: rubbish in front of the one real entry a removal names.
fn forged_log(device: DeviceId, real: &[Entry]) -> Vec<u8> {
    let junk = |seq| Entry { kind: 200, device, seq, clock: 1, prev: [0; 32], body: vec![], signature: [0; 64] };
    (0..real.len() as u64 - 1).flat_map(|seq| junk(seq).encode()).chain(real.last().unwrap().encode()).collect()
}

/// R writes, at `h0`, a rotation to words of its own, then removes `honest` with them.
fn rival(
    r: &mut Bad,
    vault: VaultId,
    h0: Hash,
    approve: impl FnOnce(&Hash, &Bad) -> Vec<Approval>,
    honest: DeviceId,
    (kept, last_kept): (u64, Hash),
) -> RecoveryDraft {
    let attacker = RecoveryDraft::new();
    let public = attacker.0.new_public(vault).unwrap();
    let digest = rotate_digest(&vault, &h0, &r.id(), &public);
    let proof = attacker.0.sign(&digest).unwrap();
    let approvals = approve(&digest, r);
    r.write(0, &Body::RecoveryRotate { after: h0, recovery: public, proof, approvals });
    let head = r.entries.last().unwrap().hash();
    let digest = revoke_digest(&vault, &head, &r.id(), &honest, kept, &last_kept);
    let approvals = vec![words_approval(&attacker.0, &digest)];
    r.write(0, &Body::DeviceRevoke { after: head, device: honest, entries_kept: kept, last_kept, approvals });
    attacker
}

/// The owner, on A, removes R and replaces the words. D takes no part.
fn remove_and_replace_words(a: &mut Fixture, r: &Bad) -> RecoveryDraft {
    let removal = a.vault.prepare_removal(&a.vault.device_name(&r.id())).unwrap();
    let approvals = a.both_approvals(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
    let new_words = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&new_words.0).unwrap();
    let approvals = a.both_approvals(&rotation.digest);
    a.vault.rotate_recovery(rotation, approvals).unwrap();
    new_words
}

#[test]
fn a_forged_copy_of_a_removed_first_device_s_log_breaks_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut first = Fixture::new();
    let words = first.recovery.words().to_string();
    let home = first.vault.home.clone();
    let personal = first.vault.space(FIRST_SPACE).unwrap().id;
    let mut b = second_device(&home, &words, &dir.path().join("b"), "B");
    first.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let mut d = second_device(&first.vault.home.clone(), &words, &dir.path().join("d"), "D");
    let d_home = d.home.clone();
    first.vault.merge_logs(d.all_logs().unwrap(), None).unwrap();
    b.merge_logs(first.vault.all_logs().unwrap(), None).unwrap();
    d.merge_logs(first.vault.all_logs().unwrap(), None).unwrap();

    // The first device writes once more. B hears, and removes it. D is offline.
    first.vault.add(&personal, Meta::new(Kind::Env, "LAST"), &env("v")).unwrap();
    b.merge_logs(first.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    let me = first.vault.me;
    let removal = b.prepare_removal(&b.device_name(&me)).unwrap();
    let approvals = first.recovery_approval(&removal.digest);
    b.remove_device(&removal, approvals).unwrap();

    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &no_settled()).unwrap();
    let path = log::path_for(&backup, &me);
    let real = log::parse(&std::fs::read(&path).unwrap()).entries;
    std::fs::write(&path, forged_log(me, &real)).unwrap();

    d.merge_logs(crate::sync::folder::read_logs(&backup).unwrap(), None).unwrap();
    assert_ne!(log::parse(&std::fs::read(log::path_for(&d_home, &me)).unwrap()).entries[0].kind, 200, "the junk reached D's own disk");
    drop(d);
    assert!(Vault::open(&d_home, Some("pass")).is_ok());
}

#[test]
fn a_forged_copy_of_a_removed_device_s_log_is_neither_taken_nor_spread() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let (epoch, _) = newest_epoch(&a.vault);
    r.write(a.vault.state.clock + 1, &Body::Audit { epoch, sealed: vec![1] });
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();
    let held = std::fs::read(log::path_for(&b.home, &r.id())).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    remove_r(&mut a, &r);
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();
    let path = log::path_for(&backup, &r.id());
    let real = std::fs::read(&path).unwrap();
    std::fs::write(&path, forged_log(r.id(), &log::parse(&real).entries)).unwrap();

    b.merge_logs(crate::sync::folder::read_logs(&backup).unwrap(), None).unwrap();
    assert!(is_removed(&b, r.id()), "the removal did not survive");
    assert_eq!(std::fs::read(log::path_for(&b.home, &r.id())).unwrap(), held, "the forgery is B's copy now");
}

#[test]
fn a_device_behind_on_a_removed_log_takes_what_its_removal_kept_from_a_copy_that_holds_more() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let key = a.vault.newest_space_key(&personal).unwrap();
    let from_r = ItemId::random();
    r.write(
        a.vault.state.clock + 1,
        &a.vault.put_body(&key, personal, from_r, BatchId::random(), &Meta::new(Kind::Env, "FROM_R"), &env("written on R")).unwrap(),
    );
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();

    // One more entry from R, which A hears and B, now offline, does not.
    let (epoch, _) = newest_epoch(&a.vault);
    r.write(a.vault.state.clock + 1, &Body::Audit { epoch, sealed: vec![1] });
    a.vault.merge_logs(r.log(), None).unwrap();
    remove_r(&mut a, &r);
    let after = a.vault.add(&personal, Meta::new(Kind::Env, "AFTER_REMOVAL"), &env("written on A")).unwrap();
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();

    // R has not heard, and copies its log to the shared folder as any device does.
    r.write(a.vault.state.clock + 1, &Body::Audit { epoch, sealed: vec![2] });
    std::fs::write(log::path_for(&backup, &r.id()), r.bytes()).unwrap();

    b.merge_logs(crate::sync::folder::read_logs(&backup).unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    assert_eq!(b.secret(&personal, &from_r).unwrap(), env("written on R"));
    assert_eq!(b.secret(&personal, &after).unwrap(), env("written on A"));
    assert!(b.problems().any(|problem| problem.reason == PAST_THE_CUT), "what it wrote since has to be reported");
    let kept = b.state.kept_entries(&r.id()).unwrap();
    let held = log::parse(&std::fs::read(log::path_for(&b.home, &r.id())).unwrap()).entries.len();
    assert_eq!(held as u64, kept, "what a removal cut is neither kept here nor passed on");
}

#[test]
fn a_device_behind_on_a_removed_first_device_is_not_left_with_an_empty_vault() {
    let dir = tempfile::tempdir().unwrap();
    let mut first = Fixture::new();
    let personal = first.vault.space(FIRST_SPACE).unwrap().id;
    let recovery = first.recovery.clone();
    let mut b = add_with(&mut first.vault, |vault, digest| vec![signed_by(vault, digest)], &dir.path().join("b"), "B");
    let mut d =
        add_with(&mut first.vault, |vault, digest| vec![signed_by(vault, digest), words_approval(&recovery, digest)], &dir.path().join("d"), "D");
    b.merge_logs(first.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    relock(&mut d);
    let years = first.vault.add(&personal, Meta::new(Kind::Env, "YEARS_OF_WORK"), &env("v")).unwrap();
    d.merge_logs(first.vault.all_logs().unwrap(), None).unwrap();

    first.vault.add(&personal, Meta::new(Kind::Env, "LATER"), &env("v")).unwrap();
    b.merge_logs(first.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    let me = first.vault.me;
    let removal = b.prepare_removal(&b.device_name(&me)).unwrap();
    let approvals = first.recovery_approval(&removal.digest);
    b.remove_device(&removal, approvals).unwrap();
    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &no_settled()).unwrap();

    // The first device has not heard, and backs up its log as it always does.
    first.vault.add(&personal, Meta::new(Kind::Env, "NOT_HEARD"), &env("v")).unwrap();
    std::fs::write(log::path_for(&backup, &me), first.vault.all_logs().unwrap().into_iter().find(|(device, _)| *device == me).unwrap().1).unwrap();

    d.merge_logs(crate::sync::folder::read_logs(&backup).unwrap(), None).unwrap();
    relock(&mut d);
    d.repair().unwrap();
    assert_eq!(d.secret(&personal, &years).unwrap(), env("v"));
    assert!(d.find(&personal, "NOT_HEARD").is_err(), "what it wrote after its removal does not count");
}

#[test]
fn a_device_that_heard_of_a_removal_does_not_give_it_up_to_a_rival_with_no_more_behind_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut d, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let old_words = a.recovery.clone();
    let h0 = a.vault.state.roster_head();
    let a_at_h0 = a.vault.held_log(&a.vault.me);
    let new_words = remove_and_replace_words(&mut a, &r);

    d.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut d);
    d.repair().unwrap();
    assert!(is_removed(&d, r.id()));

    // R and the old sheet, at the position where both still counted, against A and the same sheet.
    rival(&mut r, vault, h0, |digest, r| vec![r.actor.approve(digest), words_approval(&old_words, digest)], a.vault.me, a_at_h0);
    d.merge_logs(r.log(), None).unwrap();
    assert!(is_removed(&d, r.id()), "R came back on D");
    assert!(new_words.0.matches(&d.state.recovery).unwrap(), "D stopped answering to the owner's words");
}

#[test]
fn two_removed_devices_cannot_take_over_a_device_that_heard() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut d, mut r1) = three(dir.path());
    let vault = a.vault.state.vault;
    let r2 = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r2.log(), None).unwrap();
    d.merge_logs(r2.log(), None).unwrap();
    d.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut a.vault);
    relock(&mut d);
    let h0 = a.vault.state.roster_head();
    let a_at_h0 = a.vault.held_log(&a.vault.me);
    for id in [r1.id(), r2.id()] {
        let removal = a.vault.prepare_removal(&a.vault.device_name(&id)).unwrap();
        let approvals = a.both_approvals(&removal.digest);
        a.vault.remove_device(&removal, approvals).unwrap();
    }
    d.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut d);
    d.repair().unwrap();

    rival(&mut r1, vault, h0, |digest, r| vec![r.actor.approve(digest), r2.actor.approve(digest)], a.vault.me, a_at_h0);
    d.merge_logs(r1.log(), None).unwrap();
    assert!(is_removed(&d, r1.id()) && is_removed(&d, r2.id()), "they came back");
    assert!(!is_removed(&d, a.vault.me), "A went out");
}

#[test]
fn a_person_s_words_bring_back_a_device_a_rival_reached_first_and_it_stays_back() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut d, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let old_words = a.recovery.clone();
    let h0 = a.vault.state.roster_head();
    let a_at_h0 = a.vault.held_log(&a.vault.me);
    let new_words = remove_and_replace_words(&mut a, &r);

    // D has been offline all along, and the rival reaches it first. Nothing on D can tell which is
    // real, so it keeps what it has and says so.
    let me_a = a.vault.me;
    rival(&mut r, vault, h0, |digest, r| vec![r.actor.approve(digest), words_approval(&old_words, digest)], me_a, a_at_h0);
    d.merge_logs(r.log(), None).unwrap();
    assert!(is_removed(&d, me_a), "this has to start captured");
    d.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(d.problems().next().is_some(), "D has to say something is wrong");

    d.merge_logs(a.vault.all_logs().unwrap(), Some(&new_words.0)).unwrap();
    assert!(new_words.0.matches(&d.state.recovery).unwrap(), "the words did not bring D back");
    assert!(is_removed(&d, r.id()));
    let home = d.home.clone();
    drop(d);
    let reopened = Vault::open(&home, Some("pass")).unwrap();
    assert!(new_words.0.matches(&reopened.state.recovery).unwrap(), "what a person settled went back to a default");
}

#[test]
fn an_unnoticed_device_and_retired_words_do_not_turn_the_current_words_away() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let vault = a.vault.state.vault;
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let item = a.vault.add(&personal, Meta::new(Kind::Env, "OWNERS"), &env("the owner's")).unwrap();
    let mut s = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(s.log(), None).unwrap();
    let old_words = a.recovery.clone();
    let h0 = a.vault.state.roster_head();
    let a_at_h0 = a.vault.held_log(&a.vault.me);

    let new_words = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&new_words.0).unwrap();
    let approvals = a.both_approvals(&rotation.digest);
    a.vault.rotate_recovery(rotation, approvals).unwrap();
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();

    rival(&mut s, vault, h0, |digest, r| vec![r.actor.approve(digest), words_approval(&old_words, digest)], a.vault.me, a_at_h0);
    std::fs::write(log::path_for(&backup, &s.id()), s.bytes()).unwrap();

    let at = dir.path().join("new");
    Recovery::open(&backup, &new_words.0.words()).unwrap().finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();
    assert_eq!(new.secret(&personal, &item).unwrap(), env("the owner's"));
    assert!(new_words.0.matches(&new.state.recovery).unwrap());
}

#[test]
fn a_new_device_finds_itself_in_what_it_was_sent_whatever_else_is_in_there() {
    let mut a = Fixture::new();
    let vault = a.vault.state.vault;
    let mut s = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(s.log(), None).unwrap();
    let old_words = a.recovery.clone();
    let h0 = a.vault.state.roster_head();
    let a_at_h0 = a.vault.held_log(&a.vault.me);
    let new_words = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&new_words.0).unwrap();
    let approvals = a.both_approvals(&rotation.digest);
    a.vault.rotate_recovery(rotation, approvals).unwrap();
    rival(&mut s, vault, h0, |digest, r| vec![r.actor.approve(digest), words_approval(&old_words, digest)], a.vault.me, a_at_h0);
    a.vault.merge_logs(s.log(), None).unwrap();

    let joiner = Actor::new();
    let enrollment = a.vault.prepare_enrollment(joiner.fresh.record.clone(), "New").unwrap();
    let approvals = vec![signed_by(&a.vault, &enrollment.digest), words_approval(&new_words.0, &enrollment.digest)];
    a.vault.enroll(&enrollment, approvals).unwrap();

    let anchor = Anchor::Device { keys: &joiner.fresh.record.keys, settled: None };
    let on_joiner = crate::store::replay(&a.vault.all_logs().unwrap(), &anchor).unwrap();
    assert!(on_joiner.members.contains_key(&joiner.id()), "the join would fail");
}

#[test]
fn what_a_later_device_wrote_under_a_key_it_reached_by_a_link_comes_back() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let (epoch, epoch_key) = newest_epoch(&b);

    let (e1, k1) = (epoch.after(r.id()), Key::generate());
    let clock = b.state.clock;
    let sealed = crypto::seal(&k1, &Binding::EpochLink { vault, epoch: e1 }, epoch_key.as_bytes());
    r.write(
        clock + 1,
        &Body::EpochLink { epoch: e1, previous: epoch, commitment: epoch_commitment(&vault, e1, &k1), roster: b.state.roster_head(), sealed },
    );
    r.write(clock + 2, &wrap_to(&b, b.me, e1, &k1));
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    let work = b.create_space("Work").unwrap();

    let (e2, k2) = (e1.after(r.id()), Key::generate());
    let clock = b.state.clock;
    let sealed = crypto::seal(&k2, &Binding::EpochLink { vault, epoch: e2 }, k1.as_bytes());
    r.write(
        clock + 1,
        &Body::EpochLink { epoch: e2, previous: e1, commitment: epoch_commitment(&vault, e2, &k2), roster: b.state.roster_head(), sealed },
    );
    r.write(clock + 2, &wrap_to(&b, b.me, e2, &k2));
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);

    let words = a.recovery.clone();
    let mut j = add_with(&mut b, |vault, digest| vec![signed_by(vault, digest), words_approval(&words, digest)], &dir.path().join("j"), "J");
    let item = j.add(&work.id, Meta::new(Kind::Env, "ONLY_ON_J"), &env("the only copy")).unwrap();

    let without_tail: Logs = j.all_logs().unwrap().into_iter().filter(|(device, _)| *device != r.id()).collect();
    a.vault.merge_logs(without_tail, None).unwrap();
    relock(&mut a.vault);
    remove_r(&mut a, &r);

    j.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut j);
    j.repair().unwrap();
    assert_eq!(j.secret(&work.id, &item).unwrap(), env("the only copy"));
}

#[test]
fn what_a_lost_device_built_on_a_cut_tail_comes_back_through_the_words() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let (epoch, epoch_key) = newest_epoch(&b);
    let recovery = b.state.recovery.clone();

    // R, honest at this point, rotates and wraps to B and to the words. Only B hears.
    let (next, next_key) = (epoch.after(r.id()), Key::generate());
    let clock = b.state.clock;
    let sealed = crypto::seal(&next_key, &Binding::EpochLink { vault, epoch: next }, epoch_key.as_bytes());
    r.write(
        clock + 1,
        &Body::EpochLink {
            epoch: next,
            previous: epoch,
            commitment: epoch_commitment(&vault, next, &next_key),
            roster: b.state.roster_head(),
            sealed,
        },
    );
    r.write(clock + 2, &wrap_to(&b, b.me, next, &next_key));
    let binding = Binding::Epoch { vault, epoch: next, recipient: Recipient::Recovery };
    r.write(
        clock + 3,
        &Body::Wrap { epoch: next, sealed: Sealed::Recovery(recovery.id(), crypto::wrap(recovery.wrap_to(), &binding, &next_key).unwrap()) },
    );
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    let work = b.create_space("Work").unwrap();
    let item = b.add(&work.id, Meta::new(Kind::Env, "ONLY_ON_B"), &env("the only copy")).unwrap();

    // Everything reaches the folder. Then R is removed by A, which had not heard, and B is lost.
    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &no_settled()).unwrap();
    let b_id = b.me;
    let b_log: Logs = b.all_logs().unwrap().into_iter().filter(|(device, _)| *device == b_id).collect();
    drop(b);
    a.vault.merge_logs(b_log, None).unwrap();
    relock(&mut a.vault);
    remove_r(&mut a, &r);
    a.vault.repair().unwrap();
    write_logs(&backup, &a.vault.home, &a.vault.logs_removals_kept()).unwrap();

    let words = a.recovery.words().to_string();
    let at = dir.path().join("new");
    Recovery::open(&backup, &words).unwrap().finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();
    assert_eq!(new.secret(&work.id, &item).unwrap(), env("the only copy"), "the words did not get it back");
}

#[test]
fn a_pile_of_junk_files_does_not_keep_a_recovered_device_out_of_a_folder() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let genesis = a.vault.state.genesis;
    let n = second_device(&a.vault.home.clone(), &words, &dir.path().join("n"), "N");
    let backup = dir.path().join("backup");
    write_logs(&backup, &n.home, &no_settled()).unwrap();
    for byte in 0..40u8 {
        let mut id = [0u8; 16];
        id[15] = byte;
        let device = DeviceId::from(id);
        let entry = Entry { kind: 5, device, seq: 0, clock: now_ms() << 16, prev: root(&genesis, &device), body: vec![], signature: [0; 64] };
        std::fs::write(log::path_for(&backup, &device), entry.encode()).unwrap();
    }
    a.vault.merge_logs(crate::sync::folder::read_logs(&backup).unwrap(), None).unwrap();
    assert!(a.vault.state.members.contains_key(&n.me), "a real device never got a turn");
}

#[path = "audit5_tests.rs"]
mod fifth;
#[path = "fork_tests.rs"]
mod forks;
#[path = "audit4_tests.rs"]
mod fourth;
#[path = "rescue_tests.rs"]
mod rescue;
#[path = "rotation_tests.rs"]
mod rotations;
#[path = "audit6_tests.rs"]
mod sixth;
