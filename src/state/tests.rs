//! Forged entries, correctly signed. These are what a stolen log key or a hostile peer could
//! actually produce, so only the rules in `State` stand between them and the vault. Each test
//! exists because a mutation run showed that rule could be broken with nothing noticing.

use aws_lc_rs::signature::Ed25519KeyPair;

use super::*;
use crate::device::Device;
use crate::device::software::{Cost, Software};
use crate::ids::VaultId;
use crate::item::{Kind, Meta, Secret};
use crate::record::{Approval, Approver, Body, RecoveryPublic};
use crate::recovery::{RecoveryDraft, RecoveryKey};
use crate::setup::{NewDevice, new_device};
use crate::store::log::{Chain, Clock, now_ms};
use crate::vault::Vault;
use crate::{FIRST_SPACE, Setup};

/// A device that exists only for this test, holding every key an attacker could hold.
pub(super) struct Actor {
    pub device: Software,
    pub fresh: NewDevice,
    pub log: Ed25519KeyPair,
}

impl Actor {
    pub fn new() -> Self {
        let device = Software::generate("pass", Cost::FAST).unwrap();
        let fresh = new_device(&device).unwrap();
        let log = Ed25519KeyPair::from_seed_unchecked(fresh.log_seed.as_bytes()).unwrap();
        Self { device, fresh, log }
    }

    pub fn id(&self) -> DeviceId {
        self.fresh.record.id()
    }

    pub fn approve(&self, digest: &Hash) -> Approval {
        Approval { by: Approver::Device(self.id()), signature: self.device.authorize("test").unwrap().sign(digest).unwrap() }
    }

    /// The next entry in this actor's own log, signed with its real key.
    pub fn entry(&self, state: &State, body: &Body) -> Entry {
        let (seq, prev) = state.heads.get(&self.id()).map_or((0, root(&state.genesis, &self.id())), |head| (head.seq + 1, head.hash));
        let mut clock = Clock::default();
        clock.observe(state.clock);
        Chain { device: self.id(), seq, prev }.next(clock.tick(now_ms()), body, &self.log)
    }
}

pub(super) struct Fixture {
    _dir: tempfile::TempDir,
    pub vault: Vault,
    pub recovery: RecoveryKey,
}

impl Fixture {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let setup = Setup::new(Software::generate("pass", Cost::FAST).unwrap());
        let recovery = RecoveryKey::parse(&setup.recovery().words()).unwrap();
        let mut vault = setup.create(&dir.path().join("vault"), "Owner").unwrap();
        vault.unlock("test").unwrap();
        Self { _dir: dir, vault, recovery }
    }

    pub fn state(&mut self) -> &mut State {
        &mut self.vault.state
    }

    /// Enrolls an actor with the recovery key, as a real recovering device would.
    pub fn enroll(&mut self, actor: &Actor) {
        let after = self.vault.state.roster_head();
        let digest = add_digest(&self.vault.state.vault, &after, &actor.id(), &actor.fresh.record);
        let approvals = vec![Approval { by: Approver::Recovery, signature: self.recovery.sign(&digest).unwrap() }];
        let body = Body::DeviceAdd { after, device: actor.fresh.record.clone(), approvals };
        let entry = actor.entry(&self.vault.state, &body);
        self.vault.state.apply(&entry).unwrap();
    }

    pub fn recovery_approval(&self, digest: &Hash) -> Vec<Approval> {
        vec![Approval { by: Approver::Recovery, signature: self.recovery.sign(digest).unwrap() }]
    }

    /// The words and this device together, as replacing the words takes.
    pub fn both_approvals(&self, digest: &Hash) -> Vec<Approval> {
        let own = Approval { by: Approver::Device(self.vault.me), signature: self.vault.device().authorize("test").unwrap().sign(digest).unwrap() };
        [self.recovery_approval(digest), vec![own]].concat()
    }

    fn vault_id(&self) -> VaultId {
        self.vault.state.vault
    }
}

fn skipped(result: Result<(), Refusal>) -> bool {
    matches!(result, Err(Refusal::Skip(_)))
}

fn audit(state: &State) -> Body {
    let author = *state.members.keys().next().unwrap();
    Body::Audit { epoch: Generation::first(author), sealed: vec![1] }
}

// What an approval covers. If the digests were constants, every one of these would apply.

#[test]
fn an_approval_for_one_device_does_not_enroll_another() {
    let mut fixture = Fixture::new();
    let (intended, attacker) = (Actor::new(), Actor::new());
    let after = fixture.state().roster_head();
    let digest = add_digest(&fixture.vault_id(), &after, &attacker.id(), &intended.fresh.record);
    let approvals = fixture.recovery_approval(&digest);

    let body = Body::DeviceAdd { after, device: attacker.fresh.record.clone(), approvals };
    let entry = attacker.entry(fixture.state(), &body);
    assert!(fixture.state().apply(&entry).is_err());
    assert!(!fixture.state().members.contains_key(&attacker.id()));
}

#[test]
fn an_approval_to_remove_one_device_does_not_remove_another() {
    let mut fixture = Fixture::new();
    let (doomed, safe) = (Actor::new(), Actor::new());
    fixture.enroll(&doomed);
    fixture.enroll(&safe);
    let after = fixture.state().roster_head();
    let digest = revoke_digest(&fixture.vault_id(), &after, &doomed.id(), &doomed.id(), 0, &[0; 32]);
    let approvals = fixture.recovery_approval(&digest);

    let body = Body::DeviceRevoke { after, device: safe.id(), entries_kept: 0, last_kept: [0; 32], approvals };
    let entry = doomed.entry(fixture.state(), &body);
    assert!(skipped(fixture.state().apply(&entry)));
    assert_eq!(fixture.state().members[&safe.id()].standing, Standing::Active);
}

#[test]
fn an_approved_removal_cannot_be_given_a_different_cutoff() {
    let mut fixture = Fixture::new();
    let target = Actor::new();
    fixture.enroll(&target);
    let after = fixture.state().roster_head();
    let digest = revoke_digest(&fixture.vault_id(), &after, &target.id(), &target.id(), 1, &[0; 32]);
    let approvals = fixture.recovery_approval(&digest);

    let body = Body::DeviceRevoke { after, device: target.id(), entries_kept: 1_000, last_kept: [0; 32], approvals };
    let entry = target.entry(fixture.state(), &body);
    assert!(skipped(fixture.state().apply(&entry)));
}

#[test]
fn an_approval_for_one_recovery_key_does_not_install_another() {
    let mut fixture = Fixture::new();
    let actor = Actor::new();
    fixture.enroll(&actor);
    let vault = fixture.vault_id();
    let intended: RecoveryPublic = RecoveryDraft::new().0.new_public(vault).unwrap();
    let attacker: RecoveryPublic = RecoveryDraft::new().0.new_public(vault).unwrap();
    let after = fixture.state().roster_head();
    let digest = rotate_digest(&vault, &after, &actor.id(), &intended);
    let approvals = fixture.recovery_approval(&digest);
    let before = fixture.state().recovery.clone();
    let proof = fixture.recovery.sign(&digest).unwrap();

    let body = Body::RecoveryRotate { after, recovery: attacker, proof, approvals };
    let entry = actor.entry(fixture.state(), &body);
    assert!(skipped(fixture.state().apply(&entry)));
    assert_eq!(fixture.state().recovery, before);
}

#[test]
fn a_replayed_approval_is_not_good_for_a_later_position() {
    let mut fixture = Fixture::new();
    let (first, second) = (Actor::new(), Actor::new());
    let old_head = fixture.state().roster_head();
    let digest = add_digest(&fixture.vault_id(), &old_head, &second.id(), &second.fresh.record);
    let old_approvals = fixture.recovery_approval(&digest);
    fixture.enroll(&first);

    let body = Body::DeviceAdd { after: old_head, device: second.fresh.record.clone(), approvals: old_approvals };
    let entry = second.entry(fixture.state(), &body);
    assert!(fixture.state().apply(&entry).is_err());
    assert!(!fixture.state().members.contains_key(&second.id()));
}

// Who may approve.

#[test]
fn a_device_cannot_vote_on_its_own_removal() {
    let mut fixture = Fixture::new();
    let (second, target) = (Actor::new(), Actor::new());
    fixture.enroll(&second);
    fixture.enroll(&target);
    let after = fixture.state().roster_head();
    let digest = revoke_digest(&fixture.vault_id(), &after, &second.id(), &target.id(), 1, &[0; 32]);

    // Two approvals, but one is from the device being removed.
    let approvals = vec![second.approve(&digest), target.approve(&digest)];
    let body = Body::DeviceRevoke { after, device: target.id(), entries_kept: 1, last_kept: [0; 32], approvals };
    let entry = second.entry(fixture.state(), &body);
    assert_eq!(fixture.state().apply(&entry), Err(Refusal::Skip("not enough approvals")));
}

#[test]
fn two_other_devices_can_remove_a_third_without_the_recovery_key() {
    let mut fixture = Fixture::new();
    let (first, second, target) = (Actor::new(), Actor::new(), Actor::new());
    fixture.enroll(&first);
    fixture.enroll(&second);
    fixture.enroll(&target);
    let after = fixture.state().roster_head();
    let digest = revoke_digest(&fixture.vault_id(), &after, &first.id(), &target.id(), 1, &[0; 32]);
    let approvals = vec![first.approve(&digest), second.approve(&digest)];
    let body = Body::DeviceRevoke { after, device: target.id(), entries_kept: 1, last_kept: [0; 32], approvals };
    let entry = first.entry(fixture.state(), &body);
    fixture.state().apply(&entry).unwrap();
    assert_ne!(fixture.state().members[&target.id()].standing, Standing::Active);
}

#[test]
fn an_approval_from_a_removed_device_does_not_count() {
    let mut fixture = Fixture::new();
    let (first, removed, newcomer) = (Actor::new(), Actor::new(), Actor::new());
    fixture.enroll(&first);
    fixture.enroll(&removed);
    let after = fixture.state().roster_head();
    let digest = revoke_digest(&fixture.vault_id(), &after, &first.id(), &removed.id(), 1, &[0; 32]);
    let approvals = fixture.recovery_approval(&digest);
    let body = Body::DeviceRevoke { after, device: removed.id(), entries_kept: 1, last_kept: [0; 32], approvals };
    let entry = first.entry(fixture.state(), &body);
    fixture.state().apply(&entry).unwrap();

    let after = fixture.state().roster_head();
    let digest = add_digest(&fixture.vault_id(), &after, &newcomer.id(), &newcomer.fresh.record);
    let approvals = vec![first.approve(&digest), removed.approve(&digest)];
    let body = Body::DeviceAdd { after, device: newcomer.fresh.record.clone(), approvals };
    let entry = newcomer.entry(fixture.state(), &body);
    assert!(fixture.state().apply(&entry).is_err());
}

// What a removed device can still write.

#[test]
fn a_removal_keeps_exactly_the_entries_it_says_and_no_more() {
    let mut fixture = Fixture::new();
    let (first, removed) = (Actor::new(), Actor::new());
    fixture.enroll(&first);
    fixture.enroll(&removed);
    let kept = audit(fixture.state());
    let entry = removed.entry(fixture.state(), &kept);
    fixture.state().apply(&entry).unwrap();

    let after = fixture.state().roster_head();
    let entries_kept = fixture.state().heads[&removed.id()].seq + 1;
    let last_kept = fixture.state().heads[&removed.id()].hash;
    let digest = revoke_digest(&fixture.vault_id(), &after, &first.id(), &removed.id(), entries_kept, &last_kept);
    let approvals = fixture.recovery_approval(&digest);
    let body = Body::DeviceRevoke { after, device: removed.id(), entries_kept, last_kept, approvals };
    let entry = first.entry(fixture.state(), &body);
    fixture.state().apply(&entry).unwrap();

    // The last entry it wrote before removal replays fine. The next one is refused.
    let member = &fixture.state().members[&removed.id()];
    assert!(member.accepts(entries_kept - 1));
    assert!(!member.accepts(entries_kept));
    let late = audit(fixture.state());
    let entry = removed.entry(fixture.state(), &late);
    assert_eq!(fixture.state().apply(&entry), Err(Refusal::Stop("past what that device's removal kept")));
}

// Who an entry claims to be.

#[test]
fn a_device_can_enroll_only_itself() {
    let mut fixture = Fixture::new();
    let (author, claimed) = (Actor::new(), Actor::new());
    let after = fixture.state().roster_head();
    let digest = add_digest(&fixture.vault_id(), &after, &claimed.id(), &claimed.fresh.record);
    let approvals = fixture.recovery_approval(&digest);

    // Signed with the enrolling device's own log key, but filed under someone else's log.
    let body = Body::DeviceAdd { after, device: claimed.fresh.record.clone(), approvals };
    let genesis = fixture.state().genesis;
    let mut chain = Chain { device: author.id(), seq: 0, prev: root(&genesis, &author.id()) };
    let entry = chain.next(u64::MAX / 2, &body, &claimed.log);
    assert_eq!(fixture.state().apply(&entry), Err(Refusal::Stop("written by a device that is not enrolled")));
    assert!(!fixture.state().members.contains_key(&claimed.id()));
}

#[test]
fn an_entry_from_a_stranger_is_refused() {
    let mut fixture = Fixture::new();
    let stranger = Actor::new();
    let body = audit(fixture.state());
    let entry = stranger.entry(fixture.state(), &body);
    assert_eq!(fixture.state().apply(&entry), Err(Refusal::Stop("written by a device that is not enrolled")));
}

// Chains.

/// A log of validly signed entries, with clocks chosen by the caller.
fn log_with_clocks(fixture: &mut Fixture, actor: &Actor, clocks: &[u64]) -> Parsed {
    let genesis = fixture.state().genesis;
    let body = audit(fixture.state());
    let mut chain = Chain { device: actor.id(), seq: 0, prev: root(&genesis, &actor.id()) };
    let entries: Vec<Entry> = clocks.iter().map(|clock| chain.next(*clock, &body, &actor.log)).collect();
    Parsed { entries, ..Parsed::default() }
}

#[test]
fn a_clock_that_stalls_or_goes_backwards_breaks_the_chain() {
    let mut fixture = Fixture::new();
    let actor = Actor::new();
    let id = actor.id();
    for (clocks, whole) in [(&[5u64, 6, 7][..], 3), (&[5, 5, 7], 1), (&[5, 4, 7], 1)] {
        let parsed = log_with_clocks(&mut fixture, &actor, clocks);
        assert_eq!(fixture.state().valid_chain(&id, &parsed), whole, "{clocks:?}");
    }
}

#[test]
fn the_first_entry_of_a_log_may_have_any_clock() {
    let mut fixture = Fixture::new();
    let actor = Actor::new();
    let id = actor.id();
    let parsed = log_with_clocks(&mut fixture, &actor, &[0, 1]);
    assert_eq!(fixture.state().valid_chain(&id, &parsed), 2);
}

#[test]
fn a_log_is_rooted_in_its_own_vault() {
    assert_ne!(root(&[1; 32], &[2; 16].into()), root(&[3; 32], &[2; 16].into()));
    assert_ne!(root(&[1; 32], &[2; 16].into()), root(&[1; 32], &[4; 16].into()));
    let mut fixture = Fixture::new();
    let actor = Actor::new();
    let id = actor.id();
    let mut parsed = log_with_clocks(&mut fixture, &actor, &[1]);
    parsed.entries[0].prev = root(&[9; 32], &id);
    assert_eq!(fixture.state().valid_chain(&id, &parsed), 0);
}

// Genesis.

fn forged_genesis(mutate: impl Fn(&mut Chain, &mut DeviceId)) -> Result<State> {
    let actor = Actor::new();
    let recovery = RecoveryKey::generate();
    let vault = VaultId::random();
    let public = recovery.new_public(vault).unwrap();
    let first_epoch = [5; 32];
    let digest = genesis_digest(&vault, &actor.fresh.record, &public, &first_epoch);
    let body = Body::Genesis {
        vault,
        recovery: public,
        device: actor.fresh.record.clone(),
        first_epoch,
        device_signature: actor.device.authorize("test").unwrap().sign(&digest).unwrap(),
        recovery_signature: recovery.sign(&digest).unwrap(),
    };
    let mut chain = Chain { device: actor.id(), seq: 0, prev: [0; 32] };
    let mut device = actor.id();
    mutate(&mut chain, &mut device);
    chain.device = device;
    let entry = chain.next(1, &body, &actor.log);
    let parsed = Parsed { entries: vec![entry], ..Parsed::default() };
    State::from_logs(&[(device, parsed)])
}

#[test]
fn an_honest_genesis_is_accepted() {
    assert!(forged_genesis(|_, _| {}).is_ok());
}

#[test]
fn a_genesis_must_be_first_unlinked_and_from_its_device() {
    assert!(forged_genesis(|chain, _| chain.seq = 3).is_err());
    assert!(forged_genesis(|chain, _| chain.prev = [1; 32]).is_err());
    assert!(forged_genesis(|_, device| *device = [9; 16].into()).is_err());
}

// Rotation, checked against what is written, not what the rotating device still holds in memory.

#[test]
fn a_removed_device_is_not_wrapped_the_new_keys_and_everyone_else_is() {
    let mut fixture = Fixture::new();
    let (staying, leaving) = (Actor::new(), Actor::new());
    fixture.enroll(&staying);
    fixture.enroll(&leaving);
    let leaving_name = "Leaving";
    let vault = fixture.vault_id();
    let (epoch, key) = {
        let keys = fixture.vault.keys.as_ref().unwrap();
        let (epoch, key) = keys.newest_epoch().unwrap();
        (epoch, key.clone())
    };
    let label = crate::vault::label_body(vault, epoch, &key, leaving.id(), leaving_name).unwrap();
    let entry = leaving.entry(fixture.state(), &label);
    fixture.state().apply(&entry).unwrap();

    let removal = fixture.vault.prepare_removal(leaving_name).unwrap();
    let approvals = fixture.recovery_approval(&removal.digest);
    fixture.vault.remove_device(&removal, approvals).unwrap();

    let newest = fixture.state().wraps.iter().map(|wrap| wrap.epoch.number).max().unwrap();
    let wrapped: Vec<DeviceId> = fixture
        .state()
        .wraps
        .iter()
        .filter(|wrap| wrap.epoch.number == newest)
        .filter_map(|wrap| if let Sealed::Device(id, _) = &wrap.sealed { Some(*id) } else { None })
        .collect();
    assert!(!wrapped.contains(&leaving.id()), "the removed device was given the new key");
    assert!(wrapped.contains(&staying.id()), "a remaining device was left without the new key");
    let me = fixture.vault.me;
    assert!(wrapped.contains(&me));
}

#[test]
fn repair_adds_wraps_only_for_the_newest_epoch_and_only_where_missing() {
    let mut fixture = Fixture::new();
    let staying = Actor::new();
    fixture.enroll(&staying);
    let wraps_to =
        |state: &State, id: DeviceId| state.wraps.iter().filter(|wrap| matches!(&wrap.sealed, Sealed::Device(device, _) if *device == id)).count();
    assert_eq!(wraps_to(fixture.state(), staying.id()), 0);

    fixture.vault.repair().unwrap();
    assert_eq!(wraps_to(fixture.state(), staying.id()), 1, "the enrolled device was missing its wrap");
    fixture.vault.repair().unwrap();
    assert_eq!(wraps_to(fixture.state(), staying.id()), 1, "repair must be safe to repeat");
}

#[test]
fn an_item_survives_rotation_and_the_old_version_stays_in_history() {
    let mut fixture = Fixture::new();
    let space = fixture.vault.space(FIRST_SPACE).unwrap().id;
    let secret = Secret::Env { value: "value".to_owned() };
    let id = fixture.vault.add(&space, Meta::new(Kind::Env, "KEY"), &secret).unwrap();
    let draft = RecoveryDraft::new();
    let rotation = fixture.vault.prepare_recovery_rotation(&draft.0).unwrap();
    let approvals = fixture.both_approvals(&rotation.digest);
    fixture.vault.rotate_recovery(rotation, approvals).unwrap();
    assert_eq!(fixture.vault.secret(&space, &id).unwrap(), secret);
    assert_eq!(fixture.vault.history(&space, &id).unwrap().len(), 1, "a rotation is not an edit");
}
