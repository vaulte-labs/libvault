//! The fifth audit: each asserts a promise. Mostly what happens when honest devices race, and
//! what a person has to decide. `sim_honest_devices` is a seeded simulation of honest devices, run
//! by hand with `SIM_FROM` and `SIM_TO`.

#![allow(
    clippy::many_single_char_names,
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::needless_pass_by_value,
    reason = "a simulation, read start to finish, with one letter per device"
)]

use super::*;
use crate::device::Device;

/// What a person does with two histories: picks the one holding a device they know.
fn the_person_picks(mut opened: Recovery, device: &str) -> Recovery {
    let histories = opened.histories();
    let index = histories.iter().position(|history| history.devices.iter().any(|name| name == device)).expect("the honest history is on offer");
    opened.choose_history(index).unwrap();
    opened
}

/// H1: the first device, stolen and removed by two others with no words, signs a rival at the
/// position it once held alone, enrolls two puppets, and retires itself there too.
#[test]
fn a_removed_first_device_does_not_take_a_fresh_recovery_by_retiring_itself() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let genesis_head = a.vault.state.roster_head();
    let vault_id = a.vault.state.vault;
    let genesis = a.vault.state.genesis;

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
    relock(&mut b);

    let removal = b.prepare_removal(&b.device_name(&a.vault.me)).unwrap();
    let approvals = vec![signed_by(&b, &removal.digest), signed_by(&c, &removal.digest)];
    b.remove_device(&removal, approvals).unwrap();
    let years = b.add(&personal, Meta::new(Kind::Env, "AFTER_REMOVAL"), &env("everything written since")).unwrap();
    c.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &no_settled()).unwrap();

    // The thief. Everything here is signed with keys it holds: the stolen first device, and two of its own.
    let (p, q) = (Actor::new(), Actor::new());
    let add_p = {
        let digest = add_digest(&vault_id, &genesis_head, &p.id(), &p.fresh.record);
        let body = Body::DeviceAdd { after: genesis_head, device: p.fresh.record.clone(), approvals: vec![signed_by(&a.vault, &digest)] };
        Chain { device: p.id(), seq: 0, prev: root(&genesis, &p.id()) }.next(2, &body, &p.log)
    };
    let add_q = {
        let digest = add_digest(&vault_id, &add_p.hash(), &q.id(), &q.fresh.record);
        let approvals = vec![signed_by(&a.vault, &digest), p.approve(&digest)];
        let body = Body::DeviceAdd { after: add_p.hash(), device: q.fresh.record.clone(), approvals };
        Chain { device: q.id(), seq: 0, prev: root(&genesis, &q.id()) }.next(3, &body, &q.log)
    };
    let a_log = log::parse(&std::fs::read(log::path_for(&backup, &a.vault.me)).unwrap()).entries;
    let (kept, last) = (a_log.len() as u64, a_log.last().unwrap().hash());
    let drop_a = {
        let digest = revoke_digest(&vault_id, &add_q.hash(), &p.id(), &a.vault.me, kept, &last);
        let body = Body::DeviceRevoke {
            after: add_q.hash(),
            device: a.vault.me,
            entries_kept: kept,
            last_kept: last,
            approvals: vec![p.approve(&digest), q.approve(&digest)],
        };
        Chain { device: p.id(), seq: 1, prev: add_p.hash() }.next(4, &body, &p.log)
    };
    std::fs::write(log::path_for(&backup, &p.id()), [add_p.encode(), drop_a.encode()].concat()).unwrap();
    std::fs::write(log::path_for(&backup, &q.id()), add_q.encode()).unwrap();

    let opened = Recovery::open(&backup, &words).unwrap();
    assert!(opened.problems().iter().any(|problem| problem.contains("more than one history")));
    let at = dir.path().join("refused");
    assert!(
        Recovery::open(&backup, &words).unwrap().finish_with_passphrase("pass", Cost::FAST, &at, "New").is_err(),
        "nothing but a date tells these apart, so nothing may pick"
    );
    let opened = the_person_picks(opened, "B");
    let at = dir.path().join("new");
    opened.finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();

    let p_in = new.state.active_devices().any(|(id, _)| *id == p.id());
    let b_in = new.state.active_devices().any(|(id, _)| *id == b.me);

    // What the new device does on the thief's branch: it hands its keys to the thief's device.
    let personal_now = new.space(FIRST_SPACE).unwrap().id;
    new.add(&personal_now, Meta::new(Kind::Env, "WRITTEN_AFTER_RECOVERY"), &env("new secret")).unwrap();
    new.repair().unwrap();

    assert!(b_in && !p_in, "the owner's own words put a recovered device on the stolen device's history");
    assert!(new.secret(&personal, &years).is_ok(), "and everything since is gone");
}

/// H3: a device hears a removal first, and the log the removal kept only later.
#[test]
fn a_fork_is_taken_even_when_the_kept_log_arrives_after_the_removal() {
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
    relock(&mut b);
    relock(&mut c);

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

    let removal = c.prepare_removal(&c.device_name(&me)).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    c.remove_device(&removal, approvals).unwrap();

    // A file sync delivers C's log first and A's a minute later. Nothing else differs.
    let (of_a, others): (Logs, Logs) = c.all_logs().unwrap().into_iter().partition(|(device, _)| *device == me);
    b.merge_logs(others, None).unwrap();
    assert!(b.state.problems.iter().any(|problem| problem.reason == "contradicts what its removal kept"), "the setup");
    b.merge_logs(of_a, None).unwrap();
    for _ in 0..2 {
        b.merge_logs(c.all_logs().unwrap(), None).unwrap();
    }
    relock(&mut b);
    b.repair().unwrap();
    assert_eq!(b.secret(&personal, &years_of_work).ok(), Some(env("the person's secret")), "B holds the kept log on offer and will not take it");
}

/// H4: the 64 limit on what a removed device left. One orphan lifts it for good.
#[test]
fn a_removed_device_cannot_lift_the_limit_on_what_it_left_with_one_orphan() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let (epoch, _) = newest_epoch(&b);

    // A generation of its own, wrapped to B many times with keys that open nothing.
    let junk_epoch = epoch.after(r.id());
    r_generation_for_tests(&mut r, &b, junk_epoch, epoch, &Key::generate());
    for _ in 0..500 {
        let body = wrap_to(&b, b.me, junk_epoch, &Key::generate());
        r.write(b.state.clock + 1, &body);
    }
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();

    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    let before = b.wraps_tried_for_tests();

    // Same again, with one put under a version that exists nowhere, in the log the removal keeps.
    let dir2 = tempfile::tempdir().unwrap();
    let (mut a2, mut b2, mut r2) = three(dir2.path());
    let personal2 = a2.vault.space(FIRST_SPACE).unwrap().id;
    let (epoch2, _) = newest_epoch(&b2);
    let junk2 = epoch2.after(r2.id());
    r_generation_for_tests(&mut r2, &b2, junk2, epoch2, &Key::generate());
    for _ in 0..500 {
        let body = wrap_to(&b2, b2.me, junk2, &Key::generate());
        r2.write(b2.state.clock + 1, &body);
    }
    let orphan = Body::ItemPut {
        space: personal2,
        item: ItemId::random(),
        version: Generation::first(r2.id()),
        batch: BatchId::random(),
        meta: vec![1],
        secret: vec![2],
    };
    r2.write(b2.state.clock + 1, &orphan);
    a2.vault.merge_logs(r2.log(), None).unwrap();
    b2.merge_logs(r2.log(), None).unwrap();
    remove_r(&mut a2, &r2);
    b2.merge_logs(a2.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b2);
    b2.repair().unwrap();
    let after = b2.wraps_tried_for_tests();
    let _ = personal;
    assert!(after <= before + 8, "one entry from a removed device lifted the limit for every unlock from now on");
}

fn r_generation_for_tests(r: &mut Bad, to: &Vault, epoch: Generation, previous: Generation, key: &Key) {
    let vault = to.state.vault;
    let body =
        Body::EpochLink { epoch, previous, commitment: epoch_commitment(&vault, epoch, key), roster: to.state.roster_head(), sealed: vec![0; 80] };
    r.write(to.state.clock + 1, &body);
}

/// H2: D, honest and lost, wrote something C holds and A does not. A removes D with the words.
#[test]
fn what_a_lost_device_wrote_and_a_peer_holds_is_not_lost_to_a_removal_that_had_not_seen_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let home = a.vault.home.clone();
    let mut c = second_device(&home, &words, &dir.path().join("c"), "C");
    a.vault.merge_logs(c.all_logs().unwrap(), None).unwrap();
    let mut d = second_device(&a.vault.home.clone(), &words, &dir.path().join("d"), "D");
    a.vault.merge_logs(d.all_logs().unwrap(), None).unwrap();
    c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    d.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut c);
    relock(&mut d);

    let item = d.add(&personal, Meta::new(Kind::Env, "WRITTEN_ON_D"), &env("the only other copy is on C")).unwrap();
    c.merge_logs(d.all_logs().unwrap(), None).unwrap();
    assert_eq!(c.secret(&personal, &item).unwrap(), env("the only other copy is on C"));

    // D's bag is stolen on the train. C is at home, asleep. The person removes D from A, as they should.
    let removal = a.vault.prepare_removal(&a.vault.device_name(&d.me)).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();

    c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut c);
    c.repair().unwrap();
    let export = dir.path().join("export.json");
    c.export_plaintext(&export).unwrap();
    let exported = std::fs::read_to_string(&export).unwrap();
    assert!(
        exported.contains("WRITTEN_ON_D") && exported.contains("the only other copy is on C"),
        "a secret on an honest device is gone, with no way to get it back"
    );
    assert!(exported.contains("\"cut\":true"), "and it has to say it does not count");
    assert!(c.secret(&personal, &item).is_err(), "it does not count");
}

/// H9: two honest devices race, one removing R, one adding a phone. Nothing hostile is signed.
#[test]
fn a_removal_does_not_lose_to_an_honest_add_on_the_date_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();

    // B pairs a phone with the words while A, offline, removes R with the words.
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let phone = add_with(&mut b, with_words, &dir.path().join("phone"), "Phone");
    std::thread::sleep(std::time::Duration::from_millis(5));
    remove_with_both(&mut a, r.id());

    // A third party that has heard both. A fresh recovery stands in for any device that vouched for neither.
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();
    let _ = write_logs(&backup, &b.home, &no_settled());
    let mut opened = Recovery::open(&backup, &words.words()).unwrap();
    opened.choose_history(0).unwrap();
    let at = dir.path().join("fresh");
    opened.finish_with_passphrase("pass", Cost::FAST, &at, "Fresh").unwrap();
    let fresh = Vault::open(&at, Some("pass")).unwrap();
    let r_in = fresh.state.active_devices().any(|(id, _)| *id == r.id());

    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let _ = phone;
    assert!(!r_in, "R is in the vault on a fresh copy");
}

/// What a person who removes a device writes: this device's touch and the words.
fn remove_with_both(a: &mut Fixture, target: DeviceId) {
    let removal = a.vault.prepare_removal(&a.vault.device_name(&target)).unwrap();
    let approvals = a.both_approvals(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
}

/// R's view of a value: from a wrap anyone wrote to R, through the space record, to the secret.
fn r_reads(r: &Bad, vault: &Vault, space: SpaceId, item: ItemId) -> Option<Secret> {
    actor_reads(&r.actor, vault, space, item)
}

fn actor_reads(actor: &Actor, vault: &Vault, space: SpaceId, item: ItemId) -> Option<Secret> {
    let id = vault.state.vault;
    let Change::Put { version, secret, .. } = &vault.state.items[&(space, item)].last().unwrap().change else { return None };
    let record = &vault.state.spaces[&space][version];
    let binding = Binding::Epoch { vault: id, epoch: record.epoch, recipient: Recipient::Device(actor.id()) };
    let approved = actor.device.authorize("test").ok()?;
    let public = actor.device.public().wrap_to();
    let epoch_key = vault.state.wraps.iter().filter(|wrap| wrap.epoch == record.epoch).find_map(|wrap| {
        let Sealed::Device(to, wrapped) = &wrap.sealed else { return None };
        if *to != actor.id() {
            return None;
        }
        let shared = approved.agree(&wrapped.ephemeral, &wrapped.ciphertext).ok()?;
        crypto::unwrap(&shared, public, &binding, wrapped).ok()
    })?;
    #[derive(serde::Deserialize)]
    struct Record {
        #[allow(dead_code)]
        name: String,
        key: [u8; 32],
    }
    let opened = crypto::open(&epoch_key, &Binding::Space { vault: id, space, version: *version }, &record.sealed).ok()?;
    let record: Record = crate::item::decode(&opened).ok()?;
    let key = Key::from_bytes(record.key);
    let binding = Binding::Item { vault: id, space, item, version: *version, part: Part::Secret };
    crate::item::decode(&crypto::open(&key, &binding, secret).ok()?).ok()
}

/// H9b: the race with the approvals a person really gives. What A writes after removing R.
#[test]
fn what_a_writes_after_removing_r_stays_out_of_r_s_reach_through_a_race() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;

    // B pairs a phone on a train, using the words. A, at home, removes stolen R a moment later.
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let _phone = add_with(&mut b, with_words, &dir.path().join("phone"), "Phone");
    std::thread::sleep(std::time::Duration::from_millis(5));
    remove_with_both(&mut a, r.id());
    let new_secret = a.vault.add(&personal, Meta::new(Kind::Env, "AFTER_R_WAS_REMOVED"), &env("A believes R cannot read this")).unwrap();
    assert!(is_removed(&a.vault, r.id()));

    // They sync. Each merge is as the broker does it: lock if told to, unlock, repair.
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut a.vault);
    a.vault.repair().unwrap();
    relock(&mut b);
    b.repair().unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();

    // R, enrolled on B's roster, syncs with B and gets B's logs. Everything here is what B holds.
    let read = r_reads(&r, &b, personal, new_secret);
    assert_eq!(read, None, "a device removed from A reads what A wrote after removing it");
}

/// H9c: settling that split with the words, from either side.
#[test]
fn a_person_with_the_words_can_keep_a_removal_that_raced() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let _phone = add_with(&mut b, with_words, &dir.path().join("phone"), "Phone");
    std::thread::sleep(std::time::Duration::from_millis(5));
    remove_with_both(&mut a, r.id());
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();

    // The person tells B to take A's side, which is the side with the removal.
    b.merge_logs(a.vault.all_logs().unwrap(), Some(&words)).unwrap();
    // And the other way about, on A.
    a.vault.merge_logs(b.all_logs().unwrap(), Some(&words)).unwrap();
    assert!(is_removed(&b, r.id()) && is_removed(&a.vault, r.id()), "settling cannot keep the removal: both sides answer to one set of words");
}

/// H1b: as H1, with nothing removed at all. The first device has gone bad, and is still enrolled.
#[test]
fn an_enrolled_first_device_does_not_take_a_fresh_recovery_on_a_date() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let genesis_head = a.vault.state.roster_head();
    let mut b = add_with(&mut a.vault, |vault, digest| vec![signed_by(vault, digest)], &dir.path().join("b"), "B");
    b.add(&personal, Meta::new(Kind::Env, "ON_B"), &env("v")).unwrap();
    let backup = dir.path().join("backup");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();

    let p = Actor::new();
    let digest = add_digest(&a.vault.state.vault, &genesis_head, &p.id(), &p.fresh.record);
    let body = Body::DeviceAdd { after: genesis_head, device: p.fresh.record.clone(), approvals: vec![signed_by(&a.vault, &digest)] };
    let entry = Chain { device: p.id(), seq: 0, prev: root(&a.vault.state.genesis, &p.id()) }.next(2, &body, &p.log);
    std::fs::write(log::path_for(&backup, &p.id()), entry.encode()).unwrap();

    let opened = the_person_picks(Recovery::open(&backup, &words).unwrap(), "B");
    let at = dir.path().join("new");
    opened.finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();
    assert!(new.state.members.contains_key(&b.me), "B's whole log is gone from the recovered vault");
}

// A seeded simulation of honest devices. No hostile entry anywhere: only partial syncs, restarts,
// rotations and roster changes made while every active device agrees on the roster.
mod sim {
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            usize::try_from(self.next() % n as u64).unwrap()
        }
    }

    struct Dev {
        vault: Option<Vault>,
        home: std::path::PathBuf,
        id: DeviceId,
        removed: bool,
    }

    fn settle_keys(vault: &mut Vault) -> crate::Result<()> {
        if !vault.is_unlocked() {
            vault.unlock("test")?;
        }
        vault.repair()
    }

    /// As the broker's `take_in`, with a person who answers.
    fn take(vault: &mut Vault, logs: Logs) -> crate::Result<()> {
        let merged = vault.merge_logs(logs, None)?;
        if merged.must_lock {
            vault.lock();
        }
        settle_keys(vault)
    }

    pub struct Report {
        pub trace: Vec<String>,
        pub failure: Option<String>,
    }

    /// With roster races allowed, devices may end up apart. What must still hold: nobody panics or
    /// bricks, no honest log stops for a reason an honest device cannot give, and each device still
    /// reads what it wrote itself.
    fn race_ending(mut devs: Vec<Dev>, written: Vec<(SpaceId, ItemId, String, usize)>, mut trace: Vec<String>) -> Report {
        const NEVER: [&str; 5] = [
            "a key generation that is not its author's to write",
            "bad entry signature",
            "the hash chain is broken",
            "a sequence number is out of order",
            "the clock went backwards",
        ];
        let active: Vec<usize> = (0..devs.len()).filter(|index| !devs[*index].removed).collect();
        for round in 0..4 {
            for from in &active {
                for to in &active {
                    if from != to {
                        let logs = devs[*from].vault.as_ref().unwrap().all_logs().unwrap();
                        if let Err(error) = take(devs[*to].vault.as_mut().unwrap(), logs) {
                            return Report { failure: Some(format!("round {round}: a merge failed on d{to}: {error}")), trace };
                        }
                    }
                }
            }
        }
        for index in &active {
            let vault = devs[*index].vault.take().unwrap();
            let is_active = vault.is_active(&vault.me);
            let conflicts = vault.state.lost_ties.len();
            drop(vault);
            let reopened = Vault::open(&devs[*index].home, Some("pass"));
            let Ok(mut reopened) = reopened else {
                return Report { failure: Some(format!("d{index} would not open: {:?}", reopened.err())), trace };
            };
            if let Err(error) = settle_keys(&mut reopened) {
                return Report { failure: Some(format!("d{index} would not unlock: {error}")), trace };
            }
            if let Some(problem) = reopened.state.problems.iter().find(|problem| NEVER.contains(&problem.reason)) {
                return Report { failure: Some(format!("d{index} sees a stop no honest device earns: {problem:?}")), trace };
            }
            if is_active {
                for (space, item, name, by) in &written {
                    if by == index && reopened.secret(space, item).is_err() {
                        return Report { failure: Some(format!("d{index} cannot read {name}, which it wrote (ties {conflicts})")), trace };
                    }
                }
            }
            trace.push(format!("end: d{index} active={is_active} ties={conflicts} devices={}", reopened.device_count()));
            devs[*index].vault = Some(reopened);
        }
        Report { failure: None, trace }
    }

    pub fn run(seed: u64, steps: usize, partial: bool, race: bool) -> Report {
        let mut rng = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let dir = tempfile::tempdir().unwrap();
        let mut trace = Vec::new();
        let mut first = Fixture::new();
        let mut words = first.recovery.clone();
        let mut every_words = vec![first.recovery.clone()];
        let personal = first.vault.space(FIRST_SPACE).unwrap().id;
        let home0 = first.vault.home.clone();
        let id0 = first.vault.me;

        let mut devs: Vec<Dev> = Vec::new();
        for n in 1..3 {
            let at = dir.path().join(format!("d{n}"));
            let vault = second_device(&home0, &words.words(), &at, &format!("D{n}"));
            first.vault.merge_logs(vault.all_logs().unwrap(), None).unwrap();
            devs.push(Dev { id: vault.me, home: at, vault: Some(vault), removed: false });
        }
        // Everyone level, one way or another.
        let all = first.vault.all_logs().unwrap();
        for dev in &mut devs {
            take(dev.vault.as_mut().unwrap(), all.clone()).unwrap();
        }
        settle_keys(&mut first.vault).unwrap();
        let fixture_words = first.recovery.clone();
        let _ = fixture_words;
        let mut first_dev = Some(first);
        let vault0 = {
            let fixture = first_dev.as_mut().unwrap();
            std::mem::replace(&mut fixture.vault, Fixture::new().vault)
        };
        devs.insert(0, Dev { id: id0, home: home0, vault: Some(vault0), removed: false });

        let mut written: Vec<(SpaceId, ItemId, String, usize)> = Vec::new();
        let mut made = 0usize;

        for step in 0..steps {
            let active: Vec<usize> = (0..devs.len()).filter(|index| !devs[*index].removed).collect();
            let at = active[rng.below(active.len())];
            let other = active[rng.below(active.len())];
            let roster_level = {
                let heads: BTreeSet<Hash> = active.iter().map(|index| devs[*index].vault.as_ref().unwrap().state.roster_head()).collect();
                race || heads.len() == 1
            };
            match rng.below(100) {
                0..=34 => {
                    let vault = devs[at].vault.as_mut().unwrap();
                    let spaces = vault.spaces().unwrap_or_default();
                    if spaces.is_empty() {
                        continue;
                    }
                    let space = spaces[rng.below(spaces.len())].id;
                    let name = format!("ITEM_{step}");
                    let value = format!("v{step}");
                    match vault.add(&space, Meta::new(Kind::Env, name.clone()), &env(&value)) {
                        Ok(item) => {
                            trace.push(format!("{step}: d{at} add {name} in {space}"));
                            written.push((space, item, name, at));
                        }
                        Err(error) => trace.push(format!("{step}: d{at} add failed: {error}")),
                    }
                }
                35..=44 => {
                    if !written.is_empty() {
                        let (space, item, name, _) = written[rng.below(written.len())].clone();
                        let vault = devs[at].vault.as_mut().unwrap();
                        if vault.items(&space).unwrap_or_default().iter().any(|found| found.id == item) {
                            match vault.replace(&space, &item, &Meta::new(Kind::Env, name.clone()), &env(&format!("edit{step}"))) {
                                Ok(()) => trace.push(format!("{step}: d{at} edit {name}")),
                                Err(error) => trace.push(format!("{step}: d{at} edit {name} failed: {error}")),
                            }
                        }
                    }
                }
                45..=74 => {
                    if at != other {
                        let mut logs = devs[other].vault.as_ref().unwrap().all_logs().unwrap();
                        if partial && rng.below(3) == 0 {
                            let keep = rng.next();
                            let mut index = 0;
                            logs.retain(|_, _| {
                                index += 1;
                                keep >> (index % 60) & 1 == 1
                            });
                        }
                        trace.push(format!("{step}: d{at} hears d{other} ({} logs)", logs.len()));
                        if let Err(error) = take(devs[at].vault.as_mut().unwrap(), logs) {
                            return Report { failure: Some(format!("step {step}: a merge failed on d{at}: {error}")), trace };
                        }
                    }
                }
                75..=79 => {
                    let vault = devs[at].vault.take().unwrap();
                    drop(vault);
                    let reopened = Vault::open(&devs[at].home, Some("pass"));
                    let Ok(mut reopened) = reopened else {
                        return Report { failure: Some(format!("step {step}: d{at} would not open: {:?}", reopened.err())), trace };
                    };
                    if let Err(error) = settle_keys(&mut reopened) {
                        return Report { failure: Some(format!("step {step}: d{at} would not unlock: {error}")), trace };
                    }
                    trace.push(format!("{step}: d{at} restarts"));
                    devs[at].vault = Some(reopened);
                }
                80..=84 if roster_level => {
                    // Replacing the words.
                    let vault = devs[at].vault.as_mut().unwrap();
                    let held = every_words.iter().find(|held| held.matches(&vault.state.recovery).unwrap()).unwrap().clone();
                    let new = RecoveryDraft::new();
                    let rotation = vault.prepare_recovery_rotation(&new.0).unwrap();
                    let approvals = vec![signed_by(vault, &rotation.digest), words_approval(&held, &rotation.digest)];
                    match vault.rotate_recovery(rotation, approvals) {
                        Ok(()) => {
                            words = new.0.clone();
                            every_words.push(new.0.clone());
                            trace.push(format!("{step}: d{at} rotates words"));
                        }
                        Err(error) => trace.push(format!("{step}: d{at} rotate failed: {error}")),
                    }
                }
                85..=89 if roster_level && active.len() > 2 && at != other => {
                    let target = devs[other].id;
                    let vault = devs[at].vault.as_mut().unwrap();
                    if !vault.is_active(&target) {
                        continue;
                    }
                    let held = every_words.iter().find(|held| held.matches(&vault.state.recovery).unwrap()).unwrap().clone();
                    let name = vault.device_name(&target);
                    let removal = vault.prepare_removal(&name).unwrap();
                    let approvals = vec![signed_by(vault, &removal.digest), words_approval(&held, &removal.digest)];
                    match vault.remove_device(&removal, approvals) {
                        Ok(_) => {
                            trace.push(format!("{step}: d{at} removes d{other}"));
                            devs[other].removed = true;
                        }
                        Err(error) => trace.push(format!("{step}: d{at} remove failed: {error}")),
                    }
                }
                90..=94 if roster_level && active.len() < 5 => {
                    made += 1;
                    let path = dir.path().join(format!("p{made}"));
                    let vault = devs[at].vault.as_mut().unwrap();
                    let held = every_words.iter().find(|held| held.matches(&vault.state.recovery).unwrap()).unwrap().clone();
                    let approve = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&held, digest)];
                    let joined = add_with(vault, approve, &path, &format!("P{made}"));
                    trace.push(format!("{step}: d{at} adds device {}", devs.len()));
                    devs.push(Dev { id: joined.me, home: path, vault: Some(joined), removed: false });
                }
                95..=97 => {
                    let vault = devs[at].vault.as_mut().unwrap();
                    let name = format!("S{step}");
                    if vault.create_space(&name).is_ok() {
                        trace.push(format!("{step}: d{at} creates space {name}"));
                    }
                }
                _ => {}
            }
        }

        if race {
            return race_ending(devs, written, trace);
        }
        // Everyone hears everyone until nothing changes, with a person at each device.
        let active: Vec<usize> = (0..devs.len()).filter(|index| !devs[*index].removed).collect();
        for round in 0..6 {
            for from in &active {
                for to in &active {
                    if from != to {
                        let logs = devs[*from].vault.as_ref().unwrap().all_logs().unwrap();
                        if let Err(error) = take(devs[*to].vault.as_mut().unwrap(), logs) {
                            return Report { failure: Some(format!("final round {round}: a merge failed on d{to}: {error}")), trace };
                        }
                    }
                }
            }
            for index in &active {
                let vault = devs[*index].vault.as_mut().unwrap();
                vault.lock();
                vault.unlock("test").unwrap();
                vault.repair().unwrap();
            }
        }

        let removed: BTreeSet<usize> = (0..devs.len()).filter(|index| devs[*index].removed).collect();
        let head = devs[active[0]].vault.as_ref().unwrap();
        let backup = dir.path().join("backup");
        write_logs(&backup, &head.home, &head.logs_removals_kept()).unwrap();
        for index in &active {
            let vault = devs[*index].vault.as_ref().unwrap();
            let honest_stop = vault.state.problems.iter().find(|problem| {
                let dev = devs.iter().position(|dev| dev.id == problem.device);
                problem.reason != "offered an older copy of a log" && dev.is_some_and(|dev| !removed.contains(&dev))
            });
            if let Some(problem) = honest_stop {
                return Report { failure: Some(format!("d{index} holds a problem with an honest device: {problem:?}")), trace };
            }
            for (space, item, name, by) in &written {
                if removed.contains(by) {
                    continue;
                }
                if vault.secret(space, item).is_err() {
                    return Report { failure: Some(format!("d{index} cannot read {name} written by d{by}")), trace };
                }
            }
        }
        for (space, item, _, by) in &written {
            if removed.contains(by) {
                continue;
            }
            let values: Vec<_> = active.iter().map(|index| devs[*index].vault.as_ref().unwrap().secret(space, item).ok()).collect();
            if values.windows(2).any(|pair| pair[0] != pair[1]) {
                return Report { failure: Some(format!("devices disagree on an item by d{by}")), trace };
            }
        }

        // Every device is lost. Only the folder and the words are left.
        let at = dir.path().join("recovered");
        let opened = Recovery::open(&backup, &words.words());
        let Ok(opened) = opened else {
            return Report { failure: Some(format!("the words were refused: {:?}", opened.err())), trace };
        };
        if let Err(error) = opened.finish_with_passphrase("pass", Cost::FAST, &at, "Recovered") {
            return Report { failure: Some(format!("recovery failed: {error}")), trace };
        }
        let mut new = Vault::open(&at, Some("pass")).unwrap();
        new.unlock("test").unwrap();
        new.repair().unwrap();
        for (space, item, name, by) in &written {
            if removed.contains(by) {
                continue;
            }
            if new.secret(space, item).is_err() {
                return Report { failure: Some(format!("recovery cannot read {name} written by d{by}")), trace };
            }
        }
        let _ = personal;
        Report { failure: None, trace }
    }
}

mod sim_race_marker {}

#[test]
#[ignore = "simulation; run by hand with SIM_FROM and SIM_TO"]
fn sim_honest_devices() {
    let parse = |name: &str, default: u64| std::env::var(name).ok().and_then(|value| value.parse().ok()).unwrap_or(default);
    let (from, to, steps) = (parse("SIM_FROM", 1), parse("SIM_TO", 30), parse("SIM_STEPS", 60));
    let partial = std::env::var("SIM_PARTIAL").is_ok();
    let race = std::env::var("SIM_RACE").is_ok();
    let mut failed = Vec::new();
    for seed in from..to {
        let outcome = std::panic::catch_unwind(|| sim::run(seed, usize::try_from(steps).unwrap(), partial, race));
        match outcome {
            Ok(report) if report.failure.is_none() => {}
            Ok(report) => failed.push((seed, report.failure, report.trace.into_iter().rev().take(40).rev().collect::<Vec<_>>())),
            Err(_) => failed.push((seed, Some("it panicked".to_owned()), Vec::new())),
        }
    }
    assert_eq!(failed.first(), None);
}

/// Row 270/315: "a device with an approval that checks out goes first". A key that was removed, or
/// any position it once held, still checks out, so a thief can make files that outrank a real device.
#[test]
fn files_a_removed_first_device_signed_do_not_keep_a_real_device_out_of_a_folder() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let genesis_head = a.vault.state.roster_head();
    let (vault_id, genesis) = (a.vault.state.vault, a.vault.state.genesis);
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
    relock(&mut b);
    let removal = b.prepare_removal(&b.device_name(&a.vault.me)).unwrap();
    let approvals = vec![signed_by(&b, &removal.digest), signed_by(&c, &removal.digest)];
    b.remove_device(&removal, approvals).unwrap();
    c.merge_logs(b.all_logs().unwrap(), None).unwrap();

    // A real new device, recovered with the words, drops its log in the shared folder.
    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &no_settled()).unwrap();
    let n = second_device(&b.home.clone(), &words, &dir.path().join("n"), "N");
    write_logs(&backup, &n.home, &no_settled()).unwrap();

    let mut planted = 0;
    while planted < 17 {
        let p = Actor::new();
        if p.id() > n.me {
            continue;
        }
        planted += 1;
        let digest = add_digest(&vault_id, &genesis_head, &p.id(), &p.fresh.record);
        let body = Body::DeviceAdd { after: genesis_head, device: p.fresh.record.clone(), approvals: vec![signed_by(&a.vault, &digest)] };
        let entry = Chain { device: p.id(), seq: 0, prev: root(&genesis, &p.id()) }.next(now_ms() << 16, &body, &p.log);
        std::fs::write(log::path_for(&backup, &p.id()), entry.encode()).unwrap();
    }
    for _ in 0..3 {
        c.merge_logs(crate::sync::folder::read_logs(&backup).unwrap(), None).unwrap();
    }
    assert!(c.state.members.contains_key(&n.me), "a real device never gets a turn in this folder");
}

/// Row 290: chains of roster changes, with and without a side branch at each step.
fn timed_chain(steps: usize, branch: bool) -> (std::time::Duration, usize, usize) {
    use super::super::attacks::Forge;
    let (mut forge, owner) = Forge::new();
    let helper = Actor::new();
    forge.enroll(&helper, 10);
    let mut after = forge.logs[&helper.id()].last().unwrap().hash();
    for step in 0..steps {
        let clock = 20 + 2 * u64::try_from(step).unwrap();
        let device = Actor::new().fresh.record.clone();
        let digest = add_digest(&forge.vault, &after, &owner.id(), &device);
        forge.write(&owner, clock, &Body::DeviceAdd { after, device, approvals: vec![owner.approve(&digest), helper.approve(&digest)] });
        let next = forge.logs[&owner.id()].last().unwrap().hash();
        if branch {
            let side = Actor::new().fresh.record.clone();
            let digest = add_digest(&forge.vault, &after, &helper.id(), &side);
            forge.write(
                &helper,
                clock + 1,
                &Body::DeviceAdd { after, device: side, approvals: vec![owner.approve(&digest), helper.approve(&digest)] },
            );
        }
        after = next;
    }
    let bytes: usize = forge.logs.values().flatten().map(|entry| entry.encode().len()).sum();
    let started = std::time::Instant::now();
    let state = forge.state();
    (started.elapsed(), state.roster.len(), bytes)
}

/// H10b: H10 with the approvals a person really gives.
#[test]
fn an_approval_got_from_a_device_does_not_keep_the_asker_in_it_past_a_removal() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let vault_id = a.vault.state.vault;
    let personal = b.space(FIRST_SPACE).unwrap().id;

    let phone = Actor::new();
    let after = b.state.roster_head();
    let digest = add_digest(&vault_id, &after, &r.id(), &phone.fresh.record);
    let approvals = vec![r.actor.approve(&digest), signed_by(&b, &digest)];
    r.write(b.state.clock + 1, &Body::DeviceAdd { after, device: phone.fresh.record.clone(), approvals });
    b.merge_logs(r.log(), None).unwrap();

    remove_with_both(&mut a, r.id());
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    b.add(&personal, Meta::new(Kind::Env, "WRITTEN_ON_B_AFTER"), &env("v")).unwrap();

    // The person settles on B with the words, once they notice.
    b.merge_logs(a.vault.all_logs().unwrap(), Some(&a.recovery)).unwrap();
    assert!(is_removed(&b, r.id()));
}

/// H9d: the same race the other way about, the removal dated first.
#[test]
fn a_removal_dated_first_is_heard_on_the_device_that_raced_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    remove_with_both(&mut a, r.id());
    std::thread::sleep(std::time::Duration::from_millis(5));
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let _phone = add_with(&mut b, with_words, &dir.path().join("phone"), "Phone");
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    assert!(is_removed(&b, r.id()), "the removal won every tie-break and B still keeps R");
}

/// Row 271, for the log a device writes itself.
#[test]
fn one_flipped_bit_in_a_device_s_own_log_heals_from_a_peer() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, _r) = three(dir.path());
    let personal = b.space(FIRST_SPACE).unwrap().id;
    b.add(&personal, Meta::new(Kind::Env, "FIRST"), &env("v")).unwrap();
    b.add(&personal, Meta::new(Kind::Env, "SECOND"), &env("v")).unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();

    let home = b.home.clone();
    let path = log::path_for(&home, &b.me);
    drop(b);
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.len() - 200;
    bytes[at] ^= 1;
    std::fs::write(&path, &bytes).unwrap();

    let mut b = Vault::open(&home, Some("pass")).unwrap();
    b.unlock("test").unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    let wrote = b.add(&personal, Meta::new(Kind::Env, "THIRD"), &env("v"));
    assert!(wrote.is_ok());
}

#[test]
#[ignore = "one size, for a memory reading"]
fn one_size() {
    let steps: usize = std::env::var("P7_STEPS").unwrap().parse().unwrap();
    let (time, length, bytes) = timed_chain(steps, std::env::var("P7_BRANCH").is_ok());
    assert!(length > 0 && bytes > 0, "{time:?}");
}

/// H9f: the branch that raced a removal simply has more signers behind it, so nothing is tied.
#[test]
fn a_removal_is_not_lost_with_nothing_said_when_more_signers_stand_behind_a_race() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let mut c = add_with(&mut a.vault, with_words, &dir.path().join("c"), "C");
    let mut d = add_with(&mut a.vault, with_words, &dir.path().join("d"), "D");
    for _ in 0..2 {
        b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        d.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        a.vault.merge_logs(c.all_logs().unwrap(), None).unwrap();
        a.vault.merge_logs(d.all_logs().unwrap(), None).unwrap();
    }
    relock(&mut b);
    relock(&mut c);
    relock(&mut d);

    // A removes R, with its touch and the words. B and C, elsewhere, pair a phone, then a tablet.
    remove_with_both(&mut a, r.id());
    let both = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), signed_by(&c, digest)];
    let phone = add_with(&mut b, both, &dir.path().join("phone"), "Phone");
    let tablet = add_with(&mut b, with_words, &dir.path().join("tablet"), "Tablet");

    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();
    let _ = write_logs(&backup, &b.home, &no_settled());
    let opened = Recovery::open(&backup, &words.words()).unwrap();
    let at = dir.path().join("fresh");
    opened.finish_with_passphrase("pass", Cost::FAST, &at, "Fresh").unwrap();

    // D heard of the removal first, from A. It wrote and approved nothing either way.
    d.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(is_removed(&d, r.id()));
    d.merge_logs(b.all_logs().unwrap(), None).unwrap();
    drop((phone, tablet));
    assert!(is_removed(&d, r.id()), "a removal D had heard of is undone by a race it knows nothing about");
}
