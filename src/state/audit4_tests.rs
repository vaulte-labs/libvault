//! The fourth audit, as its author wrote it: each asserts a promise. Mostly what `rescue` has to
//! get right, and what one device gone bad can do to it.

use super::*;

/// R writes `body` as its next entry, hands back that log, and rewinds, so it can sign another.
fn fork_of(r: &mut Bad, clock: u64, body: &Body) -> Logs {
    let base = r.entries.clone();
    r.write(clock, body);
    let log = r.log();
    r.entries = base;
    log
}

/// R rotates, wrapping to `to` and the words.
fn r_rotates(r: &mut Bad, to: &Vault) -> (Generation, Key) {
    let vault = to.state.vault;
    let (epoch, epoch_key) = newest_epoch(to);
    let recovery = to.state.recovery.clone();
    let (next, next_key) = (epoch.after(r.id()), Key::generate());
    let clock = to.state.clock;
    let sealed = crypto::seal(&next_key, &Binding::EpochLink { vault, epoch: next }, epoch_key.as_bytes());
    r.write(
        clock + 1,
        &Body::EpochLink {
            epoch: next,
            previous: epoch,
            commitment: epoch_commitment(&vault, next, &next_key),
            roster: to.state.roster_head(),
            sealed,
        },
    );
    r.write(clock + 2, &wrap_to(to, to.me, next, &next_key));
    let binding = Binding::Epoch { vault, epoch: next, recipient: Recipient::Recovery };
    r.write(
        clock + 3,
        &Body::Wrap { epoch: next, sealed: Sealed::Recovery(recovery.id(), crypto::wrap(recovery.wrap_to(), &binding, &next_key).unwrap()) },
    );
    (next, next_key)
}

#[test]
fn a_removal_keeps_the_key_to_what_b_built_on_the_history_it_refused() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    let (epoch, epoch_key) = newest_epoch(&a.vault);
    let (top, _) = a.vault.newest_space_key(&space_id).unwrap();

    // R signs two continuations of its log. B gets a new version of the space, A an audit note.
    let version = space::body(vault, epoch, &epoch_key, space_id, top.after(r.id()), FIRST_SPACE, &Key::generate()).unwrap();
    let to_b = fork_of(&mut r, b.state.clock + 1, &version);
    r.write(a.vault.state.clock + 1, &Body::Audit { epoch, sealed: vec![1] });
    b.merge_logs(to_b, None).unwrap();
    a.vault.merge_logs(r.log(), None).unwrap();

    let item = b.add(&space_id, Meta::new(Kind::Env, "ONLY_COPY_ON_B"), &env("honest-work")).unwrap();
    assert_eq!(b.secret(&space_id, &item).unwrap(), env("honest-work"));

    // The owner sees the fork and removes R on A, keeping A's copy. B hears, as any device would.
    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    assert_eq!(b.secret(&space_id, &item).ok(), Some(env("honest-work")), "the only copy of this secret is unreadable for good");
}

#[test]
fn a_space_rescued_under_its_old_id_does_not_stop_the_device_in_the_replay_recovery_reads() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    r_rotates(&mut r, &b);
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    let work = b.create_space("Work").unwrap();
    let item = b.add(&work.id, Meta::new(Kind::Env, "ONLY_ON_B"), &env("the only copy")).unwrap();

    // A, which never heard that tail, removes R. B hears and puts things right.
    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    assert_eq!(b.secret(&work.id, &item).unwrap(), env("the only copy"), "rescue itself worked");

    let whole = State::with_nothing_cut(&crate::store::parse_all(&crate::store::read_logs(&b.home).unwrap()), &b.anchor()).unwrap();
    assert!(!whole.problems.iter().any(|problem| problem.device == b.me), "B's own log stops in the replay recovery reads");
}

#[test]
fn new_words_recover_a_vault_after_a_rescue() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    r_rotates(&mut r, &b);
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    let work = b.create_space("Work").unwrap();
    let item = b.add(&work.id, Meta::new(Kind::Env, "ONLY_ON_B"), &env("the only copy")).unwrap();
    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();

    // Later, on B, the person replaces the words, and writes something more.
    let new_words = RecoveryDraft::new();
    let rotation = b.prepare_recovery_rotation(&new_words.0).unwrap();
    let approvals = vec![signed_by(&b, &rotation.digest), words_approval(&a.recovery, &rotation.digest)];
    b.rotate_recovery(rotation, approvals).unwrap();
    let later = b.add(&work.id, Meta::new(Kind::Env, "AFTER_NEW_WORDS"), &env("written later")).unwrap();

    // Every device is lost. The folder holds everything, and the person holds the new words.
    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &b.logs_removals_kept()).unwrap();
    let words = new_words.words().to_string();
    let at = dir.path().join("new");
    let opened = Recovery::open(&backup, &words).unwrap();
    let finished = opened.finish_with_passphrase("pass", Cost::FAST, &at, "New");
    finished.unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();
    assert_eq!(new.secret(&work.id, &item).ok(), Some(env("the only copy")));
    assert_eq!(new.secret(&work.id, &later).ok(), Some(env("written later")));
}

#[test]
fn the_same_words_recover_what_was_written_after_a_later_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    r_rotates(&mut r, &b);
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    let work = b.create_space("Work").unwrap();
    b.add(&work.id, Meta::new(Kind::Env, "ONLY_ON_B"), &env("the only copy")).unwrap();
    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();

    // B removes A, which it believes lost, with the words. That rotates, and B goes on working.
    let removal = b.prepare_removal(&b.device_name(&a.vault.me)).unwrap();
    let approvals = vec![words_approval(&a.recovery, &removal.digest)];
    b.remove_device(&removal, approvals).unwrap();
    let later = b.add(&personal, Meta::new(Kind::Env, "AFTER_THE_LAST_ROTATION"), &env("written later")).unwrap();
    assert_eq!(b.secret(&personal, &later).unwrap(), env("written later"));

    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &b.logs_removals_kept()).unwrap();
    let words = a.recovery.words().to_string();
    let at = dir.path().join("new");
    let opened = Recovery::open(&backup, &words).unwrap();
    opened.finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();
    assert_eq!(new.secret(&personal, &later).ok(), Some(env("written later")), "the newest work did not come back through the words");
}

/// The state P2 leaves: B has rescued a space, so its log stops in every uncut replay.
fn after_a_rescue(dir: &Path) -> (Fixture, Vault, Bad) {
    let (mut a, mut b, mut r) = three(dir);
    r_rotates(&mut r, &b);
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    let work = b.create_space("Work").unwrap();
    b.add(&work.id, Meta::new(Kind::Env, "ONLY_ON_B"), &env("the only copy")).unwrap();
    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    (a, b, r)
}

#[test]
fn what_a_device_wrote_before_its_removal_is_not_lost_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let (epoch, epoch_key) = newest_epoch(&a.vault);

    // R makes a space, and B, which is all that hears, puts a secret in it.
    let work = SpaceId::random();
    r.write(b.state.clock + 1, &space::body(vault, epoch, &epoch_key, work, Generation::first(r.id()), "Work", &Key::generate()).unwrap());
    b.merge_logs(r.log(), None).unwrap();
    let item = b.add(&work, Meta::new(Kind::Env, "B_WROTE_THIS"), &env("honest-work")).unwrap();
    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &no_settled()).unwrap();

    // A has B's entries but not R's tail. The owner removes R, then B, which has also gone.
    remove_r(&mut a, &r);
    let b_only: Logs = b.all_logs().unwrap().into_iter().filter(|(device, _)| *device == b.me).collect();
    a.vault.merge_logs(b_only, None).unwrap();
    let removal = a.vault.prepare_removal(&a.vault.device_name(&b.me)).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
    write_logs(&backup, &a.vault.home, &a.vault.logs_removals_kept()).unwrap();

    // Everything is in the folder: B's ciphertext, R's tail with the space key, a generation the words open.
    let at = dir.path().join("new");
    Recovery::open(&backup, &a.recovery.words()).unwrap().finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();
    assert_eq!(new.secret(&work, &item).ok(), Some(env("honest-work")), "both halves are in the folder and the secret is gone");
}

#[test]
fn a_device_record_with_a_key_nobody_can_wrap_to_does_not_stop_every_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());

    // A joiner, or a sock puppet a person approved, sends a record with a P-256 key that is no point.
    let mut actor = Actor::new();
    actor.fresh.record.keys.agreement = [0; 65];
    let after = a.vault.state.roster_head();
    let digest = add_digest(&a.vault.state.vault, &after, &actor.id(), &actor.fresh.record);
    let approvals = a.recovery_approval(&digest);
    let record = actor.fresh.record.clone();
    let mut m = Bad { actor, genesis: a.vault.state.genesis, entries: Vec::new() };
    m.write(a.vault.state.clock + 1, &Body::DeviceAdd { after, device: record, approvals });
    a.vault.merge_logs(m.log(), None).unwrap();
    b.merge_logs(m.log(), None).unwrap();

    assert!(!a.vault.state.members.contains_key(&m.id()), "nothing can be wrapped to it, so nothing could ever rotate past it");
    a.vault.repair().unwrap();
    let removal = a.vault.prepare_removal(&a.vault.device_name(&r.id())).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
}

#[test]
fn one_junk_orphan_does_not_cost_a_device_its_newest_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, _r) = after_a_rescue(dir.path());
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;

    // Level everyone, and enroll M, a hostile device that stays in the vault.
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    let mut m = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(m.log(), None).unwrap();
    b.merge_logs(m.log(), None).unwrap();

    // B rotates as part of an ordinary change, and goes on working. This is what the uncut replay misses.
    let new_words = RecoveryDraft::new();
    let rotation = b.prepare_recovery_rotation(&new_words.0).unwrap();
    let approvals = vec![signed_by(&b, &rotation.digest), words_approval(&a.recovery, &rotation.digest)];
    b.rotate_recovery(rotation, approvals).unwrap();
    let later = b.add(&personal, Meta::new(Kind::Env, "AFTER_ROTATION"), &env("written later")).unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    relock(&mut a.vault);

    // M writes one put under a version that exists nowhere.
    let bogus = Generation::first(m.id());
    let junk = Body::ItemPut { space: personal, item: ItemId::random(), version: bogus, batch: BatchId::random(), meta: vec![1], secret: vec![2] };
    m.write(a.vault.state.clock + 1, &junk);
    a.vault.merge_logs(m.log(), None).unwrap();
    b.merge_logs(m.log(), None).unwrap();

    relock(&mut a.vault);
    relock(&mut b);
    let (reads_a, reads_b) = (a.vault.secret(&personal, &later).is_ok(), b.secret(&personal, &later).is_ok());
    assert!(reads_a && reads_b, "one entry from one device took the vault's newest keys from every device");
}

#[test]
fn removing_the_junk_writer_does_not_brick_the_device_doing_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, _r) = after_a_rescue(dir.path());
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    let mut m = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(m.log(), None).unwrap();
    b.merge_logs(m.log(), None).unwrap();
    let new_words = RecoveryDraft::new();
    let rotation = b.prepare_recovery_rotation(&new_words.0).unwrap();
    let approvals = vec![signed_by(&b, &rotation.digest), words_approval(&a.recovery, &rotation.digest)];
    b.rotate_recovery(rotation, approvals).unwrap();

    let junk = Body::ItemPut {
        space: personal,
        item: ItemId::random(),
        version: Generation::first(m.id()),
        batch: BatchId::random(),
        meta: vec![1],
        secret: vec![2],
    };
    m.write(b.state.clock + 1, &junk);
    b.merge_logs(m.log(), None).unwrap();
    relock(&mut b);

    // B does the right thing: remove M, with the new words.
    let removal = b.prepare_removal(&b.device_name(&m.id())).unwrap();
    let approvals = vec![words_approval(&new_words.0, &removal.digest)];
    let removed = b.remove_device(&removal, approvals);
    drop(b);
    let reopened = Vault::open(&dir.path().join("b"), Some("pass")).unwrap();
    let mut reopened = reopened;
    reopened.unlock("test").unwrap();
    a.vault.merge_logs(reopened.all_logs().unwrap(), None).unwrap();
    assert!(removed.is_ok());
}

/// Wraps to `to` that open nothing, naming `epoch`.
fn junk_wraps(r: &mut Bad, to: &Vault, epoch: Generation, count: usize) {
    for _ in 0..count {
        let body = wrap_to(to, to.me, epoch, &Key::generate());
        r.write(to.state.clock + 1, &body);
    }
}

/// A generation that links to nothing real, wrapped to `to` if `key` is given.
fn r_generation(r: &mut Bad, to: &Vault, epoch: Generation, previous: Generation, key: &Key) {
    let vault = to.state.vault;
    let body =
        Body::EpochLink { epoch, previous, commitment: epoch_commitment(&vault, epoch, key), roster: to.state.roster_head(), sealed: vec![0; 80] };
    r.write(to.state.clock + 1, &body);
}

#[test]
fn junk_a_removed_device_left_does_not_push_out_the_wrap_b_needs() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let (x1, _) = r_rotates(&mut r, &b);
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    let work = b.create_space("Work").unwrap();
    let item = b.add(&work.id, Meta::new(Kind::Env, "ONLY_ON_B"), &env("the only copy")).unwrap();

    // R leaves junk under a newer generation of its own. A is what cannot be reached by any link.
    let x2 = x1.after(r.id());
    r_generation(&mut r, &b, x2, x1, &Key::generate());
    junk_wraps(&mut r, &b, x2, 64);
    b.merge_logs(r.log(), None).unwrap();

    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    assert_eq!(b.secret(&work.id, &item).ok(), Some(env("the only copy")), "the wrap is in B's replay and is never tried");
}

#[test]
fn one_bad_device_alone_cannot_brick_an_honest_one() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let (x1, _) = r_rotates(&mut r, &b);
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    let first = b.create_space("First").unwrap();
    b.add(&first.id, Meta::new(Kind::Env, "STRANDED"), &env("v")).unwrap();

    // A second generation B can open, not linked to the first, then junk to push the first out.
    let (x2, k2) = (x1.after(r.id()), Key::generate());
    r_generation(&mut r, &b, x2, x1, &k2);
    let wrap = wrap_to(&b, b.me, x2, &k2);
    r.write(b.state.clock + 1, &wrap);
    let x3 = x2.after(r.id());
    r_generation(&mut r, &b, x3, x2, &Key::generate());
    junk_wraps(&mut r, &b, x3, 63);
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    let second = b.create_space("Second").unwrap();
    b.add(&second.id, Meta::new(Kind::Env, "RESCUED"), &env("v")).unwrap();

    // R is removed. It writes nothing more. A takes no further part.
    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();

    // Some ordinary rotation on B, and more work. The next unlock cannot reach any of it.
    let new_words = RecoveryDraft::new();
    let rotation = b.prepare_recovery_rotation(&new_words.0).unwrap();
    let approvals = vec![signed_by(&b, &rotation.digest), words_approval(&a.recovery, &rotation.digest)];
    b.rotate_recovery(rotation, approvals).unwrap();
    b.add(&personal, Meta::new(Kind::Env, "LATER"), &env("v")).unwrap();
    relock(&mut b);

    let removal = b.prepare_removal(&b.device_name(&a.vault.me)).unwrap();
    let approvals = vec![words_approval(&new_words.0, &removal.digest)];
    let removed = b.remove_device(&removal, approvals);
    assert!(removed.is_ok(), "one bad device, removed, and B can never write again");
}

#[test]
#[ignore = "writes more than 1 GiB"]
fn a_log_grown_past_what_a_folder_reads_does_not_turn_the_owner_s_words_away() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let mut m = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(m.log(), None).unwrap();
    let (version, _) = a.vault.newest_space_key(&personal).unwrap();

    // A device gone bad sends 600 MiB, then 600 MiB more. Each is well inside what one sync allows.
    let chunk = crate::store::log::MAX_BODY - 200;
    for _ in 0..2 {
        for _ in 0..38 {
            let body =
                Body::ItemPut { space: personal, item: ItemId::random(), version, batch: BatchId::random(), meta: vec![1; chunk], secret: vec![] };
            m.write(a.vault.state.clock + 1, &body);
        }
        a.vault.merge_logs(m.log(), None).unwrap();
    }
    assert!(a.vault.state.heads[&m.id()].seq < 40, "the log was taken past what a folder keeps");
    assert!(a.vault.problems().any(|problem| problem.device == m.id()), "and nothing said so");
    m.entries.clear();

    // The owner removes M and replaces the words, the right response to a device gone bad.
    let removal = a.vault.prepare_removal(&a.vault.device_name(&m.id())).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
    let new_words = RecoveryDraft::new();
    let rotation = a.vault.prepare_recovery_rotation(&new_words.0).unwrap();
    let approvals = a.both_approvals(&rotation.digest);
    a.vault.rotate_recovery(rotation, approvals).unwrap();
    let item = a.vault.add(&personal, Meta::new(Kind::Env, "KEPT"), &env("v")).unwrap();

    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &a.vault.logs_removals_kept()).unwrap();
    let read = crate::sync::folder::read_logs(&backup).unwrap();
    drop(read);

    let opened = Recovery::open(&backup, &new_words.words());
    let at = dir.path().join("new");
    opened.unwrap().finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    assert_eq!(new.secret(&personal, &item).ok(), Some(env("v")));
}

#[test]
#[ignore = "timing"]
fn how_replay_grows_with_a_chain_of_roster_changes() {
    use super::super::attacks::Forge;
    for steps in [250_usize, 500, 1000, 2000] {
        let (mut forge, owner) = Forge::new();
        let helper = Actor::new();
        forge.enroll(&helper, 10);
        let mut after = forge.logs[&helper.id()].last().unwrap().hash();
        for step in 0..steps {
            let device = Actor::new().fresh.record.clone();
            let digest = add_digest(&forge.vault, &after, &owner.id(), &device);
            forge.write(
                &owner,
                20 + u64::try_from(step).unwrap(),
                &Body::DeviceAdd { after, device, approvals: vec![owner.approve(&digest), helper.approve(&digest)] },
            );
            after = forge.logs[&owner.id()].last().unwrap().hash();
        }
        let _bytes: usize = forge.logs.values().flatten().map(|entry| entry.encode().len()).sum();
    }
}

#[test]
fn an_export_from_a_removed_device_holds_what_it_wrote_under_a_generation_it_made_after_the_cut() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let vault = a.vault.state.vault;
    let q = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(q.log(), None).unwrap();
    b.merge_logs(q.log(), None).unwrap();

    // A departure with no new generation behind it, so every device has to rotate on its own.
    let head = a.vault.state.roster_head();
    let (kept, last) = a.vault.held_log(&q.id());
    let digest = revoke_digest(&vault, &head, &r.id(), &q.id(), kept, &last);
    let approvals = a.recovery_approval(&digest);
    r.write(a.vault.state.clock + 1, &Body::DeviceRevoke { after: head, device: q.id(), entries_kept: kept, last_kept: last, approvals });
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    let item = b.add(&personal, Meta::new(Kind::Env, "WRITTEN_ON_B"), &env("only on b")).unwrap();
    assert_eq!(b.secret(&personal, &item).unwrap(), env("only on b"));

    // B is removed while out of touch. What it wrote there is cut, and it takes it out by export.
    relock(&mut a.vault);
    let name = a.vault.device_name(&b.me);
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    let path = dir.path().join("out.json");
    b.export_plaintext(&path).unwrap();
    let out = std::fs::read_to_string(&path).unwrap();
    assert!(out.contains("WRITTEN_ON_B"), "export finished with no error and left out what this device wrote");
}

#[test]
fn a_new_machine_is_told_when_a_copy_holds_more_than_it_took() {
    let dir = tempfile::tempdir().unwrap();
    let (a, b, mut r) = three(dir.path());
    let (epoch, _) = newest_epoch(&b);
    let ahead = (now_ms() + 3 * 24 * 60 * 60 * 1000) << 16;
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();
    r.write(ahead, &Body::Audit { epoch, sealed: vec![1] });
    std::fs::write(log::path_for(&backup, &r.id()), r.bytes()).unwrap();
    let opened = Recovery::open(&backup, &a.recovery.words()).unwrap();
    assert!(!opened.problems().is_empty(), "an entry was dropped from this copy and nobody is told");
}

#[test]
fn a_generation_re_issued_after_a_cut_does_not_stop_the_device_either() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    r_rotates(&mut r, &b);
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);

    // B replaces the words, on top of a generation only it has heard of. No space, no item.
    let second = RecoveryDraft::new();
    let rotation = b.prepare_recovery_rotation(&second.0).unwrap();
    let approvals = vec![signed_by(&b, &rotation.digest), words_approval(&a.recovery, &rotation.digest)];
    b.rotate_recovery(rotation, approvals).unwrap();

    // A hears B but not R's tail, and removes R. Then B replaces the words again.
    let only_b: Logs = b.all_logs().unwrap().into_iter().filter(|(device, _)| *device == b.me).collect();
    a.vault.merge_logs(only_b, None).unwrap();
    relock(&mut a.vault);
    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = vec![words_approval(&second.0, &removal.digest)];
    a.vault.remove_device(&removal, approvals).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    let third = RecoveryDraft::new();
    let rotation = b.prepare_recovery_rotation(&third.0).unwrap();
    let approvals = vec![signed_by(&b, &rotation.digest), words_approval(&second.0, &rotation.digest)];
    b.rotate_recovery(rotation, approvals).unwrap();
    let personal = b.space(FIRST_SPACE).unwrap().id;
    let later = b.add(&personal, Meta::new(Kind::Env, "LATER"), &env("written later")).unwrap();

    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &b.logs_removals_kept()).unwrap();
    let at = dir.path().join("new");
    let opened = Recovery::open(&backup, &third.words()).unwrap();
    let finished = opened.finish_with_passphrase("pass", Cost::FAST, &at, "New");
    finished.unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    assert_eq!(new.secret(&personal, &later).ok(), Some(env("written later")));
}

#[test]
fn one_flipped_bit_in_a_copy_of_a_peer_s_log_heals_from_that_peer() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, _r) = three(dir.path());
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let first = a.vault.add(&personal, Meta::new(Kind::Env, "FIRST"), &env("v")).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();

    // A bit rots in B's copy of A's log, inside the body of its last entry.
    let path = log::path_for(&b.home, &a.vault.me);
    let mut bytes = std::fs::read(&path).unwrap();
    let at = bytes.len() - 200;
    bytes[at] ^= 1;
    std::fs::write(&path, &bytes).unwrap();
    drop(b);
    let mut b = Vault::open(&dir.path().join("b"), Some("pass")).unwrap();
    b.unlock("test").unwrap();

    let second = a.vault.add(&personal, Meta::new(Kind::Env, "SECOND"), &env("v")).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(b.secret(&personal, &first).is_ok() && b.secret(&personal, &second).is_ok(), "A's whole log is on offer, and B refuses it for good");
}

#[test]
#[ignore = "timing"]
fn one_long_chain() {
    use super::super::attacks::Forge;
    let (mut forge, owner) = Forge::new();
    let helper = Actor::new();
    forge.enroll(&helper, 10);
    let mut after = forge.logs[&helper.id()].last().unwrap().hash();
    let steps = 8000;
    for step in 0..steps {
        let device = Actor::new().fresh.record.clone();
        let digest = add_digest(&forge.vault, &after, &owner.id(), &device);
        forge.write(
            &owner,
            20 + u64::try_from(step).unwrap(),
            &Body::DeviceAdd { after, device, approvals: vec![owner.approve(&digest), helper.approve(&digest)] },
        );
        after = forge.logs[&owner.id()].last().unwrap().hash();
    }
    let _bytes: usize = forge.logs.values().flatten().map(|entry| entry.encode().len()).sum();
}
