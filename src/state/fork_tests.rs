use super::*;

#[test]
fn a_copy_holding_what_a_removal_kept_that_does_not_replay_whole_replaces_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let (epoch, _) = newest_epoch(&a.vault);
    let audit = |sealed| Body::Audit { epoch, sealed: vec![sealed] };
    r.write(a.vault.state.clock + 1, &audit(1));
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();

    // R signs two histories from here, one for A and one for B, and A removes it keeping its own.
    let agreed = r.entries.clone();
    r.write(a.vault.state.clock + 1, &audit(2));
    a.vault.merge_logs(r.log(), None).unwrap();
    r.entries = agreed;
    r.write(b.state.clock + 1, &audit(3));
    b.merge_logs(r.log(), None).unwrap();
    let held = std::fs::read(log::path_for(&b.home, &r.id())).unwrap();
    remove_r(&mut a, &r);

    // A folder holds the entry the removal names, behind one that is not what R signed.
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();
    let path = log::path_for(&backup, &r.id());
    let mut entries = log::parse(&std::fs::read(&path).unwrap()).entries;
    entries[1].signature[0] ^= 1;
    std::fs::write(&path, entries.iter().flat_map(Entry::encode).collect::<Vec<u8>>()).unwrap();

    b.merge_logs(crate::sync::folder::read_logs(&backup).unwrap(), None).unwrap();
    assert!(is_removed(&b, r.id()));
    assert_eq!(std::fs::read(log::path_for(&b.home, &r.id())).unwrap(), held, "a copy that does not replay replaced B's");
}

#[test]
fn an_addition_a_device_was_only_told_of_gives_way_to_a_rival_more_of_the_vault_signed() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let recovery = a.recovery.clone();
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    relock(&mut a.vault);

    let told = Bad::enroll(&b, &recovery);
    b.merge_logs(told.log(), None).unwrap();
    assert!(b.state.members.contains_key(&told.id()));
    let both = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&recovery, digest)];
    let y = add_with(&mut a.vault, both, &dir.path().join("y"), "Y");

    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(b.state.members.contains_key(&y.me), "B kept what it was told over what A and the words signed");
    assert!(!b.state.members.contains_key(&told.id()));
    assert_eq!(b.state.roster, a.vault.state.roster);
}

#[test]
fn a_change_approved_against_an_older_roster_is_refused_before_it_is_written() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let removal = a.vault.prepare_removal(&a.vault.device_name(&r.id())).unwrap();
    let approvals = a.both_approvals(&removal.digest);
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let _phone = add_with(&mut b, with_words, &dir.path().join("phone"), "Phone");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    relock(&mut a.vault);

    let own = log::path_for(&a.vault.home, &a.vault.me);
    let length = std::fs::read(&own).unwrap().len();
    assert!(matches!(a.vault.remove_device(&removal, approvals), Err(Error::NotApproved(_))));
    assert_eq!(std::fs::read(&own).unwrap().len(), length);
}

#[test]
fn an_addition_a_device_approved_stays_against_a_rival_more_of_the_vault_signed() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let approved = Actor::new();
    let after = b.state.roster_head();
    let digest = add_digest(&b.state.vault, &after, &approved.id(), &approved.fresh.record);
    let approvals = vec![signed_by(&b, &digest), words_approval(&words, &digest)];
    let add = Body::DeviceAdd { after, device: approved.fresh.record.clone(), approvals };
    let entry = Chain { device: approved.id(), seq: 0, prev: root(&b.state.genesis, &approved.id()) }.next(b.state.clock + 1, &add, &approved.log);
    b.merge_logs(Logs::from([(approved.id(), entry.encode())]), None).unwrap();
    assert!(b.state.members.contains_key(&approved.id()));

    let three_of_us = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), r.actor.approve(digest), words_approval(&words, digest)];
    let rival = add_with(&mut a.vault, three_of_us, &dir.path().join("rival"), "Y");
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(b.state.members.contains_key(&approved.id()), "B gave up what it approved");
    assert!(!b.state.members.contains_key(&rival.me));
}

#[test]
fn a_refusal_gives_way_once_that_log_is_taken() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let words = a.recovery.words().to_string();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let mut b = second_device(&a.vault.home.clone(), &words, &dir.path().join("b"), "B");
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    b.add(&personal, Meta::new(Kind::Env, "FIRST"), &env("v")).unwrap();
    let older = b.all_logs().unwrap();
    b.add(&personal, Meta::new(Kind::Env, "SECOND"), &env("v")).unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();

    a.vault.merge_logs(older, None).unwrap();
    assert!(a.vault.problems().any(|problem| problem.device == b.me), "an older copy is reported");
    b.add(&personal, Meta::new(Kind::Env, "THIRD"), &env("v")).unwrap();
    a.vault.merge_logs(b.all_logs().unwrap(), None).unwrap();
    assert!(!a.vault.problems().any(|problem| problem.device == b.me), "{:?}", a.vault.problems().collect::<Vec<_>>());
}
