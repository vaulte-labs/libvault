use super::*;
use crate::ids::BatchId;

fn own_log_len(vault: &Vault) -> usize {
    std::fs::read(log::path_for(&vault.home, &vault.me)).unwrap().len()
}

#[test]
fn a_removed_device_handed_a_new_key_writes_nothing_when_it_repairs() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let removal = a.vault.prepare_removal("B").unwrap();
    let approvals = a.recovery_approval(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
    a.vault.merge_logs(r.log(), None).unwrap();

    let (epoch, key) = newest_epoch(&a.vault);
    r.write(a.vault.state.clock + 1, &wrap_to(&a.vault, b.me, epoch, &key));
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();
    relock(&mut b);
    assert!(is_removed(&b, b.me));
    assert!(b.writing_epoch(&b.state.clean_epochs()).is_some(), "B has to hold a key that is safe to write under");

    let length = own_log_len(&b);
    b.repair().unwrap();
    assert_eq!(own_log_len(&b), length);
}

#[test]
fn a_rescue_does_not_write_over_an_edit_that_won_at_the_same_moment() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let mut k = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(k.log(), None).unwrap();
    b.merge_logs(k.log(), None).unwrap();
    let vault = a.vault.state.vault;
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    let item = a.vault.add(&space_id, Meta::new(Kind::Env, "DB_PASSWORD"), &env("first")).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();

    // The edit on the cut key comes from whichever device loses a tie on the clock.
    let words = &a.recovery;
    let (cut, winner) = if a.vault.me < b.me { (&mut a.vault, &mut b) } else { (&mut b, &mut a.vault) };
    let (epoch, epoch_key) = newest_epoch(winner);
    let (top, _) = winner.newest_space_key(&space_id).unwrap();
    r.write(cut.state.clock + 1, &space::body(vault, epoch, &epoch_key, space_id, top.after(r.id()), FIRST_SPACE, &Key::generate()).unwrap());
    cut.merge_logs(r.log(), None).unwrap();

    // Both devices hear the same future clock, so their next entries tie.
    k.write((now_ms() + 60 * 60 * 1000) << 16, &wrap_to(winner, k.id(), epoch, &epoch_key));
    cut.merge_logs(k.log(), None).unwrap();
    winner.merge_logs(k.log(), None).unwrap();
    let meta = Meta::new(Kind::Env, "DB_PASSWORD");
    cut.replace(&space_id, &item, &meta, &env("cut")).unwrap();
    winner.replace(&space_id, &item, &meta, &env("counts")).unwrap();
    let clock_of = |vault: &Vault| vault.state.items[&(space_id, item)].last().unwrap().clock;
    assert_eq!(clock_of(cut), clock_of(winner), "the two edits have to tie");

    let removal = winner.prepare_removal(&winner.device_name(&r.id())).unwrap();
    let approvals = vec![words_approval(words, &removal.digest)];
    winner.remove_device(&removal, approvals).unwrap();
    cut.merge_logs(winner.all_logs().unwrap(), None).unwrap();
    relock(cut);
    cut.repair().unwrap();
    assert_eq!(cut.secret(&space_id, &item).unwrap(), env("counts"));
}

#[test]
fn a_rescue_brings_back_what_this_device_wrote_not_what_a_removed_device_wrote_over_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let vault = a.vault.state.vault;
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    let (epoch, epoch_key) = newest_epoch(&a.vault);
    let (top, _) = a.vault.newest_space_key(&space_id).unwrap();
    let (version, space_key) = (top.after(r.id()), Key::generate());
    r.write(b.state.clock + 1, &space::body(vault, epoch, &epoch_key, space_id, version, FIRST_SPACE, &space_key).unwrap());
    b.merge_logs(r.log(), None).unwrap();
    let meta = Meta::new(Kind::Env, "ONLY_COPY_ON_B");
    let item = b.add(&space_id, meta.clone(), &env("honest-work")).unwrap();

    let planted = b.put_body(&(version, space_key), space_id, item, BatchId::random(), &meta, &env("planted")).unwrap();
    r.write(b.state.clock + 1, &planted);
    b.merge_logs(r.log(), None).unwrap();

    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    assert_eq!(b.secret(&space_id, &item).unwrap(), env("honest-work"));
}

#[test]
fn an_edit_that_won_at_the_same_moment_under_a_cut_key_is_given_back() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let mut k = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(k.log(), None).unwrap();
    b.merge_logs(k.log(), None).unwrap();
    let vault = a.vault.state.vault;
    let space_id = a.vault.space(FIRST_SPACE).unwrap().id;
    let item = a.vault.add(&space_id, Meta::new(Kind::Env, "DB_PASSWORD"), &env("first")).unwrap();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();

    // The edit on the cut key comes from whichever device wins a tie on the clock.
    let words = &a.recovery;
    let (cut, other) = if a.vault.me > b.me { (&mut a.vault, &mut b) } else { (&mut b, &mut a.vault) };
    let (epoch, epoch_key) = newest_epoch(other);
    let (top, _) = other.newest_space_key(&space_id).unwrap();
    r.write(cut.state.clock + 1, &space::body(vault, epoch, &epoch_key, space_id, top.after(r.id()), FIRST_SPACE, &Key::generate()).unwrap());
    cut.merge_logs(r.log(), None).unwrap();

    k.write((now_ms() + 60 * 60 * 1000) << 16, &wrap_to(other, k.id(), epoch, &epoch_key));
    cut.merge_logs(k.log(), None).unwrap();
    other.merge_logs(k.log(), None).unwrap();
    let meta = Meta::new(Kind::Env, "DB_PASSWORD");
    cut.replace(&space_id, &item, &meta, &env("seen")).unwrap();
    other.replace(&space_id, &item, &meta, &env("lost the tie")).unwrap();
    let clock_of = |vault: &Vault| vault.state.items[&(space_id, item)].last().unwrap().clock;
    assert_eq!(clock_of(cut), clock_of(other), "the two edits have to tie");

    let removal = other.prepare_removal(&other.device_name(&r.id())).unwrap();
    let approvals = vec![words_approval(words, &removal.digest)];
    other.remove_device(&removal, approvals).unwrap();
    cut.merge_logs(other.all_logs().unwrap(), None).unwrap();
    relock(cut);
    cut.repair().unwrap();
    assert_eq!(cut.secret(&space_id, &item).unwrap(), env("seen"));
    other.merge_logs(cut.all_logs().unwrap(), None).unwrap();
    assert_eq!(other.secret(&space_id, &item).unwrap(), env("seen"));
}
