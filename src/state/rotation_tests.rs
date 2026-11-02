//! Rotations and repair after a race, each from what a device or the words can open afterwards.

use super::*;

fn replace_words(vault: &mut Vault, words: &RecoveryKey) -> RecoveryDraft {
    let new_words = RecoveryDraft::new();
    let rotation = vault.prepare_recovery_rotation(&new_words.0).unwrap();
    let approvals = vec![signed_by(vault, &rotation.digest), words_approval(words, &rotation.digest)];
    vault.rotate_recovery(rotation, approvals).unwrap();
    new_words
}

#[test]
fn new_words_open_what_was_written_under_either_side_of_a_race() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let mut r = Bad::enroll(&a.vault, &a.recovery);
    a.vault.merge_logs(r.log(), None).unwrap();
    let first = Generation::first(a.vault.me);
    let first_key = a.vault.keys.as_ref().unwrap().epochs[&first].clone();

    let second_words = replace_words(&mut a.vault, &a.recovery.clone());
    let from_a = a.vault.add(&personal, Meta::new(Kind::Env, "FROM_A"), &env("a")).unwrap();

    // R, which had not heard, rotates from the first generation too, and makes a space under it.
    let vault = a.vault.state.vault;
    let (next, next_key) = (first.after(r.id()), Key::generate());
    let theirs = SpaceId::random();
    let clock = a.vault.state.clock;
    r.write(
        clock + 1,
        &Body::EpochLink {
            epoch: next,
            previous: first,
            commitment: epoch_commitment(&vault, next, &next_key),
            roster: a.vault.state.roster_head(),
            sealed: crypto::seal(&next_key, &Binding::EpochLink { vault, epoch: next }, first_key.as_bytes()),
        },
    );
    r.write(clock + 2, &wrap_to(&a.vault, a.vault.me, next, &next_key));
    r.write(clock + 3, &space::body(vault, next, &next_key, theirs, Generation::first(r.id()), "Theirs", &Key::generate()).unwrap());
    a.vault.merge_logs(r.log(), None).unwrap();
    relock(&mut a.vault);
    let from_r = a.vault.add(&theirs, Meta::new(Kind::Env, "FROM_R"), &env("r")).unwrap();

    let third_words = replace_words(&mut a.vault, &second_words.0);
    let restored = second_device(&a.vault.home.clone(), &third_words.words(), &dir.path().join("restored"), "Restored");
    assert_eq!(restored.secret(&personal, &from_a).unwrap(), env("a"));
    assert_eq!(restored.secret(&theirs, &from_r).unwrap(), env("r"));
}

/// A removes R while B and C, elsewhere, pair a phone and a tablet. More stand behind B's side, so
/// on B the removal lost and what it made is set apart. A believes R is gone and writes a secret.
struct Raced {
    dir: tempfile::TempDir,
    b: Vault,
    r: Bad,
    words: RecoveryKey,
    personal: SpaceId,
    before: ItemId,
    after_removal: ItemId,
}

fn raced() -> Raced {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let before = a.vault.add(&personal, Meta::new(Kind::Env, "BEFORE"), &env("before")).unwrap();
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let mut c = add_with(&mut a.vault, with_words, &dir.path().join("c"), "C");
    for _ in 0..2 {
        b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        a.vault.merge_logs(c.all_logs().unwrap(), None).unwrap();
    }
    relock(&mut b);
    relock(&mut c);

    remove_r(&mut a, &r);
    let after_removal = a.vault.add(&personal, Meta::new(Kind::Env, "AFTER_R_WAS_REMOVED"), &env("A believes R cannot read this")).unwrap();
    let both = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), signed_by(&c, digest)];
    let _phone = add_with(&mut b, both, &dir.path().join("phone"), "Phone");
    let _tablet = add_with(&mut b, with_words, &dir.path().join("tablet"), "Tablet");
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    assert!(!is_removed(&b, r.id()) && is_removed(&a.vault, r.id()));
    Raced { dir, b, r, words, personal, before, after_removal }
}

#[test]
fn a_rotation_where_a_removal_lost_keeps_what_the_remover_wrote_from_the_removed_device() {
    let mut raced = raced();
    replace_words(&mut raced.b, &raced.words);
    let r = joined(&raced.b, &raced.r.actor.device, &raced.r.actor.fresh, &raced.dir.path().join("r"));
    assert_eq!(r.secret(&raced.personal, &raced.before).unwrap(), env("before"));
    assert!(r.secret(&raced.personal, &raced.after_removal).is_err(), "R reads what A wrote after removing it");
}

#[test]
fn a_device_with_no_keys_yet_is_given_the_newest_clean_generation_after_a_race() {
    let mut raced = raced();
    let x = Bad::enroll(&raced.b, &raced.words);
    raced.b.merge_logs(x.log(), None).unwrap();
    raced.b.repair().unwrap();
    let x = joined(&raced.b, &x.actor.device, &x.actor.fresh, &raced.dir.path().join("x"));
    assert_eq!(x.secret(&raced.personal, &raced.before).unwrap(), env("before"));
    assert!(x.secret(&raced.personal, &raced.after_removal).is_err());
}

#[test]
fn a_device_with_no_keys_yet_reads_the_oldest_items_when_only_a_set_apart_generation_reaches_them() {
    let mut raced = raced();
    let vault = raced.b.state.vault;
    let first = *raced.b.state.epochs.keys().next().unwrap();
    let (next, next_key) = (first.after(raced.r.id()), Key::generate());
    let clock = raced.b.state.clock;
    // A clean generation whose link opens nothing, so only the set-apart one still reaches the first.
    raced.r.write(
        clock + 1,
        &Body::EpochLink {
            epoch: next,
            previous: first,
            commitment: epoch_commitment(&vault, next, &next_key),
            roster: raced.b.state.roster_head(),
            sealed: vec![9; 80],
        },
    );
    raced.r.write(clock + 2, &wrap_to(&raced.b, raced.b.me, next, &next_key));
    raced.b.merge_logs(raced.r.log(), None).unwrap();
    relock(&mut raced.b);
    let x = Bad::enroll(&raced.b, &raced.words);
    raced.b.merge_logs(x.log(), None).unwrap();
    raced.b.repair().unwrap();
    let x = joined(&raced.b, &x.actor.device, &x.actor.fresh, &raced.dir.path().join("x"));
    assert_eq!(raced.b.secret(&raced.personal, &raced.before).unwrap(), env("before"));
    assert_eq!(x.secret(&raced.personal, &raced.before).ok(), Some(env("before")), "X cannot read what B reads");
}

#[test]
fn a_space_waiting_for_its_new_key_says_so_and_one_that_does_not_exist_says_that() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let personal = b.space(FIRST_SPACE).unwrap().id;
    remove_r(&mut a, &r);
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(matches!(b.newest_space_key(&personal), Err(Error::Locked)), "a touch opens what this needs");
    assert!(matches!(b.newest_space_key(&SpaceId::random()), Err(Error::NotFound(_))));
}
