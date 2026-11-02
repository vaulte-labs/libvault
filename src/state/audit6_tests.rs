//! Sixth audit proofs. Each test asserts the safe outcome, so a failure is the finding.
#![allow(clippy::many_single_char_names, clippy::too_many_lines, clippy::items_after_statements)]

use super::super::tests::Actor;
use super::*;
use crate::device::Device;

fn remove_with_both(a: &mut Fixture, target: DeviceId) {
    let removal = a.vault.prepare_removal(&a.vault.device_name(&target)).unwrap();
    let approvals = a.both_approvals(&removal.digest);
    a.vault.remove_device(&removal, approvals).unwrap();
}

/// The H9f race: A removes R, B and C pair two devices with more signers. The add side is the
/// default, so A's removal loses and the person settles A with the words.
fn lost_removal(dir: &Path) -> (Fixture, Vault, Bad, Vault) {
    let (mut a, mut b, r) = three(dir);
    let words = a.recovery.clone();
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let mut c = add_with(&mut a.vault, with_words, &dir.join("c"), "C");
    for _ in 0..2 {
        b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        a.vault.merge_logs(c.all_logs().unwrap(), None).unwrap();
    }
    relock(&mut b);
    relock(&mut c);
    remove_with_both(&mut a, r.id());
    let both = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), signed_by(&c, digest)];
    let _phone = add_with(&mut b, both, &dir.join("phone"), "Phone");
    let _tablet = add_with(&mut b, with_words, &dir.join("tablet"), "Tablet");
    (a, b, r, c)
}

#[test]
fn p1_a_device_that_settled_against_its_removal_can_remove_again() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, b, r, _c) = lost_removal(dir.path());
    let words = a.recovery.clone();
    assert!(is_removed(&a.vault, r.id()), "setup: A's own removal stands on A");

    a.vault.merge_logs(b.all_logs().unwrap(), Some(&words)).unwrap();
    assert!(!is_removed(&a.vault, r.id()), "setup: the person settled A on the side where R is still in");
    assert!(!a.vault.state.set_apart.is_empty(), "setup: A's generation is set apart");
    println!("set apart {:?}", a.vault.state.set_apart);

    // R is still in, so the person removes it again, from the same device.
    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.both_approvals(&removal.digest);
    let again = a.vault.remove_device(&removal, approvals);
    println!("remove again: {again:?}");
    println!("problems: {:?}", a.vault.problems().collect::<Vec<_>>());
    assert!(again.is_ok(), "removing R again failed: {again:?}");
}

/// What P1 leaves behind: A's log stops at the entry, and everyone refuses all of it.
#[test]
fn p1b_after_that_a_still_writes_and_its_earlier_work_still_reaches_the_others() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, b, r, mut c) = lost_removal(dir.path());
    let words = a.recovery.clone();
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    a.vault.merge_logs(b.all_logs().unwrap(), Some(&words)).unwrap();
    let item = a.vault.add(&personal, Meta::new(Kind::Env, "UNSYNCED_ON_A"), &env("written before the second removal")).unwrap();
    c.merge_logs(b.all_logs().unwrap(), Some(&words)).unwrap();

    let name = a.vault.device_name(&r.id());
    let removal = a.vault.prepare_removal(&name).unwrap();
    let approvals = a.both_approvals(&removal.digest);
    let again = a.vault.remove_device(&removal, approvals);
    println!("second removal: {again:?}");

    let home = a.vault.home.clone();
    let logs = a.vault.all_logs().unwrap();
    let spare = Fixture::new();
    drop(std::mem::replace(&mut a.vault, spare.vault));
    let mut reopened = Vault::open(&home, Some("pass")).unwrap();
    reopened.unlock("test").unwrap();
    println!("A's own problems after restart: {:?}", reopened.state.problems);
    let wrote = reopened.add(&personal, Meta::new(Kind::Env, "NEXT"), &env("v"));
    println!("A writes: {wrote:?}");
    println!("A reads its own: {:?}", reopened.secret(&personal, &item).is_ok());

    c.merge_logs(logs, None).unwrap();
    println!("C problems: {:?}", c.state.problems);
    println!("C has the item: {}", c.state.items.contains_key(&(personal, item)));
    println!("C sees R removed: {}", is_removed(&c, r.id()));
    assert!(wrote.is_ok(), "A can never write again");
    assert!(c.state.items.contains_key(&(personal, item)), "what A wrote before never reaches another device");
}

/// A stolen first device added C, so it may name C. It swaps the names of the two devices.
#[test]
fn p2_a_stolen_adder_cannot_point_a_removal_at_an_honest_device() {
    let dir = tempfile::tempdir().unwrap();
    let mut a = Fixture::new();
    let mut b = add_with(&mut a.vault, |vault, digest| vec![signed_by(vault, digest)], &dir.path().join("b"), "Laptop");
    let device = Software::generate("pass", Cost::FAST).unwrap();
    let fresh = crate::setup::new_device(&device).unwrap();
    let enrollment = a.vault.prepare_enrollment(fresh.record.clone(), "Studio iMac").unwrap();
    let approvals = vec![signed_by(&a.vault, &enrollment.digest), signed_by(&b, &enrollment.digest)];
    a.vault.enroll(&enrollment, approvals).unwrap();
    let c = joined(&a.vault, &device, &fresh, &dir.path().join("c"));
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    println!("before: {:?}", b.devices().unwrap());

    // A goes bad: `Owner` is what the person calls the stolen machine.
    let (vault_id, me) = (a.vault.state.vault, a.vault.me);
    let (epoch, key) = newest_epoch(&a.vault);
    // Written past what its own replay would let through, as a thief can.
    let own = a.vault.all_logs().unwrap().into_iter().find(|(device, _)| *device == me).unwrap().1;
    let mut last = log::parse(&own).entries.pop().unwrap();
    let mut forged = own;
    for (device, name) in [(c.me, "Owner"), (me, "Studio iMac")] {
        let body = crate::vault::label_body(vault_id, epoch, &key, device, name).unwrap();
        last = Chain { device: me, seq: last.seq + 1, prev: last.hash() }.next(last.clock + 1, &body, &a.vault.keys.as_ref().unwrap().log);
        forged.extend(last.encode());
    }
    b.merge_logs(Logs::from([(me, forged)]), None).unwrap();
    println!("after: {:?}", b.devices().unwrap());

    // The person, on B, removes the stolen machine by the name they know it by.
    assert_ne!(b.device_named("Owner").ok(), Some(c.me), "the honest device answers to the stolen one's name");
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

struct Stolen {
    a: Fixture,
    b: Vault,
    backup: std::path::PathBuf,
    p: Actor,
    add_p: Entry,
    label_p: Entry,
    add_q: Entry,
    q: Actor,
    label_q: Entry,
    keep: (u64, Hash),
}

/// H1: three devices, the first one stolen and removed by the other two, no words used since.
fn stolen_first_device(dir: &Path) -> Stolen {
    let mut a = Fixture::new();
    let genesis_head = a.vault.state.roster_head();
    let (vault_id, genesis) = (a.vault.state.vault, a.vault.state.genesis);
    let first = newest_epoch(&a.vault);
    let mut b = add_with(&mut a.vault, |vault, digest| vec![signed_by(vault, digest)], &dir.join("b"), "Laptop");
    let mut c = {
        let device = Software::generate("pass", Cost::FAST).unwrap();
        let fresh = crate::setup::new_device(&device).unwrap();
        let enrollment = a.vault.prepare_enrollment(fresh.record.clone(), "Phone").unwrap();
        let approvals = vec![signed_by(&a.vault, &enrollment.digest), signed_by(&b, &enrollment.digest)];
        a.vault.enroll(&enrollment, approvals).unwrap();
        joined(&a.vault, &device, &fresh, &dir.join("c"))
    };
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    let removal = b.prepare_removal(&b.device_name(&a.vault.me)).unwrap();
    let approvals = vec![signed_by(&b, &removal.digest), signed_by(&c, &removal.digest)];
    b.remove_device(&removal, approvals).unwrap();
    let personal = b.space(FIRST_SPACE).unwrap().id;
    b.add(&personal, Meta::new(Kind::Env, "AFTER_REMOVAL"), &env("everything written since")).unwrap();
    c.merge_logs(b.all_logs().unwrap(), None).unwrap();
    let backup = dir.join("backup");
    write_logs(&backup, &b.home, &no_settled()).unwrap();

    let (p, q) = (Actor::new(), Actor::new());
    let label = |actor: &Actor, name: &str| crate::vault::label_body(vault_id, first.0, &first.1, actor.id(), name).unwrap();
    let add_p = {
        let digest = add_digest(&vault_id, &genesis_head, &p.id(), &p.fresh.record);
        let body = Body::DeviceAdd { after: genesis_head, device: p.fresh.record.clone(), approvals: vec![signed_by(&a.vault, &digest)] };
        Chain { device: p.id(), seq: 0, prev: root(&genesis, &p.id()) }.next(2, &body, &p.log)
    };
    let label_p = Chain { device: p.id(), seq: 1, prev: add_p.hash() }.next(3, &label(&p, "Laptop"), &p.log);
    let add_q = {
        let digest = add_digest(&vault_id, &add_p.hash(), &q.id(), &q.fresh.record);
        let approvals = vec![signed_by(&a.vault, &digest), p.approve(&digest)];
        let body = Body::DeviceAdd { after: add_p.hash(), device: q.fresh.record.clone(), approvals };
        Chain { device: q.id(), seq: 0, prev: root(&genesis, &q.id()) }.next(4, &body, &q.log)
    };
    let label_q = Chain { device: q.id(), seq: 1, prev: add_q.hash() }.next(5, &label(&q, "Phone"), &q.log);
    let a_log = log::parse(&std::fs::read(log::path_for(&backup, &a.vault.me)).unwrap()).entries;
    let keep = (a_log.len() as u64, a_log.last().unwrap().hash());
    Stolen { a, b, backup, p, add_p, label_p, add_q, q, label_q, keep }
}

impl Stolen {
    /// P retires A on its own history too, so that a date is all that is left, and it sets the date.
    fn drop_a(&self, prev: &Entry, seq: u64) -> Entry {
        let vault_id = self.a.vault.state.vault;
        let (kept, last) = self.keep;
        let digest = revoke_digest(&vault_id, &self.add_q.hash(), &self.p.id(), &self.a.vault.me, kept, &last);
        let body = Body::DeviceRevoke {
            after: self.add_q.hash(),
            device: self.a.vault.me,
            entries_kept: kept,
            last_kept: last,
            approvals: vec![self.p.approve(&digest), self.q.approve(&digest)],
        };
        Chain { device: self.p.id(), seq, prev: prev.hash() }.next(6 + seq, &body, &self.p.log)
    }
}

#[test]
fn p3_a_person_can_tell_a_stolen_device_s_history_from_their_own() {
    let dir = tempfile::tempdir().unwrap();
    let t = stolen_first_device(dir.path());
    let drop_a = t.drop_a(&t.label_p, 2);
    std::fs::write(log::path_for(&t.backup, &t.p.id()), [t.add_p.encode(), t.label_p.encode(), drop_a.encode()].concat()).unwrap();
    std::fs::write(log::path_for(&t.backup, &t.q.id()), [t.add_q.encode(), t.label_q.encode()].concat()).unwrap();

    let words = t.a.recovery.words().to_string();
    let mut opened = Recovery::open(&t.backup, &words).unwrap();
    let histories = opened.histories();
    assert_eq!(histories.len(), 2, "{histories:?}");
    // The person knows what they wrote on their own devices after the thief was removed.
    let theirs = histories.iter().position(|history| history.newest_items.iter().any(|name| name == "AFTER_REMOVAL"));
    let theirs = theirs.expect("what the person wrote last tells their history apart");
    assert_eq!(histories.iter().filter(|history| history.newest_items.iter().any(|name| name == "AFTER_REMOVAL")).count(), 1);

    let at = dir.path().join("new");
    opened.choose_history(theirs).unwrap();
    opened.finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    new.repair().unwrap();
    let on_thief = new.state.active_devices().any(|(id, _)| *id == t.p.id());
    let personal = new.space(FIRST_SPACE).unwrap().id;
    let secret = new.add(&personal, Meta::new(Kind::Env, "WRITTEN_AFTER_RECOVERY"), &env("a new secret")).unwrap();
    let read = actor_reads(&t.p, &new, personal, secret);
    let _ = &t.b;
    assert!(!on_thief);
    assert_eq!(read, None, "the thief reads what is written after recovery");
}

#[test]
fn p4_every_history_shown_can_be_chosen() {
    let dir = tempfile::tempdir().unwrap();
    let t = stolen_first_device(dir.path());
    let vault_id = t.a.vault.state.vault;
    let genesis = t.a.vault.state.genesis;
    let honest = t.b.state.roster[1];

    // A side branch whose words are the thief's own, so nothing a person holds fits it, with two
    // children that tie. The loser goes in `lost_ties`, and `rival` cannot open it.
    let thief_words = RecoveryDraft::new();
    let thief_public = thief_words.0.new_public(vault_id).unwrap();
    let z = {
        let after = t.add_p.hash();
        let digest = rotate_digest(&vault_id, &after, &t.p.id(), &thief_public);
        let body = Body::RecoveryRotate {
            after,
            recovery: thief_public.clone(),
            proof: thief_words.0.sign(&digest).unwrap(),
            approvals: vec![signed_by(&t.a.vault, &digest), t.p.approve(&digest)],
        };
        Chain { device: t.p.id(), seq: 2, prev: t.label_p.hash() }.next(5, &body, &t.p.log)
    };
    let child = |actor: &Actor, clock: u64| {
        let digest = add_digest(&vault_id, &z.hash(), &actor.id(), &actor.fresh.record);
        let body = Body::DeviceAdd { after: z.hash(), device: actor.fresh.record.clone(), approvals: vec![words_approval(&thief_words.0, &digest)] };
        Chain { device: actor.id(), seq: 0, prev: root(&genesis, &actor.id()) }.next(clock, &body, &actor.log)
    };
    let (x1, x2) = (Actor::new(), Actor::new());
    let z1 = child(&x1, 20);
    let mut clock = 21;
    let z2 = loop {
        let entry = child(&x2, clock);
        if entry.hash() < honest {
            break entry;
        }
        clock += 1;
    };
    let drop_a = t.drop_a(&z, 3);
    std::fs::write(log::path_for(&t.backup, &t.p.id()), [t.add_p.encode(), t.label_p.encode(), z.encode(), drop_a.encode()].concat()).unwrap();
    std::fs::write(log::path_for(&t.backup, &t.q.id()), [t.add_q.encode(), t.label_q.encode()].concat()).unwrap();
    std::fs::write(log::path_for(&t.backup, &x1.id()), z1.encode()).unwrap();
    std::fs::write(log::path_for(&t.backup, &x2.id()), z2.encode()).unwrap();

    let words = t.a.recovery.words().to_string();
    let mut opened = Recovery::open(&t.backup, &words).unwrap();
    let shown = opened.histories();
    assert_eq!(shown.len(), 2, "a branch under the thief's own words is no choice for the person");
    let theirs = shown.iter().position(|history| history.newest_items.iter().any(|name| name == "AFTER_REMOVAL"));
    let theirs = theirs.expect("the person's own history is on the list");
    opened.choose_history(theirs).unwrap();
    assert!(opened.histories()[0].newest_items.iter().any(|name| name == "AFTER_REMOVAL"), "what was chosen is what was shown");
}

#[test]
fn p5_a_file_in_a_folder_does_not_stop_every_sync_with_it() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let mut c = add_with(&mut a.vault, with_words, &dir.path().join("c"), "C");
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);

    // C hears a phone added on B, which then writes, so C holds its log.
    let mut phone = add_with(&mut b, with_words, &dir.path().join("phone"), "Phone");
    let personal = phone.space(FIRST_SPACE).unwrap().id;
    phone.add(&personal, Meta::new(Kind::Env, "ON_PHONE"), &env("v")).unwrap();
    c.merge_logs(b.all_logs().unwrap(), None).unwrap();
    c.merge_logs(phone.all_logs().unwrap(), None).unwrap();
    assert!(c.state.heads.contains_key(&phone.me), "setup");

    // A's removal raced that add and wins, and C has only been told, so C moves.
    remove_with_both(&mut a, r.id());
    c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(!c.state.heads.contains_key(&phone.me), "setup: the phone's log is here with nothing applied");

    // Someone who can write to a folder puts this there. Nothing in it is signed.
    let planted = Entry { kind: Body::GENESIS, device: phone.me, seq: 0, clock: 1, prev: [0; 32], body: vec![], signature: [0; 64] };
    let outcome = c.merge_logs(Logs::from([(phone.me, planted.encode())]), None);
    println!("merge: {outcome:?}");
    assert!(outcome.is_ok(), "one unsigned file stops every merge with that folder");
}

#[test]
fn p6_a_refused_removal_stays_on_the_list_of_problems() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let mut c = add_with(&mut a.vault, with_words, &dir.path().join("c"), "C");
    for _ in 0..2 {
        b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        a.vault.merge_logs(c.all_logs().unwrap(), None).unwrap();
    }
    relock(&mut b);
    relock(&mut c);

    // B pairs a phone with the words. A, elsewhere, removes R, then adds a tablet with C.
    let mut phone = add_with(&mut b, with_words, &dir.path().join("phone"), "Phone");
    remove_with_both(&mut a, r.id());
    let both = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), signed_by(&c, digest)];
    let _tablet = add_with(&mut a.vault, both, &dir.path().join("tablet"), "Tablet");

    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(!is_removed(&b, r.id()), "setup: B refuses, because its own change does not stand on A's history");
    let told = |vault: &Vault| vault.problems().any(|problem| problem.reason == "conflicts with a roster change on this device");
    println!("told at first: {}", told(&b));

    // Anything else arriving replaces the state, and so the list.
    let personal = phone.space(FIRST_SPACE).unwrap().id;
    phone.add(&personal, Meta::new(Kind::Env, "ON_PHONE"), &env("v")).unwrap();
    b.merge_logs(phone.all_logs().unwrap(), None).unwrap();
    println!("told after one more log: {}", told(&b));
    println!("everything B shows: {:?}", b.problems().collect::<Vec<_>>());
    assert!(told(&b), "R is on B's roster, A says it is gone, and nothing on B says so any more");
}

/// Signatures cannot tell an honest race from a thief's, so this is the person's to choose, and
/// finishing has to wait for that, but each history on offer finishes.
#[test]
fn p7_a_folder_recovers_after_an_honest_race_once_a_history_is_chosen() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let _phone = add_with(&mut b, with_words, &dir.path().join("phone"), "Phone");
    remove_with_both(&mut a, r.id());
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();
    let _ = write_logs(&backup, &b.home, &no_settled());
    let shown = Recovery::open(&backup, &words.words()).unwrap().histories().len();
    assert_eq!(shown, 2);
    let mut opened = Recovery::open(&backup, &words.words()).unwrap();
    assert!(opened.choose_history(shown).is_err());
    assert_eq!(opened.histories().len(), shown, "a wrong choice keeps every history on offer");
    for index in 0..shown {
        let mut opened = Recovery::open(&backup, &words.words()).unwrap();
        opened.choose_history(index).unwrap();
        opened.finish_with_passphrase("pass", Cost::FAST, &dir.path().join(format!("new-{index}")), "New").unwrap();
    }
}

/// A phone paired in a race, then removed on its own side, then the other side's history wins.
#[test]
fn p8_a_removed_device_can_still_open_and_take_out_what_it_wrote() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let mut phone = add_with(&mut b, with_words, &dir.path().join("phone"), "Phone");
    let personal = phone.space(FIRST_SPACE).unwrap().id;
    let written = phone.add(&personal, Meta::new(Kind::Env, "ONLY_ON_PHONE"), &env("the phone's work")).unwrap();
    // A, elsewhere, removes R. The phone hears it, stays where it is, and keeps A's log.
    remove_with_both(&mut a, r.id());
    phone.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    assert!(phone.is_active(&phone.me), "setup");

    // B, not having heard, removes the phone, which it had not meant to keep, with the words.
    let own: Logs = phone.all_logs().unwrap().into_iter().filter(|(device, _)| *device == phone.me).collect();
    b.merge_logs(own, None).unwrap();
    let removal = b.prepare_removal(&b.device_name(&phone.me)).unwrap();
    let approvals = vec![signed_by(&b, &removal.digest), words_approval(&words, &removal.digest)];
    b.remove_device(&removal, approvals).unwrap();
    let merged = phone.merge_logs(b.all_logs().unwrap(), None);
    println!("merge: {merged:?}");
    println!("phone in its own state: {:?}", phone.state.members.get(&phone.me).map(|member| member.standing));

    let home = phone.home.clone();
    drop(phone);
    let reopened = Vault::open(&home, Some("pass"));
    println!("reopen: {:?}", reopened.as_ref().map(|_| "opened").map_err(ToString::to_string));
    let mut reopened = reopened.expect("the only copy of what this device wrote is behind this");
    reopened.unlock("test").unwrap();
    let export = dir.path().join("export.json");
    reopened.export_plaintext(&export).unwrap();
    let text = std::fs::read_to_string(&export).unwrap();
    let _ = written;
    assert!(text.contains("ONLY_ON_PHONE"));
}

/// A's removal is the second thing it does on its branch, so the first step says nothing about it.
#[test]
fn p9_on_an_even_count_someone_leaving_beats_anything_else_wherever_it_comes_on_the_branch() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, r) = three(dir.path());
    let words = a.recovery.clone();
    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let c_home = dir.path().join("c");
    let mut c = add_with(&mut a.vault, with_words, &c_home, "C");
    for _ in 0..2 {
        b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        c.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
        a.vault.merge_logs(c.all_logs().unwrap(), None).unwrap();
    }
    relock(&mut b);
    relock(&mut c);

    // B pairs a phone first. Then A pairs a tablet and removes R. All with the words.
    let _phone = add_with(&mut b, with_words, &dir.path().join("phone"), "Phone");
    std::thread::sleep(std::time::Duration::from_millis(5));
    let _tablet = add_with(&mut a.vault, with_words, &dir.path().join("tablet"), "Tablet");
    remove_with_both(&mut a, r.id());

    // C, which signed nothing here, hears both at once.
    let mut both = a.vault.all_logs().unwrap();
    for (device, bytes) in b.all_logs().unwrap() {
        let longest = both.entry(device).or_default();
        if bytes.len() > longest.len() {
            *longest = bytes;
        }
    }
    c.merge_logs(both, None).unwrap();
    println!("conflicts on C: {:?}", c.state.conflicts);
    println!("lost ties on C: {}", c.state.lost_ties.len());
    assert!(is_removed(&c, r.id()), "the date alone kept R in on a device that signed neither");
}

/// DESIGN: what a lost removal made "goes to the words and to nobody else".
#[test]
fn p10_what_a_lost_removal_made_goes_to_nobody_else() {
    let dir = tempfile::tempdir().unwrap();
    let (a, mut b, _r, _c) = lost_removal(dir.path());
    let words = a.recovery.clone();
    b.merge_logs(a.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    let apart = b.state.set_apart.clone();
    assert!(!apart.is_empty() && apart.iter().all(|epoch| b.keys.as_ref().unwrap().epochs.contains_key(epoch)), "setup: B holds what A made");

    let with_words = |vault: &Vault, digest: &Hash| vec![signed_by(vault, digest), words_approval(&words, digest)];
    let new = add_with(&mut b, with_words, &dir.path().join("new"), "New");
    let held: Vec<_> = apart.iter().filter(|epoch| new.keys.as_ref().unwrap().epochs.contains_key(epoch)).collect();
    println!("the new device holds: {held:?}");
    assert!(held.is_empty(), "a device added here was handed what a lost removal made");
}

/// Row 324, for a new machine: what a folder holds comes along, whoever approved it.
#[test]
fn p5b_recovery_keeps_no_log_from_a_device_nobody_approved_and_a_file_cannot_then_stop_a_folder() {
    let dir = tempfile::tempdir().unwrap();
    let a = Fixture::new();
    let words = a.recovery.words().to_string();
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();

    // Anyone who can write to the folder: an unsigned entry under a name of their choosing.
    let stray = DeviceId::from([7; 16]);
    let junk = Entry { kind: 8, device: stray, seq: 0, clock: 1, prev: [0; 32], body: vec![1], signature: [0; 64] };
    std::fs::write(log::path_for(&backup, &stray), junk.encode()).unwrap();

    let at = dir.path().join("new");
    Recovery::open(&backup, &words).unwrap().finish_with_passphrase("pass", Cost::FAST, &at, "New").unwrap();
    let mut new = Vault::open(&at, Some("pass")).unwrap();
    new.unlock("test").unwrap();
    assert!(!log::path_for(&at, &stray).exists(), "a log nobody approved came along");
    println!("problems: {:?}", new.problems().collect::<Vec<_>>());

    let planted = Entry { kind: Body::GENESIS, device: stray, seq: 0, clock: 1, prev: [0; 32], body: vec![], signature: [0; 64] };
    std::fs::write(log::path_for(&backup, &stray), planted.encode()).unwrap();
    let outcome = new.merge_logs(crate::sync::folder::read_logs(&backup).unwrap(), None);
    println!("the next read of that folder: {outcome:?}");
    assert!(outcome.is_ok(), "one unsigned file stops a folder being read or written, for good");
}

/// Row 292, with the last entry of the copy dated far ahead, which a removed device is free to write.
#[test]
fn p11_a_far_dated_tail_past_a_cut_does_not_cost_a_device_what_the_removal_kept() {
    let dir = tempfile::tempdir().unwrap();
    let (mut a, mut b, mut r) = three(dir.path());
    let personal = a.vault.space(FIRST_SPACE).unwrap().id;
    let key = a.vault.newest_space_key(&personal).unwrap();
    let heard = ItemId::random();
    r.write(
        a.vault.state.clock + 1,
        &a.vault.put_body(&key, personal, heard, BatchId::random(), &Meta::new(Kind::Env, "B_HEARD_THIS"), &env("on R, heard by B")).unwrap(),
    );
    a.vault.merge_logs(r.log(), None).unwrap();
    b.merge_logs(r.log(), None).unwrap();
    assert_eq!(b.secret(&personal, &heard).unwrap(), env("on R, heard by B"), "setup");

    // One more from R, which A hears and B, now offline, does not.
    let (epoch, _) = newest_epoch(&a.vault);
    r.write(a.vault.state.clock + 1, &Body::Audit { epoch, sealed: vec![1] });
    a.vault.merge_logs(r.log(), None).unwrap();
    remove_r(&mut a, &r);
    let backup = dir.path().join("backup");
    write_logs(&backup, &a.vault.home, &no_settled()).unwrap();

    // R copies its log to the shared folder, ending in an entry dated a hundred days ahead.
    let far = (now_ms() + 100 * 24 * 60 * 60 * 1000) << 16;
    r.write(far, &Body::Audit { epoch, sealed: vec![2] });
    std::fs::write(log::path_for(&backup, &r.id()), r.bytes()).unwrap();

    // A writes to the folder again. Its copy of R is a prefix of what is there, so it leaves it.
    write_logs(&backup, &a.vault.home, &a.vault.logs_removals_kept()).unwrap();
    b.merge_logs(crate::sync::folder::read_logs(&backup).unwrap(), None).unwrap();
    relock(&mut b);
    b.repair().unwrap();
    println!("B reads what R wrote before its removal: {:?}", b.secret(&personal, &heard).is_ok());
    println!("B's problems: {:?}", b.problems().map(|problem| problem.reason).collect::<Vec<_>>());
    assert!(b.secret(&personal, &heard).is_ok(), "B could read this, and hearing of the removal cost it the value");
}

/// Row 292's first-device case, with one far-dated entry at the end of the thief's copy.
#[test]
fn p11b_a_far_dated_tail_does_not_leave_a_device_with_an_empty_vault() {
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
    assert_eq!(d.secret(&personal, &years).unwrap(), env("v"), "setup");

    first.vault.add(&personal, Meta::new(Kind::Env, "LATER"), &env("v")).unwrap();
    b.merge_logs(first.vault.all_logs().unwrap(), None).unwrap();
    relock(&mut b);
    let me = first.vault.me;
    let removal = b.prepare_removal(&b.device_name(&me)).unwrap();
    let approvals = first.recovery_approval(&removal.digest);
    b.remove_device(&removal, approvals).unwrap();
    let backup = dir.path().join("backup");
    write_logs(&backup, &b.home, &no_settled()).unwrap();

    // The thief copies the first device's log to the folder with one more entry, dated far ahead.
    let own = first.vault.all_logs().unwrap().into_iter().find(|(device, _)| *device == me).unwrap().1;
    let last = log::parse(&own).entries.pop().unwrap();
    let far = (now_ms() + 100 * 24 * 60 * 60 * 1000) << 16;
    let (epoch, _) = newest_epoch(&first.vault);
    let tail = Chain { device: me, seq: last.seq + 1, prev: last.hash() }
        .next(far, &Body::Audit { epoch, sealed: vec![1] }, &first.vault.keys.as_ref().unwrap().log)
        .encode();
    std::fs::write(log::path_for(&backup, &me), [own, tail].concat()).unwrap();

    // B leaves it there, as it is ahead of B's copy, so this is what D sees for as long as it lasts.
    write_logs(&backup, &b.home, &b.logs_removals_kept()).unwrap();
    d.merge_logs(crate::sync::folder::read_logs(&backup).unwrap(), None).unwrap();
    relock(&mut d);
    d.repair().unwrap();
    println!("spaces D sees: {:?}", d.spaces().unwrap().iter().map(|space| space.name.clone()).collect::<Vec<_>>());
    println!("D's problems: {:?}", d.problems().map(|problem| problem.reason).collect::<Vec<_>>());
    println!("D reads years of work: {}", d.secret(&personal, &years).is_ok());
    let export = dir.path().join("export.json");
    let exported = d.export_plaintext(&export);
    println!("export: {exported:?} holds it: {}", std::fs::read_to_string(&export).is_ok_and(|text| text.contains("YEARS_OF_WORK")));
    assert_eq!(d.secret(&personal, &years).ok(), Some(env("v")), "D is left with an empty vault");
}
