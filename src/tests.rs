//! The vault's promises, including the attacks the design claims to stop.

use std::fs;
use std::path::Path;

use tempfile::TempDir;

use crate::device::software::{Cost, Software};
use crate::ids::{DeviceId, ItemId, SpaceId};
use crate::item::{Kind, Meta, Secret};
use crate::state::Change;
use crate::store::log;
use crate::{Error, FIRST_SPACE, Setup, Vault};

const PASSPHRASE: &str = "test passphrase";

fn env(value: &str) -> Secret {
    Secret::Env { value: value.to_owned() }
}

fn new_vault() -> (TempDir, Vault, String) {
    let dir = tempfile::tempdir().unwrap();
    let device = Software::generate(PASSPHRASE, Cost::FAST).unwrap();
    let setup = Setup::new(device);
    let words = setup.recovery().words().to_string();
    let mut vault = setup.create(&dir.path().join("vault"), "Test Mac").unwrap();
    vault.unlock("test").unwrap();
    (dir, vault, words)
}

fn reopen(home: &Path) -> Vault {
    let mut vault = Vault::open(home, Some(PASSPHRASE)).unwrap();
    vault.unlock("test").unwrap();
    vault
}

fn own_log(vault: &Vault) -> std::path::PathBuf {
    log::path_for(&vault.home, &vault.me)
}

#[test]
fn a_new_vault_has_one_space_and_knows_its_device() {
    let (_dir, vault, words) = new_vault();
    assert_eq!(vault.spaces().unwrap()[0].name, FIRST_SPACE);
    assert_eq!(vault.devices().unwrap()[0].name, "Test Mac");
    assert_eq!(words.split(' ').count(), 24);
    assert!(!vault.is_hardware());
}

#[test]
fn items_survive_closing_and_reopening() {
    let (dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    let id = vault.add(&space.id, Meta::new(Kind::Env, "OPENAI_API_KEY"), &env("sk-one")).unwrap();
    drop(vault);

    let vault = reopen(&dir.path().join("vault"));
    let found = vault.find(&space.id, "OPENAI_API_KEY").unwrap();
    assert_eq!(found.id, id);
    assert_eq!(vault.secret(&space.id, &id).unwrap(), env("sk-one"));
}

#[test]
fn the_same_name_in_two_spaces_holds_different_values() {
    let (_dir, mut vault, _) = new_vault();
    let a = vault.create_space("project-a").unwrap();
    let b = vault.create_space("project-b").unwrap();
    let in_a = vault.add(&a.id, Meta::new(Kind::Env, "OPENAI_API_KEY"), &env("key-a")).unwrap();
    let in_b = vault.add(&b.id, Meta::new(Kind::Env, "OPENAI_API_KEY"), &env("key-b")).unwrap();
    assert_eq!(vault.secret(&a.id, &in_a).unwrap(), env("key-a"));
    assert_eq!(vault.secret(&b.id, &in_b).unwrap(), env("key-b"));
}

#[test]
fn a_taken_name_is_refused_rather_than_overwritten() {
    let (_dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    vault.add(&space.id, Meta::new(Kind::Env, "KEY"), &env("first")).unwrap();
    let again = vault.add(&space.id, Meta::new(Kind::Env, "KEY"), &env("second"));
    assert!(matches!(again, Err(Error::Exists(_))));
}

#[test]
fn one_undo_brings_back_items_deleted_together_with_their_secrets() {
    let (_dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    let id = vault.add(&space.id, Meta::new(Kind::Env, "KEY"), &env("value")).unwrap();
    let other = vault.add(&space.id, Meta::new(Kind::Env, "OTHER"), &env("other")).unwrap();
    vault.remove(&[(space.id, id), (space.id, other)]).unwrap();
    assert!(vault.find(&space.id, "KEY").is_err());
    assert!(vault.find(&space.id, "OTHER").is_err());

    assert_eq!(vault.undo().unwrap(), ["KEY", "OTHER"]);
    assert_eq!(vault.secret(&space.id, &id).unwrap(), env("value"));
    assert_eq!(vault.secret(&space.id, &other).unwrap(), env("other"));
}

#[test]
fn undo_restores_the_previous_value_after_a_replace() {
    let (_dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    let id = vault.add(&space.id, Meta::new(Kind::Env, "KEY"), &env("old")).unwrap();
    vault.replace(&space.id, &id, &Meta::new(Kind::Env, "KEY"), &env("new")).unwrap();
    vault.undo().unwrap();
    assert_eq!(vault.secret(&space.id, &id).unwrap(), env("old"));
    assert_eq!(vault.history(&space.id, &id).unwrap().len(), 3);
}

#[test]
fn undo_removes_a_whole_batch_at_once() {
    let (_dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    let batch: Vec<_> = (0..5).map(|n| (Meta::new(Kind::Env, format!("KEY_{n}")), env("v"))).collect();
    vault.add_many(&space.id, &batch).unwrap();
    assert_eq!(vault.items(&space.id).unwrap().len(), 5);
    assert_eq!(vault.undo().unwrap().len(), 5);
    assert_eq!(vault.items(&space.id).unwrap(), [] as [crate::items::Summary; 0]);
}

#[test]
fn each_undo_goes_one_change_further_back_and_never_undoes_itself() {
    let (_dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    let a = vault.add(&space.id, Meta::new(Kind::Env, "A"), &env("a")).unwrap();
    vault.add(&space.id, Meta::new(Kind::Env, "B"), &env("b")).unwrap();
    vault.replace(&space.id, &a, &Meta::new(Kind::Env, "A"), &env("a2")).unwrap();

    assert_eq!(vault.undo().unwrap(), ["A"]);
    assert_eq!(vault.secret(&space.id, &a).unwrap(), env("a"));
    assert_eq!(vault.undo().unwrap(), ["B"]);
    assert!(vault.find(&space.id, "B").is_err());
    assert_eq!(vault.undo().unwrap(), ["A"]);
    assert!(vault.find(&space.id, "A").is_err());
    assert!(matches!(vault.undo(), Err(Error::NotFound(_))));
}

#[test]
fn undo_skips_what_it_already_undid_after_a_new_change() {
    let (_dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    vault.add(&space.id, Meta::new(Kind::Env, "A"), &env("a")).unwrap();
    vault.add(&space.id, Meta::new(Kind::Env, "B"), &env("b")).unwrap();
    vault.undo().unwrap();
    vault.add(&space.id, Meta::new(Kind::Env, "C"), &env("c")).unwrap();

    assert_eq!(vault.undo().unwrap(), ["C"]);
    assert_eq!(vault.undo().unwrap(), ["A"]);
    assert!(vault.find(&space.id, "B").is_err());
}

#[test]
fn a_locked_vault_cannot_read_or_write() {
    let (_dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    let id = vault.add(&space.id, Meta::new(Kind::Env, "KEY"), &env("value")).unwrap();
    vault.lock();
    assert!(matches!(vault.secret(&space.id, &id), Err(Error::Locked)));
    assert!(matches!(vault.items(&space.id), Err(Error::Locked)));
    assert!(matches!(vault.add(&space.id, Meta::new(Kind::Env, "B"), &env("v")), Err(Error::Locked)));
}

#[test]
fn a_second_setup_cannot_replace_an_existing_vault() {
    let (dir, vault, _) = new_vault();
    drop(vault);
    let device = Software::generate(PASSPHRASE, Cost::FAST).unwrap();
    let result = Setup::new(device).create(&dir.path().join("vault"), "Other");
    assert!(matches!(result, Err(Error::VaultExists)));
}

#[test]
fn two_processes_cannot_hold_one_vault() {
    let (dir, vault, _) = new_vault();
    let second = Vault::open(&dir.path().join("vault"), Some(PASSPHRASE));
    assert!(matches!(second, Err(Error::Busy)));
    drop(vault);
}

#[test]
fn no_secret_or_name_appears_in_anything_written_to_disk() {
    let (dir, mut vault, _) = new_vault();
    let space = vault.create_space("very-secret-project").unwrap();
    vault.add(&space.id, Meta::new(Kind::Env, "MY_UNIQUE_KEY_NAME"), &env("sk-plaintext-value")).unwrap();
    drop(vault);

    let mut files = vec![dir.path().join("vault")];
    while let Some(path) = files.pop() {
        if path.is_dir() {
            files.extend(fs::read_dir(path).unwrap().map(|entry| entry.unwrap().path()));
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        for needle in [&b"sk-plaintext-value"[..], b"MY_UNIQUE_KEY_NAME", b"very-secret-project", b"Test Mac"] {
            assert!(!bytes.windows(needle.len()).any(|window| window == needle), "{path:?} leaks {:?}", String::from_utf8_lossy(needle));
        }
    }
}

#[test]
fn flipping_any_byte_of_an_entry_is_detected() {
    let (dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    let id = vault.add(&space.id, Meta::new(Kind::Env, "KEY"), &env("value")).unwrap();
    let path = own_log(&vault);
    drop(vault);

    let original = fs::read(&path).unwrap();
    let parsed = log::parse(&original);
    let last = parsed.entries.last().unwrap().encode();
    let start = original.len() - last.len();
    // Headers, body and signature, stepping over the entry.
    for offset in (0..last.len()).step_by(257) {
        let mut tampered = original.clone();
        tampered[start + offset] ^= 0x01;
        fs::write(&path, &tampered).unwrap();
        let vault = Vault::open(&dir.path().join("vault"), Some(PASSPHRASE));
        let Ok(mut vault) = vault else { continue };
        vault.unlock("test").unwrap();
        assert!(vault.secret(&space.id, &id).is_err(), "byte {offset} changed without detection");
        assert!(vault.problems().next().is_some() || parsed.entries.len() > log::parse(&tampered).entries.len());
    }
}

#[test]
fn a_rewritten_entry_with_a_fresh_chain_still_fails_on_its_signature() {
    let (dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    vault.add(&space.id, Meta::new(Kind::Env, "KEY"), &env("value")).unwrap();
    let path = own_log(&vault);
    let device: DeviceId = vault.me;
    drop(vault);

    let mut parsed = log::parse(&fs::read(&path).unwrap());
    let last = parsed.entries.last_mut().unwrap();
    last.clock += 1;
    fs::write(&path, parsed.entries.iter().flat_map(log::Entry::encode).collect::<Vec<u8>>()).unwrap();

    let vault = Vault::open(&dir.path().join("vault"), Some(PASSPHRASE)).unwrap();
    assert!(vault.problems().any(|problem| problem.device == device && problem.reason == "bad entry signature"));
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

// Every field here is validly signed by the real device: only the hash chain can tell that
// the spliced entry belongs to a different history.
#[test]
fn a_validly_signed_entry_from_a_forked_history_is_rejected() {
    let (dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap();
    vault.add(&space.id, Meta::new(Kind::Env, "SHARED"), &env("v")).unwrap();
    let home = dir.path().join("vault");
    let fork = dir.path().join("fork");
    let path = own_log(&vault);
    let fork_path = fork.join("log").join(path.file_name().unwrap());
    copy_dir(&home, &fork);

    vault.add(&space.id, Meta::new(Kind::Env, "MAIN_1"), &env("v")).unwrap();
    drop(vault);

    let mut forked = reopen(&fork);
    forked.add(&space.id, Meta::new(Kind::Env, "FORK_1"), &env("v")).unwrap();
    forked.add(&space.id, Meta::new(Kind::Env, "FORK_2"), &env("v")).unwrap();
    drop(forked);

    let mut main = log::parse(&fs::read(&path).unwrap()).entries;
    let fork_entries = log::parse(&fs::read(&fork_path).unwrap()).entries;
    let spliced = fork_entries.last().unwrap();
    assert_eq!(spliced.seq, main.len() as u64, "the splice must look like the next entry");
    main.push(spliced.clone());
    fs::write(&path, main.iter().flat_map(log::Entry::encode).collect::<Vec<u8>>()).unwrap();

    let vault = Vault::open(&home, Some(PASSPHRASE)).unwrap();
    assert!(vault.problems().any(|problem| problem.reason == "the hash chain is broken"), "{:?}", vault.problems().collect::<Vec<_>>());
}

fn put_slots(vault: &mut Vault, space: SpaceId, item: ItemId) -> (&mut Vec<u8>, &mut Vec<u8>) {
    let versions = vault.state.items.get_mut(&(space, item)).unwrap();
    let Change::Put { meta, secret, .. } = &mut versions[0].change else { unreachable!() };
    (meta, secret)
}

// Stands in for a hostile writer who can reorder ciphertext but cannot decrypt it.
#[test]
fn a_secret_moved_onto_another_item_will_not_decrypt() {
    let (_dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    let a = vault.add(&space, Meta::new(Kind::Env, "A"), &env("a")).unwrap();
    let b = vault.add(&space, Meta::new(Kind::Env, "B"), &env("b")).unwrap();

    let stolen = put_slots(&mut vault, space, a).1.clone();
    *put_slots(&mut vault, space, b).1 = stolen;

    assert!(matches!(vault.secret(&space, &b), Err(Error::NotFound(_))), "the moved value must not open, even as its original");
    assert_eq!(vault.secret(&space, &a).unwrap(), env("a"), "and nothing else may suffer for it");
}

#[test]
fn a_secret_moved_into_the_metadata_slot_will_not_decrypt() {
    let (_dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    let id = vault.add(&space, Meta::new(Kind::Env, "A"), &env("a")).unwrap();

    let (meta, secret) = put_slots(&mut vault, space, id);
    std::mem::swap(meta, secret);

    assert_eq!(vault.read_rows(&space).items, Vec::new(), "neither moved value may open");
    assert!(matches!(vault.secret(&space, &id), Err(Error::NotFound(_))));
}

// A crash can stop a write at any byte. Whatever whole entries reached the disk must open, and
// the next write must carry on as if the torn part never happened.
#[test]
fn a_crash_at_any_byte_of_a_write_leaves_a_working_vault() {
    let (dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    vault.add(&space, Meta::new(Kind::Env, "FIRST"), &env("one")).unwrap();
    let path = own_log(&vault);
    let before = fs::read(&path).unwrap().len();
    vault.add(&space, Meta::new(Kind::Env, "SECOND"), &env("two")).unwrap();
    drop(vault);
    let whole = fs::read(&path).unwrap();
    let home = dir.path().join("vault");

    for length in (before..whole.len()).step_by(97) {
        fs::write(&path, &whole[..length]).unwrap();
        let mut vault = reopen(&home);
        assert_eq!(vault.items(&space).unwrap().len(), 1, "cut at {length}");
        vault.add(&space, Meta::new(Kind::Env, "AFTER"), &env("three")).unwrap();
        drop(vault);
        assert_eq!(reopen(&home).find(&space, "AFTER").unwrap().meta.name, "AFTER");
    }
}

// What cannot be read back must not be written: an entry past the limit would be cut off, with
// everything after it, the next time the log is read.
#[test]
fn an_entry_too_large_to_read_back_is_refused_when_it_is_written() {
    let (dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    let huge = Secret::Note { body: "x".repeat(log::MAX_BODY) };
    assert!(vault.add(&space, Meta::new(Kind::Note, "BIG"), &huge).is_err(), "it would vanish at the next start");
    vault.add(&space, Meta::new(Kind::Env, "AFTER"), &env("v")).unwrap();
    drop(vault);
    let mut vault = reopen(&dir.path().join("vault"));
    vault.unlock("test").unwrap();
    assert_eq!(vault.items(&space).unwrap().len(), 1);
}

/// A new vault at `home` with `record` properly enrolled, for tests of what comes after.
pub(crate) fn approval_for_tests(home: &Path, record: &crate::record::DeviceRecord) -> crate::store::Logs {
    let device = Software::generate(PASSPHRASE, Cost::FAST).unwrap();
    let setup = Setup::new(device);
    let words = setup.recovery().words().to_string();
    let mut vault = setup.create(home, "Test Mac").unwrap();
    vault.unlock("test").unwrap();
    let enrollment = vault.prepare_enrollment(record.clone(), "New").unwrap();
    let approvals = vec![vault.recovery_approval(&words, &enrollment.digest).unwrap()];
    vault.enroll(&enrollment, approvals).unwrap();
    vault.all_logs().unwrap()
}

/// Writes real logs for the fuzzers to start from. Run by `scripts/fuzz.sh`.
#[test]
#[ignore = "only for scripts/fuzz.sh"]
fn write_fuzz_seeds() {
    let (dir, mut vault, _) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    vault.add(&space, Meta::new(Kind::Env, "KEY"), &env("value")).unwrap();
    vault.record("add", "KEY", "this user").unwrap();
    let bytes = fs::read(own_log(&vault)).unwrap();
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    for (target, name, seed) in [("log", "whole", bytes.clone()), ("replay", "whole", bytes.clone()), ("noise_frames", "zeros", vec![0; 64])] {
        fs::create_dir_all(corpus.join(target)).unwrap();
        fs::write(corpus.join(target).join(name), seed).unwrap();
    }
    fs::create_dir_all(corpus.join("body")).unwrap();
    for entry in log::parse(&bytes).entries {
        fs::write(corpus.join("body").join(format!("kind-{}", entry.kind)), [&[entry.kind][..], &entry.body].concat()).unwrap();
    }
    fs::create_dir_all(corpus.join("icon")).unwrap();
    let mut icon = Vec::new();
    let mut encoder = png::Encoder::new(&mut icon, 16, 16);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.write_header().unwrap().write_image_data(&[90; 16 * 16 * 4]).unwrap();
    fs::write(corpus.join("icon").join("small"), icon).unwrap();
    fs::create_dir_all(corpus.join("archive")).unwrap();
    let logs = crate::store::Logs::from([(vault.me, bytes)]);
    fs::write(corpus.join("archive").join("one"), crate::store::encode_archive(&logs)).unwrap();
    drop(dir);
}
