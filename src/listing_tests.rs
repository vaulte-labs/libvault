//! The rows must always be what opening everything would give, and must cost almost nothing.

use std::cell::Cell;

use tempfile::TempDir;

use super::*;
use crate::device::software::{Cost, Software};
use crate::item::{Kind, Secret};
use crate::state::State;
use crate::{FIRST_SPACE, Setup};

fn new_vault() -> (TempDir, Vault) {
    let dir = tempfile::tempdir().unwrap();
    let setup = Setup::new(Software::generate("pass", Cost::FAST).unwrap());
    let mut vault = setup.create(&dir.path().join("vault"), "Test").unwrap();
    vault.unlock("test").unwrap();
    (dir, vault)
}

fn env(value: &str) -> Secret {
    Secret::Env { value: value.to_owned() }
}

/// Env names are upper case, because a list leaves out what fails validation.
fn meta(name: &str) -> Meta {
    Meta::new(Kind::Env, name.to_uppercase().replace('-', "_"))
}

fn opens(work: impl FnOnce()) -> usize {
    let before = META_OPENED.with(Cell::get);
    work();
    META_OPENED.with(Cell::get) - before
}

fn assert_rows_are_true(vault: &Vault, space: &SpaceId) {
    let opened = vault.read_rows(space).items;
    assert_eq!(vault.items(space).unwrap(), opened);
    for row in &opened {
        assert_eq!(vault.find(space, &row.meta.name).unwrap().id, row.id);
    }
}

#[test]
fn rows_stay_true_through_every_kind_of_change() {
    let (_dir, mut vault) = new_vault();
    let first = vault.space(FIRST_SPACE).unwrap().id;
    vault.create_space("Work").unwrap();
    let work = vault.space("Work").unwrap().id;
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let mut next = |limit: usize| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        usize::try_from(seed % limit as u64).unwrap()
    };
    for made in 0..400 {
        let space = if next(2) == 0 { first } else { work };
        let existing = vault.items(&space).unwrap();
        let pick = (!existing.is_empty()).then(|| existing[next(existing.len())].id);
        match (next(7), pick) {
            (0, Some(id)) => vault.remove(&space, &id).unwrap(),
            (1, Some(id)) => vault.replace(&space, &id, &meta(&format!("renamed-{made}")), &env("new")).unwrap(),
            (2, _) if vault.undo().is_err() => {}
            (3, _) => {
                let many: Vec<_> = (0..3).map(|index| (meta(&format!("batch-{made}-{index}")), env("value"))).collect();
                vault.add_many(&space, &many).unwrap();
            }
            _ => drop(vault.add(&space, meta(&format!("item-{made}")), &env("value")).unwrap()),
        }
        assert_rows_are_true(&vault, &first);
        assert_rows_are_true(&vault, &work);
    }
    let rows = vault.items(&first).unwrap().len() + vault.items(&work).unwrap().len();
    assert!(rows > 50, "only {rows} rows, so this compared too little to mean anything");
}

#[test]
fn only_the_first_read_opens_everything() {
    let (_dir, mut vault) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    let items: Vec<_> = (0..50).map(|index| (meta(&format!("item-{index}")), env("value"))).collect();
    vault.add_many(&space, &items).unwrap();

    assert_eq!(opens(|| assert_eq!(vault.read_rows(&space).items.len(), 50)), 50, "what the rows save");
    assert_eq!(opens(|| assert_eq!(vault.items(&space).unwrap().len(), 50)), 0, "the batch carried its rows over");
    assert_eq!(opens(|| drop(vault.find(&space, "ITEM_7").unwrap())), 0);
    assert_eq!(
        opens(|| {
            vault.add(&space, meta("one-more"), &env("value")).unwrap();
        }),
        1,
        "only the new item"
    );
    let id = vault.find(&space, "ONE_MORE").unwrap().id;
    assert_eq!(opens(|| vault.remove(&space, &id).unwrap()), 2, "to see that it exists, and to reread its row");
}

#[test]
fn a_taken_name_is_refused_and_so_is_one_repeated_in_a_batch() {
    let (_dir, mut vault) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    vault.add(&space, meta("taken"), &env("value")).unwrap();
    assert!(matches!(vault.add(&space, meta("taken"), &env("value")), Err(Error::Exists(name)) if name == "TAKEN"));
    let repeated = [(meta("twice"), env("a")), (meta("twice"), env("b"))];
    assert!(matches!(vault.add_many(&space, &repeated), Err(Error::Exists(name)) if name == "TWICE"));
    assert!(matches!(vault.find(&space, "TWICE"), Err(Error::NotFound(_))), "a refused batch adds nothing");
}

#[test]
fn locking_takes_the_rows_with_it() {
    let (_dir, mut vault) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    vault.add(&space, meta("key"), &env("value")).unwrap();
    assert!(vault.find(&space, "KEY").is_ok());
    vault.lock();
    assert!(matches!(vault.find(&space, "KEY"), Err(Error::Locked)));
    assert!(matches!(vault.items(&space), Err(Error::Locked)));
    vault.unlock("test").unwrap();
    assert_rows_are_true(&vault, &space);
}

#[test]
fn a_different_state_gets_its_own_rows() {
    let (_dir, mut vault) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    let earlier = vault.state.clone();
    vault.add(&space, meta("later"), &env("value")).unwrap();
    assert!(vault.find(&space, "LATER").is_ok());

    // Merging and exporting both put a whole other state in place.
    let current = std::mem::replace(&mut vault.state, earlier);
    assert!(matches!(vault.find(&space, "LATER"), Err(Error::NotFound(_))), "the earlier state has no such item");
    vault.state = current;
    assert!(vault.find(&space, "LATER").is_ok());
    vault.state = State::from_logs(&crate::store::parse_all(&crate::store::read_logs(&vault.home).unwrap())).unwrap();
    assert_rows_are_true(&vault, &space);
}

#[test]
fn a_new_key_can_make_more_rows_readable() {
    let (_dir, mut vault) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    vault.add(&space, meta("key"), &env("value")).unwrap();
    assert_eq!(opens(|| drop(vault.items(&space).unwrap())), 0);
    let keys = vault.keys.as_mut().unwrap();
    let (epoch, key) = keys.epochs.iter().next().map(|(epoch, key)| (*epoch, key.clone())).unwrap();
    keys.epochs.insert(Generation { number: epoch.number + 1, ..epoch }, key);
    assert_eq!(opens(|| drop(vault.items(&space).unwrap())), 1, "so a new key means reading again");
}

#[test]
fn a_change_made_without_reading_first_does_not_keep_rows_from_another_state() {
    let (_dir, mut vault) = new_vault();
    let space = vault.space(FIRST_SPACE).unwrap().id;
    let gone = vault.add(&space, meta("gone"), &env("value")).unwrap();
    let earlier = vault.state.clone();
    vault.add(&space, meta("later"), &env("value")).unwrap();
    let current = std::mem::replace(&mut vault.state, earlier);
    drop(vault.items(&space).unwrap());
    vault.state = current;

    // Removing reads the state, not the rows, so the rows from before are still stale here.
    vault.remove(&space, &gone).unwrap();
    assert!(vault.find(&space, "LATER").is_ok());
    assert_rows_are_true(&vault, &space);
}
