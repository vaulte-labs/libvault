//! Spaces as a person shapes them: one name each, renamed and removed without losing anything.

mod support;

use libvault::item::Meta;
use libvault::{ErrorCode, FIRST_SPACE};
use support::{Vault, code, env};

#[test]
fn a_name_differing_only_by_case_or_spaces_is_the_same_space() {
    let vault = Vault::new();
    assert_eq!(vault.client().create_space(" Work ").unwrap(), "Work");
    assert_eq!(code(vault.client().create_space("work")), ErrorCode::Exists);
    assert_eq!(code(vault.client().create_space("Work")), ErrorCode::Exists);
    vault.add_env("KEY", "value", Some("work"));
    assert_eq!(vault.client().items(Some("Work")).unwrap().len(), 1, "a lookup finds it however it is capitalised");
}

#[test]
fn a_renamed_space_keeps_its_items_and_its_grants() {
    let vault = Vault::new();
    vault.space("Work");
    vault.add_env("KEY", "value", Some("Work"));
    let token = vault.session("Work", "agent");
    assert_eq!(vault.client().rename_space("Work", "Clients").unwrap(), "Clients");
    assert_eq!(vault.client().spaces().unwrap(), ["Clients", FIRST_SPACE]);
    assert_eq!(vault.client().items(Some("Clients")).unwrap()[0].meta.name, "KEY");
    assert_eq!(vault.session_client(&token).items(None).unwrap()[0].space, "Clients");
    assert_eq!(code(vault.client().rename_space(FIRST_SPACE, "Mine")), ErrorCode::Error, "everything unnamed goes to Personal");
    vault.space("Other");
    assert_eq!(code(vault.client().rename_space("Other", "clients")), ErrorCode::Exists);
}

#[test]
fn only_an_empty_space_is_removed_and_making_it_again_brings_back_its_history() {
    let vault = Vault::new();
    vault.space("Work");
    vault.add_env("KEY", "value", Some("Work"));
    let refused = vault.client().remove_space("Work").unwrap_err().to_string();
    assert!(refused.contains("holds 1 item"), "{refused}");
    vault.client().remove(Some("Work"), "KEY").unwrap();
    vault.client().remove_space("Work").unwrap();
    assert_eq!(vault.client().spaces().unwrap(), [FIRST_SPACE]);
    assert_eq!(code(vault.client().items(Some("Work"))), ErrorCode::NotFound);
    assert_eq!(code(vault.client().remove_space(FIRST_SPACE)), ErrorCode::Error);

    vault.client().create_space("Work").unwrap();
    vault.client().restore(Some("Work"), "KEY", 0).unwrap();
    assert!(matches!(vault.client().reveal(Some("Work"), "KEY").unwrap(), libvault::item::Secret::Env { ref value } if value == "value"));
}

#[test]
fn removing_a_space_ends_the_grants_on_it() {
    let vault = Vault::new();
    vault.space("Work");
    let token = vault.session("Work", "agent");
    vault.client().remove_space("Work").unwrap();
    assert_eq!(code(vault.session_client(&token).add(None, Meta::env("KEY"), env("value"), false)), ErrorCode::Denied);
}

#[test]
fn a_session_cannot_rename_or_remove_a_space() {
    let vault = Vault::new();
    vault.space("Work");
    let token = vault.session("Work", "agent");
    assert_eq!(code(vault.session_client(&token).rename_space("Work", "Mine")), ErrorCode::Denied);
    assert_eq!(code(vault.session_client(&token).remove_space("Work")), ErrorCode::Denied);
}
