//! A person's details for forms, and the rules every item meets before it is written.

mod support;

use std::fs;

use libvault::ErrorCode;
use libvault::item::{Kind, Meta, Profile, Secret};
use support::{Vault, code, env};

fn jane() -> Secret {
    Secret::Profile(Profile {
        first_name: "Jane".into(),
        last_name: "Doe".into(),
        email: "jane@example.com".into(),
        phone: "+1 555 010 0199".into(),
        birth_date: "1990-04-21".into(),
        address_line1: "1 Main St".into(),
        city: "Springfield".into(),
        postal_code: "62701".into(),
        country: "US".into(),
        ..Profile::default()
    })
}

fn with_profile(vault: &Vault) {
    let mut meta = Meta::new(Kind::Profile, "Home");
    meta.hint = Some("Jane Doe, Springfield".to_owned());
    vault.client().add(None, meta, jane(), false).unwrap();
}

#[test]
fn a_profile_is_listed_by_its_name_alone() {
    let vault = Vault::new();
    with_profile(&vault);
    let listed = vault.client().items(None).unwrap();
    assert_eq!((listed[0].meta.name.as_str(), listed[0].meta.hint.as_deref()), ("Home", None));
    let shown = serde_json::to_string(&listed).unwrap();
    assert!(!shown.contains("Jane") && !shown.contains("Springfield"), "{shown}");
}

#[test]
fn a_profile_is_offered_on_any_form_and_sent_only_to_a_secure_page() {
    let vault = Vault::new();
    with_profile(&vault);
    let mut client = vault.client();
    let offered = client.fill_options("https://shop.example/checkout").unwrap();
    assert_eq!(offered.iter().map(|option| (option.name.as_str(), option.kind)).collect::<Vec<_>>(), [("Home", Kind::Profile)]);
    assert_eq!(client.fill("Personal", "Home", "https://shop.example/checkout").unwrap().secret, jane());
    assert_eq!(code(client.fill("Personal", "Home", "http://shop.example/checkout")), ErrorCode::Denied);
}

#[test]
fn an_agent_never_gets_a_profile_onto_a_page() {
    let vault = Vault::new();
    with_profile(&vault);
    let mut session = vault.session_client(&vault.session("Personal", "agent"));
    assert_eq!(code(session.fill("Personal", "Home", "https://shop.example")), ErrorCode::Denied);
}

#[test]
fn details_no_form_would_take_are_refused_before_anyone_is_asked() {
    let vault = Vault::new();
    fs::write(vault.home.join("deny"), "").unwrap();
    let mut client = vault.client();
    let typo = Secret::Profile(Profile { email: "jane.example.com".into(), ..Profile::default() });
    assert_eq!(code(client.add(None, Meta::new(Kind::Profile, "Home"), typo, false)), ErrorCode::Error);
    assert_eq!(code(client.add(None, Meta::new(Kind::Profile, "Home"), env("not a profile"), false)), ErrorCode::Error);
}

#[test]
fn an_edited_card_has_its_number_checked_and_its_hint_rebuilt() {
    let vault = Vault::new();
    let mut client = vault.client();
    let (meta, secret) = libvault::item::card("Card", "4242 4242 4242 4242", "12/30".into(), "123".into(), "Jane Doe".into()).unwrap();
    client.add(None, meta.clone(), secret, false).unwrap();
    let new_card = |number: &str| Secret::Card { number: number.into(), expiry: "12/30".into(), cvc: "123".into(), holder: "Jane Doe".into() };

    client.edit(None, "Card", meta.clone(), Some(new_card("5555555555554444"))).unwrap();
    assert_eq!(client.item(None, "Card").unwrap().meta.hint.as_deref(), Some("Mastercard 4444"));
    assert_eq!(code(client.edit(None, "Card", meta, Some(new_card("4242424242424241")))), ErrorCode::Error);
    assert_eq!(client.item(None, "Card").unwrap().meta.hint.as_deref(), Some("Mastercard 4444"));
}
