//! What an interface can do with an item once it exists.

mod support;

use std::fs;
use std::time::Duration;

use libvault::item::{Kind, Meta, Secret};
use libvault::{Client, ErrorCode};
use support::{Vault, code, env, options};

const SEED: &str = "JBSWY3DPEHPK3PXP";

fn login(password: &str, totp: Option<&str>) -> Secret {
    Secret::Login { password: password.to_owned(), totp: totp.map(str::to_owned) }
}

fn with_two_factor(vault: &Vault) {
    vault.client().add(None, Meta::login("github.com"), login("password", Some(SEED)), false).unwrap();
}

fn refuse_touches(vault: &Vault) -> impl FnOnce() {
    let deny = vault.home.join("deny");
    fs::write(&deny, "").unwrap();
    move || fs::remove_file(deny).unwrap()
}

#[test]
fn a_list_says_a_login_has_two_factor_without_a_touch() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let mut client = vault.client();
    client.add(None, Meta::login("plain.example"), login("password", None), false).unwrap();
    let allow = refuse_touches(&vault);
    assert!(client.item(None, "github.com").unwrap().meta.two_factor);
    assert!(!client.item(None, "plain.example").unwrap().meta.two_factor);
    allow();
}

#[test]
fn an_interface_cannot_claim_two_factor() {
    let vault = Vault::new();
    let mut client = vault.client();
    let mut meta = Meta::login("plain.example");
    meta.two_factor = true;
    client.add(None, meta, login("password", None), false).unwrap();
    assert!(!client.item(None, "plain.example").unwrap().meta.two_factor);
}

#[test]
fn a_code_comes_out_and_the_secret_behind_it_does_not() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let current = vault.client().code(None, "github.com").unwrap();
    assert_eq!(current.code.len(), 6);
    assert!(current.code.bytes().all(|byte| byte.is_ascii_digit()));
    assert!((1..=30).contains(&current.seconds_left), "{}", current.seconds_left);
    assert!(!serde_json::to_string(&current).unwrap().contains(SEED));
}

/// The codes a site would take right now, either side of a call that may cross a step.
fn codes_around(call: impl FnOnce() -> Vec<String>) -> (Vec<String>, [String; 2]) {
    let now = || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let totp = libvault::Totp::parse(SEED).unwrap();
    let before = totp.code(now());
    let codes = call();
    (codes, [before, totp.code(now())])
}

#[test]
fn a_code_is_the_one_the_site_expects_now() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let mut client = vault.client();
    let (codes, expected) = codes_around(|| vec![client.code(None, "github.com").unwrap().code]);
    assert!(expected.contains(&codes[0]), "{codes:?} against {expected:?}");
    let (codes, expected) = codes_around(|| client.codes(None).unwrap().into_iter().map(|code| code.code.code).collect());
    assert!(expected.contains(&codes[0]), "{codes:?} against {expected:?}");
}

#[test]
fn a_code_takes_a_touch_and_is_on_the_record() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let mut client = vault.client();
    let allow = refuse_touches(&vault);
    assert_eq!(code(client.code(None, "github.com")), ErrorCode::Denied);
    allow();
    client.code(None, "github.com").unwrap();
    assert!(client.audit().unwrap().iter().any(|event| event.action == "code" && event.target == "github.com"));
}

#[test]
fn only_a_login_with_two_factor_has_a_code() {
    let vault = Vault::new();
    vault.add_env("TOKEN", "value", None);
    let mut client = vault.client();
    client.add(None, Meta::login("plain.example"), login("password", None), false).unwrap();
    assert_eq!(code(client.code(None, "plain.example")), ErrorCode::NotFound);
    assert_eq!(code(client.code(None, "TOKEN")), ErrorCode::NotFound);
    assert_eq!(code(client.code(None, "nothing")), ErrorCode::NotFound);
}

#[test]
fn a_session_cannot_read_a_code() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let token = vault.client().grant(None, "agent", Duration::from_secs(60), None).unwrap().token;
    let mut session = Client::connect(&vault.home, options(Some(&token))).unwrap();
    assert_eq!(code(session.code(None, "github.com")), ErrorCode::Denied);
}

#[test]
fn renaming_keeps_the_secret_and_the_history() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let mut client = vault.client();
    let mut meta = client.item(None, "github.com").unwrap().meta;
    meta.name = "GitHub".to_owned();
    client.edit(None, "github.com", meta, None, false).unwrap();

    assert_eq!(code(client.item(None, "github.com")), ErrorCode::NotFound);
    assert_eq!(client.reveal(None, "GitHub").unwrap(), login("password", None));
    assert!(client.item(None, "GitHub").unwrap().meta.two_factor, "still derived from the secret it kept");
    assert!(client.code(None, "GitHub").is_ok());
    assert_eq!(client.history(None, "GitHub").unwrap().len(), 2);
}

#[test]
fn websites_can_be_added_without_touching_the_password() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let mut client = vault.client();
    let mut meta = client.item(None, "github.com").unwrap().meta;
    meta.urls.push("https://gist.github.com".to_owned());
    meta.username = Some("me".to_owned());
    client.edit(None, "github.com", meta, None, false).unwrap();
    let item = client.item(None, "github.com").unwrap();
    assert_eq!(item.meta.urls.len(), 2);
    assert_eq!(item.meta.username.as_deref(), Some("me"));
    assert!(client.fill_options("https://gist.github.com").unwrap().iter().any(|option| option.name == "github.com"));
}

#[test]
fn a_new_secret_replaces_the_old_and_undo_brings_it_back() {
    let vault = Vault::new();
    vault.add_env("KEY", "first", None);
    let mut client = vault.client();
    let meta = client.item(None, "KEY").unwrap().meta;
    client.edit(None, "KEY", meta, Some(env("second")), false).unwrap();
    assert_eq!(client.reveal(None, "KEY").unwrap(), env("second"));
    client.undo().unwrap();
    assert_eq!(client.reveal(None, "KEY").unwrap(), env("first"));
}

#[test]
fn a_reveal_gives_the_password_and_never_the_setup_key() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let mut client = vault.client();
    assert_eq!(client.reveal(None, "github.com").unwrap(), login("password", None));
    assert_eq!(client.code(None, "github.com").unwrap().code.len(), 6);
}

#[test]
fn a_new_password_keeps_two_factor_with_no_setup_key_sent() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let mut client = vault.client();
    let meta = client.item(None, "github.com").unwrap().meta;
    client.edit(None, "github.com", meta, Some(login("changed", None)), false).unwrap();
    assert_eq!(client.reveal(None, "github.com").unwrap(), login("changed", None));
    assert!(client.item(None, "github.com").unwrap().meta.two_factor);
    assert!(client.code(None, "github.com").is_ok());
}

#[test]
fn removing_two_factor_is_part_of_one_edit_that_one_undo_reverses() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let mut client = vault.client();
    let mut meta = client.item(None, "github.com").unwrap().meta;
    meta.username = Some("renamed".to_owned());
    client.edit(None, "github.com", meta.clone(), None, true).unwrap();
    let item = client.item(None, "github.com").unwrap();
    assert!(!item.meta.two_factor);
    assert_eq!(item.meta.username.as_deref(), Some("renamed"));
    assert_eq!(client.reveal(None, "github.com").unwrap(), login("password", None));
    assert_eq!(code(client.edit(None, "github.com", meta, None, true)), ErrorCode::NotFound, "there is no code left to take off");

    client.undo().unwrap();
    let item = client.item(None, "github.com").unwrap();
    assert!(item.meta.two_factor, "one undo brings the code back");
    assert_eq!(item.meta.username, None, "and the rest of the save with it");
}

#[test]
fn a_name_already_in_use_is_refused_and_nothing_changes() {
    let vault = Vault::new();
    vault.add_env("FIRST", "one", None);
    vault.add_env("SECOND", "two", None);
    let mut client = vault.client();
    let mut meta = client.item(None, "FIRST").unwrap().meta;
    meta.name = "SECOND".to_owned();
    assert_eq!(code(client.edit(None, "FIRST", meta, None, false)), ErrorCode::Error);
    assert_eq!(client.reveal(None, "FIRST").unwrap(), env("one"));
}

#[test]
fn an_item_cannot_change_kind() {
    let vault = Vault::new();
    vault.add_env("KEY", "value", None);
    let meta = Meta::new(Kind::Note, "KEY");
    assert_eq!(code(vault.client().edit(None, "KEY", meta, None, false)), ErrorCode::Error);
}

#[test]
fn an_edit_takes_a_touch() {
    let vault = Vault::new();
    vault.add_env("KEY", "value", None);
    let mut client = vault.client();
    let mut meta = client.item(None, "KEY").unwrap().meta;
    meta.name = "RENAMED".to_owned();
    let allow = refuse_touches(&vault);
    assert_eq!(code(client.edit(None, "KEY", meta, None, false)), ErrorCode::Denied);
    allow();
    assert!(client.item(None, "KEY").is_ok());
}

#[test]
fn a_session_needs_the_same_touch_to_edit() {
    let vault = Vault::new();
    vault.add_env("KEY", "value", None);
    let token = vault.client().grant(None, "agent", Duration::from_secs(60), None).unwrap().token;
    let mut session = Client::connect(&vault.home, options(Some(&token))).unwrap();
    let mut meta = session.item(None, "KEY").unwrap().meta;
    meta.name = "RENAMED".to_owned();
    let allow = refuse_touches(&vault);
    assert_eq!(code(session.edit(None, "KEY", meta, None, false)), ErrorCode::Denied);
    allow();
}

fn card(name: &str, expiry: &str) -> (Meta, Secret) {
    libvault::item::card(name, "4242424242424242", expiry.to_owned(), "123".to_owned(), "A Person".to_owned()).unwrap()
}

fn add_card(client: &mut Client, name: &str, expiry: &str) {
    let (meta, secret) = card(name, expiry);
    client.add(None, meta, secret, false).unwrap();
}

#[test]
fn a_cards_expiry_can_be_read_without_a_touch() {
    let vault = Vault::new();
    let mut client = vault.client();
    add_card(&mut client, "Visa", "12/30");
    let allow = refuse_touches(&vault);
    assert_eq!(client.item(None, "Visa").unwrap().meta.expires.as_deref(), Some("2030-12"));
    allow();
}

#[test]
fn a_card_with_no_real_expiry_is_refused() {
    let result = libvault::item::card("Visa", "4242424242424242", "soon".to_owned(), "123".to_owned(), "A Person".to_owned());
    assert!(result.is_err());
}

#[test]
fn only_cards_running_out_are_reported() {
    let vault = Vault::new();
    let mut client = vault.client();
    add_card(&mut client, "Long way off", "12/90");
    add_card(&mut client, "Old", "01/20");
    vault.add_env("KEY", "value", None);
    let expiring = client.expiring().unwrap();
    assert_eq!(expiring.iter().map(|item| item.meta.name.as_str()).collect::<Vec<_>>(), ["Old"]);
}

#[test]
fn a_new_expiry_moves_with_the_secret() {
    let vault = Vault::new();
    let mut client = vault.client();
    add_card(&mut client, "Visa", "01/20");
    let (meta, secret) = card("Visa", "12/90");
    client.edit(None, "Visa", meta, Some(secret), false).unwrap();
    assert_eq!(client.item(None, "Visa").unwrap().meta.expires.as_deref(), Some("2090-12"));
    assert!(client.expiring().unwrap().is_empty());
}

#[test]
fn asking_about_expiry_never_raises_a_prompt() {
    let vault = Vault::new();
    let mut client = vault.client();
    add_card(&mut client, "Old", "01/20");
    client.lock().unwrap();
    assert_eq!(code(client.expiring()), ErrorCode::Locked);
    assert!(!client.status().unwrap().unlocked);
}

#[test]
fn a_session_hears_only_about_its_own_space() {
    let vault = Vault::new();
    vault.space("Work");
    let mut client = vault.client();
    add_card(&mut client, "Personal card", "01/20");
    let (meta, secret) = card("Work card", "01/20");
    client.add(Some("Work"), meta, secret, false).unwrap();
    let token = client.grant(Some("Work"), "agent", Duration::from_secs(60), None).unwrap().token;
    let mut session = Client::connect(&vault.home, options(Some(&token))).unwrap();
    let expiring = session.expiring().unwrap();
    assert_eq!(expiring.iter().map(|item| item.meta.name.as_str()).collect::<Vec<_>>(), ["Work card"]);
}

#[test]
fn a_wifi_network_is_kept_and_stays_off_web_pages() {
    let vault = Vault::new();
    let mut client = vault.client();
    let password = Secret::Wifi { password: "correct horse".to_owned() };
    client.add(None, Meta::new(Kind::Wifi, "Home Network"), password.clone(), false).unwrap();
    assert_eq!(client.item(None, "Home Network").unwrap().meta.kind, Kind::Wifi);
    assert_eq!(client.reveal(None, "Home Network").unwrap(), password);
    assert!(client.fill_options("https://example.com").unwrap().is_empty());
    assert_eq!(code(client.fill("Personal", "Home Network", "https://example.com")), ErrorCode::Error);
}

#[test]
fn a_wifi_name_longer_than_any_network_is_refused() {
    let vault = Vault::new();
    let password = Secret::Wifi { password: "password".to_owned() };
    assert!(vault.client().add(None, Meta::new(Kind::Wifi, "x".repeat(33)), password, false).is_err());
}

#[test]
fn a_secret_with_nowhere_to_go_has_its_own_code_for_interfaces_to_explain() {
    let vault = Vault::new();
    vault.add_env("SOME_UNKNOWN_TOKEN", "value", None);
    let mut client = vault.client();
    let options = libvault::RunOptions { space: Some("Personal".to_owned()), env: Vec::new(), env_all: false };
    let error = libvault::run::run(&mut client, &[std::ffi::OsString::from("true")], &options).unwrap_err();
    assert_eq!(error.code(), ErrorCode::NeedsHost, "{error}");
    assert!(error.to_string().contains("SOME_UNKNOWN_TOKEN"), "{error}");
    assert_eq!(ErrorCode::NeedsHost.exit_code(), 1);
}

#[test]
fn every_code_comes_out_in_one_call_with_one_record() {
    let vault = Vault::new();
    vault.space("Work");
    with_two_factor(&vault);
    let mut client = vault.client();
    client.add(Some("Work"), Meta::login("gitlab.com"), login("password", Some(SEED)), false).unwrap();
    client.add(None, Meta::login("plain.example"), login("password", None), false).unwrap();
    let records = |client: &mut Client| client.audit().unwrap().iter().filter(|event| event.action == "codes").count();
    let codes = client.codes(None).unwrap();
    let mut shown: Vec<(&str, &str)> = codes.iter().map(|code| (code.space.as_str(), code.name.as_str())).collect();
    shown.sort_unstable();
    assert_eq!(shown, [("Personal", "github.com"), ("Work", "gitlab.com")]);
    assert!(codes.iter().all(|code| code.code.code.len() == 6));
    assert_eq!(records(&mut client), 1);
    assert_eq!(client.codes(Some("Work")).unwrap().len(), 1);
    assert_eq!(records(&mut client), 2);
}

#[test]
fn every_code_at_once_takes_a_touch_and_no_session_gets_them() {
    let vault = Vault::new();
    with_two_factor(&vault);
    let mut session = Client::connect(&vault.home, options(Some(&vault.session("Personal", "agent")))).unwrap();
    assert_eq!(code(session.codes(None)), ErrorCode::Denied);
    let allow = refuse_touches(&vault);
    assert_eq!(code(vault.client().codes(None)), ErrorCode::Denied);
    allow();
}

#[test]
fn history_says_what_a_restore_or_an_undo_brought_back_and_which_versions_match_now() {
    let vault = Vault::new();
    vault.add_env("KEY", "first", None);
    let mut client = vault.client();
    let meta = client.item(None, "KEY").unwrap().meta;
    client.edit(None, "KEY", meta, Some(env("second")), false).unwrap();
    client.restore(None, "KEY", 0).unwrap();
    let flags = |client: &mut libvault::Client| -> Vec<(bool, bool)> {
        client.history(None, "KEY").unwrap().iter().map(|version| (version.restored, version.identical)).collect()
    };
    assert_eq!(flags(&mut client), [(false, true), (false, false), (true, true)], "the first holds what the restore brought back");

    client.undo().unwrap();
    assert_eq!(flags(&mut client), [(false, false), (false, true), (true, false), (true, true)], "an undo brings back a version too");

    client.remove(None, "KEY").unwrap();
    assert!(client.history(None, "KEY").unwrap().iter().all(|version| !version.identical), "a deleted item holds nothing to match");
}
