//! Rules every interface gets from the library: what a grant may last, where a secret may go,
//! what replacing keeps, what history says, and what a passphrase prompt names.

mod support;

use std::time::Duration;

use libvault::item::{Kind, Meta, Secret};
use libvault::{Client, Connect, ErrorCode};
use support::{PASSPHRASE, Vault, code, env, options};
use zeroize::Zeroizing;

const SEED: &str = "JBSWY3DPEHPK3PXP";

fn login(password: &str, totp: Option<&str>) -> Secret {
    Secret::Login { password: password.to_owned(), totp: totp.map(str::to_owned) }
}

#[test]
fn a_grant_says_how_long_and_where_and_refuses_what_it_cannot_last() {
    let vault = Vault::new();
    let granted = vault.client().grant(None, "claude", Duration::from_secs(3600), None).unwrap();
    assert_eq!((granted.seconds, granted.space.as_str()), (3600, "Personal"));
    assert_eq!(code(vault.client().grant(None, "claude", Duration::ZERO, None)), ErrorCode::Error);
    let refused = vault.client().grant(None, "claude", Duration::from_hours(100_000), None).unwrap_err().to_string();
    assert!(refused.contains("at most 24 hours"), "{refused}");
}

#[test]
fn only_an_env_var_is_sent_to_a_host() {
    let vault = Vault::new();
    vault.client().add(None, Meta::login("github.com"), login("pw", None), false).unwrap();
    let refused = vault.client().allow(None, "github.com", "api.github.com").unwrap_err().to_string();
    assert!(refused.contains("github.com is not an env var"), "{refused}");
    assert_eq!(vault.client().item(None, "github.com").unwrap().meta.hosts, Vec::<String>::new());
}

#[test]
fn replacing_keeps_the_setup_key_and_never_changes_kind() {
    let vault = Vault::new();
    vault.client().add(None, Meta::login("github.com"), login("old", Some(SEED)), false).unwrap();
    vault.client().add(None, Meta::login("github.com"), login("new", None), true).unwrap();
    assert!(vault.client().item(None, "github.com").unwrap().meta.two_factor);
    assert!(vault.client().code(None, "github.com").is_ok());
    assert_eq!(code(vault.client().add(None, Meta::new(Kind::Env, "github.com"), env("v"), true)), ErrorCode::Error);
}

#[test]
fn history_names_each_version_what_it_changed_and_which_is_current() {
    let vault = Vault::new();
    vault.add_env("KEY", "one", None);
    vault.client().add(None, Meta::env("KEY"), env("two"), true).unwrap();
    vault.client().edit(None, "KEY", Meta::env("RENAMED"), None).unwrap();
    let versions = vault.client().history(None, "RENAMED").unwrap();
    let changed: Vec<Vec<String>> = versions.iter().map(|version| version.changed.clone()).collect();
    assert_eq!(changed, [vec![], vec!["secret".to_owned()], vec!["name".to_owned()]]);
    assert_eq!(versions.iter().map(|version| version.current).collect::<Vec<_>>(), [false, false, true]);
    assert_eq!(versions[0].name, "KEY");
}

#[test]
fn the_same_import_twice_adds_nothing_even_where_a_name_clashed() {
    let vault = Vault::new();
    vault.add_env("KEY", "held", None);
    let items = || vec![(Meta::env("KEY"), env("imported"))];
    assert_eq!(vault.client().import(None, items()).unwrap().renamed, 1);
    let again = vault.client().import(None, items()).unwrap();
    assert_eq!((again.added, again.skipped), (0, 1));
}

#[allow(clippy::unnecessary_wraps, reason = "it has the shape a passphrase prompt takes")]
fn passphrase_for_reveal(reason: &str) -> libvault::Result<Zeroizing<String>> {
    assert_eq!(reason, "reveal KEY from Personal");
    Ok(Zeroizing::new(PASSPHRASE.to_owned()))
}

#[test]
fn a_passphrase_is_asked_for_by_what_it_approves_and_the_request_goes_again() {
    let vault = Vault::new();
    vault.add_env("KEY", "the-secret", None);
    let mut client = Client::connect(&vault.home, Connect { passphrase: None, ..options(None) }).unwrap();
    assert!(client.items(None).is_ok(), "nothing is asked for what needs no approval");
    let needed = client.reveal(None, "KEY").unwrap_err();
    assert_eq!(needed.to_string(), "a passphrase is needed to reveal KEY from Personal");
    client.ask_for_passphrase_with(passphrase_for_reveal);
    assert!(matches!(client.reveal(None, "KEY").unwrap(), Secret::Env { ref value } if value == "the-secret"));
}
