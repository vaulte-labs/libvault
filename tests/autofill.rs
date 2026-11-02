//! What the system's autofill may suggest: each login's sites and username, and nothing else.

mod support;

use std::fs;

use libvault::item::{Kind, Meta, Secret};
use libvault::{AutofillIdentity, ErrorCode};
use support::{Vault, code, env};

fn identity(site: &str, username: Option<&str>, name: &str) -> AutofillIdentity {
    AutofillIdentity { site: site.to_owned(), username: username.map(str::to_owned), space: "Personal".to_owned(), name: name.to_owned() }
}

fn with_logins(vault: &Vault) {
    let mut client = vault.client();
    let mut github = Meta::login("github.com");
    github.username = Some("me".to_owned());
    github.urls.push("https://gist.github.com/login".to_owned());
    client.add(None, github, Secret::Login { password: "hunter2-secret".to_owned(), totp: Some("JBSWY3DPEHPK3PXP".to_owned()) }, false).unwrap();
    client.add(None, Meta::login("No site anywhere"), Secret::Login { password: "x".to_owned(), totp: None }, false).unwrap();
    let mut note = Meta::new(Kind::Note, "plans");
    note.urls.push("https://plans.example.com".to_owned());
    client.add(None, note, Secret::Note { body: "x".to_owned() }, false).unwrap();
    client.add(None, Meta::env("API_KEY"), env("value"), false).unwrap();
}

#[test]
fn each_logins_sites_and_username_are_listed_and_nothing_secret() {
    let vault = Vault::new();
    with_logins(&vault);
    fs::write(vault.home.join("deny"), "").unwrap();
    let identities = vault.client().autofill_identities().unwrap();
    assert_eq!(identities, [identity("github.com", Some("me"), "github.com"), identity("gist.github.com", Some("me"), "github.com")]);
    let sent = serde_json::to_string(&identities).unwrap();
    assert!(!sent.contains("hunter2") && !sent.contains("JBSWY3DP"), "{sent}");
}

#[test]
fn an_agent_gets_no_autofill_list() {
    let vault = Vault::new();
    with_logins(&vault);
    let mut session = vault.session_client(&vault.session("Personal", "agent"));
    assert_eq!(code(session.autofill_identities()), ErrorCode::Denied);
}

#[test]
fn a_locked_vault_lists_nothing_and_asks_nobody() {
    let vault = Vault::new();
    with_logins(&vault);
    let mut client = vault.client();
    client.lock().unwrap();
    assert_eq!(code(client.autofill_identities()), ErrorCode::Locked);
    assert!(!client.status().unwrap().unlocked);
}
