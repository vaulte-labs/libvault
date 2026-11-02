//! The vault's own apps, whose signature the broker checks, use an open vault without a touch for
//! every use. Tests cannot sign themselves, so `trust-callers` stands in for a signed app.

mod support;

use std::fs;

use libvault::item::{Meta, Secret};
use libvault::{Client, ErrorCode};
use support::{Vault, code, env, options};

fn refusing_touches(vault: &Vault) {
    fs::write(vault.home.join("deny"), "").unwrap();
}

fn trusting_callers(vault: &Vault) {
    fs::write(vault.home.join("trust-callers"), "").unwrap();
}

fn with_a_login(vault: &Vault) {
    let secret = Secret::Login { password: "hunter2".to_owned(), totp: Some("JBSWY3DPEHPK3PXP".to_owned()) };
    vault.client().add(None, Meta::login("github.com"), secret, false).unwrap();
}

#[test]
fn a_caller_whose_signature_is_not_the_apps_is_asked_every_time() {
    let vault = Vault::new();
    with_a_login(&vault);
    vault.client().unlock().unwrap();
    refusing_touches(&vault);
    assert_eq!(code(vault.client().reveal(None, "github.com")), ErrorCode::Denied, "this test is no signed app");
}

#[test]
fn the_app_reveals_fills_and_edits_without_a_touch_once_unlocked() {
    let vault = Vault::new();
    with_a_login(&vault);
    vault.client().unlock().unwrap();
    trusting_callers(&vault);
    refusing_touches(&vault);
    let mut app = vault.client();
    assert_eq!(app.reveal(None, "github.com").unwrap(), Secret::Login { password: "hunter2".to_owned(), totp: None });
    assert!(app.code(None, "github.com").is_ok());
    assert!(app.fill("Personal", "github.com", "https://github.com").is_ok());
    app.add(None, Meta::env("KEY"), env("v"), false).unwrap();
    app.remove(None, "KEY").unwrap();
}

#[test]
fn status_says_whether_the_caller_is_the_vaults_own_app() {
    let vault = Vault::new();
    assert!(!vault.client().status().unwrap().trusted, "this test is no signed app");
    trusting_callers(&vault);
    assert!(vault.client().status().unwrap().trusted);
}

#[test]
fn the_app_shows_every_code_without_a_touch_once_unlocked() {
    let vault = Vault::new();
    with_a_login(&vault);
    vault.client().unlock().unwrap();
    trusting_callers(&vault);
    refusing_touches(&vault);
    assert_eq!(vault.client().codes(None).unwrap().len(), 1);
}

#[test]
fn the_app_still_needs_a_touch_for_what_widens_access() {
    let vault = Vault::new();
    vault.client().unlock().unwrap();
    trusting_callers(&vault);
    refusing_touches(&vault);
    let mut app = vault.client();
    assert_eq!(code(app.export_archive(&vault.dir.path().join("copy"))), ErrorCode::Denied);
    assert_eq!(code(app.set_lock_settings(libvault::LockSettings::default())), ErrorCode::Denied);
    assert_eq!(code(app.grant(None, "agent", std::time::Duration::from_secs(60), None)), ErrorCode::Denied);
}

#[test]
fn opening_a_locked_vault_still_takes_the_one_touch() {
    let vault = Vault::new();
    with_a_login(&vault);
    trusting_callers(&vault);
    let mut app = vault.client();
    app.lock().unwrap();
    refusing_touches(&vault);
    assert!(matches!(code(app.reveal(None, "github.com")), ErrorCode::Denied | ErrorCode::Locked));
    assert!(!app.status().unwrap().unlocked);
}

#[test]
fn an_agents_session_is_a_session_whoever_carries_it() {
    let vault = Vault::new();
    with_a_login(&vault);
    trusting_callers(&vault);
    let mut session = vault.session_client(&vault.session("Personal", "agent"));
    assert_eq!(code(session.code(None, "github.com")), ErrorCode::Denied);
    assert_eq!(code(session.fill("Personal", "github.com", "https://github.com")), ErrorCode::Denied);
}

/// The app group's container in tests, which the broker opens when it is there.
fn shared_folder(vault: &Vault) -> std::path::PathBuf {
    let folder = vault.home.join("shared");
    fs::create_dir(&folder).unwrap();
    folder
}

/// The app group is Apple's, so only a Mac has the shared socket.
#[cfg(target_os = "macos")]
#[test]
fn sandboxed_code_reaches_a_running_broker_through_the_shared_folder_and_meets_the_same_checks() {
    let vault = Vault::new();
    let shared = shared_folder(&vault);
    with_a_login(&vault);
    let mut sandboxed = Client::connect_shared(&shared, options(None)).unwrap();
    assert_eq!(sandboxed.items(None).unwrap().len(), 1);
    refusing_touches(&vault);
    assert_eq!(code(sandboxed.reveal(None, "github.com")), ErrorCode::Denied, "no more trusted than at the main socket");
}

#[test]
fn sandboxed_code_with_no_broker_running_is_told_to_open_the_app() {
    let vault = Vault::new();
    let shared = shared_folder(&vault);
    vault.client().stop().unwrap();
    let error = Client::connect_shared(&shared, options(None)).unwrap_err();
    assert!(error.to_string().contains("Open Vaulty"), "{error}");
}

#[test]
fn a_shared_folder_too_deep_for_a_socket_says_so() {
    let vault = Vault::new();
    let deep = vault.dir.path().join("a".repeat(120));
    let error = Client::connect_shared(&deep, options(None)).unwrap_err();
    assert!(error.to_string().contains("too long"), "{error}");
}
