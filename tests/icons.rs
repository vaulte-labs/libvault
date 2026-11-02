//! A website's icon: saved once, on every device, and never in anyone's way.

mod support;

use std::fs;
use std::time::Duration;

use libvault::item::{Meta, Secret};
use libvault::{Client, ErrorCode, Icon};
use support::{Vault, code, options, restored};

const SITE: &str = "https://github.com";

/// A real 16 pixel PNG in one shade, as a website might send it.
fn png(fill: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut encoder = ::png::Encoder::new(&mut bytes, 16, 16);
    encoder.set_color(::png::ColorType::Rgba);
    encoder.set_depth(::png::BitDepth::Eight);
    encoder.write_header().unwrap().write_image_data(&pixels(fill)).unwrap();
    bytes
}

fn pixels(fill: u8) -> Vec<u8> {
    [fill, fill, fill, 255].repeat(16 * 16)
}

/// What drawing `png(fill)` gives back.
fn drawn(fill: u8) -> Icon {
    Icon { width: 16, height: 16, rgba: pixels(fill) }
}

/// Icons never raise a prompt, so nothing here works on a locked vault.
fn unlocked(vault: &Vault) -> Client {
    let mut client = vault.client();
    client.unlock().unwrap();
    client
}

fn login(vault: &Vault, name: &str) {
    let secret = Secret::Login { password: "password".to_owned(), totp: None };
    vault.client().add(None, Meta::login(name), secret, false).unwrap();
}

#[test]
fn an_icon_comes_back_exactly_as_it_was_saved() {
    let vault = Vault::new();
    let mut client = unlocked(&vault);
    assert_eq!(client.icon(None, SITE).unwrap(), None);
    client.save_icon(None, SITE, &png(7)).unwrap();
    assert_eq!(client.icon(None, SITE).unwrap(), Some(drawn(7)));
}

#[test]
fn a_site_shares_one_icon_however_it_is_written() {
    let vault = Vault::new();
    let mut client = unlocked(&vault);
    client.save_icon(None, "https://www.github.com/login", &png(7)).unwrap();
    assert_eq!(client.icon(None, "http://github.com").unwrap(), Some(drawn(7)));
    assert_eq!(client.icon(None, "https://gist.github.com").unwrap(), None);
}

#[test]
fn the_first_icon_stays() {
    let vault = Vault::new();
    let mut client = unlocked(&vault);
    client.save_icon(None, SITE, &png(1)).unwrap();
    client.save_icon(None, SITE, &png(2)).unwrap();
    assert_eq!(client.icon(None, SITE).unwrap(), Some(drawn(1)));
}

#[test]
fn an_icon_stays_out_of_everything_a_person_sees() {
    let vault = Vault::new();
    login(&vault, "github.com");
    let mut client = unlocked(&vault);
    client.save_icon(None, SITE, &png(7)).unwrap();

    let names: Vec<String> = client.items(None).unwrap().into_iter().map(|item| item.meta.name).collect();
    assert_eq!(names, ["github.com"]);
    assert_eq!(code(client.item(None, "icon:github.com")), ErrorCode::NotFound);
    assert_eq!(code(client.reveal(None, "icon:github.com")), ErrorCode::NotFound);
    assert_eq!(client.fill_options(SITE).unwrap().len(), 1, "only the login");
    assert!(client.expiring().unwrap().is_empty());

    let path = vault.dir.path().join("everything.json");
    client.export_plaintext(&path, None).unwrap();
    assert!(!fs::read_to_string(path).unwrap().contains("icon:"));
}

#[test]
fn a_login_named_like_an_icon_is_still_just_a_login() {
    let vault = Vault::new();
    let mut client = unlocked(&vault);
    client.save_icon(None, SITE, &png(7)).unwrap();
    login(&vault, "icon:github.com");
    assert_eq!(client.item(None, "icon:github.com").unwrap().meta.name, "icon:github.com");
    assert_eq!(client.icon(None, SITE).unwrap(), Some(drawn(7)));
}

#[test]
fn undo_passes_over_an_icon_to_what_the_person_did() {
    let vault = Vault::new();
    login(&vault, "github.com");
    let mut client = unlocked(&vault);
    client.save_icon(None, SITE, &png(7)).unwrap();
    assert_eq!(client.undo().unwrap(), 1);
    assert_eq!(code(client.item(None, "github.com")), ErrorCode::NotFound, "the login went");
    assert_eq!(client.icon(None, SITE).unwrap(), Some(drawn(7)), "the icon did not");
}

#[test]
fn another_device_gets_the_icon_without_asking_the_site() {
    let vault = Vault::new();
    unlocked(&vault).save_icon(None, SITE, &png(7)).unwrap();
    let archive = vault.dir.path().join("copy.vaulty");
    vault.client().export_archive(&archive).unwrap();

    let other = restored(&archive, &vault.words, "Other Mac");
    assert_eq!(unlocked(&other).icon(None, SITE).unwrap(), Some(drawn(7)));
}

#[test]
fn a_locked_vault_says_so_and_raises_no_prompt() {
    let vault = Vault::new();
    let mut client = unlocked(&vault);
    client.save_icon(None, SITE, &png(7)).unwrap();
    client.lock().unwrap();
    assert_eq!(code(client.icon(None, SITE)), ErrorCode::Locked);
    assert_eq!(code(client.save_icon(None, "https://example.com", &png(7))), ErrorCode::Locked);
    assert!(!client.status().unwrap().unlocked);
}

#[test]
fn a_session_reads_its_own_space_and_cannot_write() {
    let vault = Vault::new();
    vault.space("Work");
    let mut client = unlocked(&vault);
    client.save_icon(Some("Work"), SITE, &png(1)).unwrap();
    client.save_icon(None, SITE, &png(2)).unwrap();
    let (token, _) = client.grant(Some("Work"), "agent", Duration::from_secs(60), None).unwrap();
    let mut session = Client::connect(&vault.home, options(Some(&token))).unwrap();

    assert_eq!(session.icon(None, SITE).unwrap(), Some(drawn(1)));
    assert_eq!(code(session.icon(Some("Personal"), SITE)), ErrorCode::Denied);
    assert_eq!(code(session.save_icon(None, "https://example.com", &png(1))), ErrorCode::Denied);
}

#[test]
fn what_is_not_a_small_png_is_refused_and_nothing_is_written() {
    let vault = Vault::new();
    let mut client = unlocked(&vault);
    assert!(client.save_icon(None, SITE, b"<svg onload=alert(1)>").is_err());
    assert!(client.save_icon(None, SITE, &[0; 100]).is_err());
    assert!(client.save_icon(None, SITE, &png(1)[..40]).is_err());
    assert_eq!(client.icon(None, SITE).unwrap(), None);
}
