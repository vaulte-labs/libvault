//! Passkeys made and used for a site through the broker, as a browser extension would.

mod support;

use std::fs;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use libvault::item::{Kind, Meta, Secret};
use libvault::{Client, ErrorCode, NewPasskey, PasskeyRequest};
use support::{Vault, code};

const SITE: &str = "https://github.com/login";

fn request(origin: &str, rp_id: &str) -> PasskeyRequest {
    PasskeyRequest {
        space: None,
        origin: origin.to_owned(),
        rp_id: rp_id.to_owned(),
        user_name: "alice".to_owned(),
        user_handle: b"user-1".to_vec(),
        exclude: Vec::new(),
    }
}

fn made(vault: &Vault) -> (Client, NewPasskey) {
    let mut client = vault.client();
    client.unlock().unwrap();
    let created = client.create_passkey(request(SITE, "github.com")).unwrap();
    (client, created)
}

fn client_data_hash() -> Vec<u8> {
    digest(&SHA256, br#"{"type":"webauthn.get","challenge":"abc","origin":"https://github.com"}"#).as_ref().to_vec()
}

#[test]
fn a_passkey_made_for_a_site_signs_in_there_and_the_site_can_check_it() {
    let vault = Vault::new();
    let (mut client, created) = made(&vault);
    assert_eq!(created.name, "alice on github.com");
    let offered = client.passkey_options(SITE, Vec::new()).unwrap();
    assert_eq!(offered.iter().map(|option| option.name.as_str()).collect::<Vec<_>>(), ["alice on github.com"]);
    let assertion = client.sign_passkey("Personal", &created.name, "https://github.com", &client_data_hash()).unwrap();
    assert_eq!(assertion.credential_id, created.credential_id);
    let signed = [assertion.authenticator_data.as_slice(), &client_data_hash()].concat();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &created.public_key[26..]).verify(&signed, &assertion.signature).unwrap();
}

#[test]
fn another_site_never_sees_or_uses_it_or_makes_one_for_it() {
    let vault = Vault::new();
    let (mut client, created) = made(&vault);
    assert_eq!(client.passkey_options("https://evil.example", Vec::new()).unwrap(), []);
    assert_eq!(code(client.sign_passkey("Personal", &created.name, "https://evil.example", &client_data_hash())), ErrorCode::Denied);
    assert_eq!(code(client.create_passkey(request("https://evil.example", "github.com"))), ErrorCode::Denied);
    assert_eq!(code(client.create_passkey(request("https://example.co.uk", "co.uk"))), ErrorCode::Denied);
}

#[test]
fn a_site_naming_its_own_credentials_gets_only_those() {
    let vault = Vault::new();
    let (mut client, created) = made(&vault);
    assert_eq!(client.passkey_options(SITE, vec![created.credential_id.clone()]).unwrap().len(), 1);
    assert_eq!(client.passkey_options(SITE, vec![vec![0; 32]]).unwrap(), []);
    let again = PasskeyRequest { exclude: vec![created.credential_id], ..request(SITE, "github.com") };
    assert_eq!(code(client.create_passkey(again)), ErrorCode::Exists, "it was made here before");
}

#[test]
fn making_or_using_a_passkey_takes_a_touch_even_for_the_vaults_own_app() {
    let vault = Vault::new();
    let (_, created) = made(&vault);
    fs::write(vault.home.join("trust-callers"), "").unwrap();
    fs::write(vault.home.join("deny"), "").unwrap();
    let mut app = vault.client();
    assert_eq!(code(app.sign_passkey("Personal", &created.name, "https://github.com", &client_data_hash())), ErrorCode::Denied);
    assert_eq!(code(app.create_passkey(request(SITE, "github.com"))), ErrorCode::Denied);
    assert_eq!(app.passkey_options(SITE, Vec::new()).unwrap().len(), 1, "listing needs no touch");
}

#[test]
fn an_agent_lists_no_passkeys_and_makes_or_uses_one_only_with_a_touch() {
    let vault = Vault::new();
    let (_, created) = made(&vault);
    vault.space("work");
    let mut elsewhere = vault.session_client(&vault.session("work", "agent"));
    let mut agent = vault.session_client(&vault.session("Personal", "agent"));
    assert_eq!(code(agent.passkey_options(SITE, Vec::new())), ErrorCode::Denied);
    vault.deny_touches();
    assert_eq!(code(agent.create_passkey(request(SITE, "github.com"))), ErrorCode::Denied);
    assert_eq!(code(agent.sign_passkey("Personal", &created.name, "https://github.com", &client_data_hash())), ErrorCode::Denied);
    vault.allow_touches();
    assert!(agent.sign_passkey("Personal", &created.name, "https://github.com", &client_data_hash()).is_ok());
    let outside = elsewhere.sign_passkey("Personal", &created.name, "https://github.com", &client_data_hash());
    assert_eq!(code(outside), ErrorCode::Denied, "a grant reaches only its own space");
}

#[test]
fn the_private_key_never_leaves_the_broker_and_none_can_be_handed_in() {
    let vault = Vault::new();
    let (mut client, created) = made(&vault);
    let revealed = client.reveal(None, &created.name).unwrap();
    let Secret::Passkey { private_key, rp_id, .. } = &revealed else { panic!("a passkey") };
    assert_eq!((private_key.as_str(), rp_id.as_str()), ("", "github.com"));
    let handed_in = Secret::Passkey { rp_id: "github.com".into(), user_handle: "x".into(), credential_id: "x".into(), private_key: "x".into() };
    assert_eq!(code(client.add(None, Meta::new(Kind::Passkey, "planted"), handed_in, false)), ErrorCode::Error);
}

#[test]
fn a_locked_vault_offers_nothing_and_asks_nobody() {
    let vault = Vault::new();
    let (mut client, _) = made(&vault);
    client.lock().unwrap();
    assert_eq!(code(client.passkey_options(SITE, Vec::new())), ErrorCode::Locked);
    assert!(!client.status().unwrap().unlocked);
}

#[test]
fn a_locked_vault_says_which_of_a_sites_credential_ids_are_its_own_and_nothing_else() {
    let vault = Vault::new();
    let (mut client, created) = made(&vault);
    let ids = vec![created.credential_id.clone(), vec![7; 32]];
    assert_eq!(client.passkeys_held(SITE, ids.clone()).unwrap(), [true, false]);
    let mut agent = vault.session_client(&vault.session("Personal", "agent"));
    assert_eq!(code(agent.passkeys_held(SITE, ids.clone())), ErrorCode::Denied, "only a person's browser asks");
    client.lock().unwrap();
    vault.deny_touches();

    let mut locked = vault.client();
    assert_eq!(locked.passkeys_held(SITE, ids.clone()).unwrap(), [true, false], "answered without unlocking");
    assert_eq!(locked.passkeys_held("https://gist.github.com", ids.clone()).unwrap(), [true, false], "a page under its site");
    assert_eq!(locked.passkeys_held("https://evil.example", ids.clone()).unwrap(), [false, false], "another site learns nothing");
    assert_eq!(locked.passkeys_held("http://github.com", ids).unwrap(), [false, false], "nor a page over plain HTTP");
    assert!(!locked.status().unwrap().unlocked);
}
