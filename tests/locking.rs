//! When a device's vault locks by itself, as its person chose.

mod support;

use std::fs;
use std::time::Duration;

use libvault::{ErrorCode, LockSettings, StayUnlocked};
use support::{Vault, code};

const STAY_OPEN: LockSettings = LockSettings { stay_unlocked: StayUnlocked::Never, with_screen: false };

#[test]
fn a_new_device_stays_unlocked_an_hour_and_locks_with_the_screen() {
    let vault = Vault::new();
    assert_eq!(vault.client().lock_settings().unwrap(), LockSettings { stay_unlocked: StayUnlocked::OneHour, with_screen: true });
}

#[test]
fn changing_when_it_locks_takes_a_touch_and_no_agent_can() {
    let vault = Vault::new();
    let mut session = vault.session_client(&vault.session("Personal", "agent"));
    assert_eq!(code(session.set_lock_settings(STAY_OPEN)), ErrorCode::Denied);
    fs::write(vault.home.join("deny"), "").unwrap();
    assert_eq!(code(vault.client().set_lock_settings(STAY_OPEN)), ErrorCode::Denied);
    assert_eq!(vault.client().lock_settings().unwrap(), LockSettings::default());
}

#[test]
fn the_choice_outlives_a_restart_and_a_restart_still_locks() {
    let vault = Vault::new();
    let mut client = vault.client();
    client.unlock().unwrap();
    client.set_lock_settings(STAY_OPEN).unwrap();
    client.stop().unwrap();
    let mut client = vault.client();
    assert_eq!(client.lock_settings().unwrap(), STAY_OPEN);
    assert!(!client.status().unwrap().unlocked, "the keys were only ever in memory");
}

#[test]
fn a_locked_screen_leaves_the_vault_open_when_that_is_chosen() {
    let vault = Vault::new();
    let mut client = vault.client();
    client.unlock().unwrap();
    client.set_lock_settings(STAY_OPEN).unwrap();
    fs::write(vault.home.join("screen-locked"), "").unwrap();
    // The broker looks every two seconds.
    std::thread::sleep(Duration::from_secs(5));
    assert!(client.status().unwrap().unlocked);
    client.set_lock_settings(LockSettings { with_screen: true, ..STAY_OPEN }).unwrap();
    std::thread::sleep(Duration::from_secs(5));
    assert!(!client.status().unwrap().unlocked, "with the screen chosen again, it locks");
}
