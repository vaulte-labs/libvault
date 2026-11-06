//! Flows 6 and 13 between real brokers: pairing, direct sync, and what a stranger or a removed
//! device can do.

mod support;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use libvault::item::{Meta, Secret};
use libvault::{Client, Cost, ErrorCode, Join, RecoveryDraft};
use support::{PASSPHRASE, Vault, code, env, options, restored};

fn value(client: &mut Client, space: Option<&str>, name: &str) -> String {
    match &client.reveal(space, name).unwrap() {
        Secret::Env { value } => value.clone(),
        other => panic!("not an env var: {other:?}"),
    }
}

/// Pairs a new device with `adder`, the way two people at two screens would.
fn pair(adder: &Vault, name: &str, recovery: Option<&str>) -> Vault {
    pair_with(adder, Join::with_passphrase(PASSPHRASE, Cost::FAST, name).unwrap(), recovery, None)
}

/// As `pair`, with how the new device joins, and for a server, the spaces it may hold.
fn pair_with(adder: &Vault, join: Join, recovery: Option<&str>, spaces: Option<&[&str]>) -> Vault {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let port = join.port().unwrap();

    let waiting = std::thread::spawn(move || {
        let pending = join.wait(Duration::from_secs(10)).unwrap();
        let words = pending.words().clone();
        pending.confirm(&home).unwrap();
        (words, home)
    });
    let mut client = adder.client();
    let words = client.begin_pairing(Some(&format!("127.0.0.1:{port}"))).unwrap();
    client.confirm_pairing_holding(recovery, spaces).unwrap();
    let (joined_words, home) = waiting.join().unwrap();
    assert_eq!(words, joined_words, "both screens must show the same words");
    Vault { dir, home, words: adder.words.clone() }
}

fn connect_peers(first: &Vault, second: &Vault) {
    let port = |vault: &Vault| {
        for _ in 0..200 {
            if let Some(port) = vault.client().status().unwrap().sync_port {
                return port;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!("the broker never opened a sync port");
    };
    let (first_port, second_port) = (port(first), port(second));
    first.client().add_peer(&format!("127.0.0.1:{second_port}")).unwrap();
    second.client().add_peer(&format!("127.0.0.1:{first_port}")).unwrap();
}

/// Two paired devices that can reach each other.
fn paired() -> (Vault, Vault) {
    let first = Vault::new();
    first.add_env("KEY", "the-secret", None);
    let second = pair(&first, "Second Mac", None);
    connect_peers(&first, &second);
    (first, second)
}

#[test]
fn pairing_gives_the_new_device_everything() {
    let (first, second) = paired();
    let mut client = second.client();
    assert_eq!(value(&mut client, None, "KEY"), "the-secret");
    let names: Vec<String> = client.devices().unwrap().into_iter().map(|device| device.name).collect();
    assert!(names.contains(&"Test Mac".to_owned()) && names.contains(&"Second Mac".to_owned()), "{names:?}");
    assert_eq!(first.client().status().unwrap().device_count, 2);
}

#[test]
fn a_person_saying_the_words_differ_changes_nothing_on_either_side() {
    let first = Vault::new();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let join = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Other Mac").unwrap();
    let port = join.port().unwrap();
    let waiting = std::thread::spawn(move || {
        let pending = join.wait(Duration::from_secs(10)).unwrap();
        pending.confirm(&home).map(|()| home)
    });

    // The person sees a mismatch, so this device walks away instead of confirming.
    let mut client = first.client();
    client.begin_pairing(Some(&format!("127.0.0.1:{port}"))).unwrap();
    drop(client);

    assert!(waiting.join().unwrap().is_err());
    assert!(!dir.path().join("vault").exists());
    assert_eq!(first.client().status().unwrap().device_count, 1);
}

#[test]
fn a_person_refusing_the_touch_adds_nothing() {
    let first = Vault::new();
    first.client().unlock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let join = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Other Mac").unwrap();
    let port = join.port().unwrap();
    let waiting = std::thread::spawn(move || join.wait(Duration::from_secs(10)).unwrap().confirm(&home));

    let mut client = first.client();
    client.begin_pairing(Some(&format!("127.0.0.1:{port}"))).unwrap();
    first.deny_touches();
    assert_eq!(code(client.confirm_pairing(None)), ErrorCode::Denied);
    first.allow_touches();
    assert_eq!(first.client().status().unwrap().device_count, 1);
    assert!(waiting.join().unwrap().is_err());
}

#[test]
fn a_stranger_connecting_first_does_not_end_a_join() {
    let first = Vault::new();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let join = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Other Mac").unwrap();
    let port = join.port().unwrap();
    let joined = home.clone();
    let waiting = std::thread::spawn(move || join.wait(Duration::from_secs(10)).unwrap().confirm(&joined));

    let mut stranger = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stranger.write_all(b"\x00\x20not a noise handshake at all, sorry").unwrap();
    drop(stranger);

    let mut client = first.client();
    client.begin_pairing(Some(&format!("127.0.0.1:{port}"))).unwrap();
    client.confirm_pairing(None).unwrap();
    waiting.join().unwrap().unwrap();
    assert!(libvault::exists(&home));
    Client::connect(&home, options(None)).unwrap().stop().unwrap();
}

#[test]
fn a_session_cannot_add_a_device() {
    let vault = Vault::new();
    vault.space("project-a");
    let mut session = vault.session_client(&vault.session("project-a", "claude"));
    assert_eq!(code(session.begin_pairing(Some("127.0.0.1:1"))), ErrorCode::Denied);
    assert_eq!(code(session.add_peer("127.0.0.1:1")), ErrorCode::Denied);
}

#[test]
fn a_third_device_needs_a_second_approval() {
    let (first, second) = paired();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let join = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Third Mac").unwrap();
    let port = join.port().unwrap();
    let waiting = std::thread::spawn(move || join.wait(Duration::from_secs(10)).unwrap().confirm(&home));

    // The other device refuses, so with no recovery key this cannot go ahead.
    second.deny_touches();
    let mut client = first.client();
    client.begin_pairing(Some(&format!("127.0.0.1:{port}"))).unwrap();
    assert_eq!(code(client.confirm_pairing(None)), ErrorCode::Denied);
    second.allow_touches();
    assert_eq!(first.client().status().unwrap().device_count, 2);
    assert!(waiting.join().unwrap().is_err());
}

#[test]
fn another_device_can_give_the_second_approval() {
    let (first, second) = paired();
    let third = pair(&first, "Third Mac", None);
    assert_eq!(first.client().status().unwrap().device_count, 3);
    assert_eq!(value(&mut third.client(), None, "KEY"), "the-secret");
    drop(second);
}

#[test]
fn the_recovery_key_can_stand_in_for_a_missing_device() {
    let (first, _second) = paired();
    first.client().stop().unwrap();
    // A fresh broker has no peers it has reached yet, so only the words can approve.
    let third = pair(&first, "Third Mac", Some(&first.words));
    assert_eq!(first.client().status().unwrap().device_count, 3);
    assert_eq!(value(&mut third.client(), None, "KEY"), "the-secret");
}

// Four devices, as one person might have: laptop, desktop, phone and tablet. A change has to
// reach everyone even when two of them can never reach each other directly.
#[test]
fn four_devices_stay_in_step_through_each_other() {
    let (mac, desktop) = paired();
    let phone = pair(&mac, "Phone", None);
    connect_peers(&mac, &phone);
    let tablet = pair(&desktop, "Tablet", None);
    connect_peers(&desktop, &tablet);
    for device in [&mac, &desktop, &phone, &tablet] {
        device.client().sync_now().unwrap();
    }
    for device in [&mac, &desktop, &phone, &tablet] {
        device.client().sync_now().unwrap();
        assert_eq!(device.client().status().unwrap().device_count, 4);
    }

    // The phone only knows the laptop, and the tablet only knows the desktop.
    phone.add_env("FROM_PHONE", "typed on the phone", None);
    phone.client().sync_now().unwrap();
    mac.client().sync_now().unwrap();
    desktop.client().sync_now().unwrap();
    tablet.client().sync_now().unwrap();
    assert_eq!(value(&mut tablet.client(), None, "FROM_PHONE"), "typed on the phone");

    // Losing one loses nothing, and any two of the rest can remove it.
    let exposed = desktop.client().remove_device("Phone", Some(&desktop.words)).unwrap();
    assert!(exposed.contains(&"FROM_PHONE".to_owned()));
    for device in [&desktop, &mac, &tablet] {
        device.client().sync_now().unwrap();
    }
    mac.client().sync_now().unwrap();
    assert_eq!(mac.client().status().unwrap().device_count, 3);
    assert_eq!(value(&mut tablet.client(), None, "FROM_PHONE"), "typed on the phone");
}

#[test]
fn a_repeated_name_gets_a_suffix() {
    let first = Vault::new();
    let second = pair(&first, "Test Mac", None);
    let names: Vec<String> = second.client().devices().unwrap().into_iter().map(|device| device.name).collect();
    assert!(names.contains(&"Test Mac 2".to_owned()), "{names:?}");
}

#[test]
fn a_device_with_a_vault_cannot_join_another() {
    let first = Vault::new();
    let existing = Vault::new();
    let join = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Other").unwrap();
    let port = join.port().unwrap();
    let home = existing.home.clone();
    let waiting = std::thread::spawn(move || join.wait(Duration::from_secs(10)).unwrap().confirm(&home));
    let mut client = first.client();
    client.begin_pairing(Some(&format!("127.0.0.1:{port}"))).unwrap();
    assert!(matches!(waiting.join().unwrap(), Err(libvault::Error::VaultExists)));
    assert!(client.confirm_pairing(None).is_err());
    assert_eq!(first.client().status().unwrap().device_count, 1);
}

// Flow 13: direct sync.

/// Where multicast is missing, an address a person gave is all there is. The log is read directly
/// because a client would replace a broker that stopped answering, which is what this looks for.
#[test]
fn an_address_a_person_gave_keeps_devices_current_with_no_beacons() {
    let (first, second) = paired();
    first.client().stop().unwrap();
    first.start_broker_with_env("LV_DISCOVERY_PORT", Path::new("1"));
    let logs = |vault: &Vault| fs::read_dir(vault.home.join("log")).unwrap().map(|entry| entry.unwrap().metadata().unwrap().len()).sum::<u64>();
    let before = logs(&first);
    second.add_env("WRITTEN_LATER", "value", None);
    for _ in 0..300 {
        if logs(&first) > before {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the write never arrived");
}

#[test]
fn status_says_when_each_device_was_last_heard_from() {
    let (first, second) = paired();
    first.client().sync_now().unwrap();
    let contacts = first.client().status().unwrap().contacts;
    assert_eq!(contacts.len(), 1, "{contacts:?}");
    assert_eq!(contacts[0].device, "Second Mac");
    assert!(contacts[0].last_ok_ms.is_some(), "a sync just happened");
    assert_eq!(second.client().status().unwrap().contacts.len(), 1);
}

#[test]
fn a_device_that_has_gone_quiet_shows_as_never_heard_from() {
    let first = Vault::new();
    let dir = tempfile::tempdir().unwrap();
    let second = pair(&first, "Second Mac", None);
    drop(dir);
    second.client().stop().unwrap();
    second.go_offline();
    first.client().stop().unwrap();
    let contacts = first.client().status().unwrap().contacts;
    assert_eq!(contacts.iter().map(|contact| contact.last_ok_ms).collect::<Vec<_>>(), [None]);
}

#[test]
fn nothing_listens_until_there_is_a_second_device() {
    let vault = Vault::new();
    vault.add_env("KEY", "v", None);
    std::thread::sleep(Duration::from_millis(400));
    assert_eq!(vault.client().status().unwrap().sync_port, None);
}

#[test]
fn paired_devices_exchange_changes_directly_both_ways() {
    let (first, second) = paired();
    first.add_env("FROM_FIRST", "one", None);
    second.add_env("FROM_SECOND", "two", None);
    first.client().sync_now().unwrap();
    assert_eq!(value(&mut first.client(), None, "FROM_SECOND"), "two");
    assert_eq!(value(&mut second.client(), None, "FROM_FIRST"), "one");
}

#[test]
fn direct_sync_runs_while_locked() {
    let (first, second) = paired();
    second.add_env("FROM_SECOND", "two", None);
    let mut client = first.client();
    client.lock().unwrap();
    client.sync_now().unwrap();
    assert!(!client.status().unwrap().unlocked);
    assert_eq!(value(&mut client, None, "FROM_SECOND"), "two");
}

#[test]
fn a_stranger_on_the_port_gets_nothing_and_breaks_nothing() {
    let (first, _second) = paired();
    let port = first.client().status().unwrap().sync_port.unwrap();
    let mut stranger = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let _ = stranger.write_all(b"\x00\x20not a noise handshake at all, sorry");
    drop(stranger);

    // A well-formed handshake from an unenrolled device fares no better.
    let dir = tempfile::tempdir().unwrap();
    let other = {
        let setup = libvault::Setup::with_passphrase(PASSPHRASE, Cost::FAST).unwrap();
        setup.finish(&dir.path().join("vault"), "Stranger").unwrap();
        dir.path().join("vault")
    };
    let mut stranger = Client::connect(&other, options(None)).unwrap();
    assert!(stranger.add_peer(&format!("127.0.0.1:{port}")).is_ok());
    stranger.sync_now().unwrap();
    stranger.stop().unwrap();

    let mut client = first.client();
    assert_eq!(value(&mut client, None, "KEY"), "the-secret");
    assert_eq!(client.status().unwrap().device_count, 2);
    assert_eq!(client.status().unwrap().problems, Vec::<String>::new());
}

#[test]
fn a_flood_of_connections_is_turned_away_at_the_door() {
    let (first, _second) = paired();
    let port = first.client().status().unwrap().sync_port.unwrap();
    let mut held: Vec<TcpStream> = (0..16).map(|_| TcpStream::connect(("127.0.0.1", port)).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(100));

    let mut late = TcpStream::connect(("127.0.0.1", port)).unwrap();
    late.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    assert_eq!(late.read(&mut [0u8; 1]).unwrap_or(1), 0, "connections past the limit must close at once");

    // Each one held gives up its place by the handshake deadline, so the flood costs only time.
    held.clear();
    std::thread::sleep(Duration::from_millis(100));
    first.add_env("AFTER", "v", None);
    first.client().sync_now().unwrap();
}

#[test]
fn a_removed_device_is_refused_by_its_old_peers() {
    let (first, second) = paired();
    let mut client = first.client();
    client.remove_device("Second Mac", Some(&first.words)).unwrap();
    client.add(None, Meta::env("AFTER"), env("new-secret"), false).unwrap();

    let mut removed = second.client();
    removed.sync_now().unwrap();
    assert!(removed.item(None, "AFTER").is_err(), "a removed device must not receive new entries");
}

#[test]
fn a_request_from_another_device_cannot_open_a_locked_vault() {
    let (first, second) = paired();
    second.client().lock().unwrap();
    first.client().export_plaintext(&first.dir.path().join("export.json"), None).unwrap();
    assert!(!second.client().status().unwrap().unlocked, "another device opened this vault by asking for an approval");
}

#[test]
fn a_person_can_approve_a_plaintext_export_from_another_device() {
    let (first, second) = paired();
    let path = first.dir.path().join("export.json");
    second.deny_touches();
    assert_eq!(code(first.client().export_plaintext(&path, None)), ErrorCode::Denied);
    assert!(!path.exists());
    second.allow_touches();
    first.client().export_plaintext(&path, None).unwrap();
    assert!(fs::metadata(&path).unwrap().len() > 2);
}

#[test]
fn the_words_settle_a_conflict_between_devices_with_no_folder() {
    let first = Vault::new();
    first.add_env("KEY", "the-secret", None);
    let backup = tempfile::tempdir().unwrap();
    first.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();
    let second = restored(backup.path(), &first.words, "New Mac");
    second.client().add_backup(backup.path()).unwrap();
    first.client().sync_now().unwrap();
    first.client().remove_backup(backup.path()).unwrap();
    second.client().remove_backup(backup.path()).unwrap();
    first.go_offline();
    second.go_offline();

    let (first_draft, second_draft) = (RecoveryDraft::new(), RecoveryDraft::new());
    first.client().rotate_recovery(&first_draft, Some(&first.words)).unwrap();
    std::thread::sleep(Duration::from_millis(5));
    second.client().rotate_recovery(&second_draft, Some(&second.words)).unwrap();
    first.add_env("FROM_FIRST", "one", None);
    second.add_env("FROM_SECOND", "two", None);

    fs::remove_file(first.home.join("offline")).unwrap();
    fs::remove_file(second.home.join("offline")).unwrap();
    let port = |vault: &Vault| vault.client().status().unwrap().sync_port;
    let mut tries = 0;
    while port(&first).is_none() || port(&second).is_none() {
        tries += 1;
        assert!(tries < 200, "no port");
        std::thread::sleep(Duration::from_millis(50));
    }
    first.client().add_peer(&format!("127.0.0.1:{}", port(&second).unwrap())).unwrap();
    second.client().add_peer(&format!("127.0.0.1:{}", port(&first).unwrap())).unwrap();
    for _ in 0..2 {
        first.client().sync_now().unwrap();
        second.client().sync_now().unwrap();
    }

    assert_ne!(second.client().resolve_conflict(first_draft.words().as_ref()).unwrap(), 0, "the words brought in nothing");
    second.client().item(None, "FROM_FIRST").unwrap();
}

// Devices on different networks, such as a phone on mobile data and a Mac on a wired network.

/// A real `lv-relay`, which Vaulte keeps private, from `LV_RELAY_BIN`; `scripts/check.sh` builds
/// one from a relay checkout beside this one. With `root`, a key in hex, it asks for passes that
/// key vouched for. It lives until this test binary exits and closes the shell's stdin.
fn start_relay(root: Option<&str>) -> String {
    let relay = std::env::var("LV_RELAY_BIN").expect("relay tests need lv-relay: set LV_RELAY_BIN");
    let port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    let address = format!("127.0.0.1:{port}");
    let mut shell = std::process::Command::new("sh");
    shell.args(["-c", r#""$0" "$1" & cat > /dev/null; kill $!"#, &relay, &address]).stdin(std::process::Stdio::piped());
    if let Some(root) = root {
        shell.env("LV_RELAY_ROOT_KEY", root);
    }
    std::mem::forget(shell.spawn().unwrap());
    let started = std::time::Instant::now();
    while TcpStream::connect(&address).is_err() {
        assert!(started.elapsed() < Duration::from_secs(5), "lv-relay did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    address
}

fn relay() -> String {
    start_relay(None)
}

/// Two devices that hear no beacons and know no address for each other, with a relay between them.
fn apart() -> (Vault, Vault) {
    let first = Vault::new();
    let second = pair(&first, "Phone", None);
    // Each announces and listens on a port of its own, so neither can hear the other's beacons.
    for (vault, port) in [(&first, "1"), (&second, "2")] {
        vault.client().stop().unwrap();
        vault.start_broker_with_env("LV_DISCOVERY_PORT", Path::new(port));
    }
    assert_eq!(first.client().sync_now().unwrap().peers_reached, 0, "nothing but the relay may reach the other device");
    let relay = relay();
    first.client().add_peer(&format!("relay:{relay}")).unwrap();
    second.client().add_peer(&format!("relay:{relay}")).unwrap();
    (first, second)
}

/// Waits for `name` to reach `vault`. A device waits at the relay from its next beat, and the side
/// that answered a sync takes in what it was sent a moment after the caller returns.
fn arrives(vault: &Vault, name: &str) -> String {
    arrives_in(vault, None, name)
}

fn arrives_in(vault: &Vault, space: Option<&str>, name: &str) -> String {
    for _ in 0..300 {
        vault.client().sync_now().unwrap();
        if let Ok(Secret::Env { value }) = &vault.client().reveal(space, name) {
            return value.clone();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{name} never arrived");
}

#[test]
fn devices_that_share_no_network_stay_current_through_a_relay() {
    let (first, second) = apart();
    second.add_env("FROM_THE_PHONE", "two", None);
    assert_eq!(arrives(&first, "FROM_THE_PHONE"), "two");
    first.add_env("FROM_THE_MAC", "one", None);
    assert_eq!(arrives(&second, "FROM_THE_MAC"), "one");
}

#[test]
fn a_change_reaches_a_device_through_a_relay_moments_after_it_is_made() {
    let (first, second) = apart();
    second.add_env("FROM_THE_PHONE", "two", None);
    arrives(&first, "FROM_THE_PHONE");
    // The two have just heard from each other, so neither calls again on its own for a while.
    // Nobody asks for a sync here: the write itself must send it.
    first.add_env("FROM_THE_MAC", "one", None);
    arrives_unasked(&second, "FROM_THE_MAC", Duration::from_secs(5));
}

#[test]
fn a_device_on_another_network_joins_with_the_code_it_shows() {
    let relay = relay();
    let adder = Vault::new();
    adder.add_env("KEY", "the-secret", None);
    adder.client().add_peer(&format!("relay:{relay}")).unwrap();
    let mut join = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Far Away").unwrap();
    let code = join.wait_at_relay(&relay).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let joined = home.clone();
    let waiting = std::thread::spawn(move || {
        let pending = join.wait(Duration::from_secs(10)).unwrap();
        let words = pending.words().clone();
        pending.confirm(&joined).unwrap();
        words
    });
    // In place of an address, as a person types it.
    let mut client = adder.client();
    let words = client.begin_pairing(Some(&code.replace('-', " "))).unwrap();
    client.confirm_pairing_holding(None, None).unwrap();
    assert_eq!(waiting.join().unwrap(), words, "both screens must show the same words");
    let far = Vault { dir, home, words: adder.words.clone() };
    assert_eq!(value(&mut far.client(), None, "KEY"), "the-secret");
    // The devices are on networks apart, so only the relay the code came through keeps them current.
    for (vault, port) in [(&adder, "1"), (&far, "2")] {
        vault.client().stop().unwrap();
        vault.start_broker_with_env("LV_DISCOVERY_PORT", Path::new(port));
    }
    adder.add_env("AFTER_JOINING", "still in step", None);
    assert_eq!(arrives(&far, "AFTER_JOINING"), "still in step");
}

#[test]
fn a_code_nobody_is_waiting_with_says_so() {
    let relay = relay();
    let adder = Vault::new();
    adder.client().add_peer(&format!("relay:{relay}")).unwrap();
    let error = adder.client().begin_pairing(Some("1111-2222-3333")).unwrap_err();
    assert!(error.to_string().contains("no device is waiting with that code"), "{error}");
}

/// Three devices in a line: the first and the middle meet at one relay, the middle and the last at
/// another, and no beacon reaches any of them. The first and the last never meet.
fn in_a_line() -> (Vault, Vault, Vault) {
    let first = Vault::new();
    let middle = pair(&first, "Middle", None);
    let last = pair(&first, "Last", Some(&first.words));
    for (vault, port) in [(&first, "1"), (&middle, "2"), (&last, "3")] {
        vault.client().stop().unwrap();
        vault.start_broker_with_env("LV_DISCOVERY_PORT", Path::new(port));
    }
    let (near, far) = (relay(), relay());
    first.client().add_peer(&format!("relay:{near}")).unwrap();
    middle.client().add_peer(&format!("relay:{near}")).unwrap();
    middle.client().add_peer(&format!("relay:{far}")).unwrap();
    last.client().add_peer(&format!("relay:{far}")).unwrap();
    (first, middle, last)
}

/// Waits for `name` to reach `vault` without asking anyone for a sync.
fn arrives_unasked(vault: &Vault, name: &str, within: Duration) {
    let started = std::time::Instant::now();
    while vault.client().reveal(None, name).is_err() {
        assert!(started.elapsed() < within, "{name} waited for the next round of calls");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn a_change_travels_on_through_a_device_that_did_not_make_it() {
    let (first, _middle, last) = in_a_line();
    last.add_env("FROM_THE_END", "settled", None);
    arrives(&first, "FROM_THE_END");
    // Everyone has just heard from their neighbours, so nobody calls again on their own for a
    // while. The middle device writes nothing: taking the change in has to send it on.
    first.add_env("FROM_THE_START", "passed along", None);
    arrives_unasked(&last, "FROM_THE_START", Duration::from_secs(5));
}

#[test]
fn a_person_can_approve_on_a_device_that_is_only_reachable_through_a_relay() {
    let (first, second) = apart();
    second.add_env("FROM_THE_PHONE", "two", None);
    arrives(&first, "FROM_THE_PHONE");
    first.add_env("KEY", "the-secret", None);
    let path = first.dir.path().join("export.json");
    // Only the phone can give the second approval, and only the relay reaches it.
    second.deny_touches();
    assert_eq!(code(first.client().export_plaintext(&path, None)), ErrorCode::Denied);
    second.allow_touches();
    first.client().export_plaintext(&path, None).unwrap();
    assert!(fs::read_to_string(&path).unwrap().contains("the-secret"));
}

#[test]
fn a_relay_that_cannot_be_reached_is_refused_when_given() {
    let (first, _second) = paired();
    assert_eq!(code(first.client().add_peer("relay:nowhere.invalid:7687")), ErrorCode::Error);
}

// Flow 22: an agent asks, and the person answers on whichever device they are at.

/// A client for an agent on `vault`'s device, where nobody is at hand to approve anything, as on a
/// server. The vault is already open.
fn unattended(vault: &Vault) -> Client {
    vault.client().unlock().unwrap();
    nobody_at(vault)
}

/// A client with nothing to present, as an agent has.
fn nobody_at(vault: &Vault) -> Client {
    let options = libvault::Connect { passphrase: None, session: None, daemon: Some(Path::new(support::LVD)) };
    Client::connect(&vault.home, options).unwrap()
}

/// Every prompt a device showed, one a line.
fn shown(vault: &Vault) -> String {
    fs::read_to_string(vault.home.join("prompts")).unwrap_or_default()
}

#[test]
fn an_agent_s_grant_is_approved_on_another_device_which_shows_the_facts_then_its_reason() {
    let (server, laptop) = paired();
    let reason = Some("renewing the deploy token");
    unattended(&server).grant(None, "deploy-bot", Duration::from_secs(3600), reason).unwrap();
    let prompt = shown(&laptop);
    assert!(
        prompt.contains("Test Mac wants to let \"deploy-bot\" use Personal for 1 hour. It says: \u{201c}renewing the deploy token\u{201d}"),
        "{prompt}"
    );
    assert_eq!(server.client().grants().unwrap().len(), 1);
}

#[test]
fn a_grant_nobody_approves_is_not_given() {
    let (server, laptop) = paired();
    laptop.deny_touches();
    assert!(unattended(&server).grant(None, "deploy-bot", Duration::from_secs(60), Some("please")).is_err());
    assert!(server.client().grants().unwrap().is_empty());
}

#[test]
fn the_first_device_to_approve_wins_and_the_others_are_called_off() {
    let (server, laptop) = paired();
    let phone = pair(&server, "Phone", None);
    connect_peers(&server, &phone);
    connect_peers(&laptop, &phone);
    laptop.client().sync_now().unwrap();

    // The laptop's person is slow, and the phone's answers at once.
    fs::write(laptop.home.join("slow"), "").unwrap();
    let started = std::time::Instant::now();
    unattended(&server).grant(None, "agent", Duration::from_secs(60), Some("first")).unwrap();
    assert!(started.elapsed() < Duration::from_millis(2500), "nobody waits for the laptop");

    // Its prompt went away when the phone answered, so the laptop is free for the next one at
    // once, and a refusal on the phone does not stop it.
    fs::remove_file(laptop.home.join("slow")).unwrap();
    phone.deny_touches();
    unattended(&server).grant(None, "agent", Duration::from_secs(60), Some("second")).unwrap();
    assert!(shown(&laptop).contains("second"));
}

#[test]
fn a_prompt_here_goes_away_when_another_device_approves_first() {
    let (mac, phone) = paired();
    fs::write(mac.home.join("slow"), "").unwrap();
    let started = std::time::Instant::now();
    mac.client().grant(None, "agent", Duration::from_secs(60), Some("approved on the phone")).unwrap();
    assert!(started.elapsed() < Duration::from_millis(2500), "nobody waits for the slow prompt here");
    assert!(shown(&phone).contains("approved on the phone"));
}

// Servers: a machine nobody sits at, such as a VPS running agents.

/// A laptop holding a token, and a server joined to its vault.
fn laptop_and_server() -> (Vault, Vault) {
    let laptop = Vault::new();
    laptop.add_env("DEPLOY_TOKEN", "the-token", None);
    let server = pair_with(&laptop, Join::as_server("VPS").unwrap(), None, None);
    connect_peers(&laptop, &server);
    (laptop, server)
}

#[test]
fn a_server_opens_its_vault_by_itself_and_its_agent_gets_a_grant_from_another_device() {
    let (laptop, server) = laptop_and_server();
    // Nobody on the server ever types a passphrase, after a restart too.
    for _ in 0..2 {
        let token = nobody_at(&server).grant(None, "deploy-bot", Duration::from_secs(3600), Some("renewing the deploy token")).unwrap().token;
        let items = server.session_client(&token).items(None).unwrap();
        assert!(items.iter().any(|item| item.meta.name == "DEPLOY_TOKEN"), "the agent can use what the laptop saved");
        nobody_at(&server).stop().unwrap();
    }
    assert!(shown(&laptop).contains("VPS wants to let \"deploy-bot\" use Personal for 1 hour"), "{}", shown(&laptop));
}

#[test]
fn nothing_on_a_server_stands_in_for_a_person() {
    let (laptop, server) = laptop_and_server();
    // Not for itself, even handed a passphrase.
    assert_eq!(code(server.client().reveal(None, "DEPLOY_TOKEN")), ErrorCode::NeedsPerson);
    assert_eq!(code(nobody_at(&server).reveal(None, "DEPLOY_TOKEN")), ErrorCode::NeedsPerson);
    // With nobody approving anywhere, an agent there is told a person is needed.
    laptop.deny_touches();
    assert_eq!(code(nobody_at(&server).grant(None, "agent", Duration::from_secs(60), Some("please"))), ErrorCode::NeedsPerson);
}

#[test]
fn a_server_has_no_say_in_what_needs_two_devices() {
    // A laptop and a server are one person's device: the laptop acts alone, as it would by itself.
    let (laptop, _server) = laptop_and_server();
    let path = laptop.dir.path().join("export.json");
    laptop.client().export_plaintext(&path, None).unwrap();

    // With a phone as well, the second approval has to be the phone's. The server is not asked.
    let phone = pair(&laptop, "Phone", None);
    connect_peers(&laptop, &phone);
    phone.deny_touches();
    let path = laptop.dir.path().join("again.json");
    assert_eq!(code(laptop.client().export_plaintext(&path, None)), ErrorCode::Denied);
    phone.allow_touches();
    laptop.client().export_plaintext(&path, None).unwrap();
}

// A server holding only the spaces a person picks.

/// A laptop with a pin in Personal and a token in Agents, and a server holding only Agents.
fn laptop_and_agents_server() -> (Vault, Vault) {
    let laptop = Vault::new();
    laptop.add_env("BANK_PIN", "1234", None);
    laptop.space("Agents");
    laptop.add_env("DEPLOY_TOKEN", "the-token", Some("Agents"));
    let server = pair_with(&laptop, Join::as_server("VPS").unwrap(), None, Some(&["Agents"]));
    connect_peers(&laptop, &server);
    (laptop, server)
}

/// What an agent on `server` can list in Agents, once the laptop's person grants it.
fn granted_agents(server: &Vault, reason: &str) -> Vec<String> {
    let token = nobody_at(server).grant(Some("Agents"), "deploy-bot", Duration::from_secs(3600), Some(reason)).unwrap().token;
    server.session_client(&token).items(Some("Agents")).unwrap().into_iter().map(|item| item.meta.name).collect()
}

#[test]
fn a_server_holding_chosen_spaces_opens_them_alone() {
    let (laptop, server) = laptop_and_agents_server();
    assert_eq!(nobody_at(&server).spaces().unwrap(), ["Agents"], "it cannot even see that Personal exists by name");
    assert_eq!(granted_agents(&server, "deploying"), ["DEPLOY_TOKEN"]);
    assert!(shown(&laptop).contains("VPS wants to let \"deploy-bot\" use Agents for 1 hour"), "{}", shown(&laptop));
    assert_eq!(code(nobody_at(&server).items(Some("Personal"))), ErrorCode::NotFound);
    assert_eq!(code(nobody_at(&server).grant(Some("Personal"), "deploy-bot", Duration::from_secs(60), None)), ErrorCode::NotFound);
}

#[test]
fn what_an_agent_saves_on_a_server_reaches_the_laptop() {
    let (laptop, server) = laptop_and_agents_server();
    let token = nobody_at(&server).grant(Some("Agents"), "deploy-bot", Duration::from_secs(3600), Some("saving a token")).unwrap().token;
    server.session_client(&token).add(Some("Agents"), Meta::env("NEW_TOKEN"), env("fresh"), false).unwrap();
    assert_eq!(arrives_in(&laptop, Some("Agents"), "NEW_TOKEN"), "fresh");
}
#[test]
fn a_change_from_the_laptop_leaves_the_server_s_agent_its_grant() {
    let (laptop, server) = laptop_and_agents_server();
    let token = nobody_at(&server).grant(Some("Agents"), "deploy-bot", Duration::from_secs(3600), Some("deploying")).unwrap().token;
    let agent = || server.session_client(&token);
    assert!(agent().items(Some("Agents")).is_ok(), "the grant works before anything changes");
    laptop.add_env("ROTATED_TOKEN", "new", Some("Agents"));
    for _ in 0..200 {
        let names: Vec<String> =
            agent().items(Some("Agents")).expect("the grant outlives a change from the laptop").into_iter().map(|item| item.meta.name).collect();
        if names.iter().any(|name| name == "ROTATED_TOKEN") {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the change never reached the server");
}

#[test]
fn a_server_keeps_its_spaces_through_a_rotation_and_is_given_nothing_else() {
    let (laptop, server) = laptop_and_agents_server();
    let phone = pair(&laptop, "Phone", None);
    connect_peers(&laptop, &phone);
    laptop.client().sync_now().unwrap();
    // Removing a device rotates every key, and the server is wrapped only Agents' new one.
    laptop.client().remove_device("Phone", Some(&laptop.words)).unwrap();
    laptop.add_env("AFTER_ROTATION", "new", Some("Agents"));
    laptop.add_env("PRIVATE_AFTER", "no", None);
    laptop.client().sync_now().unwrap();
    for _ in 0..100 {
        if granted_agents(&server, "after the rotation").contains(&"AFTER_ROTATION".to_owned()) {
            assert_eq!(nobody_at(&server).spaces().unwrap(), ["Agents"]);
            return;
        }
        laptop.client().sync_now().unwrap();
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the server never read what was written under Agents' new key");
}

#[test]
fn removing_a_server_names_only_what_its_spaces_held() {
    let (laptop, _server) = laptop_and_agents_server();
    assert_eq!(laptop.client().remove_device("VPS", None).unwrap(), ["DEPLOY_TOKEN"], "not BANK_PIN, which the server never held");
}

#[test]
fn a_server_names_only_the_spaces_it_holds_for_an_item_in_several() {
    let (laptop, server) = laptop_and_agents_server();
    laptop.client().link(Some("Agents"), "DEPLOY_TOKEN", "Personal").unwrap();
    assert_eq!(laptop.client().item(Some("Agents"), "DEPLOY_TOKEN").unwrap().also_in, ["Personal"]);
    reaches_every_device(&laptop);
    let shown = nobody_at(&server).item(Some("Agents"), "DEPLOY_TOKEN").unwrap();
    assert!(shown.also_in.is_empty(), "{:?}", shown.also_in);
}

/// Syncs `vault` until every other device has answered, so what it wrote has reached them.
fn reaches_every_device(vault: &Vault) {
    for _ in 0..100 {
        vault.client().sync_now().unwrap();
        if vault.client().status().unwrap().contacts.iter().all(|contact| contact.last_ok_ms.is_some()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("a device never answered");
}

#[test]
fn a_server_cannot_change_an_item_that_is_also_in_a_space_it_does_not_hold() {
    let (laptop, server) = laptop_and_agents_server();
    laptop.client().link(Some("Agents"), "DEPLOY_TOKEN", "Personal").unwrap();
    reaches_every_device(&laptop);
    let token = nobody_at(&server).grant(Some("Agents"), "deploy-bot", Duration::from_secs(3600), Some("rotating it")).unwrap().token;
    let mut agent = server.session_client(&token);
    // Changing what is there takes a touch, and nobody is at a server to give one, so neither copy
    // can be changed from it, let alone one without the other.
    assert_eq!(code(agent.add(Some("Agents"), Meta::env("DEPLOY_TOKEN"), env("replaced"), true)), ErrorCode::NeedsPerson);
    assert_eq!(code(agent.remove(Some("Agents"), "DEPLOY_TOKEN")), ErrorCode::NeedsPerson);
    reaches_every_device(&laptop);
    assert_eq!(value(&mut laptop.client(), Some("Agents"), "DEPLOY_TOKEN"), "the-token");
    assert_eq!(value(&mut laptop.client(), Some("Personal"), "DEPLOY_TOKEN"), "the-token");
}

// Relay accounts: the relay Vaulte hosts lets in only those showing a pass for this month.

#[path = "issuer/mod.rs"]
mod issuer;

/// Two devices that meet only at a relay that asks for passes, both on `account`.
fn apart_at_a_paid_relay(issuer: &issuer::Issuer, account: &str) -> (Vault, Vault) {
    let relay = start_relay(Some(&issuer.issuer().root));
    let first = Vault::new();
    let second = pair(&first, "Phone", None);
    for (vault, port) in [(&first, "1"), (&second, "2")] {
        vault.client().stop().unwrap();
        vault.start_broker_with_env("LV_DISCOVERY_PORT", Path::new(port));
        vault.client().use_relay_account(account, Some(issuer.issuer())).unwrap();
        vault.client().add_peer(&format!("relay:{relay}")).unwrap();
    }
    (first, second)
}

#[test]
fn a_paid_account_s_devices_meet_at_a_relay_that_asks_for_passes() {
    let issuer = issuer::Issuer::start();
    issuer.pay("1234 5678 9012 3456");
    let (first, second) = apart_at_a_paid_relay(&issuer, "1234 5678 9012 3456");
    second.add_env("THROUGH_A_PAID_RELAY", "yes", None);
    assert_eq!(arrives(&first, "THROUGH_A_PAID_RELAY"), "yes");
}

#[test]
fn a_device_joins_through_a_relay_that_asks_for_passes_with_only_the_adder_paid() {
    let issuer = issuer::Issuer::start();
    issuer.pay("1234 5678 9012 3456");
    let relay = start_relay(Some(&issuer.issuer().root));
    let adder = Vault::new();
    adder.add_env("KEY", "the-secret", None);
    adder.client().use_relay_account("1234 5678 9012 3456", Some(issuer.issuer())).unwrap();
    adder.client().add_peer(&format!("relay:{relay}")).unwrap();
    let mut join = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Far Away").unwrap();
    let code = join.wait_at_relay(&relay).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let joined = home.clone();
    let waiting = std::thread::spawn(move || join.wait(Duration::from_secs(10)).unwrap().confirm(&joined).unwrap());
    let mut client = adder.client();
    client.begin_pairing(Some(&code)).unwrap();
    client.confirm_pairing_holding(None, None).unwrap();
    waiting.join().unwrap();
    assert_eq!(value(&mut Vault { dir, home, words: adder.words.clone() }.client(), None, "KEY"), "the-secret");
}

#[test]
fn an_account_that_has_not_paid_gets_nothing_through() {
    let issuer = issuer::Issuer::start();
    let (first, second) = apart_at_a_paid_relay(&issuer, "1234 5678 9012 3456");
    second.add_env("THROUGH_A_PAID_RELAY", "yes", None);
    // Longer than a paid account takes: the phone waits at the relay from its next beat.
    for _ in 0..15 {
        first.client().sync_now().unwrap();
        std::thread::sleep(Duration::from_secs(1));
    }
    assert_eq!(code(first.client().reveal(None, "THROUGH_A_PAID_RELAY")), ErrorCode::NotFound);
}

#[test]
fn subscribing_makes_one_account_and_says_where_to_pay() {
    let issuer = issuer::Issuer::start();
    let vault = Vault::new();
    let (account, url) = vault.client().relay_subscribe(None, Some(issuer.issuer())).unwrap();
    assert_eq!((account.as_str(), url.as_str()), ("1111 2222 3333 4444", "https://checkout.example/pay"));
    assert_eq!(vault.client().relay_subscribe(Some("me@example.com"), None).unwrap().0, account, "the same account, not a second");
    assert_eq!(vault.client().relay_status().unwrap(), Some((account, Some(4_000_000_000))));
    assert_eq!(code(vault.client().use_relay_account("1234", None)), ErrorCode::Error);
}

#[test]
fn the_billing_page_is_for_the_account_this_device_uses() {
    let issuer = issuer::Issuer::start();
    let vault = Vault::new();
    assert_eq!(code(vault.client().relay_billing()), ErrorCode::NotFound, "no account, no page");
    vault.client().relay_subscribe(None, Some(issuer.issuer())).unwrap();
    assert_eq!(vault.client().relay_billing().unwrap(), "https://billing.example/manage");
}
