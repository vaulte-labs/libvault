//! Finding devices on the network. A separate test binary, because beacons from tests running in
//! parallel would be heard here as other people's devices. Beacons also go straight to this machine
//! under test, so all of this runs even where the system stops a process hearing multicast. That
//! leaves only the multicast socket itself, which `the_network_path_itself` reports on.

mod support;

use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use libvault::item::Secret;
use libvault::{Client, Connect, Cost, Join};
use support::{PASSPHRASE, Vault, options};

/// These tests would hear each other's beacons, so they take turns.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

/// Whether this process can hear multicast at all. macOS's Local Network privacy can stop a
/// third-party binary receiving it while Apple's own tools still can, so a failure here says
/// something about the machine rather than the code, and must not read as either.
#[test]
fn the_network_path_itself() {
    const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 76, 86);
    let listener = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED).unwrap();
    listener.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
    let sender = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    sender.set_multicast_loop_v4(true).unwrap();
    // A machine with no multicast route, such as a CI runner, refuses the send itself.
    if sender.send_to(b"probe", (GROUP, port)).is_err() || listener.recv_from(&mut [0u8; 8]).is_err() {
        eprintln!("NOT TESTED: this process cannot send or receive multicast. Check Local Network access.");
    }
}

#[test]
fn a_device_can_join_found_on_the_network() {
    let _turn = ONE_AT_A_TIME.lock();
    let first = Vault::new();
    first.add_env("KEY", "the-secret", None);
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let join = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Nearby Mac").unwrap();
    let waiting = std::thread::spawn(move || {
        join.wait(Duration::from_secs(10)).unwrap().confirm(&home).unwrap();
        home
    });
    let mut client = first.client();
    client.begin_pairing(None).unwrap();
    client.confirm_pairing(None).unwrap();

    let home = waiting.join().unwrap();
    let mut joined = Client::connect(&home, Connect { passphrase: Some(PASSPHRASE), ..options(None) }).unwrap();
    assert!(matches!(&joined.reveal(None, "KEY").unwrap(), Secret::Env { value } if value == "the-secret"));
    joined.stop().unwrap();
}

#[test]
fn a_stale_beacon_does_not_stop_a_device_being_found() {
    let _turn = ONE_AT_A_TIME.lock();
    let first = Vault::new();
    let stale = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Long Gone").unwrap();
    drop(stale);

    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let join = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Nearby Mac").unwrap();
    let joined = home.clone();
    let waiting = std::thread::spawn(move || join.wait(Duration::from_secs(10)).unwrap().confirm(&joined).unwrap());
    let mut client = first.client();
    client.begin_pairing(None).unwrap();
    client.confirm_pairing(None).unwrap();
    waiting.join().unwrap();
    assert!(libvault::exists(&home));
    Client::connect(&home, options(None)).unwrap().stop().unwrap();
}

#[test]
fn paired_devices_find_each_other_by_their_beacons_alone() {
    let _turn = ONE_AT_A_TIME.lock();
    let first = Vault::new();
    first.add_env("KEY", "the-secret", None);
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("vault");
    let join = Join::with_passphrase(PASSPHRASE, Cost::FAST, "Nearby Mac").unwrap();
    let port = join.port().unwrap();
    let joined = home.clone();
    let waiting = std::thread::spawn(move || join.wait(Duration::from_secs(10)).unwrap().confirm(&joined).unwrap());
    let mut client = first.client();
    client.begin_pairing(Some(&format!("127.0.0.1:{port}"))).unwrap();
    client.confirm_pairing(None).unwrap();
    waiting.join().unwrap();

    // Neither was told where the other is.
    let second = Vault { dir, home, words: first.words.clone() };
    second.add_env("LATER", "typed on the other device", None);
    let deadline = Instant::now() + Duration::from_secs(30);
    while let Err(error) = client.item(None, "LATER") {
        assert!(Instant::now() < deadline, "the devices never found each other: {error}");
        std::thread::sleep(Duration::from_millis(100));
    }
}
