//! Adding a device. Both sides show three words and a person compares them.
//!
//! Three words is about 33 bits, which a man in the middle could beat offline by trying keys until
//! the words match. So each side commits to a random value before seeing the other's, as Bluetooth
//! numeric comparison does. An attacker must then pick before knowing the outcome, and gets one
//! guess in 2^33 per attempt, with a person watching.

use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use bip39::Language;

use super::channel::{Channel, IO_TIMEOUT, MAX_LOGS};
use super::discovery::{self, Beacon};
use super::join_code;
use crate::crypto::{self, Hash};
use crate::device::Device;
use crate::device::software::{Cost, Software};
use crate::record::DeviceRecord;
use crate::setup::{NewDevice, STAGING_PREFIX, new_device, remove_stale_staging, write_device_files};
use crate::state::Anchor;
use crate::store::log;
use crate::store::private_dir;
use crate::store::{self, Logs, decode_archive, encode_archive};
use crate::vault::exists;
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

const PROLOGUE: &[u8] = b"vaulty.pair.v1";
const MAX_REQUEST: usize = 16 * 1024;
const ANNOUNCE_EVERY: Duration = Duration::from_millis(500);
const JOINER_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a person gets to compare the words and approve.
pub(crate) const PERSON_TIMEOUT: Duration = Duration::from_secs(120);

fn commitment(connection: &[u8; 32], nonce: &[u8; 32]) -> Hash {
    crypto::hash(&[b"vaulty.pair.commit.v2", connection, nonce])
}

/// Three words from the connection and both sides' values.
fn comparison_words(connection: &[u8; 32], first: &[u8; 32], second: &[u8; 32]) -> [String; 3] {
    let hash = crypto::hash(&[b"vaulty.pair.words.v1", connection, first, second]);
    let words = Language::English.word_list();
    [0, 2, 4].map(|at| words[usize::from(u16::from_le_bytes([hash[at], hash[at + 1]])) % words.len()].to_owned())
}

fn expect_32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| Error::Peer("the other device sent something unexpected"))
}

/// The adding side commits first, and reveals only after seeing the joining side's value.
pub(crate) fn words_as_adder(channel: &mut Channel) -> Result<[String; 3]> {
    let mine: [u8; 32] = crypto::random();
    channel.send(&commitment(&channel.hash, &mine))?;
    let theirs = expect_32(&channel.recv(32)?)?;
    channel.send(&mine)?;
    Ok(comparison_words(&channel.hash, &mine, &theirs))
}

/// The joining side, once it holds a commitment.
fn words_as_joiner(channel: &mut Channel, committed: &Hash) -> Result<[String; 3]> {
    let mine: [u8; 32] = crypto::random();
    channel.send(&mine)?;
    let revealed = expect_32(&channel.recv(32)?)?;
    if commitment(&channel.hash, &revealed) != *committed {
        return Err(Error::Peer("the other device broke its commitment, so someone may be interfering"));
    }
    Ok(comparison_words(&channel.hash, &revealed, &mine))
}

/// Connects to a joining device: at an address, through `relays` by the code it shows, or by
/// waiting to hear one on the network.
pub(crate) fn connect_to_joiner(address: Option<&str>, key: &[u8; 32], timeout: Duration, relays: &[String], pass: &[u8]) -> Result<Channel> {
    if let Some(digits) = address.and_then(join_code::parse) {
        for relay in relays {
            if let Ok(channel) = join_code::dial(relay, &digits, pass).and_then(|stream| Channel::initiate(stream, key, PROLOGUE, None)) {
                return Ok(channel);
            }
        }
        return Err(Error::Peer("no device is waiting with that code. Check it, and that the other device is still joining"));
    }
    if let Some(address) = address {
        return Channel::initiate(TcpStream::connect(address)?, key, PROLOGUE, None);
    }
    let socket = discovery::listen(Duration::from_millis(250))?;
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let Some((Beacon::Join { port }, from)) = discovery::next_beacon(&socket) else { continue };
        // A beacon can outlive its device, and on a shared network it may be someone else's. The
        // words catch the second case, so anything that does not answer is simply skipped.
        let Ok(stream) = TcpStream::connect_timeout(&SocketAddr::new(from.ip(), port), JOINER_TIMEOUT) else { continue };
        if let Ok(channel) = Channel::initiate(stream, key, PROLOGUE, None) {
            return Ok(channel);
        }
    }
    Err(Error::Peer("no new device appeared. Start joining on it, and if it is on this network, give its address or check Local Network access"))
}

/// What a joining device asks for: to be enrolled, under a name, as a server or not. A server
/// says so itself, so that whoever adds it signs for one with no say in the roster.
pub(crate) fn encode_request(record: &DeviceRecord, name: &str, server: bool) -> Vec<u8> {
    let mut w = Writer::new();
    record.write(&mut w);
    w.bytes(name.as_bytes());
    w.u8(u8::from(server));
    w.finish()
}

pub(crate) fn decode_request(bytes: &[u8]) -> Result<(DeviceRecord, String, bool)> {
    let mut r = Reader::new(bytes);
    let record = DeviceRecord::read(&mut r)?;
    let name = String::from_utf8(r.bytes()?.to_vec()).map_err(|_| Error::Peer("the device sent a bad name"))?;
    let server = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(Error::Peer("the device sent a bad request")),
    };
    r.finish()?;
    Ok((record, name, server))
}

/// Sends the new device everything it needs: logs, which hold only ciphertext and public keys.
pub(crate) fn send_logs(channel: &mut Channel, logs: &Logs) -> Result<()> {
    channel.send(&encode_archive(logs))
}

/// A device waiting to be added. Nothing is written until the person confirms.
#[derive(Debug)]
pub struct Join {
    device: Arc<dyn Device>,
    fresh: NewDevice,
    name: String,
    listener: TcpListener,
    /// Devices that reached this one through a relay, by its code.
    relayed: Option<mpsc::Receiver<TcpStream>>,
    stop: Arc<AtomicBool>,
}

impl Join {
    /// Starts joining with this device's secure hardware, or reports that it has none.
    pub fn with_hardware(name: &str) -> Result<Self> {
        #[cfg(target_os = "macos")]
        if crate::device::enclave::available() {
            return Self::start(Arc::new(crate::device::enclave::Enclave::generate()?), name);
        }
        let _ = name;
        Err(Error::NoHardware)
    }

    /// Starts joining as a server: a machine nobody sits at, which opens its vault by itself and
    /// approves nothing. Every approval it needs comes from another device.
    pub fn as_server(name: &str) -> Result<Self> {
        Self::start(Arc::new(crate::device::server::Server::generate()?), name)
    }

    /// Starts joining on a device with no secure hardware.
    pub fn with_passphrase(passphrase: &str, cost: Cost, name: &str) -> Result<Self> {
        Self::start(Arc::new(Software::generate(passphrase, cost)?), name)
    }

    fn start(device: Arc<dyn Device>, name: &str) -> Result<Self> {
        let fresh = new_device(device.as_ref())?;
        let listener = TcpListener::bind(("0.0.0.0", 0))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let port = listener.local_addr()?.port();
        let (beacon, stopped) = (Beacon::Join { port }, Arc::clone(&stop));
        std::thread::spawn(move || {
            while !stopped.load(Ordering::Relaxed) {
                // A network with no multicast still works through the address.
                let _ = discovery::announce(&beacon);
                std::thread::sleep(ANNOUNCE_EVERY);
            }
        });
        Ok(Self { device, fresh, name: name.to_owned(), listener, relayed: None, stop })
    }

    /// The port to give the other device when it cannot find this one on its own.
    pub fn port(&self) -> Result<u16> {
        Ok(self.listener.local_addr()?.port())
    }

    /// Waits at `relay` too, for a device on another network, and returns the code to type there
    /// in place of an address.
    pub fn wait_at_relay(&mut self, relay: &str) -> Result<String> {
        let digits = join_code::new_code();
        self.relayed = Some(join_code::wait(relay, &digits, Arc::clone(&self.stop))?);
        Ok(join_code::shown(&digits))
    }

    /// Waits for an enrolled device to connect, then works out the words to compare. A stranger
    /// that cannot get as far as a commitment costs nothing. Past that, a failure ends this and
    /// says so: an attacker who could hang up and try again would get a guess at the words each
    /// time, unseen, where the design promises one guess with a person watching.
    pub fn wait(self, timeout: Duration) -> Result<PendingJoin> {
        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() > deadline {
                return Err(Error::Peer("no device with this vault connected. Add this one from a device that has it"));
            }
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    let Some(stream) = self.relayed.as_ref().and_then(|relayed| relayed.try_recv().ok()) else {
                        std::thread::sleep(Duration::from_millis(20));
                        continue;
                    };
                    stream
                }
                Err(error) => return Err(error.into()),
            };
            stream.set_nonblocking(false)?;
            let Ok(mut channel) = Channel::respond(stream, &self.fresh.sync_seed, PROLOGUE, None) else { continue };
            channel.wait_up_to(deadline.saturating_duration_since(Instant::now()));
            let Ok(committed) = channel.recv(32).and_then(|bytes| expect_32(&bytes)) else { continue };
            channel.wait_up_to(IO_TIMEOUT);
            self.stop.store(true, Ordering::Relaxed);
            let words = words_as_joiner(&mut channel, &committed)?;
            return Ok(PendingJoin { join: self, channel, words });
        }
    }
}

impl Drop for Join {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// The words are on both screens. Dropping this refuses, and nothing has been written.
#[derive(Debug)]
pub struct PendingJoin {
    join: Join,
    channel: Channel,
    words: [String; 3],
}

impl PendingJoin {
    pub fn words(&self) -> &[String; 3] {
        &self.words
    }

    /// The person says the words match. Waits for the other device, then creates the vault here
    /// in one atomic step.
    pub fn confirm(mut self, home: &Path) -> Result<()> {
        if exists(home) {
            return Err(Error::VaultExists);
        }
        let parent = home.parent().ok_or(Error::NoVault)?;
        private_dir(parent)?;
        remove_stale_staging(parent);

        self.channel.send(&encode_request(&self.join.fresh.record, &self.join.name, !self.join.device.has_person()))?;
        self.channel.wait_up_to(PERSON_TIMEOUT);
        let logs = decode_archive(&self.channel.recv(MAX_LOGS)?)?;

        let staging = parent.join(format!("{STAGING_PREFIX}{}", log::hex(&crypto::random::<8>())));
        let result = self.build(&staging, &logs).and_then(|()| {
            if home.exists() {
                fs::remove_dir(home).map_err(|_| Error::VaultExists)?;
            }
            fs::rename(&staging, home)?;
            Ok(())
        });
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result
    }

    fn build(&self, home: &Path, logs: &Logs) -> Result<()> {
        store::create(home, logs)?;
        let state = store::replay(logs, &Anchor::Device { keys: &self.join.fresh.record.keys, settled: None })?;
        let id = self.join.fresh.record.id();
        if !state.members.contains_key(&id) {
            return Err(Error::Peer("the other device did not enroll this one"));
        }
        if !state.active_devices().any(|(_, member)| member.record.sync == self.channel.remote) {
            return Err(Error::Peer("the other device is not part of the vault it sent"));
        }
        write_device_files(home, self.join.device.as_ref(), state.vault, &self.join.fresh)
    }
}

/// Reads the request once the person on the other side has confirmed. The words vouch for this
/// connection, so what is enrolled has to be the key at the other end of it.
pub(crate) fn receive_request(channel: &mut Channel) -> Result<(DeviceRecord, String, bool)> {
    channel.wait_up_to(PERSON_TIMEOUT);
    let (record, name, server) = decode_request(&channel.recv(MAX_REQUEST)?)?;
    if record.sync != channel.remote {
        return Err(Error::Peer("the other device sent a key that is not the one it connected with"));
    }
    Ok((record, name, server))
}

#[cfg(test)]
#[path = "pair_model_tests.rs"]
mod model;

#[cfg(test)]
mod tests {
    use aws_lc_rs::agreement::{PrivateKey, X25519};

    use super::*;
    use crate::tests::approval_for_tests;

    fn public(key: &[u8; 32]) -> [u8; 32] {
        PrivateKey::from_private_key(&X25519, key).unwrap().compute_public_key().unwrap().as_ref().try_into().unwrap()
    }

    /// Both ends of a pairing connection, using these sync keys.
    fn connected(adder: [u8; 32], joiner: [u8; 32]) -> (Channel, Channel) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let connecting = std::thread::spawn(move || Channel::initiate(TcpStream::connect(address).unwrap(), &adder, PROLOGUE, None).unwrap());
        let (stream, _) = listener.accept().unwrap();
        let responder = Channel::respond(stream, &joiner, PROLOGUE, None).unwrap();
        (connecting.join().unwrap(), responder)
    }

    #[test]
    fn a_stranger_who_goes_silent_does_not_hold_a_join_past_its_time() {
        let join = Join::with_passphrase("test passphrase", Cost::FAST, "New Mac").unwrap();
        let port = join.port().unwrap();
        let started = Instant::now();
        let waiting = std::thread::spawn(move || join.wait(Duration::from_secs(1)).is_err());
        let _stranger = Channel::initiate(TcpStream::connect(("127.0.0.1", port)).unwrap(), &[9; 32], PROLOGUE, None).unwrap();
        assert!(waiting.join().unwrap());
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
    }

    #[test]
    fn what_is_enrolled_must_be_the_key_on_this_connection() {
        let (mut adder, mut joiner) = connected([1; 32], [2; 32]);
        let device = Software::generate("p", Cost::FAST).unwrap();
        let mut record = new_device(&device).unwrap().record;
        record.sync = public(&[3; 32]);
        joiner.send(&encode_request(&record, "Mac", false)).unwrap();
        assert!(receive_request(&mut adder).is_err(), "the words vouched for another key");

        let (mut adder, mut joiner) = connected([1; 32], [2; 32]);
        record.sync = public(&[2; 32]);
        joiner.send(&encode_request(&record, "Mac", false)).unwrap();
        assert_eq!(receive_request(&mut adder).unwrap().0, record);
    }

    #[test]
    fn a_man_in_the_middle_who_hangs_up_after_a_commitment_ends_the_join() {
        let join = Join::with_passphrase("p", Cost::FAST, "New").unwrap();
        let port = join.port().unwrap();
        let waiting = std::thread::spawn(move || join.wait(Duration::from_secs(10)).map(drop));
        let mut attacker = Channel::initiate(TcpStream::connect(("127.0.0.1", port)).unwrap(), &[9; 32], PROLOGUE, None).unwrap();
        attacker.send(&commitment(&attacker.hash, &[1; 32])).unwrap();
        attacker.recv(32).unwrap();
        drop(attacker);
        assert!(waiting.join().unwrap().is_err(), "another try would be another guess at the words, with nobody the wiser");
    }

    #[test]
    fn a_join_gives_up_on_time_however_many_strangers_keep_connecting() {
        let join = Join::with_passphrase("p", Cost::FAST, "New").unwrap();
        let port = join.port().unwrap();
        let started = Instant::now();
        let waiting = std::thread::spawn(move || join.wait(Duration::from_millis(300)).map(drop));
        while !waiting.is_finished() {
            let _ = TcpStream::connect(("127.0.0.1", port));
            assert!(started.elapsed() < Duration::from_secs(8), "a stream of strangers held the deadline off");
        }
        assert!(waiting.join().unwrap().is_err());
    }

    #[test]
    fn a_vault_must_come_from_a_device_in_it() {
        let dir = tempfile::tempdir().unwrap();
        let join = Join::with_passphrase("p", Cost::FAST, "New").unwrap();
        let record = join.fresh.record.clone();
        let logs = approval_for_tests(&dir.path().join("vault"), &record);

        let port = join.port().unwrap();
        let joined = dir.path().join("joined");
        let target = joined.clone();
        let joining = std::thread::spawn(move || join.wait(Duration::from_secs(10)).unwrap().confirm(&target));

        // Words matched, a real vault that enrolls the joiner, and a key that is in no roster.
        let mut channel = Channel::initiate(TcpStream::connect(("127.0.0.1", port)).unwrap(), &[9; 32], PROLOGUE, None).unwrap();
        words_as_adder(&mut channel).unwrap();
        receive_request(&mut channel).unwrap();
        send_logs(&mut channel, &logs).unwrap();

        assert!(joining.join().unwrap().is_err());
        assert!(!joined.exists());
    }

    #[test]
    fn each_word_is_eleven_bits_of_the_hash_so_both_sides_read_the_same() {
        let hash = crypto::hash(&[b"vaulty.pair.words.v1", &[1; 32], &[2; 32], &[3; 32]]);
        let list = Language::English.word_list();
        let expected = [0, 2, 4].map(|at| list[(usize::from(hash[at]) | usize::from(hash[at + 1]) << 8) & 0x7ff].to_owned());
        assert_eq!(comparison_words(&[1; 32], &[2; 32], &[3; 32]), expected);
    }

    #[test]
    fn words_depend_on_the_connection_and_both_values() {
        let base = comparison_words(&[1; 32], &[2; 32], &[3; 32]);
        assert_eq!(base, comparison_words(&[1; 32], &[2; 32], &[3; 32]));
        assert_ne!(base, comparison_words(&[9; 32], &[2; 32], &[3; 32]));
        assert_ne!(base, comparison_words(&[1; 32], &[9; 32], &[3; 32]));
        assert_ne!(base, comparison_words(&[1; 32], &[2; 32], &[9; 32]));
    }

    #[test]
    fn a_join_request_round_trips_and_trailing_bytes_are_refused() {
        let device = Software::generate("p", Cost::FAST).unwrap();
        let fresh = new_device(&device).unwrap();
        for server in [false, true] {
            let bytes = encode_request(&fresh.record, "Mac", server);
            assert_eq!(decode_request(&bytes).unwrap(), (fresh.record.clone(), "Mac".to_owned(), server));
            assert!(decode_request(&[bytes, vec![0]].concat()).is_err());
        }
    }
}
