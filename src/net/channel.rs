//! An encrypted, mutually authenticated connection, using Noise XX over TCP. What crosses it is
//! ciphertext and public keys, so Noise is here to prove who is talking, not to hide secrets.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use snow::{Builder, HandshakeState, TransportState};

use crate::{Error, Result};

/// For pairing, where the two sides have nothing in common yet.
const PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";
/// Between devices of one vault, where a key from the vault keeps the handshake from telling a
/// stranger anything. Plain XX sends the responder's static key to anyone who connects, and that
/// key never changes, so probing would pick out a device wherever it went.
const VAULT_PATTERN: &str = "Noise_XXpsk0_25519_ChaChaPoly_SHA256";
const NOISE_MAX: usize = 65535;
const CHUNK: usize = NOISE_MAX - 16;
/// Whole logs, and so the most any message may claim to be.
pub(crate) const MAX_LOGS: usize = 1 << 30;
/// A stranger gets this long to finish a handshake, however it spends it. Timing out each read is
/// not enough, because one byte at a time would keep a connection open for ever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(if cfg!(feature = "test-hooks") { 2 } else { 10 });
/// How long one frame may take.
pub(super) const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a connection may last, whoever is on the other end.
const SESSION_TIMEOUT: Duration = Duration::from_mins(20);

const BROKEN: Error = Error::Peer("the connection to the other device failed");

#[derive(Debug)]
pub(crate) struct Channel {
    stream: TcpStream,
    noise: TransportState,
    /// Unique to this connection. A man in the middle has a different one on each side.
    pub hash: [u8; 32],
    /// The other side's static key, which callers must check before trusting anything it sends.
    pub remote: [u8; 32],
    patience: Duration,
    ends: Instant,
}

fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    let length = u16::try_from(bytes.len()).map_err(|_| BROKEN)?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

/// Fills `buffer` by `deadline`, or fails.
fn read_by(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(BROKEN);
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => return Err(BROKEN),
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_frame(stream: &mut TcpStream, buffer: &mut [u8], deadline: Instant) -> Result<usize> {
    let mut length = [0u8; 2];
    read_by(stream, &mut length, deadline)?;
    let length = usize::from(u16::from_be_bytes(length));
    read_by(stream, buffer.get_mut(..length).ok_or(BROKEN)?, deadline)?;
    Ok(length)
}

fn builder<'a>(key: &'a [u8; 32], prologue: &'a [u8], vault_key: Option<&'a [u8; 32]>) -> Result<Builder<'a>> {
    let params = vault_key.map_or(PATTERN, |_| VAULT_PATTERN).parse().map_err(|_| BROKEN)?;
    let builder = Builder::new(params).local_private_key(key).and_then(|builder| builder.prologue(prologue)).map_err(|_| BROKEN)?;
    match vault_key {
        Some(vault_key) => builder.psk(0, vault_key).map_err(|_| BROKEN),
        None => Ok(builder),
    }
}

fn handshake(mut stream: TcpStream, mut state: HandshakeState, mut sending: bool) -> Result<Channel> {
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let (mut wire, mut payload) = (vec![0u8; NOISE_MAX], vec![0u8; NOISE_MAX]);
    while !state.is_handshake_finished() {
        if sending {
            let length = state.write_message(&[], &mut wire).map_err(|_| BROKEN)?;
            write_frame(&mut stream, &wire[..length])?;
        } else {
            let length = read_frame(&mut stream, &mut wire, deadline)?;
            state.read_message(&wire[..length], &mut payload).map_err(|_| BROKEN)?;
        }
        sending = !sending;
    }
    let hash = state.get_handshake_hash().try_into().map_err(|_| BROKEN)?;
    let remote = state.get_remote_static().ok_or(BROKEN)?.try_into().map_err(|_| BROKEN)?;
    let noise = state.into_transport_mode().map_err(|_| BROKEN)?;
    Ok(Channel { stream, noise, hash, remote, patience: IO_TIMEOUT, ends: Instant::now() + SESSION_TIMEOUT })
}

impl Channel {
    pub fn initiate(stream: TcpStream, key: &[u8; 32], prologue: &[u8], vault_key: Option<&[u8; 32]>) -> Result<Self> {
        handshake(stream, builder(key, prologue, vault_key)?.build_initiator().map_err(|_| BROKEN)?, true)
    }

    pub fn respond(stream: TcpStream, key: &[u8; 32], prologue: &[u8], vault_key: Option<&[u8; 32]>) -> Result<Self> {
        handshake(stream, builder(key, prologue, vault_key)?.build_responder().map_err(|_| BROKEN)?, false)
    }

    /// The connection underneath, to watch for a hang-up or end it from another thread.
    pub fn try_clone_stream(&self) -> Result<TcpStream> {
        Ok(self.stream.try_clone()?)
    }

    /// Ends this session by `deadline` at the latest, for one that something is waiting on.
    pub fn give_up_by(&mut self, deadline: Instant) {
        self.ends = self.ends.min(deadline);
    }

    /// Waits longer from here on, when a person has to answer on the other side.
    pub fn wait_up_to(&mut self, timeout: Duration) {
        self.patience = timeout;
    }

    fn write(&mut self, plain: &[u8]) -> Result<()> {
        let mut wire = vec![0u8; NOISE_MAX];
        let length = self.noise.write_message(plain, &mut wire).map_err(|_| BROKEN)?;
        let left = self.ends.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Error::Peer("the connection to the other device ran out of time"));
        }
        self.stream.set_write_timeout(Some(left.clamp(Duration::from_millis(1), IO_TIMEOUT)))?;
        write_frame(&mut self.stream, &wire[..length])
    }

    fn read(&mut self, into: &mut Vec<u8>) -> Result<()> {
        let mut wire = vec![0u8; NOISE_MAX];
        let mut plain = vec![0u8; NOISE_MAX];
        let deadline = (Instant::now() + self.patience).min(self.ends);
        let length = read_frame(&mut self.stream, &mut wire, deadline)?;
        let read = self.noise.read_message(&wire[..length], &mut plain).map_err(|_| BROKEN)?;
        into.extend_from_slice(&plain[..read]);
        Ok(())
    }

    /// Sends one message of any size.
    pub fn send(&mut self, message: &[u8]) -> Result<()> {
        let length = u32::try_from(message.len()).map_err(|_| BROKEN)?;
        self.write(&length.to_le_bytes())?;
        message.chunks(CHUNK).try_for_each(|chunk| self.write(chunk))
    }

    /// Receives one message of at most `limit` bytes. It grows as bytes arrive, so claiming a
    /// length costs the sender as much as it costs this device.
    pub fn recv(&mut self, limit: usize) -> Result<Vec<u8>> {
        let mut header = Vec::with_capacity(4);
        self.read(&mut header)?;
        let length: [u8; 4] = header.as_slice().try_into().map_err(|_| BROKEN)?;
        let length = u32::from_le_bytes(length) as usize;
        if length > limit {
            return Err(BROKEN);
        }
        let mut message = Vec::new();
        while message.len() < length {
            let before = message.len();
            self.read(&mut message)?;
            if message.len() == before || message.len() > length {
                return Err(BROKEN);
            }
        }
        Ok(message)
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;

    fn pair() -> (Channel, Channel) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let connecting = std::thread::spawn(move || Channel::initiate(TcpStream::connect(address).unwrap(), &[1; 32], b"test", None).unwrap());
        let (stream, _) = listener.accept().unwrap();
        (Channel::respond(stream, &[2; 32], b"test", None).unwrap(), connecting.join().unwrap())
    }

    #[test]
    fn a_stranger_gets_nothing_from_a_device_s_handshake() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let answering = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            Channel::respond(stream, &[2; 32], b"test", Some(&[3; 32])).map(drop)
        });
        // A well-formed first message, from someone who does not hold the vault's key.
        let mut stranger = TcpStream::connect(address).unwrap();
        let mut hello = vec![0u8; 256];
        let mut noise = builder(&[1; 32], b"test", None).unwrap().build_initiator().unwrap();
        let length = noise.write_message(&[], &mut hello).unwrap();
        write_frame(&mut stranger, &hello[..length]).unwrap();
        stranger.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert!(answering.join().unwrap().is_err());
        let mut reply = [0u8; 2];
        assert_eq!(stranger.read(&mut reply).unwrap_or(0), 0, "nothing may come back, and a static key would have");
    }

    #[test]
    fn two_devices_of_a_vault_still_connect_with_its_key() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let connecting = std::thread::spawn(move || Channel::initiate(TcpStream::connect(address).unwrap(), &[1; 32], b"test", Some(&[3; 32])));
        let (stream, _) = listener.accept().unwrap();
        let mut answering = Channel::respond(stream, &[2; 32], b"test", Some(&[3; 32])).unwrap();
        let mut asking = connecting.join().unwrap().unwrap();
        asking.send(b"hello").unwrap();
        assert_eq!(answering.recv(5).unwrap(), b"hello");
    }

    #[test]
    fn a_message_comes_through_whole_at_any_size() {
        let (mut a, mut b) = pair();
        for size in [0, 1, CHUNK, CHUNK + 1, 3 * CHUNK + 7] {
            let message = vec![7u8; size];
            let sending = message.clone();
            let sender = std::thread::spawn(move || {
                a.send(&sending).unwrap();
                a
            });
            assert_eq!(b.recv(MAX_LOGS).unwrap(), message);
            a = sender.join().unwrap();
        }
    }

    #[test]
    fn a_message_past_its_limit_is_refused_before_it_is_read() {
        let (mut a, mut b) = pair();
        a.send(&[0; 33]).unwrap();
        assert!(b.recv(32).is_err());
    }

    #[test]
    fn logs_past_the_old_limit_still_sync() {
        let (mut a, mut b) = pair();
        let message = vec![9u8; (1 << 26) + 1];
        let sending = message.clone();
        let sender = std::thread::spawn(move || a.send(&sending));
        assert_eq!(b.recv(MAX_LOGS).unwrap(), message);
        sender.join().unwrap().unwrap();
    }

    #[test]
    fn a_message_longer_than_it_claimed_is_refused() {
        let (mut a, mut b) = pair();
        a.write(&5u32.to_le_bytes()).unwrap();
        a.write(&[0; 6]).unwrap();
        assert!(b.recv(32).is_err());
    }

    #[test]
    fn empty_frames_cannot_keep_a_message_open() {
        let (mut a, mut b) = pair();
        a.write(&5u32.to_le_bytes()).unwrap();
        a.write(&[]).unwrap();
        assert!(b.recv(32).is_err());
    }

    #[test]
    fn a_session_ends_when_its_time_is_up() {
        let (a, mut b) = pair();
        b.ends = Instant::now();
        assert!(b.recv(32).is_err(), "only an open connection and no data here, so this would otherwise wait");
        drop(a);
    }

    #[test]
    fn nothing_goes_out_once_the_session_is_over() {
        let (a, mut b) = pair();
        b.ends = Instant::now();
        assert!(b.send(&[1]).is_err());
        drop(a);
    }

    #[test]
    fn a_write_stops_when_the_session_s_time_is_up() {
        let (a, mut b) = pair();
        b.ends = Instant::now() + Duration::from_millis(200);
        let started = Instant::now();
        assert!(b.send(&vec![0; 1 << 24]).is_err(), "nothing is reading on the other side");
        assert!(started.elapsed() < Duration::from_secs(5), "took {:?}", started.elapsed());
        drop(a);
    }

    #[test]
    fn a_handshake_sent_a_byte_at_a_time_is_cut_off() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let mut stranger = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let dripping = std::thread::spawn(move || {
            // Far more frame than the deadline allows, and never long enough between bytes to time out.
            let _ = stranger.write_all(&[0xff, 0xff]);
            while stranger.write_all(&[0]).is_ok() {
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        let started = Instant::now();
        assert!(Channel::respond(stream, &[2; 32], b"test", None).is_err());
        assert!(started.elapsed() <= HANDSHAKE_TIMEOUT + Duration::from_secs(1), "took {:?}", started.elapsed());
        dripping.join().unwrap();
    }
}
