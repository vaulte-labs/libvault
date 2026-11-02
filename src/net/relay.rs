//! Reaching a device on another network, through a relay both can call out to. A phone on mobile
//! data and a Mac on a wired network share no network, and routers stop either being called, but
//! both can call out. The relay pairs two such connections and copies bytes between them. What
//! crosses is the same Noise channel a local network carries, so the relay sees addresses, timing
//! and sizes, and nothing a device sends.
//!
//! A device waits under one tag per peer, which only that pair can compute and which changes every
//! period, so tags tell the relay nothing about which vault a device is in. The connection it holds
//! open still shows its address. This is the device's side; the relay Vaulte hosts is its own.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::{Error, Result};

pub(crate) const TAG_LEN: usize = 32;
pub(crate) type Tag = [u8; TAG_LEN];
type Id = [u8; 16];

const MAGIC: &[u8; 8] = b"VAULTE02";
const LISTEN: u8 = 1;
const DIAL: u8 = 2;
const ACCEPT: u8 = 3;
const HELLO_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[path = "relay_pass.rs"]
pub mod pass;

/// `pass` is empty for a relay that asks for none.
fn connect(relay: &str, kind: u8, pass: &[u8]) -> Result<TcpStream> {
    let address = relay.to_socket_addrs()?.next().ok_or(Error::Peer("the relay cannot be reached"))?;
    let mut stream = TcpStream::connect_timeout(&address, CONNECT_TIMEOUT)?;
    stream.set_write_timeout(Some(HELLO_TIMEOUT))?;
    let length = u16::try_from(pass.len()).map_err(|_| Error::Peer("that pass is too long"))?;
    stream.write_all(&[MAGIC.as_slice(), &[kind], &length.to_be_bytes(), pass].concat())?;
    Ok(stream)
}

/// A connection to the device waiting under `tag`, ready for a Noise handshake. A dial nobody
/// answers ends, and the handshake then fails as it would at an address with nobody there.
pub(crate) fn dial(relay: &str, tag: &Tag, pass: &[u8]) -> Result<TcpStream> {
    let mut stream = connect(relay, DIAL, pass)?;
    stream.write_all(tag)?;
    Ok(stream)
}

/// This device, waiting at a relay for other devices to dial in.
#[derive(Debug)]
pub(crate) struct Waiting {
    relay: String,
    pass: Vec<u8>,
    control: TcpStream,
}

impl Waiting {
    pub fn open(relay: &str, tags: &[Tag], pass: &[u8]) -> Result<Self> {
        let control = connect(relay, LISTEN, pass)?;
        let mut waiting = Self { relay: relay.to_owned(), pass: pass.to_vec(), control };
        waiting.renew(tags)?;
        Ok(waiting)
    }

    /// Replaces the tags this device waits under. It also tells the relay this device is still here.
    pub fn renew(&mut self, tags: &[Tag]) -> Result<()> {
        let count = u8::try_from(tags.len()).map_err(|_| Error::Peer("too many devices for a relay"))?;
        let frame: Vec<u8> = std::iter::once(count).chain(tags.iter().flatten().copied()).collect();
        self.control.write_all(&frame)?;
        Ok(())
    }

    /// The next device to dial in within `timeout`, as a connection ready for a Noise handshake.
    pub fn next(&mut self, timeout: Duration) -> Result<Option<TcpStream>> {
        let mut id: Id = [0; 16];
        self.control.set_read_timeout(Some(timeout))?;
        match self.control.read(&mut id[..1]) {
            Ok(0) => return Err(Error::Peer("the relay hung up")),
            Ok(_) => {}
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        // The relay writes an id whole, so once it has begun the rest is moments away.
        self.control.set_read_timeout(Some(HELLO_TIMEOUT))?;
        self.control.read_exact(&mut id[1..])?;
        let mut stream = connect(&self.relay, ACCEPT, &self.pass)?;
        stream.write_all(&id)?;
        Ok(Some(stream))
    }
}
