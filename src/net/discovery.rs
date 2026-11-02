//! Finding other devices on the local network. A sync beacon carries a fresh nonce and, for each
//! other device, a tag only that pair can compute. Nothing in it repeats, so an observer cannot
//! recognize or follow a device, and nothing in a log helps: the tag comes from what the two sync
//! keys agree, not from anything public. A removed device stops being tagged and stops hearing.
//! What a network already shows, such as an address or which port is in use, a beacon cannot hide.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use aws_lc_rs::agreement::{self, UnparsedPublicKey, X25519};
use socket2::{Domain, Protocol, Socket, Type};
use zeroize::Zeroizing;

use crate::crypto::{self, Hash};
use crate::net::relay::Tag;
use crate::store::log::now_ms;
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

const GROUP: Ipv4Addr = Ipv4Addr::new(239, 255, 76, 86);
const DEFAULT_PORT: u16 = 7686;
const MAGIC: &[u8; 8] = b"VAULTY01";
const JOIN: u8 = 1;
const SYNC: u8 = 2;
const TAG_PERIOD_MS: u64 = 10 * 60 * 1000;
const NONCE_LEN: usize = 16;
const TAG_LEN: usize = 8;
const MAX_BEACON: usize = 512;
/// As many tags as a beacon holds. A vault with more devices than this finds the rest by address.
const MAX_TAGS: usize = (MAX_BEACON - MAGIC.len() - 4 - NONCE_LEN) / TAG_LEN;
/// Every beacon carries at least this many, whatever the vault's size.
const MIN_TAGS: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Beacon {
    Join { port: u16 },
    Sync { port: u16, nonce: [u8; NONCE_LEN], tags: Vec<[u8; TAG_LEN]> },
}

impl Beacon {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(MAGIC);
        match self {
            Self::Join { port } => {
                w.u8(JOIN);
                w.array(&port.to_le_bytes());
            }
            Self::Sync { port, nonce, tags } => {
                w.u8(SYNC);
                w.array(&port.to_le_bytes());
                w.array(nonce);
                w.u8(u8::try_from(tags.len()).expect("a beacon holds few tags"));
                for tag in tags {
                    w.array(tag);
                }
            }
        }
        w.finish()
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        if r.array::<8>().ok()? != *MAGIC {
            return None;
        }
        let kind = r.u8().ok()?;
        let port = u16::from_le_bytes(r.array().ok()?);
        let beacon = match kind {
            JOIN => Self::Join { port },
            SYNC => {
                let nonce = r.array().ok()?;
                let tags = (0..r.u8().ok()?).map(|_| r.array().ok()).collect::<Option<_>>()?;
                Self::Sync { port, nonce, tags }
            }
            _ => return None,
        };
        r.finish().ok()?;
        Some(beacon)
    }
}

/// One tag, for a beacon from `sender`. It covers the port, so a tag cannot be reused to point
/// this device at somewhere else, and the time, so it cannot be replayed for long.
fn tag_for(secret: &Hash, sender: &[u8; 32], bucket: u64, nonce: &[u8; NONCE_LEN], port: u16) -> [u8; TAG_LEN] {
    let mut tag = [0u8; TAG_LEN];
    crypto::derive_into(&mut tag, secret, nonce, &[b"vaulty.discovery.v2", sender, &bucket.to_le_bytes(), &port.to_le_bytes()]);
    tag
}

/// Where `waiter` waits at a relay for the one peer it shares `secret` with. Only the pair can work
/// it out, and it changes every period.
fn relay_tag(secret: &Hash, waiter: &[u8; 32], bucket: u64) -> Tag {
    let mut tag = [0u8; 32];
    crypto::derive_into(&mut tag, secret, &[], &[b"vaulte.relay.v1", waiter, &bucket.to_le_bytes()]);
    tag
}

/// What this device shares with each other device, for telling their beacons from anyone else's.
pub(crate) struct Neighbours {
    public: [u8; 32],
    peers: Vec<([u8; 32], Zeroizing<Hash>)>,
}

impl std::fmt::Debug for Neighbours {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Neighbours({})", self.peers.len())
    }
}

impl Neighbours {
    /// Works out a secret with each device in `peers`, by its public sync key.
    pub fn new(key: &[u8; 32], peers: impl IntoIterator<Item = [u8; 32]>) -> Result<Self> {
        const FAILED: Error = Error::Peer("a sync key could not be used");
        let private = agreement::PrivateKey::from_private_key(&X25519, key).map_err(|_| FAILED)?;
        let public = private.compute_public_key().map_err(|_| FAILED)?.as_ref().try_into().map_err(|_| FAILED)?;
        let agree = |peer: &[u8; 32]| {
            agreement::agree(&private, UnparsedPublicKey::new(&X25519, peer), FAILED, |secret| {
                Ok(Zeroizing::new(crypto::hash(&[b"vaulty.discovery.key.v2", secret])))
            })
        };
        // A key that agrees on nothing is one peer lost, not all of them.
        Ok(Self { public, peers: peers.into_iter().filter_map(|peer| Some((peer, agree(&peer).ok()?))).take(MAX_TAGS).collect() })
    }

    /// A beacon only these peers can recognize, sharing nothing with the last one.
    pub fn beacon(&self, port: u16) -> Beacon {
        self.beacon_at(port, now_ms() / TAG_PERIOD_MS)
    }

    fn beacon_at(&self, port: u16, bucket: u64) -> Beacon {
        let nonce: [u8; NONCE_LEN] = crypto::random();
        let mut tags: Vec<[u8; TAG_LEN]> = self.peers.iter().map(|(_, secret)| tag_for(secret, &self.public, bucket, &nonce, port)).collect();
        // Random tags look the same as real ones, so this says nothing about how many devices there are.
        while tags.len() < MIN_TAGS {
            tags.push(crypto::random());
        }
        Beacon::Sync { port, nonce, tags }
    }

    /// Whether a beacon came from one of these peers, allowing for a change of period between two
    /// clocks. Only a peer's own tags count, so a device never recognizes itself.
    pub fn recognizes(&self, beacon: &Beacon) -> bool {
        self.recognizes_at(beacon, now_ms() / TAG_PERIOD_MS)
    }

    /// The tags this device waits under at a relay: one per peer, for each period a peer's clock may
    /// be in. Random ones pad it as they do a beacon.
    pub fn relay_tags(&self) -> Vec<Tag> {
        let bucket = now_ms() / TAG_PERIOD_MS;
        let mut tags: Vec<Tag> = [bucket.saturating_sub(1), bucket, bucket + 1]
            .iter()
            .flat_map(|bucket| self.peers.iter().map(move |(_, secret)| relay_tag(secret, &self.public, *bucket)))
            .collect();
        while tags.len() < 3 * MIN_TAGS {
            tags.push(crypto::random());
        }
        tags
    }

    /// Where `peer` waits at a relay now, if it is one of these.
    pub fn relay_tag_of(&self, peer: &[u8; 32]) -> Option<Tag> {
        let (_, secret) = self.peers.iter().find(|(key, _)| key == peer)?;
        Some(relay_tag(secret, peer, now_ms() / TAG_PERIOD_MS))
    }

    fn recognizes_at(&self, beacon: &Beacon, bucket: u64) -> bool {
        let Beacon::Sync { port, nonce, tags } = beacon else { return false };
        [bucket.saturating_sub(1), bucket, bucket + 1]
            .iter()
            .any(|bucket| self.peers.iter().any(|(peer, secret)| tags.contains(&tag_for(secret, peer, *bucket, nonce, *port))))
    }
}

/// The discovery port. Test runs each take their own, because a machine running several at once
/// would otherwise hear each other as real devices.
fn port() -> u16 {
    if cfg!(feature = "test-hooks") {
        return std::env::var("LV_DISCOVERY_PORT").ok().and_then(|port| port.parse().ok()).unwrap_or(DEFAULT_PORT);
    }
    DEFAULT_PORT
}

/// Sends a beacon to the local network. Loopback stays on so devices on one machine, as in tests,
/// can see each other. Tests also send it straight to this machine: an operating system can stop a
/// process hearing multicast, and everything past the socket should be tested regardless.
pub(crate) fn announce(beacon: &Beacon) -> Result<()> {
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    socket.set_multicast_ttl_v4(1)?;
    socket.set_multicast_loop_v4(true)?;
    if cfg!(feature = "test-hooks") {
        let _ = socket.send_to(&beacon.encode(), SocketAddrV4::new(Ipv4Addr::LOCALHOST, port()));
    }
    socket.send_to(&beacon.encode(), SocketAddrV4::new(GROUP, port()))?;
    Ok(())
}

/// Listens for beacons. Several processes on one machine can share this port.
pub(crate) fn listen(timeout: Duration) -> Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port()).into())?;
    socket.join_multicast_v4(&GROUP, &Ipv4Addr::UNSPECIFIED)?;
    let socket: UdpSocket = socket.into();
    socket.set_read_timeout(Some(timeout))?;
    Ok(socket)
}

/// Waits for the next beacon, returning `None` on a timeout.
pub(crate) fn next_beacon(socket: &UdpSocket) -> Option<(Beacon, SocketAddr)> {
    let mut buffer = [0u8; MAX_BEACON];
    let (length, from) = socket.recv_from(&mut buffer).ok()?;
    Some((Beacon::decode(&buffer[..length])?, from))
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::agreement::{PrivateKey, X25519};

    use super::*;

    struct Device {
        key: [u8; 32],
        public: [u8; 32],
    }

    fn device() -> Device {
        let key: [u8; 32] = crypto::random();
        let public = PrivateKey::from_private_key(&X25519, &key).unwrap().compute_public_key().unwrap().as_ref().try_into().unwrap();
        Device { key, public }
    }

    fn neighbours(of: &Device, peers: &[&Device]) -> Neighbours {
        Neighbours::new(&of.key, peers.iter().map(|peer| peer.public)).unwrap()
    }

    #[test]
    fn beacons_round_trip_and_garbage_is_ignored() {
        for beacon in [Beacon::Join { port: 1 }, Beacon::Sync { port: 3, nonce: [2; 16], tags: vec![[4; 8], [5; 8]] }] {
            assert_eq!(Beacon::decode(&beacon.encode()), Some(beacon));
        }
        assert_eq!(Beacon::decode(b"nonsense"), None);
        assert_eq!(Beacon::decode(&[]), None);
        assert_eq!(Beacon::decode(&[Beacon::Join { port: 1 }.encode(), vec![0]].concat()), None, "one beacon, one encoding");
    }

    #[test]
    fn only_a_peer_knows_where_a_device_waits_at_a_relay() {
        let (first, second, stranger) = (device(), device(), device());
        let waiting = neighbours(&first, &[&second]).relay_tags();
        assert!(waiting.contains(&neighbours(&second, &[&first]).relay_tag_of(&first.public).unwrap()));
        assert!(!waiting.contains(&neighbours(&stranger, &[&first]).relay_tag_of(&first.public).unwrap()));
        assert_eq!(waiting.len(), 3 * MIN_TAGS, "padded, so the count says nothing");
    }

    #[test]
    fn a_join_beacon_says_nothing_about_the_person() {
        assert_eq!(Beacon::Join { port: 1 }.encode().len(), MAGIC.len() + 3);
    }

    #[test]
    fn a_peer_recognizes_a_beacon_and_nobody_else_does() {
        let (first, second, third) = (device(), device(), device());
        let beacon = neighbours(&first, &[&second, &third]).beacon(7000);
        assert!(neighbours(&second, &[&first, &third]).recognizes(&beacon));
        assert!(neighbours(&third, &[&first, &second]).recognizes(&beacon));

        // Everything in a log is known to this stranger, and every public key is.
        let stranger = device();
        assert!(!neighbours(&stranger, &[&first, &second, &third]).recognizes(&beacon));
    }

    #[test]
    fn a_beacon_does_not_say_how_many_devices_a_vault_has() {
        let (first, second, third) = (device(), device(), device());
        let length = |peers: &[&Device]| neighbours(&first, peers).beacon(7000).encode().len();
        assert_eq!(length(&[&second]), length(&[&second, &third]));
    }

    #[test]
    fn a_device_does_not_recognize_itself() {
        let (first, second) = (device(), device());
        let mine = neighbours(&first, &[&second]);
        assert!(!mine.recognizes(&mine.beacon(7000)));
    }

    #[test]
    fn a_removed_device_is_neither_tagged_nor_heard() {
        let (first, second, removed) = (device(), device(), device());
        let after = neighbours(&first, &[&second]);
        assert!(!neighbours(&removed, &[&first, &second]).recognizes(&after.beacon(7000)));
        let from_removed = neighbours(&removed, &[&first, &second]).beacon(7000);
        assert!(!after.recognizes(&from_removed));
    }

    #[test]
    fn nothing_in_a_beacon_repeats_so_it_cannot_be_followed() {
        let (first, second) = (device(), device());
        let mine = neighbours(&first, &[&second]);
        let (Beacon::Sync { nonce: one, tags: first_tags, .. }, Beacon::Sync { nonce: two, tags: second_tags, .. }) =
            (mine.beacon(7000), mine.beacon(7000))
        else {
            panic!("a sync beacon");
        };
        assert_ne!(one, two);
        assert_ne!(first_tags, second_tags);

        // Two devices in one vault are not linked by anything they send either.
        let theirs = neighbours(&second, &[&first]);
        let Beacon::Sync { tags: their_tags, .. } = theirs.beacon(7000) else { panic!("a sync beacon") };
        assert_ne!(first_tags, their_tags);
    }

    #[test]
    fn a_beacon_cannot_be_pointed_at_another_port_or_kept_for_long() {
        let (first, second) = (device(), device());
        let (mine, theirs) = (neighbours(&first, &[&second]), neighbours(&second, &[&first]));
        let Beacon::Sync { nonce, tags, .. } = mine.beacon_at(7000, 100) else { panic!("a sync beacon") };
        assert!(theirs.recognizes_at(&Beacon::Sync { port: 7000, nonce, tags: tags.clone() }, 101));
        assert!(!theirs.recognizes_at(&Beacon::Sync { port: 7001, nonce, tags: tags.clone() }, 100));
        assert!(!theirs.recognizes_at(&Beacon::Sync { port: 7000, nonce, tags }, 102));
    }

    #[test]
    fn a_full_beacon_fits_in_what_is_read() {
        let (first, peers) = (device(), (0..MAX_TAGS + 5).map(|_| device()).collect::<Vec<_>>());
        let beacon = neighbours(&first, &peers.iter().collect::<Vec<_>>()).beacon(7000);
        assert!(beacon.encode().len() <= MAX_BEACON);
    }
}
