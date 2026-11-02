//! Keeping devices in step directly. A vault with one device opens no port. Past that, a peer is
//! checked against the roster before anything it sends is read, and whatever it offers then goes
//! through the same checks as a backup folder. Devices on different networks meet at a relay a
//! person gave, which carries the same channel and reads none of it.

use std::collections::BTreeSet;
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::Broker;
use super::asks::{Ask, what_to_approve};
use super::policy::{Action, Caller, Verdict, decide};
use crate::crypto::{self, Hash};
use crate::device::software::present;
use crate::ids::DeviceId;
use crate::net::channel::Channel;
use crate::net::discovery::Neighbours;
use crate::net::relay;
use crate::recovery::RecoveryKey;
use crate::sync::exchange;
use crate::wire::Writer;
use crate::{Error, Result};
use zeroize::Zeroizing;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Long enough for a person at the other device to answer.
pub(super) const APPROVAL_TIMEOUT: Duration = Duration::from_secs(65);
/// Even the largest vault crosses a slow network in less than this. Past it, the other device is
/// holding this up, and with it the next sync.
const SESSION_FOR_SYNC: Duration = Duration::from_mins(5);
const BEFORE_A_REMOVAL: Duration = Duration::from_secs(10);
/// More than a vault's devices ever need at once, and few enough that a flood costs little.
const MAX_CONNECTIONS: usize = 16;

const SYNC: u8 = 1;
pub(super) const ASK: u8 = 2;
const MAX_ASK: usize = 16 * 1024;
pub(super) const MAX_APPROVAL: usize = 8 * 1024;

/// Where another device can be reached: at an address, or through a relay as the device it is.
#[derive(Debug, Clone)]
pub(super) enum Route {
    Direct(SocketAddr),
    Relay { relay: String, device: DeviceId, sync: [u8; 32] },
}

/// Sets `cancelled` if the other side hangs up before `done`. It sends nothing while its person is
/// asked, so anything but silence means it has gone.
fn watch_for_hang_up(line: &TcpStream, cancelled: &AtomicBool, done: &AtomicBool) {
    let _ = line.set_read_timeout(Some(Duration::from_millis(100)));
    while !done.load(Ordering::Acquire) {
        match line.peek(&mut [0]) {
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            _ => {
                cancelled.store(true, Ordering::Release);
                return;
            }
        }
    }
}

/// One of a limited number of connections. Giving it up happens by dropping it.
#[derive(Debug)]
pub(super) struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(count: &Arc<AtomicUsize>) -> Option<Self> {
        count.try_update(Ordering::AcqRel, Ordering::Acquire, |taken| (taken < MAX_CONNECTIONS).then_some(taken + 1)).ok()?;
        Some(Self(Arc::clone(count)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Broker {
    fn prologue(&self) -> Vec<u8> {
        [b"vaulty.sync.v1".as_slice(), &self.core().vault.genesis()].concat()
    }

    /// Known to anyone holding a copy of the logs, and to nobody just passing on the network.
    fn vault_key(&self) -> Hash {
        crypto::hash(&[b"vaulty.sync.key.v1", &self.core().vault.genesis()])
    }

    /// Who is on the other end, by the roster. Anyone else is dropped unread.
    fn peer_id(&self, channel: &Channel) -> Result<DeviceId> {
        self.core().vault.active_peer(&channel.remote).ok_or(Error::Peer("that device is not enrolled"))
    }

    pub(super) fn connect_peer(&self, route: &Route) -> Result<(Channel, DeviceId)> {
        let stream = match route {
            Route::Direct(address) => TcpStream::connect_timeout(address, CONNECT_TIMEOUT)?,
            Route::Relay { relay, sync, .. } => {
                let tag = self.neighbours()?.relay_tag_of(sync).ok_or(Error::Peer("that device is not enrolled"))?;
                relay::dial(relay, &tag, &self.relay_pass())?
            }
        };
        let channel = Channel::initiate(stream, &self.sync_key, &self.prologue(), Some(&self.vault_key()))?;
        let peer = self.peer_id(&channel)?;
        Ok((channel, peer))
    }

    /// Lets end-to-end tests stand in for a device that is out of reach.
    fn out_of_reach(&self) -> bool {
        cfg!(feature = "test-hooks") && self.home.join("offline").exists()
    }

    pub(super) fn sync_with(&self, route: &Route, accept: Option<&RecoveryKey>) -> Result<(DeviceId, usize)> {
        self.sync_within(route, accept, None, Instant::now() + SESSION_FOR_SYNC)
    }

    /// One exchange along a route, over by `deadline`, unless `skip` is who answers there.
    fn sync_within(&self, route: &Route, accept: Option<&RecoveryKey>, skip: Option<&DeviceId>, deadline: Instant) -> Result<(DeviceId, usize)> {
        if self.out_of_reach() {
            return Err(Error::Peer("out of reach"));
        }
        if let Route::Relay { device, .. } = route
            && skip == Some(device)
        {
            return Ok((*device, 0));
        }
        let (mut channel, peer) = self.connect_peer(route)?;
        if skip == Some(&peer) {
            return Ok((peer, 0));
        }
        channel.give_up_by(deadline);
        channel.send(&[SYNC])?;
        let incoming = exchange::initiate(&mut channel, &self.home)?;
        let updated = self.take_in(incoming, accept)?;
        self.heard_from(peer);
        Ok((peer, updated))
    }

    /// Catches up before a removal, so that it follows the newest roster. The device being removed
    /// is not asked, and nothing here may hold the removal up for long: it may be that very device
    /// on the other end, and the person has already decided.
    pub(super) fn sync_peers_before_removing(&self, target: &DeviceId) {
        let deadline = Instant::now() + BEFORE_A_REMOVAL;
        self.reach_each(|route| {
            if Instant::now() < deadline {
                self.sync_within(route, None, Some(target), deadline).map(|(peer, _)| peer)
            } else {
                Err(Error::Peer("out of time"))
            }
        });
    }

    /// Runs `exchange` at every address, then through the relays to each device no address
    /// reached, so a device is never asked twice when one way works. Returns who answered, and
    /// how many attempts failed.
    pub(super) fn reach_each(&self, mut exchange: impl FnMut(&Route) -> Result<DeviceId>) -> (BTreeSet<DeviceId>, usize) {
        let mut reached = BTreeSet::new();
        let mut failed = 0;
        let direct: Vec<Route> = self.core().places.addresses().into_iter().map(Route::Direct).collect();
        for route in direct {
            match exchange(&route) {
                Ok(peer) => drop(reached.insert(peer)),
                Err(_) => failed += 1,
            }
        }
        for route in self.relay_routes(&reached) {
            if let Route::Relay { device, .. } = &route
                && reached.contains(device)
            {
                continue;
            }
            match exchange(&route) {
                Ok(peer) => drop(reached.insert(peer)),
                Err(_) => failed += 1,
            }
        }
        (reached, failed)
    }

    /// Takes in what every known device holds, with the words of the side a person chose.
    pub(super) fn settle_with_peers(&self, accept: &RecoveryKey) -> usize {
        let mut updated = 0;
        self.reach_each(|route| {
            let (peer, count) = self.sync_with(route, Some(accept))?;
            updated += count;
            Ok(peer)
        });
        updated
    }

    /// Brings every known device up to date now, returning how many answered and how many did not.
    /// Through a relay every enrolled device is within reach, so those it missed are counted.
    pub(super) fn sync_peers(&self) -> (usize, usize) {
        let (reached, failed) = self.reach_each(|route| self.sync_with(route, None).map(|(peer, _)| peer));
        if self.relays().is_empty() {
            return (reached.len(), failed);
        }
        (reached.len(), self.core().vault.peer_sync_keys().len().saturating_sub(reached.len()))
    }

    fn answer(&self, channel: &mut Channel, peer: DeviceId) -> Result<()> {
        let ask = Ask::decode(&channel.recv(MAX_ASK)?)?;
        // Another device can never open this vault. A removal needs a name, which needs it open,
        // so that one waits for the person here to unlock.
        let (digest, what) = what_to_approve(&self.core().vault, &ask, peer)?;
        // These are already in the words a person reads, and too long to be cut to a name's length.
        let reason = if let Ask::Grant { .. } | Ask::AddServer { .. } = ask {
            what
        } else {
            let Verdict::Touch(reason) = decide(&Caller::Anyone, Action::ApproveForDevice { what: &what }) else {
                return Err(Error::NotApproved("this needs a touch"));
            };
            reason
        };
        // The asker hangs up once someone has answered on another device, and the prompt here
        // goes with it.
        let line = channel.try_clone_stream()?;
        let (cancelled, done) = (AtomicBool::new(false), AtomicBool::new(false));
        let signature = std::thread::scope(|scope| {
            scope.spawn(|| watch_for_hang_up(&line, &cancelled, &done));
            let signature = self.asks.through(&cancelled, || {
                // With no secure hardware there is nobody to ask here, so this refuses unless a
                // test is standing in for the person.
                let test_passphrase = std::env::var("LV_TEST_PASSPHRASE").ok().filter(|_| cfg!(feature = "test-hooks"));
                let _presented = present(test_passphrase.map(Zeroizing::new));
                self.prompt_unless(&reason, &cancelled)?.sign(&digest)
            });
            done.store(true, Ordering::Release);
            signature
        })?;
        let mut w = Writer::new();
        w.array(&signature.ec);
        w.bytes(&signature.pq);
        channel.send(&w.finish())
    }

    fn serve_peer(&self, stream: TcpStream) -> Result<()> {
        if self.out_of_reach() {
            return Err(Error::Peer("out of reach"));
        }
        let mut channel = Channel::respond(stream, &self.sync_key, &self.prologue(), Some(&self.vault_key()))?;
        let peer = self.peer_id(&channel)?;
        match channel.recv(1)?.as_slice() {
            [SYNC] => {
                let incoming = exchange::respond(&mut channel, &self.home)?;
                self.take_in(incoming, None)?;
                self.heard_from(peer);
                Ok(())
            }
            [ASK] => self.answer(&mut channel, peer),
            _ => Err(Error::Peer("the other device sent something unexpected")),
        }
    }

    /// Who this device shares a beacon with, from the roster as it stands now.
    pub(super) fn neighbours(&self) -> Result<Neighbours> {
        Neighbours::new(&self.sync_key, self.core().vault.peer_sync_keys())
    }

    pub(super) fn serve_in_a_slot(self: &Arc<Self>, stream: TcpStream, slots: &Arc<AtomicUsize>) {
        let Some(slot) = Slot::take(slots) else { return };
        let serving = Arc::clone(self);
        std::thread::spawn(move || {
            let _slot = slot;
            serving.serve_peer(stream)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connections_past_the_limit_are_refused_until_one_ends() {
        let count = Arc::new(AtomicUsize::new(0));
        let slots: Vec<Slot> = (0..MAX_CONNECTIONS).map(|_| Slot::take(&count).unwrap()).collect();
        assert!(Slot::take(&count).is_none());
        drop(slots);
        assert!(Slot::take(&count).is_some());
    }
}
