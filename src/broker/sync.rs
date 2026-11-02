//! When this device syncs, and with what. Every place it keeps in step with is in one table: the
//! addresses a person gave or a beacon showed, the relays, and the backup folders. A sync goes out
//! as soon as the logs here grow, by a write here or by taking one in, so a change travels on from
//! device to device without waiting.
//!
//! A direct call costs nothing, so a device calls every address on each beacon and beat: one whose
//! address changed may have no way to call back. Through a relay, which costs, a device is called
//! only when it is due: it may lack something here, or has been quiet long enough that it may hold
//! something this one lacks. One that cannot be reached there is tried again after a growing wait,
//! and everyone is called when this device comes back to a relay.
//!
//! Folders and devices sync on two threads, because a cloud folder can stall for as long as it
//! likes and must not hold up the devices.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::{SocketAddr, TcpListener, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::time::{Duration, Instant};

use super::Broker;
use super::peers::Route;
use crate::ids::DeviceId;
use crate::net::{discovery, relay};
use crate::store::log::now_ms;
use crate::store::{Growth, write_private};
use crate::sync::folder::{read_logs, vault_folder, write_logs};
use crate::{BackupInfo, Error, Result};

/// How often a device announces itself, renews its relay tags and checks on the others.
pub(super) const BEACON_EVERY: Duration = Duration::from_secs(10);
/// The least time between two syncs that growth sets off. A person's change goes out at once,
/// and a burst, such as an agent's audited uses, at most this often, all together.
const MIN_GAP: Duration = Duration::from_secs(1);
/// The least time between two syncs at one address, however often a beacon shows it.
const MIN_RESYNC: Duration = Duration::from_secs(3);
/// How long a device may go unheard before it is called anyway, in case a change missed it.
/// Changes go out as they happen, so this is only a backstop.
const CATCH_UP: Duration = Duration::from_mins(15);
/// The first wait before calling again a device that answered nowhere, doubling up to `CATCH_UP`.
const FIRST_RETRY: Duration = Duration::from_secs(10);
/// How often every folder is read, for what other devices wrote there.
const FOLDER_REFRESH: Duration = Duration::from_secs(30);
/// How a peer address names a relay rather than a device.
const RELAY_PREFIX: &str = "relay:";
const PEERS_FILE: &str = "peers.json";

/// Every place this device keeps in step with, and how each went. Part of `Core`, so it changes
/// under the one lock like everything else.
#[derive(Debug, Default)]
pub(super) struct Places {
    /// Each address and when it was last tried. A beacon's address stays only once a real device
    /// has answered there, because a beacon can be recorded and sent again from anywhere.
    addresses: BTreeMap<SocketAddr, Option<Instant>>,
    /// When each device last completed a sync with this one, by the wall clock.
    pub contacts: BTreeMap<DeviceId, u64>,
    /// How far the logs here had grown, by `Growth`'s count, when each device was last given all
    /// of them.
    holds: BTreeMap<DeviceId, u64>,
    /// When each device that answered nowhere may be called again, and the wait before that.
    retries: BTreeMap<DeviceId, (Instant, Duration)>,
    pub backups: BTreeMap<PathBuf, BackupInfo>,
}

impl Places {
    /// Whether `address` is due a sync, counting it as tried if it is.
    fn try_address(&mut self, address: SocketAddr) -> bool {
        let last = self.addresses.entry(address).or_default();
        let due = last.is_none_or(|last| last.elapsed() >= MIN_RESYNC);
        if due {
            *last = Some(Instant::now());
        }
        due
    }

    pub fn addresses(&self) -> Vec<SocketAddr> {
        self.addresses.keys().copied().collect()
    }

    /// Whether `device` should be called, with the logs here grown to `grown` and the wall clock at
    /// `now`: it may lack something, or has been quiet so long it may hold something, and it is not
    /// waiting out a failed call.
    fn due(&self, device: &DeviceId, grown: u64, now: u64) -> bool {
        let behind = self.holds.get(device).is_none_or(|holds| *holds < grown);
        let quiet = self.contacts.get(device).is_none_or(|last| Duration::from_millis(now.saturating_sub(*last)) >= CATCH_UP);
        let waiting = self.retries.get(device).is_some_and(|(next, _)| Instant::now() < *next);
        (behind || quiet) && !waiting
    }

    /// Notes a completed sync, after which `device` holds all the logs here had grown to `holds`.
    pub fn heard_from(&mut self, device: DeviceId, holds: u64) {
        self.contacts.insert(device, now_ms());
        self.holds.insert(device, holds);
        self.retries.remove(&device);
    }

    /// Notes that `device` answered nowhere, so it waits twice as long as last time to be called.
    fn missed(&mut self, device: DeviceId) {
        let gap = self.retries.get(&device).map_or(FIRST_RETRY, |(_, gap)| (*gap * 2).min(CATCH_UP));
        self.retries.insert(device, (Instant::now() + gap, gap));
    }

    /// Forgets what every device holds and every wait, so each is called once more. For coming
    /// back to a relay, after which anything sent meanwhile may have missed this device.
    fn call_everyone(&mut self) {
        self.holds.clear();
        self.retries.clear();
    }
}

/// Syncs set off by the logs here growing: the first after a quiet spell at once, then at most one
/// every `MIN_GAP`, taking in all that grew meanwhile.
struct Paced {
    growth: Arc<Growth>,
    seen: u64,
    last: Option<Instant>,
}

impl Paced {
    fn new(growth: Arc<Growth>) -> Self {
        Self { seen: growth.count(), growth, last: None }
    }

    /// Whether the logs grew within `timeout`, having waited out the gap since the last sync if so.
    fn grew_within(&mut self, timeout: Duration) -> bool {
        if self.growth.wait_past(self.seen, timeout) == self.seen {
            return false;
        }
        if let Some(last) = self.last {
            std::thread::sleep(MIN_GAP.saturating_sub(last.elapsed()));
        }
        self.seen = self.growth.count();
        self.last = Some(Instant::now());
        true
    }
}

/// The places a person gave: `host:port` for a device, `relay:host:port` for a relay.
fn given(home: &Path) -> Result<Vec<String>> {
    match fs::read(home.join("local").join(PEERS_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| Error::Corrupt("the peer list is damaged")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn resolve(address: &str) -> Option<SocketAddr> {
    address.to_socket_addrs().ok()?.next()
}

impl Broker {
    /// The addresses a person gave, as they resolve now.
    fn given_addresses(&self) -> Vec<SocketAddr> {
        let given = given(&self.home).unwrap_or_default();
        given.iter().filter(|place| !place.starts_with(RELAY_PREFIX)).filter_map(|address| resolve(address)).collect()
    }

    /// The relays a person gave.
    pub(super) fn relays(&self) -> Vec<String> {
        let given = given(&self.home).unwrap_or_default();
        given.into_iter().filter_map(|place| place.strip_prefix(RELAY_PREFIX).map(str::to_owned)).collect()
    }

    /// Remembers a place a person gave, such as a device reachable over Tailscale but out of
    /// multicast range, or a relay. Giving one twice changes nothing.
    pub(super) fn add_place(&self, place: &str) -> Result<()> {
        let reachable = resolve(place.strip_prefix(RELAY_PREFIX).unwrap_or(place));
        let resolved = reachable.ok_or(Error::Invalid(if place.starts_with(RELAY_PREFIX) {
            "that relay cannot be reached"
        } else {
            "that address cannot be reached"
        }))?;
        if !place.starts_with(RELAY_PREFIX) {
            self.core().places.addresses.entry(resolved).or_default();
        }
        let mut places = given(&self.home)?;
        if !places.iter().any(|existing| existing == place) {
            places.push(place.to_owned());
            let bytes = serde_json::to_vec(&places).map_err(|_| Error::Corrupt("the peer list could not be saved"))?;
            write_private(&self.home.join("local").join(PEERS_FILE), &bytes)?;
        }
        Ok(())
    }

    /// A route through each relay to each device not in `reached`, by the roster as it stands now.
    pub(super) fn relay_routes(&self, reached: &BTreeSet<DeviceId>) -> Vec<Route> {
        let relays = self.relays();
        if relays.is_empty() {
            return Vec::new();
        }
        let core = self.core();
        let devices: Vec<(DeviceId, [u8; 32])> = core
            .vault
            .peer_sync_keys()
            .into_iter()
            .filter_map(|sync| Some((core.vault.active_peer(&sync)?, sync)))
            .filter(|(device, _)| !reached.contains(device))
            .collect();
        drop(core);
        relays
            .iter()
            .flat_map(|relay| devices.iter().map(|(device, sync)| Route::Relay { relay: relay.clone(), device: *device, sync: *sync }))
            .collect()
    }

    /// Waits for a second device, then listens, announces and stays in step: with everyone at once
    /// when the logs here grow, and on every beat with whoever is due.
    pub(super) fn keep_peers_current(self: Arc<Self>) {
        while self.core().vault.device_count() < 2 {
            std::thread::sleep(Duration::from_millis(250));
        }
        let Ok(listener) = TcpListener::bind(("0.0.0.0", 0)) else { return };
        let Ok(port) = listener.local_addr().map(|address| address.port()) else { return };
        let _ = self.sync_port.set(port);

        // Shared by the port and every relay, so no way in can take more than the limit.
        let taken = Arc::new(AtomicUsize::new(0));
        let accepting = Arc::clone(&self);
        let slots = Arc::clone(&taken);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                accepting.serve_in_a_slot(stream, &slots);
            }
        });
        let listening = Arc::clone(&self);
        std::thread::spawn(move || listening.listen_for_beacons());

        let mut waiting_at = BTreeSet::new();
        let mut paced = Paced::new(Arc::clone(&self.core().vault.growth));
        let mut beat: Option<Instant> = None;
        loop {
            if beat.is_none_or(|beat| beat.elapsed() >= BEACON_EVERY) {
                beat = Some(Instant::now());
                if let Ok(neighbours) = self.neighbours() {
                    let _ = discovery::announce(&neighbours.beacon(port));
                }
                for relay in self.relays() {
                    if waiting_at.insert(relay.clone()) {
                        let waiting = Arc::clone(&self);
                        let slots = Arc::clone(&taken);
                        std::thread::spawn(move || waiting.wait_at_relay(&relay, &slots));
                    }
                }
                self.sync_given_addresses();
                self.sync_through_relays(BTreeSet::new());
            }
            let until_beat = beat.map_or(Duration::ZERO, |beat| BEACON_EVERY.saturating_sub(beat.elapsed()));
            if paced.grew_within(until_beat) {
                self.push();
            }
        }
    }

    /// Stays in step with addresses a person gave, which no beacon may ever reach. A sync that
    /// fails here changes nothing: the address is still the person's.
    fn sync_given_addresses(&self) {
        for address in self.given_addresses() {
            if self.core().places.try_address(address) {
                let _ = self.sync_with(&Route::Direct(address), None);
            }
        }
    }

    /// Sends a change out: to every address, then through the relays to each device that is due
    /// and was not reached there.
    fn push(&self) {
        let addresses = self.core().places.addresses();
        let reached = addresses.into_iter().filter_map(|address| self.sync_with(&Route::Direct(address), None).ok().map(|(peer, _)| peer)).collect();
        self.sync_through_relays(reached);
    }

    /// Calls through the relays each device that is due and not in `reached`. One that answers at
    /// none waits longer before the next call.
    fn sync_through_relays(&self, mut reached: BTreeSet<DeviceId>) {
        let due: BTreeSet<DeviceId> = {
            let core = self.core();
            let (grown, now) = (core.vault.growth.count(), now_ms());
            core.vault
                .peer_sync_keys()
                .iter()
                .filter_map(|sync| core.vault.active_peer(sync))
                .filter(|device| core.places.due(device, grown, now))
                .collect()
        };
        let mut called = BTreeSet::new();
        for route in self.relay_routes(&reached) {
            if let Route::Relay { device, .. } = &route
                && due.contains(device)
                && !reached.contains(device)
            {
                called.insert(*device);
                if let Ok((peer, _)) = self.sync_with(&route, None) {
                    reached.insert(peer);
                }
            }
        }
        let mut core = self.core();
        for device in called.difference(&reached) {
            core.places.missed(*device);
        }
    }

    fn listen_for_beacons(&self) {
        // Joining a multicast group fails with no network, and a network can come along later.
        let socket = loop {
            match discovery::listen(Duration::from_secs(1)) {
                Ok(socket) => break socket,
                Err(_) => std::thread::sleep(BEACON_EVERY),
            }
        };
        let mut neighbours = self.neighbours().ok();
        let mut refreshed = Instant::now();
        loop {
            let heard = discovery::next_beacon(&socket);
            if refreshed.elapsed() >= BEACON_EVERY {
                neighbours = self.neighbours().ok();
                refreshed = Instant::now();
            }
            let Some((beacon @ discovery::Beacon::Sync { port, .. }, from)) = heard else { continue };
            if !neighbours.as_ref().is_some_and(|neighbours| neighbours.recognizes(&beacon)) {
                continue;
            }
            let address = SocketAddr::new(from.ip(), port);
            if self.core().places.try_address(address) && self.sync_with(&Route::Direct(address), None).is_err() {
                self.core().places.addresses.remove(&address);
            }
        }
    }

    /// Stays at a relay for other devices to call in, under tags renewed on every beat, coming
    /// back whenever the connection drops. Calls to this device while it was away found nobody, so
    /// on coming back it calls everyone.
    fn wait_at_relay(self: &Arc<Self>, relay: &str, slots: &Arc<AtomicUsize>) {
        loop {
            let _ = (|| -> Result<()> {
                let mut waiting = relay::Waiting::open(relay, &self.neighbours()?.relay_tags(), &self.relay_pass())?;
                self.core().places.call_everyone();
                let mut renewed = Instant::now();
                loop {
                    if renewed.elapsed() >= BEACON_EVERY {
                        waiting.renew(&self.neighbours()?.relay_tags())?;
                        renewed = Instant::now();
                    }
                    if let Some(stream) = waiting.next(BEACON_EVERY)? {
                        self.serve_in_a_slot(stream, slots);
                    }
                }
            })();
            std::thread::sleep(BEACON_EVERY);
        }
    }

    /// Exchanges logs with one folder. No lock is held while touching it, because a cloud folder
    /// can stall for as long as it likes.
    fn sync_folder(&self, root: &Path) -> Result<()> {
        if !root.is_dir() {
            return Err(Error::Invalid("the folder is not available"));
        }
        let folder = vault_folder(root, self.core().vault.vault_id());
        self.take_in(read_logs(&folder)?, None, None)?;
        let settled = self.core().vault.logs_removals_kept();
        write_logs(&folder, &self.home, &settled)
    }

    pub(super) fn sync_backups(&self) {
        let Ok(roots) = self.core().vault.backup_roots() else { return };
        for root in roots {
            let outcome = self.sync_folder(&root);
            let mut core = self.core();
            let entry = core.places.backups.entry(root.clone()).or_insert_with(|| BackupInfo { path: root, last_ok_ms: None, problem: None });
            match outcome {
                Ok(()) => {
                    entry.last_ok_ms = Some(now_ms());
                    entry.problem = None;
                }
                Err(error) => entry.problem = Some(error.to_string()),
            }
        }
    }

    /// Copies out each change as it happens, and reads every folder now and then.
    pub(super) fn keep_backups_current(&self) {
        let mut paced = Paced::new(Arc::clone(&self.core().vault.growth));
        loop {
            self.sync_backups();
            paced.grew_within(FOLDER_REFRESH);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_due_once_per_interval_however_often_it_shows() {
        let mut places = Places::default();
        let address = SocketAddr::from(([127, 0, 0, 1], 7000));
        assert!(places.try_address(address), "never tried");
        assert!(!places.try_address(address), "tried a moment ago");
        places.addresses.insert(address, Instant::now().checked_sub(MIN_RESYNC));
        assert!(places.try_address(address));
    }

    #[test]
    fn a_change_after_a_quiet_spell_goes_at_once_and_a_burst_goes_together() {
        let growth = Arc::new(Growth::default());
        let mut paced = Paced::new(Arc::clone(&growth));
        assert!(!paced.grew_within(Duration::from_millis(20)), "nothing grew");

        growth.note();
        let started = Instant::now();
        assert!(paced.grew_within(Duration::from_secs(10)));
        assert!(started.elapsed() < Duration::from_millis(500), "the first change does not wait");

        for _ in 0..50 {
            growth.note();
        }
        let started = Instant::now();
        assert!(paced.grew_within(Duration::from_secs(10)));
        assert!(started.elapsed() >= MIN_GAP.saturating_sub(Duration::from_millis(50)), "a burst waits out the gap");
        assert!(!paced.grew_within(Duration::from_millis(20)), "and goes out as one sync, not fifty");
    }

    #[test]
    fn a_device_is_called_when_it_may_lack_something_or_has_been_quiet_long() {
        let mut places = Places::default();
        let device = DeviceId::from([1; 16]);
        let now = now_ms();
        assert!(places.due(&device, 0, now), "never synced since this device started");

        places.heard_from(device, 5);
        assert!(!places.due(&device, 5, now), "holds everything and was just heard");
        assert!(places.due(&device, 6, now), "the logs here grew since");
        let (heard, catch_up) = (places.contacts[&device], u64::try_from(CATCH_UP.as_millis()).unwrap());
        assert!(!places.due(&device, 5, heard + catch_up - 1), "not yet quiet long enough");
        assert!(places.due(&device, 5, heard + catch_up), "quiet long enough to have something");

        places.missed(device);
        assert!(!places.due(&device, 6, now), "waiting out a failed call");
        places.missed(device);
        assert_eq!(places.retries[&device].1, FIRST_RETRY * 2, "each miss waits twice as long");
        places.call_everyone();
        assert!(places.due(&device, 5, now), "back at a relay, everyone is called");
    }
}
