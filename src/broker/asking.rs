//! Asking every device at once. The person may be at any of them, so a request goes to this device
//! and every other at the same moment, the first approval that verifies counts, and the rest are
//! called off, which takes their prompts away.

use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::Broker;
use super::asks::{Ask, grant_digest, in_its_words};
use super::handlers::human_duration;
use super::peers::{APPROVAL_TIMEOUT, ASK, MAX_APPROVAL, Route};
use super::policy::{Action, Caller, Verdict, decide};
use crate::crypto::{self, Hash};
use crate::device::Authorized;
use crate::ids::{DeviceId, SpaceId};
use crate::net::channel::Channel;
use crate::record::{Approval, Approver};
use crate::wire::Reader;
use crate::{Error, Result};

impl Broker {
    /// Stands in for a person in tests. A slow one gives up when called off, as a person's prompt
    /// goes away when they answer elsewhere.
    pub(super) fn before_prompt_unless(&self, cancelled: &AtomicBool) -> Result<()> {
        if cfg!(feature = "test-hooks") {
            if self.home.join("slow").exists() {
                let until = Instant::now() + Duration::from_secs(3);
                while Instant::now() < until {
                    if cancelled.load(Ordering::Acquire) {
                        return Err(Error::Cancelled);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            if self.home.join("deny").exists() {
                return Err(Error::Cancelled);
            }
        }
        Ok(())
    }

    /// Asks the person here, unless `cancelled` is set first because they answered elsewhere.
    pub(super) fn prompt_unless(&self, reason: &str, cancelled: &AtomicBool) -> Result<Box<dyn Authorized + '_>> {
        if cfg!(feature = "test-hooks") {
            use std::io::Write;
            let shown = std::fs::OpenOptions::new().create(true).append(true).open(self.home.join("prompts"));
            let _ = shown.and_then(|mut file| writeln!(file, "{reason}"));
        }
        self.before_prompt_unless(cancelled)?;
        self.device.authorize_unless(reason, cancelled)
    }

    /// A channel to every other device that answers, by address or else through a relay, leaving
    /// out `skip`, which has no say.
    fn connect_everyone(&self, skip: Option<&DeviceId>) -> Vec<(Channel, DeviceId)> {
        let mut channels: Vec<(Channel, DeviceId)> = Vec::new();
        self.reach_each(|route| {
            if let Route::Relay { device, .. } = route
                && skip == Some(device)
            {
                return Err(Error::Peer("that device has no say in this"));
            }
            let (channel, peer) = self.connect_peer(route)?;
            if skip != Some(&peer) && !channels.iter().any(|(_, known)| *known == peer) {
                channels.push((channel, peer));
            }
            Ok(peer)
        });
        channels
    }

    /// Puts `ask` to one device and waits for its person.
    fn ask_one(&self, mut channel: Channel, peer: DeviceId, ask: &Ask, digest: &Hash) -> Result<Approval> {
        channel.send(&[ASK])?;
        channel.send(&ask.encode())?;
        channel.wait_up_to(APPROVAL_TIMEOUT);
        let reply = channel.recv(MAX_APPROVAL)?;
        let mut r = Reader::new(&reply);
        let signature = crypto::HybridSignature { ec: r.array()?, pq: r.bytes()?.to_vec() };
        let approval = Approval { by: Approver::Device(peer), signature };
        self.core().vault.verify_peer_approval(digest, &approval, ask.target())?;
        Ok(approval)
    }

    /// Asks the person here with `here`, if anyone may be, and every other device with `ask`, all
    /// at once. The first approval that verifies counts. A refusal here ends it, since the person
    /// is here and said no. Anything else that goes wrong takes out only the device it happened on.
    /// The prompt here stays on this thread, which holds what the client presented for it.
    pub(super) fn ask_everyone(&self, here: Option<&str>, ask: &Ask, digest: &Hash) -> Result<Approval> {
        let channels = self.connect_everyone(ask.target());
        let lines: Vec<TcpStream> = channels.iter().filter_map(|(channel, _)| channel.try_clone_stream().ok()).collect();
        let hang_up = || {
            for line in &lines {
                let _ = line.shutdown(Shutdown::Both);
            }
        };
        let me = self.core().vault.me;
        let cancelled = AtomicBool::new(false);
        let (answers, answered) = mpsc::channel();
        std::thread::scope(|scope| {
            for (channel, peer) in channels {
                let answers = answers.clone();
                scope.spawn(move || answers.send(self.ask_one(channel, peer, ask, digest)));
            }
            drop(answers);
            // The first device to approve calls off the prompt here.
            let cancelled_here = &cancelled;
            let elsewhere = scope.spawn(move || {
                let approval = answered.iter().find_map(Result::ok);
                if approval.is_some() {
                    cancelled_here.store(true, Ordering::Release);
                }
                approval
            });
            let local = here.map(|reason| {
                let signature = self.prompt_unless(reason, &cancelled).and_then(|approved| approved.sign(digest));
                signature.map(|signature| Approval { by: Approver::Device(me), signature })
            });
            let refused_here = matches!(local, Some(Err(Error::Cancelled))) && !cancelled.load(Ordering::Acquire);
            if refused_here || matches!(local, Some(Ok(_))) {
                hang_up();
            }
            let elsewhere = elsewhere.join().ok().flatten();
            cancelled.store(true, Ordering::Release);
            hang_up();
            match (local, elsewhere) {
                (Some(Ok(approval)), _) => Ok(approval),
                _ if refused_here => Err(Error::Cancelled),
                (_, Some(approval)) => Ok(approval),
                (Some(Err(error)), None) => Err(error),
                (None, None) => Err(Error::NotApproved("no device approved this")),
            }
        })
    }

    /// A second approval, from whichever other device's person answers first.
    pub(super) fn ask_peers(&self, ask: &Ask, digest: &Hash) -> Option<Approval> {
        self.ask_everyone(None, ask, digest).ok()
    }

    /// Asks for an agent's grant wherever the person is: here, and on every other device. What
    /// they see comes from this vault, and the agent's reason after it, as its own words.
    pub(super) fn approve_grant(&self, caller: &Caller, space: SpaceId, space_name: &str, agent: &str, seconds: u64, reason: &str) -> Result<()> {
        let here = match decide(caller, Action::IssueGrant { agent, space: space_name, duration: &human_duration(seconds) }) {
            Verdict::Allow => return Ok(()),
            Verdict::Refuse(why) => return Err(Error::NotApproved(why)),
            Verdict::Touch(prompt) => format!("{prompt}{}", in_its_words(reason)),
        };
        let (me, from, vault) = {
            let core = self.core();
            (core.vault.me, core.vault.device_name(&core.vault.me), core.vault.vault_id())
        };
        let ask = Ask::Grant {
            nonce: crypto::random(),
            from,
            space,
            space_name: space_name.to_owned(),
            agent: agent.to_owned(),
            seconds,
            reason: reason.to_owned(),
        };
        self.ask_everyone(Some(&here), &ask, &grant_digest(vault, &me, &ask)).map(drop)
    }
}
