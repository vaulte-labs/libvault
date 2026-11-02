//! What one device asks another to approve. An approval is the only thing standing between one
//! compromised device and the rest, so all of this assumes the asker is lying.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::Vault;
use super::grants::sanitize;
use super::handlers::{MAX_GRANT_SECONDS, human_duration, space_name};
use crate::crypto::{self, Hash};
use crate::ids::{DeviceId, SpaceId};
use crate::record::DeviceRecord;
use crate::state::{add_digest, revoke_digest};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

/// How much of an agent's reason a prompt shows. Facts come first, so this is what gets cut.
const MAX_REASON_SHOWN: usize = 160;

/// How long after a refusal another device must wait to ask again, so that it cannot wear a person
/// down with prompts until one is approved by mistake.
const AFTER_REFUSAL: Duration = Duration::from_secs(if cfg!(feature = "test-hooks") { 0 } else { 30 });

/// A change another device wants this one to approve. It carries the change itself, not a digest,
/// so this device works out what it signs instead of signing what it is told.
#[derive(Debug)]
pub(super) enum Ask {
    Add {
        after: Hash,
        record: DeviceRecord,
        name: String,
    },
    /// A server, holding `spaces` or the whole vault, with no say in the roster.
    AddServer {
        after: Hash,
        record: DeviceRecord,
        name: String,
        spaces: Option<Vec<SpaceId>>,
    },
    Remove {
        after: Hash,
        device: DeviceId,
        entries_kept: u64,
        last_kept: Hash,
    },
    Export {
        nonce: [u8; 32],
    },
    /// An agent on the asking device wants a grant. `from` is that device's name for itself, and
    /// `reason` the agent's own words.
    Grant {
        nonce: [u8; 32],
        from: String,
        space: SpaceId,
        space_name: String,
        agent: String,
        seconds: u64,
        reason: String,
    },
}

impl Ask {
    /// The device this would remove, whose word on it counts for nothing.
    pub fn target(&self) -> Option<&DeviceId> {
        if let Self::Remove { device, .. } = self { Some(device) } else { None }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Self::Add { after, record, name } => {
                w.u8(0);
                w.array(after);
                record.write(&mut w);
                w.bytes(name.as_bytes());
            }
            Self::Remove { after, device, entries_kept, last_kept } => {
                w.u8(1);
                w.array(after);
                w.array(device.as_bytes());
                w.u64(*entries_kept);
                w.array(last_kept);
            }
            Self::Export { nonce } => {
                w.u8(2);
                w.array(nonce);
            }
            Self::AddServer { after, record, name, spaces } => {
                w.u8(4);
                w.array(after);
                record.write(&mut w);
                w.bytes(name.as_bytes());
                crate::digest::write_spaces(&mut w, spaces.as_deref());
            }
            Self::Grant { nonce, from, space, space_name, agent, seconds, reason } => {
                w.u8(3);
                w.array(nonce);
                w.bytes(from.as_bytes());
                w.array(space.as_bytes());
                w.bytes(space_name.as_bytes());
                w.bytes(agent.as_bytes());
                w.u64(*seconds);
                w.bytes(reason.as_bytes());
            }
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let name = |r: &mut Reader<'_>| String::from_utf8(r.bytes()?.to_vec()).map_err(|_| Error::Peer("the device sent a bad name"));
        let ask = match r.u8()? {
            0 => Self::Add { after: r.array()?, record: DeviceRecord::read(&mut r)?, name: name(&mut r)? },
            1 => Self::Remove { after: r.array()?, device: r.id()?, entries_kept: r.u64()?, last_kept: r.array()? },
            2 => Self::Export { nonce: r.array()? },
            4 => Self::AddServer {
                after: r.array()?,
                record: DeviceRecord::read(&mut r)?,
                name: name(&mut r)?,
                spaces: match r.u8()? {
                    0 => None,
                    1 => Some((0..r.u32()?).map(|_| r.id()).collect::<Result<_>>()?),
                    _ => return Err(Error::Peer("the other device asked for something unknown")),
                },
            },
            3 => Self::Grant {
                nonce: r.array()?,
                from: name(&mut r)?,
                space: r.id()?,
                space_name: name(&mut r)?,
                agent: name(&mut r)?,
                seconds: r.u64()?,
                reason: String::from_utf8(r.bytes()?.to_vec()).map_err(|_| Error::Peer("the device sent a bad reason"))?,
            },
            _ => return Err(Error::Peer("the other device asked for something unknown")),
        };
        r.finish()?;
        Ok(ask)
    }
}

/// A request from another device can be read back as sent, or it is refused.
#[cfg(feature = "fuzz")]
pub(crate) fn fuzz_ask(bytes: &[u8]) {
    if let Ok(ask) = Ask::decode(bytes) {
        assert_eq!(ask.encode(), bytes, "a request must have one encoding");
    }
}

/// What an approval of a plaintext export signs.
pub(super) fn export_digest(vault: crate::ids::VaultId, nonce: &[u8; 32]) -> Hash {
    crypto::hash(&[b"vaulty.export.v1", vault.as_bytes(), nonce])
}

/// What an approval of a grant signs: the whole request, and which device asked.
pub(super) fn grant_digest(vault: crate::ids::VaultId, asker: &DeviceId, ask: &Ask) -> Hash {
    crypto::hash(&[b"vaulte.grant.v1", vault.as_bytes(), asker.as_bytes(), &ask.encode()])
}

/// The agent's own words, after the facts, quoted so they read as its claim and cut so they cannot
/// push anything out of a prompt.
pub(super) fn in_its_words(reason: &str) -> String {
    let clean: String = reason.chars().map(|c| if c.is_control() || matches!(c, '"' | '\u{201c}' | '\u{201d}') { ' ' } else { c }).collect();
    let clean = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    if clean.is_empty() {
        return String::new();
    }
    let shown: String = if clean.chars().count() > MAX_REASON_SHOWN {
        clean.chars().take(MAX_REASON_SHOWN - 1).chain(std::iter::once('\u{2026}')).collect()
    } else {
        clean
    };
    format!(". It says: \u{201c}{shown}\u{201d}")
}

/// What a server would hold, in the words a person reads. Naming spaces needs the vault open.
pub(super) fn what_a_server_holds(vault: &Vault, spaces: Option<&[SpaceId]>) -> Result<String> {
    let Some(spaces) = spaces else { return Ok("your whole vault".to_owned()) };
    if !vault.is_unlocked() {
        return Err(Error::Locked);
    }
    Ok(spaces.iter().map(|space| sanitize(&space_name(vault, space))).collect::<Vec<_>>().join(", "))
}

/// What a request would have this device sign, and what to tell the person, worked out from this
/// device's own roster and never from what the asker says about it. An approval is the only thing
/// standing between one compromised device and the rest, so a prompt must name the real target.
pub(super) fn what_to_approve(vault: &Vault, ask: &Ask, peer: DeviceId) -> Result<(Hash, String)> {
    let id = vault.vault_id();
    let out_of_date = Error::Peer("that request is out of date");
    match ask {
        Ask::Add { after, record, name } => {
            if *after != vault.roster_head() {
                return Err(out_of_date);
            }
            crate::item::validate_text(name)?;
            Ok((add_digest(&id, after, &peer, record), format!("add {name}")))
        }
        Ask::AddServer { after, record, name, spaces } => {
            if *after != vault.roster_head() {
                return Err(out_of_date);
            }
            crate::item::validate_text(name)?;
            let holds = what_a_server_holds(vault, spaces.as_deref())?;
            let digest = crate::digest::server_digest(&id, after, &peer, record, spaces.as_deref());
            Ok((digest, format!("add {} as a server holding {holds}", sanitize(name))))
        }
        Ask::Remove { after, device, entries_kept, last_kept } => {
            if *after != vault.roster_head() {
                return Err(out_of_date);
            }
            if *device == vault.me {
                return Err(Error::NotApproved("a device gets no say in its own removal"));
            }
            if !vault.is_active(device) {
                return Err(Error::Peer("that is not an enrolled device"));
            }
            if vault.held_log(device) != (*entries_kept, *last_kept) {
                return Err(Error::Peer("that request does not match this device's copy of the log. Sync, then try again"));
            }
            if !vault.is_unlocked() {
                return Err(Error::Locked);
            }
            Ok((revoke_digest(&id, after, &peer, device, *entries_kept, last_kept), format!("remove {}", vault.device_name(device))))
        }
        Ask::Export { nonce } => {
            let from = vault.device_label(&peer).unwrap_or_else(|| "another device".to_owned());
            Ok((export_digest(id, nonce), format!("export secrets from {from}")))
        }
        // A locked device can answer this: it names nothing a device holding the vault could not
        // already use. One that can read its spaces refuses a request that names one wrongly.
        Ask::Grant { from, space, space_name: named, agent, seconds, reason, .. } => {
            for text in [from, named, agent] {
                crate::item::validate_text(text)?;
            }
            if !reason.is_empty() {
                crate::item::validate_text(reason)?;
            }
            if *seconds > MAX_GRANT_SECONDS {
                return Err(Error::Peer("that grant is longer than any device gives"));
            }
            if vault.is_unlocked() && space_name(vault, space) != *named {
                return Err(Error::Peer("that request names a space this vault does not have"));
            }
            let from = vault.device_label(&peer).unwrap_or_else(|| from.clone());
            let what = format!(
                "{} wants to let \"{}\" use {} for {}{}",
                sanitize(&from),
                sanitize(agent),
                sanitize(named),
                human_duration(*seconds),
                in_its_words(reason)
            );
            Ok((grant_digest(id, &peer, ask), what))
        }
    }
}

/// Keeps prompts asked for by other devices to one at a time, with a pause after a person refuses.
/// Only a real prompt counts: a request that never reached a person must not close this for others.
#[derive(Debug)]
pub(super) struct AskGate(Mutex<Instant>);

impl AskGate {
    pub fn new() -> Self {
        Self(Mutex::new(Instant::now()))
    }

    /// Runs one prompt. One called off because the person answered elsewhere is not a refusal.
    pub fn through<T>(&self, called_off: &AtomicBool, prompt: impl FnOnce() -> Result<T>) -> Result<T> {
        let mut next = self.0.try_lock().map_err(|_| Error::NotApproved("another request is waiting for a person"))?;
        if Instant::now() < *next {
            return Err(Error::NotApproved("a request like this was just refused. Try again shortly"));
        }
        let outcome = prompt();
        if outcome.is_err() && !called_off.load(Ordering::Acquire) {
            *next = Instant::now() + AFTER_REFUSAL;
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::device::Device;
    use crate::device::software::{Cost, Software};
    use crate::setup::new_device;
    use crate::{Setup, Vault};

    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        other: DeviceId,
    }

    /// A vault with a second device named "Old Mac", and this device named "Test Mac".
    fn vault_with_a_second_device() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let setup = Setup::new(Software::generate("p", Cost::FAST).unwrap());
        let words = setup.recovery().words().to_string();
        let mut vault = setup.create(&dir.path().join("vault"), "Test Mac").unwrap();
        vault.unlock("test").unwrap();
        let record = new_device(&Software::generate("p", Cost::FAST).unwrap() as &dyn Device).unwrap().record;
        let enrollment = vault.prepare_enrollment(record.clone(), "Old Mac").unwrap();
        let approvals = vec![vault.recovery_approval(&words, &enrollment.digest).unwrap()];
        vault.enroll(&enrollment, approvals).unwrap();
        Fixture { _dir: dir, vault, other: record.id() }
    }

    #[test]
    fn a_prompt_names_the_device_this_vault_says_it_is() {
        let Fixture { vault, other, .. } = vault_with_a_second_device();
        let (entries_kept, last_kept) = vault.held_log(&other);
        let ask = Ask::Remove { after: vault.roster_head(), device: other, entries_kept, last_kept };
        assert_eq!(what_to_approve(&vault, &ask, other).unwrap().1, "remove Old Mac");
    }

    fn grant(vault: &Vault, space_name: &str, reason: &str) -> Ask {
        let space = vault.space("Personal").unwrap().id;
        Ask::Grant {
            nonce: [0; 32],
            from: "VPS".into(),
            space,
            space_name: space_name.into(),
            agent: "bot".into(),
            seconds: 3600,
            reason: reason.into(),
        }
    }

    #[test]
    fn a_device_that_can_read_its_spaces_refuses_a_grant_that_names_one_wrongly() {
        let Fixture { vault, other, .. } = vault_with_a_second_device();
        assert!(what_to_approve(&vault, &grant(&vault, "Personal", "deploys"), other).is_ok());
        assert!(what_to_approve(&vault, &grant(&vault, "Servers", "deploys"), other).is_err());
    }

    #[test]
    fn an_agent_s_reason_comes_after_the_facts_as_its_own_words_and_cannot_push_them_out() {
        let Fixture { vault, other, .. } = vault_with_a_second_device();
        let (_, what) = what_to_approve(&vault, &grant(&vault, "Personal", "renewing the \"deploy\" token"), other).unwrap();
        assert_eq!(what, "Old Mac wants to let \"bot\" use Personal for 1 hour. It says: \u{201c}renewing the deploy token\u{201d}");
        let (_, what) = what_to_approve(&vault, &grant(&vault, "Personal", &"x".repeat(500)), other).unwrap();
        assert!(what.starts_with("Old Mac wants to let \"bot\" use Personal for 1 hour. It says: "), "{what}");
        assert!(what.chars().count() < 250, "{what}");
    }

    #[test]
    fn a_grant_reads_back_as_sent_and_its_approval_covers_every_word() {
        let Fixture { vault, other, .. } = vault_with_a_second_device();
        let ask = grant(&vault, "Personal", "deploys");
        assert_eq!(Ask::decode(&ask.encode()).unwrap().encode(), ask.encode());
        let other_reason = grant(&vault, "Personal", "deploy");
        assert_ne!(grant_digest(vault.vault_id(), &other, &ask), grant_digest(vault.vault_id(), &other, &other_reason));
        assert_ne!(grant_digest(vault.vault_id(), &other, &ask), grant_digest(vault.vault_id(), &vault.me, &ask), "it names who asked");
    }

    #[test]
    fn this_device_never_helps_remove_itself() {
        let Fixture { vault, other, .. } = vault_with_a_second_device();
        let (entries_kept, last_kept) = vault.held_log(&vault.me);
        let ask = Ask::Remove { after: vault.roster_head(), device: vault.me, entries_kept, last_kept };
        assert!(what_to_approve(&vault, &ask, other).is_err());
    }

    #[test]
    fn a_device_that_is_not_enrolled_cannot_be_removed() {
        let Fixture { vault, other, .. } = vault_with_a_second_device();
        let ask = Ask::Remove { after: vault.roster_head(), device: [9; 16].into(), entries_kept: 0, last_kept: [0; 32] };
        assert!(what_to_approve(&vault, &ask, other).is_err());
    }

    #[test]
    fn a_removal_must_keep_exactly_what_this_device_holds() {
        let Fixture { vault, other, .. } = vault_with_a_second_device();
        let (count, last) = vault.held_log(&other);
        for lie in [count + 1, u64::MAX] {
            let ask = Ask::Remove { after: vault.roster_head(), device: other, entries_kept: lie, last_kept: last };
            assert!(what_to_approve(&vault, &ask, other).is_err(), "kept {lie} entries of {count}");
        }
        let ask = Ask::Remove { after: vault.roster_head(), device: other, entries_kept: count, last_kept: [7; 32] };
        assert!(what_to_approve(&vault, &ask, other).is_err(), "a different history of the same length");
    }

    #[test]
    fn a_request_from_before_a_roster_change_is_out_of_date() {
        let Fixture { vault, other, .. } = vault_with_a_second_device();
        let ask = Ask::Remove { after: [7; 32], device: other, entries_kept: 0, last_kept: [0; 32] };
        assert!(what_to_approve(&vault, &ask, other).is_err());
    }

    #[test]
    fn prompts_for_other_devices_come_one_at_a_time() {
        let gate = Arc::new(AskGate::new());
        let (entered, release) = (std::sync::mpsc::channel(), std::sync::mpsc::channel::<()>());
        let (held, waiting) = (Arc::clone(&gate), release.1);
        let first = std::thread::spawn(move || {
            held.through(&AtomicBool::new(false), || {
                entered.0.send(()).unwrap();
                waiting.recv().unwrap();
                Ok(())
            })
        });
        entered.1.recv().unwrap();
        assert!(gate.through(&AtomicBool::new(false), || Ok(())).is_err(), "a second prompt while one is up");
        release.0.send(()).unwrap();
        first.join().unwrap().unwrap();
        gate.through(&AtomicBool::new(false), || Ok(())).unwrap();
    }

    #[test]
    fn a_refusal_holds_off_the_next_prompt() {
        let gate = AskGate(Mutex::new(Instant::now()));
        *gate.0.lock().unwrap() = Instant::now() + Duration::from_secs(60);
        assert!(gate.through(&AtomicBool::new(false), || Ok(())).is_err());
    }
}
