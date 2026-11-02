//! Changing who can open the vault. Anyone removed already holds the old keys, so every change
//! ends in a fresh epoch and fresh space keys.

use std::collections::{BTreeMap, BTreeSet};

use crate::binding::{Binding, Recipient};
use crate::crypto::{self, Hash, HybridSignature, Key};
use crate::digest::server_digest;
use crate::ids::{DeviceId, Generation, SpaceId};
use crate::record::{Approval, Approver, Body, DeviceRecord, RecoveryPublic, Sealed};
use crate::recovery::RecoveryKey;
use crate::state::{Holds, SpaceWrap, Standing, add_digest, epoch_commitment, revoke_digest, rotate_digest};
use crate::unlock::opened_links;
use crate::vault::{Vault, label_body, unused_name};
use crate::{Error, Result};

/// A fresh epoch worked out and not yet written.
struct Rotation {
    keys: Vec<Body>,
    /// Everything else this device holds, so whoever holds the new key reaches all of it.
    links: Vec<Body>,
    epoch: Generation,
    key: Key,
}

/// A removal that has been worked out and needs approvals.
#[derive(Debug)]
pub(crate) struct Removal {
    pub after: Hash,
    pub device: DeviceId,
    pub entries_kept: u64,
    pub last_kept: Hash,
    pub digest: Hash,
}

/// A new device that has been worked out and needs approvals.
#[derive(Debug)]
pub(crate) struct Enrollment {
    pub after: Hash,
    pub record: DeviceRecord,
    pub name: String,
    pub digest: Hash,
    /// For a server, what it may hold.
    pub server: Option<Holds>,
}

/// A new recovery key that has been worked out and needs approvals.
#[derive(Debug)]
pub(crate) struct RecoveryRotation {
    pub after: Hash,
    pub recovery: RecoveryPublic,
    pub proof: HybridSignature,
    pub digest: Hash,
}

impl Vault {
    /// A fresh epoch that only the remaining devices and `recovery` can open. Nothing is
    /// re-encrypted: what is in the logs stays there, so anyone removed can read it either way, and
    /// a value written again would look newer than an edit it never saw. What a rotation protects
    /// is what comes next.
    fn rotation(&self, recovery: &RecoveryPublic, leaving: Option<DeviceId>) -> Result<Rotation> {
        let keys = self.keys.as_ref().ok_or(Error::Locked)?;
        let vault = self.state.vault;
        let (previous, previous_key) = self.known_epochs().rfind(|(epoch, _)| !self.state.set_apart.contains(epoch)).ok_or(Error::Locked)?;
        let previous = *previous;
        // Above every generation on record, so as not to be one this device made and set apart.
        let number = self.state.epochs.keys().map(|epoch| epoch.number).max().unwrap_or(previous.number) + 1;
        let epoch = Generation { number, author: self.me };
        let epoch_key = Key::generate();

        let sealed = crypto::seal(&epoch_key, &Binding::EpochLink { vault, epoch }, previous_key.as_bytes());
        let roster = self.state.roster_head();
        let mut bodies = vec![Body::EpochLink { epoch, previous, commitment: epoch_commitment(&vault, epoch, &epoch_key), roster, sealed }];

        // A server holding chosen spaces gets no epoch: `repair` wraps it what replaces its spaces.
        let devices = self.state.active_devices().filter(|(id, _)| Some(**id) != leaving && self.state.spaces_held_by(id).is_none());
        for (id, member) in devices {
            let binding = Binding::Epoch { vault, epoch, recipient: Recipient::Device(*id) };
            bodies.push(Body::Wrap { epoch, sealed: Sealed::Device(*id, crypto::wrap(member.record.keys.wrap_to(), &binding, &epoch_key)?) });
        }
        let binding = Binding::Epoch { vault, epoch, recipient: Recipient::Recovery };
        bodies.push(Body::Wrap { epoch, sealed: Sealed::Recovery(recovery.id(), crypto::wrap(recovery.wrap_to(), &binding, &epoch_key)?) });

        let mut links = Vec::new();
        for head in self.heads().into_iter().filter(|head| *head != previous && !self.state.set_apart.contains(head)) {
            let sealed = crypto::seal(&epoch_key, &Binding::EpochLink { vault, epoch }, keys.epochs[&head].as_bytes());
            links.push(Body::ExtraLink { epoch, previous: head, sealed });
        }
        Ok(Rotation { keys: bodies, links, epoch, key: epoch_key })
    }

    /// Generations held here that no other held generation really reaches. Between them, they
    /// reach everything this device can read.
    fn heads(&self) -> Vec<Generation> {
        let reached: BTreeSet<Generation> =
            self.known_epochs().flat_map(|(epoch, key)| opened_links(&self.state, *epoch, key)).map(|(reached, _)| reached).collect();
        self.known_epochs().map(|(epoch, _)| *epoch).filter(|epoch| !reached.contains(epoch)).collect()
    }

    /// What reaches every generation here but those set apart, which go to the words and nobody
    /// else: each head, or for one set apart, what it reaches.
    fn heads_past_what_is_set_apart(&self) -> Vec<Generation> {
        let Some(keys) = self.keys.as_ref() else { return Vec::new() };
        let (mut heads, mut seen, mut pending) = (Vec::new(), BTreeSet::new(), self.heads());
        while let Some(epoch) = pending.pop() {
            if !seen.insert(epoch) {
                continue;
            }
            if self.state.set_apart.contains(&epoch) {
                pending.extend(opened_links(&self.state, epoch, &keys.epochs[&epoch]).into_iter().map(|(reached, _)| reached));
            } else {
                heads.push(epoch);
            }
        }
        heads
    }

    /// Writes a rotation, with `first` landing together with its keys. The rest can be many, and
    /// can stop partway, which `repair` finishes.
    fn commit_rotation(&mut self, first: Option<Body>, rotation: Rotation) -> Result<()> {
        let Rotation { keys, links, epoch, key } = rotation;
        self.commit_together(first.into_iter().chain(keys).collect())?;
        self.install_epoch(epoch, key)?;
        self.commit(&links)?;
        self.rekey_spaces()
    }

    fn install_epoch(&mut self, epoch: Generation, key: Key) -> Result<()> {
        self.keys.as_mut().ok_or(Error::Locked)?.epochs.insert(epoch, key);
        Ok(())
    }

    /// An approval from the 24 words, which stands in for a second device.
    pub(crate) fn recovery_approval(&self, words: &str, digest: &Hash) -> Result<Approval> {
        let key = RecoveryKey::parse(words)?;
        if !key.matches(&self.state.recovery)? {
            return Err(Error::WrongRecoveryKey);
        }
        Ok(Approval { by: Approver::Recovery, signature: key.sign(digest)? })
    }

    /// Whether the words are this vault's current recovery key.
    pub(crate) fn check_recovery_words(&self, words: &str) -> Result<()> {
        if RecoveryKey::parse(words)?.matches(&self.state.recovery)? { Ok(()) } else { Err(Error::WrongRecoveryKey) }
    }

    /// Whether `approval` is a valid signature over `digest` from an enrolled device other than
    /// this one, or than `target`, which has no say in its own removal.
    pub(crate) fn verify_peer_approval(&self, digest: &Hash, approval: &Approval, target: Option<&DeviceId>) -> Result<()> {
        let Approver::Device(id) = approval.by else { return Err(Error::NotApproved("that approval is from no device")) };
        let member = self.state.voters().find(|(device, _)| **device == id && id != self.me && Some(*device) != target).map(|(_, member)| member);
        let member = member.ok_or(Error::NotApproved("that approval is from no enrolled device"))?;
        approval
            .signature
            .verify(&member.record.keys.signing, &member.record.keys.dsa, digest)
            .map_err(|_| Error::NotApproved("that approval does not verify"))
    }

    /// Whether a sensitive action can go ahead on one device's say-so.
    pub(crate) fn needs_second_approval(&self) -> bool {
        self.state.voters().count() >= 2
    }

    /// Works out a removal without changing anything. A device cannot remove itself: that is
    /// `wipe`, which also covers the last device.
    pub(crate) fn prepare_removal(&self, name: &str) -> Result<Removal> {
        let device = self.device_named(name)?;
        let (entries_kept, last_kept) = self.held_log(&device);
        let after = self.state.roster_head();
        let digest = revoke_digest(&self.state.vault, &after, &self.me, &device, entries_kept, &last_kept);
        Ok(Removal { after, device, entries_kept, last_kept, digest })
    }

    /// Removes a device and rotates every key. Returns the names of everything it could read,
    /// because rotation cannot un-read what it already saw.
    pub(crate) fn remove_device(&mut self, removal: &Removal, approvals: Vec<Approval>) -> Result<Vec<String>> {
        self.state.verify_roster_change(&removal.after, &removal.digest, &approvals, Some(&removal.device))?;
        let mut exposed = Vec::new();
        for space in self.spaces()? {
            exposed.extend(self.items(&space.id)?.into_iter().map(|item| item.meta.name));
        }
        let recovery = self.state.recovery.clone();
        let rotation = self.rotation(&recovery, Some(removal.device))?;
        let revoke = Body::DeviceRevoke {
            after: removal.after,
            device: removal.device,
            entries_kept: removal.entries_kept,
            last_kept: removal.last_kept,
            approvals,
        };
        self.commit_rotation(Some(revoke), rotation)?;
        Ok(exposed)
    }

    /// Works out adding a device without changing anything. A name already in use gets a suffix.
    pub(crate) fn prepare_enrollment(&self, record: DeviceRecord, name: &str) -> Result<Enrollment> {
        let taken: Vec<String> = self.devices()?.into_iter().map(|device| device.name).collect();
        let unique = unused_name(name, &taken);
        let after = self.state.roster_head();
        let digest = add_digest(&self.state.vault, &after, &self.me, &record);
        Ok(Enrollment { after, record, name: unique, digest, server: None })
    }

    /// Works out adding a server, which holds `holds` and has no say in the roster.
    pub(crate) fn prepare_server_enrollment(&self, record: DeviceRecord, name: &str, holds: Holds) -> Result<Enrollment> {
        let mut enrollment = self.prepare_enrollment(record, name)?;
        enrollment.digest = server_digest(&self.state.vault, &enrollment.after, &self.me, &enrollment.record, holds.spaces().as_deref());
        enrollment.server = Some(holds);
        Ok(enrollment)
    }

    /// Adds a device, wrapping it every newest key this device holds.
    pub(crate) fn enroll(&mut self, enrollment: &Enrollment, approvals: Vec<Approval>) -> Result<()> {
        let id = enrollment.record.id();
        if self.state.members.contains_key(&id) {
            return Err(Error::Invalid("that device has been in this vault before, so it has to join with new keys"));
        }
        self.state.verify_roster_change(&enrollment.after, &enrollment.digest, &approvals, None)?;
        let keys = self.keys.as_ref().ok_or(Error::Locked)?;
        let vault = self.state.vault;
        let device = enrollment.record.clone();
        let mut bodies = vec![match &enrollment.server {
            None => Body::DeviceAdd { after: enrollment.after, device, approvals },
            Some(holds) => Body::ServerAdd { after: enrollment.after, device, spaces: holds.spaces(), approvals },
        }];
        let only = match &enrollment.server {
            Some(Holds::Spaces(spaces)) => Some(spaces),
            Some(Holds::Everything) | None => None,
        };
        for epoch in self.heads_past_what_is_set_apart().into_iter().filter(|_| only.is_none()) {
            let binding = Binding::Epoch { vault, epoch, recipient: Recipient::Device(id) };
            bodies.push(Body::Wrap {
                epoch,
                sealed: Sealed::Device(id, crypto::wrap(enrollment.record.keys.wrap_to(), &binding, &keys.epochs[&epoch])?),
            });
        }
        let (epoch, key) = self.key_for_records()?;
        bodies.push(label_body(vault, epoch, key, id, &enrollment.name)?);
        self.commit_together(bodies)?;
        // Apart from the enrollment, so no batch can grow past its limit. `repair` finishes them.
        let wraps = only.map(|spaces| self.space_wraps_for(&id, &enrollment.record, spaces)).transpose()?.unwrap_or_default();
        if wraps.is_empty() { Ok(()) } else { self.commit(&wraps) }
    }

    /// Wraps to a server every version it holds of `spaces` that this device can open and has not
    /// wrapped to it yet, so it reads what was written under any of them, with each space's name.
    fn space_wraps_for(&self, server: &DeviceId, record: &DeviceRecord, spaces: &BTreeSet<SpaceId>) -> Result<Vec<Body>> {
        let vault = self.state.vault;
        let mut bodies = Vec::new();
        for space in spaces {
            for version in self.state.spaces.get(space).into_iter().flat_map(BTreeMap::keys) {
                let wrote = |wrap: &&SpaceWrap| wrap.by == self.me && wrap.device == *server && wrap.space == *space && wrap.version == *version;
                if self.state.space_wraps.iter().any(|wrap| wrote(&wrap)) {
                    continue;
                }
                let Ok((name, key)) = self.space_in(&self.state, space, *version) else { continue };
                let binding = Binding::SpaceKey { vault, space: *space, version: *version, device: *server };
                let wrapped = crypto::wrap(record.keys.wrap_to(), &binding, &key)?;
                let name = crypto::seal(&key, &Binding::SpaceName { vault, space: *space, version: *version }, name.as_bytes());
                bodies.push(Body::SpaceWrap { space: *space, version: *version, device: *server, wrapped, name });
            }
        }
        Ok(bodies)
    }

    /// Works out a change of recovery key without changing anything.
    pub(crate) fn prepare_recovery_rotation(&self, new: &RecoveryKey) -> Result<RecoveryRotation> {
        let recovery = new.new_public(self.state.vault)?;
        let after = self.state.roster_head();
        let digest = rotate_digest(&self.state.vault, &after, &self.me, &recovery);
        Ok(RecoveryRotation { proof: new.sign(&digest)?, after, recovery, digest })
    }

    /// Replaces the recovery key and rotates every key, so the old words open nothing new.
    pub(crate) fn rotate_recovery(&mut self, rotation: RecoveryRotation, approvals: Vec<Approval>) -> Result<()> {
        self.state.verify_roster_change(&rotation.after, &rotation.digest, &approvals, None)?;
        let keys = self.rotation(&rotation.recovery, None)?;
        let change = Body::RecoveryRotate { after: rotation.after, recovery: rotation.recovery, proof: rotation.proof, approvals };
        self.commit_rotation(Some(change), keys)
    }

    /// Brings what is written next up to what the roster now says, using keys this device already
    /// holds. Everything here is worked out from the logs, so it is safe to repeat and safe to race,
    /// and it picks up wherever a crash or another device left off.
    pub(crate) fn repair(&mut self) -> Result<()> {
        if self.keys.is_none() || self.state.members.get(&self.me).is_none_or(|member| member.standing != Standing::Active) {
            return Ok(());
        }
        // A server holding chosen spaces has no epoch key to repair with, and waits for a device
        // that has one.
        if self.state.spaces_held_by(&self.me).is_some() {
            return Ok(());
        }
        if self.writing_epoch(&self.state.clean_epochs()).is_none() {
            // Nothing is decided on a partial view: a generation here has not been tried, and it
            // is probably what replaced these keys.
            if self.keys_are_stale() {
                return Ok(());
            }
            let recovery = self.state.recovery.clone();
            let rotation = self.rotation(&recovery, None)?;
            return self.commit_rotation(None, rotation);
        }
        self.share_newest_keys()?;
        self.rekey_spaces()?;
        self.rescue()
    }

    /// Wraps to everyone who should hold them the newest clean generations, and any generation
    /// nothing else reaches, which is what a race leaves behind and may hold what someone wrote.
    /// Only a wrap this device wrote counts as done: a device can write a wrap that opens nothing,
    /// and the words cannot be asked whether it does until they are all that is left. Extra wraps
    /// cost nothing.
    fn share_newest_keys(&mut self) -> Result<()> {
        let clean = self.state.clean_epochs();
        let newest = self.known_epochs().filter(|(epoch, _)| clean.contains(epoch)).map(|(epoch, _)| epoch.number).max();
        let mut heads = self.heads();
        heads.extend(self.heads_past_what_is_set_apart());
        let vault = self.state.vault;
        let recovery = &self.state.recovery;
        let mut bodies = Vec::new();
        for (epoch, key) in self.known_epochs().filter(|(epoch, _)| heads.contains(epoch) || (clean.contains(epoch) && Some(epoch.number) == newest))
        {
            let wrote = |wanted: &dyn Fn(&Sealed) -> bool| {
                self.state.wraps.iter().any(|wrap| wrap.by == self.me && wrap.epoch == *epoch && wanted(&wrap.sealed))
            };
            if !wrote(&|sealed| matches!(sealed, Sealed::Recovery(id, _) if *id == recovery.id())) {
                let binding = Binding::Epoch { vault, epoch: *epoch, recipient: Recipient::Recovery };
                bodies.push(Body::Wrap { epoch: *epoch, sealed: Sealed::Recovery(recovery.id(), crypto::wrap(recovery.wrap_to(), &binding, key)?) });
            }
            let devices = self
                .state
                .active_devices()
                .filter(|(id, _)| **id != self.me && !self.state.set_apart.contains(epoch) && self.state.spaces_held_by(id).is_none());
            for (id, member) in devices {
                if !wrote(&|sealed| matches!(sealed, Sealed::Device(device, _) if device == id)) {
                    let binding = Binding::Epoch { vault, epoch: *epoch, recipient: Recipient::Device(*id) };
                    bodies
                        .push(Body::Wrap { epoch: *epoch, sealed: Sealed::Device(*id, crypto::wrap(member.record.keys.wrap_to(), &binding, key)?) });
                }
            }
        }
        for (id, member) in self.state.active_devices() {
            if let Some(spaces) = self.state.spaces_held_by(id) {
                bodies.extend(self.space_wraps_for(id, &member.record, spaces)?);
            }
        }
        if bodies.is_empty() { Ok(()) } else { self.commit(&bodies) }
    }
}
