//! Who is in the vault. Servers are machines nobody sits at, such as a VPS running agents. A
//! server holds the whole vault or the spaces it was enrolled with, and it has no say in the
//! roster whatever it signs, since its keys sit in a file. Who may approve a roster change, sign
//! at a fork or count toward the two devices a change needs is decided by `voters`.

use std::collections::BTreeSet;

use super::{Refusal, State};
use crate::crypto::Wrapped;
use crate::ids::{DeviceId, Generation, SpaceId};
use crate::record::DeviceRecord;

/// Whether a device still counts. A removed device keeps only the entries written before it
/// was removed, as far as the remover had seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    Active,
    Removed { entries_kept: u64 },
}

#[derive(Debug, Clone)]
pub struct Member {
    pub record: DeviceRecord,
    pub standing: Standing,
    pub label: Option<(Generation, Vec<u8>)>,
    /// The device whose log enrolled this one, which is the one that may name it.
    pub added_by: DeviceId,
    /// For a server, what it holds. A server has no say in the roster.
    pub server: Option<Holds>,
}

impl Member {
    pub(super) fn entries_kept(&self) -> Option<u64> {
        match self.standing {
            Standing::Active => None,
            Standing::Removed { entries_kept } => Some(entries_kept),
        }
    }

    pub(super) fn accepts(&self, seq: u64) -> bool {
        match self.standing {
            Standing::Active => true,
            Standing::Removed { entries_kept } => seq < entries_kept,
        }
    }
}

/// What a server was enrolled to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holds {
    Everything,
    Spaces(BTreeSet<SpaceId>),
}

impl Holds {
    /// As a server's entry names them: none for the whole vault.
    pub fn spaces(&self) -> Option<Vec<SpaceId>> {
        match self {
            Self::Everything => None,
            Self::Spaces(spaces) => Some(spaces.iter().copied().collect()),
        }
    }
}

/// A version of a space's key wrapped to a server holding the space, and who wrote it.
#[derive(Debug, Clone)]
pub struct SpaceWrap {
    pub space: SpaceId,
    pub version: Generation,
    pub device: DeviceId,
    pub wrapped: Wrapped,
    pub name: Vec<u8>,
    pub by: DeviceId,
}

impl State {
    /// What `id` was enrolled to hold, if that is only some spaces.
    pub fn spaces_held_by(&self, id: &DeviceId) -> Option<&BTreeSet<SpaceId>> {
        match &self.members.get(id)?.server {
            Some(Holds::Spaces(spaces)) => Some(spaces),
            Some(Holds::Everything) | None => None,
        }
    }

    /// A wrap counts only for a server holding that space, of a version on record. Anything else
    /// is something nobody should be given, and is passed over.
    pub(super) fn apply_space_wrap(&mut self, wrap: SpaceWrap) -> Result<(), Refusal> {
        if !self.spaces_held_by(&wrap.device).is_some_and(|spaces| spaces.contains(&wrap.space)) {
            return Err(Refusal::Skip("wraps a space to a device that does not hold it"));
        }
        if !self.spaces.get(&wrap.space).is_some_and(|versions| versions.contains_key(&wrap.version)) {
            return Err(Refusal::Skip("wraps a version of a space that is not on record"));
        }
        self.space_wraps.push(wrap);
        Ok(())
    }

    pub fn active_devices(&self) -> impl Iterator<Item = (&DeviceId, &Member)> {
        self.members.iter().filter(|(_, member)| member.standing == Standing::Active)
    }

    /// The enrolled devices with a say in the roster: every one but a server.
    pub fn voters(&self) -> impl Iterator<Item = (&DeviceId, &Member)> {
        self.active_devices().filter(|(_, member)| member.server.is_none())
    }

    pub(super) fn is_server(&self, id: &DeviceId) -> bool {
        self.members.get(id).is_some_and(|member| member.server.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::super::add_digest;
    use super::super::attacks::Forge;
    use super::super::tests::Actor;
    use super::Holds;
    use crate::crypto::{Hash, P256_PUBLIC_LEN, Wrapped};
    use crate::device::Device;
    use crate::device::server::Server;
    use crate::device::software::{Cost, Software};
    use crate::digest::server_digest;
    use crate::ids::DeviceId;
    use crate::ids::{Generation, SpaceId};
    use crate::record::{Approval, Approver, Body, DeviceRecord};
    use crate::setup::new_device;
    use crate::{Setup, Vault};

    fn approval(device: &dyn Device, by: DeviceId, digest: &Hash) -> Approval {
        Approval { by: Approver::Device(by), signature: device.authorize("test").unwrap().sign(digest).unwrap() }
    }

    /// What someone holding a server's key file can sign, which is anything.
    fn forged_by(server: &Server, by: DeviceId, digest: &Hash) -> Approval {
        Approval { by: Approver::Device(by), signature: server.authorize_unlock("unlock").unwrap().sign(digest).unwrap() }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        phone: Option<(Software, DeviceId)>,
        server: (Server, DeviceId),
    }

    /// A Mac, with a phone if `phone`, and a server holding the whole vault.
    fn fixture(phone: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let mut vault = Setup::new(Software::generate("p", Cost::FAST).unwrap()).create(&dir.path().join("vault"), "Mac").unwrap();
        vault.unlock("test").unwrap();
        let mac = vault.device();
        let phone = phone.then(|| {
            let device = Software::generate("p", Cost::FAST).unwrap();
            let record = new_device(&device).unwrap().record;
            let enrollment = vault.prepare_enrollment(record.clone(), "Phone").unwrap();
            vault.enroll(&enrollment, vec![approval(mac.as_ref(), vault.me, &enrollment.digest)]).unwrap();
            (device, record.id())
        });
        let server = Server::generate().unwrap();
        let record = new_device(&server).unwrap().record;
        let enrollment = vault.prepare_server_enrollment(record.clone(), "VPS", Holds::Everything).unwrap();
        let mut approvals = vec![approval(mac.as_ref(), vault.me, &enrollment.digest)];
        if let Some((phone, id)) = &phone {
            approvals.push(approval(phone, *id, &enrollment.digest));
        }
        vault.enroll(&enrollment, approvals).unwrap();
        assert!(vault.state.is_server(&record.id()));
        Fixture { _dir: dir, vault, phone, server: (server, record.id()) }
    }

    fn newcomer() -> DeviceRecord {
        new_device(&Software::generate("p", Cost::FAST).unwrap()).unwrap().record
    }

    #[test]
    fn a_server_s_signature_never_counts_toward_a_roster_change() {
        let Fixture { mut vault, phone, server: (server, server_id), .. } = fixture(true);
        let mac = vault.device();
        let record = newcomer();
        let enrollment = vault.prepare_enrollment(record.clone(), "Thief").unwrap();
        let approvals = vec![approval(mac.as_ref(), vault.me, &enrollment.digest), forged_by(&server, server_id, &enrollment.digest)];
        assert!(vault.enroll(&enrollment, approvals).is_err(), "a Mac and a server are one person's device, not two");

        let (phone, phone_id) = phone.unwrap();
        let approvals = vec![approval(mac.as_ref(), vault.me, &enrollment.digest), approval(&phone, phone_id, &enrollment.digest)];
        vault.enroll(&enrollment, approvals).unwrap();
        assert!(vault.state.members.contains_key(&record.id()), "two people's devices still can");
    }

    /// Enrolls `server` as a server holding `spaces`, or the whole vault, with the words, as a
    /// recovering one would.
    fn enroll_server(forge: &mut Forge, server: &Actor, clock: u64, spaces: Option<Vec<SpaceId>>) {
        let after = forge.state().roster_head();
        let digest = server_digest(&forge.vault, &after, &server.id(), &server.fresh.record, spaces.as_deref());
        let body = Body::ServerAdd { after, device: server.fresh.record.clone(), spaces, approvals: forge.approved_by_recovery(&digest) };
        forge.write(server, clock, &body);
    }

    fn adding(forge: &Forge, by: &Actor, newcomer: &Actor, signers: &[&Actor], words: bool) -> Body {
        let after = forge.state().roster_head();
        let digest = add_digest(&forge.vault, &after, &by.id(), &newcomer.fresh.record);
        let mut approvals: Vec<Approval> = signers.iter().map(|signer| signer.approve(&digest)).collect();
        if words {
            approvals.extend(forge.approved_by_recovery(&digest));
        }
        Body::DeviceAdd { after, device: newcomer.fresh.record.clone(), approvals }
    }

    #[test]
    fn a_change_a_server_signed_as_the_second_device_counts_on_no_copy() {
        let (mut forge, mac) = Forge::new();
        let phone = Actor::new();
        forge.enroll(&phone, 2);
        let server = Actor::new();
        enroll_server(&mut forge, &server, 3, None);
        assert!(forge.state().is_server(&server.id()));
        let thief = Actor::new();
        let body = adding(&forge, &mac, &thief, &[&mac, &server], false);
        forge.write(&mac, 4, &body);
        assert!(!forge.state().members.contains_key(&thief.id()));
    }

    #[test]
    fn a_server_s_signature_does_not_win_a_fork() {
        let (mut forge, mac) = Forge::new();
        let phone = Actor::new();
        forge.enroll(&phone, 2);
        let server = Actor::new();
        enroll_server(&mut forge, &server, 3, None);
        // Two additions at one position, each with the words. The phone's also carries the
        // server's signature, which would make it the stronger branch if it counted.
        let (first, second) = (Actor::new(), Actor::new());
        let earlier = adding(&forge, &mac, &first, &[], true);
        let later = adding(&forge, &phone, &second, &[&server], true);
        forge.write(&mac, 4, &earlier);
        forge.write(&phone, 5, &later);
        let state = forge.state();
        assert!(state.members.contains_key(&first.id()), "an even count goes by the clock");
        assert!(!state.members.contains_key(&second.id()));
    }

    #[test]
    fn a_server_neither_needs_nor_gives_a_second_approval() {
        let Fixture { vault, server: (_, server_id), .. } = fixture(false);
        assert!(!vault.needs_second_approval(), "with one Mac and a server, the Mac is the only device with a say");
        assert!(vault.state.voters().all(|(id, _)| *id != server_id));
        assert!(vault.state.active_devices().any(|(id, _)| *id == server_id), "it is still in the vault, and syncs");
    }

    #[test]
    fn a_server_cannot_remove_a_device_on_its_own_say() {
        let Fixture { mut vault, phone, server: (server, server_id), .. } = fixture(true);
        let (_, phone_id) = phone.unwrap();
        let removal = vault.prepare_removal("Phone").unwrap();
        let mac = vault.device();
        let approvals = vec![approval(mac.as_ref(), vault.me, &removal.digest), forged_by(&server, server_id, &removal.digest)];
        assert!(vault.remove_device(&removal, approvals).is_err());
        assert!(vault.state.voters().any(|(id, _)| *id == phone_id));
    }

    #[test]
    fn a_space_s_key_is_given_only_to_a_server_holding_that_space() {
        let (mut forge, mac) = Forge::new();
        let (agents, version) = forge.space(&mac, 2);
        let (personal, other) = forge.space(&mac, 3);
        let server = Actor::new();
        enroll_server(&mut forge, &server, 4, Some(vec![agents]));
        let phone = Actor::new();
        forge.enroll(&phone, 5);
        let wrap = |space, version, device| Body::SpaceWrap {
            space,
            version,
            device,
            wrapped: Wrapped { ephemeral: [4; P256_PUBLIC_LEN], ciphertext: vec![1], sealed: vec![2] },
            name: vec![3],
        };
        forge.write(&mac, 6, &wrap(personal, other, server.id()));
        forge.write(&mac, 7, &wrap(agents, version, phone.id()));
        forge.write(&mac, 8, &wrap(agents, Generation::first(phone.id()), server.id()));
        assert!(forge.state().space_wraps.is_empty(), "not its space, not a server, not a version on record");
        forge.write(&mac, 9, &wrap(agents, version, server.id()));
        assert_eq!(forge.state().space_wraps.len(), 1);
    }
}
