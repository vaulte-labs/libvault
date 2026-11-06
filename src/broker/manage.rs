//! Requests that change the vault itself rather than what is in it: devices, recovery, backups,
//! exports and erasing.

use std::fs;
use std::path::Path;

use super::asks::{Ask, export_digest, what_a_server_holds};
use super::policy::{Action, Caller, Verdict, decide};
use super::{Broker, Connection};
use crate::crypto::Hash;
use crate::ids::DeviceId;
use crate::net::pair;
use crate::protocol::{Request, Response};
use crate::record::{Approval, Approver};
use crate::recovery::RecoveryKey;
use crate::state::Holds;
use crate::store::Logs;
use crate::sync::folder::{read_logs, vault_folder};
use crate::view::SyncReport;
use crate::{Error, Result};

impl Broker {
    /// Asks the person, and has this device's hardware sign what they approved. One touch.
    fn approve_and_sign(&self, caller: &Caller, action: Action<'_>, digest: &Hash) -> Result<Approval> {
        let me = self.core().vault.me;
        match decide(caller, action) {
            Verdict::Refuse(reason) => Err(Error::NotApproved(reason)),
            Verdict::Allow => Err(Error::NotApproved("this needs a touch")),
            Verdict::Touch(reason) => {
                self.before_prompt()?;
                let signature = self.device.authorize(&reason)?.sign(digest)?;
                Ok(Approval { by: Approver::Device(me), signature })
            }
        }
    }

    pub(super) fn manage(&self, caller: &Caller, request: Request) -> Result<Response> {
        match request {
            Request::Devices => {
                self.check(caller, Action::Read)?;
                Ok(Response::Devices { devices: self.unlocked()?.vault.devices()? })
            }
            Request::DeviceRemove { name, recovery } => {
                // A roster change must follow the newest one, or other devices will refuse it.
                let target = self.unlocked()?.vault.device_named(&name)?;
                self.sync_peers_before_removing(&target);
                let removal = self.unlocked()?.vault.prepare_removal(&name)?;
                let mut approvals = vec![self.approve_and_sign(caller, Action::RemoveDevice { name: &name }, &removal.digest)?];
                let ask =
                    Ask::Remove { after: removal.after, device: removal.device, entries_kept: removal.entries_kept, last_kept: removal.last_kept };
                approvals.extend(self.second_approval(&removal.digest, recovery.as_deref(), &ask)?);
                let mut core = self.open_core()?;
                let exposed = core.vault.remove_device(&removal, approvals)?;
                core.vault.record("remove-device", &name, caller.name())?;
                Ok(Response::Removed { exposed })
            }
            Request::RecoveryRotate { new_words, recovery } => {
                let new = RecoveryKey::parse(&new_words)?;
                self.sync_peers();
                let rotation = self.unlocked()?.vault.prepare_recovery_rotation(&new)?;
                let mut approvals = vec![self.approve_and_sign(caller, Action::RotateRecovery, &rotation.digest)?];
                let mut core = self.open_core()?;
                if let Some(words) = recovery {
                    approvals.push(core.vault.recovery_approval(&words, &rotation.digest)?);
                }
                core.vault.rotate_recovery(rotation, approvals)?;
                core.vault.record("rotate-recovery", "", caller.name())?;
                Ok(Response::Ok)
            }
            Request::Export { path, recovery, plaintext } => self.export(caller, &path, recovery.as_deref(), plaintext),
            Request::BackupAdd { path } => {
                self.check(caller, Action::AddBackup { folder: &path.display().to_string() })?;
                self.core().vault.add_backup(&path)?;
                self.sync_backups();
                Ok(Response::Ok)
            }
            Request::BackupRemove { path } => {
                self.check(caller, Action::RemoveBackup { folder: &path.display().to_string() })?;
                let mut core = self.core();
                core.vault.remove_backup(&path)?;
                core.places.backups.remove(&path);
                Ok(Response::Ok)
            }
            Request::BackupVerify { path } => {
                self.check(caller, Action::Read)?;
                let vault = self.core().vault.vault_id();
                let logs = read_logs(&vault_folder(&path, vault))?;
                if logs.is_empty() {
                    return Err(Error::Invalid("that folder holds no backup of this vault"));
                }
                Ok(Response::Verified(self.core().vault.verify_copy(&logs)?))
            }
            Request::SyncNow => {
                self.check(caller, Action::Read)?;
                self.sync_backups();
                let (peers_reached, peers_missed) = self.sync_peers();
                let backup_problems = self.core().places.backups.values().filter_map(|backup| backup.problem.clone()).collect();
                Ok(Response::Synced(SyncReport { peers_reached, peers_missed, backup_problems }))
            }
            Request::PeerAdd { address } => {
                self.check(caller, Action::ManageGrants)?;
                self.add_place(&address)?;
                Ok(Response::Ok)
            }
            Request::ResolveConflict { words } => {
                self.check(caller, Action::ResolveConflict)?;
                let accept = RecoveryKey::parse(&words)?;
                let (roots, vault) = {
                    let core = self.core();
                    (core.vault.backup_roots()?, core.vault.vault_id())
                };
                let mut devices_updated = 0;
                for root in roots {
                    devices_updated += self.take_in(read_logs(&vault_folder(&root, vault))?, Some(&accept), None)?;
                }
                devices_updated += self.settle_with_peers(&accept);
                Ok(Response::Settled { devices_updated })
            }
            Request::Wipe { device_name } => {
                let is_this_device = self.unlocked()?.vault.devices()?.iter().any(|device| device.is_this_device && device.name == device_name);
                if !is_this_device {
                    return Err(Error::Invalid("that is not this device's name"));
                }
                self.check(caller, Action::Wipe)?;
                let core = self.open_core()?;
                fs::remove_dir_all(&self.home)?;
                drop(core);
                Ok(Response::Wiped)
            }
            _ => Ok(Response::Ok),
        }
    }

    fn export(&self, caller: &Caller, path: &Path, recovery: Option<&str>, plaintext: bool) -> Result<Response> {
        drop(self.unlocked()?);
        let shown = path.display().to_string();
        self.check(caller, if plaintext { Action::ExportPlaintext { path: &shown } } else { Action::ExportArchive { path: &shown } })?;
        if plaintext {
            self.second_approval_for_export(recovery)?;
        }
        let mut core = self.open_core()?;
        if plaintext {
            core.vault.export_plaintext(path)?;
        } else {
            core.vault.export_archive(path)?;
        }
        // A removed device can still take out what it holds, but its log counts for nothing now.
        if core.vault.is_enrolled() {
            core.vault.record(if plaintext { "export-plaintext" } else { "export" }, "", caller.name())?;
        }
        Ok(Response::Ok)
    }

    /// What a second approval needs: the words if given, otherwise another device's say-so.
    fn second_approval(&self, digest: &Hash, words: Option<&str>, ask: &Ask) -> Result<Option<Approval>> {
        if !self.core().vault.needs_second_approval() {
            return Ok(None);
        }
        if let Some(words) = words {
            return self.core().vault.recovery_approval(words, digest).map(Some);
        }
        self.ask_peers(ask, digest).map(Some).ok_or(Error::NotApproved("this needs another device or the recovery key"))
    }

    fn second_approval_for_export(&self, words: Option<&str>) -> Result<()> {
        if !self.core().vault.needs_second_approval() {
            return Ok(());
        }
        if let Some(words) = words {
            return self.core().vault.check_recovery_words(words);
        }
        let nonce: [u8; 32] = crate::crypto::random();
        let digest = export_digest(self.core().vault.vault_id(), &nonce);
        self.ask_peers(&Ask::Export { nonce }, &digest).map(drop).ok_or(Error::NotApproved("this needs another device or the recovery key"))
    }

    pub(super) fn begin_pairing(&self, caller: &Caller, address: Option<&str>, connection: &mut Connection) -> Result<Response> {
        self.check(caller, Action::BeginPairing)?;
        // A code reaches a device on another network through this device's relays, else Vaulte's.
        let mut relays = self.relays();
        if !relays.iter().any(|relay| relay == crate::net::relay::HOSTED) {
            relays.push(crate::net::relay::HOSTED.to_owned());
        }
        let mut channel = pair::connect_to_joiner(address, &self.sync_key, pair::PERSON_TIMEOUT, &relays, &self.relay_pass())?;
        let words = pair::words_as_adder(&mut channel)?;
        connection.pairing = Some((channel, words.clone()));
        Ok(Response::Pairing { words })
    }

    /// Everything here waits on people, so nothing holds the core until the change is ready.
    pub(super) fn confirm_pairing(
        &self,
        caller: &Caller,
        recovery: Option<&str>,
        spaces: Option<&[String]>,
        connection: &mut Connection,
    ) -> Result<Response> {
        let (mut channel, words) = connection.pairing.take().ok_or(Error::Usage("no pairing is in progress"))?;
        let (record, name, server) = pair::receive_request(&mut channel)?;
        crate::item::validate_text(&name)?;
        self.sync_peers();
        let (enrollment, holds) = {
            let core = self.unlocked()?;
            if server {
                let holds = match spaces {
                    None => Holds::Everything,
                    Some(names) => Holds::Spaces(names.iter().map(|name| Ok(core.vault.space(name)?.id)).collect::<Result<_>>()?),
                };
                let enrollment = core.vault.prepare_server_enrollment(record, &name, holds)?;
                let holds = what_a_server_holds(&core.vault, enrollment.server.as_ref().and_then(Holds::spaces).as_deref())?;
                (enrollment, Some(holds))
            } else if spaces.is_some() {
                return Err(Error::Invalid("only a server can hold chosen spaces. Join it with --server"));
            } else {
                (core.vault.prepare_enrollment(record, &name)?, None)
            }
        };
        let (name, words) = (&enrollment.name, &words);
        let action = match &holds {
            None => Action::AddDevice { name, words },
            Some(holds) => Action::AddServer { name, holds, words },
        };
        let mut approvals = vec![self.approve_and_sign(caller, action, &enrollment.digest)?];
        let (after, record, name) = (enrollment.after, enrollment.record.clone(), enrollment.name.clone());
        let ask = match &enrollment.server {
            None => Ask::Add { after, record, name },
            Some(holds) => Ask::AddServer { after, record, name, spaces: holds.spaces() },
        };
        approvals.extend(self.second_approval(&enrollment.digest, recovery, &ask)?);
        let logs = {
            let mut core = self.open_core()?;
            core.vault.enroll(&enrollment, approvals)?;
            core.vault.record("add-device", &enrollment.name, caller.name())?;
            core.vault.all_logs()?
        };
        pair::send_logs(&mut channel, &logs)?;
        Ok(Response::Paired { name: enrollment.name })
    }

    /// Merges logs, then locks if keys changed, or repairs with the keys already held. With `from`,
    /// they are what a device sent in an exchange, begun with the logs here grown to that count.
    pub(super) fn take_in(&self, logs: Logs, accept: Option<&RecoveryKey>, from: Option<(DeviceId, u64)>) -> Result<usize> {
        let mut core = self.core();
        let unchanged = from.is_some_and(|(_, began)| core.vault.growth.count() == began);
        let merged = core.vault.merge_logs(logs, accept)?;
        if let Some((device, began)) = from {
            // The device was sent everything here as of `began`, and holds what it sent. The logs
            // grow only under the core's lock, so an unchanged count means it now holds them all.
            let holds = if unchanged { core.vault.growth.count() } else { began };
            core.places.heard_from(device, holds);
        }
        if merged.must_lock {
            core.lock();
        } else {
            core.vault.repair()?;
        }
        Ok(merged.devices_updated)
    }
}
