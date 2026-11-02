//! Carries out requests. What is allowed is decided in `policy`; this file only resolves names,
//! asks that table, and acts.

use std::collections::HashMap;

use super::grants::Grant;
use super::policy::{Action, Caller, Verdict, decide};
use super::{Broker, Connection};
use crate::device::software::present;
use crate::expiry;
use crate::ids::{ItemId, SpaceId};
use crate::item::{self, Meta, Secret};
use crate::protocol::{Envelope, Request, Response};
use crate::store::log::now_ms;
use crate::view::{ContactInfo, GrantInfo, HistoryInfo, ItemInfo, StatusInfo};
use crate::{Error, ErrorCode, Result, Vault};

pub(super) const MAX_GRANT_SECONDS: u64 = 24 * 60 * 60;

fn failure(error: &Error) -> Response {
    Response::Error { code: error.code(), message: error.to_string() }
}

/// Resolves which space a request means. A session is confined to its own.
pub(super) fn resolve_space(vault: &Vault, caller: &Caller, name: Option<&str>) -> Result<SpaceId> {
    match (caller, name) {
        (Caller::Session(grant), None) => Ok(grant.space),
        (Caller::Session(grant), Some(name)) => {
            let space = vault.space(name)?;
            if space.id == grant.space { Ok(space.id) } else { Err(Error::NotApproved("this session cannot use that space")) }
        }
        (Caller::Anyone | Caller::App, name) => Ok(vault.space(name.unwrap_or(crate::FIRST_SPACE))?.id),
    }
}

/// Names the other spaces an item is in, given the space it is listed in. Built once per
/// request, so a list costs one pass over the vault rather than one per item.
fn also_in(vault: &Vault, caller: &Caller) -> Result<impl Fn(&SpaceId, &ItemId) -> Vec<String>> {
    // A session sees one space, so the others an item is in are none of its business.
    let copies = if matches!(caller, Caller::Session(_)) { HashMap::new() } else { vault.copies() };
    // Only spaces this device can open, which on a server are the ones it holds.
    let names: HashMap<SpaceId, String> = vault.spaces()?.into_iter().map(|space| (space.id, space.name)).collect();
    Ok(move |space: &SpaceId, item: &ItemId| {
        copies.get(item).into_iter().flatten().filter(|other| *other != space).filter_map(|other| names.get(other).cloned()).collect()
    })
}

pub(super) fn space_name(vault: &Vault, id: &SpaceId) -> String {
    vault
        .spaces()
        .ok()
        .and_then(|spaces| spaces.into_iter().find(|space| space.id == *id))
        .map_or_else(|| "this space".to_owned(), |space| space.name)
}

pub(super) fn human_duration(seconds: u64) -> String {
    let minutes = seconds / 60;
    match minutes {
        60 => "1 hour".to_owned(),
        120.. => format!("{} hours", minutes / 60),
        _ => format!("{minutes} minutes"),
    }
}

impl Broker {
    pub(super) fn handle(&self, mut envelope: Envelope, connection: &mut Connection) -> Response {
        // Asking whether the broker is alive needs no permission and is not activity.
        if matches!(envelope.request, Request::Status) {
            return self.status(connection.app);
        }
        let _presented = present(envelope.passphrase.take());
        let caller = {
            let mut core = self.core();
            core.last_used = now_ms();
            match &envelope.session {
                None if connection.app => Caller::App,
                None => Caller::Anyone,
                Some(token) => match core.grants.find(token) {
                    Some(grant) => Caller::Session(grant.clone()),
                    None => return Response::Error { code: ErrorCode::Denied, message: "that session has ended; ask for a new grant".to_owned() },
                },
            }
        };
        match envelope.request {
            Request::Run { space, command, env, env_all } => match self.start_run(&caller, space.as_deref(), &command, &env, env_all) {
                Ok((run, env, scrub)) => {
                    connection.runs.push(run);
                    Response::Run { env, scrub }
                }
                Err(error) => failure(&error),
            },
            Request::Login { space, name, into } => self.login(&caller, space.as_deref(), &name, &into).unwrap_or_else(|error| failure(&error)),
            Request::FillOptions { origin } => self.fill_options(&caller, &origin).unwrap_or_else(|error| failure(&error)),
            Request::Fill { space, name, origin } => self.fill(&caller, &space, &name, &origin).unwrap_or_else(|error| failure(&error)),
            Request::PairBegin { address } => self.begin_pairing(&caller, address.as_deref(), connection).unwrap_or_else(|error| failure(&error)),
            Request::PairConfirm { recovery, spaces } => {
                self.confirm_pairing(&caller, recovery.as_deref(), spaces.as_deref(), connection).unwrap_or_else(|error| failure(&error))
            }
            request => self.dispatch(&caller, request).unwrap_or_else(|error| failure(&error)),
        }
    }

    /// Applies the policy. Waits for the person when it asks for a touch, holding no lock.
    pub(super) fn check(&self, caller: &Caller, action: Action<'_>) -> Result<()> {
        match decide(caller, action) {
            Verdict::Allow => Ok(()),
            Verdict::Refuse(reason) => Err(Error::NotApproved(reason)),
            Verdict::Touch(reason) => {
                self.before_prompt()?;
                self.device.authorize(&reason).map(drop)
            }
        }
    }

    #[allow(clippy::too_many_lines, reason = "one arm per request, which reads better than one function per arm")]
    fn dispatch(&self, caller: &Caller, request: Request) -> Result<Response> {
        match request {
            // Handled before dispatch.
            Request::Status
            | Request::Run { .. }
            | Request::PairBegin { .. }
            | Request::PairConfirm { .. }
            | Request::Login { .. }
            | Request::FillOptions { .. }
            | Request::Fill { .. } => Ok(Response::Ok),
            Request::AutofillIdentities => self.autofill_identities(caller),
            Request::PasskeyOptions { origin, allow } => self.passkey_options(caller, &origin, &allow),
            Request::CreatePasskey(request) => self.create_passkey(caller, &request),
            Request::SignPasskey { space, name, origin, client_data_hash } => self.sign_passkey(caller, &space, &name, &origin, &client_data_hash),
            Request::LockSettings => self.check(caller, Action::Read).map(|()| Response::LockSettings(self.core().settings)),
            Request::SetLockSettings { settings } => {
                self.check(caller, Action::ChangeLockSettings)?;
                settings.write(&self.home)?;
                self.core().settings = settings;
                Ok(Response::Ok)
            }
            Request::Stop => self.check(caller, Action::Stop).map(|()| Response::Ok),
            Request::Unlock => self.unlocked().map(|_| Response::Ok),
            Request::Lock => {
                self.check(caller, Action::Lock)?;
                self.core().lock();
                Ok(Response::Ok)
            }
            Request::Spaces => self.spaces(caller),
            Request::SpaceAdd { name } => {
                item::validate_text(&name)?;
                self.check(caller, Action::CreateSpace)?;
                self.unlocked()?.vault.create_space(&name)?;
                Ok(Response::Ok)
            }
            Request::List { space } => {
                self.check(caller, Action::Read)?;
                let core = self.unlocked()?;
                let id = resolve_space(&core.vault, caller, space.as_deref())?;
                let name = space_name(&core.vault, &id);
                let also_in = also_in(&core.vault, caller)?;
                let items = core
                    .vault
                    .items(&id)?
                    .into_iter()
                    .map(|item| ItemInfo { space: name.clone(), also_in: also_in(&id, &item.id), meta: item.meta })
                    .collect();
                Ok(Response::Items { items })
            }
            Request::Show { space, name } => {
                self.check(caller, Action::Read)?;
                let core = self.unlocked()?;
                let id = resolve_space(&core.vault, caller, space.as_deref())?;
                let found = core.vault.find(&id, &name)?;
                let also_in = also_in(&core.vault, caller)?(&id, &found.id);
                Ok(Response::Item { item: ItemInfo { space: space_name(&core.vault, &id), meta: found.meta, also_in } })
            }
            Request::Add { space, meta, secret, replace } => self.add(caller, space.as_deref(), meta, &secret, replace),
            Request::Import { space, items } => self.import(caller, space.as_deref(), items),
            Request::Remove { space, name } => {
                let (id, item) = self.locate(caller, space.as_deref(), &name)?;
                self.check(caller, Action::DeleteItem { name: &name })?;
                let mut core = self.open_core()?;
                core.vault.remove(&id, &item.id)?;
                core.vault.record("delete", &name, caller.name())?;
                Ok(Response::Ok)
            }
            Request::Undo => {
                drop(self.unlocked()?);
                self.check(caller, Action::Undo)?;
                let mut core = self.open_core()?;
                let count = core.vault.undo()?;
                core.vault.record("undo", "", caller.name())?;
                Ok(Response::Undone { count })
            }
            Request::History { space, name } => {
                self.check(caller, Action::Read)?;
                let core = self.unlocked()?;
                let id = resolve_space(&core.vault, caller, space.as_deref())?;
                let item = core.vault.find_any(&id, &name)?;
                let versions = core.vault.history(&id, &item)?;
                let versions = versions.iter().map(|version| HistoryInfo { at_ms: version.clock >> 16, deleted: version.meta.is_none() }).collect();
                Ok(Response::History { versions })
            }
            Request::Restore { space, name, version } => {
                let (id, item) = {
                    let core = self.unlocked()?;
                    let id = resolve_space(&core.vault, caller, space.as_deref())?;
                    (id, core.vault.find_any(&id, &name)?)
                };
                self.check(caller, Action::ReplaceItem { name: &name })?;
                let mut core = self.open_core()?;
                core.vault.restore(&id, &item, version)?;
                core.vault.record("restore", &name, caller.name())?;
                Ok(Response::Ok)
            }
            Request::Code { space, name } => self.current_code(caller, space.as_deref(), &name),
            Request::Codes { space } => self.current_codes(caller, space.as_deref()),
            Request::RemoveCode { space, name } => self.remove_code(caller, space.as_deref(), &name),
            Request::Expiring => self.expiring(caller),
            Request::Icon { space, url } => {
                self.check(caller, Action::Read)?;
                let core = self.open_core()?;
                let id = resolve_space(&core.vault, caller, space.as_deref())?;
                Ok(Response::Icon { png: core.vault.icon(&id, &url)? })
            }
            Request::SaveIcon { space, url, png } => {
                self.check(caller, Action::SaveIcon)?;
                let mut core = self.open_core()?;
                let id = resolve_space(&core.vault, caller, space.as_deref())?;
                core.vault.save_icon(&id, &url, &png)?;
                Ok(Response::Ok)
            }
            Request::Edit { space, name, meta, secret } => self.edit(caller, space.as_deref(), &name, meta, secret),
            Request::Link { space, name, to } => {
                let (from, item) = self.locate(caller, space.as_deref(), &name)?;
                let to_id = resolve_space(&self.unlocked()?.vault, caller, Some(&to))?;
                self.check(caller, Action::LinkItem { name: &name, to: &to })?;
                let mut core = self.open_core()?;
                core.vault.link(&from, &item.id, &to_id)?;
                core.vault.record("link", &name, caller.name())?;
                Ok(Response::Ok)
            }
            Request::Reveal { space, name } => {
                let (id, item) = self.locate(caller, space.as_deref(), &name)?;
                let target = space_name(&self.core().vault, &id);
                self.check(caller, Action::Reveal { name: &name, space: &target })?;
                let mut core = self.open_core()?;
                let secret = match core.vault.secret(&id, &item.id)? {
                    // The setup key stays here. `code` shows what it makes, and only a plaintext
                    // export, with its second approval, carries it out.
                    Secret::Login { ref password, .. } => Secret::Login { password: password.clone(), totp: None },
                    // And a passkey's private key: a site gets signatures, and nothing gets the key.
                    Secret::Passkey { ref rp_id, ref user_handle, ref credential_id, .. } => Secret::Passkey {
                        rp_id: rp_id.clone(),
                        user_handle: user_handle.clone(),
                        credential_id: credential_id.clone(),
                        private_key: String::new(),
                    },
                    other => other,
                };
                core.vault.record("reveal", &name, caller.name())?;
                Ok(Response::Secret { secret })
            }
            Request::Allow { space, name, host } => {
                item::validate_host(&host)?;
                let (id, item) = self.locate(caller, space.as_deref(), &name)?;
                self.check(caller, Action::AllowHost { name: &name, host: &host })?;
                let mut core = self.open_core()?;
                let secret = core.vault.secret(&id, &item.id)?;
                let mut meta = item.meta;
                if !meta.hosts.contains(&host) {
                    meta.hosts.push(host);
                }
                core.vault.replace(&id, &item.id, &meta, &secret)?;
                core.vault.record("allow", &name, caller.name())?;
                Ok(Response::Ok)
            }
            Request::Grant { space, agent, seconds, reason } => {
                self.grant(caller, space.as_deref(), &agent, seconds, reason.as_deref().unwrap_or_default())
            }
            Request::Grants => {
                self.check(caller, Action::ManageGrants)?;
                let mut core = self.core();
                let now = now_ms();
                let grants = core.grants.list();
                let grants = grants
                    .into_iter()
                    .map(|grant: Grant| GrantInfo {
                        seconds_left: grant.expires.saturating_sub(now) / 1000,
                        space: space_name(&core.vault, &grant.space),
                        id: grant.id,
                        agent: grant.agent,
                    })
                    .collect();
                Ok(Response::Grants { grants })
            }
            Request::GrantRevoke { id } => {
                self.check(caller, Action::ManageGrants)?;
                let mut core = self.core();
                if !core.grants.revoke(&id) {
                    return Err(Error::NotFound(format!("grant {id}")));
                }
                core.end_runs(|grant| grant == Some(id.as_str()));
                Ok(Response::Ok)
            }
            Request::Audit => {
                self.check(caller, Action::ReadAudit)?;
                Ok(Response::Audit { events: self.unlocked()?.vault.audit()? })
            }
            Request::Devices
            | Request::DeviceRemove { .. }
            | Request::RecoveryRotate { .. }
            | Request::Export { .. }
            | Request::BackupAdd { .. }
            | Request::BackupRemove { .. }
            | Request::BackupVerify { .. }
            | Request::SyncNow
            | Request::PeerAdd { .. }
            | Request::ResolveConflict { .. }
            | Request::Wipe { .. } => self.manage(caller, request),
            Request::RelaySubscribe { email, issuer } => self.relay_subscribe(caller, email.as_deref(), issuer),
            Request::RelayAccount { number, issuer } => self.use_relay_account(caller, &number, issuer),
            Request::RelayStatus => self.relay_status(caller),
        }
    }

    pub(super) fn locate(&self, caller: &Caller, space: Option<&str>, name: &str) -> Result<(SpaceId, crate::items::Summary)> {
        let core = self.unlocked()?;
        let id = resolve_space(&core.vault, caller, space)?;
        let item = core.vault.find(&id, name)?;
        Ok((id, item))
    }

    fn status(&self, trusted: bool) -> Response {
        let core = self.core();
        let problems = core.vault.problems().map(|problem| format!("{}: {}", problem.device, problem.reason)).collect();
        let contacts = core
            .vault
            .peer_ids()
            .into_iter()
            .map(|id| ContactInfo {
                device: core.vault.device_label(&id).unwrap_or_else(|| id.to_string()),
                last_ok_ms: core.places.contacts.get(&id).copied(),
            })
            .collect();
        Response::Status(StatusInfo {
            unlocked: core.vault.is_unlocked(),
            hardware: core.vault.is_hardware(),
            device_count: core.vault.device_count(),
            sync_port: self.sync_port.get().copied(),
            backups: core.places.backups.values().cloned().collect(),
            contacts,
            last_copy: core.vault.is_last_copy(),
            problems,
            build: super::build(),
            trusted,
            revision: core.vault.state.revision(),
        })
    }

    fn spaces(&self, caller: &Caller) -> Result<Response> {
        self.check(caller, Action::Read)?;
        let core = self.unlocked()?;
        let spaces = core.vault.spaces()?.into_iter();
        let spaces = match caller {
            Caller::Anyone | Caller::App => spaces.map(|space| space.name).collect(),
            Caller::Session(grant) => spaces.filter(|space| space.id == grant.space).map(|space| space.name).collect(),
        };
        Ok(Response::Spaces { spaces })
    }

    /// Cards running out, which an interface asks about in the background. So a locked vault
    /// just says so, and a person is never interrupted to find out nothing is wrong.
    fn expiring(&self, caller: &Caller) -> Result<Response> {
        self.check(caller, Action::Read)?;
        let core = self.core();
        if !core.vault.is_unlocked() {
            return Err(Error::Locked);
        }
        let now = crate::store::log::now_ms() / 1000;
        let also_in = also_in(&core.vault, caller)?;
        let mut items = Vec::new();
        for space in core.vault.spaces()? {
            if matches!(caller, Caller::Session(grant) if space.id != grant.space) {
                continue;
            }
            for item in core.vault.items(&space.id)? {
                if item.meta.expires.as_deref().is_some_and(|expires| expiry::runs_out_soon(expires, now)) {
                    items.push(ItemInfo { space: space.name.clone(), also_in: also_in(&space.id, &item.id), meta: item.meta });
                }
            }
        }
        Ok(Response::Items { items })
    }

    /// Changes an item in place, keeping its history. With no `secret`, the current one stays, so
    /// a rename or a new website does not mean typing a password again.
    fn edit(&self, caller: &Caller, space: Option<&str>, name: &str, meta: Meta, secret: Option<Secret>) -> Result<Response> {
        match &secret {
            Some(secret) => item::check(&meta, secret)?,
            None => item::validate(&meta)?,
        }
        let (id, current) = self.locate(caller, space, name)?;
        if meta.kind != current.meta.kind {
            return Err(Error::Invalid("an item cannot change kind"));
        }
        if meta.name != name && self.core().vault.find(&id, &meta.name).is_ok() {
            return Err(Error::Exists(meta.name));
        }
        self.check(caller, Action::ReplaceItem { name })?;
        let mut core = self.open_core()?;
        let stored = core.vault.secret(&id, &current.id)?;
        let mut secret = secret.unwrap_or_else(|| stored.clone());
        if let (Secret::Login { totp: given @ None, .. }, Secret::Login { totp: kept, .. }) = (&mut secret, &stored) {
            given.clone_from(kept);
        }
        core.vault.replace(&id, &current.id, &meta, &secret)?;
        core.vault.record("edit", name, caller.name())?;
        Ok(Response::Ok)
    }

    fn remove_code(&self, caller: &Caller, space: Option<&str>, name: &str) -> Result<Response> {
        let (id, current) = self.locate(caller, space, name)?;
        self.check(caller, Action::ReplaceItem { name })?;
        let mut core = self.open_core()?;
        let stored = core.vault.secret(&id, &current.id)?;
        let Secret::Login { password, totp: Some(_) } = &stored else {
            return Err(Error::NotFound(format!("a two-factor code for {name}")));
        };
        core.vault.replace(&id, &current.id, &current.meta, &Secret::Login { password: password.clone(), totp: None })?;
        core.vault.record("edit", name, caller.name())?;
        Ok(Response::Ok)
    }

    fn add(&self, caller: &Caller, space: Option<&str>, meta: Meta, secret: &Secret, replace: bool) -> Result<Response> {
        item::check(&meta, secret)?;
        let (id, existing) = {
            let core = self.unlocked()?;
            let id = resolve_space(&core.vault, caller, space)?;
            (id, core.vault.find(&id, &meta.name).ok())
        };
        let name = meta.name.clone();
        match existing {
            None => {
                self.check(caller, Action::CreateItem)?;
                let mut core = self.open_core()?;
                core.vault.add(&id, meta, secret)?;
                core.vault.record("add", &name, caller.name())?;
            }
            Some(_) if !replace => return Err(Error::Exists(name)),
            Some(item) => {
                self.check(caller, Action::ReplaceItem { name: &name })?;
                let mut core = self.open_core()?;
                core.vault.replace(&id, &item.id, &meta, secret)?;
                core.vault.record("replace", &name, caller.name())?;
            }
        }
        Ok(Response::Ok)
    }

    fn import(&self, caller: &Caller, space: Option<&str>, items: Vec<(Meta, Secret)>) -> Result<Response> {
        items.iter().try_for_each(|(meta, secret)| item::check(meta, secret))?;
        let (id, target) = {
            let core = self.unlocked()?;
            let id = resolve_space(&core.vault, caller, space)?;
            (id, space_name(&core.vault, &id))
        };
        self.check(caller, Action::Import { count: items.len(), space: &target })?;
        let mut core = self.open_core()?;
        let imported = core.vault.import(&id, items)?;
        core.vault.record("import", &target, caller.name())?;
        Ok(Response::Imported(imported))
    }

    /// Lets an agent use a space for a while, approved by the person wherever they are. `reason` is
    /// the agent's own words, shown after the facts.
    fn grant(&self, caller: &Caller, space: Option<&str>, agent: &str, seconds: u64, reason: &str) -> Result<Response> {
        if !reason.is_empty() {
            crate::item::validate_text(reason)?;
        }
        let (id, target) = {
            let core = self.unlocked()?;
            let id = resolve_space(&core.vault, caller, space)?;
            (id, space_name(&core.vault, &id))
        };
        let agent = super::grants::sanitize(agent);
        let seconds = seconds.min(MAX_GRANT_SECONDS);
        self.approve_grant(caller, id, &target, &agent, seconds, reason)?;
        let mut core = self.open_core()?;
        let (token, grant) = core.grants.issue(agent, id, std::time::Duration::from_secs(seconds));
        core.vault.record("grant", &target, &grant.agent)?;
        Ok(Response::Granted { token, id: grant.id, seconds })
    }
}
