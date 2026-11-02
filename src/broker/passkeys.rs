//! Passkeys for a browser: which ones fit a page, making one for a site, and signing a sign-in.
//! Making or using one takes a touch naming the site, even for the vault's own apps and for an
//! agent, because a passkey tells the site its user was just verified. Only a person lists them.

use super::Broker;
use super::handlers::resolve_space;
use super::policy::{Action, Caller};
use crate::fill::Origin;
use crate::ids::SpaceId;
use crate::item::{self, Kind, Meta, Secret};
use crate::passkey;
use crate::protocol::{PasskeyOption, PasskeyRequest, Response};
use crate::vault::Vault;
use crate::{Error, Result};

fn page(origin: &str) -> Result<Origin> {
    Origin::parse(origin).ok_or(Error::Invalid("that page has no origin"))
}

/// Every passkey in the vault, with the space it is in, its listing and its secret.
fn passkeys(vault: &Vault) -> Result<Vec<(String, SpaceId, Meta, Secret)>> {
    let mut found = Vec::new();
    for space in vault.spaces()? {
        for item in vault.items(&space.id)?.into_iter().filter(|item| item.meta.kind == Kind::Passkey) {
            let secret = vault.secret(&space.id, &item.id)?;
            found.push((space.name.clone(), space.id, item.meta, secret));
        }
    }
    Ok(found)
}

fn rp_id(secret: &Secret) -> Option<&str> {
    if let Secret::Passkey { rp_id, .. } = secret { Some(rp_id) } else { None }
}

impl Broker {
    /// The passkeys that fit `origin`, or only those of `allow` when the site names its own. Names
    /// only, and never a prompt, as for fills.
    pub(super) fn passkey_options(&self, caller: &Caller, origin: &str, allow: &[Vec<u8>]) -> Result<Response> {
        self.check(caller, Action::ListPasskeys)?;
        let page = page(origin)?;
        let core = self.open_core()?;
        let options = passkeys(&core.vault)?
            .into_iter()
            .filter(|(_, _, _, secret)| rp_id(secret).is_some_and(|rp_id| passkey::fits(rp_id, &page)))
            .filter(|(_, _, _, secret)| allow.is_empty() || passkey::credential_id(secret).is_some_and(|id| allow.contains(&id)))
            .map(|(space, _, meta, _)| PasskeyOption { space, name: meta.name, user_name: meta.username })
            .collect();
        Ok(Response::PasskeyOptions { options })
    }

    /// Makes a passkey for the site and saves it, after a touch.
    pub(super) fn create_passkey(&self, caller: &Caller, request: &PasskeyRequest) -> Result<Response> {
        let PasskeyRequest { space, origin, rp_id, user_name, user_handle, exclude } = request;
        if !passkey::fits(rp_id, &page(origin)?) {
            return Err(Error::NotApproved("a page can make a passkey only for its own site"));
        }
        item::validate_text(user_name)?;
        let id = resolve_space(&self.open_core()?.vault, caller, space.as_deref())?;
        self.check(caller, Action::CreatePasskey { site: rp_id, user: user_name })?;
        let mut core = self.open_core()?;
        let made_before =
            passkeys(&core.vault)?.iter().any(|(_, _, _, secret)| passkey::credential_id(secret).is_some_and(|id| exclude.contains(&id)));
        if made_before {
            return Err(Error::Exists(format!("a passkey for {user_name} on {rp_id}")));
        }
        let (secret, mut created) = passkey::create(rp_id, user_handle)?;
        let taken: Vec<String> = core.vault.items(&id)?.into_iter().map(|item| item.meta.name).collect();
        let name = crate::vault::unused_name(&format!("{user_name} on {rp_id}"), &taken);
        let mut meta = Meta::new(Kind::Passkey, name.clone());
        meta.username = Some(user_name.to_owned());
        meta.urls = vec![format!("https://{rp_id}")];
        item::validate(&meta)?;
        core.vault.add(&id, meta, &secret)?;
        core.vault.record("passkey", &name, caller.name())?;
        created.name = name;
        Ok(Response::NewPasskey(created))
    }

    /// Signs a sign-in on `origin` with the passkey `name`, after a touch naming the passkey and
    /// the site. A passkey for another site is refused before anyone is asked.
    pub(super) fn sign_passkey(&self, caller: &Caller, space: &str, name: &str, origin: &str, client_data_hash: &[u8]) -> Result<Response> {
        let page = page(origin)?;
        let secret = {
            let core = self.open_core()?;
            let id = resolve_space(&core.vault, caller, Some(space))?;
            let found = core.vault.find(&id, name)?;
            if found.meta.kind != Kind::Passkey {
                return Err(Error::Invalid("that is not a passkey"));
            }
            core.vault.secret(&id, &found.id)?
        };
        let site = rp_id(&secret).ok_or(Error::Invalid("that is not a passkey"))?.to_owned();
        if !passkey::fits(&site, &page) {
            return Err(Error::NotApproved("that passkey is not for this site"));
        }
        self.check(caller, Action::UsePasskey { name, site: &site })?;
        let assertion = passkey::sign(&secret, client_data_hash)?;
        self.open_core()?.vault.record("passkey", name, &page.host)?;
        Ok(Response::PasskeyAssertion(assertion))
    }
}
