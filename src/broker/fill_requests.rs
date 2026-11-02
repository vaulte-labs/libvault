//! Filling a field for a person, through an interface such as a browser extension.

use super::Broker;
use super::policy::{Action, Caller};
use crate::fill::{Origin, matches};
use crate::item::{Kind, Secret};
use crate::protocol::{AutofillIdentity, FillOption, Filled, Response};
use crate::{Error, Result, Totp};

impl Broker {
    /// Lists what could fill on a page. Names only, and only what matches its origin. A session
    /// sees only its space.
    pub(super) fn fill_options(&self, caller: &Caller, origin: &str) -> Result<Response> {
        self.check(caller, Action::Read)?;
        let origin = Origin::parse(origin).ok_or(Error::Invalid("that page has no origin"))?;
        // Clicking into a field must never raise a prompt, so a locked vault just says so.
        let core = self.core();
        if !core.vault.is_unlocked() {
            return Err(Error::Locked);
        }
        let mut options = Vec::new();
        for space in core.vault.spaces()? {
            if let Caller::Session(grant) = caller
                && space.id != grant.space
            {
                continue;
            }
            for item in core.vault.items(&space.id)? {
                let on_this_page = item.meta.kind == Kind::Login && item.meta.urls.iter().any(|saved| matches(saved, &origin));
                // A card or a profile suits any form, so it is offered everywhere and sent only
                // where a person approves.
                if on_this_page || matches!(item.meta.kind, Kind::Card | Kind::Profile) {
                    options.push(FillOption {
                        space: space.name.clone(),
                        name: item.meta.name,
                        kind: item.meta.kind,
                        username: item.meta.username,
                        hint: item.meta.hint,
                    });
                }
            }
        }
        Ok(Response::FillOptions { options })
    }

    /// Each login's sites and username in every space, for the system's autofill to suggest while
    /// the vault is locked. Like `fill_options`, it never prompts.
    pub(super) fn autofill_identities(&self, caller: &Caller) -> Result<Response> {
        self.check(caller, Action::AutofillIdentities)?;
        let core = self.core();
        let mut identities = Vec::new();
        for space in core.vault.spaces()? {
            for item in core.vault.items(&space.id)?.into_iter().filter(|item| item.meta.kind == Kind::Login) {
                for site in item.meta.urls.iter().filter_map(|url| Origin::parse(url)) {
                    let identity = AutofillIdentity {
                        site: site.host,
                        username: item.meta.username.clone(),
                        space: space.name.clone(),
                        name: item.meta.name.clone(),
                    };
                    if !identities.contains(&identity) {
                        identities.push(identity);
                    }
                }
            }
        }
        Ok(Response::AutofillIdentities { identities })
    }

    /// Returns what to put on a page. This is plaintext leaving the broker, so it takes a fresh
    /// touch that names the item and the page, and a login goes only to the origin it is saved for.
    pub(super) fn fill(&self, caller: &Caller, space: &str, name: &str, origin: &str) -> Result<Response> {
        let parsed = Origin::parse(origin).ok_or(Error::Invalid("that page has no origin"))?;
        // A session is refused before anything is looked up, so the answer says nothing about what
        // exists, and nothing prompts on its behalf.
        if matches!(caller, Caller::Session(_)) {
            return self.check(caller, Action::Fill { name, origin: &parsed.host }).map(|()| Response::Ok);
        }
        // A fill never opens the vault. A slow one could otherwise undo a lock, so a locked vault
        // says so here, as `fill_options` does, and unlocking stays one path.
        let (id, item) = {
            let core = self.open_core()?;
            let id = core.vault.space(space)?.id;
            (id, core.vault.find(&id, name)?)
        };
        match item.meta.kind {
            Kind::Login if item.meta.urls.iter().any(|saved| matches(saved, &parsed)) => {}
            Kind::Login => return Err(Error::NotApproved("that login is not saved for this site")),
            Kind::Card | Kind::Profile if parsed.scheme == "https" || parsed.is_loopback() => {}
            Kind::Card => return Err(Error::NotApproved("a card goes only to a secure page")),
            Kind::Profile => return Err(Error::NotApproved("a profile goes only to a secure page")),
            _ => return Err(Error::Invalid("only logins, cards and profiles go on a page")),
        }
        self.check(caller, Action::Fill { name, origin: &parsed.host })?;

        let mut core = self.open_core()?;
        let secret = core.vault.secret(&id, &item.id)?;
        core.vault.record("fill", name, &parsed.host)?;
        let current_code = match &secret {
            Secret::Login { totp: Some(totp), .. } => Some(Totp::parse(totp)?.now()),
            _ => None,
        };
        let secret = match &secret {
            Secret::Login { password, .. } => Secret::Login { password: password.clone(), totp: None },
            other => other.clone(),
        };
        Ok(Response::Filled(Box::new(Filled { username: item.meta.username, secret, code: current_code })))
    }
}
