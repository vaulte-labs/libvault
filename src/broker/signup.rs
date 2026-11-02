//! Signing up for an agent. The agent fills in the form; the broker makes the password, puts it in
//! the page's password fields and saves the login, so the password never passes through the agent.
//! Whatever drives that browser could still read the page, which is why this only ever hands over
//! a password made for this sign-up, never one the vault already held.

use serde::Deserialize;

use super::Broker;
use super::agent_browser::AgentBrowser;
use super::browser::Tab;
use super::handlers::resolve_space;
use super::policy::{Action, Caller};
use crate::fill::{Origin, matches};
use crate::generate::{self, PasswordRules};
use crate::ids::SpaceId;
use crate::item::{self, Meta, Secret};
use crate::protocol::{Response, SignUpWith};
use crate::{Error, Result};

/// Finds the form's password fields, a new one and its confirmation, and reads the username the
/// agent typed. It reads the page and reports, and takes no input.
const FORM: &str = r"(() => {
  const usable = e => { const r = e.getBoundingClientRect(), s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !e.disabled && !e.readOnly; };
  const inputs = [...document.querySelectorAll('input')].filter(usable);
  const label = e => (e.name + ' ' + e.id + ' ' + e.autocomplete).toLowerCase();
  const passwords = inputs.filter(e => e.type === 'password');
  const user = inputs.find(e => e.autocomplete === 'username') || inputs.find(e => e.type === 'email' || /user|email|login|identifier/.test(label(e)));
  globalThis.lvFields = { password: passwords[0], confirm: passwords[1] };
  return JSON.stringify({ passwords: passwords.length, user: user ? user.value : '' });
})()";

#[derive(Debug, Deserialize)]
struct Form {
    passwords: usize,
    user: String,
}

/// The site an account is for: a URL's origin, or a bare name over https.
fn site_origin(site: &str) -> Result<Origin> {
    let url = if site.contains("://") { site.to_owned() } else { format!("https://{site}") };
    Origin::parse(&url).ok_or(Error::Invalid("that is not a site, like github.com"))
}

/// Puts `value` in each of the form's password fields, and says which it filled.
fn fill(tab: &mut Tab<'_, AgentBrowser>, world: u64, count: usize, value: &str) -> Result<()> {
    for field in ["password", "confirm"].into_iter().take(count) {
        if !tab.set_field(world, field, value)? {
            return Err(Error::LoginRefused("the password field disappeared"));
        }
    }
    Ok(())
}

impl Broker {
    /// Signs the agent up for `site` in its own browser, where it has the form open.
    pub(super) fn sign_up(&self, caller: &Caller, space: Option<&str>, site: &str, into: &str, with: SignUpWith) -> Result<Response> {
        let site = site_origin(site)?;
        let name = match with {
            SignUpWith::Password => self.sign_up_with_password(caller, space, &site, into)?,
            SignUpWith::Passkey => self.sign_up_with_passkey(caller, space, &site, into)?,
        };
        Ok(Response::SignedUp { name })
    }

    fn sign_up_with_password(&self, caller: &Caller, space: Option<&str>, site: &Origin, into: &str) -> Result<String> {
        let id = resolve_space(&self.unlocked()?.vault, caller, space)?;
        self.check(caller, Action::CreateItem)?;
        let saved = site.to_string();
        let password = generate::password(PasswordRules::default())?;
        let mut browser = AgentBrowser::connect(into)?;
        let mut tab = browser.tab(&site.host, |page| matches(&saved, page))?;
        let world = tab.world()?;
        let form: Form = serde_json::from_str(&tab.evaluate(world, FORM)?).map_err(|_| Error::Peer("the page could not be read"))?;
        // Read after the world, so a page that moved on takes the world with it.
        if !Origin::parse(&tab.url()?).is_some_and(|page| matches(&saved, &page)) {
            return Err(Error::LoginRefused("the page moved to another site"));
        }
        if form.passwords == 0 {
            return Err(Error::Invalid("the page has no password field. Open the sign-up form first"));
        }
        fill(&mut tab, world, form.passwords, &password)?;
        let user = Some(form.user).filter(|user| !user.is_empty());
        self.save_login(caller, &id, site, user, &Secret::Login { password: password.to_string(), totp: None }).inspect_err(|_| {
            // Nothing was saved, so nothing may be submitted with it.
            let _ = fill(&mut tab, world, form.passwords, "");
        })
    }

    fn save_login(&self, caller: &Caller, space: &SpaceId, site: &Origin, user: Option<String>, secret: &Secret) -> Result<String> {
        let mut core = self.open_core()?;
        let taken: Vec<String> = core.vault.items(space)?.into_iter().map(|item| item.meta.name).collect();
        let name = crate::vault::unused_name(&site.host, &taken);
        let mut meta = Meta::login(name.clone());
        meta.urls = vec![site.to_string()];
        meta.username = user;
        item::check(&meta, secret)?;
        core.vault.add(space, meta, secret)?;
        core.vault.record("signup", &name, caller.name())?;
        Ok(name)
    }
}
