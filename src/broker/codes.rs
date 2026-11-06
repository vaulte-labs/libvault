//! Two-factor codes. The setup key behind each stays in the broker; only the code it makes now
//! leaves.

use super::Broker;
use super::handlers::{resolve_space, space_name};
use super::policy::{Action, Caller};
use crate::ids::SpaceId;
use crate::item::Secret;
use crate::protocol::{CurrentCode, Response, SpaceCode};
use crate::{Error, Result, Totp};

impl Broker {
    pub(super) fn current_code(&self, caller: &Caller, space: Option<&str>, name: &str) -> Result<Response> {
        let (id, item) = self.locate(caller, space, name)?;
        let target = space_name(&self.core().vault, &id);
        self.check(caller, Action::Code { name, space: &target })?;
        let mut core = self.open_core()?;
        let secret = core.vault.secret(&id, &item.id)?;
        let Secret::Login { totp: Some(totp), .. } = &secret else {
            return Err(Error::NotFound(format!("a two-factor code for {name}")));
        };
        let (totp, now) = (Totp::parse(totp)?, crate::store::log::now_ms() / 1000);
        core.vault.record("code", name, caller.name())?;
        Ok(Response::Code(CurrentCode { code: totp.code(now), seconds_left: totp.seconds_left(now) }))
    }

    /// Every login's current code at once, in `space` or every space, for a view that shows them
    /// all live. One record says they were shown, not one per code. The vault's own app reads them
    /// again each half minute while its view is open, so for it only the first read of each space
    /// since the vault unlocked is recorded: Activity then says codes were on screen during that
    /// unlock, which is true, without a line every 30 seconds. Every other caller is recorded on
    /// every read.
    pub(super) fn current_codes(&self, caller: &Caller, space: Option<&str>) -> Result<Response> {
        let spaces: Vec<SpaceId> = {
            let core = self.unlocked()?;
            match space {
                Some(_) => vec![resolve_space(&core.vault, caller, space)?],
                None => core.vault.spaces()?.into_iter().map(|space| space.id).collect(),
            }
        };
        self.check(caller, Action::Codes)?;
        let mut core = self.open_core()?;
        let now = crate::store::log::now_ms() / 1000;
        let mut codes = Vec::new();
        for id in spaces {
            let space = space_name(&core.vault, &id);
            for item in core.vault.items(&id)?.into_iter().filter(|item| item.meta.two_factor) {
                let secret = core.vault.secret(&id, &item.id)?;
                // A setup key that cannot make codes costs its own row, not the whole view.
                let Secret::Login { totp: Some(totp), .. } = &secret else { continue };
                let Ok(totp) = Totp::parse(totp) else { continue };
                let current = CurrentCode { code: totp.code(now), seconds_left: totp.seconds_left(now) };
                codes.push(SpaceCode { space: space.clone(), name: item.meta.name, code: current });
            }
        }
        let target = space.unwrap_or("every space");
        if !matches!(caller, Caller::App) || core.codes_shown.insert(target.to_owned()) {
            core.vault.record("codes", target, caller.name())?;
        }
        Ok(Response::Codes { codes })
    }
}
