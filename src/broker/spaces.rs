//! Making, renaming and removing spaces. Each is checked before anyone is asked, so a touch is
//! never spent on something that would then be refused.

use super::Broker;
use super::policy::{Action, Caller};
use crate::Result;
use crate::protocol::Response;

impl Broker {
    pub(super) fn create_space(&self, caller: &Caller, name: &str) -> Result<Response> {
        self.check(caller, Action::CreateSpace)?;
        let mut core = self.unlocked()?;
        let space = core.vault.create_space(name)?;
        core.vault.record("create space", &space.name, caller.name())?;
        Ok(Response::Space { name: space.name })
    }

    pub(super) fn rename_space(&self, caller: &Caller, name: &str, to: &str) -> Result<Response> {
        let (space, to) = {
            let core = self.unlocked()?;
            let space = core.vault.space(name)?;
            let to = core.vault.check_rename(&space, to)?;
            (space, to)
        };
        self.check(caller, Action::RenameSpace { name: &space.name, to: &to })?;
        let mut core = self.open_core()?;
        let name = core.vault.rename_space(&space, &to)?;
        core.vault.record("rename space", &format!("{} to {name}", space.name), caller.name())?;
        Ok(Response::Space { name })
    }

    /// Ends the grants on it too, so no agent keeps writing into a space nobody can see.
    pub(super) fn remove_space(&self, caller: &Caller, name: &str) -> Result<Response> {
        let space = {
            let core = self.unlocked()?;
            let space = core.vault.space(name)?;
            core.vault.check_removable(&space)?;
            space
        };
        self.check(caller, Action::RemoveSpace { name: &space.name })?;
        let mut core = self.open_core()?;
        core.vault.remove_space(&space)?;
        let ended: Vec<String> = core.grants.list().into_iter().filter(|grant| grant.space == space.id).map(|grant| grant.id).collect();
        for id in &ended {
            core.grants.revoke(id);
        }
        core.end_runs(|grant| grant.is_some_and(|grant| ended.iter().any(|id| id == grant)));
        core.vault.record("remove space", &space.name, caller.name())?;
        Ok(Response::Ok)
    }
}
