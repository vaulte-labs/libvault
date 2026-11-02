//! One item in several spaces: showing it in another, moving it there, and saying where each copy
//! is from.

use std::collections::HashMap;

use super::Broker;
use super::handlers::resolve_space;
use super::policy::{Action, Caller};
use crate::ids::SpaceId;
use crate::items::Summary;
use crate::protocol::Response;
use crate::view::ItemInfo;
use crate::{Result, Vault};

/// Shows an item listed in the space named `space`, with the other spaces it is in and its home
/// when that is another. Built once per request, so a list costs one pass over the vault rather
/// than one per item.
pub(super) fn shown(vault: &Vault, caller: &Caller) -> Result<impl Fn(&str, Summary) -> ItemInfo> {
    // A session sees one space, so the others an item is in are none of its business.
    let copies = if matches!(caller, Caller::Session(_)) { HashMap::new() } else { vault.copies() };
    // Only spaces this device can open, which on a server are the ones it holds.
    let names: HashMap<SpaceId, String> = vault.spaces()?.into_iter().map(|space| (space.id, space.name)).collect();
    Ok(move |space: &str, item: Summary| {
        let known: Vec<&SpaceId> = copies.get(&item.id).into_iter().flatten().filter(|copy| names.contains_key(copy)).collect();
        let linked_from = known.first().filter(|home| **home != &item.space).map(|home| names[*home].clone());
        let also_in = known.into_iter().filter(|other| **other != item.space).map(|other| names[other].clone()).collect();
        ItemInfo { space: space.to_owned(), meta: item.meta, also_in, linked_from }
    })
}

impl Broker {
    /// Shows the item in `to` as well, or with `moving` takes it out of where it is too.
    pub(super) fn copy_to(&self, caller: &Caller, space: Option<&str>, name: &str, to: &str, moving: bool) -> Result<Response> {
        let (from, item) = self.locate(caller, space, name)?;
        let to_id = resolve_space(&self.unlocked()?.vault, caller, Some(to))?;
        self.check(caller, if moving { Action::MoveItem { name, to } } else { Action::LinkItem { name, to } })?;
        let mut core = self.open_core()?;
        if moving {
            core.vault.move_item(&from, &item.id, &to_id)?;
        } else {
            core.vault.link(&from, &item.id, &to_id)?;
        }
        core.vault.record(if moving { "move" } else { "link" }, name, caller.name())?;
        Ok(Response::Ok)
    }
}
