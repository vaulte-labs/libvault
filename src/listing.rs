//! What lists show, opened once.
//!
//! Item names are encrypted in the log, so finding an item by name means opening items. Doing that
//! on every lookup made `find` and `add` cost the whole vault, so the rows are kept while the vault
//! is unlocked, beside keys that could open them anyway, and are wiped when it locks.
//!
//! Nothing has to remember to keep the rows current. They are stamped with the [`State`] revision
//! and the keys they were read with, and a stamp that no longer matches discards them. Every
//! replay and every applied entry makes a new revision, so a new way of changing the state costs
//! a slower read and can never show a stale row. `commit` carries the rows over the common writes,
//! so adding one item does not reopen all the others.
//!
//! [`State`]: crate::state::State

use std::collections::{BTreeMap, BTreeSet};

use zeroize::Zeroize;

use crate::crypto::Key;
use crate::ids::{Generation, ItemId, SpaceId};
use crate::item::{Kind, Meta};
use crate::items::Summary;
use crate::record::Body;
use crate::vault::{Keys, Vault};
use crate::{Error, Result};

#[cfg(test)]
thread_local! {
    /// Items opened on this thread, so a test can see what a read spent.
    pub(crate) static META_OPENED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// One space as lookups see it. Icons are items, but never listed or found by name.
#[derive(Debug, Default)]
pub(crate) struct Rows {
    pub items: Vec<Summary>,
    pub icons: Vec<Summary>,
}

impl Rows {
    fn of(&mut self, kind: Kind) -> &mut Vec<Summary> {
        if kind == Kind::Icon { &mut self.icons } else { &mut self.items }
    }
}

/// Which state and keys a listing describes.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Stamp {
    state: u64,
    keys: usize,
}

#[derive(Debug, Default)]
pub(crate) struct Listing {
    built_from: Stamp,
    /// Sorted by name and then id, so a name held twice always finds the same item.
    spaces: BTreeMap<SpaceId, Rows>,
}

fn wipe(meta: &mut Meta) {
    meta.name.zeroize();
    meta.username.zeroize();
    meta.urls.zeroize();
    meta.hosts.zeroize();
    meta.hint.zeroize();
}

impl Listing {
    fn clear(&mut self) {
        self.spaces.values_mut().flat_map(|rows| rows.items.iter_mut().chain(&mut rows.icons)).for_each(|row| wipe(&mut row.meta));
        self.spaces.clear();
    }
}

impl Drop for Listing {
    fn drop(&mut self) {
        self.clear();
    }
}

pub(crate) fn named<'a>(rows: &'a [Summary], name: &str) -> Option<&'a Summary> {
    let first = rows.partition_point(|row| row.meta.name.as_str() < name);
    rows.get(first).filter(|row| row.meta.name == name)
}

impl Vault {
    fn stamp(&self, keys: &Keys) -> Stamp {
        Stamp { state: self.state.revision(), keys: keys.epochs.len() }
    }

    /// Opens every item in a space. Secrets stay encrypted.
    pub(crate) fn read_rows(&self, space: &SpaceId) -> Rows {
        let mut keys = BTreeMap::new();
        let mut key_for = |version: Generation| {
            if let Some(key) = keys.get(&version) {
                return Ok(Key::clone(key));
            }
            let key = self.space_key(space, version)?;
            keys.insert(version, key.clone());
            Ok(key)
        };
        let mut rows = Rows::default();
        for ((_, id), versions) in self.state.items.range((*space, ItemId::from([0; 16]))..=(*space, ItemId::from([0xff; 16]))) {
            if let Some(meta) = self.meta_of(&mut key_for, space, id, versions) {
                rows.of(meta.kind).push(Summary { space: *space, id: *id, meta });
            }
        }
        // Stable, so items sharing a name stay in id order.
        rows.items.sort_by(|a, b| a.meta.name.cmp(&b.meta.name));
        rows.icons.sort_by(|a, b| a.meta.name.cmp(&b.meta.name));
        rows
    }

    /// Runs `read` over a space's rows, opening them first if this state has not listed them.
    pub(crate) fn with_rows<T>(&self, space: &SpaceId, read: impl FnOnce(&Rows) -> T) -> Result<T> {
        let keys = self.keys.as_ref().ok_or(Error::Locked)?;
        let stamp = self.stamp(keys);
        let mut listing = keys.listing.borrow_mut();
        if listing.built_from != stamp {
            listing.clear();
            listing.built_from = stamp;
        }
        if !listing.spaces.contains_key(space) {
            listing.spaces.insert(*space, self.read_rows(space));
        }
        Ok(read(&listing.spaces[space]))
    }

    /// Lists a space. Secrets stay encrypted.
    pub fn items(&self, space: &SpaceId) -> Result<Vec<Summary>> {
        self.with_rows(space, |rows| rows.items.clone())
    }

    pub fn find(&self, space: &SpaceId, name: &str) -> Result<Summary> {
        self.with_rows(space, |rows| named(&rows.items, name).cloned())?.ok_or_else(|| Error::NotFound(name.to_owned()))
    }

    /// The first of these names already in the space, or repeated among them.
    pub(crate) fn name_in_use<'a>(&self, space: &SpaceId, names: impl Iterator<Item = &'a str>) -> Result<Option<&'a str>> {
        let mut seen = BTreeSet::new();
        self.with_rows(space, |rows| names.into_iter().find(|name| named(&rows.items, name).is_some() || !seen.insert(*name)))
    }

    /// Whether the rows match the state, which `commit` asks before it changes the state.
    pub(crate) fn listing_is_current(&self) -> bool {
        self.keys.as_ref().is_some_and(|keys| keys.listing.borrow().built_from == self.stamp(keys))
    }

    /// Carries current rows over what `commit` just applied. Any other kind of change leaves the
    /// stamp behind, so the next read opens everything again.
    pub(crate) fn carry_listing_over(&self, bodies: &[Body]) {
        let Some(keys) = &self.keys else { return };
        let mut listing = keys.listing.borrow_mut();
        for body in bodies {
            let (Body::ItemPut { space, item, .. } | Body::ItemDelete { space, item, .. }) = body else { return };
            if let Some(rows) = listing.spaces.get_mut(space) {
                self.reread_row(rows, space, item);
            }
        }
        listing.built_from = self.stamp(keys);
    }

    fn reread_row(&self, rows: &mut Rows, space: &SpaceId, id: &ItemId) {
        for kept in [&mut rows.items, &mut rows.icons] {
            if let Some(at) = kept.iter().position(|row| row.id == *id) {
                wipe(&mut kept.remove(at).meta);
            }
        }
        let Some(versions) = self.state.items.get(&(*space, *id)) else { return };
        let Some(meta) = self.meta_of(&mut |version| self.space_key(space, version), space, id, versions) else { return };
        let rows = rows.of(meta.kind);
        let at = rows.partition_point(|row| (&row.meta.name, &row.id) < (&meta.name, id));
        rows.insert(at, Summary { space: *space, id: *id, meta });
    }
}

#[cfg(test)]
#[path = "listing_tests.rs"]
mod tests;
