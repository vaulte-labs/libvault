//! One item in more than one space. Each space holds its own copy, sealed under that space's key,
//! so whoever holds only one of the spaces opens its copy and nothing else. The copies share the
//! item's id, and every write reaches all of them in one entry, so they share a clock and a winner
//! and cannot drift apart.

use std::collections::HashMap;

use crate::ids::{BatchId, ItemId, SpaceId};
use crate::item::{Meta, Secret};
use crate::state::{Change, Version};
use crate::vault::Vault;
use crate::{Error, Result};

impl Vault {
    /// The spaces holding a live copy of the item `id`.
    pub(crate) fn copies_of(&self, id: &ItemId) -> Vec<SpaceId> {
        self.state.items.iter().filter(|((_, item), versions)| item == id && live(versions)).map(|((space, _), _)| *space).collect()
    }

    /// The spaces holding a live copy of each item, in one pass, for a whole list at once.
    pub(crate) fn copies(&self) -> HashMap<ItemId, Vec<SpaceId>> {
        let mut copies: HashMap<ItemId, Vec<SpaceId>> = HashMap::new();
        for ((space, item), versions) in &self.state.items {
            if live(versions) {
                copies.entry(*item).or_default().push(*space);
            }
        }
        copies
    }

    /// Shows the item at `id` in `to` as well, sealed under `to`'s key alone.
    pub fn link(&mut self, from: &SpaceId, id: &ItemId, to: &SpaceId) -> Result<()> {
        let meta = self.items(from)?.into_iter().find(|item| item.id == *id).ok_or_else(|| Error::NotFound("that item".to_owned()))?.meta;
        if self.copies_of(id).contains(to) {
            return Err(Error::Exists(meta.name));
        }
        if self.name_in_use(to, std::iter::once(meta.name.as_str()))?.is_some() {
            return Err(Error::Exists(meta.name));
        }
        let secret = self.secret(from, id)?;
        let key = self.writing_key(to)?;
        let body = self.put_body(&key, *to, *id, BatchId::random(), &meta, &secret)?;
        self.commit(&[body])
    }

    /// Writes one version of the item `id` to `space` and every other space holding it, as one
    /// batch, so one `undo` takes them all back. A device has to hold every one of those spaces,
    /// or the copies would part.
    pub(crate) fn write_everywhere(&mut self, space: &SpaceId, id: &ItemId, meta: &Meta, secret: &Secret) -> Result<()> {
        let mut spaces = self.copies_of(id);
        if !spaces.contains(space) {
            spaces.push(*space);
        }
        let batch = BatchId::random();
        let mut bodies = Vec::with_capacity(spaces.len());
        for space in spaces {
            if self.find(&space, &meta.name).is_ok_and(|found| found.id != *id) {
                return Err(Error::Exists(meta.name.clone()));
            }
            let key = self.writing_key(&space).map_err(|_| Error::NotApproved("this item is also in a space this device cannot write"))?;
            bodies.push(self.put_body(&key, space, *id, batch, meta, secret)?);
        }
        self.commit(&bodies)
    }
}

fn live(versions: &[Version]) -> bool {
    matches!(versions.last(), Some(Version { change: Change::Put { .. }, .. }))
}
