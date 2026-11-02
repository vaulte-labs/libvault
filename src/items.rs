//! Reading and changing items. What lists show is in `listing`.

use crate::binding::{Binding, Part};
use crate::crypto::{self, Key};
use crate::ids::{BatchId, DeviceId, Generation, ItemId, SpaceId};
use crate::item::{self, Meta, Secret};
use crate::record::Body;
use crate::state::{Change, Version};
use crate::vault::Vault;
use crate::{Error, Result};

/// An item as lists show it. Holds nothing secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub space: SpaceId,
    pub id: ItemId,
    pub meta: Meta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub clock: u64,
    pub device: DeviceId,
    pub meta: Option<Meta>,
}

impl Vault {
    pub(crate) fn binding(&self, space: &SpaceId, item: &ItemId, version: Generation, part: Part) -> Binding {
        Binding::Item { vault: self.state.vault, space: *space, item: *item, version, part }
    }

    /// The listing for the newest of `versions` that can be read, or `None` when the item was
    /// deleted. Any enrolled device can write a version that opens for nobody, or one with a name
    /// that could spoof a terminal, and that must not cost anyone the item.
    pub(crate) fn meta_of(
        &self,
        key_for: &mut impl FnMut(Generation) -> Result<Key>,
        space: &SpaceId,
        item: &ItemId,
        versions: &[Version],
    ) -> Option<Meta> {
        #[cfg(test)]
        crate::listing::META_OPENED.with(|opened| opened.set(opened.get() + 1));
        for entry in versions.iter().rev() {
            let Change::Put { version, meta, .. } = &entry.change else { return None };
            let opened = key_for(*version).and_then(|key| crypto::open(&key, &self.binding(space, item, *version, Part::Meta), meta));
            let meta: Option<Meta> = opened.ok().and_then(|opened| item::decode(&opened).ok());
            if let Some(meta) = meta.filter(|meta| item::validate(meta).is_ok()) {
                return Some(meta);
            }
        }
        None
    }

    pub(crate) fn put_body(
        &self,
        key: &(Generation, Key),
        space: SpaceId,
        item: ItemId,
        batch: BatchId,
        meta: &Meta,
        secret: &Secret,
    ) -> Result<Body> {
        let (version, key) = key;
        Ok(Body::ItemPut {
            space,
            item,
            version: *version,
            batch,
            meta: crypto::seal(key, &self.binding(&space, &item, *version, Part::Meta), &item::encode(&item::derived(meta, secret))?),
            secret: crypto::seal(key, &self.binding(&space, &item, *version, Part::Secret), &item::encode(secret)?),
        })
    }

    /// Adds an item. Fails if the name is taken, so nothing is overwritten by accident.
    pub fn add(&mut self, space: &SpaceId, meta: Meta, secret: &Secret) -> Result<ItemId> {
        Ok(self.add_many(space, &[(meta, secret.clone())])?[0])
    }

    /// Adds items as one batch, so one `undo` removes them all.
    pub fn add_many(&mut self, space: &SpaceId, items: &[(Meta, Secret)]) -> Result<Vec<ItemId>> {
        if let Some(name) = self.name_in_use(space, items.iter().map(|(meta, _)| meta.name.as_str()))? {
            return Err(Error::Exists(name.to_owned()));
        }
        let key = self.writing_key(space)?;
        let batch = BatchId::random();
        let mut bodies = Vec::with_capacity(items.len());
        let mut ids = Vec::with_capacity(items.len());
        for (meta, secret) in items {
            let id = ItemId::random();
            bodies.push(self.put_body(&key, *space, id, batch, meta, secret)?);
            ids.push(id);
        }
        self.commit(&bodies)?;
        Ok(ids)
    }

    fn require(&self, space: &SpaceId, id: &ItemId) -> Result<()> {
        self.keys.as_ref().ok_or(Error::Locked)?;
        let versions = self.state.items.get(&(*space, *id)).ok_or_else(|| Error::NotFound("that item".to_owned()))?;
        let exists = self.meta_of(&mut |version| self.space_key(space, version), space, id, versions).is_some();
        if exists { Ok(()) } else { Err(Error::NotFound("that item".to_owned())) }
    }

    /// Replaces an item. The old version stays in history.
    pub fn replace(&mut self, space: &SpaceId, id: &ItemId, meta: &Meta, secret: &Secret) -> Result<()> {
        self.require(space, id)?;
        self.write_everywhere(space, id, meta, secret)
    }

    /// Deletes an item from one space. A copy in another space stays. It stays in history, and
    /// `undo` brings it back.
    pub fn remove(&mut self, space: &SpaceId, id: &ItemId) -> Result<()> {
        self.require(space, id)?;
        self.commit(&[Body::ItemDelete { space: *space, item: *id, batch: BatchId::random() }])
    }

    /// Decrypts a secret. Callers are responsible for who gets to see it.
    pub fn secret(&self, space: &SpaceId, id: &ItemId) -> Result<Secret> {
        self.keys.as_ref().ok_or(Error::Locked)?;
        let not_found = || Error::NotFound("that item".to_owned());
        for entry in self.state.items.get(&(*space, *id)).ok_or_else(not_found)?.iter().rev() {
            let Change::Put { version, secret, .. } = &entry.change else { break };
            let key = self.space_key(space, *version);
            let opened = key.and_then(|key| crypto::open(&key, &self.binding(space, id, *version, Part::Secret), secret));
            if let Some(secret) = opened.ok().and_then(|opened| item::decode(&opened).ok()) {
                return Ok(secret);
            }
        }
        Err(not_found())
    }

    /// Every version of an item, oldest first. `meta` is `None` for a deletion.
    pub fn history(&self, space: &SpaceId, id: &ItemId) -> Result<Vec<HistoryEntry>> {
        let versions = self.state.items.get(&(*space, *id)).ok_or(Error::NotFound("that item".to_owned()))?;
        let mut key_for = |version| self.space_key(space, version);
        versions
            .iter()
            .enumerate()
            .map(|(index, version)| {
                let meta = self.meta_of(&mut key_for, space, id, &versions[..=index]);
                Ok(HistoryEntry { clock: version.clock, device: version.device, meta })
            })
            .collect()
    }

    /// Finds an item by name even if it has been deleted, going by any name it has ever had.
    pub fn find_any(&self, space: &SpaceId, name: &str) -> Result<ItemId> {
        self.keys.as_ref().ok_or(Error::Locked)?;
        let mut key_for = |version| self.space_key(space, version);
        for ((_, id), versions) in self.state.items.range((*space, ItemId::from([0; 16]))..=(*space, ItemId::from([0xff; 16]))) {
            let named = |index: usize| self.meta_of(&mut key_for, space, id, &versions[..=index]).is_some_and(|meta| meta.name == name);
            if (0..versions.len()).rev().any(named) {
                return Ok(*id);
            }
        }
        Err(Error::NotFound(name.to_owned()))
    }

    /// Makes one of an item's versions current again, whatever has happened since. `history` lists
    /// them oldest first. It is a new write, so nothing in between is lost.
    pub fn restore(&mut self, space: &SpaceId, id: &ItemId, version: usize) -> Result<()> {
        let versions = self.state.items.get(&(*space, *id)).ok_or(Error::NotFound("that item".to_owned()))?;
        let Some(Version { change: Change::Put { version: generation, meta, secret }, .. }) = versions.get(version) else {
            return Err(Error::NotFound("that version".to_owned()));
        };
        let key = self.space_key(space, *generation)?;
        let meta: Meta = item::decode(&crypto::open(&key, &self.binding(space, id, *generation, Part::Meta), meta)?)?;
        let secret: Secret = item::decode(&crypto::open(&key, &self.binding(space, id, *generation, Part::Secret), secret)?)?;
        self.write_everywhere(space, id, &meta, &secret)
    }

    /// Reverses this device's most recent batch. Returns how many items changed.
    pub fn undo(&mut self) -> Result<usize> {
        let batch = self
            .state
            .items
            .values()
            .flatten()
            .filter(|version| version.device == self.me && version.batch != BatchId::ICONS)
            .max_by_key(|version| version.clock)
            .map(|version| version.batch)
            .ok_or(Error::NotFound("nothing to undo".to_owned()))?;

        let undo_batch = BatchId::random();
        let mut bodies = Vec::new();
        for ((space, item), versions) in &self.state.items {
            let Some(index) = versions.iter().rposition(|version| version.batch == batch) else { continue };
            if index + 1 != versions.len() {
                continue;
            }
            bodies.push(match versions[..index].last() {
                Some(Version { change: Change::Put { version, meta, secret }, .. }) => {
                    Body::ItemPut { space: *space, item: *item, version: *version, batch: undo_batch, meta: meta.clone(), secret: secret.clone() }
                }
                _ => Body::ItemDelete { space: *space, item: *item, batch: undo_batch },
            });
        }
        self.commit(&bodies)?;
        Ok(bodies.len())
    }
}
