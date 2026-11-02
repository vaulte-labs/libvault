//! Spaces group secrets, one per project. Each has its own key.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::binding::Binding;
use crate::crypto::{self, Key};
use crate::ids::{Generation, SpaceId, VaultId};
use crate::item;
use crate::record::Body;
use crate::state::State;
use crate::vault::Vault;
use crate::{Error, Result};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Sealed {
    name: String,
    key: [u8; 32],
}

/// Builds the entry for a version of a space, under the newest epoch key.
pub(crate) fn body(vault: VaultId, epoch: Generation, epoch_key: &Key, space: SpaceId, version: Generation, name: &str, key: &Key) -> Result<Body> {
    let record = Sealed { name: name.to_owned(), key: *key.as_bytes() };
    let sealed = crypto::seal(epoch_key, &Binding::Space { vault, space, version }, &item::encode(&record)?);
    Ok(Body::Space { space, version, epoch, sealed })
}

fn open_sealed(state: &State, epochs: &BTreeMap<Generation, Key>, space: &SpaceId, version: Generation) -> Result<Sealed> {
    let record = state.spaces.get(space).and_then(|versions| versions.get(&version)).ok_or(Error::Decrypt)?;
    let epoch_key = epochs.get(&record.epoch).ok_or(Error::Decrypt)?;
    let opened = crypto::open(epoch_key, &Binding::Space { vault: state.vault, space: *space, version }, &record.sealed)?;
    let sealed: Sealed = item::decode(&opened)?;
    item::validate_text(&sealed.name)?;
    Ok(sealed)
}

/// The name and key of a version of a space, with whatever epoch keys are at hand.
pub(crate) fn space_record(state: &State, epochs: &BTreeMap<Generation, Key>, space: &SpaceId, version: Generation) -> Result<(String, Key)> {
    let sealed = open_sealed(state, epochs, space, version)?;
    Ok((sealed.name.clone(), Key::from_bytes(sealed.key)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Space {
    pub id: SpaceId,
    pub name: String,
}

impl Vault {
    fn open_space(&self, space: &SpaceId, version: Generation) -> Result<Sealed> {
        self.open_space_in(&self.state, space, version)
    }

    /// Opened the usual way, under an epoch key, or as wrapped to a server holding the space.
    fn open_space_in(&self, state: &State, space: &SpaceId, version: Generation) -> Result<Sealed> {
        let keys = self.keys.as_ref().ok_or(Error::Locked)?;
        open_sealed(state, &keys.epochs, space, version).or_else(|error| {
            let (name, key) = keys.spaces.get(&(*space, version)).ok_or(error)?;
            Ok(Sealed { name: name.clone(), key: *key.as_bytes() })
        })
    }

    /// The name and key of a version in a replay other than the current one.
    pub(crate) fn space_in(&self, state: &State, space: &SpaceId, version: Generation) -> Result<(String, Key)> {
        let sealed = self.open_space_in(state, space, version)?;
        Ok((sealed.name.clone(), Key::from_bytes(sealed.key)))
    }

    /// Makes a space anew under its old id, for one that a removal cut, or that nothing left of it
    /// opens.
    pub(crate) fn restore_space(&mut self, space: SpaceId, name: &str) -> Result<()> {
        let (epoch, epoch_key) = self.writing_epoch(&self.state.clean_epochs()).ok_or(Error::Locked)?;
        let newest = self.state.spaces.get(&space).and_then(|versions| versions.keys().next_back());
        let version = newest.map_or(Generation::first(self.me), |newest| newest.after(self.me));
        let entry = body(self.state.vault, epoch, epoch_key, space, version, name, &Key::generate())?;
        self.commit(&[entry])
    }

    /// The version to write under. Nothing new goes under a key someone outside the vault could
    /// hold, and of the rest, a key nearest the newest generation is one every device can reach.
    fn clean_version(&self, space: &SpaceId, clean: &BTreeSet<Generation>) -> Option<(Generation, Sealed)> {
        let mut versions: Vec<_> = self.state.spaces.get(space)?.iter().filter(|(_, record)| clean.contains(&record.epoch)).collect();
        versions.sort_by_key(|(version, record)| (record.epoch.number, **version));
        versions.into_iter().rev().find_map(|(version, _)| Some((*version, self.open_space(space, *version).ok()?)))
    }

    /// The newest version that opens. Any enrolled device can write one that does not, and that
    /// must cost nobody the space.
    fn newest_open(&self, space: &SpaceId, clean: &BTreeSet<Generation>) -> Option<(Generation, Sealed)> {
        let versions = self.state.spaces.get(space)?;
        self.clean_version(space, clean)
            .or_else(|| versions.keys().rev().find_map(|version| Some((*version, self.open_space(space, *version).ok()?))))
    }

    pub(crate) fn space_key(&self, space: &SpaceId, version: Generation) -> Result<Key> {
        Ok(Key::from_bytes(self.open_space(space, version)?.key))
    }

    /// The key to write under. A space with none yet is waiting for `repair`, which is what a
    /// write needs here. Otherwise this device has to open what has replaced its keys first.
    pub(crate) fn newest_space_key(&self, space: &SpaceId) -> Result<(Generation, Key)> {
        self.keys.as_ref().ok_or(Error::Locked)?;
        let clean = self.state.clean_epochs();
        match self.clean_version(space, &clean) {
            Some((version, record)) => Ok((version, Key::from_bytes(record.key))),
            None if self.newest_open(space, &clean).is_some() => Err(Error::Locked),
            None => Err(Error::NotFound("that space".to_owned())),
        }
    }

    /// The key to write under, making one if `repair` has not got to this space yet.
    pub(crate) fn writing_key(&mut self, space: &SpaceId) -> Result<(Generation, Key)> {
        self.keys.as_ref().ok_or(Error::Locked)?;
        if self.clean_version(space, &self.state.clean_epochs()).is_none() {
            self.repair()?;
        }
        self.newest_space_key(space)
    }

    /// Gives every space that needs one a version under the newest clean key. One entry each,
    /// because a batch has a size limit and a device could otherwise make enough spaces to stop
    /// its own removal. Stopping partway is fine: the next `repair` carries on from here.
    pub(crate) fn rekey_spaces(&mut self) -> Result<()> {
        let clean = self.state.clean_epochs();
        let Some((epoch, epoch_key)) = self.writing_epoch(&clean) else { return Ok(()) };
        let mut bodies = Vec::new();
        for space in self.spaces()? {
            if self.clean_version(&space.id, &clean).is_none() {
                let newest = self.state.spaces[&space.id].keys().next_back().expect("a space has a version");
                bodies.push(body(self.state.vault, epoch, epoch_key, space.id, newest.after(self.me), &space.name, &Key::generate())?);
            }
        }
        if bodies.is_empty() { Ok(()) } else { self.commit(&bodies) }
    }

    pub fn spaces(&self) -> Result<Vec<Space>> {
        self.keys.as_ref().ok_or(Error::Locked)?;
        let clean = self.state.clean_epochs();
        let mut spaces: Vec<Space> =
            self.space_ids().into_iter().filter_map(|id| Some(Space { id, name: self.newest_open(&id, &clean)?.1.name.clone() })).collect();
        spaces.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(spaces)
    }

    pub fn space(&self, name: &str) -> Result<Space> {
        self.spaces()?.into_iter().find(|space| space.name == name).ok_or_else(|| Error::NotFound(format!("space {name}")))
    }

    pub fn create_space(&mut self, name: &str) -> Result<Space> {
        if self.spaces()?.iter().any(|space| space.name == name) {
            return Err(Error::Exists(format!("space {name}")));
        }
        let id = SpaceId::random();
        let clean = self.state.clean_epochs();
        let (epoch, epoch_key) = self.writing_epoch(&clean).ok_or(Error::Locked)?;
        let entry = body(self.state.vault, epoch, epoch_key, id, Generation::first(self.me), name, &Key::generate())?;
        self.commit(&[entry])?;
        Ok(Space { id, name: name.to_owned() })
    }
}
