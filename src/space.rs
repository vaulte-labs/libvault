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
    /// Removed while empty. Its log stays, so a space made with its name again is this one, with
    /// the history of what was deleted from it. A version from before this field reads as kept.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    removed: bool,
}

/// Builds the entry for a version of a space, under the newest epoch key.
pub(crate) fn body(vault: VaultId, epoch: Generation, epoch_key: &Key, space: SpaceId, version: Generation, name: &str, key: &Key) -> Result<Body> {
    sealed_body(vault, epoch, epoch_key, space, version, &Sealed { name: name.to_owned(), key: *key.as_bytes(), removed: false })
}

fn sealed_body(vault: VaultId, epoch: Generation, epoch_key: &Key, space: SpaceId, version: Generation, record: &Sealed) -> Result<Body> {
    let sealed = crypto::seal(epoch_key, &Binding::Space { vault, space, version }, &item::encode(record)?);
    Ok(Body::Space { space, version, epoch, sealed })
}

/// A space's name as kept: without the spaces around it, and short and printable.
fn kept_name(name: &str) -> Result<&str> {
    let name = name.trim();
    item::validate_text(name)?;
    Ok(name)
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
            Ok(Sealed { name: name.clone(), key: *key.as_bytes(), removed: false })
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
        self.write_space(space, name, false)
    }

    /// Writes a new version of a space, with a new key, which becomes its newest.
    fn write_space(&mut self, space: SpaceId, name: &str, removed: bool) -> Result<()> {
        let (epoch, epoch_key) = self.writing_epoch(&self.state.clean_epochs()).ok_or(Error::Locked)?;
        let newest = self.state.spaces.get(&space).and_then(|versions| versions.keys().next_back());
        let version = newest.map_or(Generation::first(self.me), |newest| newest.after(self.me));
        let record = Sealed { name: name.to_owned(), key: *Key::generate().as_bytes(), removed };
        let entry = sealed_body(self.state.vault, epoch, epoch_key, space, version, &record)?;
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
        // A removed space holds nothing, and a new key for it would only bring it back.
        for space in self.spaces()? {
            if self.clean_version(&space.id, &clean).is_none() {
                let newest = self.state.spaces[&space.id].keys().next_back().expect("a space has a version");
                bodies.push(body(self.state.vault, epoch, epoch_key, space.id, newest.after(self.me), &space.name, &Key::generate())?);
            }
        }
        if bodies.is_empty() { Ok(()) } else { self.commit(&bodies) }
    }

    /// Every space this device can open, with whether it was removed.
    fn every_space(&self) -> Result<Vec<(Space, bool)>> {
        self.keys.as_ref().ok_or(Error::Locked)?;
        let clean = self.state.clean_epochs();
        let mut spaces: Vec<(Space, bool)> = self
            .space_ids()
            .into_iter()
            .filter_map(|id| {
                let (_, newest) = self.newest_open(&id, &clean)?;
                Some((Space { id, name: newest.name.clone() }, newest.removed))
            })
            .collect();
        spaces.sort_by(|a, b| a.0.name.cmp(&b.0.name));
        Ok(spaces)
    }

    pub fn spaces(&self) -> Result<Vec<Space>> {
        Ok(self.every_space()?.into_iter().filter(|(_, removed)| !removed).map(|(space, _)| space).collect())
    }

    /// The space with this name, or the one whose name differs only by case.
    pub fn space(&self, name: &str) -> Result<Space> {
        let spaces = self.spaces()?;
        let name = name.trim();
        let exact = spaces.iter().position(|space| space.name == name);
        let mut alike = spaces.iter().enumerate().filter(|(_, space)| space.name.eq_ignore_ascii_case(name)).map(|(index, _)| index);
        let found = exact.or_else(|| alike.next().filter(|_| alike.next().is_none()));
        found.map(|index| spaces[index].clone()).ok_or_else(|| Error::NotFound(format!("space {name}")))
    }

    /// Makes a space, or brings back a removed one by that name, with its history.
    pub fn create_space(&mut self, name: &str) -> Result<Space> {
        let name = kept_name(name)?;
        let every = self.every_space()?;
        if let Some((taken, _)) = every.iter().find(|(space, removed)| !removed && space.name.eq_ignore_ascii_case(name)) {
            return Err(Error::Exists(format!("space {}", taken.name)));
        }
        if let Some((removed, _)) = every.iter().find(|(space, removed)| *removed && space.name.eq_ignore_ascii_case(name)) {
            self.write_space(removed.id, name, false)?;
            return Ok(Space { id: removed.id, name: name.to_owned() });
        }
        let id = SpaceId::random();
        let clean = self.state.clean_epochs();
        let (epoch, epoch_key) = self.writing_epoch(&clean).ok_or(Error::Locked)?;
        let entry = body(self.state.vault, epoch, epoch_key, id, Generation::first(self.me), name, &Key::generate())?;
        self.commit(&[entry])?;
        Ok(Space { id, name: name.to_owned() })
    }

    /// The name `space` would have, or why it cannot. Only its case may match another space's,
    /// and only when that space is itself.
    pub fn check_rename(&self, space: &Space, to: &str) -> Result<String> {
        let to = kept_name(to)?;
        if space.name == crate::FIRST_SPACE {
            return Err(Error::Invalid("Personal is where everything goes when no space is named, so it keeps its name"));
        }
        if let Some(taken) = self.spaces()?.into_iter().find(|other| other.id != space.id && other.name.eq_ignore_ascii_case(to)) {
            return Err(Error::Exists(format!("space {}", taken.name)));
        }
        Ok(to.to_owned())
    }

    pub fn rename_space(&mut self, space: &Space, to: &str) -> Result<String> {
        let to = self.check_rename(space, to)?;
        self.write_space(space.id, &to, false)?;
        Ok(to)
    }

    /// Why `space` cannot be removed, if it cannot: it is the first space, or it holds something.
    pub fn check_removable(&self, space: &Space) -> Result<()> {
        if space.name == crate::FIRST_SPACE {
            return Err(Error::Invalid("Personal is where everything goes when no space is named, so it stays"));
        }
        match self.items(&space.id)?.len() {
            0 => Ok(()),
            1 => Err(Error::Unreadable(format!("{} holds 1 item, so it stays. Move or delete it first", space.name))),
            held => Err(Error::Unreadable(format!("{} holds {held} items, so it stays. Move or delete them first", space.name))),
        }
    }

    /// Removes an empty space. Whatever was deleted from it stays in its log, and making a space
    /// with this name again brings that back.
    pub fn remove_space(&mut self, space: &Space) -> Result<()> {
        self.check_removable(space)?;
        self.write_space(space.id, &space.name, true)
    }
}
