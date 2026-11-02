//! Getting back what this device wrote on top of entries a removal then cut. A removal keeps what
//! the remover had seen, so a device that heard more can have built on something that is about to
//! stop counting: a space a lost device made, say, with this person's secrets in it.

use crate::binding::Part;
use crate::crypto;
use crate::ids::{BatchId, DeviceId, ItemId, SpaceId};
use crate::item::{self, Meta, Secret};
use crate::state::{Change, State};
use crate::vault::Vault;
use crate::{Error, Result};

impl Vault {
    /// Items where what a device wrote last no longer counts, whether the item has gone or has
    /// slipped back to something older. Any device can put it right, because the one that wrote it
    /// may be the next one lost. Each names an entry in a log, so nothing but a replay is needed to
    /// know, and writing it again ends it. What a removed device wrote past its cut is not among
    /// these: those entries stop at its author check, and stay cut.
    pub(crate) fn lost_items(&self) -> Vec<(DeviceId, SpaceId, ItemId)> {
        // In the order versions are kept, so a tie on the clock goes the way it went before the cut.
        let newest = |space: &SpaceId, item: &ItemId| {
            self.state.items.get(&(*space, *item)).and_then(|versions| versions.last()).map(|version| (version.clock, version.device))
        };
        let lost = |((device, space, item), clock): (&(DeviceId, SpaceId, ItemId), &u64)| {
            newest(space, item).is_none_or(|newest| newest < (*clock, *device)).then_some((*device, *space, *item))
        };
        self.state.orphans.iter().filter_map(lost).collect()
    }

    /// Writes lost items again under keys that still count. One whose key is out of reach stays
    /// lost, and `problems` keeps saying so. This runs inside `repair`, so nothing here may ask for
    /// it again.
    pub(crate) fn rescue(&mut self) -> Result<()> {
        let lost = self.lost_items();
        let Some(whole) = self.state_with_nothing_cut() else { return Ok(()) };
        for (device, space, item) in lost {
            let Ok((name, meta, secret)) = self.read_cut(&whole, device, space, item) else { continue };
            if self.newest_space_key(&space).is_err() {
                self.restore_space(space, &name)?;
            }
            let key = self.newest_space_key(&space)?;
            let body = self.put_body(&key, space, item, BatchId::random(), &meta, &secret)?;
            self.commit(&[body])?;
        }
        Ok(())
    }

    /// The newest value a device wrote for an item, from a replay that kept what was cut.
    fn read_cut(&self, whole: &State, device: DeviceId, space: SpaceId, item: ItemId) -> Result<(String, Meta, Secret)> {
        let versions = whole.items.get(&(space, item)).ok_or(Error::Decrypt)?;
        let written = versions.iter().rev().find_map(|entry| match &entry.change {
            Change::Put { version, meta, secret } if entry.device == device => Some((*version, meta, secret)),
            _ => None,
        });
        let (version, meta, secret) = written.ok_or(Error::Decrypt)?;
        let (name, key) = self.space_in(whole, &space, version)?;
        let meta = item::decode(&crypto::open(&key, &self.binding(&space, &item, version, Part::Meta), meta)?)?;
        let secret = item::decode(&crypto::open(&key, &self.binding(&space, &item, version, Part::Secret), secret)?)?;
        Ok((name, meta, secret))
    }
}
