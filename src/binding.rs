//! What each ciphertext is for. Every seal and wrap names one of these, so nothing can be moved
//! to another slot, item or vault and still decrypt. Being the only source of associated data,
//! this enum also keeps every use domain-separated: the leading tag differs by variant.

use crate::ids::{DeviceId, Generation, ItemId, SpaceId, VaultId};
use crate::wire::Writer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Part {
    Meta,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recipient {
    Device(DeviceId),
    Recovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Binding {
    SoftwareKeys,
    /// The recovery key's private half, sealed under the 24 words.
    RecoveryKeys {
        vault: VaultId,
    },
    /// An epoch key wrapped to someone who may read that epoch.
    Epoch {
        vault: VaultId,
        epoch: Generation,
        recipient: Recipient,
    },
    /// An epoch key sealed under the next epoch's key.
    EpochLink {
        vault: VaultId,
        epoch: Generation,
    },
    /// A device's log signing key, wrapped to its own hardware.
    LogKey {
        vault: VaultId,
        device: DeviceId,
    },
    /// A device's name.
    Label {
        vault: VaultId,
        device: DeviceId,
    },
    Space {
        vault: VaultId,
        space: SpaceId,
        version: Generation,
    },
    /// A version of a space's key wrapped to a server holding that space.
    SpaceKey {
        vault: VaultId,
        space: SpaceId,
        version: Generation,
        device: DeviceId,
    },
    /// A space's name, sealed under that version's key for a server, which holds no epoch key.
    SpaceName {
        vault: VaultId,
        space: SpaceId,
        version: Generation,
    },
    Item {
        vault: VaultId,
        space: SpaceId,
        item: ItemId,
        version: Generation,
        part: Part,
    },
    Audit {
        vault: VaultId,
    },
}

impl Binding {
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.array(b"lv.bind.v1");
        match self {
            Self::SoftwareKeys => w.u8(0),
            Self::Epoch { vault, epoch, recipient } => {
                w.u8(1);
                w.array(vault.as_bytes());
                w.generation(*epoch);
                match recipient {
                    Recipient::Device(device) => {
                        w.u8(0);
                        w.array(device.as_bytes());
                    }
                    Recipient::Recovery => w.u8(1),
                }
            }
            Self::EpochLink { vault, epoch } => {
                w.u8(2);
                w.array(vault.as_bytes());
                w.generation(*epoch);
            }
            Self::LogKey { vault, device } => {
                w.u8(3);
                w.array(vault.as_bytes());
                w.array(device.as_bytes());
            }
            Self::Label { vault, device } => {
                w.u8(4);
                w.array(vault.as_bytes());
                w.array(device.as_bytes());
            }
            Self::Space { vault, space, version } => {
                w.u8(5);
                w.array(vault.as_bytes());
                w.array(space.as_bytes());
                w.generation(*version);
            }
            Self::Item { vault, space, item, version, part } => {
                w.u8(6);
                w.array(vault.as_bytes());
                w.array(space.as_bytes());
                w.array(item.as_bytes());
                w.generation(*version);
                w.u8(match part {
                    Part::Meta => 0,
                    Part::Secret => 1,
                });
            }
            Self::Audit { vault } => {
                w.u8(7);
                w.array(vault.as_bytes());
            }
            Self::RecoveryKeys { vault } => {
                w.u8(8);
                w.array(vault.as_bytes());
            }
            Self::SpaceKey { vault, space, version, device } => {
                w.u8(9);
                w.array(vault.as_bytes());
                w.array(space.as_bytes());
                w.generation(*version);
                w.array(device.as_bytes());
            }
            Self::SpaceName { vault, space, version } => {
                w.u8(10);
                w.array(vault.as_bytes());
                w.array(space.as_bytes());
                w.generation(*version);
            }
        }
        w.finish()
    }
}
