//! What a log entry says. Everything here is public keys, random ids or ciphertext, so logs
//! are safe to hand to any peer or folder.

use crate::crypto::Hash;
use crate::crypto::{HybridSignature, MLDSA_PUBLIC_LEN, MLKEM_PUBLIC_LEN, PublicKeys, WrapTo, Wrapped};
use crate::ids::{BatchId, DeviceId, Generation, ItemId, SpaceId, VaultId};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};
use parts::{
    read_approvals, read_key, read_recovery, read_signature, read_wrapped, write_approvals, write_recovery, write_server_add, write_signature,
    write_space_wrap, write_wrapped,
};

/// The public half of a device, fixed at enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub keys: PublicKeys,
    /// Ed25519. Signs log entries; held only while unlocked.
    pub log: [u8; 32],
    /// X25519. Authenticates sync, which runs while locked.
    pub sync: [u8; 32],
}

impl DeviceRecord {
    pub fn id(&self) -> DeviceId {
        let mut w = Writer::new();
        self.write(&mut w);
        let hash = crate::crypto::hash(&[b"lv.device.v1", &w.finish()]);
        let id: [u8; 16] = hash[..16].try_into().expect("hash is longer than a device id");
        id.into()
    }

    pub(crate) fn write(&self, w: &mut Writer) {
        w.array(&self.keys.agreement);
        w.bytes(&self.keys.kem);
        w.array(&self.keys.signing);
        w.bytes(&self.keys.dsa);
        w.array(&self.log);
        w.array(&self.sync);
    }

    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        let keys =
            PublicKeys { agreement: r.array()?, kem: read_key(r, MLKEM_PUBLIC_LEN)?, signing: r.array()?, dsa: read_key(r, MLDSA_PUBLIC_LEN)? };
        Ok(Self { keys, log: r.array()?, sync: r.array()? })
    }
}

/// The recovery key's public half. Signing keys derive from the words. The wrap keys are random
/// and their private half is sealed under the words here, so any device can wrap to recovery
/// without ever holding the words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPublic {
    pub ed25519: [u8; 32],
    pub dsa: Vec<u8>,
    pub agreement: [u8; 65],
    pub kem: Vec<u8>,
    pub sealed_private: Vec<u8>,
}

pub type RecoveryId = [u8; 16];

const BATCH: u8 = 12;

impl RecoveryPublic {
    pub fn wrap_to(&self) -> WrapTo<'_> {
        WrapTo { agreement: &self.agreement, kem: &self.kem }
    }

    /// Covers everything public, because approvals sign this: an approval that named only the
    /// signing keys would let whoever writes the entry choose where future keys are wrapped.
    pub fn id(&self) -> RecoveryId {
        let mut w = Writer::new();
        write_recovery(&mut w, self);
        let hash = crate::crypto::hash(&[b"lv.recovery.id.v2", &w.finish()]);
        hash[..16].try_into().expect("hash is longer than an id")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Approver {
    Device(DeviceId),
    Recovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    pub by: Approver,
    pub signature: HybridSignature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sealed {
    Device(DeviceId, Wrapped),
    /// Names the recovery key it was wrapped to, which rotation can retire.
    Recovery(RecoveryId, Wrapped),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Genesis {
        vault: VaultId,
        recovery: RecoveryPublic,
        device: DeviceRecord,
        /// What the first epoch's key must match. See `epoch_commitment`.
        first_epoch: Hash,
        device_signature: HybridSignature,
        recovery_signature: HybridSignature,
    },
    DeviceAdd {
        /// The roster change this one follows, as in `Body::after`.
        after: Hash,
        device: DeviceRecord,
        approvals: Vec<Approval>,
    },
    /// A machine nobody sits at. It holds `spaces`, or the whole vault, and it has no say in the
    /// roster, whatever it signs: its keys sit in a file.
    ServerAdd {
        after: Hash,
        device: DeviceRecord,
        spaces: Option<Vec<SpaceId>>,
        approvals: Vec<Approval>,
    },
    DeviceRevoke {
        after: Hash,
        device: DeviceId,
        /// Entries from the removed device to keep, as far as the remover had seen.
        entries_kept: u64,
        /// The last of those, so that a different history of the same length does not count.
        last_kept: Hash,
        approvals: Vec<Approval>,
    },
    RecoveryRotate {
        after: Hash,
        recovery: RecoveryPublic,
        /// The new key's own signature, as a first entry has. Its public half is in every log, so
        /// without this anyone could name it and have the owner's words open their vault.
        proof: HybridSignature,
        approvals: Vec<Approval>,
    },
    Wrap {
        epoch: Generation,
        sealed: Sealed,
    },
    /// The key of `previous`, sealed under the key of `epoch`.
    EpochLink {
        epoch: Generation,
        previous: Generation,
        /// What the key of `epoch` must match. See `epoch_commitment`.
        commitment: Hash,
        /// The roster change this was made after, which says who could not be holding it.
        roster: Hash,
        sealed: Vec<u8>,
    },
    /// The key of another generation, sealed under the key of `epoch`, so whoever holds `epoch`
    /// reaches what a generation raced with it, or a side branch, was used for.
    ExtraLink {
        epoch: Generation,
        previous: Generation,
        sealed: Vec<u8>,
    },
    Space {
        space: SpaceId,
        version: Generation,
        epoch: Generation,
        sealed: Vec<u8>,
    },
    /// A version of a space's key wrapped to a server holding that space, with the space's name
    /// sealed under it, since a server holds no epoch key to open either the usual way.
    SpaceWrap {
        space: SpaceId,
        version: Generation,
        device: DeviceId,
        wrapped: Wrapped,
        name: Vec<u8>,
    },
    ItemPut {
        space: SpaceId,
        item: ItemId,
        version: Generation,
        batch: BatchId,
        meta: Vec<u8>,
        secret: Vec<u8>,
    },
    ItemDelete {
        space: SpaceId,
        item: ItemId,
        batch: BatchId,
    },
    Audit {
        epoch: Generation,
        sealed: Vec<u8>,
    },
    Label {
        device: DeviceId,
        epoch: Generation,
        sealed: Vec<u8>,
    },
    /// Changes that have to land together. One entry is whole or absent, so a crash cannot leave a
    /// removal without the new keys it needs.
    Batch {
        bodies: Vec<Body>,
    },
}

impl Body {
    pub const GENESIS: u8 = 1;

    /// The approvals on a roster change, which is what makes it one.
    pub fn approvals(&self) -> Option<&[Approval]> {
        match self {
            Self::DeviceAdd { approvals, .. }
            | Self::ServerAdd { approvals, .. }
            | Self::DeviceRevoke { approvals, .. }
            | Self::RecoveryRotate { approvals, .. } => Some(approvals),
            _ => None,
        }
    }

    pub fn kind(&self) -> u8 {
        match self {
            Self::Genesis { .. } => Self::GENESIS,
            Self::DeviceAdd { .. } => 2,
            Self::DeviceRevoke { .. } => 3,
            Self::RecoveryRotate { .. } => 4,
            Self::Wrap { .. } => 5,
            Self::EpochLink { .. } => 6,
            Self::Space { .. } => 7,
            Self::ItemPut { .. } => 8,
            Self::ItemDelete { .. } => 9,
            Self::Audit { .. } => 10,
            Self::Label { .. } => 11,
            Self::ExtraLink { .. } => 13,
            Self::ServerAdd { .. } => 14,
            Self::SpaceWrap { .. } => 15,
            Self::Batch { .. } => BATCH,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Self::Genesis { vault, recovery, device, first_epoch, device_signature, recovery_signature } => {
                w.array(vault.as_bytes());
                write_recovery(&mut w, recovery);
                device.write(&mut w);
                w.array(first_epoch);
                write_signature(&mut w, device_signature);
                write_signature(&mut w, recovery_signature);
            }
            Self::DeviceAdd { after, device, approvals } => {
                w.array(after);
                device.write(&mut w);
                write_approvals(&mut w, approvals);
            }
            Self::SpaceWrap { space, version, device, wrapped, name } => write_space_wrap(&mut w, space, *version, device, wrapped, name),
            Self::ServerAdd { after, device, spaces, approvals } => write_server_add(&mut w, after, device, spaces.as_deref(), approvals),
            Self::DeviceRevoke { after, device, entries_kept, last_kept, approvals } => {
                w.array(after);
                w.array(device.as_bytes());
                w.u64(*entries_kept);
                w.array(last_kept);
                write_approvals(&mut w, approvals);
            }
            Self::RecoveryRotate { after, recovery, proof, approvals } => {
                w.array(after);
                write_recovery(&mut w, recovery);
                write_signature(&mut w, proof);
                write_approvals(&mut w, approvals);
            }
            Self::Wrap { epoch, sealed } => {
                w.generation(*epoch);
                match sealed {
                    Sealed::Device(device, wrapped) => {
                        w.u8(0);
                        w.array(device.as_bytes());
                        write_wrapped(&mut w, wrapped);
                    }
                    Sealed::Recovery(id, wrapped) => {
                        w.u8(1);
                        w.array(id);
                        write_wrapped(&mut w, wrapped);
                    }
                }
            }
            Self::EpochLink { epoch, previous, commitment, roster, sealed } => {
                w.generation(*epoch);
                w.generation(*previous);
                w.array(commitment);
                w.array(roster);
                w.bytes(sealed);
            }
            Self::ExtraLink { epoch, previous, sealed } => {
                w.generation(*epoch);
                w.generation(*previous);
                w.bytes(sealed);
            }
            Self::Audit { epoch, sealed } => {
                w.generation(*epoch);
                w.bytes(sealed);
            }
            Self::Space { space, version, epoch, sealed } => {
                w.array(space.as_bytes());
                w.generation(*version);
                w.generation(*epoch);
                w.bytes(sealed);
            }
            Self::ItemPut { space, item, version, batch, meta, secret } => {
                w.array(space.as_bytes());
                w.array(item.as_bytes());
                w.generation(*version);
                w.array(batch.as_bytes());
                w.bytes(meta);
                w.bytes(secret);
            }
            Self::ItemDelete { space, item, batch } => {
                w.array(space.as_bytes());
                w.array(item.as_bytes());
                w.array(batch.as_bytes());
            }
            Self::Label { device, epoch, sealed } => {
                w.array(device.as_bytes());
                w.generation(*epoch);
                w.bytes(sealed);
            }
            Self::Batch { bodies } => {
                w.u32(u32::try_from(bodies.len()).expect("a batch is far smaller than this"));
                for body in bodies {
                    w.u8(body.kind());
                    w.bytes(&body.encode());
                }
            }
        }
        w.finish()
    }

    pub fn decode(kind: u8, body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        let decoded = match kind {
            Self::GENESIS => Self::Genesis {
                vault: r.id()?,
                recovery: read_recovery(&mut r)?,
                device: DeviceRecord::read(&mut r)?,
                first_epoch: r.array()?,
                device_signature: read_signature(&mut r)?,
                recovery_signature: read_signature(&mut r)?,
            },
            2 => Self::DeviceAdd { after: r.array()?, device: DeviceRecord::read(&mut r)?, approvals: read_approvals(&mut r)? },
            3 => Self::DeviceRevoke {
                after: r.array()?,
                device: r.id()?,
                entries_kept: r.u64()?,
                last_kept: r.array()?,
                approvals: read_approvals(&mut r)?,
            },
            4 => Self::RecoveryRotate {
                after: r.array()?,
                recovery: read_recovery(&mut r)?,
                proof: read_signature(&mut r)?,
                approvals: read_approvals(&mut r)?,
            },
            5 => Self::Wrap {
                epoch: r.generation()?,
                sealed: match r.u8()? {
                    0 => Sealed::Device(r.id()?, read_wrapped(&mut r)?),
                    1 => Sealed::Recovery(r.array()?, read_wrapped(&mut r)?),
                    _ => return Err(Error::Corrupt("unknown wrap kind")),
                },
            },
            15 => Self::SpaceWrap {
                space: r.id()?,
                version: r.generation()?,
                device: r.id()?,
                wrapped: read_wrapped(&mut r)?,
                name: r.bytes()?.to_vec(),
            },
            14 => Self::ServerAdd {
                after: r.array()?,
                device: DeviceRecord::read(&mut r)?,
                spaces: match r.u8()? {
                    0 => None,
                    1 => Some((0..r.u32()?).map(|_| r.id()).collect::<Result<_>>()?),
                    _ => return Err(Error::Corrupt("unknown kind of server")),
                },
                approvals: read_approvals(&mut r)?,
            },
            13 => Self::ExtraLink { epoch: r.generation()?, previous: r.generation()?, sealed: r.bytes()?.to_vec() },
            6 => Self::EpochLink {
                epoch: r.generation()?,
                previous: r.generation()?,
                commitment: r.array()?,
                roster: r.array()?,
                sealed: r.bytes()?.to_vec(),
            },
            7 => Self::Space { space: r.id()?, version: r.generation()?, epoch: r.generation()?, sealed: r.bytes()?.to_vec() },
            8 => Self::ItemPut {
                space: r.id()?,
                item: r.id()?,
                version: r.generation()?,
                batch: r.id()?,
                meta: r.bytes()?.to_vec(),
                secret: r.bytes()?.to_vec(),
            },
            9 => Self::ItemDelete { space: r.id()?, item: r.id()?, batch: r.id()? },
            10 => Self::Audit { epoch: r.generation()?, sealed: r.bytes()?.to_vec() },
            11 => Self::Label { device: r.id()?, epoch: r.generation()?, sealed: r.bytes()?.to_vec() },
            BATCH => {
                let mut bodies = Vec::new();
                for _ in 0..r.u32()? {
                    let kind = r.u8()?;
                    if kind == BATCH {
                        return Err(Error::Corrupt("a batch inside a batch"));
                    }
                    bodies.push(Self::decode(kind, r.bytes()?)?);
                }
                if bodies.iter().filter(|body| body.approvals().is_some()).count() > 1 {
                    return Err(Error::Corrupt("two roster changes in one batch"));
                }
                Self::Batch { bodies }
            }
            _ => return Err(Error::Newer),
        };
        r.finish()?;
        Ok(decoded)
    }
}

/// A public key is its exact size or it is not a key.
#[path = "record_parts.rs"]
mod parts;
#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;
