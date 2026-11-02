//! What gets signed and linked, in one place, so no two uses can come to mean the same bytes.

use crate::crypto::{self, Hash, Key};
use crate::ids::{DeviceId, Generation, SpaceId, VaultId};
use crate::record::{DeviceRecord, RecoveryPublic};
use crate::wire::Writer;

/// The value a first entry links to, tying every device's chain to this vault.
pub fn root(genesis: &Hash, device: &DeviceId) -> Hash {
    crypto::hash(&[b"lv.root.v1", genesis, device.as_bytes()])
}

/// What ties a generation to its key. Any enrolled device can wrap anything to anyone, and a wrap
/// that opens proves only that someone made it, so a key counts only if it matches this.
pub fn epoch_commitment(vault: &VaultId, epoch: Generation, key: &Key) -> Hash {
    let mut w = Writer::new();
    w.generation(epoch);
    crypto::hash(&[b"lv.epoch.v1", vault.as_bytes(), &w.finish(), key.as_bytes()])
}

/// What an approval signs. Naming the roster head it follows makes an approval good for exactly
/// one position in one vault, so it cannot be replayed, and it cannot be backdated past a change
/// the approver had not seen. Naming the writer means it cannot be copied into another device's
/// log, which could take that position for itself by dating the copy earlier.
fn roster_digest(vault: &VaultId, after: &Hash, writer: &DeviceId, tag: &[u8], payload: &[u8]) -> Hash {
    crypto::hash(&[b"lv.roster.v2", vault.as_bytes(), after, writer.as_bytes(), tag, payload])
}

pub fn add_digest(vault: &VaultId, after: &Hash, writer: &DeviceId, device: &DeviceRecord) -> Hash {
    roster_digest(vault, after, writer, b"add", device.id().as_bytes())
}

/// What approving a server signs: the device, and what it may hold, which nobody can widen later.
pub fn server_digest(vault: &VaultId, after: &Hash, writer: &DeviceId, device: &DeviceRecord, spaces: Option<&[SpaceId]>) -> Hash {
    let mut w = Writer::new();
    w.array(device.id().as_bytes());
    write_spaces(&mut w, spaces);
    roster_digest(vault, after, writer, b"add-server", &w.finish())
}

/// The spaces a server may hold, or none at all for the whole vault.
pub fn write_spaces(w: &mut Writer, spaces: Option<&[SpaceId]>) {
    match spaces {
        None => w.u8(0),
        Some(spaces) => {
            w.u8(1);
            w.u32(u32::try_from(spaces.len()).expect("a vault has fewer spaces than that"));
            for space in spaces {
                w.array(space.as_bytes());
            }
        }
    }
}

pub fn revoke_digest(vault: &VaultId, after: &Hash, writer: &DeviceId, device: &DeviceId, entries_kept: u64, last_kept: &Hash) -> Hash {
    roster_digest(vault, after, writer, b"revoke", &[device.as_bytes().as_slice(), &entries_kept.to_le_bytes(), last_kept].concat())
}

pub fn rotate_digest(vault: &VaultId, after: &Hash, writer: &DeviceId, recovery: &RecoveryPublic) -> Hash {
    roster_digest(vault, after, writer, b"rotate", &recovery.id())
}

/// What the first roster change follows.
const ROSTER_START: Hash = [0; 32];

/// What both of a vault's creators sign: its first device and its recovery key, whole, so neither
/// can be swapped for another in a copy of the first entry.
pub fn genesis_digest(vault: &VaultId, device: &DeviceRecord, recovery: &RecoveryPublic, first_epoch: &Hash) -> Hash {
    let id = device.id();
    roster_digest(vault, &ROSTER_START, &id, b"genesis", &[recovery.id().as_slice(), first_epoch].concat())
}
