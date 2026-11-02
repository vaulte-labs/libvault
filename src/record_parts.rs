//! How the parts of a record are written and read, kept apart from the record kinds themselves.

use super::{Approval, Approver, DeviceRecord, RecoveryPublic};
use crate::crypto::{Hash, HybridSignature, MLDSA_PUBLIC_LEN, MLDSA_SIGNATURE_LEN, MLKEM_PUBLIC_LEN, Wrapped};
use crate::ids::{DeviceId, Generation, SpaceId};
use crate::wire::{Reader, Writer};
use crate::{Error, Result};

pub(super) fn read_key(r: &mut Reader<'_>, length: usize) -> Result<Vec<u8>> {
    let key = r.bytes()?;
    if key.len() == length { Ok(key.to_vec()) } else { Err(Error::Corrupt("bad public key length")) }
}

pub(super) fn write_recovery(w: &mut Writer, recovery: &RecoveryPublic) {
    w.array(&recovery.ed25519);
    w.bytes(&recovery.dsa);
    w.array(&recovery.agreement);
    w.bytes(&recovery.kem);
    w.bytes(&recovery.sealed_private);
}

pub(super) fn read_recovery(r: &mut Reader<'_>) -> Result<RecoveryPublic> {
    Ok(RecoveryPublic {
        ed25519: r.array()?,
        dsa: read_key(r, MLDSA_PUBLIC_LEN)?,
        agreement: r.array()?,
        kem: read_key(r, MLKEM_PUBLIC_LEN)?,
        sealed_private: r.bytes()?.to_vec(),
    })
}

pub(super) fn write_signature(w: &mut Writer, signature: &HybridSignature) {
    w.array(&signature.ec);
    w.bytes(&signature.pq);
}

pub(super) fn read_signature(r: &mut Reader<'_>) -> Result<HybridSignature> {
    let ec = r.array()?;
    let pq = r.bytes()?;
    if pq.len() != MLDSA_SIGNATURE_LEN {
        return Err(Error::Corrupt("bad signature length"));
    }
    Ok(HybridSignature { ec, pq: pq.to_vec() })
}

pub(super) fn write_wrapped(w: &mut Writer, wrapped: &Wrapped) {
    w.array(&wrapped.ephemeral);
    w.bytes(&wrapped.ciphertext);
    w.bytes(&wrapped.sealed);
}

pub(super) fn read_wrapped(r: &mut Reader<'_>) -> Result<Wrapped> {
    Ok(Wrapped { ephemeral: r.array()?, ciphertext: r.bytes()?.to_vec(), sealed: r.bytes()?.to_vec() })
}

pub(super) fn write_approvals(w: &mut Writer, approvals: &[Approval]) {
    w.u8(u8::try_from(approvals.len()).expect("approvals are few"));
    for approval in approvals {
        match approval.by {
            Approver::Device(device) => {
                w.u8(0);
                w.array(device.as_bytes());
            }
            Approver::Recovery => w.u8(1),
        }
        write_signature(w, &approval.signature);
    }
}

pub(super) fn read_approvals(r: &mut Reader<'_>) -> Result<Vec<Approval>> {
    (0..r.u8()?)
        .map(|_| {
            let by = match r.u8()? {
                0 => Approver::Device(r.id()?),
                1 => Approver::Recovery,
                _ => return Err(Error::Corrupt("unknown approver")),
            };
            Ok(Approval { by, signature: read_signature(r)? })
        })
        .collect()
}

pub(super) fn write_space_wrap(w: &mut Writer, space: &SpaceId, version: Generation, device: &DeviceId, wrapped: &Wrapped, name: &[u8]) {
    w.array(space.as_bytes());
    w.generation(version);
    w.array(device.as_bytes());
    write_wrapped(w, wrapped);
    w.bytes(name);
}

pub(super) fn write_server_add(w: &mut Writer, after: &Hash, device: &DeviceRecord, spaces: Option<&[SpaceId]>, approvals: &[Approval]) {
    w.array(after);
    device.write(w);
    crate::digest::write_spaces(w, spaces);
    write_approvals(w, approvals);
}
