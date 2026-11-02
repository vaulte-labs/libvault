//! Encoding, one form per value.

use super::*;
use crate::crypto::MLDSA_SIGNATURE_LEN;

fn signature() -> HybridSignature {
    HybridSignature { ec: [1; 64], pq: vec![2; MLDSA_SIGNATURE_LEN] }
}

fn device() -> DeviceRecord {
    let keys = PublicKeys { agreement: [3; 65], kem: vec![4; 1568], signing: [5; 65], dsa: vec![6; 2592] };
    DeviceRecord { keys, log: [7; 32], sync: [8; 32] }
}

fn recovery() -> RecoveryPublic {
    RecoveryPublic { ed25519: [9; 32], dsa: vec![10; 2592], agreement: [22; 65], kem: vec![23; 1568], sealed_private: vec![24; 40] }
}

#[test]
fn a_public_key_of_the_wrong_size_is_refused_where_it_is_read() {
    let short = |record: DeviceRecord| {
        let mut w = Writer::new();
        record.write(&mut w);
        DeviceRecord::read(&mut Reader::new(&w.finish())).is_err()
    };
    assert!(short(DeviceRecord { keys: PublicKeys { kem: vec![4; 10], ..device().keys }, ..device() }));
    assert!(short(DeviceRecord { keys: PublicKeys { dsa: vec![6; 10], ..device().keys }, ..device() }));
    assert!(
        Body::decode(
            4,
            &Body::RecoveryRotate {
                after: [0; 32],
                recovery: RecoveryPublic { kem: vec![1; 9], ..recovery() },
                proof: signature(),
                approvals: vec![]
            }
            .encode()
        )
        .is_err()
    );
    assert!(
        Body::decode(
            4,
            &Body::RecoveryRotate {
                after: [0; 32],
                recovery: RecoveryPublic { dsa: vec![1; 9], ..recovery() },
                proof: signature(),
                approvals: vec![]
            }
            .encode()
        )
        .is_err()
    );
}

/// The kind numbers in `kind` and `decode` are two lists of one fact. This fails if they differ.
#[test]
fn every_kind_of_body_round_trips() {
    let id = || -> [u8; 16] { [11; 16] };
    let gen_ = |number| Generation { number, author: id().into() };
    let approvals =
        vec![Approval { by: Approver::Device(id().into()), signature: signature() }, Approval { by: Approver::Recovery, signature: signature() }];
    let wrapped = Wrapped { ephemeral: [12; 65], ciphertext: vec![13; 8], sealed: vec![14; 8] };
    let bodies = [
        Body::Genesis {
            vault: id().into(),
            recovery: recovery(),
            device: device(),
            first_epoch: [34; 32],
            device_signature: signature(),
            recovery_signature: signature(),
        },
        Body::DeviceAdd { after: [30; 32], device: device(), approvals: approvals.clone() },
        Body::DeviceRevoke { after: [31; 32], device: id().into(), entries_kept: 5, last_kept: [35; 32], approvals: approvals.clone() },
        Body::RecoveryRotate { after: [32; 32], recovery: recovery(), proof: signature(), approvals },
        Body::Wrap { epoch: gen_(1), sealed: Sealed::Device(id().into(), wrapped) },
        Body::Wrap {
            epoch: gen_(2),
            sealed: Sealed::Recovery([33; 16], Wrapped { ephemeral: [15; 65], ciphertext: vec![15; 8], sealed: vec![15; 8] }),
        },
        Body::EpochLink { epoch: gen_(3), previous: gen_(2), commitment: [36; 32], roster: [37; 32], sealed: vec![16; 8] },
        Body::ExtraLink { epoch: gen_(3), previous: gen_(1), sealed: vec![17; 8] },
        Body::Space { space: id().into(), version: gen_(4), epoch: gen_(5), sealed: vec![17; 8] },
        Body::ItemPut { space: id().into(), item: id().into(), version: gen_(6), batch: id().into(), meta: vec![18; 8], secret: vec![19; 8] },
        Body::ItemDelete { space: id().into(), item: id().into(), batch: id().into() },
        Body::Audit { epoch: gen_(7), sealed: vec![20; 8] },
        Body::Label { device: id().into(), epoch: gen_(8), sealed: vec![21; 8] },
        Body::Batch {
            bodies: vec![
                Body::Audit { epoch: gen_(9), sealed: vec![25; 8] },
                Body::ItemDelete { space: id().into(), item: id().into(), batch: id().into() },
            ],
        },
    ];
    for body in bodies {
        assert_eq!(Body::decode(body.kind(), &body.encode()).unwrap(), body);
    }
}

#[test]
fn a_batch_cannot_hold_a_batch() {
    let inner = Body::Batch { bodies: vec![] };
    let outer = Body::Batch { bodies: vec![inner] };
    assert!(Body::decode(outer.kind(), &outer.encode()).is_err(), "nesting would let an entry recurse without limit");
}

#[test]
fn an_unknown_kind_asks_for_a_newer_lv() {
    assert!(matches!(Body::decode(200, &[]), Err(Error::Newer)));
}

#[test]
fn trailing_bytes_are_rejected() {
    let mut bytes = Body::Audit { epoch: Generation { number: 7, author: [1; 16].into() }, sealed: vec![1] }.encode();
    bytes.push(0);
    assert!(Body::decode(10, &bytes).is_err());
}
