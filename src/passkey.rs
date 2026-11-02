//! Passkeys, kept like any other item so they reach every device in their space. A key that syncs
//! cannot be bound to one device's Secure Enclave, which is the trade every synced passkey makes.
//! The private key never leaves the broker: a site gets a signature, and an interface gets the
//! public half and the bytes `WebAuthn` asks for.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use zeroize::Zeroizing;

use crate::fill::{Origin, is_registrable};
use crate::item::Secret;
use crate::protocol::{NewPasskey, PasskeyAssertion};
use crate::{Error, Result};

/// Which authenticator made a passkey, as `WebAuthn` asks. The same for every copy of Vaulte.
const AAGUID: [u8; 16] = [0x5d, 0x58, 0x7a, 0x10, 0x83, 0xc1, 0x09, 0x36, 0x0c, 0x40, 0xc7, 0x42, 0x85, 0x3e, 0xf4, 0x4d];

const USER_PRESENT: u8 = 0x01;
/// Every use takes a touch, so this is true.
const USER_VERIFIED: u8 = 0x04;
/// It syncs, which a site may want to know before it lets someone drop their password.
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKED_UP: u8 = 0x10;
const ATTESTED_CREDENTIAL: u8 = 0x40;

/// Where a passkey lives: its host or a domain above it that is one site's own, never a suffix
/// many sites share, and over https or on this machine.
pub(crate) fn fits(rp_id: &str, origin: &Origin) -> bool {
    let secure = origin.scheme == "https" || origin.is_loopback();
    let at_or_under = origin.host == rp_id || origin.host.strip_suffix(rp_id).is_some_and(|rest| rest.ends_with('.'));
    let its_own = is_registrable(rp_id) || (rp_id == "localhost" && origin.host == "localhost");
    secure && at_or_under && its_own
}

fn generation_failed(_: aws_lc_rs::error::Unspecified) -> Error {
    Error::Corrupt("a passkey could not be made")
}

/// A new passkey for `rp_id`, as the secret to store and what the site is sent back.
pub(crate) fn create(rp_id: &str, user_handle: &[u8]) -> Result<(Secret, NewPasskey)> {
    let pkcs8 = Zeroizing::new(
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new()).map_err(generation_failed)?.as_ref().to_vec(),
    );
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8).map_err(|_| Error::Corrupt("a passkey could not be made"))?;
    let point = pair.public_key().as_ref();
    let credential_id = crate::crypto::random::<32>().to_vec();
    let flags = USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKED_UP | ATTESTED_CREDENTIAL;
    let authenticator_data = authenticator_data(rp_id, flags, Some((&credential_id, point)));
    let secret = Secret::Passkey {
        rp_id: rp_id.to_owned(),
        user_handle: URL_SAFE_NO_PAD.encode(user_handle),
        credential_id: URL_SAFE_NO_PAD.encode(&credential_id),
        private_key: URL_SAFE_NO_PAD.encode(&*pkcs8),
    };
    let attestation_object = attestation_object(&authenticator_data);
    Ok((
        secret,
        NewPasskey { name: String::new(), credential_id, public_key: subject_public_key_info(point), authenticator_data, attestation_object },
    ))
}

/// Signs a sign-in for `client_data_hash`, the SHA-256 of what the browser built for the page.
pub(crate) fn sign(secret: &Secret, client_data_hash: &[u8]) -> Result<PasskeyAssertion> {
    let Secret::Passkey { rp_id, user_handle, credential_id, private_key } = secret else {
        return Err(Error::Invalid("that is not a passkey"));
    };
    if client_data_hash.len() != 32 {
        return Err(Error::Invalid("the client data hash is SHA-256, 32 bytes"));
    }
    let unreadable = || Error::Corrupt("that passkey could not be read");
    let pkcs8 = Zeroizing::new(URL_SAFE_NO_PAD.decode(private_key).map_err(|_| unreadable())?);
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8).map_err(|_| unreadable())?;
    let authenticator_data = authenticator_data(rp_id, USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKED_UP, None);
    let signed = [authenticator_data.as_slice(), client_data_hash].concat();
    let signature = pair.sign(&SystemRandom::new(), &signed).map_err(|_| unreadable())?.as_ref().to_vec();
    Ok(PasskeyAssertion {
        credential_id: URL_SAFE_NO_PAD.decode(credential_id).map_err(|_| unreadable())?,
        user_handle: URL_SAFE_NO_PAD.decode(user_handle).map_err(|_| unreadable())?,
        authenticator_data,
        signature,
    })
}

/// The credential id a stored passkey answers to.
pub(crate) fn credential_id(secret: &Secret) -> Option<Vec<u8>> {
    let Secret::Passkey { credential_id, .. } = secret else { return None };
    URL_SAFE_NO_PAD.decode(credential_id).ok()
}

/// `WebAuthn`'s authenticator data. The sign count stays 0, as a synced passkey's must.
fn authenticator_data(rp_id: &str, flags: u8, attested: Option<(&[u8], &[u8])>) -> Vec<u8> {
    let mut data = digest(&SHA256, rp_id.as_bytes()).as_ref().to_vec();
    data.push(flags);
    data.extend([0; 4]);
    if let Some((credential_id, point)) = attested {
        data.extend(AAGUID);
        data.extend(u16::try_from(credential_id.len()).expect("a credential id is 32 bytes").to_be_bytes());
        data.extend(credential_id);
        data.extend(cose_key(point));
    }
    data
}

/// The public key as COSE wants it for ES256, from an uncompressed P-256 point, in canonical CBOR.
fn cose_key(point: &[u8]) -> Vec<u8> {
    // {1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y}
    let mut key = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    key.extend(&point[1..33]);
    key.extend([0x22, 0x58, 0x20]);
    key.extend(&point[33..65]);
    key
}

/// `{"fmt": "none", "attStmt": {}, "authData": ...}` in canonical CBOR. Nothing vouches for the
/// authenticator, which is what a synced passkey can honestly say.
fn attestation_object(authenticator_data: &[u8]) -> Vec<u8> {
    let mut object = vec![0xa3, 0x63];
    object.extend(b"fmt");
    object.push(0x64);
    object.extend(b"none");
    object.push(0x67);
    object.extend(b"attStmt");
    object.push(0xa0);
    object.push(0x68);
    object.extend(b"authData");
    // Canonical CBOR takes the shortest length that fits.
    if let Ok(length) = u8::try_from(authenticator_data.len()) {
        object.extend([0x58, length]);
    } else {
        object.push(0x59);
        object.extend(u16::try_from(authenticator_data.len()).expect("authenticator data is small").to_be_bytes());
    }
    object.extend(authenticator_data);
    object
}

/// The public key as a browser's `getPublicKey()` returns it: DER for an EC P-256 key.
fn subject_public_key_info(point: &[u8]) -> Vec<u8> {
    const PREFIX: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00,
    ];
    [PREFIX.as_slice(), point].concat()
}

#[cfg(test)]
#[path = "passkey_tests.rs"]
mod tests;
