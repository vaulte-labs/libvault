use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};

use super::*;

fn origin(url: &str) -> Origin {
    Origin::parse(url).unwrap()
}

#[test]
fn a_passkey_belongs_to_its_site_and_the_sites_under_it_and_nowhere_else() {
    assert!(fits("github.com", &origin("https://github.com/login")));
    assert!(fits("github.com", &origin("https://gist.github.com")));
    assert!(fits("alice.github.io", &origin("https://alice.github.io")));
    assert!(fits("localhost", &origin("http://localhost:3000")));
    for (rp_id, page) in [
        ("github.com", "https://evilgithub.com"),
        ("github.com", "https://github.com.evil.example"),
        ("github.com", "http://github.com"),
        ("gist.github.com", "https://github.com"),
        ("co.uk", "https://example.co.uk"),
        ("github.io", "https://alice.github.io"),
        ("com", "https://github.com"),
        ("localhost", "https://example.com"),
        ("localhost", "https://app.localhost"),
        ("127.0.0.1", "https://127.0.0.1"),
    ] {
        assert!(!fits(rp_id, &origin(page)), "{rp_id} on {page}");
    }
}

#[test]
fn a_new_passkey_signs_what_its_public_key_verifies() {
    let (secret, created) = create("github.com", b"user-1").unwrap();
    let point = &created.public_key[26..];
    assert_eq!(point.len(), 65);
    let data = &created.authenticator_data;
    assert_eq!(&data[..32], digest(&SHA256, b"github.com").as_ref());
    assert_eq!(data[32], USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKED_UP | ATTESTED_CREDENTIAL);
    assert_eq!(&data[37..53], AAGUID);
    assert_eq!(&data[55..87], created.credential_id.as_slice());
    // COSE for ES256 on P-256, as WebAuthn spells it: {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
    let cose = [&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20][..], &point[1..33], &[0x22, 0x58, 0x20], &point[33..]].concat();
    assert_eq!(&data[87..], cose.as_slice());
    assert!(created.attestation_object.starts_with(&[0xa3, 0x63, b'f', b'm', b't']));
    assert!(created.attestation_object.ends_with(data));

    let client_data_hash = digest(&SHA256, br#"{"type":"webauthn.get","challenge":"abc","origin":"https://github.com"}"#);
    let assertion = sign(&secret, client_data_hash.as_ref()).unwrap();
    assert_eq!(assertion.credential_id, created.credential_id);
    assert_eq!(assertion.user_handle, b"user-1");
    assert_eq!(assertion.authenticator_data[32], USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKED_UP);
    let signed = [assertion.authenticator_data.as_slice(), client_data_hash.as_ref()].concat();
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point).verify(&signed, &assertion.signature).expect("the site can check it");
    let other = digest(&SHA256, b"another page's request");
    let tampered = [assertion.authenticator_data.as_slice(), other.as_ref()].concat();
    assert!(UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point).verify(&tampered, &assertion.signature).is_err());
}

#[test]
fn only_a_sha256_of_the_client_data_is_signed() {
    let (secret, _) = create("github.com", b"user-1").unwrap();
    assert!(sign(&secret, b"too short").is_err());
}
