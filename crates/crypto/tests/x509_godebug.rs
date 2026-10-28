//! crypto/x509 behaviour selected by `GODEBUG` (x509usepolicies, x509sha256skid,
//! x509rsacrt, x509negativeserial) and the fallback roots. The settings are
//! process-global, so everything runs in one test, in sequence.

mod common;

use rust_stdlib_crypto::x509::{
    self, create_certificate, marshal_pkcs1_private_key, oid_from_ints, parse_certificate,
    parse_pkcs1_private_key, pkix, set_fallback_roots, system_cert_pool, BigInt, CertPool,
    Certificate, ObjectIdentifier, Time,
};
use rust_stdlib_crypto::{bigint::Int, ecdsa, elliptic, rsa};

fn set_godebug(value: &str) {
    // SAFETY-free: std::env::set_var is a safe function in this edition.
    std::env::set_var("GODEBUG", value);
}

fn template() -> Certificate {
    Certificate {
        serial_number: Some(BigInt::from_i64(1)),
        subject: pkix::Name {
            common_name: "Cert".to_string(),
            ..pkix::Name::default()
        },
        not_before: Time::unix(1000, 0),
        not_after: Time::unix(100000, 0),
        ..Certificate::default()
    }
}

#[test]
fn godebug_settings_and_fallback_roots() {
    // Keep the system roots empty and local: nothing is read from the machine.
    std::env::set_var("SSL_CERT_FILE", "/nonexistent/x509-test-file");
    std::env::set_var("SSL_CERT_DIR", "/nonexistent/x509-test-dir");
    let k = ecdsa::generate_key(elliptic::p256()).unwrap();

    // x509usepolicies=0: PolicyIdentifiers are marshaled instead of Policies.
    set_godebug("x509usepolicies=0");
    let mut t = template();
    t.policy_identifiers = vec![ObjectIdentifier(vec![1, 2, 3])];
    let der = create_certificate(&t, &t, &k.public_key, &k).unwrap();
    let cert = parse_certificate(&der).unwrap();
    assert_eq!(
        cert.policy_identifiers,
        vec![ObjectIdentifier(vec![1, 2, 3])]
    );
    assert_eq!(cert.policies, vec![oid_from_ints(&[1, 2, 3]).unwrap()]);

    // The default: Policies are marshaled and may exceed 31 bits.
    set_godebug("");
    let mut t = template();
    t.policy_identifiers = vec![ObjectIdentifier(vec![1, 2, 3])];
    t.policies = vec![oid_from_ints(&[1, 2, u64::from(u32::MAX) + 1]).unwrap()];
    let der = create_certificate(&t, &t, &k.public_key, &k).unwrap();
    let cert = parse_certificate(&der).unwrap();
    assert_eq!(cert.policies, t.policies);

    // x509sha256skid: the default subject key id is a truncated SHA-256, 0
    // selects SHA-1; both are 20 bytes and differ.
    let mut ca = template();
    ca.is_ca = true;
    ca.basic_constraints_valid = true;
    let sha256_id = parse_certificate(&create_certificate(&ca, &ca, &k.public_key, &k).unwrap())
        .unwrap()
        .subject_key_id;
    set_godebug("x509sha256skid=0");
    let sha1_id = parse_certificate(&create_certificate(&ca, &ca, &k.public_key, &k).unwrap())
        .unwrap()
        .subject_key_id;
    assert_eq!((sha256_id.len(), sha1_id.len()), (20, 20));
    assert_ne!(sha256_id, sha1_id);
    set_godebug("");

    // x509rsacrt=0: inconsistent CRT values are recomputed instead of rejected.
    let der = common::fixture_hex_const("pkcs8RSAPrivateKeyHex");
    let key = match x509::parse_pkcs8_private_key(&der).unwrap() {
        x509::PrivateKey::Rsa(k) => k,
        other => panic!("{other:?}"),
    };
    let mut broken: rsa::PrivateKey = key.clone();
    broken.precomputed.dp = Some(Int::from_u64(42));
    // Marshaling recomputes, so write the broken value by hand: replace dp in
    // the encoding of the valid key.
    let valid = marshal_pkcs1_private_key(&key);
    let dp = key.precomputed.dp.clone().unwrap().to_be_bytes();
    let at = valid
        .windows(dp.len())
        .rposition(|w| w == dp.as_slice())
        .expect("dp in encoding");
    let mut bad = valid.clone();
    bad[at] ^= 0x01;
    assert!(parse_pkcs1_private_key(&bad).is_err());
    set_godebug("x509rsacrt=0");
    let parsed = parse_pkcs1_private_key(&bad).expect("recomputed");
    assert_eq!(parsed.precomputed.dp, key.precomputed.dp);
    set_godebug("");

    // x509negativeserial=1 accepts negative serial numbers.
    let negative = common::fixture_cert_der("negativeSerialCert");
    assert!(parse_certificate(&negative).is_err());
    set_godebug("x509negativeserial=1");
    assert_eq!(
        parse_certificate(&negative)
            .unwrap()
            .serial_number
            .unwrap()
            .sign(),
        -1
    );
    set_godebug("");

    // Fallback roots replace empty system roots.
    let mut fallback = CertPool::new();
    let fallback_cert = common::fixture_cert_der("gtsRoot");
    fallback.add_cert(&parse_certificate(&fallback_cert).unwrap());
    set_fallback_roots(fallback.clone());
    assert!(system_cert_pool().unwrap().equal(&fallback));
    let second = std::panic::catch_unwind(|| set_fallback_roots(CertPool::new()));
    assert!(
        second.is_err(),
        "SetFallbackRoots must panic when called twice"
    );
}
