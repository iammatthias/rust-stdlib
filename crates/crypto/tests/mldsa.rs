//! crypto/mldsa, ported from Go's mldsa_test.go and mldsa_wycheproof_test.go.

mod common;

use std::collections::HashMap;

use common::{rows, unhex};
use rust_stdlib_crypto::mldsa::{self, Options, Parameters, PrivateKey, PublicKey};
use rust_stdlib_crypto::{sign_message, Hash, Signer};

fn params(name: &str) -> Parameters {
    match name {
        "44" => mldsa::mldsa44(),
        "65" => mldsa::mldsa65(),
        "87" => mldsa::mldsa87(),
        other => panic!("parameters {other}"),
    }
}

fn keys() -> HashMap<String, Vec<u8>> {
    rows("mldsa_keys.tsv")
        .into_iter()
        .map(|row| (row[0].clone(), unhex(&row[1])))
        .collect()
}

#[test]
fn parameters() {
    assert_eq!(mldsa::mldsa44().to_string(), "ML-DSA-44");
    assert_eq!(mldsa::mldsa65().to_string(), "ML-DSA-65");
    assert_eq!(mldsa::mldsa87().to_string(), "ML-DSA-87");
    assert_eq!(
        mldsa::mldsa65().public_key_size(),
        mldsa::MLDSA65_PUBLIC_KEY_SIZE
    );
    assert_eq!(
        mldsa::mldsa87().signature_size(),
        mldsa::MLDSA87_SIGNATURE_SIZE
    );
    assert_eq!(mldsa::mldsa44().signature_size(), 2420);
}

#[test]
fn sign_verify_round_trip() {
    for p in [mldsa::mldsa44(), mldsa::mldsa65(), mldsa::mldsa87()] {
        let key = mldsa::generate_key(p).unwrap();
        assert_eq!(key.bytes().len(), mldsa::PRIVATE_KEY_SIZE);
        let public = key.public_key();
        assert_eq!(public.bytes().len(), p.public_key_size());
        assert_eq!(public.parameters(), p);
        let msg = b"Hello, world!";
        let opts = Options {
            context: "ctx".into(),
            hash: None,
        };
        let sig = key.sign(msg, Some(&opts)).unwrap();
        assert_eq!(sig.len(), p.signature_size());
        mldsa::verify(&public, msg, &sig, Some(&opts)).unwrap();
        assert!(mldsa::verify(&public, msg, &sig, None).is_err());
        assert!(mldsa::verify(&public, b"other", &sig, Some(&opts)).is_err());
        let mut bad = sig.clone();
        bad[10] ^= 1;
        assert!(mldsa::verify(&public, msg, &bad, Some(&opts)).is_err());

        // Deterministic signatures repeat, randomized ones do not.
        let a = key.sign_deterministic(msg, None).unwrap();
        assert_eq!(a, key.sign_deterministic(msg, None).unwrap());
        assert_ne!(key.sign(msg, None).unwrap(), key.sign(msg, None).unwrap());
        mldsa::verify(&public, msg, &a, None).unwrap();

        // Public and private key round trips.
        let again = mldsa::PrivateKey::from_seed(p, &key.bytes()).unwrap();
        assert!(again.equal(&key));
        assert!(again.public_key().equal(&public));
        let parsed = mldsa::PublicKey::from_bytes(p, &public.bytes()).unwrap();
        assert!(parsed.equal(&public));
        assert!(!key.equal(&mldsa::generate_key(p).unwrap()));
    }
}

#[test]
fn errors_use_go_messages() {
    let p = mldsa::mldsa44();
    assert_eq!(
        mldsa::PrivateKey::from_seed(p, &[0; 31])
            .unwrap_err()
            .to_string(),
        "mldsa: invalid seed length"
    );
    assert_eq!(
        mldsa::PublicKey::from_bytes(p, &[0; 5])
            .unwrap_err()
            .to_string(),
        "mldsa: invalid public key length"
    );
    let key = mldsa::generate_key(p).unwrap();
    let long = Options {
        context: "x".repeat(256),
        hash: None,
    };
    assert_eq!(
        key.sign(b"m", Some(&long)).unwrap_err().to_string(),
        "mldsa: context too long"
    );
    assert_eq!(
        mldsa::verify(&key.public_key(), b"m", &[0; 10], None)
            .unwrap_err()
            .to_string(),
        "mldsa: invalid signature length"
    );
    assert_eq!(
        key.sign(b"m", Some(&Hash::Sha256)).unwrap_err().to_string(),
        "mldsa: invalid SignerOpts"
    );
    assert_eq!(
        key.sign(b"short", Some(&Hash::MlDsaMu))
            .unwrap_err()
            .to_string(),
        "mldsa: invalid message hash length"
    );
}

#[test]
fn signer_interface() {
    let key = mldsa::generate_key(mldsa::mldsa65()).unwrap();
    let signer: &dyn Signer = &key;
    assert!(signer.public().downcast_ref::<PublicKey>().is_some());
    let sig = sign_message(signer, b"msg", &Options::default()).unwrap();
    mldsa::verify(&key.public_key(), b"msg", &sig, None).unwrap();
    // External μ: a 64-byte value signs without a message.
    let mu = [9u8; 64];
    let sig = key.sign_deterministic(&mu, Some(&Hash::MlDsaMu)).unwrap();
    assert_eq!(sig.len(), mldsa::MLDSA65_SIGNATURE_SIZE);
}

#[test]
fn wycheproof_verify() {
    let keys = keys();
    let data = rows("mldsa_verify.tsv");
    assert_eq!(data.len(), 77);
    for row in &data {
        let p = params(&row[0]);
        let should_pass = match row[5].as_str() {
            "valid" => true,
            "invalid" => false,
            other => panic!("result {other}"),
        };
        let encoded = &keys[&row[1]];
        let public = match mldsa::PublicKey::from_bytes(p, encoded) {
            Ok(public) => public,
            Err(error) => {
                assert!(!should_pass, "{error}: {row:?}");
                continue;
            }
        };
        assert_eq!(&public.bytes(), encoded);
        let opts = Options {
            context: String::from_utf8(unhex(&row[3])).expect("context is text in these vectors"),
            hash: None,
        };
        let result = mldsa::verify(&public, &unhex(&row[2]), &unhex(&row[4]), Some(&opts));
        assert_eq!(result.is_ok(), should_pass, "{result:?}: {row:?}");
    }
}

#[test]
fn wycheproof_sign_deterministic() {
    let keys = keys();
    let data = rows("mldsa_sign.tsv");
    assert_eq!(data.len(), 33);
    for row in &data {
        let p = params(&row[0]);
        let should_pass = match row[7].as_str() {
            "valid" => true,
            "invalid" => false,
            other => panic!("result {other}"),
        };
        let key: PrivateKey = match mldsa::PrivateKey::from_seed(p, &unhex(&row[1])) {
            Ok(key) => key,
            Err(error) => {
                assert!(!should_pass, "{error}");
                continue;
            }
        };
        if let Some(public) = keys.get(&row[2]) {
            assert_eq!(&key.public_key().bytes(), public, "{row:?}");
        }
        let (msg, ctx, mu, expected) = (
            unhex(&row[3]),
            unhex(&row[4]),
            unhex(&row[5]),
            unhex(&row[6]),
        );
        let opts = Options {
            context: String::from_utf8(ctx).expect("text context"),
            hash: None,
        };
        let from_msg =
            (!msg.is_empty() || mu.is_empty()).then(|| key.sign_deterministic(&msg, Some(&opts)));
        let from_mu = (!mu.is_empty()).then(|| key.sign_deterministic(&mu, Some(&Hash::MlDsaMu)));
        let results: Vec<_> = [from_msg, from_mu].into_iter().flatten().collect();
        if results.iter().any(Result::is_err) {
            assert!(!should_pass, "{results:?}: {row:?}");
            continue;
        }
        assert!(should_pass, "unexpected success: {row:?}");
        for sig in results {
            assert_eq!(sig.unwrap(), expected, "{row:?}");
        }
    }
}
