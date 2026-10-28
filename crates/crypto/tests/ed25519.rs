//! crypto/ed25519, ported from Go's ed25519_test.go and ed25519_wycheproof_test.go.

mod common;

use common::{hex, rows, unhex};
use rust_stdlib_crypto::ed25519::{
    self, Options, PrivateKey, PublicKey, PRIVATE_KEY_SIZE, PUBLIC_KEY_SIZE, SIGNATURE_SIZE,
};
use rust_stdlib_crypto::{sha512, sign_message, Hash, Signer};

struct ZeroReader;

impl std::io::Read for ZeroReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }
}

#[test]
fn generate_key() {
    let (public, private) = ed25519::generate_key().unwrap();
    assert_eq!(public.0.len(), PUBLIC_KEY_SIZE);
    assert_eq!(private.as_bytes().len(), PRIVATE_KEY_SIZE);
    assert_eq!(private.public_key(), public);
    let from_seed = ed25519::PrivateKey::from_seed(&private.seed()).unwrap();
    assert_eq!(private, from_seed);
    let (_, other) = ed25519::generate_key().unwrap();
    assert_ne!(private, other);
    let mut reader = rust_stdlib_crypto::rand::Reader;
    let (_, third) = ed25519::generate_key_with_rng(&mut reader).unwrap();
    assert_ne!(private, third);
}

#[test]
fn bad_seed_and_key_lengths() {
    assert_eq!(
        ed25519::PrivateKey::from_seed(&[0; 31])
            .unwrap_err()
            .to_string(),
        "ed25519: bad seed length: 31"
    );
    let short = PrivateKey::from_bytes(vec![0; 10]);
    assert_eq!(
        ed25519::sign(&short, b"x").unwrap_err().to_string(),
        "ed25519: bad private key length: 10"
    );
    assert_eq!(
        ed25519::verify(&PublicKey(vec![0; 3]), b"x", &[0; 64])
            .unwrap_err()
            .to_string(),
        "ed25519: bad public key length: 3"
    );
    // A mismatched public half is rejected (Go signs with it).
    let mut bytes = ed25519::PrivateKey::from_seed(&[1; 32])
        .unwrap()
        .as_bytes()
        .to_vec();
    bytes[40] ^= 1;
    assert_eq!(
        ed25519::sign(&PrivateKey::from_bytes(bytes), b"x")
            .unwrap_err()
            .to_string(),
        "ed25519: bad private key: public key does not match seed"
    );
}

#[test]
fn sign_verify() {
    let (public, private) = ed25519::generate_key().unwrap();
    let message = b"Hello, world!";
    let mut sig = ed25519::sign(&private, message).unwrap();
    assert!(ed25519::verify(&public, message, &sig).unwrap());
    let wrong = b"Hello, world.";
    assert!(!ed25519::verify(&public, wrong, &sig).unwrap());
    sig[0] ^= 0xff;
    assert!(!ed25519::verify(&public, message, &sig).unwrap());
}

fn sha512_of(message: &[u8]) -> Vec<u8> {
    sha512::sum512(message).to_vec()
}

#[test]
fn sign_verify_hashed() {
    // From RFC 8032, Section 7.3.
    let key = unhex("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    let expected = unhex("98a70222f0b8121aa9d30f813d683f809e462b469c7ff87639499bb94e6dae4131f85042463c2a355a2003d062adf5aaa10b8c61e636062aaad11c2a26083406");
    let private = PrivateKey::from_bytes(key);
    let public = private.public_key();
    let hash = sha512_of(&unhex("616263"));
    let mut sig = private.sign(&hash, &Hash::Sha512).unwrap();
    assert_eq!(sig, expected);
    let ph = Options {
        hash: Some(Hash::Sha512),
        context: String::new(),
    };
    sig = private.sign(&hash, &ph).unwrap();
    assert_eq!(sig, expected);
    ed25519::verify_with_options(&public, &hash, &sig, &ph).unwrap();
    let wrong_hash = Options {
        hash: Some(Hash::Sha256),
        context: String::new(),
    };
    assert!(ed25519::verify_with_options(&public, &hash, &sig, &wrong_hash).is_err());
    assert!(
        ed25519::verify_with_options(&public, &sha512_of(b"wrong message"), &sig, &ph).is_err()
    );
    sig[0] ^= 0xff;
    assert!(ed25519::verify_with_options(&public, &hash, &sig, &ph).is_err());
    sig[0] ^= 0xff;
    sig[SIGNATURE_SIZE - 1] ^= 0xff;
    assert!(ed25519::verify_with_options(&public, &hash, &sig, &ph).is_err());

    // The RFC provides no vectors for Ed25519ph with a context.
    let with_context = Options {
        hash: Some(Hash::Sha512),
        context: "123".into(),
    };
    let sig = private.sign(&hash, &with_context).unwrap();
    ed25519::verify_with_options(&public, &hash, &sig, &with_context).unwrap();
    let other_context = Options {
        hash: Some(Hash::Sha512),
        context: "321".into(),
    };
    assert!(ed25519::verify_with_options(&public, &hash, &sig, &other_context).is_err());
    let wrong_hash_context = Options {
        hash: Some(Hash::Sha256),
        context: "123".into(),
    };
    assert!(ed25519::verify_with_options(&public, &hash, &sig, &wrong_hash_context).is_err());

    // Messages that are not 64 bytes and long contexts are rejected like Go.
    assert_eq!(
        private
            .sign(&hash[..63], &Hash::Sha512)
            .unwrap_err()
            .to_string(),
        "ed25519: bad Ed25519ph message hash length: 63"
    );
    let long = Options {
        hash: Some(Hash::Sha512),
        context: "x".repeat(256),
    };
    assert_eq!(
        private.sign(&hash, &long).unwrap_err().to_string(),
        "ed25519: bad Ed25519ph context length: 256"
    );
    assert_eq!(
        private.sign(&hash, &Hash::Sha256).unwrap_err().to_string(),
        "ed25519: expected opts.HashFunc() zero (unhashed message, for standard Ed25519) or SHA-512 (for Ed25519ph)"
    );
}

#[test]
fn ed25519ctx_is_a_documented_limit() {
    // RFC 8032, Section 7.2: reviewed ed25519-dalek does not expose Ed25519ctx.
    let key = unhex("0305334e381af78f141cb666f6199f57bc3495335a256a95bd2a55bf546663f6dfc9425e4f968f7f0c29f0259cf5f9aed6851c2bb4ad8bfb860cfee0ab248292");
    let private = PrivateKey::from_bytes(key);
    let options = Options {
        hash: None,
        context: "foo".into(),
    };
    let error = private
        .sign(&unhex("f726936d19c800494e3fdaff20b276a8"), &options)
        .unwrap_err()
        .to_string();
    assert!(error.contains("Ed25519ctx is not supported"), "{error}");
    let long = Options {
        hash: None,
        context: "x".repeat(300),
    };
    assert_eq!(
        private.sign(b"m", &long).unwrap_err().to_string(),
        "ed25519: bad Ed25519ctx context length: 300"
    );
    assert!(ed25519::verify_with_options(&private.public_key(), b"m", &[0; 64], &options).is_err());
}

#[test]
fn crypto_signer() {
    let (public, private) = ed25519::generate_key_with_rng(&mut ZeroReader).unwrap();
    let signer: &dyn Signer = &private;
    let from_signer = signer.public().downcast_ref::<PublicKey>().unwrap();
    assert_eq!(&public, from_signer);
    let message = b"message";
    let signature = signer.sign(message, &Hash::Md4).map(|_| ());
    // Hash::Md4 is not "no hash": Go rejects it too.
    assert!(signature.is_err());
    let plain = Options::default();
    let sig = signer.sign(message, &plain).unwrap();
    assert!(ed25519::verify(&public, message, &sig).unwrap());
    // sign_message with no hash passes the message through.
    let via_helper = sign_message(signer, message, &plain).unwrap();
    assert_eq!(sig, via_helper);
}

#[test]
fn equal() {
    let (public, private) = ed25519::generate_key().unwrap();
    assert!(public.equal(&public));
    assert!(public.equal(&private.public_key()));
    assert!(private.equal(&private));
    assert!(!private.equal(&public));
    let (other_public, other_private) = ed25519::generate_key().unwrap();
    assert!(!public.equal(&other_public));
    assert!(!private.equal(&other_private));
}

#[test]
fn golden() {
    let rows = rows("ed25519_golden.tsv");
    assert_eq!(rows.len(), 16);
    for (index, row) in rows.iter().enumerate() {
        let (seed, public, message, sig) = (
            unhex(&row[0]),
            unhex(&row[1]),
            unhex(&row[2]),
            unhex(&row[3]),
        );
        let mut bytes = seed.clone();
        bytes.extend_from_slice(&public);
        let private = PrivateKey::from_bytes(bytes.clone());
        assert_eq!(
            ed25519::sign(&private, &message).unwrap(),
            sig,
            "line {index}"
        );
        assert!(ed25519::verify(&PublicKey(public.clone()), &message, &sig).unwrap());
        let derived = ed25519::PrivateKey::from_seed(&seed).unwrap();
        assert_eq!(derived.as_bytes(), bytes.as_slice());
        assert_eq!(derived.public_key(), PublicKey(public));
        assert_eq!(derived.seed(), seed);
    }
}

#[test]
fn malleability() {
    // RFC 8032, Section 5.1.7: s must be in [0, order).
    let message = [0x54, 0x65, 0x73, 0x74];
    let sig = unhex("7c38e026f29e14aabd059a0f2db8b0cd783040609a8be684db12f82a27774ab067654bce3832c2d76f8f6f5dafc08d9339d4eef676573336a5c51eb6f946b31d");
    let public = PublicKey(unhex(
        "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
    ));
    assert!(!ed25519::verify(&public, &message, &sig).unwrap());
}

#[test]
fn wycheproof() {
    let rows = rows("ed25519_wycheproof.tsv");
    assert_eq!(rows.len(), 150);
    for row in &rows {
        let public = PublicKey::from_pkix_der(&unhex(&row[0])).unwrap();
        let (message, sig) = (unhex(&row[1]), unhex(&row[2]));
        let want = match row[3].as_str() {
            "valid" => true,
            "invalid" => false,
            other => panic!("unexpected result {other}"),
        };
        let got = ed25519::verify(&public, &message, &sig).unwrap();
        assert_eq!(got, want, "msg {} sig {}", hex(&message), hex(&sig));
    }
}

#[test]
fn der_round_trip() {
    let (public, private) = ed25519::generate_key().unwrap();
    let pkix = public.to_pkix_der().unwrap();
    assert_eq!(pkix.len(), 44);
    assert_eq!(PublicKey::from_pkix_der(&pkix).unwrap(), public);
    let pkcs8 = private.to_pkcs8_der().unwrap();
    assert_eq!(PrivateKey::from_pkcs8_der(&pkcs8).unwrap(), private);
    assert!(PublicKey::from_pkix_der(&pkix[..40]).is_err());
}
