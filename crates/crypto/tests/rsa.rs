//! crypto/rsa, ported from Go's rsa_test.go, pkcs1v15_test.go, pss_test.go and
//! rsa_wycheproof_test.go. The tests that need keys below 1024 bits are in
//! tests/rsa_small_keys.rs, which sets `GODEBUG=rsa1024min=0`.

mod common;

use std::collections::HashMap;
use std::io::Cursor;

use common::{rows, unhex};
use rust_stdlib_crypto::bigint::Int;
use rust_stdlib_crypto::rsa::{
    self, Error, OAEPOptions, PKCS1v15DecryptOptions, PSSOptions, PrivateKey, PublicKey,
    PSS_SALT_LENGTH_AUTO, PSS_SALT_LENGTH_EQUALS_HASH,
};
use rust_stdlib_crypto::{sha256, sign_message, Decrypter, Hash, Signer};

fn hash_by_name(name: &str) -> Hash {
    match name {
        "SHA-1" => Hash::Sha1,
        "SHA-224" => Hash::Sha224,
        "SHA-256" => Hash::Sha256,
        "SHA-384" => Hash::Sha384,
        "SHA-512" => Hash::Sha512,
        "SHA-512/224" => Hash::Sha512_224,
        "SHA-512/256" => Hash::Sha512_256,
        "SHA3-224" => Hash::Sha3_224,
        "SHA3-256" => Hash::Sha3_256,
        "SHA3-384" => Hash::Sha3_384,
        "SHA3-512" => Hash::Sha3_512,
        other => panic!("hash {other}"),
    }
}

fn digest(hash: Hash, msg: &[u8]) -> Vec<u8> {
    let mut h = hash.new().unwrap();
    std::io::Write::write_all(&mut h, msg).unwrap();
    let mut out = Vec::new();
    h.sum(&mut out);
    out
}

struct Keys {
    private: HashMap<String, PrivateKey>,
    public: HashMap<String, PublicKey>,
}

fn wycheproof_keys() -> Keys {
    let mut keys = Keys {
        private: HashMap::new(),
        public: HashMap::new(),
    };
    for row in rows("rsa_keys.tsv") {
        let der = unhex(&row[2]);
        match row[1].as_str() {
            "pkcs8" => {
                let key = PrivateKey::from_pkcs8_der(&der)
                    .unwrap_or_else(|error| panic!("key {}: {error}", row[0]));
                keys.private.insert(row[0].clone(), key);
            }
            "pkcs1pub" => {
                let key = PublicKey::from_pkcs1_der(&der)
                    .unwrap_or_else(|error| panic!("key {}: {error}", row[0]));
                keys.public.insert(row[0].clone(), key);
            }
            other => panic!("kind {other}"),
        }
    }
    keys
}

fn go_key(name: &str) -> PrivateKey {
    for row in rows("rsa_go_keys.tsv") {
        if row[0] == name {
            let der = unhex(&row[2]);
            return match row[1].as_str() {
                "pkcs1" => PrivateKey::from_pkcs1_der(&der),
                _ => PrivateKey::from_pkcs8_der(&der),
            }
            .unwrap_or_else(|error| panic!("key {name}: {error}"));
        }
    }
    panic!("no key {name}");
}

/// Go's `wycheproof.ShouldPass`.
fn should_pass(result: &str, flags: &str, flags_should_pass: &[(&str, bool)]) -> bool {
    match result {
        "valid" => true,
        "invalid" => false,
        "acceptable" => flags.split(',').all(|flag| {
            flags_should_pass
                .iter()
                .find(|(name, _)| *name == flag)
                .unwrap_or_else(|| panic!("flag {flag} has no expectation"))
                .1
        }),
        other => panic!("result {other}"),
    }
}

#[test]
fn wycheproof_oaep_decrypt() {
    let keys = wycheproof_keys();
    let flags = [
        ("Constructed", true),
        ("EncryptionWithLabel", true),
        ("SmallIntegerCiphertext", true),
    ];
    let data = rows("rsa_oaep.tsv");
    assert_eq!(data.len(), 383);
    for row in &data {
        let key = &keys.private[&row[0]];
        let opts = OAEPOptions {
            hash: Some(hash_by_name(&row[1])),
            mgf_hash: Some(hash_by_name(&row[2])),
            label: unhex(&row[3]),
        };
        let want_pass = should_pass(&row[6], &row[7], &flags);
        let result = Decrypter::decrypt(key, &unhex(&row[4]), Some(&opts));
        match result {
            Ok(plaintext) => {
                assert!(want_pass, "expected failure: {row:?}");
                assert_eq!(plaintext, unhex(&row[5]), "{row:?}");
            }
            Err(error) => assert!(!want_pass, "expected success: {error}: {row:?}"),
        }
    }
}

#[test]
fn wycheproof_pkcs1_decrypt() {
    let keys = wycheproof_keys();
    let data = rows("rsa_pkcs1_decrypt.tsv");
    assert_eq!(data.len(), 54);
    for row in &data {
        let key = &keys.private[&row[0]];
        let want_pass = should_pass(&row[3], &row[4], &[]);
        match rsa::decrypt_pkcs1v15(key, &unhex(&row[1])) {
            Ok(plaintext) => {
                assert!(want_pass, "unexpected success: {row:?}");
                assert_eq!(plaintext, unhex(&row[2]));
            }
            Err(error) => assert!(!want_pass, "{error}: {row:?}"),
        }
    }
}

#[test]
fn wycheproof_pkcs1_signatures() {
    let keys = wycheproof_keys();
    let flags = [("MissingNull", false)];
    let data = rows("rsa_pkcs1_sig.tsv");
    assert_eq!(data.len(), 533);
    for row in &data {
        let key = &keys.public[&row[0]];
        let hash = hash_by_name(&row[1]);
        let hashed = digest(hash, &unhex(&row[2]));
        let result = rsa::verify_pkcs1v15(key, Some(hash), &hashed, &unhex(&row[3]));
        let want = should_pass(&row[4], &row[5], &flags);
        assert_eq!(result.is_ok(), want, "{result:?}: {row:?}");
    }
}

#[test]
fn wycheproof_pss_signatures() {
    let keys = wycheproof_keys();
    let data = rows("rsa_pss.tsv");
    assert_eq!(data.len(), 118);
    for row in &data {
        let key = &keys.public[&row[0]];
        let hash = hash_by_name(&row[1]);
        let hashed = digest(hash, &unhex(&row[3]));
        let salt_len: i64 = row[2].parse().unwrap();
        for salt in [PSS_SALT_LENGTH_AUTO, salt_len] {
            let opts = PSSOptions {
                salt_length: salt,
                hash: Some(hash),
            };
            let mut want = should_pass(&row[5], &row[6], &[]);
            // With an automatic salt length the zero-salt cases pass.
            if salt == 0 && row[7] == "1" {
                want = true;
            }
            let result = rsa::verify_pss(key, hash, &hashed, &unhex(&row[4]), Some(&opts));
            assert_eq!(result.is_ok(), want, "salt {salt}: {result:?}: {row:?}");
        }
    }
}

#[test]
fn pss_golden() {
    // PKCS #1 v2.1 test vectors, SHA-1, salt as long as the hash.
    let data = rows("rsa_pss_golden.tsv");
    assert_eq!(data.len(), 60);
    let opts = PSSOptions {
        salt_length: PSS_SALT_LENGTH_EQUALS_HASH,
        hash: None,
    };
    for row in &data {
        let key = PublicKey {
            n: Int::from_hex(&row[0]).unwrap(),
            e: i64::from_str_radix(&row[1], 16).unwrap(),
        };
        let hashed = digest(Hash::Sha1, &unhex(&row[2]));
        rsa::verify_pss(&key, Hash::Sha1, &hashed, &unhex(&row[3]), Some(&opts))
            .unwrap_or_else(|error| panic!("{error}: {row:?}"));
    }
}

#[test]
fn oaep_known_answers() {
    for row in &rows("rsa_oaep_kat.tsv") {
        let n = Int::from_hex(&row[0]).unwrap();
        let e: i64 = row[1].parse().unwrap();
        let (msg, seed, ct) = (unhex(&row[3]), unhex(&row[4]), unhex(&row[5]));
        let public = PublicKey { n: n.clone(), e };
        // OAEP honours the reader, so the seed gives the known ciphertext.
        let mut seed = Cursor::new(seed);
        let out = rsa::encrypt_oaep_with_rng(&mut seed, Hash::Sha1, &public, &msg, b"").unwrap();
        assert_eq!(out, ct, "{row:?}");

        let private = PrivateKey {
            public_key: PublicKey { n, e },
            d: Int::from_hex(&row[2]).unwrap(),
            ..PrivateKey::default()
        };
        let plain = rsa::decrypt_oaep(Hash::Sha1, &private, &ct, b"").unwrap();
        assert_eq!(plain, msg);
    }
}

#[test]
fn oaep_round_trips_with_labels_and_mgf_hashes() {
    let key = go_key("test2048");
    for (index, msg) in [&b""[..], b"x", b"hello, OAEP", &[7u8; 100]]
        .iter()
        .enumerate()
    {
        let label = format!("hi#{index}");
        let enc = rsa::encrypt_oaep(Hash::Sha256, &key.public_key, msg, label.as_bytes()).unwrap();
        let dec = rsa::decrypt_oaep(Hash::Sha256, &key, &enc, label.as_bytes()).unwrap();
        assert_eq!(&dec, msg);
        assert_eq!(
            rsa::decrypt_oaep(Hash::Sha256, &key, &enc, b"other"),
            Err(Error::Decryption)
        );

        let opts = OAEPOptions {
            hash: Some(Hash::Sha256),
            mgf_hash: Some(Hash::Sha1),
            label: label.clone().into_bytes(),
        };
        let enc = rsa::encrypt_oaep_with_options(&key.public_key, msg, &opts).unwrap();
        let dec = key.decrypt(&enc, Some(&opts)).unwrap();
        assert_eq!(&dec, msg);
        // The same ciphertext does not open with the default MGF hash.
        let plain_opts = OAEPOptions {
            mgf_hash: None,
            ..opts.clone()
        };
        assert!(key.decrypt(&enc, Some(&plain_opts)).is_err());
    }
    // SHA-3 and MD5 work when they also serve as the MGF1 hash.
    for hash in [Hash::Sha3_256, Hash::Sha512_256] {
        let enc = rsa::encrypt_oaep(hash, &key.public_key, b"msg", b"").unwrap();
        assert_eq!(rsa::decrypt_oaep(hash, &key, &enc, b"").unwrap(), b"msg");
    }
    let mixed = OAEPOptions {
        hash: Some(Hash::Sha3_256),
        mgf_hash: Some(Hash::Sha1),
        label: vec![],
    };
    assert!(rsa::encrypt_oaep_with_options(&key.public_key, b"m", &mixed).is_err());
}

#[test]
fn oaep_rejects_bad_inputs() {
    let key = go_key("test2048");
    // A message that is too long.
    let limit = key.size() - 2 * 32 - 2;
    assert!(rsa::encrypt_oaep(Hash::Sha256, &key.public_key, &vec![1; limit], b"").is_ok());
    assert_eq!(
        rsa::encrypt_oaep(Hash::Sha256, &key.public_key, &vec![1; limit + 1], b""),
        Err(Error::MessageTooLong)
    );
    // An unavailable hash.
    let opts = OAEPOptions {
        hash: Some(Hash::Md4),
        ..OAEPOptions::default()
    };
    assert_eq!(
        key.decrypt(b"", Some(&opts)).unwrap_err().to_string(),
        "rsa: requested hash function unavailable: MD4"
    );
    // Wrong options type.
    let wrong: u32 = 1;
    assert_eq!(
        key.decrypt(b"", Some(&wrong)).unwrap_err().to_string(),
        "crypto/rsa: invalid options for Decrypt"
    );
}

/// The sizes Go's `testEverything` exercises.
fn everything(priv_key: &PrivateKey) {
    let mut private = priv_key.clone();
    let validate = private.validate();
    if private.primes.len() >= 2 {
        validate.as_ref().expect("Validate");
    }

    let msg = b"test";
    let enc = rsa::encrypt_pkcs1v15(&private.public_key, msg).unwrap();
    assert_eq!(rsa::decrypt_pkcs1v15(&private, &enc).unwrap(), msg);
    let mut key = [0u8; 4];
    rsa::decrypt_pkcs1v15_session_key(&private, &enc, &mut key).unwrap();
    assert_eq!(&key, msg);

    let label = b"label";
    let enc = rsa::encrypt_oaep(Hash::Sha256, &private.public_key, msg, label).unwrap();
    assert_eq!(
        rsa::decrypt_oaep(Hash::Sha256, &private, &enc, label).unwrap(),
        msg
    );

    let hash_msg = "crypto/rsa: input must be hashed message";
    assert_eq!(
        rsa::sign_pkcs1v15(&private, Some(Hash::Sha256), msg)
            .unwrap_err()
            .to_string(),
        hash_msg
    );

    let mut hashed = sha256::sum256(msg);
    let mut sig = rsa::sign_pkcs1v15(&private, Some(Hash::Sha256), &hashed).unwrap();
    rsa::verify_pkcs1v15(&private.public_key, Some(Hash::Sha256), &hashed, &sig).unwrap();
    sig[1] ^= 0x80;
    assert!(rsa::verify_pkcs1v15(&private.public_key, Some(Hash::Sha256), &hashed, &sig).is_err());
    sig[1] ^= 0x80;
    hashed[1] ^= 0x80;
    assert!(rsa::verify_pkcs1v15(&private.public_key, Some(Hash::Sha256), &hashed, &sig).is_err());
    hashed[1] ^= 0x80;

    for salt_length in [PSS_SALT_LENGTH_AUTO, PSS_SALT_LENGTH_EQUALS_HASH] {
        let opts = PSSOptions {
            salt_length,
            hash: None,
        };
        let mut sig = rsa::sign_pss(&private, Hash::Sha256, &hashed, Some(&opts)).unwrap();
        rsa::verify_pss(
            &private.public_key,
            Hash::Sha256,
            &hashed,
            &sig,
            Some(&opts),
        )
        .unwrap();
        sig[1] ^= 0x80;
        assert!(rsa::verify_pss(
            &private.public_key,
            Hash::Sha256,
            &hashed,
            &sig,
            Some(&opts)
        )
        .is_err());
        sig[1] ^= 0x80;
        hashed[1] ^= 0x80;
        assert!(rsa::verify_pss(
            &private.public_key,
            Hash::Sha256,
            &hashed,
            &sig,
            Some(&opts)
        )
        .is_err());
        hashed[1] ^= 0x80;
    }

    // Inputs bigger than the modulus.
    let opts = PSSOptions {
        salt_length: PSS_SALT_LENGTH_EQUALS_HASH,
        hash: None,
    };
    let mut c = vec![0xff; private.size()];
    assert!(rsa::verify_pss(&private.public_key, Hash::Sha256, &hashed, &c, Some(&opts)).is_err());
    assert!(rsa::decrypt_pkcs1v15(&private, &c).is_err());
    c.push(0xff);
    assert!(rsa::verify_pss(&private.public_key, Hash::Sha256, &hashed, &c, Some(&opts)).is_err());
    assert!(rsa::decrypt_pkcs1v15(&private, &c).is_err());

    if validate.is_ok() {
        let der = private.to_pkcs8_der().unwrap();
        assert!(PrivateKey::from_pkcs8_der(&der).unwrap().equal(&private));
        let der = private.to_pkcs1_der().unwrap();
        assert!(PrivateKey::from_pkcs1_der(&der).unwrap().equal(&private));
    }
    let der = private.public_key.to_pkix_der().unwrap();
    assert!(PublicKey::from_pkix_der(&der)
        .unwrap()
        .equal(&private.public_key));
    let der = private.public_key.to_pkcs1_der().unwrap();
    assert!(PublicKey::from_pkcs1_der(&der)
        .unwrap()
        .equal(&private.public_key));
}

#[test]
fn everything_with_go_keys() {
    for name in [
        "test1024", "test2048", "test3072", "test4096", "large1", "large2",
    ] {
        // k1 and k2 are named k1/k2 in the fixture.
        let name = match name {
            "large1" => "k1",
            "large2" => "k2",
            other => other,
        };
        everything(&go_key(name));
    }
}

#[test]
fn key_generation() {
    for bits in [1024usize, 2048] {
        let key = rsa::generate_key(bits).unwrap();
        assert_eq!(key.n.bit_len(), bits);
        assert_eq!(key.e, 65537);
        assert_eq!(key.primes.len(), 2);
        assert!(key.precomputed.dp.is_some() && key.precomputed.qinv.is_some());
        let mut copy = key.clone();
        copy.validate().unwrap();
        let msg = b"hi!";
        let enc = rsa::encrypt_pkcs1v15(&key.public_key, msg).unwrap();
        assert_eq!(rsa::decrypt_pkcs1v15(&key, &enc).unwrap(), msg);
    }
    for bits in [0usize, 64, 512, 1023] {
        let error = rsa::generate_key(bits).unwrap_err().to_string();
        assert_eq!(
            error,
            format!("crypto/rsa: {bits}-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)")
        );
    }
    assert_eq!(
        rsa::generate_multi_prime_key(1, 1024)
            .unwrap_err()
            .to_string(),
        "crypto/rsa: GenerateMultiPrimeKey: nprimes must be >= 2"
    );
    assert!(rsa::generate_multi_prime_key(3, 1024).is_err());
    assert_eq!(
        rsa::generate_multi_prime_key(2, 1024).unwrap().n.bit_len(),
        1024
    );
}

#[test]
fn not_precomputed_keys() {
    let full = go_key("test2048");
    let only_d = PrivateKey {
        public_key: full.public_key.clone(),
        d: full.d.clone(),
        ..PrivateKey::default()
    };
    everything(&only_d);
    let mut k = only_d.clone();
    k.precompute();
    everything(&k);

    let without = PrivateKey {
        public_key: full.public_key.clone(),
        d: full.d.clone(),
        primes: full.primes.clone(),
        ..PrivateKey::default()
    };
    everything(&without);
    let mut k = without.clone();
    k.precompute();
    assert!(
        k.precomputed.dp.is_some() && k.precomputed.dq.is_some() && k.precomputed.qinv.is_some()
    );
    everything(&k);
    assert_eq!(k.precomputed.dp, full.precomputed.dp);
    assert_eq!(k.precomputed.qinv, full.precomputed.qinv);
}

#[test]
fn modified_keys_are_rejected() {
    let good = go_key("test2048");
    let two = Int::from_u64(2);
    let plus = |a: &Int, b: &Int| {
        let mut out = a.to_be_bytes();
        let mut carry = b.to_u64().unwrap();
        for byte in out.iter_mut().rev() {
            let sum = u64::from(*byte) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
        }
        Int::from_be_bytes(&out)
    };
    type Modify<'a> = Box<dyn Fn(&mut PrivateKey) + 'a>;
    let cases: Vec<(&str, Modify<'_>)> = vec![
        ("D+2", Box::new(|k| k.d = plus(&k.d, &two))),
        ("D=0", Box::new(|k| k.d = Int::zero())),
        (
            "N+2",
            Box::new(|k| k.public_key.n = plus(&k.public_key.n, &two)),
        ),
        ("N=0", Box::new(|k| k.public_key.n = Int::zero())),
        ("P+2", Box::new(|k| k.primes[0] = plus(&k.primes[0], &two))),
        ("P=0", Box::new(|k| k.primes[0] = Int::zero())),
        ("Q+2", Box::new(|k| k.primes[1] = plus(&k.primes[1], &two))),
        ("Q=0", Box::new(|k| k.primes[1] = Int::zero())),
        ("E+2", Box::new(|k| k.public_key.e += 2)),
        ("E=0", Box::new(|k| k.public_key.e = 0)),
    ];
    for (name, modify) in cases {
        let mut key = good.clone();
        key.precomputed = Default::default();
        modify(&mut key);
        assert!(key.validate().is_err(), "{name}: Validate should fail");
        key.precompute();
        assert!(
            key.validate().is_err(),
            "{name}: Validate after Precompute should fail"
        );
    }
    // Precomputed values copied from another key do not match.
    let other = go_key("test1024");
    let mut key = good.clone();
    key.precomputed = other.precomputed.clone();
    assert!(key.validate().is_err());
}

#[test]
fn equal() {
    let a = go_key("test1024");
    let b = go_key("test2048");
    assert!(a.equal(&a.clone()));
    assert!(!a.equal(&b));
    assert!(a.public_key.equal(&a.public_key.clone()));
    assert!(!a.public_key.equal(&b.public_key));
    assert!(!a.equal(&a.public_key));
    let mut other = a.clone();
    other.primes.swap(0, 1);
    assert!(!a.equal(&other));
    let mut other = a.public_key.clone();
    other.e += 2;
    assert!(!a.public_key.equal(&other));
}

#[test]
fn signer_and_decrypter_interfaces() {
    let key = go_key("test2048");
    let msg = b"message to sign";
    let hashed = sha256::sum256(msg);

    // PKCS #1 v1.5 through Signer, with a Hash as the options.
    let signer: &dyn Signer = &key;
    let sig = signer.sign(&hashed, &Hash::Sha256).unwrap();
    rsa::verify_pkcs1v15(&key.public_key, Some(Hash::Sha256), &hashed, &sig).unwrap();
    assert!(signer.public().downcast_ref::<PublicKey>().is_some());

    // PSS through the PSSOptions.
    let opts = PSSOptions {
        salt_length: PSS_SALT_LENGTH_EQUALS_HASH,
        hash: Some(Hash::Sha256),
    };
    let sig = signer.sign(&hashed, &opts).unwrap();
    rsa::verify_pss(&key.public_key, Hash::Sha256, &hashed, &sig, Some(&opts)).unwrap();

    // SignMessage hashes with the options' hash.
    let sig = sign_message(signer, msg, &Hash::Sha256).unwrap();
    rsa::verify_pkcs1v15(&key.public_key, Some(Hash::Sha256), &hashed, &sig).unwrap();

    // Decrypter: no options is PKCS #1 v1.5, then OAEP and session keys.
    let decrypter: &dyn Decrypter = &key;
    let enc = rsa::encrypt_pkcs1v15(&key.public_key, b"secret").unwrap();
    assert_eq!(decrypter.decrypt(&enc, None).unwrap(), b"secret");
    let session = PKCS1v15DecryptOptions { session_key_len: 6 };
    assert_eq!(decrypter.decrypt(&enc, Some(&session)).unwrap(), b"secret");
    let session = PKCS1v15DecryptOptions { session_key_len: 4 };
    let random_key = decrypter.decrypt(&enc, Some(&session)).unwrap();
    assert_eq!(random_key.len(), 4);
    assert_eq!(
        decrypter
            .decrypt(&enc, Some(&PKCS1v15DecryptOptions::default()))
            .unwrap(),
        b"secret"
    );
}

#[test]
fn pkcs1v15_edge_cases() {
    let key = go_key("test1024");
    // A message too long for the key.
    let k = key.size();
    assert!(rsa::encrypt_pkcs1v15(&key.public_key, &vec![1; k - 11]).is_ok());
    assert_eq!(
        rsa::encrypt_pkcs1v15(&key.public_key, &vec![1; k - 10]),
        Err(Error::MessageTooLong)
    );
    // Session key left alone on a short plaintext.
    let ciphertext = rsa::encrypt_pkcs1v15(&key.public_key, &[1]).unwrap();
    let mut session = [0u8; 32];
    rsa::decrypt_pkcs1v15_session_key(&key, &ciphertext, &mut session).unwrap();
    assert_eq!(session, [0u8; 32]);
    // Unpadded signatures sign the data as given.
    let msg = b"Thu Dec 19 18:06:16 EST 2013\n";
    let sig = rsa::sign_pkcs1v15(&key, None, msg).unwrap();
    rsa::verify_pkcs1v15(&key.public_key, None, msg, &sig).unwrap();
    assert!(rsa::verify_pkcs1v15(&key.public_key, None, b"other", &sig).is_err());
    // A truncated signature is rejected.
    assert_eq!(
        rsa::verify_pkcs1v15(&key.public_key, None, msg, &sig[1..]),
        Err(Error::Verification)
    );
    // The error values print like Go's.
    assert_eq!(
        Error::Decryption.to_string(),
        "crypto/rsa: decryption error"
    );
    assert_eq!(
        Error::Verification.to_string(),
        "crypto/rsa: verification error"
    );
    assert_eq!(
        Error::MessageTooLong.to_string(),
        "crypto/rsa: message too long for RSA key size"
    );
}

#[test]
fn pss_salt_lengths() {
    let key = go_key("test2048");
    let hashed = sha256::sum256(b"pss");
    for salt in [1, 16, 32, 100, 222] {
        let opts = PSSOptions {
            salt_length: salt,
            hash: None,
        };
        let sig = rsa::sign_pss(&key, Hash::Sha256, &hashed, Some(&opts)).unwrap();
        rsa::verify_pss(&key.public_key, Hash::Sha256, &hashed, &sig, Some(&opts)).unwrap();
        // Auto-detects the salt.
        rsa::verify_pss(&key.public_key, Hash::Sha256, &hashed, &sig, None).unwrap();
        if salt != 32 {
            let equals = PSSOptions {
                salt_length: PSS_SALT_LENGTH_EQUALS_HASH,
                hash: None,
            };
            assert!(
                rsa::verify_pss(&key.public_key, Hash::Sha256, &hashed, &sig, Some(&equals))
                    .is_err()
            );
        }
    }
    let too_long = PSSOptions {
        salt_length: 223,
        hash: None,
    };
    assert!(rsa::sign_pss(&key, Hash::Sha256, &hashed, Some(&too_long)).is_err());
    let negative = PSSOptions {
        salt_length: -2,
        hash: None,
    };
    assert_eq!(
        rsa::sign_pss(&key, Hash::Sha256, &hashed, Some(&negative))
            .unwrap_err()
            .to_string(),
        "crypto/rsa: invalid PSS salt length"
    );
    // opts.Hash overrides the hash argument.
    let opts = PSSOptions {
        salt_length: PSS_SALT_LENGTH_AUTO,
        hash: Some(Hash::Sha512),
    };
    let digest512 = digest(Hash::Sha512, b"pss");
    let sig = rsa::sign_pss(&key, Hash::Sha256, &digest512, Some(&opts)).unwrap();
    rsa::verify_pss(&key.public_key, Hash::Sha512, &digest512, &sig, None).unwrap();
}

#[test]
fn small_key_rejection() {
    // 512-bit keys are rejected unless GODEBUG=rsa1024min=0.
    let key = PublicKey {
        n: Int::from_be_bytes(&[0xc1; 64]),
        e: 65537,
    };
    let error = rsa::encrypt_pkcs1v15(&key, b"x").unwrap_err().to_string();
    assert_eq!(
        error,
        "crypto/rsa: 512-bit keys are insecure (see https://go.dev/pkg/crypto/rsa#hdr-Minimum_key_size)"
    );
    let missing = PublicKey::default();
    assert_eq!(
        rsa::encrypt_pkcs1v15(&missing, b"x")
            .unwrap_err()
            .to_string(),
        "crypto/rsa: missing public modulus"
    );
}

/// Go rejects a signature whose length is not the modulus size, even when it
/// is the right signature with its leading zero byte dropped (the `rsa` crate
/// alone would left-pad it and accept it).
#[test]
fn signatures_must_be_exactly_the_modulus_size() {
    let private = go_key("test2048");
    let public = &private.public_key;
    let mut found = false;
    for i in 0u32..4096 {
        let hashed = sha256::sum256(&i.to_be_bytes());
        let sig = rsa::sign_pkcs1v15(&private, Some(Hash::Sha256), &hashed).unwrap();
        assert!(rsa::verify_pkcs1v15(public, Some(Hash::Sha256), &hashed, &sig).is_ok());
        if sig[0] != 0 {
            continue;
        }
        found = true;
        let short = &sig[1..];
        assert!(matches!(
            rsa::verify_pkcs1v15(public, Some(Hash::Sha256), &hashed, short),
            Err(Error::Verification)
        ));
        break;
    }
    assert!(found, "no signature with a leading zero byte in 4096 tries");
    let hashed = sha256::sum256(b"pss");
    let sig = rsa::sign_pss(&private, Hash::Sha256, &hashed, None).unwrap();
    let mut padded = vec![0u8];
    padded.extend_from_slice(&sig);
    assert!(matches!(
        rsa::verify_pss(public, Hash::Sha256, &hashed, &padded, None),
        Err(Error::Verification)
    ));
}
