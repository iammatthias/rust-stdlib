//! crypto/dsa, ported from Go's dsa_test.go and dsa_wycheproof_test.go.

mod common;

use common::{rows, unhex};
use rust_stdlib_crypto::bigint::Int;
use rust_stdlib_crypto::dsa::{self, Parameters, PrivateKey, PublicKey};
use rust_stdlib_crypto::Hash;

fn hex(text: &str) -> Int {
    Int::from_hex(text).unwrap()
}

fn go_private_key() -> PrivateKey {
    PrivateKey {
        public_key: PublicKey {
            parameters: Parameters {
                p: hex("A9B5B793FB4785793D246BAE77E8FF63CA52F442DA763C440259919FE1BC1D6065A9350637A04F75A2F039401D49F08E066C4D275A5A65DA5684BC563C14289D7AB8A67163BFBF79D85972619AD2CFF55AB0EE77A9002B0EF96293BDD0F42685EBB2C66C327079F6C98000FBCB79AACDE1BC6F9D5C7B1A97E3D9D54ED7951FEF"),
                q: hex("E1D3391245933D68A0714ED34BBCB7A1F422B9C1"),
                g: hex("634364FC25248933D01D1993ECABD0657CC0CB2CEED7ED2E3E8AECDFCDC4A25C3B15E9E3B163ACA2984B5539181F3EFF1A5E8903D71D5B95DA4F27202B77D2C44B430BB53741A8D59A8F86887525C9F2A6A5980A195EAA7F2FF910064301DEF89D3AA213E1FAC7768D89365318E370AF54A112EFBA9246D9158386BA1B4EEFDA"),
            },
            y: hex("32969E5780CFE1C849A1C276D7AEB4F38A23B591739AA2FE197349AEEBD31366AEE5EB7E6C6DDB7C57D02432B30DB5AA66D9884299FAA72568944E4EEDC92EA3FBC6F39F53412FBCC563208F7C15B737AC8910DBC2D9C9B8C001E72FDC40EB694AB1F06A5A2DBD18D9E36C66F31F566742F11EC0A52E9F7B89355C02FB5D32D2"),
        },
        x: hex("5078D4D29795CBE76D3AACFE48C9AF0BCDBEE91A"),
    }
}

#[test]
fn sign_and_verify() {
    let private = go_private_key();
    let hashed = b"testing";
    let (r, s) = dsa::sign(&private, hashed).unwrap();
    assert!(dsa::verify(&private.public_key, hashed, &r, &s));
    assert!(!dsa::verify(&private.public_key, b"testinG", &r, &s));
    let (r2, _) = dsa::sign(&private, hashed).unwrap();
    assert_ne!(r, r2, "signatures use a fresh nonce");
}

#[test]
fn bad_public_key_does_not_verify() {
    let mut public = go_private_key().public_key;
    public.parameters.q = hex("FA");
    assert!(!dsa::verify(&public, b"testing", &hex("2"), &hex("4")));
}

#[test]
fn degenerate_keys_do_not_sign() {
    for (p, q, g, y, x) in [
        ("00", "01", "00", "00", "00"),
        ("01", "ff", "00", "00", "00"),
    ] {
        let private = PrivateKey {
            public_key: PublicKey {
                parameters: Parameters {
                    p: hex(p),
                    q: hex(q),
                    g: hex(g),
                },
                y: hex(y),
            },
            x: hex(x),
        };
        assert!(dsa::sign(&private, b"testing").is_err());
        assert!(!dsa::verify(
            &private.public_key,
            b"testing",
            &hex("1"),
            &hex("1")
        ));
    }
}

#[test]
fn parameter_and_key_generation() {
    for (sizes, l, n) in [
        (dsa::L1024N160, 1024, 160),
        (dsa::L2048N224, 2048, 224),
        (dsa::L2048N256, 2048, 256),
    ] {
        let mut params = Parameters::default();
        dsa::generate_parameters(&mut params, sizes).unwrap();
        assert_eq!(params.p.bit_len(), l);
        assert_eq!(params.q.bit_len(), n);
        let mut private = PrivateKey {
            public_key: PublicKey {
                parameters: params,
                y: Int::zero(),
            },
            x: Int::zero(),
        };
        dsa::generate_key(&mut private).unwrap();
        let hashed = [0x5au8; 20];
        let (r, s) = dsa::sign(&private, &hashed).unwrap();
        assert!(dsa::verify(&private.public_key, &hashed, &r, &s));
        // The key survives PKIX encoding.
        let der = private.public_key.to_pkix_der().unwrap();
        assert_eq!(PublicKey::from_pkix_der(&der).unwrap(), private.public_key);
    }
    let mut empty = PrivateKey::default();
    assert_eq!(
        dsa::generate_key(&mut empty).unwrap_err().to_string(),
        "crypto/dsa: parameters not set up before generating key"
    );
}

/// A strict DER `SEQUENCE { INTEGER, INTEGER }` reader (Go's cryptobyte rules:
/// minimal lengths, positive minimal integers, nothing after the sequence).
fn parse_signature(der: &[u8]) -> Option<(Int, Int)> {
    fn length(data: &[u8]) -> Option<(usize, usize)> {
        let first = *data.first()?;
        if first < 0x80 {
            return Some((first as usize, 1));
        }
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 3 || data.len() < 1 + n || data[1] == 0 {
            return None;
        }
        let len = data[1..1 + n]
            .iter()
            .fold(0usize, |acc, &b| acc << 8 | b as usize);
        (len >= 0x80).then_some((len, 1 + n))
    }
    fn integer(data: &[u8]) -> Option<(Int, usize)> {
        if *data.first()? != 2 {
            return None;
        }
        let (len, used) = length(&data[1..])?;
        let body = data.get(1 + used..1 + used + len)?;
        if body.is_empty() || body[0] & 0x80 != 0 {
            return None;
        }
        if body.len() > 1 && body[0] == 0 && body[1] & 0x80 == 0 {
            return None;
        }
        Some((Int::from_be_bytes(body), 1 + used + len))
    }
    if *der.first()? != 0x30 {
        return None;
    }
    let (len, used) = length(&der[1..])?;
    if der.len() != 1 + used + len {
        return None;
    }
    let inner = &der[1 + used..];
    let (r, n) = integer(inner)?;
    let (s, m) = integer(&inner[n..])?;
    (n + m == inner.len()).then_some((r, s))
}

#[test]
fn wycheproof() {
    let data = rows("dsa_wycheproof.tsv");
    assert_eq!(data.len(), 204);
    let hash_of = |name: &str| match name {
        "SHA-224" => Hash::Sha224,
        "SHA-256" => Hash::Sha256,
        other => panic!("hash {other}"),
    };
    for row in &data {
        let public = PublicKey::from_pkix_der(&unhex(&row[0])).expect("group key");
        let hash = hash_of(&row[1]);
        let mut h = hash.new().unwrap();
        std::io::Write::write_all(&mut h, &unhex(&row[2])).unwrap();
        let mut hashed = Vec::new();
        h.sum(&mut hashed);
        // Truncate to the byte length of the subgroup (Q).
        hashed.truncate(public.parameters.q.bit_len() / 8);
        let got = parse_signature(&unhex(&row[3]))
            .is_some_and(|(r, s)| dsa::verify(&public, &hashed, &r, &s));
        let want = match row[4].as_str() {
            "valid" => true,
            "invalid" => false,
            "acceptable" => row[5].split(',').all(|flag| match flag {
                "MissingZero" => false,
                other => panic!("flag {other}"),
            }),
            other => panic!("result {other}"),
        };
        assert_eq!(got, want, "{row:?}");
    }
}
