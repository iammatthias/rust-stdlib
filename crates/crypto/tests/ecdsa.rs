//! crypto/ecdsa, ported from Go's ecdsa_test.go, equal_test.go and
//! ecdsa_wycheproof_test.go.

mod common;

use std::sync::Arc;

use common::{rows, unhex};
use rust_stdlib_crypto::bigint::Int;
use rust_stdlib_crypto::ecdsa::{self, PrivateKey, PublicKey};
use rust_stdlib_crypto::elliptic::{self, Curve};
use rust_stdlib_crypto::{sha256, Hash, Signer};

fn all_curves() -> Vec<(&'static str, Arc<dyn Curve>)> {
    vec![
        ("P-224", elliptic::p224()),
        ("P-256", elliptic::p256()),
        ("P-384", elliptic::p384()),
        ("P-521", elliptic::p521()),
    ]
}

fn byte_len(curve: &dyn Curve) -> usize {
    curve.params().bit_size.div_ceil(8)
}

/// `a + b` for big-endian magnitudes.
fn add(a: &Int, b: &Int) -> Int {
    let (a, b) = (a.as_be_bytes(), b.as_be_bytes());
    let len = a.len().max(b.len()) + 1;
    let mut out = vec![0u8; len];
    let mut carry = 0u16;
    for i in 0..len {
        let x = if i < a.len() {
            a[a.len() - 1 - i] as u16
        } else {
            0
        };
        let y = if i < b.len() {
            b[b.len() - 1 - i] as u16
        } else {
            0
        };
        let sum = x + y + carry;
        out[len - 1 - i] = sum as u8;
        carry = sum >> 8;
    }
    Int::from_be_bytes(&out)
}

/// `a - b` for `a >= b`.
fn sub(a: &Int, b: &Int) -> Int {
    assert!(a >= b);
    let (a, b) = (a.as_be_bytes(), b.as_be_bytes());
    let mut out = vec![0u8; a.len()];
    let mut borrow = 0i16;
    for i in 0..a.len() {
        let x = a[a.len() - 1 - i] as i16;
        let y = if i < b.len() {
            b[b.len() - 1 - i] as i16
        } else {
            0
        };
        let mut diff = x - y - borrow;
        borrow = 0;
        if diff < 0 {
            diff += 256;
            borrow = 1;
        }
        out[a.len() - 1 - i] = diff as u8;
    }
    Int::from_be_bytes(&out)
}

#[test]
fn key_generation_and_signing() {
    for (name, curve) in all_curves() {
        let key = ecdsa::generate_key(curve.clone()).unwrap();
        assert!(
            curve.is_on_curve(&key.public_key.x, &key.public_key.y),
            "{name}"
        );

        let mut hashed = b"testing".to_vec();
        let (r, s) = ecdsa::sign(&key, &hashed).unwrap();
        assert!(ecdsa::verify(&key.public_key, &hashed, &r, &s), "{name}");
        let sig = ecdsa::sign_asn1(&key, &hashed).unwrap();
        assert!(ecdsa::verify_asn1(&key.public_key, &hashed, &sig), "{name}");
        hashed[0] ^= 0xff;
        assert!(!ecdsa::verify(&key.public_key, &hashed, &r, &s), "{name}");
        assert!(
            !ecdsa::verify_asn1(&key.public_key, &hashed, &sig),
            "{name}"
        );
    }
}

#[test]
fn empty_hash_is_rejected() {
    for (name, curve) in all_curves() {
        let key = ecdsa::generate_key(curve).unwrap();
        let hash: &[u8] = b"";
        let error = ecdsa::sign_asn1(&key, hash).unwrap_err().to_string();
        assert!(error.contains("cannot be empty"), "{name}: {error}");
        let error = key.sign(hash, None).unwrap_err().to_string();
        assert!(error.contains("nil random"), "{name}: {error}");
        let error = key
            .sign_with_rng(&mut std::io::empty(), hash, None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot be empty"), "{name}: {error}");
        let sig = ecdsa::sign_asn1(&key, b"test hash").unwrap();
        assert!(!ecdsa::verify_asn1(&key.public_key, b"", &sig), "{name}");
    }
}

#[test]
fn sign_hash_length() {
    for (name, curve) in all_curves() {
        let key = ecdsa::generate_key(curve).unwrap();
        let digest = sha256::sum256(b"message");
        let mut rand = rust_stdlib_crypto::rand::Reader;
        // opts == nil skips the length check.
        key.sign_with_rng(&mut rand, &digest, None).unwrap();
        key.sign_with_rng(&mut rand, &digest, Some(&Hash::Sha256))
            .unwrap();
        for (digest, hash) in [
            (&digest[..], Hash::Sha384),
            (&digest[..31], Hash::Sha256),
            (&digest[..0], Hash::Sha256),
        ] {
            assert!(
                key.sign_with_rng(&mut rand, digest, Some(&hash)).is_err(),
                "{name}: {hash}"
            );
        }
        let error = key
            .sign_with_rng(&mut rand, &digest, Some(&Hash::Md4))
            .unwrap_err();
        assert!(
            error.to_string().contains("hash length does not match"),
            "{error}"
        );
        // Signing through the Signer interface.
        let signer: &dyn Signer = &key;
        let sig = signer
            .sign_with_rng(&mut rand, &digest, &Hash::Sha256)
            .unwrap();
        assert!(ecdsa::verify_asn1(&key.public_key, &digest, &sig));
        assert!(signer.public().downcast_ref::<PublicKey>().is_some());
    }
}

#[test]
fn zero_and_out_of_range_signatures() {
    for (name, curve) in all_curves() {
        let key = ecdsa::generate_key(curve.clone()).unwrap();
        let zero_hash = [0u8; 64];
        let (r, s) = ecdsa::sign(&key, &zero_hash).unwrap();
        assert!(ecdsa::verify(&key.public_key, &zero_hash, &r, &s), "{name}");
        assert!(
            !ecdsa::verify(&key.public_key, &zero_hash, &Int::zero(), &Int::zero()),
            "{name}"
        );
        let n = &curve.params().n;
        assert!(
            !ecdsa::verify(&key.public_key, &zero_hash, &add(&r, n), &s),
            "{name}: r+n"
        );
        assert!(
            !ecdsa::verify(&key.public_key, &zero_hash, &r, &add(&s, n)),
            "{name}: s+n"
        );
        let huge = Int::from_be_bytes(&[1; 100]);
        assert!(
            !ecdsa::verify(&key.public_key, &zero_hash, &huge, &huge),
            "{name}"
        );
        // r - n is negative in Go and cannot be represented here.
        assert!(
            !ecdsa::verify(&key.public_key, &zero_hash, n, &s),
            "{name}: r=n"
        );
        let r_minus = sub(n, &Int::from_u64(1));
        let _ = r_minus;
    }
}

#[test]
fn rfc6979() {
    struct Vector(
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
    );
    let vectors: Vec<(Arc<dyn Curve>, Vector)> = vec![
        (elliptic::p224(), Vector(
            "F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
            "00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C",
            "EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A",
            "sample",
            "61AA3DA010E8E8406C656BC477A7A7189895E7E840CDFE8FF42307BA",
            "BC814050DAB5D23770879494F9E0A680DC1AF7161991BDE692B10101")),
        (elliptic::p224(), Vector(
            "F220266E1105BFE3083E03EC7A3A654651F45E37167E88600BF257C1",
            "00CF08DA5AD719E42707FA431292DEA11244D64FC51610D94B130D6C",
            "EEAB6F3DEBE455E3DBF85416F7030CBD94F34F2D6F232C69F3C1385A",
            "test",
            "AD04DDE87B84747A243A631EA47A1BA6D1FAA059149AD2440DE6FBA6",
            "178D49B1AE90E3D8B629BE3DB5683915F4E8C99FDF6E666CF37ADCFD")),
        // Bruteforced to make the generation of k loop, checked against OpenSSL.
        (elliptic::p256(), Vector(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
            "wv[vnX",
            "EFD9073B652E76DA1B5A019C0E4A2E3FA529B035A6ABB91EF67F0ED7A1F21234",
            "3DB4706C9D9F4A4FE13BB5E08EF0FAB53A57DBAB2061C83A35FA411C68D2BA33")),
        (elliptic::p256(), Vector(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
            "sample",
            "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
            "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")),
        (elliptic::p256(), Vector(
            "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
            "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
            "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
            "test",
            "F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
            "019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083")),
        (elliptic::p384(), Vector(
            "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
            "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
            "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
            "sample",
            "21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
            "F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0")),
        (elliptic::p384(), Vector(
            "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
            "EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
            "8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
            "test",
            "6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B",
            "2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265")),
        (elliptic::p521(), Vector(
            "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
            "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
            "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
            "sample",
            "1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
            "04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC")),
        (elliptic::p521(), Vector(
            "0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
            "1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
            "0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5",
            "test",
            "00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8",
            "0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86")),
    ];
    for (curve, Vector(d, x, y, msg, r, s)) in vectors {
        let hex = |text: &str| Int::from_hex(text).unwrap();
        let key = PrivateKey {
            public_key: PublicKey {
                curve,
                x: hex(x),
                y: hex(y),
            },
            d: hex(d),
        };
        let digest = sha256::sum256(msg.as_bytes());
        let sig = key.sign(&digest, Some(&Hash::Sha256)).unwrap();
        let (r, s) = (hex(r), hex(s));
        let (got_r, got_s) = parse_der(&sig);
        assert_eq!((got_r, got_s), (r.clone(), s.clone()), "{msg}");
        assert!(ecdsa::verify(&key.public_key, &digest, &r, &s));
    }
}

/// A minimal DER reader for `SEQUENCE { INTEGER, INTEGER }`, enough to check
/// signatures independently of the encoder under test.
fn parse_der(sig: &[u8]) -> (Int, Int) {
    assert_eq!(sig[0], 0x30);
    let (len, mut at) = if sig[1] & 0x80 == 0 {
        (sig[1] as usize, 2)
    } else {
        let n = (sig[1] & 0x7f) as usize;
        let mut len = 0usize;
        for byte in &sig[2..2 + n] {
            len = len << 8 | *byte as usize;
        }
        (len, 2 + n)
    };
    assert_eq!(at + len, sig.len());
    let mut ints = Vec::new();
    for _ in 0..2 {
        assert_eq!(sig[at], 0x02);
        let l = sig[at + 1] as usize;
        assert!(l < 128);
        ints.push(Int::from_be_bytes(&sig[at + 2..at + 2 + l]));
        at += 2 + l;
    }
    (ints.remove(0), ints.remove(0))
}

#[test]
fn parse_and_bytes_round_trip() {
    for (name, curve) in all_curves() {
        let key = ecdsa::generate_key(curve.clone()).unwrap();
        let b = key.public_key.bytes().unwrap();
        assert_eq!(b[0], 4);
        let parsed = ecdsa::parse_uncompressed_public_key(curve.clone(), &b).unwrap();
        assert!(key.public_key.equal(&parsed), "{name}");
        let bk = key.bytes().unwrap();
        assert_eq!(bk.len(), byte_len(curve.as_ref()));
        let k = ecdsa::parse_raw_private_key(curve.clone(), &bk).unwrap();
        assert!(key.equal(&k), "{name}");
        if name != "P-224" {
            let ecdh = key.ecdh().unwrap();
            let pp = ecdh.curve().public_key_from_bytes(&b).unwrap();
            assert!(ecdh.public_key().equal(&pp));
            assert_eq!(b, pp.bytes());
            let kk = ecdh.curve().private_key_from_bytes(&bk).unwrap();
            assert!(ecdh.equal(&kk));
            assert_eq!(bk, kk.bytes());
            assert!(key.public_key.ecdh().unwrap().equal(ecdh.public_key()));
        } else {
            assert_eq!(
                key.ecdh().unwrap_err().to_string(),
                "ecdsa: unsupported curve by crypto/ecdh"
            );
        }
    }
}

#[test]
fn invalid_public_keys() {
    for (name, curve) in all_curves() {
        let infinity = PublicKey {
            curve: curve.clone(),
            x: Int::zero(),
            y: Int::zero(),
        };
        assert!(infinity.bytes().is_err(), "{name}");
        assert!(ecdsa::parse_uncompressed_public_key(curve.clone(), &[0]).is_err());
        let mut zeros = vec![0u8; 1 + 2 * byte_len(curve.as_ref())];
        zeros[0] = 4;
        assert!(ecdsa::parse_uncompressed_public_key(curve.clone(), &zeros).is_err());

        let mut key = ecdsa::generate_key(curve.clone()).unwrap().public_key;
        key.x = add(&key.x, &Int::from_u64(1));
        assert!(key.bytes().is_err(), "{name}");
        let b = [
            vec![4u8],
            key.x.fill_bytes(byte_len(curve.as_ref())).unwrap(),
            key.y.fill_bytes(byte_len(curve.as_ref())).unwrap(),
        ]
        .concat();
        assert!(ecdsa::parse_uncompressed_public_key(curve.clone(), &b).is_err());

        let good = ecdsa::generate_key(curve.clone()).unwrap().public_key;
        let compressed = elliptic::marshal_compressed(curve.as_ref(), &good.x, &good.y);
        assert!(ecdsa::parse_uncompressed_public_key(curve.clone(), &compressed).is_err());
    }
}

#[test]
fn invalid_private_keys() {
    for (name, curve) in all_curves() {
        let zero = PrivateKey {
            public_key: PublicKey {
                curve: curve.clone(),
                x: Int::zero(),
                y: Int::zero(),
            },
            d: Int::zero(),
        };
        assert!(zero.bytes().is_err(), "{name}");
        let len = byte_len(curve.as_ref());
        assert!(ecdsa::parse_raw_private_key(curve.clone(), &vec![0; len]).is_err());

        let d = add(&curve.params().n, &Int::from_u64(5));
        let (x, y) = curve.scalar_base_mult(d.as_be_bytes());
        let overflow = PrivateKey {
            public_key: PublicKey {
                curve: curve.clone(),
                x,
                y,
            },
            d: d.clone(),
        };
        assert!(overflow.bytes().is_err(), "{name}");
        let padded = d.fill_bytes(len);
        if let Some(padded) = padded {
            assert!(ecdsa::parse_raw_private_key(curve.clone(), &padded).is_err());
        }
        assert!(ecdsa::parse_raw_private_key(curve.clone(), &[1, 2, 3]).is_err());
        let mut long = vec![0; len];
        long.extend_from_slice(&[1, 2, 3]);
        assert!(ecdsa::parse_raw_private_key(curve.clone(), &long).is_err());
    }
}

#[test]
fn equal() {
    let curve = elliptic::p256();
    let a = ecdsa::generate_key(curve.clone()).unwrap();
    let b = ecdsa::generate_key(curve.clone()).unwrap();
    assert!(a.equal(&a.clone()));
    assert!(a.public_key.equal(&a.public_key.clone()));
    assert!(!a.equal(&b));
    assert!(!a.public_key.equal(&b.public_key));
    assert!(!a.equal(&a.public_key));
    // Same coordinates, different curve object.
    let other = PublicKey {
        curve: elliptic::p384(),
        x: a.public_key.x.clone(),
        y: a.public_key.y.clone(),
    };
    assert!(!a.public_key.equal(&other));
}

fn curve_by_name(name: &str) -> Arc<dyn Curve> {
    match name {
        "P-224" | "secp224r1" => elliptic::p224(),
        "P-256" | "secp256r1" => elliptic::p256(),
        "P-384" | "secp384r1" => elliptic::p384(),
        "P-521" | "secp521r1" => elliptic::p521(),
        other => panic!("curve {other}"),
    }
}

fn hash_by_name(name: &str) -> Hash {
    match name {
        "SHA-1" => Hash::Sha1,
        "SHA-224" => Hash::Sha224,
        "SHA-256" => Hash::Sha256,
        "SHA-384" => Hash::Sha384,
        "SHA-512" => Hash::Sha512,
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

#[test]
fn nist_sigver_vectors() {
    // NIST CAVS 186-3 SigVer, as in Go's TestVectors.
    let data = rows("ecdsa_sigver.tsv");
    assert_eq!(data.len(), 300);
    for (index, row) in data.iter().enumerate() {
        let curve = curve_by_name(&row[0]);
        let hashed = digest(hash_by_name(&row[1]), &unhex(&row[2]));
        let hex = |text: &str| Int::from_hex(text).unwrap();
        let key = PublicKey {
            curve,
            x: hex(&row[3]),
            y: hex(&row[4]),
        };
        let expected = row[7] == "P";
        assert_eq!(
            ecdsa::verify(&key, &hashed, &hex(&row[5]), &hex(&row[6])),
            expected,
            "vector {index}"
        );
    }
}

#[test]
fn wycheproof() {
    let data = rows("ecdsa_wycheproof.tsv");
    assert_eq!(data.len(), 1064);
    for row in &data {
        let key = PublicKey::from_pkix_der(&unhex(&row[2])).expect("group public key");
        assert_eq!(
            key.curve.params().name.replace('-', ""),
            curve_by_name(&row[0]).params().name.replace('-', "")
        );
        let hashed = digest(hash_by_name(&row[1]), &unhex(&row[3]));
        let got = ecdsa::verify_asn1(&key, &hashed, &unhex(&row[4]));
        let want = match row[5].as_str() {
            "valid" => true,
            "invalid" => false,
            // Go passes no flag map, so acceptable results must not occur.
            other => panic!("unexpected result {other}"),
        };
        assert_eq!(got, want, "{row:?}");
    }
}

#[test]
fn der_round_trips() {
    for (name, curve) in all_curves() {
        let key = ecdsa::generate_key(curve).unwrap();
        let pkix = key.public_key.to_pkix_der().unwrap();
        let parsed = PublicKey::from_pkix_der(&pkix).unwrap();
        assert!(parsed.equal(&key.public_key), "{name}");
        let pkcs8 = key.to_pkcs8_der().unwrap();
        assert!(
            PrivateKey::from_pkcs8_der(&pkcs8).unwrap().equal(&key),
            "{name}"
        );
        let sec1 = key.to_sec1_der().unwrap();
        assert!(
            PrivateKey::from_sec1_der(&sec1).unwrap().equal(&key),
            "{name}"
        );
    }
}
