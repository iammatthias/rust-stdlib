//! crypto/ecdh, ported from Go's ecdh_test.go and ecdh_wycheproof_test.go.

mod common;

use common::{rows, unhex};
use rust_stdlib_crypto::ecdh::{self, Curve, PrivateKey, PublicKey};

fn all_curves() -> Vec<&'static dyn Curve> {
    vec![ecdh::p256(), ecdh::p384(), ecdh::p521(), ecdh::x25519()]
}

#[test]
fn ecdh_agreement() {
    for curve in all_curves() {
        let alice = curve.generate_key().unwrap();
        let bob = curve.generate_key().unwrap();
        let alice_pub = curve
            .public_key_from_bytes(&alice.public_key().bytes())
            .unwrap();
        assert_eq!(alice.public_key().bytes(), alice_pub.bytes());
        assert!(alice.public_key().equal(&alice_pub));
        let alice_priv = curve.private_key_from_bytes(&alice.bytes()).unwrap();
        assert_eq!(alice.bytes(), alice_priv.bytes());
        assert!(alice.equal(&alice_priv));
        assert!(alice_priv.public_key().equal(&alice_pub));
        assert!(alice.public().downcast_ref::<PublicKey>().is_some());
        let a = alice.ecdh(bob.public_key()).unwrap();
        let b = bob.ecdh(alice.public_key()).unwrap();
        assert_eq!(a, b, "{curve}");
        let c = bob.ecdh(&alice_pub).unwrap();
        assert_eq!(a, c);
        assert!(!alice.equal(&bob));
        assert!(!alice.public_key().equal(bob.public_key()));
        assert!(!alice.public_key().equal(&5u8));
    }
}

#[test]
fn generate_key_sizes() {
    for (curve, private, public) in [
        (ecdh::p256(), 32, 65),
        (ecdh::p384(), 48, 97),
        (ecdh::p521(), 66, 133),
        (ecdh::x25519(), 32, 32),
    ] {
        let key = curve.generate_key().unwrap();
        assert_eq!(key.bytes().len(), private, "{curve}");
        assert_eq!(key.public_key().bytes().len(), public, "{curve}");
        assert_eq!(key.curve().name(), curve.name());
    }
}

#[test]
fn vectors() {
    // NIST CAVS 14.1 ECC CDH Primitive, P-521 leading zeros removed, and
    // RFC 7748 section 6.1.
    let vectors = [
        (
            ecdh::p256(),
            "7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
            "04ead218590119e8876b29146ff89ca61770c4edbbf97d38ce385ed281d8a6b23028af61281fd35e2fa7002523acc85a429cb06ee6648325389f59edfce1405141",
            "04700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
            "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
        ),
        (
            ecdh::p384(),
            "3cc3122a68f0d95027ad38c067916ba0eb8c38894d22e1b15618b6818a661774ad463b205da88cf699ab4d43c9cf98a1",
            "049803807f2f6d2fd966cdd0290bd410c0190352fbec7ff6247de1302df86f25d34fe4a97bef60cff548355c015dbb3e5fba26ca69ec2f5b5d9dad20cc9da711383a9dbe34ea3fa5a2af75b46502629ad54dd8b7d73a8abb06a3a3be47d650cc99",
            "04a7c76b970c3b5fe8b05d2838ae04ab47697b9eaf52e764592efda27fe7513272734466b400091adbf2d68c58e0c50066ac68f19f2e1cb879aed43a9969b91a0839c4c38a49749b661efedf243451915ed0905a32b060992b468c64766fc8437a",
            "5f9d29dc5e31a163060356213669c8ce132e22f57c9a04f40ba7fcead493b457e5621e766c40a2e3d4d6a04b25e533f1",
        ),
        (
            ecdh::p521(),
            "017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47",
            "0400602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a501b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d",
            "0400685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676",
            "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831",
        ),
        (
            ecdh::x25519(),
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        ),
    ];
    for (curve, private, public, peer, shared) in vectors {
        let key = curve.private_key_from_bytes(&unhex(private)).unwrap();
        assert_eq!(key.public_key().bytes(), unhex(public), "{curve}");
        let peer = curve.public_key_from_bytes(&unhex(peer)).unwrap();
        assert_eq!(key.ecdh(&peer).unwrap(), unhex(shared), "{curve}");
    }
}

#[test]
fn strings() {
    for curve in all_curves() {
        let text = curve.to_string();
        assert!(text.starts_with('P') || text.starts_with('X'), "{text}");
    }
    assert_eq!(ecdh::p521().to_string(), "P-521");
}

#[test]
fn x25519_failure() {
    let identity = unhex("0000000000000000000000000000000000000000000000000000000000000000");
    let low_order = unhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
    let mut scalar = [0u8; 32];
    rust_stdlib_crypto::rand::read(&mut scalar);
    for public in [identity, low_order] {
        let private = ecdh::x25519().private_key_from_bytes(&scalar).unwrap();
        let public = ecdh::x25519().public_key_from_bytes(&public).unwrap();
        let error = private.ecdh(&public).unwrap_err();
        assert_eq!(
            error.to_string(),
            "crypto/ecdh: bad X25519 remote ECDH input: low order point"
        );
    }
}

#[test]
fn private_key_from_bytes_rejects_invalid() {
    let sizes = [("P-256", 32usize), ("P-384", 48), ("P-521", 66)];
    let orders = [
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    ];
    let curves = [ecdh::p256(), ecdh::p384(), ecdh::p521()];
    for (((curve, (_, size)), order), _) in curves.iter().zip(sizes).zip(orders).zip(0..) {
        let mut bad: Vec<Vec<u8>> = vec![
            vec![],
            vec![1],
            vec![1; size - 1],
            vec![1; size + 1],
            vec![1; 200],
            vec![0; size],
            unhex(order),
        ];
        let mut above = unhex(order);
        *above.last_mut().unwrap() += 1;
        bad.push(above);
        bad.push(vec![0xff; size]);
        for key in bad {
            assert!(
                curve.private_key_from_bytes(&key).is_err(),
                "{curve}: accepted {key:02x?}"
            );
        }
    }
    for key in [vec![], vec![1], vec![1; 31], vec![1; 33], vec![1; 200]] {
        assert!(ecdh::x25519().private_key_from_bytes(&key).is_err());
    }
    // X25519 accepts any 32 bytes.
    assert!(ecdh::x25519().private_key_from_bytes(&[0; 32]).is_ok());
}

#[test]
fn public_key_from_bytes_rejects_invalid() {
    let invalid: [(&dyn Curve, &[&str]); 3] = [
        (
            ecdh::p256(),
            &[
                "",
                "04",
                "00",
                "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "02e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852",
                "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f6",
                "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "04ffffffff00000001000000000000000000000001000000000000000000000004ba6dbc4555a7e7fa016ec431667e8521ee35afc49b265c3accbea3f7cdb70433",
            ],
        ),
        (
            ecdh::p384(),
            &[
                "",
                "04",
                "00",
                "03aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
                "04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e60",
                "04fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff000000000000000100000001732152442fb6ee5c3e6ce1d920c059bc623563814d79042b903ce60f1d4487fccd450a86da03f3e6ed525d02017bfdb3",
            ],
        ),
        (
            ecdh::p521(),
            &[
                "",
                "04",
                "00",
                "030035b5df64ae2ac204c354b483487c9070cdc61c891c5ff39afc06c5d55541d3ceac8659e24afe3d0750e8b88e9f078af066a1d5025b08e5a5e2fbc87412871902f3",
                "0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16651",
                "0402000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100d9254fdf800496acb33790b103c5ee9fac12832fe546c632225b0f7fce3da4574b1a879b623d722fa8fc34d5fc2a8731aad691a9a8bb8b554c95a051d6aa505acf",
            ],
        ),
    ];
    for (curve, inputs) in invalid {
        for input in inputs {
            assert!(
                curve.public_key_from_bytes(&unhex(input)).is_err(),
                "{curve}: accepted {input}"
            );
        }
        assert!(curve.public_key_from_bytes(&[4; 200]).is_err());
    }
    for key in [vec![], vec![1], vec![1; 31], vec![1; 33]] {
        assert!(ecdh::x25519().public_key_from_bytes(&key).is_err());
    }
}

#[test]
fn mismatched_curves() {
    let a = ecdh::p256().generate_key().unwrap();
    let b = ecdh::p384().generate_key().unwrap();
    assert_eq!(
        a.ecdh(b.public_key()).unwrap_err().to_string(),
        "crypto/ecdh: private key and public key curves do not match"
    );
}

fn curve_of(name: &str) -> &'static dyn Curve {
    match name {
        "secp256r1" => ecdh::p256(),
        "secp384r1" => ecdh::p384(),
        "secp521r1" => ecdh::p521(),
        "curve25519" => ecdh::x25519(),
        other => panic!("curve {other}"),
    }
}

fn key_size(name: &str) -> usize {
    match name {
        "secp256r1" | "curve25519" => 32,
        "secp384r1" => 48,
        "secp521r1" => 66,
        other => panic!("curve {other}"),
    }
}

#[test]
fn wycheproof() {
    // Wycheproof flags Go does not support or accepts: see
    // ecdh_wycheproof_test.go.
    let acceptable = |kind: &str, flag: &str| -> Option<bool> {
        match (kind, flag) {
            ("ecpoint" | "asn", "CompressedPoint" | "CompressedPublic") => Some(false),
            (
                "asn",
                "UnnamedCurve"
                | "WrongOrder"
                | "UnusedParam"
                | "ModifiedGenerator"
                | "ModifiedCofactor"
                | "ModifiedCurveParameter"
                | "NoCofactor"
                | "Modified curve parameter"
                | "InvalidAsn",
            ) => Some(false),
            (
                "x25519",
                "Twist"
                | "NonCanonicalPublic"
                | "SpecialPublicKey"
                | "EdgeCaseMultiplication"
                | "EdgeCaseShared"
                | "Ktv",
            ) => Some(true),
            ("x25519", "SmallPublicKey" | "LowOrderPublic" | "ZeroSharedSecret") => Some(false),
            _ => None,
        }
    };
    let data = rows("ecdh_wycheproof.tsv");
    assert_eq!(data.len(), 995);
    let mut checked = 0;
    for row in &data {
        let (kind, curve_name) = (row[0].as_str(), row[1].as_str());
        let (public, private, shared) = (unhex(&row[2]), unhex(&row[3]), unhex(&row[4]));
        let (result, flags) = (row[5].as_str(), row[6].split(',').collect::<Vec<_>>());
        let curve = curve_of(curve_name);
        let should_pass = match result {
            "valid" => true,
            "invalid" => false,
            "acceptable" => flags
                .iter()
                .all(|flag| acceptable(kind, flag).unwrap_or_else(|| panic!("flag {flag}"))),
            other => panic!("result {other}"),
        };
        let parsed = match kind {
            "asn" => PublicKey::from_pkix_der(&public).and_then(|key| {
                if key.curve().name() == curve.name() {
                    Ok(key)
                } else {
                    Err(ecdh::p256().public_key_from_bytes(&[]).unwrap_err())
                }
            }),
            _ => curve.public_key_from_bytes(&public),
        };
        let Ok(public) = parsed else {
            assert!(!should_pass, "parse of {} failed: {row:?}", row[2]);
            continue;
        };
        let private: Result<PrivateKey, _> = curve.private_key_from_bytes(&private);
        let Ok(private) = private else {
            assert!(
                !(should_pass && unhex(&row[3]).len() == key_size(curve_name)),
                "private key rejected: {row:?}"
            );
            continue;
        };
        match private.ecdh(&public) {
            Err(error) => assert!(!should_pass, "ECDH failed: {error}: {row:?}"),
            Ok(x) => {
                if should_pass {
                    assert_eq!(x, shared, "{row:?}");
                } else if result == "invalid" {
                    assert_ne!(x, shared, "invalid vector produced the expected secret");
                }
            }
        }
        checked += 1;
    }
    assert!(checked > 300, "only {checked} vectors reached ECDH");
}

#[test]
fn der_round_trip() {
    for curve in all_curves() {
        let key = curve.generate_key().unwrap();
        let pkix = key.public_key().to_pkix_der().unwrap();
        let parsed = PublicKey::from_pkix_der(&pkix).unwrap();
        assert!(parsed.equal(key.public_key()), "{curve}");
        let pkcs8 = key.to_pkcs8_der().unwrap();
        let parsed = PrivateKey::from_pkcs8_der(&pkcs8).unwrap();
        assert!(parsed.equal(&key), "{curve}");
    }
    assert!(PublicKey::from_pkix_der(&[0x30, 0x00]).is_err());
}
