//! crypto/elliptic, ported from Go's elliptic_test.go, p224_test.go and
//! p256_test.go.
//!
//! Go's tests that need negative `big.Int` values or modular square roots,
//! and the "generic" `CurveParams` implementation, have no counterpart: the
//! arithmetic runs in the reviewed crates (see src/elliptic.rs).

mod common;

use std::sync::Arc;

use common::{rows, unhex};
use rust_stdlib_crypto::bigint::Int;
use rust_stdlib_crypto::elliptic::{self, Curve, CurveParams};

fn all_curves() -> Vec<(&'static str, Arc<dyn Curve>)> {
    let mut curves = vec![
        ("P256", elliptic::p256()),
        ("P224", elliptic::p224()),
        ("P384", elliptic::p384()),
        ("P521", elliptic::p521()),
    ];
    // A copy of the parameters behaves like the curve (Go's "generic" path).
    let copies: Vec<_> = curves
        .iter()
        .map(|(name, curve)| {
            let params: Arc<dyn Curve> = Arc::new(curve.params().clone());
            (*name, params)
        })
        .collect();
    curves.extend(copies);
    curves
}

fn is_infinity(point: (Int, Int)) -> bool {
    point.0.is_zero() && point.1.is_zero()
}

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

#[test]
fn on_curve() {
    for (name, curve) in all_curves() {
        let params = curve.params();
        assert!(
            curve.is_on_curve(&params.gx, &params.gy),
            "{name}: basepoint"
        );
    }
}

#[test]
fn off_curve() {
    for (name, curve) in all_curves() {
        let (x, y) = (Int::from_u64(1), Int::from_u64(1));
        assert!(!curve.is_on_curve(&x, &y), "{name}");
        let len = curve.params().bit_size.div_ceil(8);
        let mut b = vec![4u8];
        b.extend(x.fill_bytes(len).unwrap());
        b.extend(y.fill_bytes(len).unwrap());
        assert!(elliptic::unmarshal(curve.as_ref(), &b).is_none(), "{name}");
    }
}

#[test]
fn infinity() {
    for (name, curve) in all_curves() {
        let params = curve.params();
        let (xg, yg) = (&params.gx, &params.gy);
        let zero = Int::zero();
        let n = params.n.as_be_bytes();
        assert!(is_infinity(curve.scalar_mult(xg, yg, n)), "{name}: x^q");
        assert!(is_infinity(curve.scalar_mult(xg, yg, &[0])), "{name}: x^0");
        assert!(
            is_infinity(curve.scalar_mult(&zero, &zero, &[1, 2, 3])),
            "{name}: inf^k"
        );
        assert!(
            is_infinity(curve.scalar_mult(&zero, &zero, &[0])),
            "{name}: inf^0"
        );
        assert!(is_infinity(curve.scalar_base_mult(n)), "{name}: b^q");
        assert!(is_infinity(curve.scalar_base_mult(&[0])), "{name}: b^0");
        assert!(is_infinity(curve.double(&zero, &zero)), "{name}: 2 inf");

        // N - 1 as big-endian bytes.
        let mut n_minus_one = n.to_vec();
        *n_minus_one.last_mut().unwrap() -= 1;
        let (x, y) = curve.scalar_mult(xg, yg, &n_minus_one);
        assert!(is_infinity(curve.add(&x, &y, xg, yg)), "{name}: x^(q-1)+x");
        assert_eq!(
            curve.add(xg, yg, &zero, &zero),
            (xg.clone(), yg.clone()),
            "{name}"
        );
        assert_eq!(
            curve.add(&zero, &zero, xg, yg),
            (xg.clone(), yg.clone()),
            "{name}"
        );
        assert!(!curve.is_on_curve(&zero, &zero), "{name}: IsOnCurve(inf)");

        assert!(elliptic::unmarshal(
            curve.as_ref(),
            &elliptic::marshal(curve.as_ref(), &zero, &zero)
        )
        .is_none());
        assert!(elliptic::unmarshal(curve.as_ref(), &[0]).is_none());
        let len = params.bit_size.div_ceil(8);
        let mut buf = vec![0u8; len * 2 + 1];
        buf[0] = 4;
        assert!(elliptic::unmarshal(curve.as_ref(), &buf).is_none());
    }
}

#[test]
fn marshal_round_trip() {
    for (name, curve) in all_curves() {
        let mut rand = rust_stdlib_crypto::rand::Reader;
        let (_, x, y) = elliptic::generate_key_with_rng(&mut rand, curve.as_ref()).unwrap();
        let serialized = elliptic::marshal(curve.as_ref(), &x, &y);
        assert_eq!(
            elliptic::unmarshal(curve.as_ref(), &serialized),
            Some((x.clone(), y.clone())),
            "{name}"
        );
        let compressed = elliptic::marshal_compressed(curve.as_ref(), &x, &y);
        assert_eq!(
            elliptic::unmarshal_compressed(curve.as_ref(), &compressed),
            Some((x, y)),
            "{name}"
        );
    }
}

#[test]
fn unmarshal_to_large_coordinates() {
    for (name, curve) in all_curves() {
        // x = P + 5 with the y of (5, y) would be on the curve mod P; only
        // the P-256 point with small y is known without a square root.
        let p = curve.params().p.clone();
        let len = p.bit_len().div_ceil(8);
        let mut invalid = vec![4u8];
        invalid.extend(vec![0u8; 2 * len]);
        let x = add(&p, &Int::from_u64(5));
        // The overflowing x does not fit in `len` bytes for P-224/384/521
        // unless the field is not a whole number of bytes; encode as far as
        // it fits and require rejection either way.
        if let Some(bytes) = x.fill_bytes(len) {
            invalid[1..1 + len].copy_from_slice(&bytes);
        }
        assert!(
            elliptic::unmarshal(curve.as_ref(), &invalid).is_none(),
            "{name}"
        );
    }
    // A P-256 point with a small y; y + p is still 32 bytes but not reduced
    // (Go's TestUnmarshalToLargeCoordinates, issue 20482).
    let curve = elliptic::p256();
    let x = unhex("4698d49c2ac8ffbc304fc571161474b5dfa55e02f7a68475d2296d12ecbfe54a");
    let y_plus_p = unhex("ffffffff31751583e49e0bccd7c1ed8d6cab6ecb29aa4b89b0a88ef61ff1d6aa");
    let data = [vec![4u8], x, y_plus_p].concat();
    assert!(elliptic::unmarshal(curve.as_ref(), &data).is_none());
}

#[test]
fn invalid_coordinates() {
    for (name, curve) in all_curves() {
        let mut rand = rust_stdlib_crypto::rand::Reader;
        let (_, x, y) = elliptic::generate_key_with_rng(&mut rand, curve.as_ref()).unwrap();
        let p = &curve.params().p;
        let huge = Int::from_be_bytes(&[&[0x08][..], &[0; 66]].concat()); // 2^535
        for (label, xx, yy) in [
            ("x+P, y", add(&x, p), y.clone()),
            ("x, y+P", x.clone(), add(&y, p)),
            ("x+2^535, y", add(&x, &huge), y.clone()),
            ("x, y+2^535", x.clone(), add(&y, &huge)),
        ] {
            assert!(!curve.is_on_curve(&xx, &yy), "{name}: {label}");
        }
        assert!(curve.is_on_curve(&x, &y));
    }
}

#[test]
fn marshal_compressed() {
    let curve = elliptic::p256();
    let x =
        Int::from_hex("1e3987d9f9ea9d7dd7155a56a86b2009e1e0ab332f962d10d8beb6406ab1ad79").unwrap();
    for (data, want_odd) in [
        (
            "031e3987d9f9ea9d7dd7155a56a86b2009e1e0ab332f962d10d8beb6406ab1ad79",
            true,
        ),
        (
            "021e3987d9f9ea9d7dd7155a56a86b2009e1e0ab332f962d10d8beb6406ab1ad79",
            false,
        ),
    ] {
        let (gx, gy) = elliptic::unmarshal_compressed(curve.as_ref(), &unhex(data)).unwrap();
        assert_eq!(gx, x);
        assert!(curve.is_on_curve(&gx, &gy));
        assert_eq!(gy.bit(0) == 1, want_odd);
        assert_eq!(
            elliptic::marshal_compressed(curve.as_ref(), &gx, &gy),
            unhex(data)
        );
    }
    // An x with no square root is rejected.
    let invalid = unhex("02fd4bf61763b46581fd9174d623516cf3c81edd40e29ffa2777fb6cb0ae3ce535");
    assert!(elliptic::unmarshal_compressed(curve.as_ref(), &invalid).is_none());
    for bad in [&[][..], &[4][..], &[2][..], &[3, 1, 2][..]] {
        assert!(elliptic::unmarshal_compressed(curve.as_ref(), bad).is_none());
    }
}

#[test]
fn large_is_on_curve() {
    for (name, curve) in all_curves() {
        let mut bytes = vec![0u8; 126];
        bytes[0] = 1; // 2^1000
        let large = Int::from_be_bytes(&bytes);
        assert!(!curve.is_on_curve(&large, &large), "{name}");
    }
}

#[test]
fn p224_base_mult() {
    let data = rows("elliptic_p224_basemult.tsv");
    assert_eq!(data.len(), 52);
    for curve in [
        elliptic::p224(),
        Arc::new(elliptic::p224().params().clone()) as Arc<dyn Curve>,
    ] {
        for row in &data {
            let k = Int::from_hex(&row[0]).unwrap();
            let (x, y) = curve.scalar_base_mult(k.as_be_bytes());
            assert_eq!(
                (x.to_hex(), y.to_hex()),
                (row[1].clone(), row[2].clone()),
                "k={}",
                row[0]
            );
        }
    }
}

#[test]
fn p256_base_mult_and_mult() {
    let curve = elliptic::p256();
    // 2^500 and the P-224 table scalars agree between P-256 and its params.
    let params_curve: Arc<dyn Curve> = Arc::new(curve.params().clone());
    let mut scalars: Vec<Vec<u8>> = rows("elliptic_p224_basemult.tsv")
        .iter()
        .map(|row| Int::from_hex(&row[0]).unwrap().to_be_bytes())
        .collect();
    let mut k = vec![0u8; 63];
    k[0] = 1;
    scalars.push(k);
    for k in scalars {
        assert_eq!(
            curve.scalar_base_mult(&k),
            params_curve.scalar_base_mult(&k)
        );
    }

    let tests = [
        (
            "2a265f8bcbdcaf94d58519141e578124cb40d64a501fba9c11847b28965bc737",
            "023819813ac969847059028ea88a1f30dfbcde03fc791d3a252c6b41211882ea",
            "f93e4ae433cc12cf2a43fc0ef26400c0e125508224cdb649380f25479148a4ad",
            "4d4de80f1534850d261075997e3049321a0864082d24a917863366c0724f5ae3",
            "a22d2b7f7818a3563e0f7a76c9bf0921ac55e06e2e4d11795b233824b1db8cc0",
        ),
        (
            "313f72ff9fe811bf573176231b286a3bdb6f1b14e05c40146590727a71c3bccd",
            "cc11887b2d66cbae8f4d306627192522932146b42f01d3c6f92bd5c8ba739b06",
            "a2f08a029cd06b46183085bae9248b0ed15b70280c7ef13a457f5af382426031",
            "831c3f6b5f762d2f461901577af41354ac5f228c2591f84f8a6e51e2e3f17991",
            "93f90934cd0ef2c698cc471c60a93524e87ab31ca2412252337f364513e43684",
        ),
    ];
    for (k, x_in, y_in, x_out, y_out) in tests {
        let hex = |text: &str| Int::from_hex(text).unwrap();
        let k = hex(k);
        let (x, y) = curve.scalar_mult(&hex(x_in), &hex(y_in), k.as_be_bytes());
        assert_eq!((x, y), (hex(x_out), hex(y_out)));
    }
}

#[test]
fn issue_52075_long_scalar() {
    let curve = elliptic::p256();
    let params = curve.params();
    let mut scalar = vec![0u8; 33];
    scalar[32] = 1;
    assert_eq!(
        curve.scalar_base_mult(&scalar),
        (params.gx.clone(), params.gy.clone())
    );
    assert_eq!(
        curve.scalar_mult(&params.gx, &params.gy, &scalar),
        (params.gx.clone(), params.gy.clone())
    );
}

#[test]
fn p224_overflow() {
    let curve = elliptic::p224();
    let data = unhex("049B535B45FB0A2072398A6831834624C7E32CCFD5A4B933BCEAF77F1DD945E08BBE5178F5EDF5E733388F196D2A631D2E075BB16CBFEEA15B");
    let (x, y) = elliptic::unmarshal(curve.as_ref(), &data).expect("valid point");
    assert!(curve.is_on_curve(&x, &y));
}

#[test]
fn params_match_standards() {
    for (name, bits, p_len, n_len) in [
        ("P-224", 224, 224, 224),
        ("P-256", 256, 256, 256),
        ("P-384", 384, 384, 384),
        ("P-521", 521, 521, 521),
    ] {
        let curve = match name {
            "P-224" => elliptic::p224(),
            "P-256" => elliptic::p256(),
            "P-384" => elliptic::p384(),
            _ => elliptic::p521(),
        };
        let params = curve.params();
        assert_eq!(params.name, name);
        assert_eq!(params.bit_size, bits);
        assert_eq!(params.p.bit_len(), p_len);
        assert_eq!(params.n.bit_len(), n_len);
        // The base point has order n.
        assert!(is_infinity(curve.scalar_base_mult(params.n.as_be_bytes())));
        assert_eq!(
            curve.scalar_base_mult(&[1]),
            (params.gx.clone(), params.gy.clone())
        );
    }
}

#[test]
fn generate_key_matches_marshal() {
    for (name, curve) in all_curves() {
        let mut rand = rust_stdlib_crypto::rand::Reader;
        let (private, x, y) = elliptic::generate_key_with_rng(&mut rand, curve.as_ref()).unwrap();
        assert_eq!(curve.scalar_base_mult(&private), (x, y), "{name}");
        assert_eq!(private.len(), curve.params().n.bit_len().div_ceil(8));
    }
}

#[test]
#[should_panic(expected = "custom CurveParams is not supported")]
fn custom_curves_panic() {
    let p256 = elliptic::p256();
    let mut params = p256.params().clone();
    params.b = Int::from_u64(7);
    params.scalar_base_mult(&[1]);
}

#[test]
#[should_panic(expected = "Add was called on an invalid point")]
fn add_rejects_invalid_points() {
    let curve = elliptic::p256();
    let one = Int::from_u64(1);
    curve.add(&one, &one, &one, &one);
}

#[test]
#[should_panic(expected = "attempted operation on invalid point")]
fn marshal_rejects_invalid_points() {
    let curve = elliptic::p256();
    let one = Int::from_u64(1);
    elliptic::marshal(curve.as_ref(), &one, &one);
}

#[test]
fn custom_params_can_be_inspected() {
    let params = CurveParams::custom(
        Int::from_u64(23),
        Int::from_u64(29),
        Int::from_u64(1),
        Int::from_u64(3),
        Int::from_u64(10),
        5,
        "toy",
    );
    assert_eq!(params.name, "toy");
    assert!(!elliptic::same_curve(&elliptic::p256(), &elliptic::p384()));
    assert!(elliptic::same_curve(&elliptic::p256(), &elliptic::p256()));
}
