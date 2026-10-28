//! The reviewed `p224`, `p256`, `p384` and `p521` crates behind one
//! byte-oriented interface shared by `ecdh`, `ecdsa` and `elliptic`.
//!
//! All curve arithmetic, point validation and ECDSA signing/verification
//! happen in the dependencies. This module only converts between Go's byte
//! encodings (fixed-width big-endian scalars, SEC 1 points where the identity
//! is the single byte `00`) and the crates' types.
//!
//! `ecdh`, `elliptic` and `ecdsa` each use part of the backend; `ecdsa`
//! enables the other two, so only a build with it uses all of it.
#![cfg_attr(not(feature = "ecdsa"), allow(dead_code))]

use p256::elliptic_curve::group::Group;
use p256::elliptic_curve::pkcs8::spki::{DecodePublicKey, EncodePublicKey};
use p256::elliptic_curve::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use p256::elliptic_curve::sec1::{FromSec1Point, ToSec1Point};

/// Which NIST curve a backend implements.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Id {
    P224,
    P256,
    P384,
    P521,
}

/// Go's `elliptic.CurveParams` constants for one curve (FIPS 186-4, D.1.2).
pub(crate) struct Constants {
    pub name: &'static str,
    pub bit_size: usize,
    pub p: &'static str,
    pub n: &'static str,
    pub b: &'static str,
    pub gx: &'static str,
    pub gy: &'static str,
}

pub(crate) trait Backend: Send + Sync {
    fn id(&self) -> Id;
    fn constants(&self) -> &'static Constants;
    /// Width of field elements and scalars in bytes.
    fn len(&self) -> usize;
    /// The group order, big-endian, `len()` bytes.
    fn order(&self) -> Vec<u8>;
    /// Whether `d` is a `len()`-byte scalar with `0 < d < n`.
    fn valid_scalar(&self, d: &[u8]) -> bool;
    /// The uncompressed SEC 1 public key of the scalar `d`.
    fn public_from_scalar(&self, d: &[u8]) -> Option<Vec<u8>>;
    /// Parses a SEC 1 point (identity `00`, compressed or uncompressed) and
    /// returns it uncompressed, or `00` for the identity.
    fn point(&self, data: &[u8]) -> Option<Vec<u8>>;
    /// ECDH with a valid private scalar and uncompressed public point; the
    /// shared secret is the x coordinate.
    fn ecdh(&self, d: &[u8], peer: &[u8]) -> Option<Vec<u8>>;
    fn add(&self, a: &[u8], b: &[u8]) -> Option<Vec<u8>>;
    fn double(&self, a: &[u8]) -> Option<Vec<u8>>;
    /// `k * p` for any-length big-endian `k` (reduced modulo the order).
    fn scalar_mult(&self, p: &[u8], k: &[u8]) -> Option<Vec<u8>>;
    fn scalar_base_mult(&self, k: &[u8]) -> Vec<u8>;
    /// Signs `digest` with the scalar `d`; `entropy` is mixed into the
    /// nonce derivation (RFC 6979 section 3.6). Returns `(r, s)`.
    fn sign_hedged(&self, d: &[u8], digest: &[u8], entropy: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
    /// Deterministic ECDSA (RFC 6979) with HMAC over `hash`; `None` if the
    /// scalar is invalid or `hash` is not implemented by this crate.
    fn sign_deterministic(
        &self,
        d: &[u8],
        digest: &[u8],
        hash: crate::Hash,
    ) -> Option<(Vec<u8>, Vec<u8>)>;
    /// Why `data` is not a valid point, with the messages of Go's `nistec`.
    fn point_error(&self, data: &[u8]) -> String;
    /// Verifies `(r, s)`, each `len()` bytes, over `digest`.
    fn verify(&self, public: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool;
    /// ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` of `(r, s)`.
    fn signature_to_der(&self, r: &[u8], s: &[u8]) -> Option<Vec<u8>>;
    /// Parses a DER signature to `(r, s)`, each `len()` bytes.
    fn signature_from_der(&self, der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)>;
    fn private_to_pkcs8(&self, d: &[u8]) -> Option<Vec<u8>>;
    fn private_from_pkcs8(&self, der: &[u8]) -> Option<Vec<u8>>;
    fn private_to_sec1_der(&self, d: &[u8]) -> Option<Vec<u8>>;
    fn private_from_sec1_der(&self, der: &[u8]) -> Option<Vec<u8>>;
    fn public_to_pkix(&self, point: &[u8]) -> Option<Vec<u8>>;
    fn public_from_pkix(&self, der: &[u8]) -> Option<Vec<u8>>;
}

pub(crate) fn backend(id: Id) -> &'static dyn Backend {
    match id {
        Id::P224 => &P224,
        Id::P256 => &P256,
        Id::P384 => &P384,
        Id::P521 => &P521,
    }
}

macro_rules! curve {
    ($ty:ident, $krate:ident, $curve:ident, $id:expr, $len:expr, $digest:ty, $constants:expr) => {
        pub(crate) struct $ty;

        impl $ty {
            fn field_bytes(bytes: &[u8]) -> Option<$krate::FieldBytes> {
                $krate::FieldBytes::try_from(bytes).ok()
            }

            fn nonzero(d: &[u8]) -> Option<$krate::NonZeroScalar> {
                if d.len() != $len {
                    return None;
                }
                let repr = Self::field_bytes(d)?;
                Option::from($krate::NonZeroScalar::from_repr(repr).into_option())
            }

            fn affine(point: &[u8]) -> Option<$krate::AffinePoint> {
                $krate::AffinePoint::from_sec1_bytes(point).ok()
            }

            fn encode(point: $krate::AffinePoint) -> Vec<u8> {
                point.to_sec1_point(false).as_bytes().to_vec()
            }

            /// Go's `normalizeScalar`: the scalar modulo the group order.
            fn reduce(k: &[u8]) -> $krate::Scalar {
                let base = $krate::Scalar::from(256u64);
                let mut acc = $krate::Scalar::ZERO;
                for &byte in k {
                    acc = acc * base + $krate::Scalar::from(u64::from(byte));
                }
                acc
            }
        }

        impl Backend for $ty {
            fn id(&self) -> Id {
                $id
            }

            fn constants(&self) -> &'static Constants {
                &$constants
            }

            fn len(&self) -> usize {
                $len
            }

            fn order(&self) -> Vec<u8> {
                let n = crate::bigint::Int::from_hex($constants.n).expect("order");
                n.fill_bytes($len).expect("order width")
            }

            fn valid_scalar(&self, d: &[u8]) -> bool {
                Self::nonzero(d).is_some()
            }

            fn public_from_scalar(&self, d: &[u8]) -> Option<Vec<u8>> {
                let scalar = Self::nonzero(d)?;
                let public = $krate::PublicKey::from_secret_scalar(&scalar);
                Some(Self::encode(*public.as_affine()))
            }

            fn point(&self, data: &[u8]) -> Option<Vec<u8>> {
                if data == [0] {
                    return Some(vec![0]);
                }
                Self::affine(data).map(Self::encode)
            }

            fn ecdh(&self, d: &[u8], peer: &[u8]) -> Option<Vec<u8>> {
                let scalar = Self::nonzero(d)?;
                let public = $krate::PublicKey::from_sec1_bytes(peer).ok()?;
                let shared = $krate::ecdh::diffie_hellman(&scalar, public.as_affine());
                Some(shared.raw_secret_bytes().to_vec())
            }

            fn add(&self, a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
                let a = self.projective(a)?;
                let b = self.projective(b)?;
                Some(Self::encode((a + b).to_affine()))
            }

            fn double(&self, a: &[u8]) -> Option<Vec<u8>> {
                let a = self.projective(a)?;
                Some(Self::encode(a.double().to_affine()))
            }

            fn scalar_mult(&self, p: &[u8], k: &[u8]) -> Option<Vec<u8>> {
                let p = self.projective(p)?;
                Some(Self::encode((p * Self::reduce(k)).to_affine()))
            }

            fn scalar_base_mult(&self, k: &[u8]) -> Vec<u8> {
                let point = $krate::ProjectivePoint::GENERATOR * Self::reduce(k);
                Self::encode(point.to_affine())
            }

            fn sign_deterministic(
                &self,
                d: &[u8],
                digest: &[u8],
                hash: crate::Hash,
            ) -> Option<(Vec<u8>, Vec<u8>)> {
                let scalar = Self::nonzero(d)?;
                deterministic::<$krate::$curve>(&scalar, digest, hash)
            }

            fn point_error(&self, data: &[u8]) -> String {
                let name = $constants.name.replace('-', "");
                let field = $len;
                let uncompressed = 1 + 2 * field;
                let compressed = 1 + field;
                let well_formed = (data.len() == uncompressed && data[0] == 4)
                    || (data.len() == compressed && (data[0] == 2 || data[0] == 3));
                if !well_formed {
                    return format!("invalid {name} point encoding");
                }
                let p = crate::bigint::Int::from_hex($constants.p).expect("p");
                let over = |bytes: &[u8]| crate::bigint::Int::from_be_bytes(bytes) >= p;
                if data[0] == 4 {
                    if over(&data[1..1 + field]) || over(&data[1 + field..]) {
                        return format!("invalid {name}Element encoding");
                    }
                    return format!("{name} point not on curve");
                }
                if over(&data[1..]) {
                    return format!("invalid {name}Element encoding");
                }
                format!("invalid {name} compressed point encoding")
            }

            fn sign_hedged(
                &self,
                d: &[u8],
                digest: &[u8],
                entropy: &[u8],
            ) -> Option<(Vec<u8>, Vec<u8>)> {
                let scalar = Self::nonzero(d)?;
                let (signature, _) = ::ecdsa::hazmat::sign_prehashed_rfc6979::<
                    $krate::$curve,
                    $digest,
                >(&scalar, digest, entropy);
                let (r, s) = signature.split_bytes();
                Some((r.to_vec(), s.to_vec()))
            }

            fn verify(&self, public: &[u8], digest: &[u8], r: &[u8], s: &[u8]) -> bool {
                let (Some(point), Some(r), Some(s)) = (
                    Self::affine(public),
                    Self::field_bytes(r),
                    Self::field_bytes(s),
                ) else {
                    return false;
                };
                let Ok(signature) = $krate::ecdsa::Signature::from_scalars(r, s) else {
                    return false;
                };
                ::ecdsa::hazmat::verify_prehashed::<$krate::$curve>(
                    &$krate::ProjectivePoint::from(point),
                    digest,
                    &signature,
                )
                .is_ok()
            }

            fn signature_to_der(&self, r: &[u8], s: &[u8]) -> Option<Vec<u8>> {
                let signature = $krate::ecdsa::Signature::from_scalars(
                    Self::field_bytes(r)?,
                    Self::field_bytes(s)?,
                )
                .ok()?;
                Some(signature.to_der().as_bytes().to_vec())
            }

            fn signature_from_der(&self, der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
                let signature = $krate::ecdsa::Signature::from_der(der).ok()?;
                let (r, s) = signature.split_bytes();
                Some((r.to_vec(), s.to_vec()))
            }

            fn private_to_pkcs8(&self, d: &[u8]) -> Option<Vec<u8>> {
                let key = $krate::SecretKey::from_slice(d).ok()?;
                Some(key.to_pkcs8_der().ok()?.as_bytes().to_vec())
            }

            fn private_from_pkcs8(&self, der: &[u8]) -> Option<Vec<u8>> {
                let key = $krate::SecretKey::from_pkcs8_der(der).ok()?;
                Some(key.to_bytes().to_vec())
            }

            fn private_to_sec1_der(&self, d: &[u8]) -> Option<Vec<u8>> {
                let key = $krate::SecretKey::from_slice(d).ok()?;
                Some(key.to_sec1_der().ok()?.to_vec())
            }

            fn private_from_sec1_der(&self, der: &[u8]) -> Option<Vec<u8>> {
                let key = $krate::SecretKey::from_sec1_der(der).ok()?;
                Some(key.to_bytes().to_vec())
            }

            fn public_to_pkix(&self, point: &[u8]) -> Option<Vec<u8>> {
                let key = $krate::PublicKey::from_sec1_bytes(point).ok()?;
                Some(key.to_public_key_der().ok()?.as_bytes().to_vec())
            }

            fn public_from_pkix(&self, der: &[u8]) -> Option<Vec<u8>> {
                let key = $krate::PublicKey::from_public_key_der(der).ok()?;
                Some(Self::encode(*key.as_affine()))
            }
        }

        impl $ty {
            fn projective(&self, point: &[u8]) -> Option<$krate::ProjectivePoint> {
                if point == [0] {
                    return Some($krate::ProjectivePoint::IDENTITY);
                }
                Self::affine(point).map($krate::ProjectivePoint::from)
            }
        }
    };
}

/// RFC 6979 signing with HMAC over `hash`, for the hashes the reviewed
/// RustCrypto digests implement.
fn deterministic<C>(
    d: &p256::elliptic_curve::NonZeroScalar<C>,
    z: &[u8],
    hash: crate::Hash,
) -> Option<(Vec<u8>, Vec<u8>)>
where
    C: ::ecdsa::EcdsaCurve + p256::elliptic_curve::CurveArithmetic,
{
    use crate::Hash;
    fn run<C, D>(d: &p256::elliptic_curve::NonZeroScalar<C>, z: &[u8]) -> (Vec<u8>, Vec<u8>)
    where
        C: ::ecdsa::EcdsaCurve + p256::elliptic_curve::CurveArithmetic,
        D: sha2::digest::Digest + sha2::digest::block_api::BlockSizeUser,
    {
        let (signature, _) = ::ecdsa::hazmat::sign_prehashed_rfc6979::<C, D>(d, z, &[]);
        let (r, s) = signature.split_bytes();
        (r.to_vec(), s.to_vec())
    }
    Some(match hash {
        #[cfg(feature = "md5")]
        Hash::Md5 => run::<C, ::md5::Md5>(d, z),
        #[cfg(feature = "sha1")]
        Hash::Sha1 => run::<C, ::sha1::Sha1>(d, z),
        Hash::Sha224 => run::<C, sha2::Sha224>(d, z),
        Hash::Sha256 => run::<C, sha2::Sha256>(d, z),
        Hash::Sha384 => run::<C, sha2::Sha384>(d, z),
        Hash::Sha512 => run::<C, sha2::Sha512>(d, z),
        Hash::Sha512_224 => run::<C, sha2::Sha512_224>(d, z),
        Hash::Sha512_256 => run::<C, sha2::Sha512_256>(d, z),
        #[cfg(feature = "sha3")]
        Hash::Sha3_224 => run::<C, ::sha3::Sha3_224>(d, z),
        #[cfg(feature = "sha3")]
        Hash::Sha3_256 => run::<C, ::sha3::Sha3_256>(d, z),
        #[cfg(feature = "sha3")]
        Hash::Sha3_384 => run::<C, ::sha3::Sha3_384>(d, z),
        #[cfg(feature = "sha3")]
        Hash::Sha3_512 => run::<C, ::sha3::Sha3_512>(d, z),
        _ => return None,
    })
}

curve!(
    P224,
    p224,
    NistP224,
    Id::P224,
    28,
    sha2::Sha256,
    P224_CONSTANTS
);
curve!(
    P256,
    p256,
    NistP256,
    Id::P256,
    32,
    sha2::Sha256,
    P256_CONSTANTS
);
curve!(
    P384,
    p384,
    NistP384,
    Id::P384,
    48,
    sha2::Sha384,
    P384_CONSTANTS
);
curve!(
    P521,
    p521,
    NistP521,
    Id::P521,
    66,
    sha2::Sha512,
    P521_CONSTANTS
);

static P224_CONSTANTS: Constants = Constants {
    name: "P-224",
    bit_size: 224,
    p: "ffffffffffffffffffffffffffffffff000000000000000000000001",
    n: "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
    b: "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
    gx: "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
    gy: "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
};

static P256_CONSTANTS: Constants = Constants {
    name: "P-256",
    bit_size: 256,
    p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
    n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
    gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
};

static P384_CONSTANTS: Constants = Constants {
    name: "P-384",
    bit_size: 384,
    p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
    n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
    b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
    gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
    gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
};

static P521_CONSTANTS: Constants = Constants {
    name: "P-521",
    bit_size: 521,
    p: "1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    n: "1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
    b: "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
    gx: "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
    gy: "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650",
};
