//! The Elliptic Curve Digital Signature Algorithm, compatible with Go's
//! `crypto/ecdsa`.
//!
//! P-224, P-256, P-384 and P-521 signing and verification run in the reviewed
//! `p224`, `p256`, `p384`, `p521` and `ecdsa` crates (see `crate::nistec`).
//! Randomized signatures are the "hedged" RFC 6979 variant with fresh
//! entropy from [`crate::rand`]; signing without a reader is deterministic
//! RFC 6979 with the hash named by the options, as in Go. Like Go 1.26 and
//! later (without `GODEBUG=cryptocustomrand=1`) the random reader arguments
//! are ignored.
//!
//! Go's fallback for custom curves implements ECDSA on arbitrary
//! `elliptic.CurveParams` with `math/big`. That would be a first-party
//! signature implementation (docs/adr/0003), so keys on custom curves can be
//! held but not used: the operations return an error.

use std::any::Any;
use std::fmt;
use std::io;
use std::ops::Deref;
use std::sync::Arc;

use crate::bigint::Int;
use crate::elliptic::{self, Curve};
use crate::nistec::{self, Backend};
use crate::sysrng::Source;
use crate::{BoxError, PublicKey as AnyPublicKey, Signer, SignerOpts};

/// An error with one of Go's `crypto/ecdsa` messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error(String);

impl Error {
    fn new(message: impl Into<String>) -> Error {
        Error(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Go's `ecdsa.PublicKey`: an ECDSA public key.
#[derive(Clone)]
pub struct PublicKey {
    /// Go's embedded `elliptic.Curve`.
    pub curve: Arc<dyn Curve>,
    /// The x coordinate.
    pub x: Int,
    /// The y coordinate.
    pub y: Int,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("curve", &self.curve.params().name)
            .field("x", &self.x)
            .field("y", &self.y)
            .finish()
    }
}

/// Go's `ecdsa.PrivateKey`: an ECDSA private key.
#[derive(Clone)]
pub struct PrivateKey {
    /// Go's embedded `PublicKey`.
    pub public_key: PublicKey,
    /// The private scalar.
    pub d: Int,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl Deref for PrivateKey {
    type Target = PublicKey;

    /// Go promotes the fields and methods of the embedded `PublicKey`.
    fn deref(&self) -> &PublicKey {
        &self.public_key
    }
}

fn unsupported_curve(operation: &str) -> Error {
    Error::new(format!("ecdsa: curve not supported by {operation}"))
}

fn custom_curve() -> Error {
    Error::new("ecdsa: custom curves are not supported (docs/adr/0003)")
}

fn backend_of(curve: &dyn Curve) -> Option<&'static dyn Backend> {
    curve.nist().map(nistec::backend)
}

fn big_int_equal(a: &Int, b: &Int) -> bool {
    crate::subtle::constant_time_compare(a.as_be_bytes(), b.as_be_bytes()) == 1
}

/// Go's `pointFromAffine`: the uncompressed encoding of `(x, y)`.
fn point_from_affine(curve: &dyn Curve, x: &Int, y: &Int) -> Result<Vec<u8>, Error> {
    let bit_size = curve.params().bit_size;
    if x.bit_len() > bit_size || y.bit_len() > bit_size {
        return Err(Error::new("overflowing coordinate"));
    }
    let len = bit_size.div_ceil(8);
    let mut out = vec![4u8];
    out.extend(x.fill_bytes(len).expect("fits"));
    out.extend(y.fill_bytes(len).expect("fits"));
    Ok(out)
}

/// Go's `ecdsa.NewPublicKey` check: the encoding is a valid point.
fn check_point(backend: &dyn Backend, q: &[u8]) -> Result<(), Error> {
    if q.is_empty() || q[0] == 0 {
        return Err(Error::new("ecdsa: invalid public key encoding"));
    }
    match backend.point(q) {
        Some(_) => Ok(()),
        None => Err(Error::new(backend.point_error(q))),
    }
}

/// Go's `publicKeyToFIPS`: the backend and the validated encoding.
fn public_point(
    key: &PublicKey,
    operation: &str,
) -> Result<(&'static dyn Backend, Vec<u8>), Error> {
    let backend = backend_of(key.curve.as_ref()).ok_or_else(|| {
        if operation.is_empty() {
            custom_curve()
        } else {
            unsupported_curve(operation)
        }
    })?;
    let q = point_from_affine(key.curve.as_ref(), &key.x, &key.y)?;
    check_point(backend, &q)?;
    Ok((backend, q))
}

/// Go's `privateKeyToFIPS`: the backend and the scalar, validated like Go.
fn private_scalar(
    key: &PrivateKey,
    operation: &str,
) -> Result<(&'static dyn Backend, Vec<u8>), Error> {
    let public = &key.public_key;
    let backend = backend_of(public.curve.as_ref()).ok_or_else(|| {
        if operation.is_empty() {
            custom_curve()
        } else {
            unsupported_curve(operation)
        }
    })?;
    let q = point_from_affine(public.curve.as_ref(), &public.x, &public.y)?;
    let n = &public.curve.params().n;
    if key.d.bit_len() > n.bit_len() {
        return Err(Error::new("ecdsa: private key scalar too large"));
    }
    if key.d.is_zero() {
        return Err(Error::new("ecdsa: private key scalar is zero or negative"));
    }
    let d = key
        .d
        .fill_bytes(n.bit_len().div_ceil(8))
        .expect("checked above");
    check_point(backend, &q)?;
    if &key.d >= n {
        return Err(Error::new("input overflows the modulus"));
    }
    Ok((backend, d))
}

fn key_from_point(curve: Arc<dyn Curve>, point: &[u8]) -> Result<PublicKey, Error> {
    if point == [0] {
        return Err(Error::new("ecdsa: public key point is the infinity"));
    }
    let len = curve.params().bit_size.div_ceil(8);
    Ok(PublicKey {
        x: Int::from_be_bytes(&point[1..1 + len]),
        y: Int::from_be_bytes(&point[1 + len..]),
        curve,
    })
}

fn curve_for(id: nistec::Id) -> Arc<dyn Curve> {
    match id {
        nistec::Id::P224 => elliptic::p224(),
        nistec::Id::P256 => elliptic::p256(),
        nistec::Id::P384 => elliptic::p384(),
        nistec::Id::P521 => elliptic::p521(),
    }
}

fn ecdh_curve(id: Option<nistec::Id>) -> Option<&'static dyn crate::ecdh::Curve> {
    match id? {
        nistec::Id::P256 => Some(crate::ecdh::p256()),
        nistec::Id::P384 => Some(crate::ecdh::p384()),
        nistec::Id::P521 => Some(crate::ecdh::p521()),
        nistec::Id::P224 => None,
    }
}

impl PublicKey {
    /// Go's `PublicKey.ECDH`: converts the key to a `crypto/ecdh` key.
    pub fn ecdh(&self) -> Result<crate::ecdh::PublicKey, Error> {
        let curve = ecdh_curve(self.curve.nist())
            .ok_or_else(|| Error::new("ecdsa: unsupported curve by crypto/ecdh"))?;
        let bytes = self.bytes()?;
        curve
            .public_key_from_bytes(&bytes)
            .map_err(|error| Error::new(error.to_string()))
    }

    /// Go's `PublicKey.Equal`.
    pub fn equal(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<PublicKey>().is_some_and(|other| {
            big_int_equal(&self.x, &other.x)
                && big_int_equal(&self.y, &other.y)
                && elliptic::same_curve(&self.curve, &other.curve)
        })
    }

    /// Go's `PublicKey.Bytes`: the uncompressed SEC 1 encoding.
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        public_point(self, "PublicKey.Bytes").map(|(_, q)| q)
    }

    /// The key as a PKIX (SubjectPublicKeyInfo) DER document, the encoding
    /// `x509.MarshalPKIXPublicKey` uses.
    pub fn to_pkix_der(&self) -> Result<Vec<u8>, Error> {
        let (backend, q) = public_point(self, "")?;
        backend
            .public_to_pkix(&q)
            .ok_or_else(|| Error::new("ecdsa: cannot encode public key"))
    }

    /// Parses a PKIX DER public key on P-224, P-256, P-384 or P-521, as
    /// `x509.ParsePKIXPublicKey` does for `*ecdsa.PublicKey`.
    pub fn from_pkix_der(der: &[u8]) -> Result<PublicKey, Error> {
        for id in [
            nistec::Id::P256,
            nistec::Id::P384,
            nistec::Id::P521,
            nistec::Id::P224,
        ] {
            if let Some(point) = nistec::backend(id).public_from_pkix(der) {
                return key_from_point(curve_for(id), &point);
            }
        }
        Err(Error::new("ecdsa: invalid public key"))
    }
}

/// Go's `ecdsa.ParseUncompressedPublicKey`: parses an uncompressed SEC 1
/// public key on a NIST curve.
pub fn parse_uncompressed_public_key(
    curve: Arc<dyn Curve>,
    data: &[u8],
) -> Result<PublicKey, Error> {
    if data.is_empty() || data[0] != 4 {
        return Err(Error::new("ecdsa: invalid uncompressed public key"));
    }
    let backend = backend_of(curve.as_ref())
        .ok_or_else(|| Error::new("ecdsa: curve not supported by ParseUncompressedPublicKey"))?;
    check_point(backend, data)?;
    key_from_point(curve, data)
}

impl PrivateKey {
    /// Go's `PrivateKey.ECDH`: converts the key to a `crypto/ecdh` key.
    pub fn ecdh(&self) -> Result<crate::ecdh::PrivateKey, Error> {
        let curve = ecdh_curve(self.public_key.curve.nist())
            .ok_or_else(|| Error::new("ecdsa: unsupported curve by crypto/ecdh"))?;
        let bytes = self.bytes()?;
        curve
            .private_key_from_bytes(&bytes)
            .map_err(|error| Error::new(error.to_string()))
    }

    /// Go's `PrivateKey.Public`.
    pub fn public(&self) -> &AnyPublicKey {
        &self.public_key
    }

    /// Go's `PrivateKey.Equal`.
    pub fn equal(&self, other: &dyn Any) -> bool {
        other.downcast_ref::<PrivateKey>().is_some_and(|other| {
            self.public_key.equal(&other.public_key) && big_int_equal(&self.d, &other.d)
        })
    }

    /// Go's `PrivateKey.Bytes`: the scalar as a fixed-width big-endian value.
    pub fn bytes(&self) -> Result<Vec<u8>, Error> {
        private_scalar(self, "PrivateKey.Bytes").map(|(_, d)| d)
    }

    /// Go's `PrivateKey.Sign(nil, digest, opts)`: signs `digest` and returns
    /// an ASN.1 DER signature. With no random source the signature is
    /// deterministic (RFC 6979) and `opts` must name the hash function. Use
    /// [`PrivateKey::sign_with_rng`] or [`sign_asn1`] for hedged signatures.
    pub fn sign(&self, digest: &[u8], opts: Option<&dyn SignerOpts>) -> Result<Vec<u8>, Error> {
        self.sign_in(None, digest, opts)
    }

    /// Go's `PrivateKey.Sign(rng, digest, opts)`: signs `digest` with a
    /// hedged signature and returns an ASN.1 DER signature. Like Go 1.26 and
    /// later, the reader is ignored by default and randomness comes from
    /// [`crate::rand`] (the reader is used with `GODEBUG=cryptocustomrand=1`).
    pub fn sign_with_rng(
        &self,
        rng: &mut dyn io::Read,
        digest: &[u8],
        opts: Option<&dyn SignerOpts>,
    ) -> Result<Vec<u8>, Error> {
        self.sign_in(Some(rng), digest, opts)
    }

    fn sign_in(
        &self,
        rand: Option<&mut dyn io::Read>,
        digest: &[u8],
        opts: Option<&dyn SignerOpts>,
    ) -> Result<Vec<u8>, Error> {
        if let Some(opts) = opts {
            let Some(hash) = opts.hash_func() else {
                return Err(Error::new(
                    "ecdsa: Sign must be called with a hash, not with crypto.Hash(0)",
                ));
            };
            if hash.size() != digest.len() {
                return Err(Error::new(
                    "ecdsa: hash length does not match hash function",
                ));
            }
        }
        match rand {
            None => self.sign_rfc6979(digest, opts),
            Some(rand) => {
                let (backend, r, s) = sign_parts(Some(rand), self, digest)?;
                encode_signature(backend, &r, &s)
            }
        }
    }

    fn sign_rfc6979(&self, digest: &[u8], opts: Option<&dyn SignerOpts>) -> Result<Vec<u8>, Error> {
        let opts =
            opts.ok_or_else(|| Error::new("ecdsa: Sign called with nil random and nil opts"))?;
        let hash = opts.hash_func().ok_or_else(|| {
            Error::new("ecdsa: requested hash function unavailable: unknown hash value 0")
        })?;
        if backend_of(self.public_key.curve.as_ref()).is_none() {
            return Err(Error::new(
                "ecdsa: curve not supported by deterministic signatures",
            ));
        }
        let (backend, d) = private_scalar(self, "")?;
        if !hash.available() {
            return Err(Error::new(format!(
                "ecdsa: requested hash function unavailable: {hash}"
            )));
        }
        if digest.is_empty() {
            return Err(Error::new("ecdsa: hash cannot be empty"));
        }
        let (r, s) = backend
            .sign_deterministic(&d, digest, hash)
            .ok_or_else(|| {
                Error::new(format!(
                    "ecdsa: requested hash function unavailable: {hash}"
                ))
            })?;
        encode_signature(backend, &r, &s)
    }

    /// The key as a PKCS #8 DER document, the encoding
    /// `x509.MarshalPKCS8PrivateKey` uses.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, Error> {
        let (backend, d) = private_scalar(self, "")?;
        backend
            .private_to_pkcs8(&d)
            .ok_or_else(|| Error::new("ecdsa: cannot encode private key"))
    }

    /// Parses a PKCS #8 DER private key on P-224, P-256, P-384 or P-521, as
    /// `x509.ParsePKCS8PrivateKey` does for `*ecdsa.PrivateKey`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<PrivateKey, Error> {
        for id in all_ids() {
            if let Some(d) = nistec::backend(id).private_from_pkcs8(der) {
                return parse_raw_private_key(curve_for(id), &d);
            }
        }
        Err(Error::new("ecdsa: invalid private key"))
    }

    /// The key as a SEC 1 `ECPrivateKey` DER document, the encoding
    /// `x509.MarshalECPrivateKey` uses.
    pub fn to_sec1_der(&self) -> Result<Vec<u8>, Error> {
        let (backend, d) = private_scalar(self, "")?;
        backend
            .private_to_sec1_der(&d)
            .ok_or_else(|| Error::new("ecdsa: cannot encode private key"))
    }

    /// Parses a SEC 1 `ECPrivateKey` DER document, as `x509.ParseECPrivateKey`
    /// does.
    pub fn from_sec1_der(der: &[u8]) -> Result<PrivateKey, Error> {
        for id in all_ids() {
            if let Some(d) = nistec::backend(id).private_from_sec1_der(der) {
                return parse_raw_private_key(curve_for(id), &d);
            }
        }
        Err(Error::new("ecdsa: invalid private key"))
    }
}

fn all_ids() -> [nistec::Id; 4] {
    [
        nistec::Id::P256,
        nistec::Id::P384,
        nistec::Id::P521,
        nistec::Id::P224,
    ]
}

impl Signer for PrivateKey {
    fn public(&self) -> &AnyPublicKey {
        &self.public_key
    }

    fn sign(&self, digest: &[u8], opts: &dyn SignerOpts) -> Result<Vec<u8>, BoxError> {
        PrivateKey::sign(self, digest, Some(opts)).map_err(Into::into)
    }

    fn sign_with_rng(
        &self,
        rng: &mut dyn io::Read,
        digest: &[u8],
        opts: &dyn SignerOpts,
    ) -> Result<Vec<u8>, BoxError> {
        PrivateKey::sign_with_rng(self, rng, digest, Some(opts)).map_err(Into::into)
    }
}

/// Go's `ecdsa.ParseRawPrivateKey`: a fixed-width big-endian scalar on a NIST
/// curve.
pub fn parse_raw_private_key(curve: Arc<dyn Curve>, data: &[u8]) -> Result<PrivateKey, Error> {
    let backend = backend_of(curve.as_ref())
        .ok_or_else(|| Error::new("ecdsa: curve not supported by ParseRawPrivateKey"))?;
    if data.len() != backend.len() {
        return Err(Error::new("invalid scalar length"));
    }
    let q = backend.scalar_base_mult(data);
    if q == [0] {
        return Err(Error::new("ecdsa: invalid public key encoding"));
    }
    if Int::from_be_bytes(data) >= curve.params().n {
        return Err(Error::new("input overflows the modulus"));
    }
    Ok(PrivateKey {
        public_key: key_from_point(curve, &q)?,
        d: Int::from_be_bytes(data),
    })
}

/// Go's `ecdsa.GenerateKey`, with randomness from [`crate::rand`].
pub fn generate_key(curve: Arc<dyn Curve>) -> Result<PrivateKey, Error> {
    generate_key_in(curve, None)
}

/// [`generate_key`] with a caller's reader. Like Go 1.26 and later, the
/// reader is ignored by default and randomness comes from [`crate::rand`]
/// (the reader is used with `GODEBUG=cryptocustomrand=1`).
pub fn generate_key_with_rng(
    rng: &mut dyn io::Read,
    curve: Arc<dyn Curve>,
) -> Result<PrivateKey, Error> {
    generate_key_in(curve, Some(rng))
}

fn generate_key_in(
    curve: Arc<dyn Curve>,
    rand: Option<&mut dyn io::Read>,
) -> Result<PrivateKey, Error> {
    let backend = backend_of(curve.as_ref()).ok_or_else(custom_curve)?;
    let mut source = Source::custom(rand);
    loop {
        let mut d = vec![0u8; backend.len()];
        source.fill(&mut d);
        if backend.id() == nistec::Id::P521 {
            d[0] &= 0b0000_0001;
        }
        if !backend.valid_scalar(&d) {
            continue;
        }
        let q = backend.public_from_scalar(&d).expect("valid scalar");
        source
            .finish()
            .map_err(|error| Error::new(error.to_string()))?;
        return Ok(PrivateKey {
            public_key: key_from_point(curve, &q)?,
            d: Int::from_be_bytes(&d),
        });
    }
}

/// Encodes `(r, s)` as an ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`.
fn encode_signature(backend: &dyn Backend, r: &[u8], s: &[u8]) -> Result<Vec<u8>, Error> {
    backend
        .signature_to_der(r, s)
        .ok_or_else(|| Error::new("invalid integer"))
}

/// Go's `ecdsa.SignASN1`: signs `hash` (hedged RFC 6979 with entropy from
/// [`crate::rand`]) and returns an ASN.1 DER signature.
pub fn sign_asn1(priv_key: &PrivateKey, hash: &[u8]) -> Result<Vec<u8>, Error> {
    let (backend, r, s) = sign_parts(None, priv_key, hash)?;
    encode_signature(backend, &r, &s)
}

/// [`sign_asn1`] with a caller's reader. Like Go 1.26 and later, the reader is
/// ignored by default (it is used with `GODEBUG=cryptocustomrand=1`).
pub fn sign_asn1_with_rng(
    rng: &mut dyn io::Read,
    priv_key: &PrivateKey,
    hash: &[u8],
) -> Result<Vec<u8>, Error> {
    let (backend, r, s) = sign_parts(Some(rng), priv_key, hash)?;
    encode_signature(backend, &r, &s)
}

/// The backend and the `(r, s)` of a signature.
type SignedParts = (&'static dyn Backend, Vec<u8>, Vec<u8>);

fn sign_parts(
    rand: Option<&mut dyn io::Read>,
    priv_key: &PrivateKey,
    hash: &[u8],
) -> Result<SignedParts, Error> {
    if hash.is_empty() {
        return Err(Error::new("ecdsa: hash cannot be empty"));
    }
    let (backend, d) = private_scalar(priv_key, "")?;
    let mut entropy = vec![0u8; d.len()];
    let mut source = Source::custom(rand);
    source.fill(&mut entropy);
    source
        .finish()
        .map_err(|error| Error::new(error.to_string()))?;
    let (r, s) = backend
        .sign_hedged(&d, hash, &entropy)
        .ok_or_else(|| Error::new("ecdsa: internal error: signing failed"))?;
    Ok((backend, r, s))
}

/// Go's `ecdsa.Sign`: signs `hash` and returns the signature as `(r, s)`.
pub fn sign(priv_key: &PrivateKey, hash: &[u8]) -> Result<(Int, Int), Error> {
    let (_, r, s) = sign_parts(None, priv_key, hash)?;
    Ok((Int::from_be_bytes(&r), Int::from_be_bytes(&s)))
}

/// [`sign`] with a caller's reader, ignored by default like
/// [`sign_asn1_with_rng`].
pub fn sign_with_rng(
    rng: &mut dyn io::Read,
    priv_key: &PrivateKey,
    hash: &[u8],
) -> Result<(Int, Int), Error> {
    let (_, r, s) = sign_parts(Some(rng), priv_key, hash)?;
    Ok((Int::from_be_bytes(&r), Int::from_be_bytes(&s)))
}

/// Go's `ecdsa.VerifyASN1`: verifies an ASN.1 DER signature of `hash`.
pub fn verify_asn1(public_key: &PublicKey, hash: &[u8], sig: &[u8]) -> bool {
    if hash.is_empty() {
        return false;
    }
    let Some(backend) = backend_of(public_key.curve.as_ref()) else {
        return false;
    };
    let Some((r, s)) = backend.signature_from_der(sig) else {
        return false;
    };
    let Ok((_, q)) = public_point(public_key, "") else {
        return false;
    };
    backend.verify(&q, hash, &r, &s)
}

/// Go's `ecdsa.Verify`: verifies the signature `(r, s)` of `hash`.
pub fn verify(public_key: &PublicKey, hash: &[u8], r: &Int, s: &Int) -> bool {
    if r.is_zero() || s.is_zero() || hash.is_empty() {
        return false;
    }
    let Some(backend) = backend_of(public_key.curve.as_ref()) else {
        return false;
    };
    let (Some(r), Some(s)) = (r.fill_bytes(backend.len()), s.fill_bytes(backend.len())) else {
        return false;
    };
    let Ok((_, q)) = public_point(public_key, "") else {
        return false;
    };
    backend.verify(&q, hash, &r, &s)
}

// Deterministic (RFC 6979) signing runs HMAC over the named hash, so Go
// requires the hash's package (`Hash.Available`); hedged signing does not.
// The expected results are a Go 1.27 program's that imports only
// crypto/ecdsa, which brings crypto/sha512 and (through its FIPS module)
// crypto/sha3; the `ecdsa` feature enables both, as Go's imports do.
#[cfg(all(test, not(any(feature = "md5", feature = "sha1", feature = "sha256"))))]
mod hash_availability_tests {
    use super::*;
    use crate::Hash;

    #[test]
    fn ecdsa_alone_signs_deterministically_only_with_sha512_hashes() {
        let key = generate_key(crate::elliptic::p256()).unwrap();
        // Go's crypto/ecdsa imports crypto/sha3 and crypto/sha512, so those
        // hashes sign deterministically with crypto/ecdsa alone.
        let digest3 = [1u8; 32];
        let sig3 = key.sign(&digest3, Some(&Hash::Sha3_256)).unwrap();
        assert_eq!(key.sign(&digest3, Some(&Hash::Sha3_256)).unwrap(), sig3);
        for hash in [Hash::Md5, Hash::Sha1, Hash::Sha256] {
            let digest = vec![1u8; hash.size()];
            assert_eq!(
                key.sign(&digest, Some(&hash)).unwrap_err().to_string(),
                format!("ecdsa: requested hash function unavailable: {hash}")
            );
            let sig = key
                .sign_with_rng(&mut crate::rand::Reader, &digest, Some(&hash))
                .unwrap();
            assert!(verify_asn1(&key.public_key, &digest, &sig));
        }
        let digest = [1u8; 48];
        let sig = key.sign(&digest, Some(&Hash::Sha384)).unwrap();
        assert_eq!(key.sign(&digest, Some(&Hash::Sha384)).unwrap(), sig);
        assert!(verify_asn1(&key.public_key, &digest, &sig));
    }
}
