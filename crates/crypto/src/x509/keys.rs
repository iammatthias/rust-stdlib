//! Public and private keys in the encodings of `crypto/x509`: PKIX, PKCS #1,
//! PKCS #8 and SEC 1.
//!
//! Where a reviewed crate already encodes a key (the `to_*_der` hooks of the
//! key types) this module wraps it; the dispatch, validation and messages are
//! Go's.

use std::any::Any;
use std::sync::Arc;

use super::asn1::{self, BigInt, BitString, ObjectIdentifier, RawValue, Reader};
use super::asn1_unmarshal::{accepts, shapes, unmarshal, Ty};
use super::pkix::AlgorithmIdentifier;
use super::types::*;
use super::Error;
use crate::bigint::Int;
use crate::{dsa, ecdh, ecdsa, ed25519, elliptic, mldsa, rsa};

/// Go's `crypto.PublicKey` as `crypto/x509` produces and accepts it: a
/// `*rsa.PublicKey`, `*dsa.PublicKey`, `*ecdsa.PublicKey`,
/// `ed25519.PublicKey`, `*mldsa.PublicKey` or `*ecdh.PublicKey` (X25519).
#[derive(Clone, Debug)]
pub enum PublicKey {
    Rsa(rsa::PublicKey),
    Dsa(dsa::PublicKey),
    Ecdsa(ecdsa::PublicKey),
    Ed25519(ed25519::PublicKey),
    Mldsa(mldsa::PublicKey),
    Ecdh(ecdh::PublicKey),
}

impl PublicKey {
    /// The key as Go's `any`, for use with the keys' own `equal` methods.
    pub fn as_any(&self) -> &dyn Any {
        match self {
            PublicKey::Rsa(k) => k,
            PublicKey::Dsa(k) => k,
            PublicKey::Ecdsa(k) => k,
            PublicKey::Ed25519(k) => k,
            PublicKey::Mldsa(k) => k,
            PublicKey::Ecdh(k) => k,
        }
    }

    /// The enum for a key of one of the concrete types, as Go's type switches
    /// recognize them.
    pub fn from_any(key: &dyn Any) -> Option<PublicKey> {
        if let Some(k) = key.downcast_ref::<PublicKey>() {
            return Some(k.clone());
        }
        if let Some(k) = key.downcast_ref::<rsa::PublicKey>() {
            return Some(PublicKey::Rsa(k.clone()));
        }
        if let Some(k) = key.downcast_ref::<rsa::PrivateKey>() {
            return Some(PublicKey::Rsa(k.public_key.clone()));
        }
        if let Some(k) = key.downcast_ref::<dsa::PublicKey>() {
            return Some(PublicKey::Dsa(k.clone()));
        }
        if let Some(k) = key.downcast_ref::<ecdsa::PublicKey>() {
            return Some(PublicKey::Ecdsa(k.clone()));
        }
        if let Some(k) = key.downcast_ref::<ed25519::PublicKey>() {
            return Some(PublicKey::Ed25519(k.clone()));
        }
        if let Some(k) = key.downcast_ref::<mldsa::PublicKey>() {
            return Some(PublicKey::Mldsa(k.clone()));
        }
        if let Some(k) = key.downcast_ref::<ecdh::PublicKey>() {
            return Some(PublicKey::Ecdh(k.clone()));
        }
        None
    }

    /// Go's `Equal` method of the key types, applied to another key.
    pub fn equal(&self, other: &PublicKey) -> bool {
        self.as_any_equal(other.as_any())
    }

    fn as_any_equal(&self, other: &dyn Any) -> bool {
        match self {
            PublicKey::Rsa(k) => k.equal(other),
            PublicKey::Dsa(k) => match other.downcast_ref::<dsa::PublicKey>() {
                Some(o) => k == o,
                None => false,
            },
            PublicKey::Ecdsa(k) => k.equal(other),
            PublicKey::Ed25519(k) => k.equal(other),
            PublicKey::Mldsa(k) => k.equal(other),
            PublicKey::Ecdh(k) => k.equal(other),
        }
    }

    /// Go's `%T` of the key.
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            PublicKey::Rsa(_) => "*rsa.PublicKey",
            PublicKey::Dsa(_) => "*dsa.PublicKey",
            PublicKey::Ecdsa(_) => "*ecdsa.PublicKey",
            PublicKey::Ed25519(_) => "ed25519.PublicKey",
            PublicKey::Mldsa(_) => "*mldsa.PublicKey",
            PublicKey::Ecdh(_) => "*ecdh.PublicKey",
        }
    }
}

/// Go's `crypto.PrivateKey` as `ParsePKCS8PrivateKey` returns it.
#[derive(Clone, Debug)]
pub enum PrivateKey {
    Rsa(rsa::PrivateKey),
    Ecdsa(ecdsa::PrivateKey),
    Ed25519(ed25519::PrivateKey),
    Mldsa(mldsa::PrivateKey),
    Ecdh(ecdh::PrivateKey),
}

impl PrivateKey {
    /// The key as Go's `any`.
    pub fn as_any(&self) -> &dyn Any {
        match self {
            PrivateKey::Rsa(k) => k,
            PrivateKey::Ecdsa(k) => k,
            PrivateKey::Ed25519(k) => k,
            PrivateKey::Mldsa(k) => k,
            PrivateKey::Ecdh(k) => k,
        }
    }
}

fn asn1_structure(msg: &str) -> Error {
    Error::new(format!("asn1: structure error: {msg}"))
}

fn asn1_syntax(msg: &str) -> Error {
    Error::new(format!("asn1: syntax error: {msg}"))
}

/// Parses an `AlgorithmIdentifier` element's contents the way
/// `encoding/asn1` does for `pkix.AlgorithmIdentifier`.
pub(crate) fn read_algorithm_identifier(r: &mut Reader<'_>) -> Result<AlgorithmIdentifier, Error> {
    let seq = r
        .read(asn1::SEQUENCE)
        .ok_or_else(|| asn1_structure("tags don't match"))?;
    let mut s = Reader(seq);
    let algorithm = s
        .read_oid()
        .ok_or_else(|| asn1_structure("tags don't match"))?;
    let mut parameters = RawValue::default();
    if !s.empty() {
        let (tag, full) = s
            .read_any_element()
            .ok_or_else(|| asn1_syntax("data truncated"))?;
        parameters.class = i64::from(tag >> 6);
        parameters.tag = i64::from(tag & 0x1f);
        parameters.is_compound = tag & 0x20 != 0;
        let (_, contents) = Reader(full).read_any().unwrap_or((tag, &[]));
        parameters.bytes = contents.to_vec();
        parameters.full_bytes = full.to_vec();
    }
    Ok(AlgorithmIdentifier {
        algorithm,
        parameters,
    })
}

/// Go's `namedCurveFromOID`.
pub(crate) fn named_curve_from_oid(oid: &ObjectIdentifier) -> Option<Arc<dyn elliptic::Curve>> {
    if oid.is(&OID_NAMED_CURVE_P224) {
        Some(elliptic::p224())
    } else if oid.is(&OID_NAMED_CURVE_P256) {
        Some(elliptic::p256())
    } else if oid.is(&OID_NAMED_CURVE_P384) {
        Some(elliptic::p384())
    } else if oid.is(&OID_NAMED_CURVE_P521) {
        Some(elliptic::p521())
    } else {
        None
    }
}

/// Go's `oidFromNamedCurve`.
pub(crate) fn oid_from_named_curve(curve: &Arc<dyn elliptic::Curve>) -> Option<ObjectIdentifier> {
    for (make, oid) in [
        (
            elliptic::p224 as fn() -> Arc<dyn elliptic::Curve>,
            &OID_NAMED_CURVE_P224[..],
        ),
        (elliptic::p256, &OID_NAMED_CURVE_P256[..]),
        (elliptic::p384, &OID_NAMED_CURVE_P384[..]),
        (elliptic::p521, &OID_NAMED_CURVE_P521[..]),
    ] {
        if elliptic::same_curve(curve, &make()) {
            return Some(ObjectIdentifier(oid.to_vec()));
        }
    }
    None
}

fn oid_from_ecdh_curve(curve: &dyn ecdh::Curve) -> Option<ObjectIdentifier> {
    match curve.name() {
        "X25519" => Some(ObjectIdentifier(OID_PUBLIC_KEY_X25519.to_vec())),
        "P-256" => Some(ObjectIdentifier(OID_NAMED_CURVE_P256.to_vec())),
        "P-384" => Some(ObjectIdentifier(OID_NAMED_CURVE_P384.to_vec())),
        "P-521" => Some(ObjectIdentifier(OID_NAMED_CURVE_P521.to_vec())),
        _ => None,
    }
}

pub(crate) fn mldsa_parameters_from_oid(oid: &ObjectIdentifier) -> Option<mldsa::Parameters> {
    if oid.is(&OID_PUBLIC_KEY_MLDSA44) {
        Some(mldsa::mldsa44())
    } else if oid.is(&OID_PUBLIC_KEY_MLDSA65) {
        Some(mldsa::mldsa65())
    } else if oid.is(&OID_PUBLIC_KEY_MLDSA87) {
        Some(mldsa::mldsa87())
    } else {
        None
    }
}

pub(crate) fn oid_from_mldsa_parameters(params: mldsa::Parameters) -> Option<ObjectIdentifier> {
    if params == mldsa::mldsa44() {
        Some(ObjectIdentifier(OID_PUBLIC_KEY_MLDSA44.to_vec()))
    } else if params == mldsa::mldsa65() {
        Some(ObjectIdentifier(OID_PUBLIC_KEY_MLDSA65.to_vec()))
    } else if params == mldsa::mldsa87() {
        Some(ObjectIdentifier(OID_PUBLIC_KEY_MLDSA87.to_vec()))
    } else {
        None
    }
}

/// Go's `getPublicKeyAlgorithmFromOID`.
pub(crate) fn public_key_algorithm_from_oid(oid: &ObjectIdentifier) -> PublicKeyAlgorithm {
    if oid.is(&OID_PUBLIC_KEY_RSA) {
        PublicKeyAlgorithm::RSA
    } else if oid.is(&OID_PUBLIC_KEY_DSA) {
        PublicKeyAlgorithm::DSA
    } else if oid.is(&OID_PUBLIC_KEY_ECDSA) {
        PublicKeyAlgorithm::ECDSA
    } else if oid.is(&OID_PUBLIC_KEY_ED25519) {
        PublicKeyAlgorithm::ED25519
    } else if oid.is(&OID_PUBLIC_KEY_MLDSA44)
        || oid.is(&OID_PUBLIC_KEY_MLDSA65)
        || oid.is(&OID_PUBLIC_KEY_MLDSA87)
    {
        PublicKeyAlgorithm::MLDSA
    } else {
        PublicKeyAlgorithm::UNKNOWN_PUBLIC_KEY_ALGORITHM
    }
}

fn to_int(b: &BigInt) -> Int {
    b.magnitude().clone()
}

/// Go's `parsePublicKey`: `data` is the right-aligned `subjectPublicKey`.
pub(crate) fn parse_public_key(
    algorithm: &AlgorithmIdentifier,
    data: &[u8],
) -> Result<PublicKey, Error> {
    let oid = &algorithm.algorithm;
    let params = &algorithm.parameters;
    if oid.is(&OID_PUBLIC_KEY_RSA) {
        // RSA public keys must have a NULL in the parameters. See RFC 3279,
        // Section 2.3.1.
        if params.full_bytes != asn1::NULL_BYTES {
            return Err(Error::new("x509: RSA key missing NULL parameters"));
        }
        let mut der = Reader(data);
        let Some(seq) = der.read(asn1::SEQUENCE) else {
            return Err(Error::new("x509: invalid RSA public key"));
        };
        let mut der = Reader(seq);
        let Some(n) = der.read_big_integer() else {
            return Err(Error::new("x509: invalid RSA modulus"));
        };
        let Some(e) = der.read_i64() else {
            return Err(Error::new("x509: invalid RSA public exponent"));
        };
        if n.sign() <= 0 {
            return Err(Error::new("x509: RSA modulus is not a positive number"));
        }
        if e <= 0 {
            return Err(Error::new(
                "x509: RSA public exponent is not a positive number",
            ));
        }
        Ok(PublicKey::Rsa(rsa::PublicKey { n: to_int(&n), e }))
    } else if oid.is(&OID_PUBLIC_KEY_ECDSA) {
        let mut params_der = Reader(&params.full_bytes);
        let Some(named_curve_oid) = params_der.read_oid() else {
            return Err(Error::new("x509: invalid ECDSA parameters"));
        };
        let Some(curve) = named_curve_from_oid(&named_curve_oid) else {
            return Err(Error::new("x509: unsupported elliptic curve"));
        };
        ecdsa::parse_uncompressed_public_key(curve, data)
            .map(PublicKey::Ecdsa)
            .map_err(|e| Error::new(e.to_string()))
    } else if oid.is(&OID_PUBLIC_KEY_ED25519) {
        // RFC 8410, Section 3: for all of the OIDs, the parameters MUST be
        // absent.
        if !params.full_bytes.is_empty() {
            return Err(Error::new(
                "x509: Ed25519 key encoded with illegal parameters",
            ));
        }
        if data.len() != 32 {
            return Err(Error::new("x509: wrong Ed25519 public key size"));
        }
        Ok(PublicKey::Ed25519(ed25519::PublicKey(data.to_vec())))
    } else if oid.is(&OID_PUBLIC_KEY_MLDSA44)
        || oid.is(&OID_PUBLIC_KEY_MLDSA65)
        || oid.is(&OID_PUBLIC_KEY_MLDSA87)
    {
        if !params.full_bytes.is_empty() {
            return Err(Error::new(
                "x509: ML-DSA key encoded with illegal parameters",
            ));
        }
        let Some(p) = mldsa_parameters_from_oid(oid) else {
            return Err(Error::new("x509: unsupported ML-DSA parameters"));
        };
        mldsa::PublicKey::from_bytes(p, data)
            .map(PublicKey::Mldsa)
            .map_err(|e| Error::new(e.to_string()))
    } else if oid.is(&OID_PUBLIC_KEY_X25519) {
        if !params.full_bytes.is_empty() {
            return Err(Error::new(
                "x509: X25519 key encoded with illegal parameters",
            ));
        }
        ecdh::x25519()
            .public_key_from_bytes(data)
            .map(PublicKey::Ecdh)
            .map_err(|e| Error::new(e.to_string()))
    } else if oid.is(&OID_PUBLIC_KEY_DSA) {
        let mut der = Reader(data);
        let Some(y) = der.read_big_integer() else {
            return Err(Error::new("x509: invalid DSA public key"));
        };
        let mut params_der = Reader(&params.full_bytes);
        let parsed = (|| {
            let seq = params_der.read(asn1::SEQUENCE)?;
            let mut s = Reader(seq);
            Some((
                s.read_big_integer()?,
                s.read_big_integer()?,
                s.read_big_integer()?,
            ))
        })();
        let Some((p, q, g)) = parsed else {
            return Err(Error::new("x509: invalid DSA parameters"));
        };
        if y.sign() <= 0 || p.sign() <= 0 || q.sign() <= 0 || g.sign() <= 0 {
            return Err(Error::new("x509: zero or negative DSA parameter"));
        }
        Ok(PublicKey::Dsa(dsa::PublicKey {
            parameters: dsa::Parameters {
                p: to_int(&p),
                q: to_int(&q),
                g: to_int(&g),
            },
            y: to_int(&y),
        }))
    } else {
        Err(Error::new("x509: unknown public key algorithm"))
    }
}

/// Go's `marshalPublicKey`: the `subjectPublicKey` bytes and the algorithm.
pub(crate) fn marshal_public_key(
    pub_key: &PublicKey,
) -> Result<(Vec<u8>, AlgorithmIdentifier), Error> {
    let mut algorithm = AlgorithmIdentifier::default();
    match pub_key {
        PublicKey::Rsa(k) => {
            let bytes = marshal_pkcs1_public_key(k);
            algorithm.algorithm = ObjectIdentifier(OID_PUBLIC_KEY_RSA.to_vec());
            // The NULL parameters value is required by RFC 3279, Section 2.3.1.
            algorithm.parameters = RawValue::null();
            Ok((bytes, algorithm))
        }
        PublicKey::Ecdsa(k) => {
            let Some(oid) = oid_from_named_curve(&k.curve) else {
                return Err(Error::new("x509: unsupported elliptic curve"));
            };
            let bytes = k.bytes().map_err(|e| Error::new(e.to_string()))?;
            algorithm.algorithm = ObjectIdentifier(OID_PUBLIC_KEY_ECDSA.to_vec());
            algorithm.parameters.full_bytes = asn1::oid(&oid.0).expect("valid curve OID");
            Ok((bytes, algorithm))
        }
        PublicKey::Ed25519(k) => {
            algorithm.algorithm = ObjectIdentifier(OID_PUBLIC_KEY_ED25519.to_vec());
            Ok((k.0.clone(), algorithm))
        }
        PublicKey::Mldsa(k) => {
            let Some(oid) = oid_from_mldsa_parameters(k.parameters()) else {
                return Err(Error::new("x509: unsupported ML-DSA parameters"));
            };
            algorithm.algorithm = oid;
            Ok((k.bytes(), algorithm))
        }
        PublicKey::Ecdh(k) => {
            let bytes = k.bytes();
            if k.curve().name() == "X25519" {
                algorithm.algorithm = ObjectIdentifier(OID_PUBLIC_KEY_X25519.to_vec());
            } else {
                let Some(oid) = oid_from_ecdh_curve(k.curve()) else {
                    return Err(Error::new("x509: unsupported elliptic curve"));
                };
                algorithm.algorithm = ObjectIdentifier(OID_PUBLIC_KEY_ECDSA.to_vec());
                algorithm.parameters.full_bytes = asn1::oid(&oid.0).expect("valid curve OID");
            }
            Ok((bytes, algorithm))
        }
        PublicKey::Dsa(_) => Err(Error::new(format!(
            "x509: unsupported public key type: {}",
            pub_key.type_name()
        ))),
    }
}

/// Go's `MarshalPKIXPublicKey`: converts a public key to PKIX, ASN.1 DER form
/// (a SubjectPublicKeyInfo, RFC 5280, Section 4.1). The key is one of the
/// concrete key types or a [`PublicKey`].
pub fn marshal_pkix_public_key(pub_key: &dyn Any) -> Result<Vec<u8>, Error> {
    let Some(key) = PublicKey::from_any(pub_key) else {
        return Err(Error::new(
            "x509: unsupported public key type: unknown".to_string(),
        ));
    };
    let (bytes, algorithm) = marshal_public_key(&key)?;
    let mut content = algorithm.marshal()?;
    content.extend(asn1::bit_string(&bytes, bytes.len() * 8));
    Ok(asn1::tlv(asn1::SEQUENCE, &content))
}

/// A parsed SubjectPublicKeyInfo.
pub(crate) struct PublicKeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub public_key: BitString,
}

fn read_public_key_info(der: &[u8]) -> Result<(PublicKeyInfo, usize), Error> {
    let mut r = Reader(der);
    let seq = r
        .read(asn1::SEQUENCE)
        .ok_or_else(|| asn1_structure("tags don't match"))?;
    let rest_len = r.0.len();
    let mut s = Reader(seq);
    let algorithm = read_algorithm_identifier(&mut s)?;
    let public_key = s
        .read_bit_string()
        .ok_or_else(|| asn1_structure("tags don't match"))?;
    Ok((
        PublicKeyInfo {
            algorithm,
            public_key,
        },
        rest_len,
    ))
}

/// Go's `ParsePKIXPublicKey`: parses a public key in PKIX, ASN.1 DER form.
/// It returns an RSA, DSA, ECDSA, Ed25519, ML-DSA or ECDH (X25519) key.
pub fn parse_pkix_public_key(der_bytes: &[u8]) -> Result<PublicKey, Error> {
    match unmarshal(der_bytes, Ty::Struct(&shapes::PUBLIC_KEY_INFO)) {
        Err(e) => {
            if accepts(der_bytes, Ty::Struct(&shapes::PKCS1_PUBLIC_KEY)) {
                return Err(Error::new(
                    "x509: failed to parse public key (use ParsePKCS1PublicKey instead for this key format)",
                ));
            }
            return Err(Error::new(e));
        }
        Ok(used) if used != der_bytes.len() => {
            return Err(Error::new("x509: trailing data after ASN.1 of public-key"));
        }
        Ok(_) => {}
    }
    let (pki, _) = read_public_key_info(der_bytes)?;
    parse_public_key(&pki.algorithm, &pki.public_key.right_align())
}

fn parse_pkcs1_public_key_fields(der: &[u8]) -> Option<(BigInt, i64, usize)> {
    let mut r = Reader(der);
    let seq = r.read(asn1::SEQUENCE)?;
    let rest = r.0.len();
    let mut s = Reader(seq);
    let n = s.read_big_integer()?;
    let e = s.read_i64()?;
    Some((n, e, rest))
}

/// Go's `ParsePKCS1PublicKey`: parses an RSA public key in PKCS #1, ASN.1 DER
/// form.
pub fn parse_pkcs1_public_key(der: &[u8]) -> Result<rsa::PublicKey, Error> {
    let used = match unmarshal(der, Ty::Struct(&shapes::PKCS1_PUBLIC_KEY)) {
        Ok(used) => used,
        Err(e) => {
            if accepts(der, Ty::Struct(&shapes::PUBLIC_KEY_INFO)) {
                return Err(Error::new(
                    "x509: failed to parse public key (use ParsePKIXPublicKey instead for this key format)",
                ));
            }
            return Err(Error::new(e));
        }
    };
    if used != der.len() {
        return Err(asn1_syntax("trailing data"));
    }
    let Some((n, e, _)) = parse_pkcs1_public_key_fields(der) else {
        return Err(asn1_structure("tags don't match"));
    };
    if n.sign() <= 0 || e <= 0 {
        return Err(Error::new(
            "x509: public key contains zero or negative value",
        ));
    }
    if e > i64::from(i32::MAX) {
        return Err(Error::new(
            "x509: public key contains large public exponent",
        ));
    }
    Ok(rsa::PublicKey { n: to_int(&n), e })
}

/// Go's `MarshalPKCS1PublicKey`: converts an RSA public key to PKCS #1, ASN.1
/// DER form.
pub fn marshal_pkcs1_public_key(key: &rsa::PublicKey) -> Vec<u8> {
    let mut content = asn1::integer_big(&BigInt::from_int(key.n.clone()));
    content.extend(asn1::integer_i64(key.e));
    asn1::tlv(asn1::SEQUENCE, &content)
}

/// Go's `ParsePKCS1PrivateKey`: parses an RSA private key in PKCS #1, ASN.1
/// DER form.
pub fn parse_pkcs1_private_key(der: &[u8]) -> Result<rsa::PrivateKey, Error> {
    let used = match unmarshal(der, Ty::Struct(&shapes::PKCS1_PRIVATE_KEY)) {
        Ok(used) => used,
        Err(e) => {
            if accepts(der, Ty::Struct(&shapes::EC_PRIVATE_KEY)) {
                return Err(Error::new(
                    "x509: failed to parse private key (use ParseECPrivateKey instead for this key format)",
                ));
            }
            if accepts(der, Ty::Struct(&shapes::PKCS8)) {
                return Err(Error::new(
                    "x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)",
                ));
            }
            return Err(Error::new(e));
        }
    };
    if used != der.len() {
        return Err(asn1_syntax("trailing data"));
    }
    let fields = (|| {
        let mut r = Reader(der);
        let seq = r.read(asn1::SEQUENCE)?;
        let rest = r.0.len();
        let mut s = Reader(seq);
        let version = s.read_i64()?;
        let n = s.read_big_integer()?;
        let e = s.read_i64()?;
        let d = s.read_big_integer()?;
        let p = s.read_big_integer()?;
        let q = s.read_big_integer()?;
        let optional = |s: &mut Reader<'_>| {
            if s.peek_tag(asn1::INTEGER) {
                s.read_big_integer().map(Some)
            } else {
                Some(None)
            }
        };
        let dp = optional(&mut s)?;
        let dq = optional(&mut s)?;
        let qinv = optional(&mut s)?;
        let mut additional = Vec::new();
        if s.peek_tag(asn1::SEQUENCE) {
            let seq = s.read(asn1::SEQUENCE)?;
            let mut a = Reader(seq);
            while !a.empty() {
                let item = a.read(asn1::SEQUENCE)?;
                let mut i = Reader(item);
                additional.push((
                    i.read_big_integer()?,
                    i.read_big_integer()?,
                    i.read_big_integer()?,
                ));
            }
        }
        Some((rest, version, n, e, d, p, q, dp, dq, qinv, additional))
    })();
    let Some((_, version, n, e, d, p, q, dp, dq, qinv, additional)) = fields else {
        return Err(asn1_structure("tags don't match"));
    };
    if version > 1 {
        return Err(Error::new("x509: unsupported private key version"));
    }
    let nonpositive = |b: &Option<BigInt>| b.as_ref().is_some_and(|b| b.sign() <= 0);
    if n.sign() <= 0
        || d.sign() <= 0
        || p.sign() <= 0
        || q.sign() <= 0
        || nonpositive(&dp)
        || nonpositive(&dq)
        || nonpositive(&qinv)
    {
        return Err(Error::new(
            "x509: private key contains zero or negative value",
        ));
    }
    let mut primes = vec![to_int(&p), to_int(&q)];
    for (prime, _, _) in &additional {
        if prime.sign() <= 0 {
            return Err(Error::new(
                "x509: private key contains zero or negative prime",
            ));
        }
        primes.push(to_int(prime));
    }
    let mut key = rsa::PrivateKey {
        public_key: rsa::PublicKey { n: to_int(&n), e },
        d: to_int(&d),
        primes,
        precomputed: rsa::PrecomputedValues::default(),
    };
    // Go uses the CRT values only when the encoding has all three; with
    // fewer it computes them (`PrivateKey.precompute`).
    let (given_dp, given_dq, given_qinv) = match (&dp, &dq, &qinv) {
        (Some(dp), Some(dq), Some(qinv)) => {
            (Some(to_int(dp)), Some(to_int(dq)), Some(to_int(qinv)))
        }
        _ => (None, None, None),
    };
    key.precomputed.dp = given_dp.clone();
    key.precomputed.dq = given_dq.clone();
    key.precomputed.qinv = given_qinv.clone();
    key.precompute();
    // Go validates CRT values that are present in the encoding against the
    // key; the values this crate computes stand in for the key's own.
    let crt_error = if given_dp.is_some() || given_dq.is_some() || given_qinv.is_some() {
        if given_dp != key.precomputed.dp || given_dq != key.precomputed.dq {
            Some("crypto/rsa: invalid CRT exponent")
        } else if given_qinv != key.precomputed.qinv {
            Some("crypto/rsa: invalid CRT coefficient")
        } else {
            None
        }
    } else {
        None
    };
    let validated = match crt_error {
        Some(message) => Err(rsa::Error::Other(message.to_string())),
        None => key.validate(),
    };
    if let Err(e) = validated {
        if crate::sysrng::godebug("x509rsacrt").as_deref() == Some("0") {
            key.precomputed.dp = None;
            key.precomputed.dq = None;
            key.precomputed.qinv = None;
            key.precompute();
            if key.validate().is_ok() {
                return Ok(key);
            }
        }
        // The reviewed crate rejected the key; Go names the first of its own
        // checks that fails.
        let crt = match (&given_dp, &given_dq, &given_qinv) {
            (Some(dp), Some(dq), Some(qinv)) => Some((dp, dq, qinv)),
            _ => None,
        };
        let message = rsa::validation_error_text(
            &key.public_key.n,
            key.public_key.e,
            &key.d,
            &key.primes,
            crt,
        )
        .unwrap_or_else(|| e.to_string());
        return Err(Error::new(message));
    }
    Ok(key)
}

/// Go's `MarshalPKCS1PrivateKey`: converts an RSA private key to PKCS #1,
/// ASN.1 DER form.
pub fn marshal_pkcs1_private_key(key: &rsa::PrivateKey) -> Vec<u8> {
    let mut key = key.clone();
    key.precompute();
    let version = if key.primes.len() > 2 { 1 } else { 0 };
    let big = |i: &Int| asn1::integer_big(&BigInt::from_int(i.clone()));
    let opt = |i: &Option<Int>| big(&i.clone().unwrap_or_default());
    let mut content = asn1::integer_i64(version);
    content.extend(big(&key.public_key.n));
    content.extend(asn1::integer_i64(key.public_key.e));
    content.extend(big(&key.d));
    content.extend(big(&key.primes[0]));
    content.extend(big(&key.primes[1]));
    content.extend(opt(&key.precomputed.dp));
    content.extend(opt(&key.precomputed.dq));
    content.extend(opt(&key.precomputed.qinv));
    if !key.precomputed.crt_values.is_empty() {
        let mut additional = Vec::new();
        for (i, v) in key.precomputed.crt_values.iter().enumerate() {
            let mut item = big(&key.primes[2 + i]);
            item.extend(big(&v.exp));
            item.extend(big(&v.coeff));
            additional.extend(asn1::tlv(asn1::SEQUENCE, &item));
        }
        content.extend(asn1::tlv(asn1::SEQUENCE, &additional));
    }
    asn1::tlv(asn1::SEQUENCE, &content)
}

struct EcPrivateKeyFields {
    version: i64,
    private_key: Vec<u8>,
    named_curve_oid: Option<ObjectIdentifier>,
}

fn read_ec_private_key_fields(der: &[u8]) -> Option<EcPrivateKeyFields> {
    let mut r = Reader(der);
    let seq = r.read(asn1::SEQUENCE)?;
    let mut s = Reader(seq);
    let version = s.read_i64()?;
    let private_key = s.read(asn1::OCTET_STRING)?.to_vec();
    let mut named_curve_oid = None;
    // encoding/asn1 parses the child of an explicit tag from the bytes that
    // follow its header, without checking the wrapper's length.
    // A child of another type makes the optional field absent.
    let saved = s.0;
    if s.read_explicit_header(asn1::context_constructed(0))? {
        if s.0.first() == Some(&asn1::OBJECT_IDENTIFIER) {
            named_curve_oid = Some(s.read_oid()?);
        } else {
            s.0 = saved;
        }
    }
    // Nothing follows, so a mismatched child is simply left unread.
    if s.read_explicit_header(asn1::context_constructed(1))?
        && s.0.first() == Some(&asn1::BIT_STRING)
    {
        s.read_bit_string()?;
    }
    Some(EcPrivateKeyFields {
        version,
        private_key,
        named_curve_oid,
    })
}

struct Pkcs8Fields {
    algorithm: AlgorithmIdentifier,
    private_key: Vec<u8>,
}

fn read_pkcs8_fields(der: &[u8]) -> Option<Pkcs8Fields> {
    let mut r = Reader(der);
    let seq = r.read(asn1::SEQUENCE)?;
    let mut s = Reader(seq);
    s.read_i64()?;
    let algorithm = read_algorithm_identifier(&mut s).ok()?;
    let private_key = s.read(asn1::OCTET_STRING)?.to_vec();
    Some(Pkcs8Fields {
        algorithm,
        private_key,
    })
}

/// Go's `ParseECPrivateKey`: parses an EC private key in SEC 1, ASN.1 DER
/// form.
pub fn parse_ec_private_key(der: &[u8]) -> Result<ecdsa::PrivateKey, Error> {
    parse_ec_private_key_with_oid(None, der)
}

fn parse_ec_private_key_with_oid(
    named_curve_oid: Option<&ObjectIdentifier>,
    der: &[u8],
) -> Result<ecdsa::PrivateKey, Error> {
    if let Err(e) = unmarshal(der, Ty::Struct(&shapes::EC_PRIVATE_KEY)) {
        if accepts(der, Ty::Struct(&shapes::PKCS8)) {
            return Err(Error::new(
                "x509: failed to parse private key (use ParsePKCS8PrivateKey instead for this key format)",
            ));
        }
        if accepts(der, Ty::Struct(&shapes::PKCS1_PRIVATE_KEY)) {
            return Err(Error::new(
                "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)",
            ));
        }
        return Err(Error::new(format!(
            "x509: failed to parse EC private key: {e}"
        )));
    }
    let Some(mut priv_key) = read_ec_private_key_fields(der) else {
        return Err(Error::new(
            "x509: failed to parse EC private key: asn1: structure error: tags don't match",
        ));
    };
    if priv_key.version != 1 {
        return Err(Error::new(format!(
            "x509: unknown EC private key version {}",
            priv_key.version
        )));
    }
    let curve = match named_curve_oid {
        Some(oid) => named_curve_from_oid(oid),
        None => priv_key
            .named_curve_oid
            .as_ref()
            .and_then(named_curve_from_oid),
    };
    let Some(curve) = curve else {
        return Err(Error::new("x509: unknown elliptic curve"));
    };
    let size = curve.params().n.bit_len().div_ceil(8);
    let mut private_key = vec![0u8; size];
    while priv_key.private_key.len() > private_key.len() {
        if priv_key.private_key[0] != 0 {
            return Err(Error::new("x509: invalid private key length"));
        }
        priv_key.private_key.remove(0);
    }
    let offset = private_key.len() - priv_key.private_key.len();
    private_key[offset..].copy_from_slice(&priv_key.private_key);
    ecdsa::parse_raw_private_key(curve, &private_key).map_err(|e| Error::new(e.to_string()))
}

fn marshal_ec_private_key_with_oid(
    key: &ecdsa::PrivateKey,
    oid: Option<&ObjectIdentifier>,
) -> Result<Vec<u8>, Error> {
    let private_key = key.bytes().map_err(|e| Error::new(e.to_string()))?;
    let public_key = key
        .public_key
        .bytes()
        .map_err(|e| Error::new(e.to_string()))?;
    Ok(marshal_ec_private_key_fields(
        &private_key,
        oid,
        &public_key,
    ))
}

fn marshal_ec_private_key_fields(
    private_key: &[u8],
    oid: Option<&ObjectIdentifier>,
    public_key: &[u8],
) -> Vec<u8> {
    let mut content = asn1::integer_i64(1);
    content.extend(asn1::octet_string(private_key));
    if let Some(oid) = oid {
        content.extend(asn1::tlv(
            asn1::context_constructed(0),
            &asn1::oid(&oid.0).expect("valid curve OID"),
        ));
    }
    content.extend(asn1::tlv(
        asn1::context_constructed(1),
        &asn1::bit_string(public_key, public_key.len() * 8),
    ));
    asn1::tlv(asn1::SEQUENCE, &content)
}

/// Go's `MarshalECPrivateKey`: converts an EC private key to SEC 1, ASN.1 DER
/// form.
pub fn marshal_ec_private_key(key: &ecdsa::PrivateKey) -> Result<Vec<u8>, Error> {
    let Some(oid) = oid_from_named_curve(&key.public_key.curve) else {
        return Err(Error::new("x509: unknown elliptic curve"));
    };
    marshal_ec_private_key_with_oid(key, Some(&oid))
}

/// Go's `ParsePKCS8PrivateKey`: parses an unencrypted private key in PKCS #8,
/// ASN.1 DER form.
pub fn parse_pkcs8_private_key(der: &[u8]) -> Result<PrivateKey, Error> {
    if let Err(e) = unmarshal(der, Ty::Struct(&shapes::PKCS8)) {
        if accepts(der, Ty::Struct(&shapes::EC_PRIVATE_KEY)) {
            return Err(Error::new(
                "x509: failed to parse private key (use ParseECPrivateKey instead for this key format)",
            ));
        }
        if accepts(der, Ty::Struct(&shapes::PKCS1_PRIVATE_KEY)) {
            return Err(Error::new(
                "x509: failed to parse private key (use ParsePKCS1PrivateKey instead for this key format)",
            ));
        }
        return Err(Error::new(e));
    }
    let Some(priv_key) = read_pkcs8_fields(der) else {
        return Err(asn1_structure("tags don't match"));
    };
    let algo = &priv_key.algorithm;
    let oid = &algo.algorithm;
    if oid.is(&OID_PUBLIC_KEY_RSA) {
        parse_pkcs1_private_key(&priv_key.private_key)
            .map(PrivateKey::Rsa)
            .map_err(|e| {
                Error::new(format!(
                    "x509: failed to parse RSA private key embedded in PKCS#8: {e}"
                ))
            })
    } else if oid.is(&OID_PUBLIC_KEY_ECDSA) {
        let named_curve_oid = Reader(&algo.parameters.full_bytes).read_oid();
        parse_ec_private_key_with_oid(named_curve_oid.as_ref(), &priv_key.private_key)
            .map(PrivateKey::Ecdsa)
            .map_err(|e| {
                Error::new(format!(
                    "x509: failed to parse EC private key embedded in PKCS#8: {e}"
                ))
            })
    } else if oid.is(&OID_PUBLIC_KEY_ED25519) {
        if !algo.parameters.full_bytes.is_empty() {
            return Err(Error::new("x509: invalid Ed25519 private key parameters"));
        }
        unmarshal(&priv_key.private_key, Ty::Octets)
            .map_err(|e| Error::new(format!("x509: invalid Ed25519 private key: {e}")))?;
        let curve_private_key = Reader(&priv_key.private_key)
            .read(asn1::OCTET_STRING)
            .map(|b| b.to_vec())
            .ok_or_else(|| asn1_structure("tags don't match"))?;
        if curve_private_key.len() != 32 {
            return Err(Error::new(format!(
                "x509: invalid Ed25519 private key length: {}",
                curve_private_key.len()
            )));
        }
        ed25519::PrivateKey::from_seed(&curve_private_key)
            .map(PrivateKey::Ed25519)
            .map_err(|e| Error::new(e.to_string()))
    } else if oid.is(&OID_PUBLIC_KEY_MLDSA44)
        || oid.is(&OID_PUBLIC_KEY_MLDSA65)
        || oid.is(&OID_PUBLIC_KEY_MLDSA87)
    {
        if !algo.parameters.full_bytes.is_empty() {
            return Err(Error::new("x509: invalid ML-DSA private key parameters"));
        }
        let pk = &priv_key.private_key;
        if pk.is_empty() {
            return Err(Error::new("x509: invalid ML-DSA private key length: 0"));
        }
        match pk[0] {
            0x80 => {}
            0x04 => {
                return Err(Error::new(
                    "x509: semi-expanded ML-DSA private keys without seed are not supported",
                ))
            }
            0x30 => {
                return Err(Error::new(
                    "x509: ML-DSA private keys with both seed and expanded key are not supported, use e.g. \"openssl pkey -provparam ml-dsa.output_formats=seed-only\" to convert to a seed-only key",
                ))
            }
            other => {
                return Err(Error::new(format!(
                    "x509: invalid ML-DSA private key: invalid ASN.1 tag {other:02x}"
                )))
            }
        }
        if pk.len() != 2 + mldsa::PRIVATE_KEY_SIZE {
            return Err(Error::new(format!(
                "x509: invalid ML-DSA private key length: {}",
                pk.len()
            )));
        }
        if pk[1] as usize != mldsa::PRIVATE_KEY_SIZE {
            return Err(Error::new(
                "x509: invalid ML-DSA private key ASN.1 encoding",
            ));
        }
        let Some(params) = mldsa_parameters_from_oid(oid) else {
            return Err(Error::new("x509: unknown ML-DSA parameters"));
        };
        mldsa::PrivateKey::from_seed(params, &pk[2..])
            .map(PrivateKey::Mldsa)
            .map_err(|e| Error::new(e.to_string()))
    } else if oid.is(&OID_PUBLIC_KEY_X25519) {
        if !algo.parameters.full_bytes.is_empty() {
            return Err(Error::new("x509: invalid X25519 private key parameters"));
        }
        unmarshal(&priv_key.private_key, Ty::Octets)
            .map_err(|e| Error::new(format!("x509: invalid X25519 private key: {e}")))?;
        let curve_private_key = Reader(&priv_key.private_key)
            .read(asn1::OCTET_STRING)
            .map(|b| b.to_vec())
            .ok_or_else(|| asn1_structure("tags don't match"))?;
        ecdh::x25519()
            .private_key_from_bytes(&curve_private_key)
            .map(PrivateKey::Ecdh)
            .map_err(|e| Error::new(e.to_string()))
    } else {
        Err(Error::new(format!(
            "x509: PKCS#8 wrapping contained private key with unknown algorithm: {oid}"
        )))
    }
}

/// Go's `MarshalPKCS8PrivateKey`: converts a private key to PKCS #8, ASN.1 DER
/// form. The key is one of the concrete private key types or a
/// [`PrivateKey`].
pub fn marshal_pkcs8_private_key(key: &dyn Any) -> Result<Vec<u8>, Error> {
    let key = key
        .downcast_ref::<PrivateKey>()
        .map(PrivateKey::as_any)
        .unwrap_or(key);
    let (algorithm, private_key): (AlgorithmIdentifier, Vec<u8>);
    if let Some(k) = key.downcast_ref::<rsa::PrivateKey>() {
        let mut k = k.clone();
        k.precompute();
        k.validate().map_err(|e| Error::new(e.to_string()))?;
        algorithm = AlgorithmIdentifier {
            algorithm: ObjectIdentifier(OID_PUBLIC_KEY_RSA.to_vec()),
            parameters: RawValue::null(),
        };
        private_key = marshal_pkcs1_private_key(&k);
    } else if let Some(k) = key.downcast_ref::<ecdsa::PrivateKey>() {
        let Some(oid) = oid_from_named_curve(&k.public_key.curve) else {
            return Err(Error::new("x509: unknown curve while marshaling to PKCS#8"));
        };
        algorithm = AlgorithmIdentifier {
            algorithm: ObjectIdentifier(OID_PUBLIC_KEY_ECDSA.to_vec()),
            parameters: RawValue::from_full_bytes(asn1::oid(&oid.0).expect("valid curve OID")),
        };
        private_key = marshal_ec_private_key_with_oid(k, None).map_err(|e| {
            Error::new(format!(
                "x509: failed to marshal EC private key while building PKCS#8: {e}"
            ))
        })?;
    } else if let Some(k) = key.downcast_ref::<ed25519::PrivateKey>() {
        algorithm = AlgorithmIdentifier {
            algorithm: ObjectIdentifier(OID_PUBLIC_KEY_ED25519.to_vec()),
            parameters: RawValue::default(),
        };
        private_key = asn1::octet_string(&k.seed());
    } else if let Some(k) = key.downcast_ref::<mldsa::PrivateKey>() {
        let Some(oid) = oid_from_mldsa_parameters(k.public_key().parameters()) else {
            return Err(Error::new(
                "x509: unknown ML-DSA parameters while marshaling to PKCS#8",
            ));
        };
        algorithm = AlgorithmIdentifier {
            algorithm: oid,
            parameters: RawValue::default(),
        };
        let mut pk = vec![0x80, mldsa::PRIVATE_KEY_SIZE as u8];
        pk.extend(k.bytes());
        private_key = pk;
    } else if let Some(k) = key.downcast_ref::<ecdh::PrivateKey>() {
        if k.curve().name() == "X25519" {
            algorithm = AlgorithmIdentifier {
                algorithm: ObjectIdentifier(OID_PUBLIC_KEY_X25519.to_vec()),
                parameters: RawValue::default(),
            };
            private_key = asn1::octet_string(&k.bytes());
        } else {
            let Some(oid) = oid_from_ecdh_curve(k.curve()) else {
                return Err(Error::new("x509: unknown curve while marshaling to PKCS#8"));
            };
            algorithm = AlgorithmIdentifier {
                algorithm: ObjectIdentifier(OID_PUBLIC_KEY_ECDSA.to_vec()),
                parameters: RawValue::from_full_bytes(asn1::oid(&oid.0).expect("valid curve OID")),
            };
            private_key = marshal_ec_private_key_fields(&k.bytes(), None, &k.public_key().bytes());
        }
    } else {
        return Err(Error::new(
            "x509: unknown key type while marshaling PKCS#8: unknown",
        ));
    }
    let mut content = asn1::integer_i64(0);
    content.extend(algorithm.marshal()?);
    content.extend(asn1::octet_string(&private_key));
    Ok(asn1::tlv(asn1::SEQUENCE, &content))
}
