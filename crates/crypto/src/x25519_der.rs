//! PKIX and PKCS #8 DER for X25519 keys (RFC 8410), built with the reviewed
//! `pkcs8`, `spki` and `der` crates.

use p256::pkcs8::der::asn1::{BitString, OctetString};
use p256::pkcs8::der::{Decode, Encode};
use p256::pkcs8::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use p256::pkcs8::{ObjectIdentifier, PrivateKeyInfoOwned};

const X25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.110");

fn algorithm() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: X25519,
        parameters: None,
    }
}

pub(crate) fn public_to_pkix(key: &[u8]) -> Option<Vec<u8>> {
    let info = SubjectPublicKeyInfoOwned {
        algorithm: algorithm(),
        subject_public_key: BitString::from_bytes(key).ok()?,
    };
    info.to_der().ok()
}

pub(crate) fn public_from_pkix(der: &[u8]) -> Option<Vec<u8>> {
    let info = SubjectPublicKeyInfoOwned::from_der(der).ok()?;
    if info.algorithm.oid != X25519 || info.algorithm.parameters.is_some() {
        return None;
    }
    let key = info.subject_public_key.as_bytes()?;
    (key.len() == 32).then(|| key.to_vec())
}

pub(crate) fn private_to_pkcs8(key: &[u8]) -> Option<Vec<u8>> {
    let inner = OctetString::new(key).ok()?.to_der().ok()?;
    let info = PrivateKeyInfoOwned::new(algorithm(), OctetString::new(inner).ok()?);
    info.to_der().ok()
}

pub(crate) fn private_from_pkcs8(der: &[u8]) -> Option<Vec<u8>> {
    let info = PrivateKeyInfoOwned::from_der(der).ok()?;
    if info.algorithm.oid != X25519 || info.algorithm.parameters.is_some() {
        return None;
    }
    let inner = OctetString::from_der(info.private_key.as_bytes()).ok()?;
    (inner.as_bytes().len() == 32).then(|| inner.as_bytes().to_vec())
}
