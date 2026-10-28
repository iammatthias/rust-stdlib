//! HMAC-based key derivation (RFC 5869), compatible with Go's `crypto/hkdf`.
//!
//! The computation runs on the reviewed RustCrypto `hkdf` crate. The hash
//! constructor must produce one of this crate's hashes, as for [`crate::hmac`].

use std::fmt;

use crate::hash::{self, UnsupportedHashError};
use crate::hmac::with_digest;
use crate::Hash;

/// Errors from [`extract`], [`expand`] and [`key`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The requested length exceeds 255 times the hash size.
    KeyLengthTooLarge,
    /// The hash function is not provided by this crate.
    UnsupportedHash,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::KeyLengthTooLarge => f.write_str("hkdf: requested key length too large"),
            Error::UnsupportedHash => UnsupportedHashError.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

fn identify<H: hash::Hash, F: FnOnce() -> H>(h: F) -> Result<Hash, Error> {
    h().crypto_hash().ok_or(Error::UnsupportedHash)
}

/// HKDF-Extract: returns a pseudorandom key from the secret and salt. An
/// empty salt acts as a string of zeros, as in the RFC.
pub fn extract<H: hash::Hash, F: FnOnce() -> H>(
    h: F,
    secret: &[u8],
    salt: &[u8],
) -> Result<Vec<u8>, Error> {
    let algorithm = identify(h)?;
    with_digest!(algorithm, D => {
        let (prk, _) = ::hkdf::SimpleHkdf::<D>::extract(Some(salt), secret);
        Ok(prk.to_vec())
    }, else Err(Error::UnsupportedHash))
}

/// HKDF-Expand: returns `key_length` bytes of output keying material.
///
/// Like Go, a pseudorandom key shorter than the hash size is accepted.
pub fn expand<H: hash::Hash, F: FnOnce() -> H>(
    h: F,
    pseudorandom_key: &[u8],
    info: impl AsRef<[u8]>,
    key_length: usize,
) -> Result<Vec<u8>, Error> {
    let algorithm = identify(h)?;
    with_digest!(algorithm, D => {
        if key_length > algorithm.size() * 255 {
            return Err(Error::KeyLengthTooLarge);
        }
        // HMAC zero-pads keys shorter than a block, so padding a short key to
        // the hash size changes nothing and satisfies the crate's RFC check.
        let mut prk = pseudorandom_key.to_vec();
        if prk.len() < algorithm.size() {
            prk.resize(algorithm.size(), 0);
        }
        let expander = ::hkdf::SimpleHkdf::<D>::from_prk(&prk).expect("the key is at least the hash size");
        let mut out = vec![0; key_length];
        expander.expand(info.as_ref(), &mut out).map_err(|_| Error::KeyLengthTooLarge)?;
        Ok(out)
    }, else Err(Error::UnsupportedHash))
}

/// HKDF extract-then-expand: derives `key_length` bytes from the secret, salt
/// and info.
pub fn key<H: hash::Hash, F: Fn() -> H>(
    h: F,
    secret: &[u8],
    salt: &[u8],
    info: impl AsRef<[u8]>,
    key_length: usize,
) -> Result<Vec<u8>, Error> {
    let algorithm = identify(&h)?;
    if key_length > algorithm.size() * 255 {
        return Err(Error::KeyLengthTooLarge);
    }
    let prk = extract(&h, secret, salt)?;
    expand(&h, &prk, info, key_length)
}
