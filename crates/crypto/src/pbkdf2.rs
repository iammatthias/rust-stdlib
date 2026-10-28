//! Password-based key derivation (PBKDF2, RFC 8018), compatible with Go's
//! `crypto/pbkdf2`.
//!
//! The computation runs on the reviewed RustCrypto `pbkdf2` crate. The hash
//! constructor must produce one of this crate's hashes, as for [`crate::hmac`].

use std::fmt;

use crate::hash::{self, UnsupportedHashError};
use crate::hmac::with_digest;

/// Errors from [`key`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// `key_length` was zero.
    KeyLengthNotPositive,
    /// `key_length` needs more than 2^32-1 blocks.
    KeyLengthTooLong,
    /// The hash function is not provided by this crate.
    UnsupportedHash,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::KeyLengthNotPositive => f.write_str("pbkdf2: keyLength must be larger than 0"),
            Error::KeyLengthTooLong => f.write_str("pbkdf2: keyLength too long"),
            Error::UnsupportedHash => UnsupportedHashError.fmt(f),
        }
    }
}

impl std::error::Error for Error {}

/// Derives `key_length` bytes from the password and salt with `iterations`
/// rounds of HMAC over the hash produced by `h`.
///
/// Go takes the password as a string and the iteration count as an `int`; a
/// byte slice and `u32` cover every practical value, and zero iterations act
/// as one, like Go.
pub fn key<H: hash::Hash, F: FnOnce() -> H>(
    h: F,
    password: impl AsRef<[u8]>,
    salt: &[u8],
    iterations: u32,
    key_length: usize,
) -> Result<Vec<u8>, Error> {
    let algorithm = h().crypto_hash().ok_or(Error::UnsupportedHash)?;
    if key_length == 0 {
        return Err(Error::KeyLengthNotPositive);
    }
    let blocks = key_length.div_ceil(algorithm.size());
    if key_length.checked_add(algorithm.size()).is_none() || blocks as u128 > u128::from(u32::MAX) {
        return Err(Error::KeyLengthTooLong);
    }
    with_digest!(algorithm, D => {
        let mut out = vec![0; key_length];
        ::pbkdf2::pbkdf2::<::hmac::SimpleHmac<D>>(password.as_ref(), salt, iterations, &mut out)
            .expect("HMAC accepts passwords of any length");
        Ok(out)
    }, else Err(Error::UnsupportedHash))
}
