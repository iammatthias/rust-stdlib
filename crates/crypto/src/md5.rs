//! MD5, compatible with Go's `crypto/md5`.
//!
//! MD5 is cryptographically broken and unsuitable for security purposes.
//! Input arrives through [`std::io::Write`] or [`Digest::update`], and
//! `marshal_binary` produces Go's `md5\x01` state format.

use crate::engine::{digest_type, Fixed, Messages};
use crate::Hash;

/// The size of an MD5 checksum in bytes.
pub const SIZE: usize = 16;

/// The blocksize of MD5 in bytes.
pub const BLOCK_SIZE: usize = 64;

static MESSAGES: Messages = Messages {
    identifier: "crypto/md5: invalid hash state identifier",
    size: "crypto/md5: invalid hash state size",
    state: "crypto/md5: invalid hash state",
};

digest_type!(
    /// A running MD5 computation (the value Go's `md5.New` returns as `hash.Hash`).
    Digest
);

/// Returns a new MD5 computation.
pub fn new() -> Digest {
    Digest {
        inner: Fixed::new(Hash::Md5, &MESSAGES),
    }
}

/// Returns the MD5 checksum of the data.
pub fn sum(data: &[u8]) -> [u8; SIZE] {
    let mut digest = new();
    digest.update(data);
    let mut out = Vec::with_capacity(SIZE);
    digest.sum(&mut out);
    out.try_into().expect("MD5 digests are 16 bytes")
}
