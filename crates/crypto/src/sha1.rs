//! SHA-1, compatible with Go's `crypto/sha1`.
//!
//! SHA-1 is cryptographically broken and unsuitable for security purposes.
//! `marshal_binary` produces Go's `sha\x01` state format.

use crate::engine::{digest_type, Fixed, Messages};
use crate::Hash;

/// The size of a SHA-1 checksum in bytes.
pub const SIZE: usize = 20;

/// The blocksize of SHA-1 in bytes.
pub const BLOCK_SIZE: usize = 64;

static MESSAGES: Messages = Messages {
    identifier: "crypto/sha1: invalid hash state identifier",
    size: "crypto/sha1: invalid hash state size",
    state: "crypto/sha1: invalid hash state",
};

digest_type!(
    /// A running SHA-1 computation (the value Go's `sha1.New` returns as `hash.Hash`).
    Digest
);

/// Returns a new SHA-1 computation.
pub fn new() -> Digest {
    Digest {
        inner: Fixed::new(Hash::Sha1, &MESSAGES),
    }
}

/// Returns the SHA-1 checksum of the data.
pub fn sum(data: &[u8]) -> [u8; SIZE] {
    let mut digest = new();
    digest.update(data);
    let mut out = Vec::with_capacity(SIZE);
    digest.sum(&mut out);
    out.try_into().expect("SHA-1 digests are 20 bytes")
}
