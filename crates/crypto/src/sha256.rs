//! SHA-224 and SHA-256, compatible with Go's `crypto/sha256`.
//!
//! `marshal_binary` produces Go's `sha\x02` (SHA-224) and `sha\x03` (SHA-256)
//! state formats.

use crate::engine::{digest_type, Fixed, Messages};
use crate::Hash;

/// The size of a SHA-256 checksum in bytes.
pub const SIZE: usize = 32;

/// The size of a SHA-224 checksum in bytes.
pub const SIZE224: usize = 28;

/// The blocksize of SHA-256 and SHA-224 in bytes.
pub const BLOCK_SIZE: usize = 64;

static MESSAGES: Messages = Messages {
    identifier: "crypto/sha256: invalid hash state identifier",
    size: "crypto/sha256: invalid hash state size",
    state: "crypto/sha256: invalid hash state",
};

digest_type!(
    /// A running SHA-256 or SHA-224 computation (Go's unexported digest).
    Digest
);

/// Returns a new SHA-256 computation.
pub fn new() -> Digest {
    Digest {
        inner: Fixed::new(Hash::Sha256, &MESSAGES),
    }
}

/// Returns a new SHA-224 computation.
pub fn new224() -> Digest {
    Digest {
        inner: Fixed::new(Hash::Sha224, &MESSAGES),
    }
}

/// Returns the SHA-256 checksum of the data.
pub fn sum256(data: &[u8]) -> [u8; SIZE] {
    let mut digest = new();
    digest.update(data);
    let mut out = Vec::with_capacity(SIZE);
    digest.sum(&mut out);
    out.try_into().expect("SHA-256 digests are 32 bytes")
}

/// Returns the SHA-224 checksum of the data.
pub fn sum224(data: &[u8]) -> [u8; SIZE224] {
    let mut digest = new224();
    digest.update(data);
    let mut out = Vec::with_capacity(SIZE224);
    digest.sum(&mut out);
    out.try_into().expect("SHA-224 digests are 28 bytes")
}
