//! SHA-384, SHA-512, SHA-512/224 and SHA-512/256, compatible with Go's
//! `crypto/sha512`.
//!
//! `marshal_binary` produces Go's `sha\x04` to `sha\x07` state formats.

use crate::engine::{digest_type, Fixed, Messages};
use crate::Hash;

/// The size of a SHA-512 checksum in bytes.
pub const SIZE: usize = 64;

/// The size of a SHA-512/224 checksum in bytes.
pub const SIZE224: usize = 28;

/// The size of a SHA-512/256 checksum in bytes.
pub const SIZE256: usize = 32;

/// The size of a SHA-384 checksum in bytes.
pub const SIZE384: usize = 48;

/// The blocksize of SHA-512 and its variants in bytes.
pub const BLOCK_SIZE: usize = 128;

static MESSAGES: Messages = Messages {
    identifier: "crypto/sha512: invalid hash state identifier",
    size: "crypto/sha512: invalid hash state size",
    state: "crypto/sha512: invalid hash state",
};

digest_type!(
    /// A running SHA-512 family computation (Go's unexported digest).
    Digest
);

/// Returns a new SHA-512 computation.
pub fn new() -> Digest {
    Digest {
        inner: Fixed::new(Hash::Sha512, &MESSAGES),
    }
}

/// Returns a new SHA-512/224 computation.
pub fn new512_224() -> Digest {
    Digest {
        inner: Fixed::new(Hash::Sha512_224, &MESSAGES),
    }
}

/// Returns a new SHA-512/256 computation.
pub fn new512_256() -> Digest {
    Digest {
        inner: Fixed::new(Hash::Sha512_256, &MESSAGES),
    }
}

/// Returns a new SHA-384 computation.
pub fn new384() -> Digest {
    Digest {
        inner: Fixed::new(Hash::Sha384, &MESSAGES),
    }
}

fn sum_with<const N: usize>(mut digest: Digest, data: &[u8]) -> [u8; N] {
    digest.update(data);
    let mut out = Vec::with_capacity(N);
    digest.sum(&mut out);
    out.try_into()
        .expect("digest length matches the requested array")
}

/// Returns the SHA-512 checksum of the data.
pub fn sum512(data: &[u8]) -> [u8; SIZE] {
    sum_with(new(), data)
}

/// Returns the SHA-384 checksum of the data.
pub fn sum384(data: &[u8]) -> [u8; SIZE384] {
    sum_with(new384(), data)
}

/// Returns the SHA-512/224 checksum of the data.
pub fn sum512_224(data: &[u8]) -> [u8; SIZE224] {
    sum_with(new512_224(), data)
}

/// Returns the SHA-512/256 checksum of the data.
pub fn sum512_256(data: &[u8]) -> [u8; SIZE256] {
    sum_with(new512_256(), data)
}
