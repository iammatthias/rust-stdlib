//! Go's `hash` interfaces as used by the `crypto/*` packages.
//!
//! The root crate has no shared hash trait (its non-cryptographic hashers
//! expose inherent methods), so the cryptographic packages define the Go
//! `hash.Hash` surface here. Input arrives through [`std::io::Write`], whose
//! writes never fail for the hashes in this crate.

use std::io;

/// Go's `hash.Hash` plus `hash.Cloner`: a running hash computation.
pub trait Hash: io::Write + Send + Sync {
    /// Appends the current digest to `into` without changing the running
    /// state, like `hash.Hash.Sum`.
    fn sum(&self, into: &mut Vec<u8>);

    /// Resets the hash to its initial state.
    fn reset(&mut self);

    /// Returns the number of bytes `sum` appends.
    fn size(&self) -> usize;

    /// Returns the hash's underlying block size.
    fn block_size(&self) -> usize;

    /// Returns an independent copy of the running state, like `hash.Cloner.Clone`.
    fn clone_hash(&self) -> Box<dyn Hash>;

    /// Identifies which [`crate::Hash`] this computation implements, when it is
    /// one of the hash functions of this crate. HMAC, HKDF and PBKDF2 are built
    /// over the reviewed RustCrypto implementations and need this identity.
    fn crypto_hash(&self) -> Option<crate::Hash> {
        None
    }
}

impl Hash for Box<dyn Hash> {
    fn sum(&self, into: &mut Vec<u8>) {
        (**self).sum(into);
    }

    fn reset(&mut self) {
        (**self).reset();
    }

    fn size(&self) -> usize {
        (**self).size()
    }

    fn block_size(&self) -> usize {
        (**self).block_size()
    }

    fn clone_hash(&self) -> Box<dyn Hash> {
        (**self).clone_hash()
    }

    fn crypto_hash(&self) -> Option<crate::Hash> {
        (**self).crypto_hash()
    }
}

/// Error returned by HMAC, HKDF and PBKDF2 when the supplied hash function is
/// not one of this crate's [`crate::Hash`] implementations.
///
/// Go accepts any `hash.Hash`. The keyed constructions here run on the
/// reviewed RustCrypto implementations, which need to know the algorithm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedHashError;

impl std::fmt::Display for UnsupportedHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("crypto: hash function is not provided by rust_stdlib_crypto")
    }
}

impl std::error::Error for UnsupportedHashError {}

/// Error returned when a serialized hash state is malformed or incompatible.
///
/// Messages are Go's, for example `crypto/sha256: invalid hash state size`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateError(&'static str);

impl StateError {
    #[cfg(any(
        feature = "md5",
        feature = "sha1",
        feature = "sha256",
        feature = "sha512",
        feature = "sha3"
    ))]
    pub(crate) const fn new(message: &'static str) -> Self {
        Self(message)
    }

    /// Returns the Go-compatible error message.
    pub const fn message(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for StateError {}
