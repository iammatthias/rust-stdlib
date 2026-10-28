//! Keyed-hash message authentication (HMAC), compatible with Go's `crypto/hmac`.
//!
//! The computation runs on the reviewed RustCrypto `hmac` crate. Go's `New`
//! accepts any `hash.Hash` constructor; here the constructor must produce one
//! of this crate's hashes (see [`crate::Hash`]), otherwise [`new`] returns
//! [`UnsupportedHashError`].

use std::io;

use ::hmac::digest::common::BlockSizeUser;
use ::hmac::digest::Mac;
use ::hmac::digest::{Digest, Reset};
use ::hmac::{KeyInit, SimpleHmacReset};

use crate::hash::{self, UnsupportedHashError};
use crate::Hash;

/// Runs `$body` with the type alias `$d` naming the RustCrypto digest for
/// `$hash`, or evaluates `$fallback` for hash functions without one.
macro_rules! with_digest {
    ($hash:expr, $d:ident => $body:expr, else $fallback:expr) => {
        match $hash {
            #[cfg(feature = "md5")]
            $crate::Hash::Md5 => {
                type $d = ::md5::Md5;
                $body
            }
            #[cfg(feature = "sha1")]
            $crate::Hash::Sha1 => {
                type $d = ::sha1::Sha1;
                $body
            }
            #[cfg(feature = "sha256")]
            $crate::Hash::Sha224 => {
                type $d = ::sha2::Sha224;
                $body
            }
            #[cfg(feature = "sha256")]
            $crate::Hash::Sha256 => {
                type $d = ::sha2::Sha256;
                $body
            }
            #[cfg(feature = "sha512")]
            $crate::Hash::Sha384 => {
                type $d = ::sha2::Sha384;
                $body
            }
            #[cfg(feature = "sha512")]
            $crate::Hash::Sha512 => {
                type $d = ::sha2::Sha512;
                $body
            }
            #[cfg(feature = "sha512")]
            $crate::Hash::Sha512_224 => {
                type $d = ::sha2::Sha512_224;
                $body
            }
            #[cfg(feature = "sha512")]
            $crate::Hash::Sha512_256 => {
                type $d = ::sha2::Sha512_256;
                $body
            }
            #[cfg(feature = "sha3")]
            $crate::Hash::Sha3_224 => {
                type $d = ::sha3::Sha3_224;
                $body
            }
            #[cfg(feature = "sha3")]
            $crate::Hash::Sha3_256 => {
                type $d = ::sha3::Sha3_256;
                $body
            }
            #[cfg(feature = "sha3")]
            $crate::Hash::Sha3_384 => {
                type $d = ::sha3::Sha3_384;
                $body
            }
            #[cfg(feature = "sha3")]
            $crate::Hash::Sha3_512 => {
                type $d = ::sha3::Sha3_512;
                $body
            }
            _ => $fallback,
        }
    };
}

#[cfg(any(feature = "hkdf", feature = "pbkdf2"))]
pub(crate) use with_digest;

trait Keyed: Send + Sync {
    fn update(&mut self, data: &[u8]);
    fn finalize(&self) -> Vec<u8>;
    fn reset(&mut self);
    fn boxed_clone(&self) -> Box<dyn Keyed>;
    fn size(&self) -> usize;
}

impl<D> Keyed for SimpleHmacReset<D>
where
    D: Digest + Reset + BlockSizeUser + Send + Sync + 'static,
    SimpleHmacReset<D>: Mac + KeyInit + Clone + Send + Sync,
{
    fn update(&mut self, data: &[u8]) {
        Mac::update(self, data);
    }

    fn finalize(&self) -> Vec<u8> {
        Mac::finalize(self.clone()).into_bytes().to_vec()
    }

    fn reset(&mut self) {
        Mac::reset(self);
    }

    fn boxed_clone(&self) -> Box<dyn Keyed> {
        Box::new(self.clone())
    }

    fn size(&self) -> usize {
        <SimpleHmacReset<D> as ::hmac::digest::OutputSizeUser>::output_size()
    }
}

/// A running HMAC computation, returned by [`new`].
pub struct Hmac {
    core: Box<dyn Keyed>,
    algorithm: Hash,
    block_size: usize,
}

impl std::fmt::Debug for Hmac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hmac")
            .field("hash", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// Returns an HMAC computation using the hash produced by `h` and the key.
///
/// ```
/// use rust_stdlib_crypto::{hmac, sha256};
/// use std::io::Write;
///
/// let mut mac = hmac::new(sha256::new, b"key").unwrap();
/// mac.write_all(b"The quick brown fox jumps over the lazy dog").unwrap();
/// let mut tag = Vec::new();
/// mac.sum(&mut tag);
/// assert_eq!(tag[..4], [0xf7, 0xbc, 0x83, 0xf4]);
/// assert!(hmac::equal(&tag, &tag.clone()));
/// ```
pub fn new<H, F>(h: F, key: &[u8]) -> Result<Hmac, UnsupportedHashError>
where
    H: hash::Hash,
    F: FnOnce() -> H,
{
    let algorithm = h().crypto_hash().ok_or(UnsupportedHashError)?;
    Hmac::new(algorithm, key)
}

impl Hmac {
    /// Returns an HMAC computation for a [`enum@Hash`] identifier and the key.
    pub fn new(algorithm: Hash, key: &[u8]) -> Result<Self, UnsupportedHashError> {
        with_digest!(algorithm, D => {
            let mac = <SimpleHmacReset<D> as KeyInit>::new_from_slice(key).expect("HMAC accepts keys of any length");
            Ok(Self {
                core: Box::new(mac),
                algorithm,
                block_size: <D as BlockSizeUser>::block_size(),
            })
        }, else Err(UnsupportedHashError))
    }

    /// Adds bytes to the authenticated message.
    pub fn update(&mut self, bytes: &[u8]) {
        self.core.update(bytes);
    }

    /// Appends the current MAC to `into` without changing the state.
    pub fn sum(&self, into: &mut Vec<u8>) {
        into.extend_from_slice(&self.core.finalize());
    }

    /// Returns to the state right after [`new`], keeping the key.
    pub fn reset(&mut self) {
        self.core.reset();
    }

    /// Returns the MAC length in bytes, the size of the underlying hash.
    pub fn size(&self) -> usize {
        self.core.size()
    }

    /// Returns the block size of the underlying hash.
    pub fn block_size(&self) -> usize {
        self.block_size
    }
}

impl Clone for Hmac {
    fn clone(&self) -> Self {
        Self {
            core: self.core.boxed_clone(),
            algorithm: self.algorithm,
            block_size: self.block_size,
        }
    }
}

impl io::Write for Hmac {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.core.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl hash::Hash for Hmac {
    fn sum(&self, into: &mut Vec<u8>) {
        Hmac::sum(self, into);
    }

    fn reset(&mut self) {
        Hmac::reset(self);
    }

    fn size(&self) -> usize {
        Hmac::size(self)
    }

    fn block_size(&self) -> usize {
        Hmac::block_size(self)
    }

    fn clone_hash(&self) -> Box<dyn hash::Hash> {
        Box::new(self.clone())
    }
}

/// Compares two MACs for equality without leaking timing information.
pub fn equal(mac1: &[u8], mac2: &[u8]) -> bool {
    crate::subtle::constant_time_compare(mac1, mac2) == 1
}
