//! Shared fixed-output digest engine over the reviewed RustCrypto crates.
//!
//! No primitive lives here. The engine erases the concrete RustCrypto type,
//! and translates the dependencies' public `SerializableState` bytes to and
//! from the binary layout of Go's `encoding.BinaryMarshaler` implementations.

use ::digest::common::hazmat::{SerializableState, SerializedState};
use ::digest::common::BlockSizeUser;
use ::digest::{Digest, Reset};

use crate::hash::StateError;
use crate::Hash as Algorithm;

pub(crate) trait Core: Send + Sync {
    fn update(&mut self, data: &[u8]);
    fn finalize(&self) -> Vec<u8>;
    fn reset(&mut self);
    fn size(&self) -> usize;
    fn block_size(&self) -> usize;
    fn boxed_clone(&self) -> Box<dyn Core>;
    fn serialize(&self) -> Vec<u8>;
    fn deserialize(&mut self, bytes: &[u8]) -> bool;
}

impl<D> Core for D
where
    D: Digest + Reset + Clone + SerializableState + BlockSizeUser + Send + Sync + 'static,
{
    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data);
    }

    fn finalize(&self) -> Vec<u8> {
        Digest::finalize(self.clone()).to_vec()
    }

    fn reset(&mut self) {
        Reset::reset(self);
    }

    fn size(&self) -> usize {
        <D as Digest>::output_size()
    }

    fn block_size(&self) -> usize {
        <D as BlockSizeUser>::block_size()
    }

    fn boxed_clone(&self) -> Box<dyn Core> {
        Box::new(self.clone())
    }

    fn serialize(&self) -> Vec<u8> {
        SerializableState::serialize(self).to_vec()
    }

    fn deserialize(&mut self, bytes: &[u8]) -> bool {
        let Ok(state) = SerializedState::<D>::try_from(bytes) else {
            return false;
        };
        match D::deserialize(&state) {
            Ok(restored) => {
                *self = restored;
                true
            }
            Err(_) => false,
        }
    }
}

/// How a Merkle-Damgard digest's state words are laid out in Go's format.
struct Layout {
    magic: &'static [u8; 4],
    words: usize,
    word: usize,
    block: usize,
    /// Width of RustCrypto's block counter (the serialized count of blocks).
    counter: usize,
}

const SHA3_MAGIC: &[u8; 4] = b"sha\x08";
const SPONGE_STATE: usize = 200;

fn layout(algorithm: Algorithm) -> Option<Layout> {
    let (magic, words, word, block, counter): (&'static [u8; 4], usize, usize, usize, usize) =
        match algorithm {
            Algorithm::Md5 => (b"md5\x01", 4, 4, 64, 8),
            Algorithm::Sha1 => (b"sha\x01", 5, 4, 64, 8),
            Algorithm::Sha224 => (b"sha\x02", 8, 4, 64, 8),
            Algorithm::Sha256 => (b"sha\x03", 8, 4, 64, 8),
            Algorithm::Sha384 => (b"sha\x04", 8, 8, 128, 16),
            Algorithm::Sha512_224 => (b"sha\x05", 8, 8, 128, 16),
            Algorithm::Sha512_256 => (b"sha\x06", 8, 8, 128, 16),
            Algorithm::Sha512 => (b"sha\x07", 8, 8, 128, 16),
            _ => return None,
        };
    Some(Layout {
        magic,
        words,
        word,
        block,
        counter,
    })
}

fn new_core(algorithm: Algorithm) -> Box<dyn Core> {
    match algorithm {
        #[cfg(feature = "md5")]
        Algorithm::Md5 => Box::new(::md5::Md5::default()),
        #[cfg(feature = "sha1")]
        Algorithm::Sha1 => Box::new(::sha1::Sha1::default()),
        #[cfg(feature = "sha256")]
        Algorithm::Sha224 => Box::new(::sha2::Sha224::default()),
        #[cfg(feature = "sha256")]
        Algorithm::Sha256 => Box::new(::sha2::Sha256::default()),
        #[cfg(feature = "sha512")]
        Algorithm::Sha384 => Box::new(::sha2::Sha384::default()),
        #[cfg(feature = "sha512")]
        Algorithm::Sha512 => Box::new(::sha2::Sha512::default()),
        #[cfg(feature = "sha512")]
        Algorithm::Sha512_224 => Box::new(::sha2::Sha512_224::default()),
        #[cfg(feature = "sha512")]
        Algorithm::Sha512_256 => Box::new(::sha2::Sha512_256::default()),
        #[cfg(feature = "sha3")]
        Algorithm::Sha3_224 => Box::new(::sha3::Sha3_224::default()),
        #[cfg(feature = "sha3")]
        Algorithm::Sha3_256 => Box::new(::sha3::Sha3_256::default()),
        #[cfg(feature = "sha3")]
        Algorithm::Sha3_384 => Box::new(::sha3::Sha3_384::default()),
        #[cfg(feature = "sha3")]
        Algorithm::Sha3_512 => Box::new(::sha3::Sha3_512::default()),
        _ => unreachable!("only implemented hash functions reach the engine"),
    }
}

/// A running fixed-output digest with Go's `hash.Hash` and binary state surface.
pub(crate) struct Fixed {
    core: Box<dyn Core>,
    algorithm: Algorithm,
    messages: &'static Messages,
}

impl Fixed {
    pub(crate) fn new(algorithm: Algorithm, messages: &'static Messages) -> Self {
        Self {
            core: new_core(algorithm),
            algorithm,
            messages,
        }
    }

    pub(crate) fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    pub(crate) fn sum(&self, into: &mut Vec<u8>) {
        into.extend_from_slice(&self.core.finalize());
    }

    pub(crate) fn reset(&mut self) {
        self.core.reset();
    }

    pub(crate) fn size(&self) -> usize {
        self.core.size()
    }

    pub(crate) fn block_size(&self) -> usize {
        self.core.block_size()
    }

    pub(crate) fn duplicate(&self) -> Self {
        Self {
            core: self.core.boxed_clone(),
            algorithm: self.algorithm,
            messages: self.messages,
        }
    }

    pub(crate) fn append_binary(&self, into: &mut Vec<u8>) {
        let state = self.core.serialize();
        match layout(self.algorithm) {
            Some(layout) => append_merkle_damgard(&layout, &state, into),
            None => append_sponge(self.core.block_size(), &state, into),
        }
    }

    pub(crate) fn unmarshal_binary(&mut self, bytes: &[u8]) -> Result<(), StateError> {
        match layout(self.algorithm) {
            Some(layout) => {
                let marshaled = layout.magic.len() + layout.words * layout.word + layout.block + 8;
                if bytes.len() < layout.magic.len() || &bytes[..4] != layout.magic {
                    return Err(StateError::new(self.messages.identifier));
                }
                if bytes.len() != marshaled {
                    return Err(StateError::new(self.messages.size));
                }
                let restored = restore_merkle_damgard(&layout, bytes);
                if !self.core.deserialize(&restored) {
                    return Err(StateError::new(self.messages.state));
                }
            }
            None => {
                let marshaled = SHA3_MAGIC.len() + 1 + SPONGE_STATE + 2;
                if bytes.len() != marshaled {
                    return Err(StateError::new("sha3: invalid hash state"));
                }
                if &bytes[..4] != SHA3_MAGIC {
                    return Err(StateError::new("sha3: invalid hash state identifier"));
                }
                if usize::from(bytes[4]) != self.core.block_size() {
                    return Err(StateError::new("sha3: invalid hash state function"));
                }
                // Go's lanes already hold the absorbed bytes; RustCrypto keeps
                // them in a block buffer in front of the core state, so the
                // restored state has the lanes as they are and a buffer of
                // zeros (XORing zeros changes nothing) of the same length.
                // Only the absorbing direction exists for the fixed-output type.
                let rate = self.core.block_size();
                let buffered = usize::from(bytes[5 + SPONGE_STATE]);
                if buffered >= rate || bytes[6 + SPONGE_STATE] != 0 {
                    return Err(StateError::new("sha3: invalid hash state"));
                }
                let mut restored = bytes[5..5 + SPONGE_STATE].to_vec();
                restored.push(buffered as u8);
                restored.resize(SPONGE_STATE + rate, 0);
                if !self.core.deserialize(&restored) {
                    return Err(StateError::new("sha3: invalid hash state"));
                }
            }
        }
        Ok(())
    }
}

/// Go's per-package state error messages.
pub(crate) struct Messages {
    pub(crate) identifier: &'static str,
    pub(crate) size: &'static str,
    pub(crate) state: &'static str,
}

/// Go: `magic || big-endian words || block buffer || big-endian byte length`.
/// RustCrypto: `little-endian words || block counter || buffered length || buffer (block - 1 bytes)`.
fn append_merkle_damgard(layout: &Layout, state: &[u8], into: &mut Vec<u8>) {
    let words_len = layout.words * layout.word;
    let (words, rest) = state.split_at(words_len);
    let (counter, rest) = rest.split_at(layout.counter);
    let buffered = usize::from(rest[0]);
    let mut count = [0u8; 16];
    count[..layout.counter].copy_from_slice(counter);
    let length = u128::from_le_bytes(count)
        .wrapping_mul(layout.block as u128)
        .wrapping_add(buffered as u128) as u64;

    into.extend_from_slice(layout.magic);
    for word in words.chunks(layout.word) {
        into.extend(word.iter().rev());
    }
    into.extend_from_slice(&rest[1..1 + buffered]);
    into.resize(into.len() + layout.block - buffered, 0);
    into.extend_from_slice(&length.to_be_bytes());
}

fn restore_merkle_damgard(layout: &Layout, bytes: &[u8]) -> Vec<u8> {
    let words_len = layout.words * layout.word;
    let mut at = layout.magic.len();
    let mut out = Vec::with_capacity(words_len + layout.counter + 1 + layout.block);
    for word in bytes[at..at + words_len].chunks(layout.word) {
        out.extend(word.iter().rev());
    }
    at += words_len;
    let buffer = &bytes[at..at + layout.block];
    at += layout.block;
    let mut length = [0u8; 8];
    length.copy_from_slice(&bytes[at..at + 8]);
    let length = u64::from_be_bytes(length);
    let buffered = (length % layout.block as u64) as usize;
    let blocks = u128::from(length / layout.block as u64);
    out.extend_from_slice(&blocks.to_le_bytes()[..layout.counter]);
    out.push(buffered as u8);
    out.extend_from_slice(&buffer[..buffered]);
    // RustCrypto serializes the eager buffer as a length byte plus block-1 bytes.
    out.resize(out.len() + layout.block - 1 - buffered, 0);
    out
}

/// Go: `magic || rate || 200-byte lane state || n || direction`.
/// RustCrypto: `200-byte lane state || buffered length || buffer (rate - 1 bytes)`,
/// where the buffered bytes have not been absorbed yet; Go has absorbed them.
fn append_sponge(rate: usize, state: &[u8], into: &mut Vec<u8>) {
    let buffered = usize::from(state[SPONGE_STATE]);
    let buffer = &state[SPONGE_STATE + 1..SPONGE_STATE + 1 + buffered];
    let mut lanes = state[..SPONGE_STATE].to_vec();
    for (lane, byte) in lanes.iter_mut().zip(buffer) {
        *lane ^= byte;
    }
    into.extend_from_slice(SHA3_MAGIC);
    into.push(rate as u8);
    into.extend_from_slice(&lanes);
    into.push(buffered as u8);
    into.push(0);
}

macro_rules! digest_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        pub struct $name {
            pub(crate) inner: crate::engine::Fixed,
        }

        impl $name {
            /// Adds bytes to the running hash.
            pub fn update(&mut self, bytes: &[u8]) {
                self.inner.update(bytes);
            }

            /// Appends the current digest to `into` without changing the state.
            pub fn sum(&self, into: &mut Vec<u8>) {
                self.inner.sum(into);
            }

            /// Resets the hash to its initial state.
            pub fn reset(&mut self) {
                self.inner.reset();
            }

            /// Returns the digest size in bytes.
            pub fn size(&self) -> usize {
                self.inner.size()
            }

            /// Returns the underlying block size in bytes.
            pub fn block_size(&self) -> usize {
                self.inner.block_size()
            }

            /// Appends the Go-compatible binary hash state.
            pub fn append_binary(&self, into: &mut Vec<u8>) {
                self.inner.append_binary(into);
            }

            /// Serializes the running state in Go's `MarshalBinary` format.
            pub fn marshal_binary(&self) -> Vec<u8> {
                let mut bytes = Vec::new();
                self.inner.append_binary(&mut bytes);
                bytes
            }

            /// Restores a state produced by [`Self::marshal_binary`] of the same
            /// hash function, with Go's error messages.
            pub fn unmarshal_binary(&mut self, bytes: &[u8]) -> Result<(), crate::hash::StateError> {
                self.inner.unmarshal_binary(bytes)
            }
        }

        impl Clone for $name {
            /// Go's `Clone`: an independent copy of the running state.
            fn clone(&self) -> Self {
                Self { inner: self.inner.duplicate() }
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($name)).field("hash", &self.inner.algorithm()).finish()
            }
        }

        impl std::io::Write for $name {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.inner.update(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl crate::hash::Hash for $name {
            fn sum(&self, into: &mut Vec<u8>) {
                self.inner.sum(into);
            }

            fn reset(&mut self) {
                self.inner.reset();
            }

            fn size(&self) -> usize {
                self.inner.size()
            }

            fn block_size(&self) -> usize {
                self.inner.block_size()
            }

            fn clone_hash(&self) -> Box<dyn crate::hash::Hash> {
                Box::new(self.clone())
            }

            fn crypto_hash(&self) -> Option<crate::Hash> {
                Some(self.inner.algorithm())
            }
        }
    };
}

pub(crate) use digest_type;
