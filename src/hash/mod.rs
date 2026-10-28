//! Go's `hash` interfaces and non-cryptographic hash functions compatible
//! with `hash/adler32`, `hash/crc32`, `hash/crc64`, `hash/fnv` and
//! `hash/maphash`.
//!
//! Go's `hash.Hash` embeds `io.Writer`, which is [`std::io::Write`] here. Every
//! digest in this crate implements the traits below, so generic code can use
//! them the way Go code uses `hash.Hash32` and `hash.Hash64`.

use std::io::Write;

pub mod adler32;
pub mod crc32;
pub mod crc64;
pub mod fnv;
pub mod maphash;

/// Go's `hash.Hash`: a hash function that is fed through `Write`.
pub trait Hash: Write {
    /// Appends the current hash to `b` and returns the result. It does not
    /// change the underlying hash state.
    fn sum(&self, b: Vec<u8>) -> Vec<u8>;
    /// Resets the hash to its initial state.
    fn reset(&mut self);
    /// The number of bytes `sum` appends.
    fn size(&self) -> usize;
    /// The hash's underlying block size.
    fn block_size(&self) -> usize;
}

/// Go's `hash.Hash32`: a [`Hash`] whose digest fits in 32 bits.
pub trait Hash32: Hash {
    /// The current 32-bit hash.
    fn sum32(&self) -> u32;
}

/// Go's `hash.Hash64`: a [`Hash`] whose digest fits in 64 bits.
pub trait Hash64: Hash {
    /// The current 64-bit hash.
    fn sum64(&self) -> u64;
}

/// Go's `hash.XOF`: an extendable output function. The output is read with
/// [`std::io::Read`] after the last `Write`; writing after a read panics in Go
/// implementations. This crate has no XOF implementation of its own (SHAKE
/// lives in the reviewed cryptography crate), so this is the trait only.
pub trait Xof: Write + std::io::Read {
    /// Resets the XOF to its initial state.
    fn reset(&mut self);
    /// The XOF's underlying block size.
    fn block_size(&self) -> usize;
}

/// Go's `hash.Cloner`: a hash that can copy its current state.
pub trait Cloner: Hash {
    /// Returns a separate [`Hash`] with the same state.
    fn clone_hash(&self) -> Box<dyn Hash>;
}

macro_rules! impl_hash {
    ($($ty:ty),*) => {$(
        impl Hash for $ty {
            fn sum(&self, mut b: Vec<u8>) -> Vec<u8> {
                <$ty>::sum(self, &mut b);
                b
            }
            fn reset(&mut self) {
                <$ty>::reset(self)
            }
            fn size(&self) -> usize {
                <$ty>::size(self)
            }
            fn block_size(&self) -> usize {
                <$ty>::block_size(self)
            }
        }
        impl Cloner for $ty {
            fn clone_hash(&self) -> Box<dyn Hash> {
                Box::new(self.clone())
            }
        }
    )*};
}

impl_hash!(
    adler32::Adler32,
    crc32::Crc32,
    crc64::Crc64,
    fnv::Fnv32,
    fnv::Fnv32a,
    fnv::Fnv64,
    fnv::Fnv64a,
    fnv::Fnv128,
    fnv::Fnv128a
);

macro_rules! impl_hash32 {
    ($($ty:ty => $f:ident),*) => {$(
        impl Hash32 for $ty {
            fn sum32(&self) -> u32 {
                <$ty>::$f(self)
            }
        }
    )*};
}

macro_rules! impl_hash64 {
    ($($ty:ty => $f:ident),*) => {$(
        impl Hash64 for $ty {
            fn sum64(&self) -> u64 {
                <$ty>::$f(self)
            }
        }
    )*};
}

impl_hash32!(adler32::Adler32 => sum32, crc32::Crc32 => sum32, fnv::Fnv32 => digest, fnv::Fnv32a => digest);
impl_hash64!(crc64::Crc64 => sum64, fnv::Fnv64 => digest, fnv::Fnv64a => digest);

/// Error returned when a serialized hash state is malformed or incompatible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateError(&'static str);

impl StateError {
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
