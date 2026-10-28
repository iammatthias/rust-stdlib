//! Go's `hash/maphash`: seeded hashing of byte sequences and comparable values.
//!
//! The mixing function is std's SipHash-1-3 (`std::hash::DefaultHasher`) keyed
//! by prefixing the seed, so a hash is a pure function of the seed and the
//! byte sequence written, independent of how the writes are chunked. Like
//! Go's, the exact values are unspecified and differ between processes.

use std::hash::{BuildHasher, DefaultHasher, Hasher as _};
use std::io::{self, Write};

/// A random value that selects the hash function of a [`struct@Hash`]. The zero
/// `Seed` is invalid; make seeds with [`make_seed`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seed {
    s: u64,
}

/// Returns a new random seed.
pub fn make_seed() -> Seed {
    loop {
        let s = std::hash::RandomState::new().build_hasher().finish();
        if s != 0 {
            return Seed { s };
        }
    }
}

fn start(seed: Seed) -> DefaultHasher {
    if seed.s == 0 {
        panic!("maphash: use of uninitialized Seed");
    }
    let mut state = DefaultHasher::new();
    state.write(&seed.s.to_le_bytes());
    state
}

/// Returns the hash of `b` with the given seed. It equals the [`struct@Hash`] value
/// after `set_seed(seed)` and `write(b)`.
pub fn bytes(seed: Seed, b: &[u8]) -> u64 {
    let mut state = start(seed);
    state.write(b);
    state.finish()
}

/// Returns the hash of `s` with the given seed. It equals [`bytes`] of the
/// string's UTF-8 bytes.
pub fn string(seed: Seed, s: &str) -> u64 {
    bytes(seed, s.as_bytes())
}

/// Returns the hash of `v` with the given seed such that `comparable(s, a) ==
/// comparable(s, b)` if `a == b`.
pub fn comparable<T: std::hash::Hash + ?Sized>(seed: Seed, v: &T) -> u64 {
    let mut h = Hash::default();
    h.set_seed(seed);
    write_comparable(&mut h, v);
    h.sum64()
}

/// Adds `x` to the data hashed by `h`.
pub fn write_comparable<T: std::hash::Hash + ?Sized>(h: &mut Hash, x: &T) {
    x.hash(h);
}

/// Computes a seeded hash of a byte sequence. The zero value is ready to use
/// and picks a random seed, which [`Hash::seed`] reports.
#[derive(Clone, Debug)]
pub struct Hash {
    seed: Seed,
    state: DefaultHasher,
}

impl Default for Hash {
    fn default() -> Self {
        let seed = make_seed();
        Self {
            seed,
            state: start(seed),
        }
    }
}

impl Hash {
    /// Creates a hash with a random seed.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `b` to the sequence of bytes hashed by the hash.
    pub fn write_byte(&mut self, b: u8) -> io::Result<()> {
        self.state.write_u8(b);
        Ok(())
    }

    /// Adds the bytes of `s`; it returns `s.len()`.
    pub fn write_string(&mut self, s: &str) -> usize {
        self.state.write(s.as_bytes());
        s.len()
    }

    /// Returns the hash's initial seed.
    pub fn seed(&self) -> Seed {
        self.seed
    }

    /// Sets the seed and discards the bytes written so far. It panics on the
    /// zero seed.
    pub fn set_seed(&mut self, seed: Seed) {
        self.state = start(seed);
        self.seed = seed;
    }

    /// Discards all bytes added since the last reset or `set_seed`.
    pub fn reset(&mut self) {
        self.state = start(self.seed);
    }

    /// Returns the current 64-bit value, which depends on the seed and the
    /// bytes written.
    pub fn sum64(&self) -> u64 {
        self.state.finish()
    }

    /// Appends [`Hash::sum64`] to `b` in little-endian order.
    pub fn sum(&self, mut b: Vec<u8>) -> Vec<u8> {
        b.extend_from_slice(&self.sum64().to_le_bytes());
        b
    }

    /// The size of a sum: 8 bytes.
    pub const fn size(&self) -> usize {
        8
    }

    /// The block size: 128 bytes.
    pub const fn block_size(&self) -> usize {
        128
    }
}

impl Write for Hash {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.state.write(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Lets `std::hash::Hash` implementations feed a [`struct@Hash`], which is how
/// [`write_comparable`] works.
impl std::hash::Hasher for Hash {
    fn write(&mut self, bytes: &[u8]) {
        self.state.write(bytes);
    }

    fn finish(&self) -> u64 {
        self.sum64()
    }
}

impl super::Hash for Hash {
    fn sum(&self, b: Vec<u8>) -> Vec<u8> {
        Hash::sum(self, b)
    }
    fn reset(&mut self) {
        Hash::reset(self)
    }
    fn size(&self) -> usize {
        8
    }
    fn block_size(&self) -> usize {
        128
    }
}

impl super::Hash64 for Hash {
    fn sum64(&self) -> u64 {
        Hash::sum64(self)
    }
}

impl super::Cloner for Hash {
    fn clone_hash(&self) -> Box<dyn super::Hash> {
        Box::new(self.clone())
    }
}

/// Go's `maphash.Hasher`: a hash function and equivalence relation over `T`.
/// Values that are `equal` must write the same bytes in `hash`.
pub trait Hasher<T: ?Sized> {
    /// Writes a hash of `v` into `h`.
    fn hash(&self, h: &mut Hash, v: &T);
    /// Reports whether `x` and `y` are equivalent.
    fn equal(&self, x: &T, y: &T) -> bool;
}

/// A [`Hasher`] for types with the usual `==` equivalence relation.
#[derive(Clone, Copy, Debug, Default)]
pub struct ComparableHasher<T: ?Sized>(std::marker::PhantomData<fn(&T)>);

impl<T: ?Sized> ComparableHasher<T> {
    /// Creates the hasher.
    pub const fn new() -> Self {
        Self(std::marker::PhantomData)
    }
}

impl<T: std::hash::Hash + PartialEq + ?Sized> Hasher<T> for ComparableHasher<T> {
    fn hash(&self, h: &mut Hash, v: &T) {
        write_comparable(h, v);
    }

    fn equal(&self, x: &T, y: &T) -> bool {
        x == y
    }
}
