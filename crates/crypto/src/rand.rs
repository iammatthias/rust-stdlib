//! Cryptographically secure random numbers, compatible with Go's `crypto/rand`.
//!
//! Randomness comes from the operating system through the reviewed
//! `getrandom` crate. `Int` and `Prime` use [`crate::bigint::Int`], the
//! non-negative integer of this crate, and the reviewed `crypto-primes` crate
//! for primality testing.

use std::io;
use std::sync::{Arc, Mutex, RwLock};

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The global cryptographically secure random reader (Go's `rand.Reader`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Reader;

impl io::Read for Reader {
    /// Fills `buf` entirely from the operating system (or the deterministic
    /// source installed by [`set_global_random`]), or fails with the system
    /// error.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        fill(buf).map_err(io::Error::other)?;
        Ok(buf.len())
    }
}

/// A deterministic byte stream: SHA-256 of the seed and a block counter.
#[derive(Debug)]
struct TestStream {
    seed: [u8; 8],
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl TestStream {
    fn new(seed: u64) -> TestStream {
        TestStream {
            seed: seed.to_le_bytes(),
            counter: 0,
            block: [0; 32],
            used: 32,
        }
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf {
            if self.used == 32 {
                let mut input = [0u8; 16];
                input[..8].copy_from_slice(&self.seed);
                input[8..].copy_from_slice(&self.counter.to_le_bytes());
                self.block = <::sha2::Sha256 as ::sha2::Digest>::digest(input).into();
                self.counter += 1;
                self.used = 0;
            }
            *b = self.block[self.used];
            self.used += 1;
        }
    }
}

static TESTING_READER: RwLock<Option<Arc<Mutex<TestStream>>>> = RwLock::new(None);

fn fill(buf: &mut [u8]) -> Result<(), getrandom::Error> {
    let stream = TESTING_READER
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    match stream {
        Some(s) => {
            s.lock().unwrap_or_else(|e| e.into_inner()).fill(buf);
            Ok(())
        }
        None => getrandom::fill(buf),
    }
}

/// The restore handle returned by [`set_global_random`]: dropping it
/// reinstates the previous random source.
#[derive(Debug)]
#[must_use = "dropping the guard immediately restores the system random source"]
pub struct GlobalRandom {
    previous: Option<Arc<Mutex<TestStream>>>,
}

impl Drop for GlobalRandom {
    fn drop(&mut self) {
        *TESTING_READER.write().unwrap_or_else(|e| e.into_inner()) = self.previous.take();
    }
}

/// Go's `testing/cryptotest.SetGlobalRandom`: makes every read of this
/// package ([`read`], [`Reader`], [`text`] and the implicit randomness of the
/// other `crypto` modules that use it) come from a global, deterministic
/// stream derived from `seed`, until the returned guard is dropped. Register
/// the drop with the test (`t.cleanup(move || drop(guard))`).
///
/// Calling it again resets the stream. The process-wide effect means it must
/// not be used by parallel tests.
///
/// The stream is SHA-256 in counter mode, not Go's ChaCha8, so the bytes for
/// a given seed differ from Go's; as in Go, the way algorithms consume
/// randomness is unspecified.
pub fn set_global_random(seed: u64) -> GlobalRandom {
    let stream = Arc::new(Mutex::new(TestStream::new(seed)));
    let previous = TESTING_READER
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .replace(stream);
    GlobalRandom { previous }
}

/// Fills `buf` with cryptographically secure random bytes and returns its
/// length. It always fills `buf` entirely.
///
/// # Panics
///
/// Go crashes the program irrecoverably when the system generator fails; this
/// panics with the system error instead.
pub fn read(buf: &mut [u8]) -> usize {
    if let Err(error) = fill(buf) {
        panic!("crypto/rand: failed to read random data: {error}");
    }
    buf.len()
}

/// Returns a random 26-character string over the RFC 4648 base32 alphabet,
/// carrying at least 128 bits of randomness.
pub fn text() -> String {
    let mut source = [0u8; 26];
    read(&mut source);
    source
        .iter()
        .map(|byte| char::from(BASE32_ALPHABET[usize::from(byte % 32)]))
        .collect()
}

/// Returns a uniform random value in `[0, max)` from the system source, like
/// Go's `rand.Int(rand.Reader, max)`. Go's `*big.Int` is
/// [`crate::bigint::Int`] here.
///
/// # Panics
///
/// Panics if `max` is zero, like Go for an argument that is not positive.
pub fn int(max: &crate::bigint::Int) -> io::Result<crate::bigint::Int> {
    int_in(None, max)
}

/// [`int`] reading from `rng`, like Go's `rand.Int(rng, max)`. The reader is
/// consumed exactly as Go consumes it (whole bytes, the top byte masked,
/// rejection sampling) and is always honoured.
///
/// # Panics
///
/// Panics if `max` is zero, like Go for an argument that is not positive.
pub fn int_with_rng(
    rng: &mut dyn io::Read,
    max: &crate::bigint::Int,
) -> io::Result<crate::bigint::Int> {
    int_in(Some(rng), max)
}

fn int_in(
    rand: Option<&mut dyn io::Read>,
    max: &crate::bigint::Int,
) -> io::Result<crate::bigint::Int> {
    use crate::bigint::Int;
    assert!(!max.is_zero(), "crypto/rand: argument to Int is <= 0");
    // limit = max - 1
    let mut limit = max.to_be_bytes();
    for byte in limit.iter_mut().rev() {
        let (value, borrow) = byte.overflowing_sub(1);
        *byte = value;
        if !borrow {
            break;
        }
    }
    let bit_len = Int::from_be_bytes(&limit).bit_len();
    if bit_len == 0 {
        return Ok(Int::zero());
    }
    let k = bit_len.div_ceil(8);
    let b = match bit_len % 8 {
        0 => 8,
        b => b,
    };
    let mut source = crate::sysrng::Source::explicit(rand);
    let mut bytes = vec![0u8; k];
    loop {
        source.fill(&mut bytes);
        source.check()?;
        bytes[0] &= ((1u16 << b) - 1) as u8;
        let n = Int::from_be_bytes(&bytes);
        if &n < max {
            return Ok(n);
        }
    }
}

/// Returns a number of the given bit length that is prime with high
/// probability, like Go's `rand.Prime`: candidates have the top two bits and
/// the bottom bit set, and are tested with the reviewed `crypto-primes`
/// Baillie-PSW test, with randomness from the system source.
pub fn prime(bits: usize) -> io::Result<crate::bigint::Int> {
    prime_in(None, bits)
}

/// [`prime`] reading from `rng`, like Go's `rand.Prime(rng, bits)`. As in
/// Go 1.26+, the reader is honoured only with `GODEBUG=cryptocustomrand=1`;
/// otherwise the system source is used.
pub fn prime_with_rng(rng: &mut dyn io::Read, bits: usize) -> io::Result<crate::bigint::Int> {
    prime_in(Some(rng), bits)
}

fn prime_in(rand: Option<&mut dyn io::Read>, bits: usize) -> io::Result<crate::bigint::Int> {
    use crate::bigint::Int;
    if bits < 2 {
        return Err(io::Error::other(
            "crypto/rand: prime size must be at least 2-bit",
        ));
    }
    let b = match bits % 8 {
        0 => 8,
        b => b,
    };
    let mut source = crate::sysrng::Source::custom(rand);
    let mut bytes = vec![0u8; bits.div_ceil(8)];
    loop {
        source.fill(&mut bytes);
        source.check()?;
        bytes[0] &= ((1u16 << b) - 1) as u8;
        if b >= 2 {
            bytes[0] |= 3 << (b - 2);
        } else {
            bytes[0] |= 1;
            if bytes.len() > 1 {
                bytes[1] |= 0x80;
            }
        }
        let last = bytes.len() - 1;
        bytes[last] |= 1;
        let candidate = crypto_bigint::BoxedUint::from_be_slice_vartime(&bytes);
        if crypto_primes::is_prime(crypto_primes::Flavor::Any, &candidate) {
            return Ok(Int::from_be_bytes(&bytes));
        }
    }
}
