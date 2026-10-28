//! Fowler–Noll–Vo hash functions (FNV-1 and FNV-1a).
//!
//! Each hasher supports incremental updates through [`std::io::Write`]. The
//! `sum` methods append the current digest in big-endian order, matching Go's
//! `hash.Hash.Sum` behavior without changing the hasher state.

use std::io::{self, Write};

const OFFSET32: u32 = 2_166_136_261;
const OFFSET64: u64 = 14_695_981_039_346_656_037;
const OFFSET128: u128 = 0x6c62272e07bb014262b821756295c58d;
const PRIME32: u32 = 16_777_619;
const PRIME64: u64 = 1_099_511_628_211;
const PRIME128: u128 = 0x0000000001000000000000000000013b;

fn update32(mut state: u32, bytes: &[u8], one_a: bool) -> u32 {
    for &byte in bytes {
        if one_a {
            state = (state ^ u32::from(byte)).wrapping_mul(PRIME32);
        } else {
            state = state.wrapping_mul(PRIME32) ^ u32::from(byte);
        }
    }
    state
}

fn update64(mut state: u64, bytes: &[u8], one_a: bool) -> u64 {
    for &byte in bytes {
        if one_a {
            state = (state ^ u64::from(byte)).wrapping_mul(PRIME64);
        } else {
            state = state.wrapping_mul(PRIME64) ^ u64::from(byte);
        }
    }
    state
}

fn update128(mut state: u128, bytes: &[u8], one_a: bool) -> u128 {
    for &byte in bytes {
        if one_a {
            state ^= u128::from(byte);
        }
        state = state.wrapping_mul(PRIME128);
        if !one_a {
            state ^= u128::from(byte);
        }
    }
    state
}

macro_rules! fnv_hasher {
    ($name:ident, $word:ty, $offset:expr, $one_a:expr, $size:expr, $update:ident, $magic:expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            state: $word,
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl $name {
            /// Creates a hasher initialized to the FNV offset basis.
            pub const fn new() -> Self {
                Self { state: $offset }
            }

            /// Restores the initial FNV offset basis.
            pub fn reset(&mut self) {
                self.state = $offset;
            }

            /// Returns the current digest as an integer.
            pub const fn digest(&self) -> $word {
                self.state
            }

            /// Returns the digest size in bytes.
            pub const fn size(&self) -> usize {
                $size
            }

            /// Returns the FNV block size, which is one byte.
            pub const fn block_size(&self) -> usize {
                1
            }

            /// Adds bytes to the current digest.
            pub fn update(&mut self, bytes: &[u8]) {
                self.state = $update(self.state, bytes, $one_a);
            }

            /// Appends the digest in big-endian order without resetting state.
            pub fn sum(&self, into: &mut Vec<u8>) {
                let bytes = self.state.to_be_bytes();
                into.extend_from_slice(&bytes);
            }

            /// Appends the Go-compatible binary hash state.
            pub fn append_binary(&self, into: &mut Vec<u8>) {
                into.extend_from_slice($magic);
                into.extend_from_slice(&self.state.to_be_bytes());
            }

            /// Serializes the current state in Go's `hash/fnv` format.
            pub fn marshal_binary(&self) -> Vec<u8> {
                let mut bytes = Vec::with_capacity(4 + $size);
                self.append_binary(&mut bytes);
                bytes
            }

            /// Restores a state produced by the matching FNV variant.
            pub fn unmarshal_binary(&mut self, bytes: &[u8]) -> Result<(), super::StateError> {
                if bytes.len() < 4 || &bytes[..4] != $magic {
                    return Err(super::StateError::new(
                        "hash/fnv: invalid hash state identifier",
                    ));
                }
                if bytes.len() != 4 + $size {
                    return Err(super::StateError::new("hash/fnv: invalid hash state size"));
                }
                let mut word = [0u8; $size];
                word.copy_from_slice(&bytes[4..]);
                self.state = <$word>::from_be_bytes(word);
                Ok(())
            }
        }

        impl Write for $name {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.update(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
    };
}

fnv_hasher!(Fnv32, u32, OFFSET32, false, 4, update32, b"fnv\x01");
fnv_hasher!(Fnv32a, u32, OFFSET32, true, 4, update32, b"fnv\x02");
fnv_hasher!(Fnv64, u64, OFFSET64, false, 8, update64, b"fnv\x03");
fnv_hasher!(Fnv64a, u64, OFFSET64, true, 8, update64, b"fnv\x04");
fnv_hasher!(Fnv128, u128, OFFSET128, false, 16, update128, b"fnv\x05");
fnv_hasher!(Fnv128a, u128, OFFSET128, true, 16, update128, b"fnv\x06");

/// Returns a fresh FNV-1 32-bit hasher.
pub fn new32() -> Fnv32 {
    Fnv32::new()
}

/// Returns a fresh FNV-1a 32-bit hasher.
pub fn new32a() -> Fnv32a {
    Fnv32a::new()
}

/// Returns a fresh FNV-1 64-bit hasher.
pub fn new64() -> Fnv64 {
    Fnv64::new()
}

/// Returns a fresh FNV-1a 64-bit hasher.
pub fn new64a() -> Fnv64a {
    Fnv64a::new()
}

/// Returns a fresh FNV-1 128-bit hasher.
pub fn new128() -> Fnv128 {
    Fnv128::new()
}

/// Returns a fresh FNV-1a 128-bit hasher.
pub fn new128a() -> Fnv128a {
    Fnv128a::new()
}
