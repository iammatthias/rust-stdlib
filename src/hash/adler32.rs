//! Adler-32 checksums compatible with Go's `hash/adler32` package.

use std::io::{self, Write};

use super::StateError;

/// The checksum size in bytes.
pub const SIZE: usize = 4;
const MOD: u32 = 65_521;
const NMAX: usize = 5_552;

/// Incremental Adler-32 digest.
#[derive(Clone, Debug)]
pub struct Adler32 {
    state: u32,
}

impl Default for Adler32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Adler32 {
    /// Creates an Adler-32 checksum initialized to one.
    pub const fn new() -> Self {
        Self { state: 1 }
    }

    /// Resets the checksum to the Adler-32 initial state.
    pub fn reset(&mut self) {
        self.state = 1;
    }

    /// Returns the current checksum.
    pub const fn sum32(&self) -> u32 {
        self.state
    }

    /// Returns the checksum size in bytes.
    pub const fn size(&self) -> usize {
        SIZE
    }

    /// Returns the Adler-32 block size in bytes.
    pub const fn block_size(&self) -> usize {
        4
    }

    /// Adds bytes to the current checksum.
    pub fn update(&mut self, bytes: &[u8]) {
        self.state = update(self.state, bytes);
    }

    /// Appends the checksum in big-endian order without resetting state.
    pub fn sum(&self, into: &mut Vec<u8>) {
        into.extend_from_slice(&self.state.to_be_bytes());
    }

    /// Appends the Go-compatible binary state.
    pub fn append_binary(&self, into: &mut Vec<u8>) {
        into.extend_from_slice(b"adl\x01");
        into.extend_from_slice(&self.state.to_be_bytes());
    }

    /// Serializes the current state in Go's `hash/adler32` format.
    pub fn marshal_binary(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        self.append_binary(&mut bytes);
        bytes
    }

    /// Restores a state produced by Go's `hash/adler32` package.
    pub fn unmarshal_binary(&mut self, bytes: &[u8]) -> Result<(), StateError> {
        if bytes.len() < 4 || &bytes[..4] != b"adl\x01" {
            return Err(StateError::new(
                "hash/adler32: invalid hash state identifier",
            ));
        }
        if bytes.len() != 8 {
            return Err(StateError::new("hash/adler32: invalid hash state size"));
        }
        self.state = u32::from_be_bytes(bytes[4..8].try_into().expect("fixed state range"));
        Ok(())
    }
}

impl Write for Adler32 {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn update(mut state: u32, mut bytes: &[u8]) -> u32 {
    let mut s1 = state & 0xffff;
    let mut s2 = state >> 16;
    while !bytes.is_empty() {
        let n = bytes.len().min(NMAX);
        for &byte in &bytes[..n] {
            s1 = s1.wrapping_add(u32::from(byte));
            s2 = s2.wrapping_add(s1);
        }
        s1 %= MOD;
        s2 %= MOD;
        bytes = &bytes[n..];
    }
    state = (s2 << 16) | s1;
    state
}

/// Computes the Adler-32 checksum of `bytes`.
pub fn checksum(bytes: &[u8]) -> u32 {
    update(1, bytes)
}
