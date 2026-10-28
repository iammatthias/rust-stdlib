//! RC4, compatible with Go's `crypto/rc4`.
//!
//! RC4 is cryptographically broken and should not be used for secure
//! applications. The cipher is the reviewed `rc4` crate.

use std::fmt;

use ::rc4::{KeyInit, StreamCipher};

use crate::cipher::{self, Error};

/// An invalid RC4 key size; the payload is the rejected length in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeySizeError(pub usize);

impl fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crypto/rc4: invalid key size {}", self.0)
    }
}

impl std::error::Error for KeySizeError {}

/// An instance of RC4 using a particular key.
pub struct Cipher {
    /// `None` after [`Cipher::reset`]: Go zeroes its state, which leaves a
    /// key stream of zeros, so the data passes through unchanged.
    state: Option<::rc4::Rc4>,
}

impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("rc4::Cipher { .. }")
    }
}

impl Cipher {
    /// Creates a new RC4 cipher. The key must be at least 1 byte and at most
    /// 256 bytes.
    pub fn new(key: &[u8]) -> Result<Self, KeySizeError> {
        match ::rc4::Rc4::new_from_slice(key) {
            Ok(state) => Ok(Self { state: Some(state) }),
            Err(_) => Err(KeySizeError(key.len())),
        }
    }

    /// Zeroes the key data and makes the cipher unusable: afterwards
    /// [`Cipher::xor_key_stream`] copies its input unchanged.
    ///
    /// Deprecated in Go, and here, because it cannot guarantee the key is
    /// entirely removed from the process's memory.
    pub fn reset(&mut self) {
        self.state = None;
    }

    /// XORs each byte of `src` with the key stream into `dst`, which may be
    /// longer than `src`. Go indexes out of range when `dst` is shorter; that
    /// is an error here.
    pub fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        if src.is_empty() {
            return Ok(());
        }
        if dst.len() < src.len() {
            return Err(Error::new("crypto/rc4: output smaller than input"));
        }
        let dst = &mut dst[..src.len()];
        dst.copy_from_slice(src);
        self.xor_key_stream_in_place(dst);
        Ok(())
    }

    /// XORs `buf` with the key stream in place (Go's `dst` equal to `src`).
    pub fn xor_key_stream_in_place(&mut self, buf: &mut [u8]) {
        if let Some(state) = &mut self.state {
            state.apply_keystream(buf);
        }
    }
}

impl cipher::Stream for Cipher {
    fn xor_key_stream(&mut self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        Cipher::xor_key_stream(self, dst, src)
    }

    fn xor_key_stream_in_place(&mut self, buf: &mut [u8]) {
        Cipher::xor_key_stream_in_place(self, buf);
    }
}
