//! AES, compatible with Go's `crypto/aes`.
//!
//! The cipher is the reviewed `aes` crate, which uses the processor's AES
//! instructions where available. [`Cipher::new`] returns a [`Cipher`], which
//! implements [`cipher::Block`] and plugs into every mode in [`cipher`].

use std::any::Any;
use std::fmt;

use ::aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

use crate::cipher::{self, Engine, Error};

/// The AES block size in bytes.
pub const BLOCK_SIZE: usize = 16;

/// An invalid AES key size; the payload is the rejected length in bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeySizeError(pub usize);

impl fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crypto/aes: invalid key size {}", self.0)
    }
}

impl std::error::Error for KeySizeError {}

#[derive(Clone)]
enum Key {
    Aes128(::aes::Aes128),
    Aes192(::aes::Aes192),
    Aes256(::aes::Aes256),
}

/// An AES block cipher with a 128, 192 or 256-bit key (Go's `*aes.Block`).
#[derive(Clone)]
pub struct Cipher(Key);

impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("aes::Cipher { .. }")
    }
}

impl Cipher {
    /// Creates a new AES cipher. The key must be 16, 24 or 32 bytes to select
    /// AES-128, AES-192 or AES-256.
    pub fn new(key: &[u8]) -> Result<Self, KeySizeError> {
        let key = match key.len() {
            16 => Key::Aes128(KeyInit::new_from_slice(key).expect("16-byte key")),
            24 => Key::Aes192(KeyInit::new_from_slice(key).expect("24-byte key")),
            32 => Key::Aes256(KeyInit::new_from_slice(key).expect("32-byte key")),
            length => return Err(KeySizeError(length)),
        };
        Ok(Self(key))
    }

    pub(crate) fn engine(&self) -> Engine<'static> {
        match &self.0 {
            Key::Aes128(c) => Engine::Aes128(c.clone()),
            Key::Aes192(c) => Engine::Aes192(c.clone()),
            Key::Aes256(c) => Engine::Aes256(c.clone()),
        }
    }
}

fn check(dst: &[u8], src: &[u8]) -> Result<(), Error> {
    if src.len() < BLOCK_SIZE {
        return Err(Error::new("crypto/aes: input not full block"));
    }
    if dst.len() < BLOCK_SIZE {
        return Err(Error::new("crypto/aes: output not full block"));
    }
    Ok(())
}

impl cipher::Block for Cipher {
    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        check(dst, src)?;
        let input = <&::aes::Block>::try_from(&src[..BLOCK_SIZE]).expect("one block");
        let output = <&mut ::aes::Block>::try_from(&mut dst[..BLOCK_SIZE]).expect("one block");
        match &self.0 {
            Key::Aes128(c) => c.encrypt_block_b2b(input, output),
            Key::Aes192(c) => c.encrypt_block_b2b(input, output),
            Key::Aes256(c) => c.encrypt_block_b2b(input, output),
        }
        Ok(())
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
        check(dst, src)?;
        let input = <&::aes::Block>::try_from(&src[..BLOCK_SIZE]).expect("one block");
        let output = <&mut ::aes::Block>::try_from(&mut dst[..BLOCK_SIZE]).expect("one block");
        match &self.0 {
            Key::Aes128(c) => c.decrypt_block_b2b(input, output),
            Key::Aes192(c) => c.decrypt_block_b2b(input, output),
            Key::Aes256(c) => c.decrypt_block_b2b(input, output),
        }
        Ok(())
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}
