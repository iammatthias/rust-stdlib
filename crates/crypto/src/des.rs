//! DES and Triple DES, compatible with Go's `crypto/des`.
//!
//! DES is cryptographically broken; it exists for compatibility with old
//! protocols. The ciphers are the reviewed `des` crate. Like Go, neither
//! constructor rejects weak or semi-weak keys.

use std::any::Any;
use std::fmt;

use ::aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};

use crate::cipher::{self, Error};

/// The DES block size in bytes.
pub const BLOCK_SIZE: usize = 8;

/// An invalid DES or Triple DES key size; the payload is the rejected length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeySizeError(pub usize);

impl fmt::Display for KeySizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "crypto/des: invalid key size {}", self.0)
    }
}

impl std::error::Error for KeySizeError {}

/// A single-DES block cipher.
#[derive(Clone)]
pub struct Cipher(pub(crate) ::des::Des);

/// A Triple DES (EDE, three independent 8-byte keys) block cipher.
#[derive(Clone)]
pub struct TripleDesCipher(pub(crate) ::des::TdesEde3);

impl fmt::Debug for Cipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("des::Cipher { .. }")
    }
}

impl fmt::Debug for TripleDesCipher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("des::TripleDesCipher { .. }")
    }
}

impl Cipher {
    /// Creates a new DES cipher. The key must be 8 bytes.
    pub fn new(key: &[u8]) -> Result<Self, KeySizeError> {
        if key.len() != 8 {
            return Err(KeySizeError(key.len()));
        }
        Ok(Self(KeyInit::new_from_slice(key).expect("8-byte key")))
    }
}

impl TripleDesCipher {
    /// Creates a new Triple DES cipher. The key must be 24 bytes.
    pub fn new(key: &[u8]) -> Result<Self, KeySizeError> {
        if key.len() != 24 {
            return Err(KeySizeError(key.len()));
        }
        Ok(Self(KeyInit::new_from_slice(key).expect("24-byte key")))
    }
}

fn check(dst: &[u8], src: &[u8]) -> Result<(), Error> {
    if src.len() < BLOCK_SIZE {
        return Err(Error::new("crypto/des: input not full block"));
    }
    if dst.len() < BLOCK_SIZE {
        return Err(Error::new("crypto/des: output not full block"));
    }
    Ok(())
}

macro_rules! block_impl {
    ($ty:ty) => {
        impl cipher::Block for $ty {
            fn block_size(&self) -> usize {
                BLOCK_SIZE
            }

            fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
                check(dst, src)?;
                let input = <&::aes::cipher::Array<u8, ::aes::cipher::consts::U8>>::try_from(
                    &src[..BLOCK_SIZE],
                )
                .expect("one block");
                let output = <&mut ::aes::cipher::Array<u8, ::aes::cipher::consts::U8>>::try_from(
                    &mut dst[..BLOCK_SIZE],
                )
                .expect("one block");
                self.0.encrypt_block_b2b(input, output);
                Ok(())
            }

            fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
                check(dst, src)?;
                let input = <&::aes::cipher::Array<u8, ::aes::cipher::consts::U8>>::try_from(
                    &src[..BLOCK_SIZE],
                )
                .expect("one block");
                let output = <&mut ::aes::cipher::Array<u8, ::aes::cipher::consts::U8>>::try_from(
                    &mut dst[..BLOCK_SIZE],
                )
                .expect("one block");
                self.0.decrypt_block_b2b(input, output);
                Ok(())
            }

            fn as_any(&self) -> Option<&dyn Any> {
                Some(self)
            }
        }
    };
}

block_impl!(Cipher);
block_impl!(TripleDesCipher);
