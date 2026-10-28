//! Text and binary encodings.
//!
//! The traits below mirror Go's `encoding` package interfaces. Each method
//! returns Go's `(T, error)` pair as a `Result`.
use std::error::Error;

/// Go's `encoding.TextMarshaler`.
pub trait TextMarshaler {
    fn marshal_text(&self) -> Result<Vec<u8>, Box<dyn Error>>;
}

/// Go's `encoding.TextUnmarshaler`.
pub trait TextUnmarshaler {
    fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Box<dyn Error>>;
}

/// Go's `encoding.BinaryMarshaler`.
pub trait BinaryMarshaler {
    fn marshal_binary(&self) -> Result<Vec<u8>, Box<dyn Error>>;
}

/// Go's `encoding.BinaryUnmarshaler`.
pub trait BinaryUnmarshaler {
    fn unmarshal_binary(&mut self, data: &[u8]) -> Result<(), Box<dyn Error>>;
}

/// Go's `encoding.TextAppender`. Appends to `out` instead of returning the
/// extended slice; on error `out` may already hold partial output.
pub trait TextAppender {
    fn append_text(&self, out: &mut Vec<u8>) -> Result<(), Box<dyn Error>>;
}

/// Go's `encoding.BinaryAppender`. Appends to `out` instead of returning the
/// extended slice; on error `out` may already hold partial output.
pub trait BinaryAppender {
    fn append_binary(&self, out: &mut Vec<u8>) -> Result<(), Box<dyn Error>>;
}

pub mod ascii85;
pub mod asn1;
pub mod base32;
pub mod base64;
pub mod binary;
pub mod csv;
pub mod gob;
pub mod hex;
pub mod json;
pub mod pem;
pub mod xml;
