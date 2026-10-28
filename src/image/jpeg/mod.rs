//! JPEG decoding and encoding compatible with Go's `image/jpeg`.
//!
//! This is a port of Go's decoder and encoder, not a wrapper: Go's pixels are
//! defined by its fixed-point IDCT/FDCT (`dct.rs`) and by its decoder's
//! leniencies, so both are reproduced step by step.
//!
//! The decoder reads baseline, extended sequential and progressive JPEGs with
//! restart markers, 8-bit precision, any of the sampling ratios Go supports
//! (4:4:4, 4:4:0, 4:2:2, 4:2:0, 4:1:1, 4:1:0 and the non-standard "flex"
//! factors added in Go 1.27), grayscale, YCbCr and RGB frames, and Adobe
//! CMYK/YCbCrK. [`decode`] returns, as Go does, an image whose concrete type
//! depends on the file: [`Gray`](crate::image::Gray) for one component,
//! [`Ycbcr`](crate::image::Ycbcr) for three, [`Rgba`](crate::image::Rgba) for
//! RGB-in-JPEG and [`Cmyk`](crate::image::Cmyk) for four; downcast with
//! [`Image::as_any`]. Errors are `io::Error`s carrying a [`FormatError`] or an
//! [`UnsupportedError`] (kinds `InvalidData` and `Unsupported`), or
//! `UnexpectedEof`, exactly where Go returns them, with Go's messages.
//!
//! The encoder writes byte-for-byte what Go writes: baseline 4:2:0 (or one
//! component for [`Gray`](crate::image::Gray)) with the standard Huffman
//! tables, quality-scaled quantization tables, and Go's buffering.
//!
//! Deliberate differences from Go: where Go panics on a malformed Huffman table
//! or a block that falls outside its plane, the decoder returns a
//! [`FormatError`]; allocation failure and the optional [`Limits`] are
//! reported as `InvalidData` errors where Go would run out of memory.
//!
//! ```
//! use rust_stdlib::image::{jpeg, rect, Gray, Image};
//! let img = Gray::new(rect(0, 0, 8, 8));
//! let mut bytes = Vec::new();
//! jpeg::encode(&mut bytes, &img, None)?;
//! let decoded = jpeg::decode(&bytes[..])?;
//! assert_eq!(decoded.bounds(), img.bounds());
//! # Ok::<(), std::io::Error>(())
//! ```
use std::fmt;
use std::io::{self, BufRead, Read};

use super::{Config, Image};

mod dct;
mod huffman;
mod reader;
mod scan;
mod writer;

pub use writer::{encode, Options, DEFAULT_QUALITY};

use reader::{Decoded, Decoder};

/// Go's `jpeg.FormatError`: the input is not a valid JPEG. It is the payload
/// of the `io::Error` (kind `InvalidData`) that the decoder returns, so
/// callers can recover it with `get_ref().and_then(|e| e.downcast_ref())`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FormatError(pub String);

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JPEG format: {}", self.0)
    }
}

impl std::error::Error for FormatError {}

/// Go's `jpeg.UnsupportedError`: the input uses a valid but unimplemented
/// JPEG feature. Returned with kind `Unsupported`, like [`FormatError`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedError(pub String);

impl fmt::Display for UnsupportedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported JPEG feature: {}", self.0)
    }
}

impl std::error::Error for UnsupportedError {}

/// Go's deprecated `jpeg.Reader`: `io.ByteReader` plus `io.Reader`, which
/// `std::io::BufRead` covers. It is not used by this package.
pub trait Reader: BufRead {}

impl<T: BufRead + ?Sized> Reader for T {}

/// A decode budget. The default is unlimited, as in Go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of pixels of the (MCU-padded) image to allocate.
    pub max_pixels: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_pixels: u64::MAX,
        }
    }
}

/// Go's `jpeg.Decode`: reads a JPEG image from `reader`.
pub fn decode(reader: impl Read) -> io::Result<Box<dyn Image>> {
    decode_with_limits(reader, Limits::default())
}

/// Like [`decode`], rejecting images over `limits` before allocating them.
pub fn decode_with_limits(reader: impl Read, limits: Limits) -> io::Result<Box<dyn Image>> {
    let mut d = Decoder::new(reader, limits);
    match d.decode(false)? {
        Some(Decoded::Gray(img)) => Ok(Box::new(img)),
        Some(Decoded::Ycbcr(img)) => Ok(Box::new(img)),
        Some(Decoded::Rgba(img)) => Ok(Box::new(img)),
        Some(Decoded::Cmyk(img)) => Ok(Box::new(img)),
        None => Err(reader::Error::Format("missing SOS marker").into()),
    }
}

/// Go's `jpeg.DecodeConfig`: the color model and dimensions of a JPEG image
/// without decoding the entire image.
pub fn decode_config(reader: impl Read) -> io::Result<Config> {
    let mut d = Decoder::new(reader, Limits::default());
    d.decode(true)?;
    Ok(d.config()?)
}
