//! The image format registry behind [`decode`] and [`decode_config`] (Go's
//! `image.RegisterFormat`, `image.Decode` and `image.DecodeConfig`).
//!
//! The PNG, GIF and JPEG codecs of this crate are registered first, as Go
//! registers them from `image/png`, `image/gif` and `image/jpeg`, and formats added with
//! [`register_format`] follow in registration order. A format matches when its
//! magic pattern equals the first bytes of the stream, where `?` matches any
//! byte. Decoding then reads the whole stream, header bytes included.
use std::fmt;
use std::io::{self, Chain, Cursor, Read};
use std::sync::{Arc, Mutex, PoisonError};

use super::{gif, jpeg, png, Config, Image, ERR_FORMAT};

type DecodeFn = dyn Fn(&mut dyn Read) -> io::Result<Box<dyn Image>> + Send + Sync;
type DecodeConfigFn = dyn Fn(&mut dyn Read) -> io::Result<Config> + Send + Sync;

struct Format {
    name: String,
    magic: Vec<u8>,
    decode: Box<DecodeFn>,
    decode_config: Box<DecodeConfigFn>,
}

impl Format {
    fn new(
        name: &str,
        magic: &[u8],
        decode: impl Fn(&mut dyn Read) -> io::Result<Box<dyn Image>> + Send + Sync + 'static,
        decode_config: impl Fn(&mut dyn Read) -> io::Result<Config> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name: name.to_owned(),
            magic: magic.to_vec(),
            decode: Box::new(decode),
            decode_config: Box::new(decode_config),
        }
    }
}

static REGISTERED: Mutex<Vec<Arc<Format>>> = Mutex::new(Vec::new());

fn builtin_formats() -> Vec<Format> {
    vec![
        Format::new(
            "png",
            b"\x89PNG\r\n\x1a\n",
            |r| png::decode(r).map(|image| Box::new(image) as Box<dyn Image>),
            |r| png::decode_config(r),
        ),
        Format::new(
            "gif",
            b"GIF8?a",
            |r| gif::decode(r).map(|image| Box::new(image) as Box<dyn Image>),
            |r| gif::decode_config(r),
        ),
        Format::new(
            "jpeg",
            b"\xff\xd8",
            |r| jpeg::decode(r),
            |r| jpeg::decode_config(r),
        ),
    ]
}

/// Every format in match order. The registry lock is released before any
/// codec runs, so a codec may register formats without deadlocking.
fn formats() -> Vec<Arc<Format>> {
    let mut all: Vec<Arc<Format>> = builtin_formats().into_iter().map(Arc::new).collect();
    all.extend(
        REGISTERED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .cloned(),
    );
    all
}

/// Go's `image.RegisterFormat`: adds a format after the existing ones. `magic`
/// is matched against the start of the stream, with `?` as a wildcard byte.
pub fn register_format(
    name: &str,
    magic: &[u8],
    decode: impl Fn(&mut dyn Read) -> io::Result<Box<dyn Image>> + Send + Sync + 'static,
    decode_config: impl Fn(&mut dyn Read) -> io::Result<Config> + Send + Sync + 'static,
) {
    let format = Format::new(name, magic, decode, decode_config);
    REGISTERED
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Arc::new(format));
}

/// Reads at most as many bytes as the longest magic pattern, stopping early
/// at end of stream.
fn read_header(reader: &mut impl Read, len: usize) -> io::Result<Vec<u8>> {
    let mut head = vec![0; len];
    let mut filled = 0;
    while filled < len {
        match reader.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    head.truncate(filled);
    Ok(head)
}

fn matches(magic: &[u8], head: &[u8]) -> bool {
    head.len() >= magic.len() && magic.iter().zip(head).all(|(&m, &b)| m == b'?' || m == b)
}

/// The first format whose magic matches the stream, and the stream positioned
/// at its start: the header bytes are replayed in front of the rest.
type Sniffed<R> = Option<(Arc<Format>, Chain<Cursor<Vec<u8>>, R>)>;

fn sniff<R: Read>(mut reader: R) -> io::Result<Sniffed<R>> {
    let formats = formats();
    let longest = formats.iter().map(|f| f.magic.len()).max().unwrap_or(0);
    let head = read_header(&mut reader, longest)?;
    Ok(formats
        .into_iter()
        .find(|f| matches(&f.magic, &head))
        .map(|format| (format, Cursor::new(head).chain(reader))))
}

/// The failure of [`decode`] or [`decode_config`]: Go returns the format name
/// together with the error, so a stream in a recognised format that fails to
/// decode still reports which format it was.
#[derive(Debug)]
pub struct DecodeError {
    /// The matched format, empty when the stream matched none ([`ERR_FORMAT`]).
    pub format: String,
    /// The error from the codec.
    pub error: io::Error,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for DecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<DecodeError> for io::Error {
    fn from(e: DecodeError) -> io::Error {
        e.error
    }
}

fn no_format(error: io::Error) -> DecodeError {
    DecodeError {
        format: String::new(),
        error,
    }
}

/// Go's `image.Decode`: decodes an image in a registered format and returns it
/// with the format name. A stream in no registered format is [`ERR_FORMAT`].
/// A decode error carries the format name, as Go returns it with the error.
pub fn decode(reader: impl Read) -> Result<(Box<dyn Image>, String), DecodeError> {
    let Some((format, mut stream)) = sniff(reader).map_err(no_format)? else {
        return Err(no_format(io::Error::new(
            io::ErrorKind::InvalidData,
            ERR_FORMAT,
        )));
    };
    match (format.decode)(&mut stream) {
        Ok(image) => Ok((image, format.name.clone())),
        Err(error) => Err(DecodeError {
            format: format.name.clone(),
            error,
        }),
    }
}

/// Go's `image.DecodeConfig`: the color model and dimensions of an image in a
/// registered format, with the format name. A decode error carries the format
/// name.
pub fn decode_config(reader: impl Read) -> Result<(Config, String), DecodeError> {
    let Some((format, mut stream)) = sniff(reader).map_err(no_format)? else {
        return Err(no_format(io::Error::new(
            io::ErrorKind::InvalidData,
            ERR_FORMAT,
        )));
    };
    match (format.decode_config)(&mut stream) {
        Ok(config) => Ok((config, format.name.clone())),
        Err(error) => Err(DecodeError {
            format: format.name.clone(),
            error,
        }),
    }
}
