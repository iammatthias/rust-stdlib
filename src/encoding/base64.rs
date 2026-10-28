//! Base64 encoding and decoding (RFC 4648).
//!
//! An [`Engine`] is an alphabet plus a padding choice. Decoding is lenient in
//! the same ways as Go's `encoding/base64`: CR and LF are skipped, and unused
//! bits in the final quantum are accepted unless the engine is
//! [`strict`](Engine::strict).
//!
//! ```
//! use rust_stdlib::encoding::base64::{STANDARD, URL_SAFE_NO_PAD};
//!
//! assert_eq!(STANDARD.encode("hello"), "aGVsbG8=");
//! assert_eq!(STANDARD.decode("aGVs\nbG8=")?, b"hello");
//! assert_eq!(URL_SAFE_NO_PAD.encode([0xfb, 0xff]), "-_8");
//! # Ok::<(), rust_stdlib::encoding::base64::Error>(())
//! ```
use std::io::{self, Read, Write};
use std::{error, fmt};

const STANDARD_ALPHABET: [u8; 64] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE_ALPHABET: [u8; 64] =
    *b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The standard alphabet with `=` padding.
pub const STANDARD: Engine = Engine::with_alphabet(STANDARD_ALPHABET, Some(PAD));
/// The URL- and filename-safe alphabet with `=` padding.
pub const URL_SAFE: Engine = Engine::with_alphabet(URL_SAFE_ALPHABET, Some(PAD));
/// The standard alphabet without padding.
pub const STANDARD_NO_PAD: Engine = Engine::with_alphabet(STANDARD_ALPHABET, None);
/// The URL- and filename-safe alphabet without padding.
pub const URL_SAFE_NO_PAD: Engine = Engine::with_alphabet(URL_SAFE_ALPHABET, None);

/// The standard padding byte, `=`.
pub const PAD: u8 = b'=';

/// Malformed base64 input. Displays as `illegal base64 data at input byte N`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    offset: usize,
}

impl Error {
    /// The input byte at which decoding failed.
    pub fn offset(&self) -> usize {
        self.offset
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "illegal base64 data at input byte {}", self.offset)
    }
}

impl error::Error for Error {}

/// An alphabet or padding byte that cannot form an [`Engine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlphabetError {
    reason: &'static str,
}

impl fmt::Display for AlphabetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason)
    }
}

impl error::Error for AlphabetError {}

/// `alphabet.contains(&byte)`, usable in a `const fn`.
const fn in_alphabet(alphabet: &[u8], byte: u8) -> bool {
    let mut i = 0;
    while i < alphabet.len() {
        if alphabet[i] == byte {
            return true;
        }
        i += 1;
    }
    false
}

/// A base64 alphabet and padding choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine {
    alphabet: [u8; 64],
    padding: Option<u8>,
    strict: bool,
}

impl Engine {
    const fn with_alphabet(alphabet: [u8; 64], padding: Option<u8>) -> Self {
        Engine {
            alphabet,
            padding,
            strict: false,
        }
    }

    /// Creates a padded engine from 64 distinct ASCII bytes. CR and LF are
    /// not allowed, because decoding skips them.
    pub fn new(alphabet: &[u8; 64]) -> Result<Self, AlphabetError> {
        let mut seen = [false; 256];
        for &byte in alphabet {
            if !byte.is_ascii() || byte == b'\r' || byte == b'\n' {
                return Err(AlphabetError {
                    reason: "base64 alphabet must be ASCII without CR or LF",
                });
            }
            if seen[byte as usize] {
                return Err(AlphabetError {
                    reason: "base64 alphabet contains a duplicate byte",
                });
            }
            seen[byte as usize] = true;
        }
        Ok(Self::with_alphabet(*alphabet, Some(PAD)))
    }

    /// Uses `padding` as the padding byte, or no padding for `None`. The byte
    /// must not be CR, LF or part of the alphabet.
    pub const fn with_padding(mut self, padding: Option<u8>) -> Result<Self, AlphabetError> {
        if let Some(byte) = padding {
            if byte == b'\r' || byte == b'\n' || in_alphabet(&self.alphabet, byte) {
                return Err(AlphabetError {
                    reason: "invalid base64 padding byte",
                });
            }
        }
        self.padding = padding;
        Ok(self)
    }

    /// Rejects input whose unused trailing bits are not zero.
    pub const fn strict(mut self) -> Self {
        self.strict = true;
        self
    }

    /// The length of the encoding of `n` bytes.
    pub fn encoded_len(&self, n: usize) -> usize {
        match self.padding {
            Some(_) => n.div_ceil(3).saturating_mul(4),
            None => (n / 3).saturating_mul(4) + (n % 3 * 8).div_ceil(6),
        }
    }

    /// The largest number of bytes that `n` encoded bytes can decode to.
    pub fn decoded_len(&self, n: usize) -> usize {
        match self.padding {
            Some(_) => n / 4 * 3,
            None => n.saturating_mul(6) / 8,
        }
    }

    /// Encodes `input`. A padding byte outside ASCII cannot be held by a
    /// `String`: here it becomes U+FFFD, so use
    /// [`encode_to_vec`](Engine::encode_to_vec) for such an engine.
    pub fn encode(&self, input: impl AsRef<[u8]>) -> String {
        String::from_utf8_lossy(&self.encode_to_vec(input)).into_owned()
    }

    /// Encodes `input` to bytes.
    pub fn encode_to_vec(&self, input: impl AsRef<[u8]>) -> Vec<u8> {
        let input = input.as_ref();
        let mut out = Vec::with_capacity(self.encoded_len(input.len()));
        self.encode_into(input, &mut out);
        out
    }

    /// Appends the encoding of `input` to `out`.
    pub fn encode_into(&self, input: impl AsRef<[u8]>, out: &mut Vec<u8>) {
        let table = &self.alphabet;
        for chunk in input.as_ref().chunks(3) {
            let a = chunk[0];
            let b = chunk.get(1).copied().unwrap_or(0);
            let c = chunk.get(2).copied().unwrap_or(0);
            out.push(table[(a >> 2) as usize]);
            out.push(table[(((a & 3) << 4) | (b >> 4)) as usize]);
            if chunk.len() > 1 {
                out.push(table[(((b & 15) << 2) | (c >> 6)) as usize]);
            } else if let Some(p) = self.padding {
                out.push(p);
            }
            if chunk.len() > 2 {
                out.push(table[(c & 63) as usize]);
            } else if let Some(p) = self.padding {
                out.push(p);
            }
        }
    }

    /// Decodes `input`.
    pub fn decode(&self, input: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        let input = input.as_ref();
        let mut out = Vec::with_capacity(self.decoded_len(input.len()));
        self.decode_into(input, &mut out)?;
        Ok(out)
    }

    /// Appends the decoding of `input` to `out`. On malformed input, the
    /// complete quanta before the error stay in `out`.
    pub fn decode_into(&self, input: impl AsRef<[u8]>, out: &mut Vec<u8>) -> Result<(), Error> {
        let input = input.as_ref();
        let err = |offset| Error { offset };
        let skip_newlines = |mut i: usize| {
            while i < input.len() && matches!(input[i], b'\r' | b'\n') {
                i += 1;
            }
            i
        };
        let mut si = 0;
        let mut trailing = None;
        while si < input.len() {
            let mut values = [0u8; 4];
            let mut j = 0;
            let mut dlen = 4;
            let mut end = false;
            while j < 4 {
                if si == input.len() {
                    if j == 0 {
                        end = true;
                        break;
                    }
                    if j == 1 || self.padding.is_some() {
                        return Err(err(si.saturating_sub(j)));
                    }
                    dlen = j;
                    break;
                }
                let byte = input[si];
                si += 1;
                if let Some(value) = self.alphabet.iter().position(|&b| b == byte) {
                    values[j] = value as u8;
                    j += 1;
                    continue;
                }
                if matches!(byte, b'\r' | b'\n') {
                    continue;
                }
                if !self.is_padding_byte(byte) || j < 2 {
                    return Err(err(si - 1));
                }
                if j == 2 {
                    si = skip_newlines(si);
                    if si == input.len() {
                        return Err(err(input.len()));
                    }
                    if !self.is_padding_byte(input[si]) {
                        return Err(err(si - 1));
                    }
                    si += 1;
                }
                si = skip_newlines(si);
                if si < input.len() {
                    // As in Go, the padded quantum is written before this error.
                    trailing = Some(err(si));
                }
                dlen = j;
                break;
            }
            if end {
                break;
            }
            if dlen == 1 {
                return Err(err(si.saturating_sub(1)));
            }
            if self.strict && dlen == 2 && values[1] & 0x0f != 0 {
                return Err(err(si.saturating_sub(2)));
            }
            if self.strict && dlen == 3 && values[2] & 0x03 != 0 {
                return Err(err(si.saturating_sub(1)));
            }
            let value = u32::from(values[0]) << 18
                | u32::from(values[1]) << 12
                | u32::from(values[2]) << 6
                | u32::from(values[3]);
            out.push((value >> 16) as u8);
            if dlen >= 3 {
                out.push((value >> 8) as u8);
            }
            if dlen == 4 {
                out.push(value as u8);
            }
            if let Some(error) = trailing {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Wraps `inner` so that bytes written are base64-encoded into it. Call
    /// [`Encoder::finish`] to write the final partial group.
    pub fn encoder<W: Write>(&self, inner: W) -> Encoder<W> {
        Encoder {
            inner,
            engine: *self,
            tail: [0; 3],
            len: 0,
            failed: false,
        }
    }

    /// Wraps `inner` so that reading yields the decoding of its bytes.
    pub fn decoder<R: Read>(&self, inner: R) -> Decoder<R> {
        Decoder {
            inner,
            engine: *self,
            group: [0; 3],
            start: 0,
            len: 0,
            done: false,
            after_padding: false,
            offset: 0,
        }
    }

    fn is_padding_byte(&self, byte: u8) -> bool {
        self.padding == Some(byte) && !self.alphabet.contains(&byte)
    }
}

/// A writer that base64-encodes into another writer; see [`Engine::encoder`].
pub struct Encoder<W> {
    inner: W,
    engine: Engine,
    tail: [u8; 3],
    len: usize,
    failed: bool,
}

impl<W: Write> Encoder<W> {
    /// Writes the final partial group and padding, flushes, and returns the
    /// inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        if self.failed {
            return Err(io::Error::other("base64 encoder failed"));
        }
        if self.len != 0 {
            let tail = self.engine.encode_to_vec(&self.tail[..self.len]);
            self.inner.write_all(&tail)?;
        }
        self.inner.flush()?;
        Ok(self.inner)
    }

    fn emit(&mut self, input: &[u8]) -> io::Result<()> {
        let encoded = self.engine.encode_to_vec(input);
        self.inner.write_all(&encoded)
    }

    fn write_groups(&mut self, mut input: &[u8]) -> io::Result<()> {
        if self.len != 0 {
            let n = (3 - self.len).min(input.len());
            self.tail[self.len..self.len + n].copy_from_slice(&input[..n]);
            self.len += n;
            input = &input[n..];
            if self.len == 3 {
                let tail = self.tail;
                self.emit(&tail)?;
                self.len = 0;
            }
        }
        while input.len() >= 3 {
            let n = (input.len() / 3 * 3).min(3072);
            self.emit(&input[..n])?;
            input = &input[n..];
        }
        if !input.is_empty() {
            self.tail[..input.len()].copy_from_slice(input);
            self.len = input.len();
        }
        Ok(())
    }
}

impl<W: Write> Write for Encoder<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("base64 encoder failed"));
        }
        let result = self.write_groups(input);
        self.failed = result.is_err();
        result.map(|()| input.len())
    }

    /// Flushes the inner writer. Bytes of an incomplete group stay buffered
    /// until more input or [`Encoder::finish`].
    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("base64 encoder failed"));
        }
        let result = self.inner.flush();
        self.failed = result.is_err();
        result
    }
}

/// A reader that base64-decodes another reader; see [`Engine::decoder`]. Groups
/// decoded before a malformed one are returned before the error.
pub struct Decoder<R> {
    inner: R,
    engine: Engine,
    group: [u8; 3],
    start: usize,
    len: usize,
    done: bool,
    after_padding: bool,
    offset: usize,
}

impl<R: Read> Decoder<R> {
    /// Returns the inner reader.
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn byte(&mut self) -> io::Result<Option<u8>> {
        let mut byte = [0u8; 1];
        loop {
            match self.inner.read(&mut byte) {
                Ok(0) => return Ok(None),
                Ok(_) => {
                    self.offset += 1;
                    return Ok(Some(byte[0]));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn fill(&mut self) -> io::Result<()> {
        if self.after_padding {
            while let Some(b) = self.byte()? {
                if !matches!(b, b'\r' | b'\n') {
                    return Err(invalid(Error {
                        offset: self.offset - 1,
                    }));
                }
            }
            self.done = true;
            return Ok(());
        }
        let mut encoded = [0u8; 4];
        let mut positions = [0usize; 4];
        let mut n = 0;
        while n < 4 {
            match self.byte()? {
                Some(b'\r' | b'\n') => continue,
                Some(b) => {
                    encoded[n] = b;
                    positions[n] = self.offset - 1;
                    n += 1;
                }
                None => break,
            }
        }
        if n == 0 {
            self.done = true;
            return Ok(());
        }
        let decoded = self.engine.decode(&encoded[..n]).map_err(|e| {
            let offset = positions.get(e.offset).filter(|_| e.offset < n).copied();
            invalid(Error {
                offset: offset.unwrap_or(self.offset),
            })
        })?;
        if n < 4 {
            self.done = true;
        } else if encoded.iter().any(|&b| self.engine.is_padding_byte(b)) {
            self.after_padding = true;
        }
        self.group[..decoded.len()].copy_from_slice(&decoded);
        self.start = 0;
        self.len = decoded.len();
        Ok(())
    }
}

impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.start == self.len {
            if self.done {
                return Ok(0);
            }
            if let Err(e) = self.fill() {
                self.done = true;
                return Err(e);
            }
        }
        let n = output.len().min(self.len - self.start);
        output[..n].copy_from_slice(&self.group[self.start..self.start + n]);
        self.start += n;
        Ok(n)
    }
}

fn invalid(error: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}
