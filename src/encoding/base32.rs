//! Base32 encoding and decoding (RFC 4648).
//!
//! An [`Engine`] is an alphabet plus a padding choice. Decoding is a port of
//! Go's `encoding/base32` quantum state machine, so corruption offsets and
//! partial output match Go byte for byte: CR and LF are skipped.
//!
//! ```
//! use rust_stdlib::encoding::base32::{HEX_NO_PAD, STANDARD};
//!
//! assert_eq!(STANDARD.encode("hello"), "NBSWY3DP");
//! assert_eq!(STANDARD.decode("NBSW\nY3DP")?, b"hello");
//! assert_eq!(HEX_NO_PAD.encode("hi"), "D1KG");
//! # Ok::<(), rust_stdlib::encoding::base32::Error>(())
//! ```
use std::{error, fmt, io};

/// Malformed base32 input. Displays as `illegal base32 data at input byte N`;
/// the offset indexes the input after CR and LF are removed, as Go reports it.
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
        write!(f, "illegal base32 data at input byte {}", self.offset)
    }
}
impl error::Error for Error {}

/// An alphabet or padding byte that cannot form an [`Engine`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlphabetError(&'static str);
impl fmt::Display for AlphabetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl error::Error for AlphabetError {}

/// A base32 alphabet and padding choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engine {
    alphabet: [u8; 32],
    padding: Option<u8>,
}

/// The standard padding byte, `=`.
pub const PAD: u8 = b'=';

const STANDARD_ALPHABET: [u8; 32] = *b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HEX_ALPHABET: [u8; 32] = *b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

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

/// The standard alphabet with `=` padding.
pub const STANDARD: Engine = Engine {
    alphabet: STANDARD_ALPHABET,
    padding: Some(PAD),
};
/// The extended-hex alphabet with `=` padding.
pub const HEX: Engine = Engine {
    alphabet: HEX_ALPHABET,
    padding: Some(PAD),
};
/// The standard alphabet without padding.
pub const STANDARD_NO_PAD: Engine = Engine {
    alphabet: STANDARD_ALPHABET,
    padding: None,
};
/// The extended-hex alphabet without padding.
pub const HEX_NO_PAD: Engine = Engine {
    alphabet: HEX_ALPHABET,
    padding: None,
};

/// Removes CR and LF anywhere in the input, as Go does before decoding.
fn strip_newlines(src: &[u8]) -> Vec<u8> {
    src.iter()
        .copied()
        .filter(|&b| b != b'\r' && b != b'\n')
        .collect()
}

impl Engine {
    /// Creates a padded engine from 32 distinct bytes other than CR and LF.
    /// The padding byte may be changed later with
    /// [`with_padding`](Engine::with_padding).
    pub fn new(alphabet: &[u8; 32]) -> Result<Self, AlphabetError> {
        let mut seen = [false; 256];
        for &b in alphabet {
            if b == b'\r' || b == b'\n' {
                return Err(AlphabetError(
                    "encoding alphabet contains newline character",
                ));
            }
            if seen[b as usize] {
                return Err(AlphabetError(
                    "encoding alphabet includes duplicate symbols",
                ));
            }
            seen[b as usize] = true;
        }
        Ok(Self {
            alphabet: *alphabet,
            padding: Some(PAD),
        })
    }
    /// Uses `padding` as the padding byte, or no padding for `None`. The byte
    /// must not be CR, LF or part of the alphabet.
    pub const fn with_padding(mut self, padding: Option<u8>) -> Result<Self, AlphabetError> {
        if let Some(p) = padding {
            if p == b'\r' || p == b'\n' {
                return Err(AlphabetError("invalid padding"));
            }
            if in_alphabet(&self.alphabet, p) {
                return Err(AlphabetError("padding contained in alphabet"));
            }
        }
        self.padding = padding;
        Ok(self)
    }
    /// The length of the encoding of `n` bytes.
    pub fn encoded_len(&self, n: usize) -> usize {
        match self.padding {
            Some(_) => n.saturating_add(4).saturating_div(5).saturating_mul(8),
            None => (n / 5)
                .saturating_mul(8)
                .saturating_add((n % 5 * 8).div_ceil(5)),
        }
    }
    /// The largest number of bytes that `n` encoded bytes can decode to.
    pub fn decoded_len(&self, n: usize) -> usize {
        match self.padding {
            Some(_) => n / 8 * 5,
            None => (n / 8).saturating_mul(5).saturating_add(n % 8 * 5 / 8),
        }
    }
    /// Encodes `src` into `dst`, which must hold `encoded_len(src.len())`
    /// bytes, and returns that length.
    fn encode_slice(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut at = 0;
        for chunk in src.chunks(5) {
            let bits = chunk.len() * 8;
            // Left-align the chunk in 40 bits and emit five-bit symbols from the top.
            let acc = chunk.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)) << (40 - bits);
            let symbols = bits.div_ceil(5);
            for (i, slot) in dst[at..at + symbols].iter_mut().enumerate() {
                *slot = self.alphabet[((acc >> (35 - 5 * i)) & 31) as usize];
            }
            at += symbols;
            if let Some(p) = self.padding {
                let pad = 8 - symbols;
                dst[at..at + pad].fill(p);
                at += pad;
            }
        }
        at
    }
    /// Encodes `input`. A padding or alphabet byte outside ASCII cannot be
    /// held by a `String`: here it becomes U+FFFD, so use
    /// [`encode_to_vec`](Engine::encode_to_vec) for such an engine.
    pub fn encode(&self, input: impl AsRef<[u8]>) -> String {
        String::from_utf8_lossy(&self.encode_to_vec(input)).into_owned()
    }
    /// Encodes `input` to bytes.
    pub fn encode_to_vec(&self, input: impl AsRef<[u8]>) -> Vec<u8> {
        let input = input.as_ref();
        let mut out = vec![0; self.encoded_len(input.len())];
        self.encode_slice(&mut out, input);
        out
    }
    /// Appends the encoding of `input` to `out`.
    pub fn encode_into(&self, input: impl AsRef<[u8]>, out: &mut Vec<u8>) {
        let input = input.as_ref();
        let start = out.len();
        out.resize(start + self.encoded_len(input.len()), 0);
        self.encode_slice(&mut out[start..], input);
    }
    fn value(&self, b: u8) -> Option<u8> {
        self.alphabet.iter().position(|&x| x == b).map(|x| x as u8)
    }
    /// Go's `decode` over CR/LF-free input. Writes whole quanta to `dst` and
    /// returns the number of bytes written before the first corrupt byte and
    /// whether the message ended (Go's `n, end, err`; `end` is false on error).
    fn decode_quanta(&self, src: &[u8], dst: &mut [u8]) -> (usize, bool, Result<(), Error>) {
        // Go compares against byte(NoPadding), which is 0xff.
        let pad = self.padding.unwrap_or(0xff);
        let corrupt = |offset| Err(Error { offset });
        let mut n = 0;
        let mut dsti = 0;
        let mut pos = 0;
        let mut end = false;
        while pos < src.len() && !end {
            let mut dbuf = [0u8; 8];
            let mut dlen = 8;
            let mut j = 0;
            while j < 8 {
                if pos == src.len() {
                    if self.padding.is_some() {
                        // We have reached the end and are missing padding.
                        return (n, false, corrupt(pos - j));
                    }
                    // We have reached the end and are not expecting any padding.
                    dlen = j;
                    end = true;
                    break;
                }
                let input = src[pos];
                pos += 1;
                if input == pad && j >= 2 && src.len() - pos < 8 {
                    // The quantum ends here and holds padding.
                    if src.len() - pos + j < 7 {
                        return (n, false, corrupt(src.len()));
                    }
                    for k in 0..7 - j {
                        if pos + k < src.len() && src[pos + k] != pad {
                            return (n, false, corrupt(pos + k - 1));
                        }
                    }
                    dlen = j;
                    end = true;
                    // 7, 5 and 2 are the only valid padded symbol counts, so
                    // 1, 3 and 6 symbols leave an incomplete byte (RFC 4648 section 6).
                    if dlen == 1 || dlen == 3 || dlen == 6 {
                        return (n, false, corrupt(pos - 1));
                    }
                    break;
                }
                let Some(value) = self.value(input) else {
                    return (n, false, corrupt(pos - 1));
                };
                dbuf[j] = value;
                j += 1;
            }
            // Pack 8 five-bit symbols into 5 bytes. Shorter quanta write fewer.
            let packed = [
                (dbuf[0] << 3) | (dbuf[1] >> 2),
                (dbuf[1] << 6) | (dbuf[2] << 1) | (dbuf[3] >> 4),
                (dbuf[3] << 4) | (dbuf[4] >> 1),
                (dbuf[4] << 7) | (dbuf[5] << 2) | (dbuf[6] >> 3),
                (dbuf[6] << 5) | dbuf[7],
            ];
            let nbytes = match dlen {
                8 => 5,
                7 => 4,
                5 => 3,
                4 => 2,
                2 => 1,
                _ => 0,
            };
            if nbytes > 0 {
                dst[dsti..dsti + nbytes].copy_from_slice(&packed[..nbytes]);
            }
            n += nbytes;
            dsti += 5;
        }
        (n, end, Ok(()))
    }
    /// Decodes `input`. CR and LF are ignored.
    pub fn decode(&self, input: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.decode_into(input, &mut out)?;
        Ok(out)
    }
    /// Appends the decoding of `input` to `out`. On corrupt input the bytes
    /// decoded before the error stay in `out`, as in Go.
    pub fn decode_into(&self, input: impl AsRef<[u8]>, out: &mut Vec<u8>) -> Result<(), Error> {
        let stripped = strip_newlines(input.as_ref());
        let start = out.len();
        out.resize(start + stripped.len(), 0);
        let (n, _, result) = self.decode_quanta(&stripped, &mut out[start..]);
        out.truncate(start + n);
        result
    }
    /// Wraps `inner` so that bytes written are base32-encoded into it. Call
    /// [`Encoder::finish`] to write the final partial quantum.
    pub fn encoder<W: io::Write>(&self, inner: W) -> Encoder<W> {
        Encoder {
            inner,
            engine: *self,
            tail: [0; 5],
            len: 0,
            failed: false,
        }
    }
    /// Wraps `inner` so that reading yields the decoding of its bytes.
    pub fn decoder<R: io::Read>(&self, inner: R) -> Decoder<R> {
        Decoder {
            inner,
            engine: *self,
            err: None,
            end: false,
            buf: [0; 1024],
            nbuf: 0,
            out: Vec::new(),
        }
    }
}

/// A writer that base32-encodes into another writer; see [`Engine::encoder`].
pub struct Encoder<W> {
    inner: W,
    engine: Engine,
    tail: [u8; 5],
    len: usize,
    failed: bool,
}
impl<W: io::Write> Encoder<W> {
    /// Writes the final partial quantum and returns the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        if self.failed {
            return Err(io::Error::other("base32 encoder failed"));
        }
        if self.len > 0 {
            self.inner
                .write_all(&self.engine.encode_to_vec(&self.tail[..self.len]))?;
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
    fn emit(&mut self, b: &[u8]) -> io::Result<()> {
        self.inner.write_all(&self.engine.encode_to_vec(b))
    }
}
impl<W: io::Write> io::Write for Encoder<W> {
    fn write(&mut self, mut input: &[u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("base32 encoder failed"));
        }
        let original = input.len();
        let result = (|| {
            if self.len > 0 {
                let n = (5 - self.len).min(input.len());
                self.tail[self.len..self.len + n].copy_from_slice(&input[..n]);
                self.len += n;
                input = &input[n..];
                if self.len == 5 {
                    let t = self.tail;
                    self.emit(&t)?;
                    self.len = 0;
                }
            }
            while input.len() >= 5 {
                let n = (input.len() / 5 * 5).min(2560);
                self.emit(&input[..n])?;
                input = &input[n..];
            }
            if !input.is_empty() {
                self.tail[..input.len()].copy_from_slice(input);
                self.len = input.len();
            }
            Ok(original)
        })();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("base32 encoder failed"));
        }
        let r = self.inner.flush();
        if r.is_err() {
            self.failed = true;
        }
        r
    }
}

/// A reader that base32-decodes another reader; see [`Engine::decoder`].
/// It is a port of Go's stream decoder, so the buffering matches: CR and LF
/// are filtered per read, input is decoded in chunks, and data after the
/// padding is an error only when it arrives in a later chunk. Corrupt-input
/// offsets are relative to the chunk being decoded, as in Go. Where Go
/// returns data together with an error, the data is returned first and the
/// error on the next read.
pub struct Decoder<R> {
    inner: R,
    engine: Engine,
    err: Option<StreamError>,
    end: bool,
    buf: [u8; 1024],
    nbuf: usize,
    out: Vec<u8>,
}

/// The sticky error of a [`Decoder`] (Go's `d.err`).
enum StreamError {
    Eof,
    UnexpectedEof,
    Corrupt(Error),
    Io(io::ErrorKind, String),
}
impl StreamError {
    fn result(&self) -> io::Result<usize> {
        match self {
            StreamError::Eof => Ok(0),
            StreamError::UnexpectedEof => Err(io::ErrorKind::UnexpectedEof.into()),
            StreamError::Corrupt(e) => Err(io::Error::new(io::ErrorKind::InvalidData, *e)),
            StreamError::Io(kind, msg) => Err(io::Error::new(*kind, msg.clone())),
        }
    }
}

/// Go's `newlineFilteringReader.Read`: reads again while a read held only CR
/// and LF. `Ok(0)` is end of input.
fn read_filtered<R: io::Read>(inner: &mut R, p: &mut [u8]) -> io::Result<usize> {
    loop {
        let n = loop {
            match inner.read(p) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                x => break x,
            }
        }?;
        if n == 0 {
            return Ok(0);
        }
        let mut kept = 0;
        for i in 0..n {
            if p[i] != b'\r' && p[i] != b'\n' {
                p[kept] = p[i];
                kept += 1;
            }
        }
        if kept > 0 {
            return Ok(kept);
        }
    }
}

impl<R: io::Read> Decoder<R> {
    /// The underlying reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
    /// Go's `readEncodedData`: fills `buf[start..end]` until `min` bytes are
    /// there or an error (including end of input) occurs.
    fn read_encoded_data(
        &mut self,
        end: usize,
        min: usize,
        expects_padding: bool,
    ) -> (usize, Option<StreamError>) {
        let mut n = 0;
        let mut err = None;
        while n < min && err.is_none() {
            let start = self.nbuf + n;
            match read_filtered(&mut self.inner, &mut self.buf[start..end]) {
                Ok(0) => err = Some(StreamError::Eof),
                Ok(nn) => n += nn,
                Err(e) => err = Some(StreamError::Io(e.kind(), e.to_string())),
            }
        }
        let at_eof = matches!(err, Some(StreamError::Eof));
        // Data was read, but less than min bytes could be read.
        if n < min && n > 0 && at_eof {
            err = Some(StreamError::UnexpectedEof);
        }
        // No data was read while the buffer already holds some; without
        // padding this is not an error, as the message can be of any length.
        if expects_padding && min < 8 && n == 0 && at_eof {
            err = Some(StreamError::UnexpectedEof);
        }
        (n, err)
    }
    /// Go's `return n, d.err`: data first, the error on the next read.
    fn finish(&self, n: usize) -> io::Result<usize> {
        match &self.err {
            Some(e) if n == 0 => e.result(),
            _ => Ok(n),
        }
    }
}
impl<R: io::Read> io::Read for Decoder<R> {
    fn read(&mut self, p: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.read_once(p)?;
            // Go can return no data and no error (a chunk that decodes to
            // nothing); `Ok(0)` would read as end of input here, so go on.
            if n > 0 || p.is_empty() || self.err.is_some() {
                return Ok(n);
            }
        }
    }
}
impl<R: io::Read> Decoder<R> {
    /// One call of Go's `decoder.Read`.
    fn read_once(&mut self, p: &mut [u8]) -> io::Result<usize> {
        // Use leftover decoded output from the last read.
        if !self.out.is_empty() {
            let n = p.len().min(self.out.len());
            p[..n].copy_from_slice(&self.out[..n]);
            self.out.drain(..n);
            return if self.out.is_empty() {
                self.finish(n)
            } else {
                Ok(n)
            };
        }
        if let Some(e) = &self.err {
            return e.result();
        }

        // Read a chunk.
        let nn = (p.len().div_ceil(5) * 8).clamp(8, self.buf.len());
        // The minimum number of bytes to read each cycle.
        let padded = self.engine.padding.is_some();
        let min = if padded { 8 - self.nbuf } else { 1 };
        let (got, err) = self.read_encoded_data(nn, min, padded);
        self.err = err;
        self.nbuf += got;
        if self.nbuf < min {
            return self.finish(0);
        }
        if got > 0 && self.end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                Error { offset: 0 },
            ));
        }

        // Decode the chunk into p, or into the leftover output and then p if
        // p is too small.
        let nr = if padded { self.nbuf / 8 * 8 } else { self.nbuf };
        let nw = self.engine.decoded_len(self.nbuf);
        let (n, end, result) = if nw > p.len() {
            let mut outbuf = [0u8; 1024 / 8 * 5];
            let (nw, end, result) = self.engine.decode_quanta(&self.buf[..nr], &mut outbuf);
            self.out = outbuf[..nw].to_vec();
            let n = p.len().min(self.out.len());
            p[..n].copy_from_slice(&self.out[..n]);
            self.out.drain(..n);
            (n, end, result)
        } else {
            self.engine.decode_quanta(&self.buf[..nr], p)
        };
        self.end = end;
        self.nbuf -= nr;
        self.buf.copy_within(nr..nr + self.nbuf, 0);

        if let Err(e) = result {
            if matches!(self.err, None | Some(StreamError::Eof)) {
                self.err = Some(StreamError::Corrupt(e));
            }
        }
        if !self.out.is_empty() {
            // Not everything fit; the error, if any, comes with the last data.
            return Ok(n);
        }
        self.finish(n)
    }
}
