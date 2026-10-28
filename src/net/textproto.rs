//! Text protocol framing in the style of Go's `net/textproto`.
//!
//! [`Reader`] reads lines, continued (folded) lines, numeric response codes,
//! dot-encoded blocks and MIME-style headers from any [`BufRead`]; [`Writer`]
//! writes CRLF lines and dot-encoded blocks to any [`Write`]. Line endings
//! follow Go: a line ends at `\n`, and a `\r` directly before it is dropped,
//! so bare LF is accepted while a bare CR stays part of the line.
//!
//! Differences from Go, all explicit errors rather than silent changes:
//! - Every accumulating read is bounded by [`Limits`]. Go's `ReadMIMEHeader`
//!   is unbounded; [`Reader::read_mime_header`] charges the same budget Go's
//!   internal limited variant (used by `net/http`) charges.
//! - Text results are `String`s, so non-UTF-8 bytes in lines and header values
//!   are rejected with [`Error::InvalidUtf8`]; byte variants exist for lines.
//! - Non-EOF I/O errors are returned immediately; Go's `bufio` may first
//!   return a partial line. An over-budget continuation line is an error
//!   where Go stops folding at a buffer-dependent position.
//! - [`Reader`] and [`Writer`] are generic over [`BufRead`] and [`Write`] instead of
//!   wrapping `*bufio.Reader` and `*bufio.Writer`, and the Go `Error` struct is
//!   [`ResponseError`] because [`Error`] is this module's error enum.
//! - [`Conn`] owns a [`Stream`] shared by a reader half and a writer half
//!   instead of embedding the three types; they are the public fields
//!   `reader`, `writer` and `pipeline`.
//! - [`Pipeline::end_request`] and [`Pipeline::end_response`] panic with
//!   `out of sync`, as Go does.
//!
//! ```
//! use rust_stdlib::net::textproto::{Reader, Writer};
//! let mut reader = Reader::new(&b"Content-Type: text/plain\r\nx-id: 7\r\n  8\r\n\r\nbody"[..]);
//! let header = reader.read_mime_header()?;
//! assert_eq!(header.get("content-type"), Some("text/plain"));
//! assert_eq!(header.get("X-Id"), Some("7 8"));
//!
//! let mut out = Vec::new();
//! let mut writer = Writer::new(&mut out);
//! writer.print_line(format_args!("DATA {}", 1))?;
//! let mut dot = writer.dot_writer();
//! std::io::Write::write_all(&mut dot, b".hidden\nline\n")?;
//! dot.close()?;
//! assert_eq!(out, b"DATA 1\r\n..hidden\r\nline\r\n.\r\n");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::net::{Shutdown, TcpStream};
#[cfg(unix)]
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};
use std::{error, fmt};

use crate::net::{self, NetError};

/// Errors from [`Reader`].
#[derive(Debug)]
pub enum Error {
    /// The input ended cleanly before a line started (Go `io.EOF`).
    Eof,
    /// The input ended inside a dot-encoded block (Go `io.ErrUnexpectedEOF`).
    UnexpectedEof,
    /// Malformed protocol data (Go `textproto.ProtocolError`).
    Protocol(ProtocolError),
    /// A response code did not match the expected code (Go `*textproto.Error`).
    Response(ResponseError),
    /// A line, header block, response or body exceeded its [`Limits`] budget.
    MessageTooLarge,
    /// Text that must be returned as a `String` was not valid UTF-8.
    InvalidUtf8,
    /// An I/O error other than end of input.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eof => f.write_str("EOF"),
            Self::UnexpectedEof => f.write_str("unexpected EOF"),
            Self::Protocol(error) => error.fmt(f),
            Self::Response(error) => error.fmt(f),
            Self::MessageTooLarge => f.write_str("message too large"),
            Self::InvalidUtf8 => f.write_str("text protocol data is not valid UTF-8"),
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Protocol(error) => Some(error),
            Self::Response(error) => Some(error),
            _ => None,
        }
    }
}

/// A protocol violation such as an invalid response or a hung-up connection
/// (Go `textproto.ProtocolError`); the text is the whole message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolError(pub String);

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl error::Error for ProtocolError {}

impl From<ProtocolError> for Error {
    fn from(error: ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// A numeric error response from a server (Go `*textproto.Error`). Its text
/// is the code in three digits and the quoted message, as `%03d %q`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseError {
    /// Go `Error.Code`.
    pub code: i32,
    /// Go `Error.Msg`.
    pub msg: String,
}

impl fmt::Display for ResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:03} {}", self.code, quote(self.msg.as_bytes()))
    }
}

impl error::Error for ResponseError {}

impl From<ResponseError> for Error {
    fn from(error: ResponseError) -> Self {
        Self::Response(error)
    }
}

fn protocol(message: String) -> Error {
    Error::Protocol(ProtocolError(message))
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Resource budgets for [`Reader`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Longest physical or continued line returned by the line methods,
    /// excluding its terminator. Also bounds folding whitespace.
    pub max_line_bytes: usize,
    /// Header budget charged as Go's internal `readMIMEHeader` does: 400 bytes
    /// once, then each new key's length plus 200, plus each value's length;
    /// every raw header line must also fit in what remains.
    pub max_header_bytes: usize,
    /// Most header fields in one header block.
    pub max_headers: usize,
    /// Most decoded bytes from [`Reader::read_dot_bytes`] or
    /// [`Reader::read_dot_lines`] (one byte charged per line terminator).
    pub max_dot_bytes: usize,
    /// Most message bytes collected by [`Reader::read_response`].
    pub max_response_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line_bytes: 1 << 20,
            max_header_bytes: 1 << 20,
            max_headers: 10_000,
            max_dot_bytes: 16 << 20,
            max_response_bytes: 1 << 20,
        }
    }
}

/// A MIME-style header: canonical keys mapped to values in input order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MIMEHeader(BTreeMap<String, Vec<String>>);

impl MIMEHeader {
    pub fn new() -> Self {
        Self::default()
    }
    /// Append a value under the canonical form of `key`.
    pub fn add(&mut self, key: &str, value: &str) {
        self.0
            .entry(canonical_mime_header_key(key))
            .or_default()
            .push(value.to_owned());
    }
    /// Replace all values of the canonical form of `key` with `value`.
    pub fn set(&mut self, key: &str, value: &str) {
        self.0
            .insert(canonical_mime_header_key(key), vec![value.to_owned()]);
    }
    /// First value of the canonical form of `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.values(key).first().map(String::as_str)
    }
    /// All values of the canonical form of `key`.
    pub fn values(&self, key: &str) -> &[String] {
        self.raw_values(&canonical_mime_header_key(key))
    }
    /// All values stored under exactly `key`, without canonicalization.
    pub fn raw_values(&self, key: &str) -> &[String] {
        self.0.get(key).map_or(&[], Vec::as_slice)
    }
    /// Remove the canonical form of `key`.
    pub fn del(&mut self, key: &str) {
        self.0.remove(&canonical_mime_header_key(key));
    }
    /// Keys and values in byte order of the stored keys.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[String])> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_slice()))
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn into_map(self) -> BTreeMap<String, Vec<String>> {
        self.0
    }
    pub(crate) fn push_raw(&mut self, key: String, value: String) {
        self.0.entry(key).or_default().push(value);
    }
}

/// Reports whether `c` may appear in a header field name (an RFC 9110 tchar).
fn valid_header_field_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c)
}

/// Reports whether `c` may appear in a header field value: VCHAR, SP, HTAB
/// or obs-text.
fn valid_header_value_byte(c: u8) -> bool {
    c == b'\t' || c >= 0x20 && c != 0x7f
}

fn canonicalize(key: &[u8]) -> Vec<u8> {
    let mut upper = true;
    key.iter()
        .map(|&c| {
            let c = if upper {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            upper = c == b'-';
            c
        })
        .collect()
}

/// Canonical form of a header key: the first letter and every letter after a
/// hyphen upper case, all other letters lower case (`accept-encoding` becomes
/// `Accept-Encoding`). A key containing a space or any byte that is not an
/// RFC 9110 token character is returned unchanged.
pub fn canonical_mime_header_key(key: &str) -> String {
    if key.bytes().all(valid_header_field_byte) {
        // Canonicalization only changes ASCII letters, so this stays UTF-8.
        String::from_utf8(canonicalize(key.as_bytes())).unwrap_or_else(|_| key.to_owned())
    } else {
        key.to_owned()
    }
}

/// Byte form of [`canonical_mime_header_key`] for keys read off the wire.
pub(crate) fn canonical_mime_header_key_bytes(key: &[u8]) -> Vec<u8> {
    if key.iter().all(|&c| valid_header_field_byte(c)) {
        canonicalize(key)
    } else {
        key.to_vec()
    }
}

/// The key accepted by `ReadMIMEHeader`: tokens are canonicalized, keys with
/// spaces are kept verbatim, and anything else (including empty) is invalid.
fn header_key_for_read(key: &[u8]) -> Option<Vec<u8>> {
    if key.is_empty() {
        return None;
    }
    let mut has_space = false;
    for &c in key {
        if c == b' ' {
            has_space = true;
        } else if !valid_header_field_byte(c) {
            return None;
        }
    }
    Some(if has_space {
        key.to_vec()
    } else {
        canonicalize(key)
    })
}

fn is_ascii_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r')
}

/// `s` without leading and trailing ASCII space, tab, CR and LF.
pub fn trim_string(s: &str) -> &str {
    s.trim_matches([' ', '\t', '\n', '\r'])
}

/// `b` without leading and trailing ASCII space, tab, CR and LF.
pub fn trim_bytes(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|&c| !is_ascii_space(c))
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|&c| !is_ascii_space(c))
        .map_or(start, |i| i + 1);
    &b[start..end]
}

/// Trim spaces and tabs only, as Go's internal `trim` does.
fn trim_space_tab(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&c| c != b' ' && c != b'\t')
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&c| c != b' ' && c != b'\t')
        .map_or(start, |i| i + 1);
    &s[start..end]
}

/// Go's `%q`.
fn quote(bytes: &[u8]) -> String {
    crate::strconv::quote(bytes)
}

fn utf8(bytes: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)
}

/// Dot-decoding states, as in Go's `dotReader`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DotState {
    BeginLine,
    Dot,
    DotCr,
    Cr,
    Data,
    Eof,
}

/// Reads text protocol units from a buffered reader.
///
/// A [`DotReader`] that is dropped before its terminating `.` line is drained
/// by the next call to any other reading method, as in Go.
#[derive(Debug)]
pub struct Reader<R> {
    inner: R,
    limits: Limits,
    dot: Option<DotState>,
}

impl<R: BufRead> Reader<R> {
    /// A reader with default [`Limits`].
    pub fn new(inner: R) -> Self {
        Self::with_limits(inner, Limits::default())
    }
    pub fn with_limits(inner: R, limits: Limits) -> Self {
        Self {
            inner,
            limits,
            dot: None,
        }
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    pub fn get_ref(&self) -> &R {
        &self.inner
    }
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
    /// The underlying reader, positioned after the last unit read. An
    /// undrained dot block is left where it stopped.
    pub fn into_inner(self) -> R {
        self.inner
    }

    fn fill(&mut self) -> io::Result<&[u8]> {
        loop {
            match self.inner.fill_buf() {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        self.inner.fill_buf()
    }

    /// Next byte without consuming it; `None` at end of input.
    pub(crate) fn peek_byte(&mut self) -> Result<Option<u8>, Error> {
        self.close_dot();
        Ok(self.fill()?.first().copied())
    }

    /// Read one line of at most `limit` content bytes (negative: unlimited),
    /// dropping `\n` or `\r\n`.
    fn read_line_slice(&mut self, limit: i64) -> Result<Vec<u8>, Error> {
        self.close_dot();
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let mut line = Vec::new();
        loop {
            let available = self.fill()?;
            if available.is_empty() {
                // End of input: a partial line is still a line, and a final
                // CR without LF is part of it.
                return match line.len() {
                    0 => Err(Error::Eof),
                    n if n > limit => Err(Error::MessageTooLarge),
                    _ => Ok(line),
                };
            }
            match available.iter().position(|&b| b == b'\n') {
                Some(i) => {
                    line.extend_from_slice(&available[..i]);
                    self.inner.consume(i + 1);
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    if line.len() > limit {
                        return Err(Error::MessageTooLarge);
                    }
                    return Ok(line);
                }
                None => {
                    let n = available.len();
                    line.extend_from_slice(available);
                    self.inner.consume(n);
                    // A trailing CR may still be the start of a CRLF.
                    let content = line.len() - usize::from(line.last() == Some(&b'\r'));
                    if content > limit {
                        return Err(Error::MessageTooLarge);
                    }
                }
            }
        }
    }

    fn line_limit(&self) -> i64 {
        i64::try_from(self.limits.max_line_bytes).unwrap_or(i64::MAX)
    }

    /// Read one line, without its `\n` or `\r\n` terminator.
    pub fn read_line(&mut self) -> Result<String, Error> {
        utf8(self.read_line_bytes()?)
    }

    /// Byte form of [`read_line`](Self::read_line).
    pub fn read_line_bytes(&mut self) -> Result<Vec<u8>, Error> {
        self.read_line_slice(self.line_limit())
    }

    /// Read a line plus any continuation lines that start with a space or
    /// tab. Each line is trimmed of surrounding spaces and tabs and the parts
    /// are joined by one space. Empty lines are never continued.
    pub fn read_continued_line(&mut self) -> Result<String, Error> {
        utf8(self.read_continued_line_bytes()?)
    }

    /// Byte form of [`read_continued_line`](Self::read_continued_line).
    pub fn read_continued_line_bytes(&mut self) -> Result<Vec<u8>, Error> {
        self.read_continued_line_slice(self.line_limit(), false)
    }

    fn skip_space(&mut self) -> Result<usize, Error> {
        let mut skipped = 0;
        loop {
            let available = self.fill()?;
            let n = available
                .iter()
                .take_while(|&&b| b == b' ' || b == b'\t')
                .count();
            let more = n == available.len() && n > 0;
            self.inner.consume(n);
            skipped += n;
            if skipped > self.limits.max_line_bytes {
                return Err(Error::MessageTooLarge);
            }
            if !more {
                return Ok(skipped);
            }
        }
    }

    /// Port of Go's `readContinuedLineSlice`, including its accounting: the
    /// first line is charged against `limit` and the remaining budget is
    /// compared with the whole accumulated line.
    fn read_continued_line_slice(
        &mut self,
        limit: i64,
        need_colon: bool,
    ) -> Result<Vec<u8>, Error> {
        let line = self.read_line_slice(limit)?;
        if line.is_empty() {
            return Ok(line);
        }
        if need_colon && !line.contains(&b':') {
            return Err(protocol(format!(
                "malformed MIME header: missing colon: {}",
                quote(&line)
            )));
        }
        let mut buf = trim_space_tab(&line).to_vec();
        let limit = if limit < 0 { i64::MAX } else { limit } - buf.len() as i64;
        while self.skip_space()? > 0 {
            buf.push(b' ');
            if buf.len() as i64 >= limit {
                return Err(Error::MessageTooLarge);
            }
            match self.read_line_slice(limit - buf.len() as i64) {
                Ok(next) => buf.extend_from_slice(trim_space_tab(&next)),
                Err(Error::Eof) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(buf)
    }

    /// Read a `code message` line and check it against `expect_code`.
    ///
    /// An `expect_code` of 1..=9 checks the first digit, 10..=99 the first two
    /// digits and 100..=999 the whole code; zero or negative disables the
    /// check. A mismatch is [`Error::Response`]; a `code-message`
    /// continuation line is a protocol error.
    pub fn read_code_line(&mut self, expect_code: i32) -> Result<(u16, String), Error> {
        let line = self.read_line()?;
        let parsed = parse_code_line(&line, expect_code);
        if let Some(error) = parsed.error {
            return Err(error);
        }
        if parsed.continued {
            return Err(protocol(format!(
                "unexpected multi-line response: {}",
                quote(parsed.message.as_bytes())
            )));
        }
        Ok((parsed.code, parsed.message))
    }

    /// Read a possibly multi-line response (`code-text` lines ending with a
    /// `code text` line, or RFC 959 lines without codes). Lines of the
    /// message are joined with `\n`. Code checks follow
    /// [`read_code_line`](Self::read_code_line); on a mismatch the error
    /// carries the complete message.
    pub fn read_response(&mut self, expect_code: i32) -> Result<(u16, String), Error> {
        let line = self.read_line()?;
        let first = parse_code_line(&line, expect_code);
        let multi = first.continued;
        let mut continued = first.continued;
        let mut message = first.message;
        while continued {
            let line = self.read_line()?;
            let parsed = parse_code_line(&line, 0);
            message.push('\n');
            if parsed.error.is_some() || parsed.code != first.code {
                message.push_str(line.trim_end_matches(['\r', '\n']));
                continued = true;
            } else {
                message.push_str(&parsed.message);
                continued = parsed.continued;
            }
            if message.len() > self.limits.max_response_bytes {
                return Err(Error::MessageTooLarge);
            }
        }
        match first.error {
            None => Ok((first.code, message)),
            Some(Error::Response(ResponseError { code, .. })) if multi && !message.is_empty() => {
                Err(Error::Response(ResponseError { code, msg: message }))
            }
            Some(error) => Err(error),
        }
    }

    /// Start reading a dot-encoded block: CRLF becomes LF, a leading dot is
    /// removed, and the block ends after a line holding only `.`.
    pub fn dot_reader(&mut self) -> DotReader<'_, R> {
        self.close_dot();
        self.dot = Some(DotState::BeginLine);
        DotReader {
            reader: self,
            finished: None,
        }
    }

    /// Drain an abandoned dot block up to its terminator or an error.
    fn close_dot(&mut self) {
        while self.dot.is_some() {
            let mut sink = [0; 128];
            if self.decode_dot(&mut sink).is_err() {
                self.dot = None;
            }
        }
    }

    /// Port of Go's `dotReader.Read` state machine. Returns `Ok(0)` only at
    /// the terminator; leaves `self.dot` as `None` once the block is done.
    fn decode_dot(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        let mut n = 0;
        while n < out.len() {
            let Some(mut state) = self.dot else {
                break;
            };
            if state == DotState::Eof {
                self.dot = None;
                break;
            }
            let available = match self.fill() {
                Ok(available) => available,
                Err(error) => {
                    if n > 0 {
                        return Ok(n);
                    }
                    self.dot = None;
                    return Err(error.into());
                }
            };
            let Some(&c) = available.first() else {
                if n > 0 {
                    return Ok(n);
                }
                self.dot = None;
                return Err(Error::UnexpectedEof);
            };
            // `emit` is the byte produced; `consume` is false where Go unreads.
            let (mut emit, mut consume) = (Some(c), true);
            match state {
                DotState::BeginLine => match c {
                    b'.' => (state, emit) = (DotState::Dot, None),
                    b'\r' => (state, emit) = (DotState::Cr, None),
                    _ => state = DotState::Data,
                },
                DotState::Dot => match c {
                    b'\r' => (state, emit) = (DotState::DotCr, None),
                    b'\n' => (state, emit) = (DotState::Eof, None),
                    _ => state = DotState::Data,
                },
                DotState::DotCr => {
                    if c == b'\n' {
                        (state, emit) = (DotState::Eof, None);
                    } else {
                        // Not ".\r\n": drop the dot and emit the saved CR.
                        (state, emit, consume) = (DotState::Data, Some(b'\r'), false);
                    }
                }
                DotState::Cr => {
                    if c == b'\n' {
                        state = DotState::BeginLine;
                    } else {
                        (state, emit, consume) = (DotState::Data, Some(b'\r'), false);
                    }
                }
                DotState::Data => match c {
                    b'\r' => (state, emit) = (DotState::Cr, None),
                    b'\n' => state = DotState::BeginLine,
                    _ => {}
                },
                DotState::Eof => {}
            }
            if consume {
                self.inner.consume(1);
            }
            self.dot = Some(state);
            if let Some(byte) = emit {
                out[n] = byte;
                n += 1;
            }
        }
        if self.dot == Some(DotState::Eof) {
            self.dot = None;
        }
        Ok(n)
    }

    /// Read a whole dot-encoded block (see [`dot_reader`](Self::dot_reader)).
    pub fn read_dot_bytes(&mut self) -> Result<Vec<u8>, Error> {
        let limit = self.limits.max_dot_bytes;
        let mut dot = self.dot_reader();
        let mut out = Vec::new();
        let mut chunk = [0; 4096];
        loop {
            let n = dot.read_decoded(&mut chunk)?;
            if n == 0 {
                return Ok(out);
            }
            if out.len() + n > limit {
                return Err(Error::MessageTooLarge);
            }
            out.extend_from_slice(&chunk[..n]);
        }
    }

    /// Read a dot-encoded block as lines, using line framing rather than the
    /// [`DotReader`] state machine (as Go does): each line loses its `\n` or
    /// `\r\n` and one leading dot, and a line holding only `.` ends the block.
    pub fn read_dot_lines(&mut self) -> Result<Vec<String>, Error> {
        let mut lines = Vec::new();
        let mut total = 0usize;
        loop {
            let line = match self.read_line_bytes() {
                Ok(line) => line,
                Err(Error::Eof) => return Err(Error::UnexpectedEof),
                Err(error) => return Err(error),
            };
            let line = match line.split_first() {
                Some((b'.', [])) => return Ok(lines),
                Some((b'.', rest)) => rest.to_vec(),
                _ => line,
            };
            total = total.saturating_add(line.len() + 1);
            if total > self.limits.max_dot_bytes {
                return Err(Error::MessageTooLarge);
            }
            lines.push(utf8(line)?);
        }
    }

    /// Read a MIME-style header block ending at an empty line, validating
    /// field names and values as Go does and enforcing
    /// [`Limits::max_header_bytes`] and [`Limits::max_headers`]. Input that
    /// ends before the empty line is [`Error::Eof`].
    pub fn read_mime_header(&mut self) -> Result<MIMEHeader, Error> {
        let memory = i64::try_from(self.limits.max_header_bytes).unwrap_or(i64::MAX);
        let headers = i64::try_from(self.limits.max_headers).unwrap_or(i64::MAX);
        self.read_mime_header_limited(memory, headers)
    }

    /// Port of Go's internal `readMIMEHeader(r, maxMemory, maxHeaders)`.
    pub(crate) fn read_mime_header_limited(
        &mut self,
        mut max_memory: i64,
        mut max_headers: i64,
    ) -> Result<MIMEHeader, Error> {
        const MAP_ENTRY_OVERHEAD: i64 = 200;
        let mut header = MIMEHeader::new();
        max_memory -= 400;
        if matches!(self.peek_byte()?, Some(b' ' | b'\t')) {
            let line = self.read_line_slice(80)?;
            return Err(protocol(format!(
                "malformed MIME header initial line: {}",
                quote(&line)
            )));
        }
        loop {
            // Go treats a negative remainder (a budget under the 400-byte
            // overhead) as "unlimited" for the line read and only fails
            // afterwards, so the error for a malformed line is the protocol
            // error rather than "message too large".
            let kv = self.read_continued_line_slice(max_memory, true)?;
            if kv.is_empty() {
                return Ok(header);
            }
            let malformed = || protocol(format!("malformed MIME header line: {}", quote(&kv)));
            let colon = kv.iter().position(|&b| b == b':').ok_or_else(malformed)?;
            let (key, value) = (&kv[..colon], &kv[colon + 1..]);
            let key = header_key_for_read(key).ok_or_else(malformed)?;
            if !value.iter().all(|&c| valid_header_value_byte(c)) {
                // Go canonicalizes the key in place, inside `kv`, before it
                // validates the value, so the message shows the canonical key.
                let shown = [&key[..], &kv[colon..]].concat();
                return Err(protocol(format!(
                    "malformed MIME header line: {}",
                    quote(&shown)
                )));
            }
            max_headers -= 1;
            if max_headers < 0 {
                return Err(Error::MessageTooLarge);
            }
            let value = &value[value
                .iter()
                .position(|&c| c != b' ' && c != b'\t')
                .unwrap_or(value.len())..];
            // Keys are ASCII here; values may carry obs-text.
            let key = utf8(key)?;
            let value = utf8(value.to_vec())?;
            if header.raw_values(&key).is_empty() {
                max_memory -= key.len() as i64 + MAP_ENTRY_OVERHEAD;
            }
            max_memory -= value.len() as i64;
            if max_memory < 0 {
                return Err(Error::MessageTooLarge);
            }
            header.push_raw(key, value);
        }
    }
}

struct CodeLine {
    code: u16,
    continued: bool,
    message: String,
    error: Option<Error>,
}

fn parse_code_line(line: &str, expect_code: i32) -> CodeLine {
    let bytes = line.as_bytes();
    let mut parsed = CodeLine {
        code: 0,
        continued: false,
        message: String::new(),
        error: None,
    };
    if bytes.len() < 4 || bytes[3] != b' ' && bytes[3] != b'-' {
        parsed.error = Some(protocol(format!(
            "short response: {}",
            quote(line.as_bytes())
        )));
        return parsed;
    }
    parsed.continued = bytes[3] == b'-';
    // Go's strconv.Atoi also takes a sign, but every signed or shorter
    // three-byte value is below 100 and rejected the same way.
    if !bytes[..3].iter().all(u8::is_ascii_digit) || bytes[0] == b'0' {
        parsed.error = Some(protocol(format!(
            "invalid response code: {}",
            quote(line.as_bytes())
        )));
        return parsed;
    }
    let code = bytes[..3]
        .iter()
        .fold(0u16, |n, &d| n * 10 + u16::from(d - b'0'));
    parsed.code = code;
    parsed.message = line[4..].to_owned();
    let code = i32::from(code);
    if (1..10).contains(&expect_code) && code / 100 != expect_code
        || (10..100).contains(&expect_code) && code / 10 != expect_code
        || (100..1000).contains(&expect_code) && code != expect_code
    {
        parsed.error = Some(Error::Response(ResponseError {
            code: i32::from(parsed.code),
            msg: parsed.message.clone(),
        }));
    }
    parsed
}

/// Streaming decoder for one dot-encoded block, from [`Reader::dot_reader`].
///
/// Reads return `Ok(0)` after the terminating `.` line and an
/// [`io::ErrorKind::UnexpectedEof`] error if the input ends first.
#[derive(Debug)]
pub struct DotReader<'a, R> {
    reader: &'a mut Reader<R>,
    /// Set once the block ended: `true` at the terminator, `false` on error.
    finished: Option<bool>,
}

impl<R: BufRead> DotReader<'_, R> {
    fn read_decoded(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        match self.finished {
            Some(true) => return Ok(0),
            Some(false) => return Err(Error::UnexpectedEof),
            None => {}
        }
        if out.is_empty() {
            return Ok(0);
        }
        match self.reader.decode_dot(out) {
            Ok(0) => {
                self.finished = Some(true);
                Ok(0)
            }
            Ok(n) => Ok(n),
            Err(error) => {
                self.finished = Some(false);
                Err(error)
            }
        }
    }
}

impl<R: BufRead> Read for DotReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_decoded(buf).map_err(|error| match error {
            Error::Io(error) => error,
            Error::UnexpectedEof => io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "dot-encoded block ended without terminator",
            ),
            other => io::Error::new(io::ErrorKind::InvalidData, other.to_string()),
        })
    }
}

/// Dot-encoding states, as in Go's `dotWriter`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DotWriteState {
    Begin,
    BeginLine,
    Cr,
    Data,
}

/// Writes text protocol lines and dot-encoded blocks.
///
/// A [`DotWriter`] that is dropped without [`DotWriter::close`] is closed by
/// the next call to [`Writer::print_line`], [`Writer::dot_writer`] or
/// [`Writer::into_inner`], as in Go.
#[derive(Debug)]
pub struct Writer<W: Write> {
    inner: W,
    dot: Option<DotWriteState>,
}

impl<W: Write> Writer<W> {
    pub fn new(inner: W) -> Self {
        Self { inner, dot: None }
    }
    pub fn get_ref(&self) -> &W {
        &self.inner
    }
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }
    /// Close any pending dot block and return the writer.
    pub fn into_inner(mut self) -> io::Result<W> {
        self.close_dot()?;
        Ok(self.inner)
    }

    /// Write `line` followed by CRLF, then flush (Go `PrintfLine`). Pass
    /// `format_args!` for formatted output. The text is written as given;
    /// callers must not embed CR or LF unless they intend several lines.
    pub fn print_line(&mut self, line: impl fmt::Display) -> io::Result<()> {
        self.close_dot()?;
        write!(self.inner, "{line}\r\n")?;
        self.inner.flush()
    }

    /// Start a dot-encoded block: leading dots are doubled, LF becomes CRLF,
    /// and [`DotWriter::close`] writes the final `.` line.
    pub fn dot_writer(&mut self) -> DotWriter<'_, W> {
        // A failed close of an abandoned block surfaces on the next write.
        let pending = self.close_dot().err();
        self.dot = Some(DotWriteState::Begin);
        DotWriter {
            writer: self,
            pending,
        }
    }

    fn close_dot(&mut self) -> io::Result<()> {
        let Some(state) = self.dot.take() else {
            return Ok(());
        };
        let tail: &[u8] = match state {
            DotWriteState::Begin | DotWriteState::Data => b"\r\n.\r\n",
            DotWriteState::Cr => b"\n.\r\n",
            DotWriteState::BeginLine => b".\r\n",
        };
        self.inner.write_all(tail)?;
        self.inner.flush()
    }
}

/// Streaming encoder for one dot-encoded block, from [`Writer::dot_writer`].
#[derive(Debug)]
pub struct DotWriter<'a, W: Write> {
    writer: &'a mut Writer<W>,
    pending: Option<io::Error>,
}

impl<W: Write> DotWriter<'_, W> {
    /// Finish the block with its terminating line and flush.
    pub fn close(mut self) -> io::Result<()> {
        if let Some(error) = self.pending.take() {
            return Err(error);
        }
        self.writer.close_dot()
    }
}

impl<W: Write> Write for DotWriter<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(error) = self.pending.take() {
            return Err(error);
        }
        let mut state = self.writer.dot.unwrap_or(DotWriteState::Begin);
        let mut out = Vec::with_capacity(buf.len() + buf.len() / 8 + 2);
        for &c in buf {
            match state {
                DotWriteState::Begin | DotWriteState::BeginLine | DotWriteState::Data => {
                    if state != DotWriteState::Data && c == b'.' {
                        out.push(b'.');
                    }
                    state = DotWriteState::Data;
                    if c == b'\r' {
                        state = DotWriteState::Cr;
                    }
                    if c == b'\n' {
                        out.push(b'\r');
                        state = DotWriteState::BeginLine;
                    }
                }
                DotWriteState::Cr => {
                    state = if c == b'\n' {
                        DotWriteState::BeginLine
                    } else {
                        DotWriteState::Data
                    };
                }
            }
            out.push(c);
        }
        self.writer.dot = Some(state);
        self.writer.inner.write_all(&out)?;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.inner.flush()
    }
}

/// Sequences numbered events that must happen in order (Go `sequencer`).
#[derive(Debug, Default)]
struct Sequencer {
    id: Mutex<u64>,
    turn: Condvar,
}

impl Sequencer {
    fn start(&self, id: u64) {
        let mut active = self.id.lock().unwrap_or_else(|e| e.into_inner());
        while *active != id {
            active = self.turn.wait(active).unwrap_or_else(|e| e.into_inner());
        }
    }

    fn end(&self, id: u64) {
        let mut active = self.id.lock().unwrap_or_else(|e| e.into_inner());
        if *active != id {
            drop(active);
            panic!("out of sync");
        }
        *active = id.wrapping_add(1);
        self.turn.notify_all();
    }
}

/// A pipelined in-order request/response sequence (Go `textproto.Pipeline`).
///
/// To use a pipeline to manage several clients on one connection, each
/// client takes a number with [`next`](Self::next), waits for its turn to
/// send with [`start_request`](Self::start_request), sends, calls
/// [`end_request`](Self::end_request), and does the same with
/// [`start_response`](Self::start_response) and
/// [`end_response`](Self::end_response) around reading the response. A
/// pipelined server uses the same calls to write responses in request order.
///
/// All methods take `&self`, so a pipeline can be shared between threads.
#[derive(Debug, Default)]
pub struct Pipeline {
    next: Mutex<u64>,
    request: Sequencer,
    response: Sequencer,
}

impl Pipeline {
    pub fn new() -> Self {
        Self::default()
    }
    /// The next id for a request/response pair.
    pub fn next(&self) -> u64 {
        let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
        let id = *next;
        *next = id.wrapping_add(1);
        id
    }
    /// Block until it is time to send (or, for a server, receive) the
    /// request with `id`.
    pub fn start_request(&self, id: u64) {
        self.request.start(id);
    }
    /// Report that the request with `id` has been sent (or received).
    ///
    /// # Panics
    ///
    /// Panics with `out of sync` if `id` is not the active request, as Go does.
    pub fn end_request(&self, id: u64) {
        self.request.end(id);
    }
    /// Block until it is time to receive (or, for a server, send) the
    /// response with `id`.
    pub fn start_response(&self, id: u64) {
        self.response.start(id);
    }
    /// Report that the response with `id` has been received (or sent).
    ///
    /// # Panics
    ///
    /// Panics with `out of sync` if `id` is not the active response.
    pub fn end_response(&self, id: u64) {
        self.response.end(id);
    }
}

/// A full-duplex byte stream whose reads and writes take `&self`, so a
/// [`Conn`] can read and write it from different threads without a lock.
pub trait Stream: Send + Sync {
    /// Read into `buf`; `Ok(0)` is end of stream.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&self, buf: &[u8]) -> io::Result<usize>;
    /// Close the stream; later and blocked reads and writes fail.
    fn close(&self) -> io::Result<()>;
}

impl Stream for TcpStream {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&mut &*self).read(buf)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        (&mut &*self).write(buf)
    }
    fn close(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Both)
    }
}

#[cfg(unix)]
impl Stream for UnixStream {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&mut &*self).read(buf)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        (&mut &*self).write(buf)
    }
    fn close(&self) -> io::Result<()> {
        self.shutdown(Shutdown::Both)
    }
}

impl Stream for Box<dyn net::Conn> {
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        net::Conn::read(&**self, buf).map_err(NetError::into_io)
    }
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        net::Conn::write(&**self, buf).map_err(NetError::into_io)
    }
    fn close(&self) -> io::Result<()> {
        net::Conn::close(&**self).map_err(NetError::into_io)
    }
}

/// The read side of a [`Conn`]'s stream.
#[derive(Debug)]
pub struct ReadHalf<S>(Arc<S>);

impl<S: Stream> Read for ReadHalf<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

/// The write side of a [`Conn`]'s stream.
#[derive(Debug)]
pub struct WriteHalf<S>(Arc<S>);

impl<S: Stream> Write for WriteHalf<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A textual network protocol connection (Go `textproto.Conn`): a buffered
/// [`Reader`] and [`Writer`] over one stream, and a [`Pipeline`] to sequence
/// concurrent requests on it. Go embeds the three types; here they are public
/// fields, so for example `conn.reader.read_response(250)` and
/// `conn.pipeline.next()`.
///
/// The halves are separate fields so they can be moved to different threads
/// with [`into_parts`](Self::into_parts) for real pipelining.
#[derive(Debug)]
pub struct Conn<S: Stream> {
    pub reader: Reader<BufReader<ReadHalf<S>>>,
    pub writer: Writer<BufWriter<WriteHalf<S>>>,
    pub pipeline: Pipeline,
    stream: Arc<S>,
}

/// Connect to `addr` on `network` with [`net::dial`] and return a [`Conn`]
/// for the connection (Go `textproto.Dial`).
pub fn dial(network: &str, addr: &str) -> Result<Conn<Box<dyn net::Conn>>, NetError> {
    Ok(Conn::new(net::dial(network, addr)?))
}

impl<S: Stream> Conn<S> {
    pub fn new(stream: S) -> Self {
        let stream = Arc::new(stream);
        Self {
            reader: Reader::new(BufReader::new(ReadHalf(stream.clone()))),
            writer: Writer::new(BufWriter::new(WriteHalf(stream.clone()))),
            pipeline: Pipeline::new(),
            stream,
        }
    }

    /// Close the connection (Go `Conn.Close`). Buffered writes are not flushed.
    pub fn close(&self) -> io::Result<()> {
        self.stream.close()
    }

    /// Send a command after waiting its turn in the pipeline: `line` plus
    /// CRLF (Go `Conn.Cmd`; pass `format_args!` for formatting). Returns the
    /// id of the command, for use with
    /// [`Pipeline::start_response`] and [`Pipeline::end_response`].
    ///
    /// ```
    /// use rust_stdlib::net::textproto::Conn;
    /// use std::net::{TcpListener, TcpStream};
    /// let listener = TcpListener::bind("127.0.0.1:0")?;
    /// let mut conn = Conn::new(TcpStream::connect(listener.local_addr()?)?);
    /// let id = conn.cmd(format_args!("HELP {}", 1))?;
    /// assert_eq!(id, 0);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn cmd(&mut self, line: impl fmt::Display) -> io::Result<u64> {
        let id = self.pipeline.next();
        self.pipeline.start_request(id);
        let result = self.writer.print_line(line);
        self.pipeline.end_request(id);
        result.map(|()| id)
    }

    /// Split into the reader, the writer and the pipeline, plus a handle that
    /// still closes the stream.
    pub fn into_parts(self) -> ConnParts<S> {
        ConnParts {
            reader: self.reader,
            writer: self.writer,
            pipeline: self.pipeline,
            closer: Closer(self.stream),
        }
    }
}

/// The pieces of a [`Conn`], from [`Conn::into_parts`].
#[derive(Debug)]
pub struct ConnParts<S: Stream> {
    pub reader: Reader<BufReader<ReadHalf<S>>>,
    pub writer: Writer<BufWriter<WriteHalf<S>>>,
    pub pipeline: Pipeline,
    pub closer: Closer<S>,
}

/// Closes the stream of a split [`Conn`].
#[derive(Debug)]
pub struct Closer<S>(Arc<S>);

impl<S: Stream> Closer<S> {
    pub fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}
