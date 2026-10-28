//! `bufio.Scanner` and its split functions.

use super::{Error, MAX_CONSECUTIVE_EMPTY_READS};
use crate::io::is_eof;
use crate::unicode::rune;
use std::io::{self, Read};

/// The default maximum size of a token (`bufio.MaxScanTokenSize`). Pass a
/// larger limit to [`Scanner::buffer`] for bigger tokens.
pub const MAX_SCAN_TOKEN_SIZE: usize = 64 * 1024;

/// Initial buffer allocation size.
const START_BUF_SIZE: usize = 4096;

/// What a split function found in the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Split<'a> {
    /// No token yet: skip the given number of bytes of input. `Skip(0)` asks
    /// for more data.
    Skip(usize),
    /// Skip the given number of bytes and deliver the token; an empty token
    /// is a token.
    Token(usize, &'a [u8]),
    /// Stop the scan after delivering the token, if any (`ErrFinalToken`).
    Last(Option<&'a [u8]>),
}

/// The result of a split function: what was found, or an error that stops
/// the scan. An advance beyond the input stops it with `ErrAdvanceTooFar`.
pub type SplitResult<'a> = io::Result<Split<'a>>;

/// The signature of the split function used to tokenize input
/// (`bufio.SplitFunc`): `(data, at_eof) -> SplitResult`.
///
/// The arguments are the unprocessed remainder of the input and whether the
/// reader has no more data.
pub trait SplitFunc: for<'a> FnMut(&'a [u8], bool) -> SplitResult<'a> {}
impl<F> SplitFunc for F where F: for<'a> FnMut(&'a [u8], bool) -> SplitResult<'a> {}

/// Provides a convenient interface for reading data such as a file of
/// newline-delimited lines of text (`bufio.Scanner`). It is an iterator over
/// the tokens: each item is a token or the first non-EOF error, after which
/// the iterator ends.
///
/// ```
/// use rust_stdlib::bufio::{scan_words, Scanner};
/// let words: Vec<String> = Scanner::new("a quick  fox".as_bytes())
///     .split(scan_words)
///     .map(|t| String::from_utf8(t.unwrap()).unwrap())
///     .collect();
/// assert_eq!(words, ["a", "quick", "fox"]);
/// ```
pub struct Scanner<R> {
    r: R,
    split: Box<dyn SplitFunc>,
    max_token_size: usize,
    token: Option<Vec<u8>>,
    buf: Vec<u8>,
    start: usize,
    end: usize,
    err: Option<io::Error>,
    reported: bool,
    empties: usize,
    scan_called: bool,
    done: bool,
}

impl<R: Read> Scanner<R> {
    /// Returns a scanner reading lines from `r` (`bufio.NewScanner`).
    pub fn new(r: R) -> Self {
        Scanner {
            r,
            split: Box::new(scan_lines),
            max_token_size: MAX_SCAN_TOKEN_SIZE,
            token: None,
            buf: Vec::new(),
            start: 0,
            end: 0,
            err: None,
            reported: false,
            empties: 0,
            scan_called: false,
            done: false,
        }
    }

    /// Advances to the next token in `self.token` (`Scanner.Scan`). Returns
    /// false at the end of input or on an error.
    fn scan(&mut self) -> bool {
        if self.done {
            return false;
        }
        self.scan_called = true;
        // Loop until we have a token.
        loop {
            // See if we can get a token with what we already have.
            // If we've run out of data but have an error, give the split
            // function a chance to recover any remaining, possibly empty
            // token.
            if self.end > self.start || self.err.is_some() {
                let at_eof = self.err.is_some();
                let (advance, token) = match (self.split)(&self.buf[self.start..self.end], at_eof) {
                    Err(err) => {
                        self.set_err(err);
                        return false;
                    }
                    Ok(Split::Last(token)) => {
                        let token = token.map(<[u8]>::to_vec);
                        let has_token = token.is_some();
                        self.token = token;
                        self.done = true;
                        // When token is not nil, it means the scanning stops
                        // with a trailing empty token, and thus the return
                        // value should be true to indicate the existence of
                        // the token.
                        return has_token;
                    }
                    Ok(Split::Skip(advance)) => (advance, None),
                    Ok(Split::Token(advance, token)) => (advance, Some(token.to_vec())),
                };
                if !self.advance(advance) {
                    return false;
                }
                self.token = token;
                if self.token.is_some() {
                    if self.err.is_none() || advance > 0 {
                        self.empties = 0;
                    } else {
                        // Returning tokens not advancing input at EOF.
                        self.empties += 1;
                        if self.empties > MAX_CONSECUTIVE_EMPTY_READS {
                            // Go panics here, whatever error is pending.
                            self.err = Some(Error::TooManyEmptyTokens.into());
                            self.token = None;
                            return false;
                        }
                    }
                    return true;
                }
            }
            // We cannot generate a token with what we are holding.
            // If we've already hit EOF or an I/O error, we are done.
            if self.err.is_some() {
                // Shut it down.
                self.start = 0;
                self.end = 0;
                return false;
            }
            // Must read more data.
            // First, shift data to beginning of buffer if there's lots of
            // empty space or space is needed.
            if self.start > 0 && (self.end == self.buf.len() || self.start > self.buf.len() / 2) {
                self.buf.copy_within(self.start..self.end, 0);
                self.end -= self.start;
                self.start = 0;
            }
            // Is the buffer full? If so, resize.
            if self.end == self.buf.len() {
                // Guarantee no overflow in the multiplication below.
                if self.buf.len() >= self.max_token_size || self.buf.len() > usize::MAX / 2 {
                    self.set_err(Error::TooLong.into());
                    return false;
                }
                let mut new_size = self.buf.len() * 2;
                if new_size == 0 {
                    new_size = START_BUF_SIZE;
                }
                new_size = new_size.min(self.max_token_size);
                let mut new_buf = vec![0; new_size];
                new_buf[..self.end - self.start].copy_from_slice(&self.buf[self.start..self.end]);
                self.buf = new_buf;
                self.end -= self.start;
                self.start = 0;
            }
            // Finally we can read some input. Make sure we don't get stuck
            // with a misbehaving Reader. Officially we don't need to do this,
            // but let's be extra careful: Scanner is for safe, simple jobs.
            let mut tries = 0;
            loop {
                match self.r.read(&mut self.buf[self.end..]) {
                    Ok(0) => {
                        self.set_err(crate::io::eof());
                        break;
                    }
                    Ok(n) => {
                        self.end += n;
                        self.empties = 0;
                        break;
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                        tries += 1;
                        if tries > MAX_CONSECUTIVE_EMPTY_READS {
                            self.set_err(crate::io::Error::NoProgress.into());
                            break;
                        }
                    }
                    Err(e) => {
                        self.set_err(e);
                        break;
                    }
                }
            }
        }
    }

    /// Consumes `n` bytes of the buffer. Reports whether the advance was legal.
    fn advance(&mut self, n: usize) -> bool {
        if n > self.end - self.start {
            self.set_err(Error::AdvanceTooFar.into());
            return false;
        }
        self.start += n;
        true
    }

    /// Sets the error if it is not already set (or is EOF).
    fn set_err(&mut self, err: io::Error) {
        if self.err.as_ref().is_none_or(is_eof) {
            self.err = Some(err);
        }
    }

    /// Sets the initial buffer to use when scanning and the maximum size of
    /// buffer that may be allocated during scanning (`Scanner.Buffer`). The
    /// initial buffer is `buf` extended to its capacity, as in Go; the
    /// maximum token size is the larger of `max` and the buffer capacity.
    ///
    /// Called after scanning started, the next item is an error (Go panics).
    pub fn buffer(mut self, mut buf: Vec<u8>, max: usize) -> Self {
        if self.misused("Buffer") {
            return self;
        }
        buf.resize(buf.capacity(), 0);
        self.buf = buf;
        self.max_token_size = max;
        self
    }

    /// Sets the split function (`Scanner.Split`); the default is
    /// [`scan_lines`].
    ///
    /// Called after scanning started, the next item is an error (Go panics).
    pub fn split<F: SplitFunc + 'static>(mut self, split: F) -> Self {
        if self.misused("Split") {
            return self;
        }
        self.split = Box::new(split);
        self
    }

    fn misused(&mut self, what: &str) -> bool {
        if self.scan_called {
            self.err = Some(io::Error::other(format!("{what} called after Scan")));
            self.reported = false;
            self.done = true;
        }
        self.scan_called
    }

    /// The underlying reader.
    pub fn get_ref(&self) -> &R {
        &self.r
    }
}

impl<R: Read> Iterator for Scanner<R> {
    type Item = io::Result<Vec<u8>>;

    /// The next token, or the first non-EOF error (`Scanner.Scan`,
    /// `Scanner.Bytes` and `Scanner.Err`); `None` at the end of the input
    /// and after the error.
    fn next(&mut self) -> Option<Self::Item> {
        if self.scan() {
            return Some(Ok(self.token.take().unwrap_or_default()));
        }
        if !self.reported {
            self.reported = true;
            if let Some(e) = self.err.take().filter(|e| !is_eof(e)) {
                return Some(Err(e));
            }
        }
        None
    }
}

/// A split function that returns each byte as a token (`bufio.ScanBytes`).
pub fn scan_bytes(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    if at_eof && data.is_empty() {
        return Ok(Split::Skip(0));
    }
    Ok(Split::Token(1, &data[0..1]))
}

/// The UTF-8 encoding of `U+FFFD`, returned for each invalid encoding.
const ERROR_RUNE: &[u8] = "\u{FFFD}".as_bytes();

/// A split function that returns each UTF-8 encoded rune as a token
/// (`bufio.ScanRunes`). Invalid encodings yield `U+FFFD` for each byte.
pub fn scan_runes(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    if at_eof && data.is_empty() {
        return Ok(Split::Skip(0));
    }
    // Fast path 1: ASCII.
    if data[0] < 0x80 {
        return Ok(Split::Token(1, &data[0..1]));
    }
    // Fast path 2: Correct UTF-8 decode without error.
    let (_, width) = rune::decode_rune(data);
    if width > 1 {
        // It's a valid encoding. Width cannot be one for a correctly encoded
        // non-ASCII rune.
        return Ok(Split::Token(width, &data[0..width]));
    }
    // We know it's an error: we have width==1 and implicitly r==utf8.RuneError.
    // Is the error because there wasn't a full rune to be decoded?
    if !at_eof && !rune::full_rune(data) {
        // Incomplete; get more bytes.
        return Ok(Split::Skip(0));
    }
    // We have a real UTF-8 encoding error. Return a properly encoded error
    // rune but advance only one byte.
    Ok(Split::Token(1, ERROR_RUNE))
}

fn drop_cr(data: &[u8]) -> &[u8] {
    match data.split_last() {
        Some((b'\r', rest)) => rest,
        _ => data,
    }
}

/// A split function that returns each line of text, stripped of any trailing
/// end-of-line marker (`\n` or `\r\n`) (`bufio.ScanLines`). The last
/// non-empty line may have no marker.
pub fn scan_lines(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    if at_eof && data.is_empty() {
        return Ok(Split::Skip(0));
    }
    if let Some(i) = data.iter().position(|&c| c == b'\n') {
        // We have a full newline-terminated line.
        return Ok(Split::Token(i + 1, drop_cr(&data[0..i])));
    }
    // If we're at EOF, we have a final, non-terminated line. Return it.
    if at_eof {
        return Ok(Split::Token(data.len(), drop_cr(data)));
    }
    // Request more data.
    Ok(Split::Skip(0))
}

/// Reports whether the character is a Unicode white space character, as
/// `bufio` and `unicode.IsSpace` define it (including U+0085 and U+00A0).
fn is_space(r: i32) -> bool {
    if r <= 0xFF {
        return matches!(r, 0x20 | 0x09..=0x0D | 0x85 | 0xA0);
    }
    if (0x2000..=0x200a).contains(&r) {
        return true;
    }
    matches!(r, 0x1680 | 0x2028 | 0x2029 | 0x202f | 0x205f | 0x3000)
}

/// A split function that returns each space-separated word of text, with
/// surrounding spaces deleted; it never returns an empty string
/// (`bufio.ScanWords`).
pub fn scan_words(data: &[u8], at_eof: bool) -> SplitResult<'_> {
    // Skip leading spaces.
    let mut start = 0;
    while start < data.len() {
        let (r, width) = rune::decode_rune(&data[start..]);
        if !is_space(r) {
            break;
        }
        start += width;
    }
    // Scan until space, marking end of word.
    let mut i = start;
    while i < data.len() {
        let (r, width) = rune::decode_rune(&data[i..]);
        if is_space(r) {
            return Ok(Split::Token(i + width, &data[start..i]));
        }
        i += width;
    }
    // If we're at EOF, we have a final, non-empty, non-terminated word.
    if at_eof && data.len() > start {
        return Ok(Split::Token(data.len(), &data[start..]));
    }
    // Request more data.
    Ok(Split::Skip(start))
}
