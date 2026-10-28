//! Go's `bufio`: buffered I/O with Go's exact buffer semantics.
//!
//! `std::io::BufReader` cannot do `Peek`, `UnreadRune`, `ReadSlice` or
//! `Discard` with Go's rules, so [`Reader`], [`Writer`] and [`Scanner`]
//! implement Go's buffering (including when a read bypasses the buffer and
//! when `ErrBufferFull` is returned). They also implement `std::io::Read`,
//! `BufRead` and `Write` so they can be used wherever std's are.
//!
//! Errors: the package's error variables are the variants of [`Error`],
//! carried as the payload of an `io::Error` (build with `io::Error::from`,
//! test with [`Error::is`]). `io.EOF` is `crate::io::eof()`.
//!
//! Where Go returns a count or data together with an error the error carries
//! it: [`SliceError::data`] for `ReadSlice`, `crate::io::ReadError::read` for
//! `Discard`, `crate::io::CopyError::written` for `Write`/`WriteString`, and
//! [`Reader::buffer`] for `Peek`. `ReadBytes` and `ReadString` are
//! `BufRead::read_until`, which [`Reader`] implements with Go's read-ahead.
//! [`Scanner`] is an `Iterator` over tokens.

use std::fmt;
use std::io;

mod reader;
mod scan;
mod writer;

pub use reader::{Reader, SliceError};
pub use scan::{
    scan_bytes, scan_lines, scan_runes, scan_words, Scanner, Split, SplitFunc, SplitResult,
    MAX_SCAN_TOKEN_SIZE,
};
pub use writer::{ReadWriter, Writer};

pub(crate) const DEFAULT_BUF_SIZE: usize = 4096;
pub(crate) const MIN_READ_BUFFER_SIZE: usize = 16;
pub(crate) const MAX_CONSECUTIVE_EMPTY_READS: usize = 100;

/// Go's `bufio` error variables.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// `bufio.ErrInvalidUnreadByte`
    InvalidUnreadByte,
    /// `bufio.ErrInvalidUnreadRune`
    InvalidUnreadRune,
    /// `bufio.ErrBufferFull`
    BufferFull,
    /// `bufio.ErrNegativeCount`
    NegativeCount,
    /// `bufio.ErrTooLong`
    TooLong,
    /// `bufio.ErrNegativeAdvance`
    NegativeAdvance,
    /// `bufio.ErrAdvanceTooFar`
    AdvanceTooFar,
    /// `bufio.ErrBadReadCount`
    BadReadCount,
    /// `bufio.ErrFinalToken`: the error of the scan after a
    /// [`Split::Last`] token; the iterator ends instead of yielding it.
    FinalToken,
    /// The split function returned too many empty tokens without advancing
    /// the input (Go's `Scan` panics with this message).
    TooManyEmptyTokens,
}

impl Error {
    /// Reports whether `err` is this error (`errors.Is(err, bufio.ErrX)`).
    pub fn is(self, err: &io::Error) -> bool {
        crate::io::chain_has(err, &self)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidUnreadByte => "bufio: invalid use of UnreadByte",
            Error::InvalidUnreadRune => "bufio: invalid use of UnreadRune",
            Error::BufferFull => "bufio: buffer full",
            Error::NegativeCount => "bufio: negative count",
            Error::TooLong => "bufio.Scanner: token too long",
            Error::NegativeAdvance => "bufio.Scanner: SplitFunc returns negative advance count",
            Error::AdvanceTooFar => "bufio.Scanner: SplitFunc returns advance count beyond input",
            Error::BadReadCount => "bufio.Scanner: Read returned impossible count",
            Error::FinalToken => "final token",
            Error::TooManyEmptyTokens => "bufio.Scan: too many empty tokens without progressing",
        })
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        io::Error::other(e)
    }
}
