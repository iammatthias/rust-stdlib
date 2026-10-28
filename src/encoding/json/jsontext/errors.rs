//! The errors of `jsontext` and of the packages built on it.
//!
//! Go reports every failure as an `error` interface value and compares
//! sentinels with `==`. Here one [`Error`] enum carries all of them: the
//! sentinels are unit variants (compare with [`Error::is`]), the structured
//! errors hold their data, and [`Error::Other`] wraps any user error.
use std::error::Error as StdError;
use std::fmt;
use std::io;
use std::sync::Arc;

use super::state::Pointer;
use super::wire::{quote_rune, truncate_pointer};
use crate::encoding::json::v2::SemanticError;
use crate::strconv;
use crate::unicode::{self, rune};

const ERROR_PREFIX: &str = "jsontext: ";

/// Every error value of `jsontext` and `json/v2`.
#[derive(Clone, Debug)]
pub enum Error {
    /// `io.EOF`.
    Eof,
    /// `io.ErrUnexpectedEOF`.
    UnexpectedEof,
    /// `jsonwire.ErrInvalidUTF8`: "invalid UTF-8".
    InvalidUtf8,
    /// `jsontext.ErrDuplicateName`.
    DuplicateName,
    /// `jsontext.ErrNonStringName`.
    NonStringName,
    /// "missing value after object name".
    MissingValue,
    /// "mismatching structural token for object or array".
    MismatchDelim,
    /// "exceeded max depth".
    MaxDepth,
    /// "object namespace is in an invalid state".
    InvalidNamespace,
    /// "invalid jsontext.Token".
    InvalidToken,
    /// `jsonv2.ErrUnknownName`.
    UnknownName,
    /// "ambiguous object member name".
    AmbiguousName,
    /// `jsonwire.InvalidTextError`.
    InvalidText(Box<InvalidTextError>),
    /// `*jsontext.SyntacticError`.
    Syntactic(Box<SyntacticError>),
    /// `*jsonv2.SemanticError`.
    Semantic(Box<SemanticError>),
    /// A failure of the underlying reader or writer.
    Io(IoError),
    /// A failed `Token.Int`, `Token.Uint` or `Token.Float`.
    Num(Box<NumError>),
    /// An error with a JSON Pointer suffix that is still being built.
    PointerSuffix(Box<PointerSuffixError>),
    /// Any other error, such as one returned by user code.
    Other(Arc<dyn StdError + Send + Sync>),
}

/// The sentinel `jsontext.ErrDuplicateName`.
pub const ERR_DUPLICATE_NAME: Error = Error::DuplicateName;
/// The sentinel `jsontext.ErrNonStringName`.
pub const ERR_NON_STRING_NAME: Error = Error::NonStringName;

impl Error {
    /// Wraps an arbitrary error value.
    pub fn other<E: StdError + Send + Sync + 'static>(e: E) -> Error {
        Error::Other(Arc::new(e))
    }

    /// An error with the given message (Go's `errors.New`).
    pub fn msg(text: &str) -> Error {
        Error::Other(Arc::new(crate::error::Message::new(text)))
    }

    /// Reports whether this is the same sentinel as `target` (Go's `==` on
    /// error values for the sentinel variants).
    pub fn is(&self, target: &Error) -> bool {
        use Error::*;
        match (self, target) {
            (Eof, Eof)
            | (UnexpectedEof, UnexpectedEof)
            | (InvalidUtf8, InvalidUtf8)
            | (DuplicateName, DuplicateName)
            | (NonStringName, NonStringName)
            | (MissingValue, MissingValue)
            | (MismatchDelim, MismatchDelim)
            | (MaxDepth, MaxDepth)
            | (InvalidNamespace, InvalidNamespace)
            | (InvalidToken, InvalidToken)
            | (UnknownName, UnknownName)
            | (AmbiguousName, AmbiguousName) => true,
            (Other(a), Other(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }

    /// Go's `errors.Is`: reports whether this error or any error it wraps is
    /// the sentinel `target`.
    pub fn has(&self, target: &Error) -> bool {
        let mut cur = Some(self);
        while let Some(e) = cur {
            if e.is(target) {
                return true;
            }
            cur = e.inner();
        }
        false
    }

    /// The wrapped error (Go's `Unwrap`).
    pub fn inner(&self) -> Option<&Error> {
        match self {
            Error::Syntactic(e) => e.err.as_ref(),
            Error::Semantic(e) => e.err.as_ref(),
            Error::PointerSuffix(e) => Some(&e.error),
            _ => None,
        }
    }

    /// The `*SyntacticError`, if that is what this is.
    pub fn as_syntactic(&self) -> Option<&SyntacticError> {
        match self {
            Error::Syntactic(e) => Some(e),
            _ => None,
        }
    }

    /// The `*SemanticError`, if that is what this is.
    pub fn as_semantic(&self) -> Option<&SemanticError> {
        match self {
            Error::Semantic(e) => Some(e),
            _ => None,
        }
    }

    /// Reports whether this is a failure of the underlying reader or writer.
    pub fn is_io_error(&self) -> bool {
        matches!(self, Error::Io(_))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Eof => f.write_str("EOF"),
            Error::UnexpectedEof => f.write_str("unexpected EOF"),
            Error::InvalidUtf8 => f.write_str("invalid UTF-8"),
            Error::DuplicateName => f.write_str("duplicate object member name"),
            Error::NonStringName => f.write_str("object member name must be a string"),
            Error::MissingValue => f.write_str("missing value after object name"),
            Error::MismatchDelim => f.write_str("mismatching structural token for object or array"),
            Error::MaxDepth => f.write_str("exceeded max depth"),
            Error::InvalidNamespace => f.write_str("object namespace is in an invalid state"),
            Error::InvalidToken => f.write_str("invalid jsontext.Token"),
            Error::UnknownName => f.write_str("unknown object member name"),
            Error::AmbiguousName => f.write_str("ambiguous object member name"),
            Error::InvalidText(e) => e.fmt(f),
            Error::Syntactic(e) => e.fmt(f),
            Error::Semantic(e) => e.fmt(f),
            Error::Io(e) => e.fmt(f),
            Error::Num(e) => e.fmt(f),
            Error::PointerSuffix(e) => e.error.fmt(f),
            Error::Other(e) => e.fmt(f),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self.inner() {
            Some(e) => Some(e),
            None => match self {
                Error::Io(e) => Some(&*e.err),
                Error::Num(e) => Some(&e.err),
                _ => None,
            },
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        if crate::io::is_eof(&e) {
            Error::Eof
        } else if crate::io::is_unexpected_eof(&e) {
            Error::UnexpectedEof
        } else {
            Error::Other(Arc::new(e))
        }
    }
}

impl From<SyntacticError> for Error {
    fn from(e: SyntacticError) -> Error {
        Error::Syntactic(Box::new(e))
    }
}

impl From<SemanticError> for Error {
    fn from(e: SemanticError) -> Error {
        Error::Semantic(Box::new(e))
    }
}

/// `jsonwire.InvalidTextError`: an invalid character or escape sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidTextError {
    /// "character", "escape sequence" or "surrogate pair".
    pub label: String,
    /// The raw invalid text.
    pub what: Vec<u8>,
    /// "in string", "at start of value", ...
    pub place: String,
}

impl fmt::Display for InvalidTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut need_escape = false;
        let mut rest: &[u8] = &self.what;
        let mut count = 0usize;
        while !rest.is_empty() {
            let (r, n) = rune::decode_rune(rest);
            count += 1;
            if r == '`' as i32
                || r == rune::RUNE_ERROR
                || unicode::is_space(r)
                || !unicode::is_print(r)
            {
                need_escape = true;
            }
            rest = &rest[n..];
        }
        let what = if count == 1 {
            quote_rune(&self.what)
        } else if need_escape {
            strconv::quote(&self.what)
        } else {
            format!("`{}`", String::from_utf8_lossy(&self.what))
        };
        let text = format!("invalid {} {} {}", self.label, what, self.place);
        f.write_str(text.strip_suffix(' ').unwrap_or(&text))
    }
}

impl StdError for InvalidTextError {}

/// `jsontext.ioError`: a failure of the underlying reader or writer.
#[derive(Clone, Debug)]
pub struct IoError {
    /// Either "read" or "write".
    pub action: &'static str,
    pub err: Arc<io::Error>,
}

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{ERROR_PREFIX}{} error: {}", self.action, self.err)
    }
}

/// `jsontext.numError`: a number token that does not fit the accessor.
#[derive(Clone, Debug)]
pub struct NumError {
    /// Either "Int", "Uint" or "Float".
    pub accessor: &'static str,
    /// The token's text, e.g. "1e1000".
    pub value: String,
    /// Either `strconv::ERR_SYNTAX` or `strconv::ERR_RANGE`.
    pub err: strconv::Error,
}

impl fmt::Display for NumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "jsontext.Token({}).{} error: {}",
            self.value, self.accessor, self.err
        )
    }
}

impl StdError for NumError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.err)
    }
}

/// `jsontext.SyntacticError`: an error in the JSON syntax or in the order of
/// the tokens.
#[derive(Clone, Debug, Default)]
pub struct SyntacticError {
    /// The byte offset after which the error occurred.
    pub byte_offset: i64,
    /// The JSON Pointer of the value where the error occurred.
    pub json_pointer: Pointer,
    /// The underlying error, if any.
    pub err: Option<Error>,
}

impl fmt::Display for SyntacticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut pointer = self.json_pointer.clone();
        let mut offset = self.byte_offset;
        let mut b = String::from(ERROR_PREFIX);
        match &self.err {
            Some(err) => {
                b.push_str(&err.to_string());
                if matches!(err, Error::DuplicateName) {
                    b.push(' ');
                    b.push_str(&strconv::quote(pointer.last_token()));
                    pointer = pointer.parent();
                    offset = 0;
                }
            }
            None => b.push_str("syntactic error"),
        }
        if !pointer.as_str().is_empty() {
            b.push_str(" within ");
            b.push_str(&strconv::quote(truncate_pointer(pointer.as_str(), 100)));
        }
        if offset > 0 {
            b.push_str(" after offset ");
            b.push_str(&offset.to_string());
        }
        f.write_str(&b)
    }
}

impl StdError for SyntacticError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.err.as_ref().map(|e| e as _)
    }
}

/// `jsontext.pointerSuffixError`: an error whose JSON Pointer is built from
/// the innermost element outward.
#[derive(Clone, Debug)]
pub struct PointerSuffixError {
    pub error: Error,
    pub reverse_pointer: Vec<u8>,
}

impl PointerSuffixError {
    /// Appends the pointer, reversed back into reading order.
    pub fn append_pointer(&self, pointer: &mut Vec<u8>) {
        let mut bi: &[u8] = &self.reverse_pointer;
        while !bi.is_empty() {
            let i = bi.iter().rposition(|&c| c == b'/').unwrap_or(0);
            pointer.extend_from_slice(&bi[i..]);
            bi = &bi[..i];
        }
    }
}

/// `wrapWithObjectName`.
pub(crate) fn wrap_with_object_name(err: Error, quoted_name: &[u8]) -> Error {
    let mut serr = match err {
        Error::PointerSuffix(s) => *s,
        other => PointerSuffixError {
            error: other,
            reverse_pointer: Vec::new(),
        },
    };
    let name = super::wire::unquote_may_copy(quoted_name, false);
    serr.reverse_pointer.push(b'/');
    super::state::append_escape_pointer_name(&mut serr.reverse_pointer, &name);
    Error::PointerSuffix(Box::new(serr))
}

/// `wrapWithArrayIndex`.
pub(crate) fn wrap_with_array_index(err: Error, index: i64) -> Error {
    let mut serr = match err {
        Error::PointerSuffix(s) => *s,
        other => PointerSuffixError {
            error: other,
            reverse_pointer: Vec::new(),
        },
    };
    serr.reverse_pointer.push(b'/');
    serr.reverse_pointer
        .extend_from_slice(index.to_string().as_bytes());
    Error::PointerSuffix(Box::new(serr))
}

/// Everything `wrapSyntacticError` needs to know about a coder.
pub(crate) struct WrapInfo {
    pub(crate) legacy_errors: bool,
    pub(crate) offset: i64,
    pub(crate) pointer: Vec<u8>,
    /// For a decoder: what to report instead of `MismatchDelim` (the
    /// replacement error and whether the pointer moves to the parent).
    pub(crate) mismatch: Option<(Error, bool)>,
}

/// `wrapSyntacticError`: turns a low-level error into a `SyntacticError`
/// positioned at `info.offset`.
pub(crate) fn finish_syntactic_error(mut err: Error, mut info: WrapInfo) -> Error {
    let mut ptr = std::mem::take(&mut info.pointer);
    if let Error::PointerSuffix(serr) = err {
        serr.append_pointer(&mut ptr);
        err = serr.error;
    }
    if matches!(err, Error::MismatchDelim) {
        if let Some((replacement, parent)) = info.mismatch.take() {
            if parent {
                let p = Pointer::from(String::from_utf8_lossy(&ptr).into_owned());
                ptr = p.parent().as_str().as_bytes().to_vec();
            }
            err = replacement;
        }
    }
    let mut offset = info.offset;
    if info.legacy_errors && !matches!(err, Error::UnexpectedEof) {
        if let Error::InvalidText(w) = &err {
            offset += w.what.len() as i64;
        } else {
            offset += 1;
        }
    }
    Error::Syntactic(Box::new(SyntacticError {
        byte_offset: offset,
        json_pointer: Pointer::from(String::from_utf8_lossy(&ptr).into_owned()),
        err: Some(err),
    }))
}
