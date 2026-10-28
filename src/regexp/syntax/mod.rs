//! Parser, simplifier and compiler for regular expressions (Go
//! `regexp/syntax`).
//!
//! [`parse`] turns a pattern into a [`Regexp`] syntax tree, [`Regexp::simplify`]
//! rewrites counted repetitions into the primitive operators and [`compile`]
//! produces the [`Prog`] executed by the matcher in [`crate::regexp`]. The
//! accepted syntax is RE2's, documented at <https://pkg.go.dev/regexp/syntax>.
//!
//! Differences from Go, all forced by the language:
//!
//! - Runes are `i32` as in Go (surrogates can appear through `\x{D800}`).
//! - [`Regexp::sub`] holds `Arc<Regexp>` so that subtrees are shared the way Go
//!   shares pointers; Go's `Sub0` and `Rune0` small-storage arrays have no
//!   counterpart.
//! - [`parse`] takes a `&str`; [`parse_bytes`] takes arbitrary bytes and is the
//!   only way to reach [`ErrorCode::INVALID_UTF8`].
//! - Go's internal `panic(ErrLarge)` and `panic(ErrNestingDepth)` are ordinary
//!   errors here; the limits are Go's own (`maxHeight`, `maxSize`, `maxRunes`).
//!
//! ```
//! use rust_stdlib::regexp::syntax::{parse, Flags};
//! let re = parse("a+b*|c", Flags::PERL)?;
//! assert_eq!(re.to_string(), "a+b*|c");
//! assert_eq!(re.max_cap(), 0);
//! # Ok::<(), rust_stdlib::regexp::syntax::Error>(())
//! ```
mod compile;
mod parse;
mod perl_groups;
mod prog;
mod regexp;
mod simplify;

pub use compile::compile;
pub use parse::{parse, parse_bytes};
pub use prog::{empty_op_context, is_word_char, EmptyOp, Inst, InstOp, Prog};
pub use regexp::{Op, Regexp};

use std::{error, fmt, ops};

/// Parse flags, a bit set. Combine with `|`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Flags(pub u16);

impl Flags {
    /// Case-insensitive match.
    pub const FOLD_CASE: Flags = Flags(1);
    /// Treat the pattern as a literal string.
    pub const LITERAL: Flags = Flags(2);
    /// Allow character classes like `[^a-z]` and `[[:space:]]` to match newline.
    pub const CLASS_NL: Flags = Flags(4);
    /// Allow `.` to match newline.
    pub const DOT_NL: Flags = Flags(8);
    /// Treat `^` and `$` as only matching at the beginning and end of the text.
    pub const ONE_LINE: Flags = Flags(16);
    /// Make repetition operators default to non-greedy.
    pub const NON_GREEDY: Flags = Flags(32);
    /// Allow Perl extensions.
    pub const PERL_X: Flags = Flags(64);
    /// Allow `\p{Han}` and `\P{Han}` for Unicode groups and negation.
    pub const UNICODE_GROUPS: Flags = Flags(128);
    /// The regexp `OpEndText` was `$`, not `\z`.
    pub const WAS_DOLLAR: Flags = Flags(256);
    /// The regexp contains no counted repetition.
    pub const SIMPLE: Flags = Flags(512);
    /// `CLASS_NL | DOT_NL`.
    pub const MATCH_NL: Flags = Flags(4 | 8);
    /// As close to Perl as possible.
    pub const PERL: Flags = Flags(4 | 16 | 64 | 128);
    /// POSIX syntax.
    pub const POSIX: Flags = Flags(0);

    /// Reports whether every bit of `other` is set.
    pub fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }
}
impl ops::BitOr for Flags {
    type Output = Flags;
    fn bitor(self, o: Flags) -> Flags {
        Flags(self.0 | o.0)
    }
}
impl ops::BitAnd for Flags {
    type Output = Flags;
    fn bitand(self, o: Flags) -> Flags {
        Flags(self.0 & o.0)
    }
}
impl ops::BitXor for Flags {
    type Output = Flags;
    fn bitxor(self, o: Flags) -> Flags {
        Flags(self.0 ^ o.0)
    }
}
impl ops::Not for Flags {
    type Output = Flags;
    fn not(self) -> Flags {
        Flags(!self.0)
    }
}
impl ops::BitOrAssign for Flags {
    fn bitor_assign(&mut self, o: Flags) {
        self.0 |= o.0;
    }
}
impl ops::BitAndAssign for Flags {
    fn bitand_assign(&mut self, o: Flags) {
        self.0 &= o.0;
    }
}
impl ops::BitXorAssign for Flags {
    fn bitxor_assign(&mut self, o: Flags) {
        self.0 ^= o.0;
    }
}

/// An error code passed to [`Error`]; its text is Go's message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ErrorCode(pub &'static str);

impl ErrorCode {
    pub const INTERNAL_ERROR: ErrorCode = ErrorCode("regexp/syntax: internal error");
    pub const INVALID_CHAR_CLASS: ErrorCode = ErrorCode("invalid character class");
    pub const INVALID_CHAR_RANGE: ErrorCode = ErrorCode("invalid character class range");
    pub const INVALID_ESCAPE: ErrorCode = ErrorCode("invalid escape sequence");
    pub const INVALID_NAMED_CAPTURE: ErrorCode = ErrorCode("invalid named capture");
    pub const INVALID_PERL_OP: ErrorCode = ErrorCode("invalid or unsupported Perl syntax");
    pub const INVALID_REPEAT_OP: ErrorCode = ErrorCode("invalid nested repetition operator");
    pub const INVALID_REPEAT_SIZE: ErrorCode = ErrorCode("invalid repeat count");
    pub const INVALID_UTF8: ErrorCode = ErrorCode("invalid UTF-8");
    pub const MISSING_BRACKET: ErrorCode = ErrorCode("missing closing ]");
    pub const MISSING_PAREN: ErrorCode = ErrorCode("missing closing )");
    pub const MISSING_REPEAT_ARGUMENT: ErrorCode =
        ErrorCode("missing argument to repetition operator");
    pub const TRAILING_BACKSLASH: ErrorCode = ErrorCode("trailing backslash at end of expression");
    pub const UNEXPECTED_PAREN: ErrorCode = ErrorCode("unexpected )");
    pub const NESTING_DEPTH: ErrorCode = ErrorCode("expression nests too deeply");
    pub const LARGE: ErrorCode = ErrorCode("expression too large");
}
impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A parse failure: the code and the offending part of the expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    pub code: ErrorCode,
    pub expr: String,
}
impl Error {
    pub(crate) fn new(code: ErrorCode, expr: &[u8]) -> Error {
        Error {
            code,
            expr: String::from_utf8_lossy(expr).into_owned(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error parsing regexp: {}: `{}`", self.code, self.expr)
    }
}
impl error::Error for Error {}
