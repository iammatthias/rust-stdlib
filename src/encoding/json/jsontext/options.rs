//! `jsontext.Options` (Go's `jsonopts.Options`): a set of option settings
//! shared by this package and `encoding/json/v2`.
//!
//! In Go every option is its own value of the `Options` interface and a set
//! is just another `Options`; here an `Options` is always a set, and the
//! constructors ([`allow_duplicate_names`], [`multiline`], ...) return a set
//! with one setting. Combine sets with [`Options::join`], where later
//! settings take precedence.
use std::sync::Arc;

use super::flags::{self, Flags};
use super::wire::quote_rune;
use crate::encoding::json::v2::{Marshalers, Unmarshalers};

/// A set of option settings (Go's `jsontext.Options`).
#[derive(Clone, Debug, Default)]
pub struct Options {
    pub(crate) flags: Flags,
    pub(crate) indent: String,
    pub(crate) indent_prefix: String,
    pub(crate) byte_limit: i64,
    pub(crate) depth_limit: i32,
    pub(crate) marshalers: Option<Arc<Marshalers>>,
    pub(crate) unmarshalers: Option<Arc<Unmarshalers>>,
    pub(crate) format: String,
}

impl Options {
    /// An empty set of options.
    pub fn new() -> Options {
        Options::default()
    }

    pub(crate) fn from_bool(flag: u64, on: bool) -> Options {
        let mut o = Options::default();
        o.flags.set(flag, on);
        o
    }

    /// Joins `src` into the set, where its settings take precedence
    /// (Go's `jsonopts.Struct.Join`).
    #[must_use]
    pub fn join(mut self, src: &Options) -> Options {
        self.join_mut(src);
        self
    }

    pub(crate) fn join_mut(&mut self, src: &Options) {
        self.flags.join(src.flags);
        if src.flags.has(flags::NON_BOOLEAN_FLAGS) {
            if src.flags.has(flags::INDENT) {
                self.indent = src.indent.clone();
            }
            if src.flags.has(flags::INDENT_PREFIX) {
                self.indent_prefix = src.indent_prefix.clone();
            }
            if src.flags.has(flags::BYTE_LIMIT) {
                self.byte_limit = src.byte_limit;
            }
            if src.flags.has(flags::DEPTH_LIMIT) {
                self.depth_limit = src.depth_limit;
            }
            if src.flags.has(flags::MARSHALERS) {
                self.marshalers = src.marshalers.clone();
            }
            if src.flags.has(flags::UNMARSHALERS) {
                self.unmarshalers = src.unmarshalers.clone();
            }
            if src.flags.has(flags::FORMAT_TAG) {
                self.format = src.format.clone();
            }
        }
    }

    pub(crate) fn join_all(&mut self, srcs: &[Options]) {
        for s in srcs {
            self.join_mut(s);
        }
    }

    /// `InitializeMultiline`: fills the defaults of multiline output.
    pub(crate) fn initialize_multiline(&mut self) {
        if !self.flags.has(flags::SPACE_AFTER_COLON) {
            self.flags.set(flags::SPACE_AFTER_COLON, true);
        }
        if !self.flags.has(flags::SPACE_AFTER_COMMA) {
            self.flags.set(flags::SPACE_AFTER_COMMA, false);
        }
        if !self.flags.has(flags::INDENT) {
            self.flags.set(flags::INDENT, true);
            self.indent = "\t".into();
        }
    }

    /// `jsonopts.ChangedWhitespace`.
    pub(crate) fn changed_whitespace(s1: &Options, s2: &Options) -> bool {
        s1.flags.get(flags::MULTILINE) != s2.flags.get(flags::MULTILINE)
            || s1.flags.get(flags::SPACE_AFTER_COLON) != s2.flags.get(flags::SPACE_AFTER_COLON)
            || s1.flags.get(flags::SPACE_AFTER_COMMA) != s2.flags.get(flags::SPACE_AFTER_COMMA)
            || (s2.flags.get(flags::MULTILINE)
                && (s1.indent != s2.indent || s1.indent_prefix != s2.indent_prefix))
    }

    /// Reports the value of a boolean flag and whether it is specified.
    pub(crate) fn bool_option(&self, flag: u64) -> (bool, bool) {
        (self.flags.get(flag), self.flags.has(flag))
    }
}

macro_rules! bool_options {
    ($($(#[$doc:meta])* $name:ident => $flag:ident),+ $(,)?) => { $(
        $(#[$doc])*
        pub fn $name(v: bool) -> Options {
            Options::from_bool(flags::$flag, v)
        }
    )+ };
}

bool_options!(
    /// Go's `AllowDuplicateNames`: whether an object may have members with
    /// the same name (default false).
    allow_duplicate_names => ALLOW_DUPLICATE_NAMES,
    /// Go's `AllowInvalidUTF8`: whether invalid UTF-8 is replaced with U+FFFD
    /// instead of being an error (default false).
    allow_invalid_utf8 => ALLOW_INVALID_UTF8,
    /// Go's `EscapeForHTML`: escape `<`, `>` and `&` in strings.
    escape_for_html => ESCAPE_FOR_HTML,
    /// Go's `EscapeForJS`: escape U+2028 and U+2029 in strings.
    escape_for_js => ESCAPE_FOR_JS,
    /// Go's `PreserveRawStrings`: write raw strings verbatim.
    preserve_raw_strings => PRESERVE_RAW_STRINGS,
    /// Go's `CanonicalizeRawInts`: canonicalize integers of 16 or more digits.
    canonicalize_raw_ints => CANONICALIZE_RAW_INTS,
    /// Go's `CanonicalizeRawFloats`: canonicalize numbers with a fraction or
    /// exponent.
    canonicalize_raw_floats => CANONICALIZE_RAW_FLOATS,
    /// Go's `ReorderRawObjects`: sort the members of raw objects (RFC 8785).
    reorder_raw_objects => REORDER_RAW_OBJECTS,
    /// Go's `SpaceAfterColon`: write a space after each `:`.
    space_after_colon => SPACE_AFTER_COLON,
    /// Go's `SpaceAfterComma`: write a space after each `,`.
    space_after_comma => SPACE_AFTER_COMMA,
    /// Go's `Multiline`: put every object member and array element on its
    /// own line.
    multiline => MULTILINE,
);

fn check_whitespace(s: &str, what: &str) {
    let trimmed = s.trim_matches(|c| c == ' ' || c == '\t');
    if !trimmed.is_empty() {
        panic!(
            "json: invalid character {} in {what}",
            quote_rune(trimmed.as_bytes())
        );
    }
}

/// Go's `WithIndent`: the indentation of each nesting level; it also turns on
/// [`multiline`]. Panics unless `indent` is only spaces and tabs.
pub fn with_indent(indent: &str) -> Options {
    check_whitespace(indent, "indent");
    let mut o = Options::default();
    o.flags.set(flags::MULTILINE | flags::INDENT, true);
    o.indent = indent.to_string();
    o
}

/// Go's `WithIndentPrefix`: the prefix of each line after the first; it also
/// turns on [`multiline`]. Panics unless `prefix` is only spaces and tabs.
pub fn with_indent_prefix(prefix: &str) -> Options {
    check_whitespace(prefix, "indent prefix");
    let mut o = Options::default();
    o.flags.set(flags::MULTILINE | flags::INDENT_PREFIX, true);
    o.indent_prefix = prefix.to_string();
    o
}
