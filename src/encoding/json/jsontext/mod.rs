//! Go's `encoding/json/jsontext`: syntactic JSON processing, without the
//! semantics of Go types.
//!
//! A [`Decoder`] reads a stream of [`Token`]s and [`Value`]s from an
//! `io::Read`, an [`Encoder`] writes them to an `io::Write`, and both track
//! the position in the document ([`Pointer`], stack depth and index). A
//! [`Value`] holds one raw JSON value and can be validated, compacted,
//! indented or canonicalized per RFC 8785. Behaviour, error text and byte
//! offsets follow Go 1.27; the [`Options`] are shared with
//! [`encoding::json::v2`](super::v2).
//!
//! Differences from Go: a [`Token`] owns its text, so it stays valid after
//! the decoder advances; an empty [`Value`] stands for both Go's nil and
//! empty value; Go's `int` is `usize` or `i64` as fits; accessors that
//! return `(T, error)` return `(T, Option<Error>)`.
mod decode;
mod encode;
mod errors;
pub(crate) mod flags;
mod options;
mod state;
mod token;
mod value;
pub(crate) mod wire;

pub use decode::Decoder;
pub use encode::Encoder;
pub use errors::{
    Error, InvalidTextError, IoError, NumError, PointerSuffixError, SyntacticError,
    ERR_DUPLICATE_NAME, ERR_NON_STRING_NAME,
};
pub use options::{
    allow_duplicate_names, allow_invalid_utf8, canonicalize_raw_floats, canonicalize_raw_ints,
    escape_for_html, escape_for_js, multiline, preserve_raw_strings, reorder_raw_objects,
    space_after_colon, space_after_comma, with_indent, with_indent_prefix, Options,
};
pub use state::Pointer;
pub(crate) use token::NAN;
pub use token::{
    begin_array, begin_object, bool, end_array, end_object, false_, float, float32, int, null,
    string, string_bytes, true_, uint, Kind, Token, KIND_BEGIN_ARRAY, KIND_BEGIN_OBJECT,
    KIND_END_ARRAY, KIND_END_OBJECT, KIND_FALSE, KIND_INVALID, KIND_NULL, KIND_NUMBER, KIND_STRING,
    KIND_TRUE,
};
pub use value::{append_float, append_format, append_quote, append_unquote, Value};
pub use wire::{
    compare_utf16, consume_whitespace, invalid_character_error, invalid_escape_sequence_error,
    lossy_string, quote_rune, truncate_pointer, ValueFlags,
};

/// Go's `jsontext.Internal`: the hook through which `encoding/json/v2`
/// reaches the coders' internals. Within this crate the v2 module uses those
/// internals directly, so there is nothing to export.
#[derive(Clone, Copy, Debug)]
pub struct Internal;

/// Go's `jsontext.Internal`.
pub const INTERNAL: Internal = Internal;
