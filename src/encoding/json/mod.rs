//! Go's `encoding/json`.
//!
//! The Go-compatible API follows the behaviour of Go 1.27, where v1 is
//! implemented on top of v2: [`marshal`], [`marshal_indent`], [`unmarshal`],
//! [`valid`], [`compact`], [`indent`], [`html_escape`], [`Decoder`] (with
//! [`Token`] streaming), [`Encoder`], [`RawMessage`], [`Number`], the
//! [`Marshaler`] and [`Unmarshaler`] hooks, every error type and
//! [`Options`]. Go's reflection becomes the [`Serialize`] and [`Deserialize`]
//! traits (derive them with `rust-stdlib-derive`, whose `#[json(...)]` field
//! attributes take Go's struct tags) and [`Value`] stands in for
//! `interface{}`. Output is byte-identical to Go's: struct fields in
//! declaration order, map keys sorted, Go's float formatting, invalid UTF-8
//! replaced with U+FFFD and HTML escaping by default. Syntax errors carry
//! Go's text and byte offsets.
//!
//! [`unmarshal`] returns the decoded value instead of filling a pointer;
//! [`unmarshal_into`] and [`Decoder::decode_into`] decode into an existing
//! value with Go's merge rules. A slice or map that is `nil` in Go is simply
//! empty here (use `Option` for `null`).
//!
//! A user [`Deserialize`] or [`Serialize`] impl reports failure with
//! [`Error::custom`] (a message) or [`Error::custom_source`] (any error type,
//! kept as-is like a custom `UnmarshalJSON` error, so
//! [`Error::downcast_ref`] plays `errors.As`):
//!
//! ```
//! use rust_stdlib::encoding::json::{self, Deserialize, Error, Value};
//!
//! #[derive(Debug)]
//! struct Even(i64);
//!
//! #[derive(Debug)]
//! struct Odd(i64);
//! impl std::fmt::Display for Odd {
//!     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//!         write!(f, "{} is odd", self.0)
//!     }
//! }
//! impl std::error::Error for Odd {}
//!
//! impl Deserialize for Even {
//!     fn from_json(v: &Value) -> Result<Self, Error> {
//!         let n = i64::from_json(v)?;
//!         match n {
//!             n if n < 0 => Err(Error::custom("negative")),
//!             n if n % 2 != 0 => Err(Error::custom_source(Odd(n))),
//!             n => Ok(Even(n)),
//!         }
//!     }
//! }
//!
//! assert_eq!(json::unmarshal::<Even>(b"4").unwrap().0, 4);
//! assert_eq!(json::unmarshal::<Even>(b"-2").unwrap_err().to_string(), "negative");
//! let err = json::unmarshal::<Even>(b"3").unwrap_err();
//! assert_eq!(err.downcast_ref::<Odd>().unwrap().0, 3);
//! ```
//!
//! [`Value`] parses with [`FromStr`] and prints compact JSON
//! with `Display`; numbers keep their literal text.
use std::{error, fmt, io, str::FromStr};

mod decode;
mod encode;
mod errors;
mod fields;
mod indent;
pub mod jsontext;
mod map;
mod options;
mod scanner;
mod stream;
pub mod v2;

pub(crate) use decode::unmarshal_with_number;
pub use decode::{
    deserialize_from_value, deserialize_struct, merge_struct, unmarshal, unmarshal_into,
    unmarshal_quoted_with, unmarshal_with_options, zero_struct, Builder, DecodeState, Deserialize,
    DeserializeFields, Node, Quoted, Unmarshaler,
};
pub use encode::{
    format_float, marshal, marshal_indent, marshal_with_options, serialize_struct,
    serialize_to_value, Bytes, MapKey, Marshaler, ObjectWriter, RawMessage, Serialize,
    SerializeFields, Serializer,
};
pub use errors::{
    InvalidUTF8Error, InvalidUnmarshalError, MarshalerError, SyntaxError, UnmarshalFieldError,
    UnmarshalTypeError, UnsupportedTypeError, UnsupportedValueError,
};
pub use fields::{fold_name, resolve, Field, FieldList, Resolved, Tag};
pub use indent::{compact, html_escape, indent, valid};
pub use map::Map;
pub use options::{
    call_methods_with_legacy_semantics, default_options_v1, format_byte_array_as_array,
    format_bytes_with_legacy_semantics, format_duration_as_nano, match_case_sensitive_delimiter,
    merge_with_legacy_semantics, omit_empty_with_legacy_semantics, parse_bytes_with_loose_rfc4648,
    parse_time_with_loose_rfc3339, report_errors_with_legacy_semantics,
    stringify_with_legacy_semantics, unmarshal_array_from_any_length, Options,
};
pub use stream::{Decoder, Delim, Encoder, Token};

/// Every error this module returns. The entry points return the variant that
/// wraps Go's error type of the same name.
#[derive(Debug)]
pub enum Error {
    Syntax {
        offset: usize,
        message: &'static str,
    },
    Limit(&'static str),
    Type(&'static str),
    Io(io::Error),
    /// Go's `*SyntaxError`.
    SyntaxError(SyntaxError),
    /// Go's `*UnmarshalTypeError`.
    UnmarshalType(UnmarshalTypeError),
    /// Go's `*InvalidUnmarshalError`.
    InvalidUnmarshal(InvalidUnmarshalError),
    /// Go's `*MarshalerError`.
    Marshaler(MarshalerError),
    /// Go's `*UnsupportedTypeError`.
    UnsupportedType(UnsupportedTypeError),
    /// Go's `*UnsupportedValueError`.
    UnsupportedValue(UnsupportedValueError),
    /// Go's `*InvalidUTF8Error`.
    InvalidUTF8(InvalidUTF8Error),
    /// Go's `*UnmarshalFieldError`.
    UnmarshalField(UnmarshalFieldError),
    /// Go's `io.EOF`.
    Eof,
    /// Any other Go `error` value (`fmt.Errorf` results and user errors).
    Other(String),
    /// A user error kept as-is (Go's custom `MarshalJSON`/`UnmarshalJSON`
    /// error), reachable with [`Error::downcast_ref`].
    Custom(Box<dyn error::Error + Send + Sync>),
}
impl Error {
    /// An error with the given message, for user [`Serialize`] and
    /// [`Deserialize`] impls (Go's `errors.New` / `fmt.Errorf`).
    pub fn custom(msg: impl fmt::Display) -> Self {
        Self::Other(msg.to_string())
    }

    /// An error wrapping `err` unchanged, so [`Error::downcast_ref`] and
    /// [`error::Error::source`] reach it (Go's `errors.As` through a custom
    /// `UnmarshalJSON` error).
    pub fn custom_source(err: impl error::Error + Send + Sync + 'static) -> Self {
        Self::Custom(Box::new(err))
    }

    /// The wrapped user error if it is an `E`, looking through
    /// [`Error::custom_source`] and the wrapper variants.
    pub fn downcast_ref<E: error::Error + 'static>(&self) -> Option<&E> {
        let mut cur: Option<&(dyn error::Error + 'static)> = Some(self);
        while let Some(e) = cur {
            if let Some(found) = e.downcast_ref::<E>() {
                return Some(found);
            }
            cur = e.source();
        }
        None
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { offset, message } => write!(f, "{message} at byte {offset}"),
            Self::Limit(s) => write!(f, "JSON limit exceeded: {s}"),
            Self::Type(s) => write!(f, "JSON type error: {s}"),
            Self::Io(e) => e.fmt(f),
            Self::SyntaxError(e) => e.fmt(f),
            Self::UnmarshalType(e) => e.fmt(f),
            Self::InvalidUnmarshal(e) => e.fmt(f),
            Self::Marshaler(e) => e.fmt(f),
            Self::UnsupportedType(e) => e.fmt(f),
            Self::UnsupportedValue(e) => e.fmt(f),
            Self::InvalidUTF8(e) => e.fmt(f),
            Self::UnmarshalField(e) => e.fmt(f),
            Self::Eof => f.write_str("EOF"),
            Self::Other(s) => f.write_str(s),
            Self::Custom(e) => e.fmt(f),
        }
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::SyntaxError(e) => Some(e),
            Self::UnmarshalType(e) => Some(e),
            Self::InvalidUnmarshal(e) => Some(e),
            Self::Marshaler(e) => Some(e),
            Self::UnsupportedType(e) => Some(e),
            Self::UnsupportedValue(e) => Some(e),
            Self::InvalidUTF8(e) => Some(e),
            Self::UnmarshalField(e) => Some(e),
            Self::Custom(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}
impl From<&str> for Error {
    fn from(msg: &str) -> Self {
        Self::Other(msg.to_owned())
    }
}
impl From<String> for Error {
    fn from(msg: String) -> Self {
        Self::Other(msg)
    }
}
impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
macro_rules! error_from {
    ($($ty:ident => $variant:ident),+ $(,)?) => { $(
        impl From<$ty> for Error {
            fn from(e: $ty) -> Self { Self::$variant(e) }
        }
    )+ };
}
error_from!(
    SyntaxError => SyntaxError,
    UnmarshalTypeError => UnmarshalType,
    InvalidUnmarshalError => InvalidUnmarshal,
    MarshalerError => Marshaler,
    UnsupportedTypeError => UnsupportedType,
    UnsupportedValueError => UnsupportedValue,
    InvalidUTF8Error => InvalidUTF8,
    UnmarshalFieldError => UnmarshalField,
);

/// Validated JSON number, without conversion through a floating-point value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Number(String);
impl Number {
    /// Wraps JSON number text (the empty text is `0`, as for Go's zero
    /// `Number`). Text that is not a JSON number fails with the error Go's
    /// `Marshal` gives for such a `Number`, so an invalid `Number` cannot
    /// exist.
    pub fn new(text: impl Into<String>) -> Result<Self, Error> {
        let text = text.into();
        if !text.is_empty() && !encode::is_valid_number(&text) {
            return Err(encode::invalid_number(&text));
        }
        Ok(Self(text))
    }
    /// The number as a `float64` (Go's `Number.Float64`).
    pub fn float64(&self) -> Result<f64, Error> {
        match self.0.parse::<f64>() {
            Ok(f) if f.is_infinite() && !self.0.to_ascii_lowercase().contains("inf") => {
                Err(Error::Other(format!(
                    "strconv.ParseFloat: parsing {}: value out of range",
                    errors::quote(&self.0)
                )))
            }
            Ok(f) => Ok(f),
            Err(_) => Err(Error::Other(format!(
                "strconv.ParseFloat: parsing {}: invalid syntax",
                errors::quote(&self.0)
            ))),
        }
    }
    /// The number as an `int64` (Go's `Number.Int64`).
    pub fn int64(&self) -> Result<i64, Error> {
        self.0.parse::<i64>().map_err(|e| {
            let why = match e.kind() {
                std::num::IntErrorKind::PosOverflow | std::num::IntErrorKind::NegOverflow => {
                    "value out of range"
                }
                _ => "invalid syntax",
            };
            Error::Other(format!(
                "strconv.ParseInt: parsing {}: {why}",
                errors::quote(&self.0)
            ))
        })
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.0.parse().ok()
    }
    pub fn as_u64(&self) -> Option<u64> {
        self.0.parse().ok()
    }
    /// Returns `None` on overflow to infinity.
    pub fn as_f64(&self) -> Option<f64> {
        self.0.parse::<f64>().ok().filter(|n| n.is_finite())
    }
}
impl FromStr for Number {
    type Err = Error;
    fn from_str(text: &str) -> Result<Self, Error> {
        Self::new(text)
    }
}
impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Map),
}
impl Value {
    /// An object whose members keep the order given.
    pub fn object<const N: usize>(fields: [(&str, Value); N]) -> Self {
        Self::Object(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Self::Object(m) => m.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Self::Number(n) => Some(n),
            _ => None,
        }
    }
    /// The members, when the value is an object.
    pub fn as_object(&self) -> Option<&Map> {
        match self {
            Self::Object(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Self::Array(v) => Some(v),
            _ => None,
        }
    }
}
impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Self::String(s.to_owned())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Self::Bool(b)
    }
}
macro_rules! integer_values {
    ($($t:ty),+ $(,)?) => { $(
        impl From<$t> for Value {
            fn from(n: $t) -> Self { Self::Number(Number(n.to_string())) }
        }
    )+ };
}
integer_values!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);

/// Resource limits of the bounded strict parser (`from_str` and friends).
/// Parses JSON text as Go's `Unmarshal` into an `interface{}` does, except that
/// numbers keep their literal text (Go's `Decoder.UseNumber`).
impl FromStr for Value {
    type Err = Error;
    fn from_str(text: &str) -> Result<Self, Error> {
        decode::unmarshal_with_number(text.as_bytes())
    }
}

/// Like the [`FromStr`] impl, for bytes.
impl TryFrom<&[u8]> for Value {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        decode::unmarshal_with_number(bytes)
    }
}

/// The compact JSON text of the value, without HTML escaping.
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = encode::marshal_with(self, false).map_err(|_| fmt::Error)?;
        f.write_str(&String::from_utf8_lossy(&bytes))
    }
}
