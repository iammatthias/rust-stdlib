//! DER-encoded ASN.1 (Go's `encoding/asn1`, ITU-T X.690).
//!
//! Go maps ASN.1 onto arbitrary values with reflection and struct tags. Rust
//! has no reflection, so this module offers a typed API instead:
//!
//! - [`parse_raw`] and [`RawValue`] for undecoded elements.
//! - [`Unmarshal`] / [`Marshal`] for typed values: `bool`, `i64`, `i32`,
//!   [`Integer`] (arbitrary precision), [`Enumerated`], [`Flag`], [`Null`],
//!   [`BitString`], `Vec<u8>` (OCTET STRING), [`ObjectIdentifier`], `String`
//!   (all string types), [`DateTime`](crate::time::DateTime) (UTCTime and
//!   GeneralizedTime), `Vec<T>` (SEQUENCE OF), [`SetOf`], [`RawValue`] and
//!   [`Any`] (decode only, Go's `interface{}`).
//! - [`Decoder`] and [`Encoder`] to hand-write SEQUENCE/SET mappings, with
//!   [`Params`] carrying Go's field options (`explicit`, `tag:N`, `optional`,
//!   `default:N`, `set`, `application`, `private`, string and time types,
//!   `omitempty`). [`Params::parse`] accepts Go's struct-tag syntax.
//! - [`Decode`] for schema-driven decoding without a static type.
//!
//! Decoding follows Go's rules: minimal lengths and tags, no indefinite
//! lengths, minimally encoded INTEGERs, DER BOOLEAN and BIT STRING padding,
//! validated string alphabets and canonical times. Trailing elements inside a
//! SEQUENCE are ignored, as in Go. Differences from Go:
//!
//! - Nesting depth defaults to 256 ([`Options::max_depth`]); Go allows 10000.
//!   Input size and SEQUENCE OF element counts are also bounded.
//! - GeneralizedTime year 0000 and zone offsets of ±24h are rejected because
//!   [`DateTime`](crate::time::DateTime) cannot represent them.
//! - Marshaling rejects negative OBJECT IDENTIFIER arcs, which Go silently
//!   drops; `Params` tag numbers are `u32`.
//! - An empty `Vec<u8>`, OID or slice is treated as Go's nil slice: OPTIONAL
//!   fields omit it. Use [`Encoder::optional`] to encode a present empty
//!   value. Go's `RawContent` is replaced by [`Element::full_bytes`].
//! - T61String and BMPString can also be marshaled (Go only parses them).
mod decode;
mod der;
mod encode;
mod time;
mod types;

pub use decode::{
    decode_sequence_of, Any, Decode, Decoder, Element, SequenceOfWith, Typed, Unmarshal,
};
pub use encode::{Encoder, Marshal};
pub use types::{
    BitString, Enumerated, Flag, Integer, Null, ObjectIdentifier, RawValue, NULL_BYTES,
};

use std::fmt;

pub const TAG_BOOLEAN: u32 = 1;
pub const TAG_INTEGER: u32 = 2;
pub const TAG_BIT_STRING: u32 = 3;
pub const TAG_OCTET_STRING: u32 = 4;
pub const TAG_NULL: u32 = 5;
pub const TAG_OID: u32 = 6;
pub const TAG_ENUM: u32 = 10;
pub const TAG_UTF8_STRING: u32 = 12;
pub const TAG_SEQUENCE: u32 = 16;
pub const TAG_SET: u32 = 17;
pub const TAG_NUMERIC_STRING: u32 = 18;
pub const TAG_PRINTABLE_STRING: u32 = 19;
pub const TAG_T61_STRING: u32 = 20;
pub const TAG_IA5_STRING: u32 = 22;
pub const TAG_UTC_TIME: u32 = 23;
pub const TAG_GENERALIZED_TIME: u32 = 24;
pub const TAG_GENERAL_STRING: u32 = 27;
pub const TAG_BMP_STRING: u32 = 30;

/// The tag class (the top two identifier bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub enum Class {
    #[default]
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl Class {
    pub(crate) fn from_bits(bits: u8) -> Self {
        match bits & 3 {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        }
    }
    /// Go's numeric class (`ClassUniversal` = 0 .. `ClassPrivate` = 3).
    pub fn bits(self) -> u8 {
        match self {
            Class::Universal => 0,
            Class::Application => 1,
            Class::ContextSpecific => 2,
            Class::Private => 3,
        }
    }
}

/// What a type expects on the wire (Go's `getUniversalType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Asn1Type {
    /// A fixed universal tag and constructed flag.
    Universal { tag: u32, compound: bool },
    /// Any character string type; decodes whichever string type is present.
    String,
    /// UTCTime or GeneralizedTime.
    Time,
    /// Go's `Flag`: a BOOLEAN-tagged presence marker.
    Flag,
    /// Matches any element ([`RawValue`]).
    Raw,
    /// Go's `interface{}`: parameters are ignored.
    Any,
}

impl Asn1Type {
    pub const SEQUENCE: Self = Asn1Type::Universal {
        tag: TAG_SEQUENCE,
        compound: true,
    };
    pub const SET: Self = Asn1Type::Universal {
        tag: TAG_SET,
        compound: true,
    };
    /// A primitive universal type.
    pub const fn universal(tag: u32) -> Self {
        Asn1Type::Universal {
            tag,
            compound: false,
        }
    }
}

/// A SET OF value: encoded elements are sorted as DER requires.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct SetOf<T>(pub Vec<T>);

/// String type selection for marshaling and implicitly tagged decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StringType {
    Utf8,
    Printable,
    Ia5,
    Numeric,
    /// Latin-1 (not settable from Go struct tags).
    T61,
    /// UCS-2 big-endian (not settable from Go struct tags).
    Bmp,
}

impl StringType {
    pub fn tag(self) -> u32 {
        match self {
            StringType::Utf8 => TAG_UTF8_STRING,
            StringType::Printable => TAG_PRINTABLE_STRING,
            StringType::Ia5 => TAG_IA5_STRING,
            StringType::Numeric => TAG_NUMERIC_STRING,
            StringType::T61 => TAG_T61_STRING,
            StringType::Bmp => TAG_BMP_STRING,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimeType {
    Utc,
    Generalized,
}

impl TimeType {
    pub fn tag(self) -> u32 {
        match self {
            TimeType::Utc => TAG_UTC_TIME,
            TimeType::Generalized => TAG_GENERALIZED_TIME,
        }
    }
}

/// Field options, equivalent to Go's `asn1:"..."` struct tags.
///
/// `explicit`, `application` and `private` without a `tag` use tag 0, as in
/// Go. Build with the methods or parse Go's syntax:
///
/// ```
/// use rust_stdlib::encoding::asn1::Params;
/// assert_eq!(Params::parse("optional,explicit,tag:3"), Params::NONE.optional().explicit(3));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Params {
    pub optional: bool,
    pub explicit: bool,
    pub application: bool,
    pub private: bool,
    /// Default for absent OPTIONAL integer fields.
    pub default: Option<i64>,
    pub tag: Option<u32>,
    pub string_type: Option<StringType>,
    pub time_type: Option<TimeType>,
    pub set: bool,
    pub omit_empty: bool,
}

impl Params {
    pub const NONE: Params = Params {
        optional: false,
        explicit: false,
        application: false,
        private: false,
        default: None,
        tag: None,
        string_type: None,
        time_type: None,
        set: false,
        omit_empty: false,
    };

    /// Parses Go's comma-separated struct-tag options; unknown or malformed
    /// parts are ignored as in Go.
    pub fn parse(text: &str) -> Params {
        let mut p = Params::NONE;
        if text.is_empty() {
            return p;
        }
        for part in text.split(',') {
            match part {
                "optional" => p.optional = true,
                "explicit" => {
                    p.explicit = true;
                    p.tag.get_or_insert(0);
                }
                "generalized" => p.time_type = Some(TimeType::Generalized),
                "utc" => p.time_type = Some(TimeType::Utc),
                "ia5" => p.string_type = Some(StringType::Ia5),
                "printable" => p.string_type = Some(StringType::Printable),
                "numeric" => p.string_type = Some(StringType::Numeric),
                "utf8" => p.string_type = Some(StringType::Utf8),
                "set" => p.set = true,
                "application" => {
                    p.application = true;
                    p.tag.get_or_insert(0);
                }
                "private" => {
                    p.private = true;
                    p.tag.get_or_insert(0);
                }
                "omitempty" => p.omit_empty = true,
                _ => {
                    if let Some(v) = part.strip_prefix("default:") {
                        if let Ok(v) = v.parse() {
                            p.default = Some(v);
                        }
                    } else if let Some(v) = part.strip_prefix("tag:") {
                        if let Ok(v) = v.parse::<u32>() {
                            p.tag = Some(v);
                        }
                    }
                }
            }
        }
        p
    }

    pub const fn optional(mut self) -> Self {
        self.optional = true;
        self
    }
    /// An EXPLICIT context-specific tag.
    pub const fn explicit(mut self, tag: u32) -> Self {
        self.explicit = true;
        self.tag = Some(tag);
        self
    }
    /// An IMPLICIT context-specific tag.
    pub const fn implicit(mut self, tag: u32) -> Self {
        self.tag = Some(tag);
        self
    }
    /// Use the APPLICATION class for the tag.
    pub const fn application(mut self) -> Self {
        self.application = true;
        if self.tag.is_none() {
            self.tag = Some(0);
        }
        self
    }
    /// Use the PRIVATE class for the tag.
    pub const fn private(mut self) -> Self {
        self.private = true;
        if self.tag.is_none() {
            self.tag = Some(0);
        }
        self
    }
    pub const fn default_value(mut self, value: i64) -> Self {
        self.default = Some(value);
        self
    }
    pub const fn set(mut self) -> Self {
        self.set = true;
        self
    }
    pub const fn omit_empty(mut self) -> Self {
        self.omit_empty = true;
        self
    }
    pub const fn string_type(mut self, string_type: StringType) -> Self {
        self.string_type = Some(string_type);
        self
    }
    pub const fn time_type(mut self, time_type: TimeType) -> Self {
        self.time_type = Some(time_type);
        self
    }

    pub(crate) fn effective_tag(&self) -> Option<u32> {
        match self.tag {
            Some(tag) => Some(tag),
            None if self.explicit || self.application || self.private => Some(0),
            None => None,
        }
    }
}

/// Decoding budgets and compatibility switches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Options {
    /// Maximum nested field depth (the top-level element is depth 1). Each
    /// level of decoding uses Rust stack, so the default is 256 where Go
    /// allows 10000 (decoding that deep overflows a 2 MiB thread stack).
    pub max_depth: usize,
    /// Maximum input length accepted by a top-level [`Decoder`].
    pub max_input_bytes: usize,
    /// Maximum elements in one SEQUENCE OF / SET OF.
    pub max_elements: usize,
    /// Stricter than Go: an explicit tag's content must be exactly one
    /// element. By default, as in Go, the wrapper length is ignored and the
    /// inner element is read from the enclosing bytes.
    pub strict_explicit: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_depth: 256,
            max_input_bytes: 64 * 1024 * 1024,
            max_elements: 1 << 22,
            strict_explicit: false,
        }
    }
}

/// The category of an [`Error`], following Go's error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorKind {
    /// Invalid DER (Go's `SyntaxError`).
    Syntax,
    /// Valid DER that does not fit the requested type (Go's `StructuralError`).
    Structural,
    /// Invalid string contents (UTF-8 or BMPString).
    String,
    /// Invalid or unrepresentable UTCTime/GeneralizedTime.
    Time,
    /// An explicit tag whose length does not match exactly one inner element.
    ExplicitLength,
    /// A configured [`Options`] budget was exceeded.
    Limit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Error {
    kind: ErrorKind,
    message: &'static str,
}

impl Error {
    /// An error for hand-written [`Unmarshal`]/[`Marshal`] implementations,
    /// such as an unsupported version number.
    pub const fn new(kind: ErrorKind, message: &'static str) -> Self {
        Self { kind, message }
    }
    pub(crate) const fn syntax(message: &'static str) -> Self {
        Self {
            kind: ErrorKind::Syntax,
            message,
        }
    }
    pub(crate) const fn structural(message: &'static str) -> Self {
        Self {
            kind: ErrorKind::Structural,
            message,
        }
    }
    pub(crate) const fn string(message: &'static str) -> Self {
        Self {
            kind: ErrorKind::String,
            message,
        }
    }
    pub(crate) const fn time(message: &'static str) -> Self {
        Self {
            kind: ErrorKind::Time,
            message,
        }
    }
    pub(crate) const fn limit(message: &'static str) -> Self {
        Self {
            kind: ErrorKind::Limit,
            message,
        }
    }
    pub(crate) const fn explicit_length() -> Self {
        Self {
            kind: ErrorKind::ExplicitLength,
            message: "explicit tag length does not match its contents",
        }
    }
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
    pub fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            ErrorKind::Syntax => write!(f, "asn1: syntax error: {}", self.message),
            ErrorKind::Structural => write!(f, "asn1: structure error: {}", self.message),
            _ => write!(f, "asn1: {}", self.message),
        }
    }
}

impl std::error::Error for Error {}

/// Parses one element of any type (Go's `Unmarshal` into a `RawValue`),
/// returning it and the bytes that follow.
pub fn parse_raw(input: &[u8]) -> Result<(RawValue, &[u8]), Error> {
    unmarshal(input)
}

/// Decodes one value and returns the remaining input.
pub fn unmarshal<T: Unmarshal>(input: &[u8]) -> Result<(T, &[u8]), Error> {
    unmarshal_with_params(input, &Params::NONE)
}

/// Decodes one value with top-level field parameters.
pub fn unmarshal_with_params<'a, T: Unmarshal>(
    input: &'a [u8],
    params: &Params,
) -> Result<(T, &'a [u8]), Error> {
    let mut decoder = Decoder::new(input)?;
    let value = decoder.field(params)?;
    Ok((value, decoder.remaining()))
}

/// Encodes a value as DER.
pub fn marshal<T: Marshal + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    marshal_with_params(value, &Params::NONE)
}

/// Encodes a value with top-level field parameters.
pub fn marshal_with_params<T: Marshal + ?Sized>(
    value: &T,
    params: &Params,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encode::marshal_field(value, params, &mut out)?;
    Ok(out)
}
