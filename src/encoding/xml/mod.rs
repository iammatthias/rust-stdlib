//! Go's `encoding/xml`: a byte-exact XML 1.0 tokenizer that understands name
//! spaces, plus struct-tag driven marshaling.
//!
//! The Go-shaped API lives at this module's top level: [`Decoder`] (tokens and
//! typed [`Decoder::decode`]), [`Encoder`], the token types, [`marshal`] /
//! [`unmarshal`], [`escape_text`] and the HTML tables. Behaviour, error texts,
//! line numbers and byte offsets follow Go's observable semantics; the
//! differential suite `tools/xml_check.py` compares them with Go.
//!
//! # Typed data without reflection
//!
//! Go maps XML onto structs by reflecting over field tags. Rust has no
//! reflection, so a type describes itself through [`Marshal`] and [`Unmarshal`]
//! (implemented here for the primitives, `String`, `Vec<T>`, `Option<T>`,
//! `Box<T>`, arrays and [`Name`]/[`Attr`]) and `#[derive(Marshal, Unmarshal)]`
//! from `rust-stdlib-derive` for structs. Field tags are Go's `xml:"..."` text,
//! written `#[xml("name,attr")]`; a field named `xml_name` of type [`Name`] is
//! Go's `XMLName`, and the Go field name used as the default element name is the
//! Rust field identifier. [`Marshaler`], [`MarshalerAttr`], [`Unmarshaler`] and
//! [`UnmarshalerAttr`] customise a type exactly as in Go.
//!
//! # Deviations from Go
//!
//! * Token byte slices are owned (`Vec<u8>`); `copy` clones them.
//! * An invalid UTF-8 byte inside a name appears as U+FFFD in the
//!   `invalid XML name` message (Rust strings cannot hold it).
//! * `%q` of a struct tag or type string uses Go's quoting; type strings are the
//!   Rust type name rather than `reflect.Type.String()`.
//! * `Decoder::from_token_reader` always wraps; it does not return an existing
//!   `*Decoder` unchanged.
//! * Optional budgets (`max_token_bytes`, `max_depth`) default to values far
//!   above any real input.

mod conv;
mod decoder;
mod encoder;
mod error;
mod marshal;
mod tables;
mod typeinfo;
mod unmarshal;

pub use decoder::{CharsetReader, Decoder};
pub use encoder::{escape, escape_text, marshal, marshal_indent, Encoder};
pub use error::{Error, SyntaxError, TagPathError, UnmarshalError, UnsupportedTypeError};
pub use marshal::{Marshal, Marshaler, MarshalerAttr, TextMarshaler, TextUnmarshaler, View};
pub use tables::{HTML_AUTO_CLOSE, HTML_ENTITY};
pub use typeinfo::{FieldSpec, StructSpec};
pub use unmarshal::{unmarshal, unmarshal_into, Kind, Unmarshal, Unmarshaler, UnmarshalerAttr};

use std::collections::HashMap;

/// A generic XML header suitable for use with the output of [`marshal`]
/// (Go `xml.Header`). It is not added automatically.
pub const HEADER: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";

/// An XML name (`local`) annotated with a name space identifier (`space`).
///
/// In tokens returned by [`Decoder::token`] the space is the canonical URL, not
/// the short prefix used in the document.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Name {
    /// Go's `Space`.
    pub space: String,
    /// Go's `Local`.
    pub local: String,
}

impl Name {
    /// A name with the given space and local part.
    pub fn new(space: impl Into<String>, local: impl Into<String>) -> Self {
        Name {
            space: space.into(),
            local: local.into(),
        }
    }
}

/// An attribute of an XML element (`name=value`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attr {
    /// Go's `Name`.
    pub name: Name,
    /// Go's `Value`.
    pub value: String,
}

/// An XML start element.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StartElement {
    /// Go's `Name`.
    pub name: Name,
    /// Go's `Attr`.
    pub attr: Vec<Attr>,
}

impl StartElement {
    /// Creates a new copy of the start element (Go `StartElement.Copy`).
    pub fn copy(&self) -> StartElement {
        self.clone()
    }
    /// Returns the corresponding end element (Go `StartElement.End`).
    pub fn end(&self) -> EndElement {
        EndElement {
            name: self.name.clone(),
        }
    }
}

/// An XML end element.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EndElement {
    /// Go's `Name`.
    pub name: Name,
}

/// Character data (raw text) in which escape sequences have been replaced by
/// the characters they represent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CharData(pub Vec<u8>);

impl CharData {
    /// Creates a new copy of the data (Go `CharData.Copy`).
    pub fn copy(&self) -> CharData {
        self.clone()
    }
}

/// An XML comment `<!--comment-->`; the bytes exclude the markers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Comment(pub Vec<u8>);

impl Comment {
    /// Creates a new copy of the comment (Go `Comment.Copy`).
    pub fn copy(&self) -> Comment {
        self.clone()
    }
}

/// A processing instruction `<?target inst?>`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcInst {
    /// Go's `Target`.
    pub target: String,
    /// Go's `Inst`.
    pub inst: Vec<u8>,
}

impl ProcInst {
    /// Creates a new copy of the instruction (Go `ProcInst.Copy`).
    pub fn copy(&self) -> ProcInst {
        self.clone()
    }
}

/// A directive `<!text>`; the bytes exclude the markers.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Directive(pub Vec<u8>);

impl Directive {
    /// Creates a new copy of the directive (Go `Directive.Copy`).
    pub fn copy(&self) -> Directive {
        self.clone()
    }
}

/// One of the token types (Go's `Token` interface).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// A [`StartElement`].
    StartElement(StartElement),
    /// An [`EndElement`].
    EndElement(EndElement),
    /// A [`CharData`].
    CharData(CharData),
    /// A [`Comment`].
    Comment(Comment),
    /// A [`ProcInst`].
    ProcInst(ProcInst),
    /// A [`Directive`].
    Directive(Directive),
}

/// Returns a copy of a token (Go `CopyToken`).
pub fn copy_token(t: &Token) -> Token {
    t.clone()
}

/// Anything that can decode a stream of XML tokens, including a [`Decoder`]
/// (Go `TokenReader`). `Err(Error::Eof)` marks the end of the stream.
pub trait TokenReader {
    /// Returns the next token.
    fn token(&mut self) -> Result<Token, Error>;
}

/// Go's `HTMLEntity` as the map [`Decoder::entity`] expects.
pub fn html_entity() -> HashMap<String, String> {
    HTML_ENTITY
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// Go's `HTMLAutoClose` as the list `Decoder::auto_close` expects.
pub fn html_auto_close() -> Vec<String> {
    HTML_AUTO_CLOSE.iter().map(|s| (*s).to_string()).collect()
}

/// Decides whether `r` is in the XML character range (Char production).
pub(crate) fn is_in_character_range(r: i32) -> bool {
    r == 0x09
        || r == 0x0A
        || r == 0x0D
        || (0x20..=0xD7FF).contains(&r)
        || (0xE000..=0xFFFD).contains(&r)
        || (0x10000..=0x10FFFF).contains(&r)
}

fn in_table(table: &[(u32, u32)], c: u32) -> bool {
    table
        .binary_search_by(|&(lo, hi)| {
            if c < lo {
                std::cmp::Ordering::Greater
            } else if c > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Go's `isName`: a name per its (XML 1.0 second edition) `first`/`second`
/// range tables; invalid UTF-8 is never a name.
pub(crate) fn is_name(s: &[u8]) -> bool {
    use crate::unicode::rune::decode_rune;
    if s.is_empty() {
        return false;
    }
    let (c, n) = decode_rune(s);
    if c == 0xFFFD && n == 1 {
        return false;
    }
    if !in_table(&tables::FIRST, c as u32) {
        return false;
    }
    let mut rest = &s[n..];
    while !rest.is_empty() {
        let (c, n) = decode_rune(rest);
        if c == 0xFFFD && n == 1 {
            return false;
        }
        let c = c as u32;
        if !in_table(&tables::FIRST, c) && !in_table(&tables::SECOND, c) {
            return false;
        }
        rest = &rest[n..];
    }
    true
}
