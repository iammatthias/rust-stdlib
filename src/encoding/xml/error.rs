//! Error values with Go's exact `Error()` texts.
use super::conv::quote;
use std::{fmt, io, sync::Arc};

/// A syntax error in the XML input stream (Go `xml.SyntaxError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    /// Go's `Msg` field.
    pub msg: String,
    /// Go's `Line` field (1-based).
    pub line: usize,
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "XML syntax error on line {}: {}", self.line, self.msg)
    }
}
impl std::error::Error for SyntaxError {}

/// Conflicting field-tag paths (Go `xml.TagPathError`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TagPathError {
    /// Go's `Struct`: the type name of the struct.
    pub struct_type: String,
    /// Go's `Field1`.
    pub field1: String,
    /// Go's `Tag1`.
    pub tag1: String,
    /// Go's `Field2`.
    pub field2: String,
    /// Go's `Tag2`.
    pub tag2: String,
}

impl fmt::Display for TagPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} field {} with tag {} conflicts with field {} with tag {}",
            self.struct_type,
            quote(self.field1.as_bytes()),
            quote(self.tag1.as_bytes()),
            quote(self.field2.as_bytes()),
            quote(self.tag2.as_bytes())
        )
    }
}
impl std::error::Error for TagPathError {}

/// An error in the unmarshaling process (Go `xml.UnmarshalError`, a string type).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnmarshalError(pub String);

impl fmt::Display for UnmarshalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for UnmarshalError {}

/// A type that cannot be converted into XML (Go `xml.UnsupportedTypeError`).
///
/// Go carries a `reflect.Type`; the Rust equivalent is its printed form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsupportedTypeError {
    /// Go's `Type`, as `reflect.Type.String()` prints it.
    pub type_name: String,
}

impl fmt::Display for UnsupportedTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "xml: unsupported type: {}", self.type_name)
    }
}
impl std::error::Error for UnsupportedTypeError {}

/// Every error `encoding/xml` can return. `Display` is Go's `Error()` text.
#[derive(Clone, Debug)]
pub enum Error {
    /// `io.EOF`: the end of the token stream.
    Eof,
    /// A `*SyntaxError`.
    Syntax(SyntaxError),
    /// A `*TagPathError`.
    TagPath(TagPathError),
    /// An `UnmarshalError`.
    Unmarshal(UnmarshalError),
    /// An `*UnsupportedTypeError`.
    UnsupportedType(UnsupportedTypeError),
    /// A failure of the underlying reader or writer.
    Io(Arc<io::Error>),
    /// An `errors.New` / `fmt.Errorf` error with only a message.
    Message(String),
    /// Any other error returned by user code (for example from `MarshalXML`).
    Custom(Arc<dyn std::error::Error + Send + Sync>),
}

impl Error {
    /// An error carrying only a message (Go `errors.New`).
    pub fn msg(message: impl Into<String>) -> Self {
        Error::Message(message.into())
    }
    /// Wraps any error value so it can be returned from user hooks.
    pub fn custom(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Error::Custom(Arc::new(error))
    }
    /// Reports whether this is `io.EOF`.
    pub fn is_eof(&self) -> bool {
        matches!(self, Error::Eof)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Eof => f.write_str("EOF"),
            Error::Syntax(e) => e.fmt(f),
            Error::TagPath(e) => e.fmt(f),
            Error::Unmarshal(e) => e.fmt(f),
            Error::UnsupportedType(e) => e.fmt(f),
            Error::Io(e) => e.fmt(f),
            Error::Message(m) => f.write_str(m),
            Error::Custom(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Syntax(e) => Some(e),
            Error::TagPath(e) => Some(e),
            Error::Unmarshal(e) => Some(e),
            Error::UnsupportedType(e) => Some(e),
            Error::Io(e) => Some(&**e),
            Error::Custom(e) => Some(&**e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(Arc::new(e))
    }
}
impl From<SyntaxError> for Error {
    fn from(e: SyntaxError) -> Self {
        Error::Syntax(e)
    }
}
impl From<TagPathError> for Error {
    fn from(e: TagPathError) -> Self {
        Error::TagPath(e)
    }
}
impl From<UnmarshalError> for Error {
    fn from(e: UnmarshalError) -> Self {
        Error::Unmarshal(e)
    }
}
impl From<UnsupportedTypeError> for Error {
    fn from(e: UnsupportedTypeError) -> Self {
        Error::UnsupportedType(e)
    }
}
