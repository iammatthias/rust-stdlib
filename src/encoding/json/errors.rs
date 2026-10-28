//! Go's `encoding/json` error types with Go's `Error()` text.
//!
//! Go's `reflect.Type` fields become Go-style type names (`int`, `[]string`,
//! `map[string]interface {}`, or the Rust struct name for derived types).
use std::{error, fmt};

type BoxError = Box<dyn error::Error + Send + Sync>;

/// Appends the escaped form of `r`, as Go's `strconv` does for quotes `"`/`'`.
fn escape_rune(out: &mut String, r: i32, quote: char) {
    let c = char::from_u32(r as u32);
    match c {
        Some(c) if c == quote || c == '\\' => {
            out.push('\\');
            out.push(c);
        }
        Some(c) if crate::unicode::is_print(r) => out.push(c),
        _ => match r {
            7 => out.push_str("\\a"),
            8 => out.push_str("\\b"),
            12 => out.push_str("\\f"),
            10 => out.push_str("\\n"),
            13 => out.push_str("\\r"),
            9 => out.push_str("\\t"),
            11 => out.push_str("\\v"),
            _ if !(32..0x7f).contains(&r) && r < 0x80 => out.push_str(&format!("\\x{r:02x}")),
            _ if c.is_none() => out.push_str("\\ufffd"),
            _ if r < 0x10000 => out.push_str(&format!("\\u{r:04x}")),
            _ => out.push_str(&format!("\\U{r:08x}")),
        },
    }
}

/// Go's `strconv.Quote` for arbitrary bytes (invalid UTF-8 becomes `\xNN`).
pub(crate) fn quote_bytes(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut rest = s;
    while !rest.is_empty() {
        let (r, n) = crate::unicode::rune::decode_rune(rest);
        if r == 0xFFFD && n == 1 {
            out.push_str(&format!("\\x{:02x}", rest[0]));
        } else {
            escape_rune(&mut out, r, '"');
        }
        rest = &rest[n..];
    }
    out.push('"');
    out
}

/// Go's `strconv.Quote`.
pub(crate) fn quote(s: &str) -> String {
    quote_bytes(s.as_bytes())
}

/// `jsonwire.QuoteRune`: quotes the first rune of `b` (an invalid byte is
/// written as `'\xNN'`) and returns the number of bytes it covers.
pub(crate) fn quote_rune_at(b: &[u8]) -> (String, usize) {
    let (r, n) = crate::unicode::rune::decode_rune(b);
    if r == 0xFFFD && n == 1 {
        return (format!("'\\x{:x}'", b[0]), 1);
    }
    let mut out = String::from("'");
    escape_rune(&mut out, r, '\'');
    out.push('\'');
    (out, n)
}

/// `jsonwire.InvalidTextError.Error`.
pub(crate) fn invalid_text(label: &str, what: &[u8], where_: &str) -> String {
    let (single, _) = {
        let (_, n) = crate::unicode::rune::decode_rune(what);
        (crate::unicode::rune::rune_count(what) == 1, n)
    };
    let need_escape = {
        let mut rest = what;
        let mut found = false;
        while !rest.is_empty() {
            let (r, n) = crate::unicode::rune::decode_rune(rest);
            if r == i32::from(b'`')
                || r == 0xFFFD
                || crate::unicode::is_space(r)
                || !crate::unicode::is_print(r)
            {
                found = true;
                break;
            }
            rest = &rest[n..];
        }
        found
    };
    let quoted = if single {
        quote_rune_at(what).0
    } else if need_escape {
        quote_bytes(what)
    } else {
        format!("`{}`", String::from_utf8_lossy(what))
    };
    format!("invalid {label} {quoted} {where_}")
        .trim_end_matches(' ')
        .to_string()
}

/// A syntax error in the JSON input; `offset` is the number of bytes read
/// before the error was detected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    msg: String,
    pub offset: i64,
}
impl SyntaxError {
    pub fn new(msg: impl Into<String>, offset: i64) -> Self {
        Self {
            msg: msg.into(),
            offset,
        }
    }
}
impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}
impl error::Error for SyntaxError {}

/// A JSON value that was not appropriate for a value of a specific type.
#[derive(Debug, Default)]
pub struct UnmarshalTypeError {
    /// Description of the JSON value: "bool", "array", "number -5".
    pub value: String,
    /// Name of the type the value could not be assigned to.
    pub type_name: String,
    /// The error occurred after reading `offset` bytes.
    pub offset: i64,
    /// Name of the struct type containing the field.
    pub struct_name: String,
    /// The full path from the root to the field, including embedded structs.
    pub field: String,
    pub err: Option<BoxError>,
}
impl fmt::Display for UnmarshalTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.struct_name.is_empty() || !self.field.is_empty() {
            // As in Go, a path ending in an index is a slice or array.
            let last = self.field.rsplit('.').next().unwrap_or("");
            let into = if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
                ""
            } else {
                "Go struct field "
            };
            write!(
                f,
                "json: cannot unmarshal {} into {}{}.{} of type {}",
                self.value, into, self.struct_name, self.field, self.type_name
            )?;
        } else {
            write!(
                f,
                "json: cannot unmarshal {} into Go value of type {}",
                self.value, self.type_name
            )?;
        }
        if let Some(err) = &self.err {
            write!(f, ": {err}")?;
        }
        Ok(())
    }
}
impl error::Error for UnmarshalTypeError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.err
            .as_deref()
            .map(|e| e as &(dyn error::Error + 'static))
    }
}

/// Deprecated: no longer returned; kept for compatibility.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnmarshalFieldError {
    pub key: String,
    pub type_name: String,
    pub field: String,
}
impl fmt::Display for UnmarshalFieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "json: cannot unmarshal object key {} into unexported field {} of type {}",
            quote(&self.key),
            self.field,
            self.type_name
        )
    }
}
impl error::Error for UnmarshalFieldError {}

/// An invalid argument passed to `unmarshal`. Go reports a nil or non-pointer
/// target; Rust's typed API cannot construct one, but the type keeps Go's text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InvalidUnmarshalError {
    /// `None` is Go's nil type.
    pub type_name: Option<String>,
    /// Whether the described type is a pointer.
    pub pointer: bool,
}
impl fmt::Display for InvalidUnmarshalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.type_name {
            None => f.write_str("json: Unmarshal(nil)"),
            Some(t) if !self.pointer => write!(f, "json: Unmarshal(non-pointer {t})"),
            Some(t) => write!(f, "json: Unmarshal(nil {t})"),
        }
    }
}
impl error::Error for InvalidUnmarshalError {}

/// A type that cannot be encoded as JSON.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnsupportedTypeError {
    pub type_name: String,
}
impl fmt::Display for UnsupportedTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "json: unsupported type: {}", self.type_name)
    }
}
impl error::Error for UnsupportedTypeError {}

/// A value that cannot be encoded as JSON, such as NaN or a cycle.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnsupportedValueError {
    /// Description of the offending value.
    pub value: String,
    pub str: String,
}
impl fmt::Display for UnsupportedValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "json: unsupported value: {}", self.str)
    }
}
impl error::Error for UnsupportedValueError {}

/// Deprecated: no longer returned; invalid UTF-8 is replaced with U+FFFD.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InvalidUTF8Error {
    pub s: String,
}
impl fmt::Display for InvalidUTF8Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "json: invalid UTF-8 in string: {}", quote(&self.s))
    }
}
impl error::Error for InvalidUTF8Error {}

/// An error returned by a `Marshaler` (or text marshaler).
#[derive(Debug)]
pub struct MarshalerError {
    pub type_name: String,
    pub err: BoxError,
    pub(crate) source_func: &'static str,
}
impl MarshalerError {
    pub fn new(type_name: impl Into<String>, err: BoxError) -> Self {
        Self {
            type_name: type_name.into(),
            err,
            source_func: "MarshalJSON",
        }
    }
}
impl fmt::Display for MarshalerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let src = if self.source_func.is_empty() {
            "MarshalJSON"
        } else {
            self.source_func
        };
        write!(
            f,
            "json: error calling {src} for type {}: {}",
            self.type_name, self.err
        )
    }
}
impl error::Error for MarshalerError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self.err.as_ref())
    }
}
