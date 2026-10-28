//! Go's JSON decoder: `Unmarshal`, `Unmarshaler`, `Number` and the
//! `Deserialize` implementations for the standard types.
//!
//! `unmarshal` validates the whole input first, as Go does, so syntax errors
//! always win over type errors. Decoding then walks a [`Node`] tree that
//! remembers the byte span of every value, which gives `UnmarshalTypeError`
//! its offsets and lets `Unmarshaler` types receive their raw JSON text.
use std::collections::{BTreeMap, HashMap};

use super::{
    default_options_v1,
    encode::{format_float, is_valid_number, MapKey},
    errors::quote,
    fields::{resolve, Field, FieldList},
    options::Flag,
    scanner::{check_valid, Scanner},
    Bytes, Error, Map, Number, Options, RawMessage, UnmarshalTypeError, Value,
};

/// Decoder settings that travel with a decode (`Decoder.UseNumber` and
/// `Decoder.DisallowUnknownFields`).
#[derive(Clone, Copy, Debug)]
pub struct DecodeState {
    /// Decode JSON numbers in dynamic values as [`Number`] instead of floats.
    pub use_number: bool,
    /// Reject object keys that match no struct field.
    pub disallow_unknown_fields: bool,
    /// v1 semantics of the `string` tag option (see
    /// [`stringify_with_legacy_semantics`](super::stringify_with_legacy_semantics)).
    pub legacy_stringify: bool,
    /// Accept JSON arrays of any length for Rust arrays (see
    /// [`unmarshal_array_from_any_length`](super::unmarshal_array_from_any_length)).
    pub array_from_any_length: bool,
    /// Treat `-` and `_` as significant when matching object keys to fields
    /// (see [`match_case_sensitive_delimiter`](super::match_case_sensitive_delimiter)).
    pub case_sensitive_delimiter: bool,
    /// Ignore `\r` and `\n` in base64 text for [`Bytes`] (see
    /// [`parse_bytes_with_loose_rfc4648`](super::parse_bytes_with_loose_rfc4648)).
    pub loose_base64: bool,
    /// Accept a JSON array for [`Bytes`] (see
    /// [`format_bytes_with_legacy_semantics`](super::format_bytes_with_legacy_semantics)).
    pub legacy_bytes: bool,
    /// Decode `std::time::Duration` from a number of nanoseconds; when off it
    /// has no representation (see
    /// [`format_duration_as_nano`](super::format_duration_as_nano)).
    pub duration_nano: bool,
}

impl Default for DecodeState {
    fn default() -> Self {
        Self {
            use_number: false,
            disallow_unknown_fields: false,
            legacy_stringify: true,
            array_from_any_length: true,
            case_sensitive_delimiter: true,
            loose_base64: true,
            legacy_bytes: true,
            duration_nano: true,
        }
    }
}

impl DecodeState {
    /// The settings of `options` over Go's v1 defaults.
    pub fn with_options(options: Options) -> Self {
        let options = default_options_v1().join(options);
        Self {
            legacy_stringify: options.get(Flag::StringifyWithLegacySemantics) != Some(false),
            array_from_any_length: options.get(Flag::UnmarshalArrayFromAnyLength) != Some(false),
            case_sensitive_delimiter: options.get(Flag::MatchCaseSensitiveDelimiter) != Some(false),
            loose_base64: options.get(Flag::ParseBytesWithLooseRFC4648) != Some(false),
            legacy_bytes: options.get(Flag::FormatBytesWithLegacySemantics) != Some(false),
            duration_nano: options.get(Flag::FormatDurationAsNano) != Some(false),
            ..Self::default()
        }
    }
}

/// Implemented by types that can decode themselves from JSON text (Go's
/// `json.Unmarshaler`). Use [`Node::unmarshal_into`] from
/// `Deserialize::unmarshal_json` to run it on a decoded value.
pub trait Unmarshaler {
    /// `data` is a valid JSON value; copy it to retain it.
    fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), Error>;
}

/// A parsed JSON value that remembers where it came from in the input.
pub struct Node<'a> {
    data: &'a [u8],
    start: usize,
    end: usize,
    kind: Kind<'a>,
}

enum Kind<'a> {
    Null,
    Bool(bool),
    Number,
    String(String),
    Array(Vec<Node<'a>>),
    Object(Vec<Member<'a>>),
}

struct Member<'a> {
    key: String,
    key_start: usize,
    key_end: usize,
    value: Node<'a>,
}

impl<'a> Node<'a> {
    /// The value's JSON text.
    pub fn raw(&self) -> &'a [u8] {
        &self.data[self.start..self.end]
    }
    pub fn is_null(&self) -> bool {
        matches!(self.kind, Kind::Null)
    }
    /// Go's description of the JSON value in type errors.
    fn describe(&self) -> &'static str {
        match self.kind {
            Kind::Null => "null",
            Kind::Bool(_) => "bool",
            Kind::Number => "number",
            Kind::String(_) => "string",
            Kind::Array(_) => "array",
            Kind::Object(_) => "object",
        }
    }
    /// Offset reported by type errors: after the literal, or after the
    /// opening bracket for arrays and objects.
    fn error_offset(&self) -> i64 {
        match self.kind {
            Kind::Array(_) | Kind::Object(_) => self.start as i64 + 1,
            _ => self.end as i64,
        }
    }
    /// The error for storing this value in a `type_name`.
    pub fn type_error(&self, type_name: impl Into<String>) -> Error {
        self.type_error_value(self.describe().to_string(), type_name)
    }
    fn type_error_value(&self, value: String, type_name: impl Into<String>) -> Error {
        Error::UnmarshalType(UnmarshalTypeError {
            value,
            type_name: type_name.into(),
            offset: self.error_offset(),
            ..UnmarshalTypeError::default()
        })
    }
    /// Runs an [`Unmarshaler`] on this value's JSON text.
    pub fn unmarshal_into<U: Unmarshaler + ?Sized>(&self, u: &mut U) -> Result<(), Error> {
        u.unmarshal_json(self.raw()).map_err(|e| match e {
            Error::UnmarshalType(mut t) if !t.field.starts_with(PATHLESS) => {
                t.field.insert_str(0, PATHLESS);
                Error::UnmarshalType(t)
            }
            other => other,
        })
    }
    /// Converts to a dynamic [`Value`] the way Go decodes into `interface{}`:
    /// numbers become `float64` (written back with Go's float formatting)
    /// unless `cx.use_number` is set. Object members are inserted sorted by
    /// key, as the `map[string]any` Go decodes into marshals them.
    pub fn to_value(&self, cx: &DecodeState) -> Result<Value, Error> {
        self.value_in(cx, true)
    }
    /// Like [`to_value`](Self::to_value), but objects keep the order of the
    /// text. Used to read back the encoding of a struct, whose fields are in
    /// declaration order.
    pub(crate) fn to_value_ordered(&self, cx: &DecodeState) -> Result<Value, Error> {
        self.value_in(cx, false)
    }
    fn value_in(&self, cx: &DecodeState, sorted: bool) -> Result<Value, Error> {
        Ok(match &self.kind {
            Kind::Null => Value::Null,
            Kind::Bool(b) => Value::Bool(*b),
            Kind::String(s) => Value::String(s.clone()),
            Kind::Number => {
                let text = String::from_utf8_lossy(self.raw()).into_owned();
                if cx.use_number {
                    Value::Number(Number(text))
                } else {
                    match text.parse::<f64>() {
                        Ok(f) if f.is_finite() => Value::Number(Number(format_float(f, 64))),
                        _ => {
                            return Err(Error::UnmarshalType(UnmarshalTypeError {
                                value: format!("number {text}"),
                                type_name: "float64".into(),
                                offset: self.end as i64,
                                ..UnmarshalTypeError::default()
                            }))
                        }
                    }
                }
            }
            Kind::Array(items) => Value::Array(
                items
                    .iter()
                    .enumerate()
                    .map(|(i, n)| {
                        n.value_in(cx, sorted)
                            .map_err(|e| add_segment(e, &i.to_string()))
                    })
                    .collect::<Result<_, _>>()?,
            ),
            Kind::Object(members) => {
                let mut entries = Vec::with_capacity(members.len());
                for m in members {
                    let v = m
                        .value
                        .value_in(cx, sorted)
                        .map_err(|e| add_segment(e, &pointer_token(&m.key)))?;
                    entries.push((m.key.clone(), v));
                }
                Value::Object(if sorted {
                    Map::from_unsorted(entries)
                } else {
                    entries.into_iter().collect()
                })
            }
        })
    }
}

/// A JSON Pointer reference token: `~` is `~0` and `/` is `~1`.
fn pointer_token(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn skip_space(data: &[u8], mut i: usize) -> usize {
    while matches!(data.get(i), Some(b' ' | b'\t' | b'\r' | b'\n')) {
        i += 1;
    }
    i
}

/// Index just past the string literal that starts at `data[start]`.
fn string_end(data: &[u8], start: usize) -> Result<usize, Error> {
    let mut i = start + 1;
    while let Some(&c) = data.get(i) {
        match c {
            b'"' => return Ok(i + 1),
            b'\\' => i += 2,
            _ => i += 1,
        }
    }
    Err(malformed())
}

fn malformed() -> Error {
    Error::Other("json: decoder out of sync - data changing underfoot?".into())
}

fn hex4(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    let mut r = 0;
    for &c in &b[..4] {
        r = r * 16 + (c as char).to_digit(16)?;
    }
    Some(r)
}

/// Go's `unquoteBytes` for a validated string literal (quotes included):
/// invalid UTF-8 and unpaired surrogates become U+FFFD.
pub(crate) fn unquote(lit: &[u8]) -> String {
    let s = &lit[1..lit.len() - 1];
    let mut out = String::with_capacity(s.len());
    let mut r = 0;
    while r < s.len() {
        let c = s[r];
        if c == b'\\' {
            r += 1;
            match s.get(r) {
                Some(b'"') => out.push('"'),
                Some(b'\\') => out.push('\\'),
                Some(b'/') => out.push('/'),
                Some(b'\'') => out.push('\''),
                Some(b'b') => out.push('\u{8}'),
                Some(b'f') => out.push('\u{c}'),
                Some(b'n') => out.push('\n'),
                Some(b'r') => out.push('\r'),
                Some(b't') => out.push('\t'),
                Some(b'u') => {
                    let first = hex4(&s[r + 1..]).unwrap_or(0xFFFD);
                    r += 4;
                    let mut ch = char::from_u32(first);
                    if (0xD800..0xE000).contains(&first) {
                        ch = None;
                        // A high surrogate followed by an escaped low one.
                        if first < 0xDC00
                            && s.get(r + 1) == Some(&b'\\')
                            && s.get(r + 2) == Some(&b'u')
                        {
                            if let Some(second) = hex4(&s[r + 3..]) {
                                if (0xDC00..0xE000).contains(&second) {
                                    ch = char::from_u32(
                                        0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00),
                                    );
                                    r += 6;
                                }
                            }
                        }
                    }
                    out.push(ch.unwrap_or('\u{FFFD}'));
                }
                _ => out.push('\u{FFFD}'),
            }
            r += 1;
        } else if c < 0x80 {
            out.push(c as char);
            r += 1;
        } else {
            let (rune, n) = crate::unicode::rune::decode_rune(&s[r..]);
            if rune == 0xFFFD && n == 1 {
                out.push('\u{FFFD}');
            } else {
                out.push(char::from_u32(rune as u32).unwrap_or('\u{FFFD}'));
            }
            r += n;
        }
    }
    out
}

enum Frame<'a> {
    Array(usize, Vec<Node<'a>>),
    Object(usize, Vec<Member<'a>>, String, usize, usize),
}

/// Builds the node tree for one valid JSON value (surrounding whitespace is
/// allowed). Iterative, so nesting depth does not consume the native stack.
pub(crate) fn parse_node(data: &[u8]) -> Result<Node<'_>, Error> {
    let mut stack: Vec<Frame<'_>> = Vec::new();
    let mut pos = skip_space(data, 0);
    // Reads an object key and the colon after it, returning the new position.
    fn read_key(data: &[u8], pos: usize) -> Result<(String, usize, usize, usize), Error> {
        if data.get(pos) != Some(&b'"') {
            return Err(malformed());
        }
        let end = string_end(data, pos)?;
        let key = unquote(&data[pos..end]);
        let colon = skip_space(data, end);
        if data.get(colon) != Some(&b':') {
            return Err(malformed());
        }
        Ok((key, pos, end, skip_space(data, colon + 1)))
    }
    'value: loop {
        let c = *data.get(pos).ok_or_else(malformed)?;
        let mut node = match c {
            b'[' => {
                let start = pos;
                pos = skip_space(data, pos + 1);
                if data.get(pos) == Some(&b']') {
                    pos += 1;
                    Node {
                        data,
                        start,
                        end: pos,
                        kind: Kind::Array(Vec::new()),
                    }
                } else {
                    stack.push(Frame::Array(start, Vec::new()));
                    continue 'value;
                }
            }
            b'{' => {
                let start = pos;
                pos = skip_space(data, pos + 1);
                if data.get(pos) == Some(&b'}') {
                    pos += 1;
                    Node {
                        data,
                        start,
                        end: pos,
                        kind: Kind::Object(Vec::new()),
                    }
                } else {
                    let (key, key_start, key_end, next) = read_key(data, pos)?;
                    pos = next;
                    stack.push(Frame::Object(start, Vec::new(), key, key_start, key_end));
                    continue 'value;
                }
            }
            b'"' => {
                let end = string_end(data, pos)?;
                let node = Node {
                    data,
                    start: pos,
                    end,
                    kind: Kind::String(unquote(&data[pos..end])),
                };
                pos = end;
                node
            }
            b't' | b'f' | b'n' => {
                let (word, kind): (&[u8], Kind<'_>) = match c {
                    b't' => (b"true", Kind::Bool(true)),
                    b'f' => (b"false", Kind::Bool(false)),
                    _ => (b"null", Kind::Null),
                };
                if !data[pos..].starts_with(word) {
                    return Err(malformed());
                }
                let node = Node {
                    data,
                    start: pos,
                    end: pos + word.len(),
                    kind,
                };
                pos += word.len();
                node
            }
            b'-' | b'0'..=b'9' => {
                let start = pos;
                while matches!(
                    data.get(pos),
                    Some(b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-')
                ) {
                    pos += 1;
                }
                Node {
                    data,
                    start,
                    end: pos,
                    kind: Kind::Number,
                }
            }
            _ => return Err(malformed()),
        };
        // Attach the finished value to its parent, closing parents as needed.
        loop {
            match stack.pop() {
                None => return Ok(node),
                Some(Frame::Array(start, mut items)) => {
                    items.push(node);
                    pos = skip_space(data, pos);
                    match data.get(pos) {
                        Some(b',') => {
                            pos = skip_space(data, pos + 1);
                            stack.push(Frame::Array(start, items));
                            continue 'value;
                        }
                        Some(b']') => {
                            pos += 1;
                            node = Node {
                                data,
                                start,
                                end: pos,
                                kind: Kind::Array(items),
                            };
                        }
                        _ => return Err(malformed()),
                    }
                }
                Some(Frame::Object(start, mut members, key, key_start, key_end)) => {
                    members.push(Member {
                        key,
                        key_start,
                        key_end,
                        value: node,
                    });
                    pos = skip_space(data, pos);
                    match data.get(pos) {
                        Some(b',') => {
                            pos = skip_space(data, pos + 1);
                            let (key, key_start, key_end, next) = read_key(data, pos)?;
                            pos = next;
                            stack.push(Frame::Object(start, members, key, key_start, key_end));
                            continue 'value;
                        }
                        Some(b'}') => {
                            pos += 1;
                            node = Node {
                                data,
                                start,
                                end: pos,
                                kind: Kind::Object(members),
                            };
                        }
                        _ => return Err(malformed()),
                    }
                }
            }
        }
    }
}

/// Implemented by types that can decode themselves from JSON.
///
/// `from_json` decodes from a dynamic [`Value`]; `unmarshal_json` decodes
/// from the parsed input and is what [`unmarshal`] uses. The derive macro
/// implements both; hand-written types may implement only `from_json`.
pub trait Deserialize: Sized {
    fn from_json(value: &Value) -> Result<Self, Error>;
    /// Decodes from parsed JSON text.
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        // Keep number text exact: `from_json` parses integers itself.
        let exact = DecodeState {
            use_number: true,
            ..*cx
        };
        Self::from_json(&node.to_value(&exact)?)
    }
    /// Decodes into an existing value, as Go's `Unmarshal(data, &existing)`
    /// does. The default replaces the value, which is Go's rule for scalars,
    /// slices and interfaces; JSON `null` leaves a scalar unchanged. Structs,
    /// maps, arrays and pointers merge (the derive implements it for
    /// structs).
    fn unmarshal_json_into(&mut self, node: &Node<'_>, cx: &mut DecodeState) -> Result<(), Error> {
        if node.is_null() && (Self::JSON_QUOTABLE || Self::JSON_NUMBER) {
            return Ok(());
        }
        *self = Self::unmarshal_json(node, cx)?;
        Ok(())
    }
    /// [`unmarshal_json_into`](Self::unmarshal_json_into) for a value written
    /// quoted by the `string` tag option; `null` and `"null"` change nothing.
    fn unmarshal_quoted_into(
        &mut self,
        node: &Node<'_>,
        cx: &mut DecodeState,
    ) -> Result<(), Error> {
        let null_text = matches!(&node.kind, Kind::String(t) if t == "null" && cx.legacy_stringify);
        if node.is_null() || null_text {
            return Ok(());
        }
        *self = Self::unmarshal_quoted(node, cx)?;
        Ok(())
    }
    /// The value used when the input has no value for this type (an absent
    /// struct field or JSON `null`): Go's zero value.
    fn json_zero() -> Result<Self, Error> {
        Err(Error::Type("missing field"))
    }
    /// Whether the `string` tag option applies to this type (numbers,
    /// booleans and strings).
    const JSON_QUOTABLE: bool = false;
    /// Whether this type decodes from a JSON number (for the v2 form of the
    /// `string` tag option, which only quotes numbers).
    const JSON_NUMBER: bool = false;
    /// Decodes a value that was written quoted by the `string` tag option.
    fn unmarshal_quoted(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        Self::unmarshal_json(node, cx)
    }
    /// Go's name for this type, used in error messages.
    fn json_type_name() -> String {
        std::any::type_name::<Self>().to_string()
    }
    /// The name Go reports in `UnmarshalTypeError.Struct` when this is the
    /// root type: the struct's name, empty for unnamed types.
    fn json_root_name() -> &'static str {
        ""
    }
}

/// What a field with the `string` tag option holds inside its JSON string.
#[derive(Clone, Copy)]
pub enum Quoted {
    Number,
    Bool,
    String,
}

/// The decoding half of a `string` tag option: the value must be a JSON
/// string holding the literal, or `null`.
pub fn unmarshal_quoted_with<T: Deserialize>(
    node: &Node<'_>,
    cx: &mut DecodeState,
    kind: Quoted,
) -> Result<T, Error> {
    let text = match &node.kind {
        Kind::Null => return T::json_zero(),
        Kind::String(text) => text,
        _ => return Err(node.type_error(T::json_type_name())),
    };
    if text == "null" && cx.legacy_stringify {
        return T::json_zero();
    }
    fn inner<'t>(text: &'t str, kind: Kind<'t>) -> Node<'t> {
        Node {
            data: text.as_bytes(),
            start: 0,
            end: text.len(),
            kind,
        }
    }
    let at_string_end = |e: Error| match e {
        Error::UnmarshalType(mut t) => {
            t.offset = node.end as i64;
            Error::UnmarshalType(t)
        }
        other => other,
    };
    match kind {
        Quoted::Number => T::unmarshal_json(&inner(text, Kind::Number), cx).map_err(at_string_end),
        Quoted::Bool => match text.as_str() {
            "true" => T::unmarshal_json(&inner(text, Kind::Bool(true)), cx),
            "false" => T::unmarshal_json(&inner(text, Kind::Bool(false)), cx),
            _ => Err(Error::UnmarshalType(UnmarshalTypeError {
                value: format!("string {}", String::from_utf8_lossy(node.raw())),
                type_name: T::json_type_name(),
                offset: node.end as i64,
                err: Some("invalid syntax".into()),
                ..UnmarshalTypeError::default()
            })),
        },
        Quoted::String => {
            if let Some(msg) = super::stream::string_literal_error(text.as_bytes()) {
                return Err(Error::UnmarshalType(UnmarshalTypeError {
                    value: "string".into(),
                    type_name: T::json_type_name(),
                    offset: node.end as i64,
                    err: Some(msg.into()),
                    ..UnmarshalTypeError::default()
                }));
            }
            let content = unquote(text.as_bytes());
            T::unmarshal_json(&inner(text, Kind::String(content)), cx).map_err(at_string_end)
        }
    }
}

/// Decodes `data` into a `T`. As in Go, the whole input is validated first
/// (a [`SyntaxError`](super::SyntaxError) takes precedence over type errors).
pub fn unmarshal<T: Deserialize>(data: &[u8]) -> Result<T, Error> {
    unmarshal_with(data, DecodeState::default())
}

/// Decodes `data` into an existing value, as Go's `Unmarshal(data, &v)` does:
/// a struct keeps the fields the input does not name (nested structs and
/// pointers are merged the same way), a map keeps its other entries and
/// every entry it names is replaced, an array is decoded in place, and a
/// scalar or `Vec` is replaced. JSON `null` empties maps, vectors and
/// options and leaves everything else unchanged. Syntax errors leave `v` untouched;
/// after a type error the fields that could be decoded are set.
///
/// ```
/// use rust_stdlib::encoding::json::unmarshal_into;
/// use std::collections::BTreeMap;
///
/// let mut counts = BTreeMap::from([("a".to_string(), 1), ("b".to_string(), 2)]);
/// unmarshal_into(br#"{"b": 3, "c": 4}"#, &mut counts).unwrap();
/// assert_eq!(counts, BTreeMap::from([("a".into(), 1), ("b".into(), 3), ("c".into(), 4)]));
/// ```
pub fn unmarshal_into<T: Deserialize>(data: &[u8], v: &mut T) -> Result<(), Error> {
    unmarshal_into_with(data, v, DecodeState::default())
}

pub(crate) fn unmarshal_into_with<T: Deserialize>(
    data: &[u8],
    v: &mut T,
    mut cx: DecodeState,
) -> Result<(), Error> {
    check_valid(data, &mut Scanner::new())?;
    let node = parse_node(data)?;
    v.unmarshal_json_into(&node, &mut cx)
        .map_err(root_context::<T>)
}

pub(crate) fn unmarshal_with<T: Deserialize>(data: &[u8], mut cx: DecodeState) -> Result<T, Error> {
    check_valid(data, &mut Scanner::new())?;
    let node = parse_node(data)?;
    T::unmarshal_json(&node, &mut cx).map_err(root_context::<T>)
}

/// Go reports the root type's name with the path to a mistyped value.
pub(crate) fn root_context<T: Deserialize>(e: Error) -> Error {
    match e {
        Error::UnmarshalType(mut t) if t.field.starts_with('/') => {
            t.struct_name = T::json_root_name().to_string();
            t.field = t.field[1..].replace('/', ".");
            Error::UnmarshalType(t)
        }
        Error::UnmarshalType(mut t) if t.field.starts_with(PATHLESS) => {
            t.field.drain(..PATHLESS.len());
            Error::UnmarshalType(t)
        }
        other => other,
    }
}

/// Like [`unmarshal`], with options changing v1 behaviour, as in
/// `jsonv2.Unmarshal(data, json.DefaultOptionsV1(), options...)`.
pub fn unmarshal_with_options<T: Deserialize>(data: &[u8], options: Options) -> Result<T, Error> {
    unmarshal_with(data, DecodeState::with_options(options))
}

/// Like [`unmarshal_with_number`], with objects in the order of the text.
pub(crate) fn unmarshal_value_ordered(data: &[u8]) -> Result<Value, Error> {
    check_valid(data, &mut Scanner::new())?;
    let cx = DecodeState {
        use_number: true,
        ..DecodeState::default()
    };
    parse_node(data)?.to_value_ordered(&cx)
}

pub(crate) fn unmarshal_with_number(data: &[u8]) -> Result<Value, Error> {
    unmarshal_with(
        data,
        DecodeState {
            use_number: true,
            ..DecodeState::default()
        },
    )
}

// ---- struct support ---------------------------------------------------------

/// Struct types that can be built from an object's members; implemented by
/// `#[derive(Deserialize)]` and used for embedded structs.
pub trait DeserializeFields: Sized {
    /// Registers every field in declaration order.
    fn json_fields(fields: &mut FieldList);
    /// Builds the struct, taking each field's value from `b` in the order the
    /// fields were registered.
    fn json_build(b: &mut Builder<'_, '_>) -> Result<Self, Error>;
    /// Decodes into an existing struct: the fields the input names are
    /// decoded into, the others are kept. The default rebuilds the struct;
    /// the derive implements the field-wise merge.
    fn json_merge(&mut self, b: &mut Builder<'_, '_>) -> Result<(), Error> {
        *self = Self::json_build(b)?;
        Ok(())
    }
}

fn count_slots<T: DeserializeFields>() -> usize {
    let mut list = FieldList::new();
    T::json_fields(&mut list);
    list.slots()
}

impl<T: DeserializeFields> DeserializeFields for Option<T> {
    fn json_fields(fields: &mut FieldList) {
        T::json_fields(fields);
    }
    fn json_build(b: &mut Builder<'_, '_>) -> Result<Self, Error> {
        let n = count_slots::<T>();
        if b.any_filled(n) {
            T::json_build(b).map(Some)
        } else {
            b.next += n;
            Ok(None)
        }
    }
    fn json_merge(&mut self, b: &mut Builder<'_, '_>) -> Result<(), Error> {
        let n = count_slots::<T>();
        if !b.any_filled(n) {
            b.next += n;
            return Ok(());
        }
        match self {
            Some(inner) => inner.json_merge(b),
            None => {
                *self = Some(T::json_build(b)?);
                Ok(())
            }
        }
    }
}
impl<T: DeserializeFields> DeserializeFields for Box<T> {
    fn json_fields(fields: &mut FieldList) {
        T::json_fields(fields);
    }
    fn json_build(b: &mut Builder<'_, '_>) -> Result<Self, Error> {
        T::json_build(b).map(Box::new)
    }
    fn json_merge(&mut self, b: &mut Builder<'_, '_>) -> Result<(), Error> {
        (**self).json_merge(b)
    }
}

/// Hands the members found for a struct to its generated `json_build`.
pub struct Builder<'n, 'd> {
    /// The members found for each field, in document order.
    slots: Vec<Vec<(&'n Node<'d>, &'n str)>>,
    fields: Vec<Option<Field>>,
    next: usize,
    cx: &'n mut DecodeState,
    struct_name: &'static str,
    /// Type errors by the position of the value, as Go saves the first one
    /// and keeps decoding.
    errors: Vec<(usize, Error)>,
}

impl Builder<'_, '_> {
    fn any_filled(&self, n: usize) -> bool {
        self.slots[self.next..(self.next + n).min(self.slots.len())]
            .iter()
            .any(|members| !members.is_empty())
    }
    /// Decodes the next registered field as a `T`, or takes its zero value
    /// when the input had no member for it. A member that cannot be decoded
    /// is recorded and the field takes its zero value; the earliest such
    /// error in the document is returned once the struct is built.
    pub fn field<T: Deserialize>(&mut self, rust_name: &'static str) -> Result<T, Error> {
        let slot = self.next;
        self.next += 1;
        let members = self.slots.get(slot).cloned().unwrap_or_default();
        let Some(f) = self.fields.get(slot).and_then(Option::as_ref) else {
            return self.zero(rust_name);
        };
        let quotable = if self.cx.legacy_stringify {
            T::JSON_QUOTABLE
        } else {
            T::JSON_NUMBER
        };
        let quoted = f.string && quotable;
        let mut value = None;
        // A repeated member is decoded again, the last one winning.
        for (node, key) in members {
            let result = if quoted {
                T::unmarshal_quoted(node, self.cx)
            } else {
                T::unmarshal_json(node, self.cx)
            };
            match result {
                Ok(v) => value = Some(v),
                // Type errors are saved while decoding goes on; any other error
                // (such as one from an `Unmarshaler`) ends the decode.
                Err(e @ Error::UnmarshalType(_)) => self
                    .errors
                    .push((node.start, add_segment(e, &pointer_token(key)))),
                Err(e) => return Err(e),
            }
        }
        match value {
            Some(v) => Ok(v),
            None => self.zero(rust_name),
        }
    }
    /// Decodes the next registered field into `target`, leaving it unchanged
    /// when the input has no member for it or the member cannot be decoded
    /// (the error is saved, as in [`field`](Self::field)). A repeated member
    /// is decoded into the same value again.
    pub fn field_into<T: Deserialize>(&mut self, target: &mut T) -> Result<(), Error> {
        let slot = self.next;
        self.next += 1;
        let members = self.slots.get(slot).cloned().unwrap_or_default();
        let Some(f) = self.fields.get(slot).and_then(Option::as_ref) else {
            return Ok(());
        };
        let quotable = if self.cx.legacy_stringify {
            T::JSON_QUOTABLE
        } else {
            T::JSON_NUMBER
        };
        let quoted = f.string && quotable;
        for (node, key) in members {
            let result = if quoted {
                target.unmarshal_quoted_into(node, self.cx)
            } else {
                target.unmarshal_json_into(node, self.cx)
            };
            match result {
                Ok(()) => {}
                Err(e @ Error::UnmarshalType(_)) => self
                    .errors
                    .push((node.start, add_segment(e, &pointer_token(key)))),
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    fn zero<T: Deserialize>(&mut self, rust_name: &'static str) -> Result<T, Error> {
        T::json_zero().map_err(|_| {
            // Without a zero value the earliest recorded error ends the decode.
            match self.earliest_error() {
                Some(e) => e,
                None => Error::Other(format!(
                    "json: no value and no zero value for field {rust_name} of {}",
                    self.struct_name
                )),
            }
        })
    }
    fn earliest_error(&mut self) -> Option<Error> {
        let at = (0..self.errors.len()).min_by_key(|i| self.errors[*i].0)?;
        Some(self.errors.remove(at).1)
    }
    /// Builds an embedded struct whose fields were promoted into this one.
    pub fn embedded<E: DeserializeFields>(&mut self) -> Result<E, Error> {
        E::json_build(self)
    }
    /// Decodes into an embedded struct whose fields were promoted into this one.
    pub fn embedded_into<E: DeserializeFields>(&mut self, target: &mut E) -> Result<(), Error> {
        target.json_merge(self)
    }
}

/// Prefixes the field of an `UnmarshalTypeError` that came from a type's own
/// `UnmarshalJSON` (`json.Number`, or any [`Unmarshaler`]). Go returns such an
/// error as the method made it, so the enclosing values add no path to it.
const PATHLESS: &str = "\u{0}";

fn pathless(mut e: UnmarshalTypeError) -> Error {
    e.field = PATHLESS.into();
    e.offset = 0;
    Error::UnmarshalType(e)
}

/// Prefixes a path segment (a field name, map key or index, already
/// pointer-escaped) onto the type error that bubbled up from that value.
/// While an error travels up, `field` holds a JSON Pointer; [`unmarshal`]
/// converts it to Go's dotted form.
fn add_segment(e: Error, segment: &str) -> Error {
    match e {
        // Errors raised inside a custom decoder carry no position (see
        // `pathless`).
        Error::UnmarshalType(t) if t.field.starts_with(PATHLESS) => Error::UnmarshalType(t),
        Error::UnmarshalType(mut t) => {
            t.field = format!("/{segment}{}", t.field);
            Error::UnmarshalType(t)
        }
        other => other,
    }
}

/// Decodes from a dynamic [`Value`] by way of its encoding. Used by the derive
/// for `Deserialize::from_json`.
pub fn deserialize_from_value<T: Deserialize>(v: &Value) -> Result<T, Error> {
    let mut s = super::Serializer::new(false);
    s.write_value(v)?;
    unmarshal(s.as_bytes())
}

/// The zero value of a struct: every field takes its zero value.
pub fn zero_struct<T: DeserializeFields>(struct_name: &'static str) -> Result<T, Error> {
    let node = parse_node(b"null")?;
    deserialize_struct(&node, &mut DecodeState::default(), struct_name)
}

/// Decodes a JSON object into a struct described by [`DeserializeFields`].
pub fn deserialize_struct<T: DeserializeFields>(
    node: &Node<'_>,
    cx: &mut DecodeState,
    struct_name: &'static str,
) -> Result<T, Error> {
    with_builder::<T, T>(node, cx, struct_name, T::json_build)
}

/// Decodes a JSON object into the fields of an existing struct, keeping the
/// fields the object does not name. JSON `null` changes nothing.
pub fn merge_struct<T: DeserializeFields>(
    target: &mut T,
    node: &Node<'_>,
    cx: &mut DecodeState,
    struct_name: &'static str,
) -> Result<(), Error> {
    if node.is_null() {
        return Ok(());
    }
    with_builder::<T, ()>(node, cx, struct_name, |b| target.json_merge(b))
}

/// Sorts the members of `node` into the fields of `T` and runs `run` on the
/// resulting [`Builder`], returning the earliest saved error if there is one.
fn with_builder<T: DeserializeFields, R>(
    node: &Node<'_>,
    cx: &mut DecodeState,
    struct_name: &'static str,
    run: impl FnOnce(&mut Builder<'_, '_>) -> Result<R, Error>,
) -> Result<R, Error> {
    let mut list = FieldList::new();
    T::json_fields(&mut list);
    let n = list.slots();
    let resolved = resolve(list);
    let mut slots: Vec<Vec<(&Node<'_>, &str)>> = vec![Vec::new(); n];
    let mut fields: Vec<Option<Field>> = vec![None; n];
    let mut errors: Vec<(usize, Error)> = Vec::new();
    match &node.kind {
        Kind::Null => {}
        Kind::Object(members) => {
            for f in &resolved.fields {
                fields[f.slot] = Some(f.clone());
            }
            for m in members {
                match resolved.lookup(&m.key, cx.case_sensitive_delimiter) {
                    Some(f) => slots[f.slot].push((&m.value, m.key.as_str())),
                    None if cx.disallow_unknown_fields => errors.push((
                        m.key_start,
                        Error::Other(format!("json: unknown field {}", quote(&m.key))),
                    )),
                    None => {}
                }
            }
        }
        _ => return Err(node.type_error(struct_name)),
    }
    let mut b = Builder {
        slots,
        fields,
        next: 0,
        cx,
        struct_name,
        errors,
    };
    let built = run(&mut b);
    match (built, b.earliest_error()) {
        (Ok(v), None) => Ok(v),
        (_, Some(e)) | (Err(e), None) => Err(e),
    }
}

// ---- Deserialize for standard types ----------------------------------------

impl Deserialize for Value {
    fn from_json(v: &Value) -> Result<Self, Error> {
        Ok(v.clone())
    }
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        node.to_value(cx)
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(Value::Null)
    }
    fn json_type_name() -> String {
        "interface {}".into()
    }
}

impl Deserialize for String {
    fn from_json(v: &Value) -> Result<Self, Error> {
        v.as_str()
            .map(str::to_owned)
            .ok_or(Error::Type("expected string"))
    }
    fn unmarshal_json(node: &Node<'_>, _: &mut DecodeState) -> Result<Self, Error> {
        match &node.kind {
            Kind::String(s) => Ok(s.clone()),
            Kind::Null => Ok(String::new()),
            _ => Err(node.type_error("string")),
        }
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(String::new())
    }
    const JSON_QUOTABLE: bool = true;
    fn unmarshal_quoted(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        unmarshal_quoted_with(node, cx, Quoted::String)
    }
    fn json_type_name() -> String {
        "string".into()
    }
}

impl Deserialize for bool {
    fn from_json(v: &Value) -> Result<Self, Error> {
        match v {
            Value::Bool(b) => Ok(*b),
            _ => Err(Error::Type("expected boolean")),
        }
    }
    fn unmarshal_json(node: &Node<'_>, _: &mut DecodeState) -> Result<Self, Error> {
        match &node.kind {
            Kind::Bool(b) => Ok(*b),
            Kind::Null => Ok(false),
            _ => Err(node.type_error("bool")),
        }
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(false)
    }
    const JSON_QUOTABLE: bool = true;
    fn unmarshal_quoted(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        unmarshal_quoted_with(node, cx, Quoted::Bool)
    }
    fn json_type_name() -> String {
        "bool".into()
    }
}

macro_rules! integer_deserialize {
    ($($t:ty => $name:expr),+ $(,)?) => { $(
        impl Deserialize for $t {
            fn from_json(v: &Value) -> Result<Self, Error> {
                v.as_number()
                    .ok_or(Error::Type("expected integer"))?
                    .as_str()
                    .parse()
                    .map_err(|_| Error::Type("integer out of range or non-integral representation"))
            }
            fn unmarshal_json(node: &Node<'_>, _: &mut DecodeState) -> Result<Self, Error> {
                match &node.kind {
                    Kind::Number => {
                        let text = String::from_utf8_lossy(node.raw());
                        text.parse::<$t>().map_err(|_| {
                            node.type_error_value(format!("number {text}"), $name)
                        })
                    }
                    Kind::Null => Ok(0),
                    _ => Err(node.type_error($name)),
                }
            }
            fn json_zero() -> Result<Self, Error> { Ok(0) }
            const JSON_QUOTABLE: bool = true;
            const JSON_NUMBER: bool = true;
            fn unmarshal_quoted(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
                unmarshal_quoted_with(node, cx, Quoted::Number)
            }
            fn json_type_name() -> String { $name.into() }
        }
    )+ };
}
integer_deserialize!(
    i8 => "int8", i16 => "int16", i32 => "int32", i64 => "int64", i128 => "int128",
    isize => "int", u8 => "uint8", u16 => "uint16", u32 => "uint32", u64 => "uint64",
    u128 => "uint128", usize => "uint"
);

macro_rules! float_deserialize {
    ($($t:ty => $name:expr),+ $(,)?) => { $(
        impl Deserialize for $t {
            fn from_json(v: &Value) -> Result<Self, Error> {
                let n = v
                    .as_number()
                    .ok_or(Error::Type("expected number"))?
                    .as_str()
                    .parse::<$t>()
                    .map_err(|_| Error::Type("expected representable float"))?;
                if !n.is_finite() {
                    return Err(Error::Type("nonfinite float"));
                }
                Ok(n)
            }
            fn unmarshal_json(node: &Node<'_>, _: &mut DecodeState) -> Result<Self, Error> {
                match &node.kind {
                    Kind::Number => {
                        let text = String::from_utf8_lossy(node.raw());
                        match text.parse::<$t>() {
                            Ok(f) if f.is_finite() => Ok(f),
                            _ => Err(node.type_error_value(format!("number {text}"), $name)),
                        }
                    }
                    Kind::Null => Ok(0.0),
                    _ => Err(node.type_error($name)),
                }
            }
            fn json_zero() -> Result<Self, Error> { Ok(0.0) }
            const JSON_QUOTABLE: bool = true;
            const JSON_NUMBER: bool = true;
            fn unmarshal_quoted(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
                unmarshal_quoted_with(node, cx, Quoted::Number)
            }
            fn json_type_name() -> String { $name.into() }
        }
    )+ };
}
float_deserialize!(f32 => "float32", f64 => "float64");

impl Deserialize for Number {
    fn from_json(value: &Value) -> Result<Self, Error> {
        value
            .as_number()
            .cloned()
            .ok_or(Error::Type("expected number"))
    }
    fn unmarshal_json(node: &Node<'_>, _: &mut DecodeState) -> Result<Self, Error> {
        match &node.kind {
            Kind::Number => Ok(Number(String::from_utf8_lossy(node.raw()).into_owned())),
            Kind::String(s) => {
                if is_valid_number(s) {
                    Ok(Number(s.clone()))
                } else {
                    Err(pathless(UnmarshalTypeError {
                        value: format!("string {}", String::from_utf8_lossy(node.raw())),
                        type_name: "json.Number".into(),
                        err: Some("invalid syntax".into()),
                        ..UnmarshalTypeError::default()
                    }))
                }
            }
            Kind::Null => Ok(Number(String::new())),
            _ => Err(pathless(UnmarshalTypeError {
                value: node.describe().into(),
                type_name: "json.Number".into(),
                ..UnmarshalTypeError::default()
            })),
        }
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(Number(String::new()))
    }
    const JSON_QUOTABLE: bool = true;
    const JSON_NUMBER: bool = true;
    fn unmarshal_quoted(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        unmarshal_quoted_with(node, cx, Quoted::Number)
    }
    fn json_type_name() -> String {
        "json.Number".into()
    }
}

impl Deserialize for RawMessage {
    fn from_json(value: &Value) -> Result<Self, Error> {
        super::marshal(value).map(RawMessage)
    }
    fn unmarshal_json(node: &Node<'_>, _: &mut DecodeState) -> Result<Self, Error> {
        Ok(RawMessage(node.raw().to_vec()))
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(RawMessage::default())
    }
    fn json_type_name() -> String {
        "json.RawMessage".into()
    }
}
impl Unmarshaler for RawMessage {
    fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), Error> {
        self.0.clear();
        self.0.extend_from_slice(data);
        Ok(())
    }
}

impl Deserialize for Bytes {
    fn from_json(value: &Value) -> Result<Self, Error> {
        match value {
            Value::String(s) => decode_base64(s).map_err(|e| Error::Other(e.to_string())),
            _ => Err(Error::Type("expected base64 string")),
        }
    }
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        match &node.kind {
            Kind::String(s) => {
                let bytes = decode_base64(s).map_err(|offset| {
                    Error::UnmarshalType(UnmarshalTypeError {
                        value: "string".into(),
                        type_name: "[]uint8".into(),
                        offset: node.error_offset(),
                        err: Some(format!("illegal base64 data at input byte {offset}").into()),
                        ..UnmarshalTypeError::default()
                    })
                })?;
                if !cx.loose_base64 {
                    // Go's base64 decoder skips line breaks; strict RFC 4648
                    // text must not contain them.
                    if let Some(i) = s.find(['\r', '\n']) {
                        let c = if s.as_bytes()[i] == b'\r' {
                            "\\r"
                        } else {
                            "\\n"
                        };
                        return Err(Error::UnmarshalType(UnmarshalTypeError {
                            value: "string".into(),
                            type_name: "[]uint8".into(),
                            offset: node.error_offset(),
                            err: Some(format!("illegal character '{c}' at offset {i}").into()),
                            ..UnmarshalTypeError::default()
                        }));
                    }
                }
                Ok(bytes)
            }
            Kind::Null => Ok(Bytes::default()),
            Kind::Array(_) if !cx.legacy_bytes => Err(node.type_error("[]uint8")),
            Kind::Array(items) => items
                .iter()
                .enumerate()
                .map(|(i, n)| u8::unmarshal_json(n, cx).map_err(|e| add_segment(e, &i.to_string())))
                .collect::<Result<Vec<_>, _>>()
                .map(Bytes),
            _ => Err(node.type_error("[]uint8")),
        }
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(Bytes::default())
    }
    fn json_type_name() -> String {
        "[]uint8".into()
    }
}
/// Decodes standard base64 as Go does; the error is the offset Go reports.
fn decode_base64(s: &str) -> Result<Bytes, usize> {
    super::super::base64::STANDARD
        .decode(s)
        .map(Bytes)
        .map_err(|e| e.offset())
}

impl<T: Deserialize> Deserialize for Vec<T> {
    fn from_json(v: &Value) -> Result<Self, Error> {
        v.as_array()
            .ok_or(Error::Type("expected array"))?
            .iter()
            .map(T::from_json)
            .collect()
    }
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        match &node.kind {
            Kind::Array(items) => items
                .iter()
                .enumerate()
                .map(|(i, n)| T::unmarshal_json(n, cx).map_err(|e| add_segment(e, &i.to_string())))
                .collect(),
            Kind::Null => Ok(Vec::new()),
            _ => Err(node.type_error(Self::json_type_name())),
        }
    }
    /// As in Go, the elements already in the vector are decoded into again
    /// (so structs merge), the vector takes the length of the JSON array and
    /// `null` empties it. A type error is returned after the other elements are decoded.
    fn unmarshal_json_into(&mut self, node: &Node<'_>, cx: &mut DecodeState) -> Result<(), Error> {
        let items = match &node.kind {
            Kind::Array(items) => items,
            Kind::Null => {
                self.clear();
                return Ok(());
            }
            _ => return Err(node.type_error(Self::json_type_name())),
        };
        // Like Go, remember the first type error and keep decoding: the
        // elements that fail keep their old value (or the zero value).
        let mut saved: Option<Error> = None;
        for (i, n) in items.iter().enumerate() {
            let result = match self.get_mut(i) {
                Some(e) => e.unmarshal_json_into(n, cx),
                None => match T::unmarshal_json(n, cx) {
                    Ok(v) => {
                        self.push(v);
                        Ok(())
                    }
                    Err(e) => {
                        match T::json_zero() {
                            Ok(zero) => self.push(zero),
                            Err(_) => return Err(add_segment(e, &i.to_string())),
                        }
                        Err(e)
                    }
                },
            };
            match result {
                Ok(()) => {}
                Err(e @ Error::UnmarshalType(_)) => {
                    saved.get_or_insert(add_segment(e, &i.to_string()));
                }
                Err(e) => return Err(add_segment(e, &i.to_string())),
            }
        }
        self.truncate(items.len());
        saved.map_or(Ok(()), Err)
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(Vec::new())
    }
    fn json_type_name() -> String {
        format!("[]{}", T::json_type_name())
    }
}

/// Go's length check for arrays under `UnmarshalArrayFromAnyLength(false)`.
fn check_array_len(
    node: &Node<'_>,
    cx: &DecodeState,
    len: usize,
    n: usize,
    type_name: String,
) -> Result<(), Error> {
    if cx.array_from_any_length || len == n {
        return Ok(());
    }
    let why = if len > n {
        "too many array elements"
    } else {
        "too few array elements"
    };
    Err(Error::UnmarshalType(UnmarshalTypeError {
        value: "array".into(),
        type_name,
        offset: node.end as i64,
        err: Some(why.into()),
        ..UnmarshalTypeError::default()
    }))
}

impl<T: Deserialize, const N: usize> Deserialize for [T; N] {
    fn from_json(value: &Value) -> Result<Self, Error> {
        let elements = value.as_array().ok_or(Error::Type("expected array"))?;
        if elements.len() != N {
            return Err(Error::Type("array length mismatch"));
        }
        elements
            .iter()
            .map(T::from_json)
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Type("array length mismatch"))
    }
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        let items = match &node.kind {
            Kind::Array(items) => items.as_slice(),
            Kind::Null => &[],
            _ => return Err(node.type_error(Self::json_type_name())),
        };
        if !node.is_null() {
            check_array_len(node, cx, items.len(), N, Self::json_type_name())?;
        }
        // Go ignores extra elements and zeroes the rest.
        let mut out = Vec::with_capacity(N);
        for i in 0..N {
            out.push(match items.get(i) {
                Some(n) => T::unmarshal_json(n, cx).map_err(|e| add_segment(e, &i.to_string()))?,
                None => T::json_zero()?,
            });
        }
        out.try_into().map_err(|_| malformed())
    }
    /// Go decodes into the elements in place and zeroes the ones the JSON
    /// array leaves out; `null` changes nothing.
    fn unmarshal_json_into(&mut self, node: &Node<'_>, cx: &mut DecodeState) -> Result<(), Error> {
        let items = match &node.kind {
            Kind::Array(items) => items.as_slice(),
            Kind::Null => return Ok(()),
            _ => return Err(node.type_error(Self::json_type_name())),
        };
        check_array_len(node, cx, items.len(), N, Self::json_type_name())?;
        for (i, slot) in self.iter_mut().enumerate() {
            match items.get(i) {
                Some(n) => slot
                    .unmarshal_json_into(n, cx)
                    .map_err(|e| add_segment(e, &i.to_string()))?,
                None => *slot = T::json_zero()?,
            }
        }
        Ok(())
    }
    fn json_zero() -> Result<Self, Error> {
        (0..N)
            .map(|_| T::json_zero())
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| malformed())
    }
    fn json_type_name() -> String {
        format!("[{N}]{}", T::json_type_name())
    }
}

impl<T: Deserialize> Deserialize for Option<T> {
    fn from_json(v: &Value) -> Result<Self, Error> {
        if *v == Value::Null {
            Ok(None)
        } else {
            T::from_json(v).map(Some)
        }
    }
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        if node.is_null() {
            Ok(None)
        } else {
            T::unmarshal_json(node, cx).map(Some)
        }
    }
    /// Go decodes into the value a non-nil pointer points to; `null` sets the
    /// pointer to nil.
    fn unmarshal_json_into(&mut self, node: &Node<'_>, cx: &mut DecodeState) -> Result<(), Error> {
        if node.is_null() {
            *self = None;
            return Ok(());
        }
        match self {
            Some(inner) => inner.unmarshal_json_into(node, cx),
            None => {
                *self = Some(T::unmarshal_json(node, cx)?);
                Ok(())
            }
        }
    }
    fn unmarshal_quoted_into(
        &mut self,
        node: &Node<'_>,
        cx: &mut DecodeState,
    ) -> Result<(), Error> {
        if node.is_null() {
            *self = None;
            return Ok(());
        }
        match self {
            Some(inner) => inner.unmarshal_quoted_into(node, cx),
            None => {
                *self = Some(T::unmarshal_quoted(node, cx)?);
                Ok(())
            }
        }
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(None)
    }
    const JSON_QUOTABLE: bool = T::JSON_QUOTABLE;
    const JSON_NUMBER: bool = T::JSON_NUMBER;
    fn unmarshal_quoted(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        if node.is_null() {
            Ok(None)
        } else {
            T::unmarshal_quoted(node, cx).map(Some)
        }
    }
    fn json_type_name() -> String {
        format!("*{}", T::json_type_name())
    }
}

impl<T: Deserialize> Deserialize for Box<T> {
    fn from_json(value: &Value) -> Result<Self, Error> {
        T::from_json(value).map(Box::new)
    }
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        T::unmarshal_json(node, cx).map(Box::new)
    }
    fn unmarshal_json_into(&mut self, node: &Node<'_>, cx: &mut DecodeState) -> Result<(), Error> {
        (**self).unmarshal_json_into(node, cx)
    }
    fn unmarshal_quoted_into(
        &mut self,
        node: &Node<'_>,
        cx: &mut DecodeState,
    ) -> Result<(), Error> {
        (**self).unmarshal_quoted_into(node, cx)
    }
    fn json_zero() -> Result<Self, Error> {
        T::json_zero().map(Box::new)
    }
    const JSON_QUOTABLE: bool = T::JSON_QUOTABLE;
    const JSON_NUMBER: bool = T::JSON_NUMBER;
    fn unmarshal_quoted(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        T::unmarshal_quoted(node, cx).map(Box::new)
    }
    fn json_type_name() -> String {
        T::json_type_name()
    }
}

/// Decodes an object's members for a map, checking each key.
fn decode_entries<K: MapKey, V: Deserialize>(
    node: &Node<'_>,
    cx: &mut DecodeState,
    type_name: String,
    mut insert: impl FnMut(K, V),
) -> Result<(), Error> {
    match &node.kind {
        Kind::Object(members) => {
            for m in members {
                let Some(key) = K::from_key(&m.key) else {
                    return Err(add_segment(
                        Error::UnmarshalType(UnmarshalTypeError {
                            value: format!("number {}", m.key),
                            type_name: K::key_type_name().into(),
                            offset: m.key_end as i64,
                            ..UnmarshalTypeError::default()
                        }),
                        &pointer_token(&m.key),
                    ));
                };
                let v = V::unmarshal_json(&m.value, cx)
                    .map_err(|e| add_segment(e, &pointer_token(&m.key)))?;
                insert(key, v);
            }
            Ok(())
        }
        Kind::Null => Ok(()),
        _ => Err(node.type_error(type_name)),
    }
}

impl<K: MapKey + Ord, V: Deserialize> Deserialize for BTreeMap<K, V> {
    fn from_json(v: &Value) -> Result<Self, Error> {
        let Value::Object(fields) = v else {
            return Err(Error::Type("expected object"));
        };
        fields
            .iter()
            .map(|(k, v)| {
                Ok((
                    K::from_key(k).ok_or(Error::Type("invalid map key"))?,
                    V::from_json(v)?,
                ))
            })
            .collect()
    }
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        let mut map = BTreeMap::new();
        decode_entries(node, cx, Self::json_type_name(), |k, v| {
            map.insert(k, v);
        })?;
        Ok(map)
    }
    /// Go keeps the entries already in the map and sets or replaces the ones
    /// the object names, each decoded into a fresh value; `null` empties it.
    fn unmarshal_json_into(&mut self, node: &Node<'_>, cx: &mut DecodeState) -> Result<(), Error> {
        if node.is_null() {
            self.clear();
            return Ok(());
        }
        decode_entries(node, cx, Self::json_type_name(), |k, v| {
            self.insert(k, v);
        })
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(BTreeMap::new())
    }
    fn json_type_name() -> String {
        format!("map[{}]{}", K::key_type_name(), V::json_type_name())
    }
}

impl<K: MapKey + Eq + std::hash::Hash, V: Deserialize> Deserialize for HashMap<K, V> {
    fn from_json(v: &Value) -> Result<Self, Error> {
        let Value::Object(fields) = v else {
            return Err(Error::Type("expected object"));
        };
        fields
            .iter()
            .map(|(k, v)| {
                Ok((
                    K::from_key(k).ok_or(Error::Type("invalid map key"))?,
                    V::from_json(v)?,
                ))
            })
            .collect()
    }
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        let mut map = HashMap::new();
        decode_entries(node, cx, Self::json_type_name(), |k, v| {
            map.insert(k, v);
        })?;
        Ok(map)
    }
    /// Go keeps the entries already in the map and sets or replaces the ones
    /// the object names, each decoded into a fresh value; `null` empties it.
    fn unmarshal_json_into(&mut self, node: &Node<'_>, cx: &mut DecodeState) -> Result<(), Error> {
        if node.is_null() {
            self.clear();
            return Ok(());
        }
        decode_entries(node, cx, Self::json_type_name(), |k, v| {
            self.insert(k, v);
        })
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(HashMap::new())
    }
    fn json_type_name() -> String {
        format!("map[{}]{}", K::key_type_name(), V::json_type_name())
    }
}

/// Durations decode from a number of nanoseconds, as Go's `time.Duration`
/// does; negative durations have no `std::time::Duration`.
impl Deserialize for std::time::Duration {
    fn from_json(v: &Value) -> Result<Self, Error> {
        u64::from_json(v).map(std::time::Duration::from_nanos)
    }
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        if !cx.duration_nano {
            // The v2 default has no JSON form for a duration.
            return Err(Error::UnmarshalType(UnmarshalTypeError {
                value: node.describe().to_string(),
                type_name: Self::json_type_name(),
                offset: node.error_offset(),
                err: Some("no default representation".into()),
                ..UnmarshalTypeError::default()
            }));
        }
        match &node.kind {
            Kind::Number => {
                let text = String::from_utf8_lossy(node.raw());
                text.parse::<u64>()
                    .map(std::time::Duration::from_nanos)
                    .map_err(|_| {
                        node.type_error_value(format!("number {text}"), Self::json_type_name())
                    })
            }
            Kind::Null => Ok(std::time::Duration::ZERO),
            _ => Err(node.type_error(Self::json_type_name())),
        }
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(std::time::Duration::ZERO)
    }
    const JSON_QUOTABLE: bool = true;
    const JSON_NUMBER: bool = true;
    fn unmarshal_quoted(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        unmarshal_quoted_with(node, cx, Quoted::Number)
    }
    fn json_type_name() -> String {
        "time.Duration".into()
    }
}

/// Durations decode from a number of nanoseconds, as Go's `time.Duration`
/// does; unlike `std::time::Duration` this one may be negative.
impl Deserialize for crate::time::Duration {
    fn from_json(v: &Value) -> Result<Self, Error> {
        i64::from_json(v).map(crate::time::Duration::from_nanos)
    }
    fn unmarshal_json(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        if !cx.duration_nano {
            // The v2 default has no JSON form for a duration.
            return Err(Error::UnmarshalType(UnmarshalTypeError {
                value: node.describe().to_string(),
                type_name: Self::json_type_name(),
                offset: node.error_offset(),
                err: Some("no default representation".into()),
                ..UnmarshalTypeError::default()
            }));
        }
        match &node.kind {
            Kind::Number => {
                let text = String::from_utf8_lossy(node.raw());
                text.parse::<i64>()
                    .map(crate::time::Duration::from_nanos)
                    .map_err(|_| {
                        node.type_error_value(format!("number {text}"), Self::json_type_name())
                    })
            }
            Kind::Null => Ok(crate::time::Duration::from_nanos(0)),
            _ => Err(node.type_error(Self::json_type_name())),
        }
    }
    fn json_zero() -> Result<Self, Error> {
        Ok(crate::time::Duration::from_nanos(0))
    }
    const JSON_QUOTABLE: bool = true;
    const JSON_NUMBER: bool = true;
    fn unmarshal_quoted(node: &Node<'_>, cx: &mut DecodeState) -> Result<Self, Error> {
        unmarshal_quoted_with(node, cx, Quoted::Number)
    }
    fn json_type_name() -> String {
        "time.Duration".into()
    }
}
