//! Go's JSON encoder: `Marshal`, `MarshalIndent`, `Marshaler`, `RawMessage`
//! and the `Serialize` implementations for the standard types.
//!
//! Output is byte-identical to Go's: struct fields in declaration order,
//! map keys sorted, Go's float formatting, invalid UTF-8 replaced with
//! U+FFFD and HTML escaping by default.
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
};

use super::{
    default_options_v1,
    errors::quote,
    fields::{resolve, Field, FieldList},
    indent::{append_compact, append_indent},
    options::Flag,
    Error, Map, MarshalerError, Number, Options, UnsupportedValueError, Value,
};

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Implemented by types that can encode themselves as JSON.
///
/// `to_json` is the dynamic form; `serialize` writes straight to a
/// [`Serializer`] and is what [`marshal`] uses. The derive macro implements
/// both; hand-written types may implement only `to_json`.
pub trait Serialize {
    fn to_json(&self) -> Result<Value, Error>;
    /// Writes the JSON encoding of `self`.
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        s.write_value(&self.to_json()?)
    }
    /// Writes the encoding used for a field with the `string` tag option:
    /// numbers, booleans and strings are wrapped in a JSON string. Other
    /// types ignore the option, as in Go.
    fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
        self.serialize(s)
    }
    /// Go's "empty" value for `omitempty`: false, 0, `None`, and empty
    /// arrays, maps, slices and strings.
    fn is_empty_value(&self) -> bool {
        false
    }
    /// Whether the value is represented as a JSON number (numbers and
    /// `Number`), which is what the `string` option quotes under Go's v2
    /// rules.
    fn is_json_number(&self) -> bool {
        false
    }
    /// Go's "zero" value for `omitzero`. Types with a custom `IsZero` method
    /// in Go implement this.
    fn is_zero_value(&self) -> bool {
        false
    }
}

/// Implemented by types that produce their own JSON text (Go's
/// `json.Marshaler`). Use [`Serializer::marshaler`] from `Serialize::serialize`.
pub trait Marshaler {
    fn marshal_json(&self) -> Result<Vec<u8>, Error>;
}

/// Struct types whose fields can be serialized one by one; implemented by
/// `#[derive(Serialize)]` and used for embedded structs.
pub trait SerializeFields {
    /// Registers every field in declaration order.
    fn json_fields(fields: &mut FieldList);
    /// Writes the field `f`, found by following `index` through embedded
    /// structs.
    fn json_emit(&self, w: &mut ObjectWriter<'_>, f: &Field, index: &[usize]) -> Result<(), Error>;
}

impl<T: SerializeFields> SerializeFields for Option<T> {
    fn json_fields(fields: &mut FieldList) {
        T::json_fields(fields);
    }
    fn json_emit(&self, w: &mut ObjectWriter<'_>, f: &Field, index: &[usize]) -> Result<(), Error> {
        match self {
            Some(v) => v.json_emit(w, f, index),
            None => Ok(()),
        }
    }
}
impl<T: SerializeFields + ?Sized> SerializeFields for Box<T> {
    fn json_fields(fields: &mut FieldList) {
        T::json_fields(fields);
    }
    fn json_emit(&self, w: &mut ObjectWriter<'_>, f: &Field, index: &[usize]) -> Result<(), Error> {
        (**self).json_emit(w, f, index)
    }
}

/// Writes the JSON object for a struct whose fields are described by
/// [`SerializeFields`].
pub fn serialize_struct<T: SerializeFields + ?Sized>(
    v: &T,
    s: &mut Serializer,
) -> Result<(), Error> {
    let mut list = FieldList::new();
    T::json_fields(&mut list);
    let resolved = resolve(list);
    let mut w = s.object();
    for f in &resolved.fields {
        v.json_emit(&mut w, f, &f.index)?;
    }
    w.finish();
    Ok(())
}

/// The dynamic form of a value: its encoding parsed back into a [`Value`]
/// with number text preserved. Used by the derive for `Serialize::to_json`.
pub fn serialize_to_value<T: Serialize + ?Sized>(v: &T) -> Result<Value, Error> {
    let mut s = Serializer::new(false);
    v.serialize(&mut s)?;
    super::decode::unmarshal_value_ordered(s.as_bytes())
}

/// Accumulates JSON output.
pub struct Serializer {
    out: Vec<u8>,
    escape_html: bool,
    legacy_omit_empty: bool,
    legacy_stringify: bool,
    /// `std::time::Duration` encodes as nanoseconds; when off it has no
    /// representation.
    duration_nano: bool,
    /// Output position of `out[0]`, for errors found while encoding a field
    /// ahead of time.
    base: usize,
}

impl Default for Serializer {
    fn default() -> Self {
        Self::new(true)
    }
}

impl Serializer {
    /// `escape_html` escapes `<`, `>` and `&` in strings, as `Marshal` does.
    pub fn new(escape_html: bool) -> Self {
        Self {
            out: Vec::new(),
            escape_html,
            legacy_omit_empty: true,
            legacy_stringify: true,
            duration_nano: true,
            base: 0,
        }
    }
    /// Applies the settings of `options` that change encoding.
    pub fn set_options(&mut self, options: Options) {
        let options = default_options_v1().join(options);
        self.legacy_omit_empty = options.get(Flag::OmitEmptyWithLegacySemantics) != Some(false);
        self.legacy_stringify = options.get(Flag::StringifyWithLegacySemantics) != Some(false);
        self.duration_nano = options.get(Flag::FormatDurationAsNano) != Some(false);
    }
    /// An empty serializer with the same settings whose output will land at
    /// position `at`.
    fn scratch_at(&self, at: usize) -> Serializer {
        Serializer {
            out: Vec::new(),
            base: at,
            ..*self
        }
    }
    pub fn escape_html(&self) -> bool {
        self.escape_html
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.out
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }
    /// Appends already-encoded JSON.
    pub fn write_raw(&mut self, raw: &[u8]) {
        self.out.extend_from_slice(raw);
    }
    pub fn write_null(&mut self) {
        self.out.extend_from_slice(b"null");
    }
    /// Writes a number or boolean literal, wrapped in quotes when `quoted`.
    pub fn write_literal(&mut self, text: &str, quoted: bool) {
        if quoted {
            self.out.push(b'"');
        }
        self.out.extend_from_slice(text.as_bytes());
        if quoted {
            self.out.push(b'"');
        }
    }
    /// Writes a float as Go's encoder does; `bits` is 32 or 64.
    pub fn write_float(&mut self, f: f64, bits: u32, quoted: bool) -> Result<(), Error> {
        if !f.is_finite() {
            return Err(UnsupportedValueError {
                value: format!("{f}"),
                str: go_float_g(f),
            }
            .into());
        }
        let text = format_float(f, bits);
        self.write_literal(&text, quoted);
        Ok(())
    }
    /// Writes a string; with `quoted` the quoted form is quoted again, which
    /// is what the `string` tag option does to strings.
    pub fn write_string(&mut self, s: &str, quoted: bool) {
        self.write_string_bytes(s.as_bytes(), quoted);
    }
    /// Like [`write_string`](Self::write_string) for arbitrary bytes; invalid
    /// UTF-8 is replaced with `�`.
    pub fn write_string_bytes(&mut self, s: &[u8], quoted: bool) {
        if quoted {
            let mut inner = Vec::new();
            append_string(&mut inner, s, self.escape_html);
            append_string(&mut self.out, &inner, false);
        } else {
            append_string(&mut self.out, s, self.escape_html);
        }
    }
    /// Writes a [`Number`] (empty is 0).
    pub fn write_number(&mut self, n: &Number, quoted: bool) -> Result<(), Error> {
        let text = if n.0.is_empty() { "0" } else { n.0.as_str() };
        self.write_literal(text, quoted);
        Ok(())
    }
    /// Writes a dynamic [`Value`]; object members come out in insertion order.
    pub fn write_value(&mut self, v: &Value) -> Result<(), Error> {
        match v {
            Value::Null => self.write_null(),
            Value::Bool(b) => self.write_literal(if *b { "true" } else { "false" }, false),
            Value::Number(n) => self.write_number(n, false)?,
            Value::String(s) => self.write_string(s, false),
            Value::Array(items) => {
                self.out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        self.out.push(b',');
                    }
                    self.write_value(item)?;
                }
                self.out.push(b']');
            }
            Value::Object(members) => {
                self.out.push(b'{');
                for (i, (k, item)) in members.iter().enumerate() {
                    if i > 0 {
                        self.out.push(b',');
                    }
                    self.write_string(k, false);
                    self.out.push(b':');
                    self.write_value(item)?;
                }
                self.out.push(b'}');
            }
        }
        Ok(())
    }
    /// Writes the output of a [`Marshaler`] the way Go does: the text must be
    /// valid JSON and is compacted (and HTML-escaped when enabled); failures
    /// are wrapped in a [`MarshalerError`] naming `type_name`.
    pub fn marshaler(
        &mut self,
        type_name: &str,
        result: Result<Vec<u8>, Error>,
    ) -> Result<(), Error> {
        let wrap = |e: Box<dyn std::error::Error + Send + Sync>| {
            // Go 1.27 names the pointer type, even for value receivers.
            Error::Marshaler(MarshalerError::new(format!("*{type_name}"), e))
        };
        let bytes = result.map_err(|e| wrap(Box::new(e)))?;
        let before = (self.base + self.out.len()) as i64;
        append_compact(&mut self.out, &bytes, self.escape_html).map_err(|mut e| {
            // Go reports the position within the whole output being written.
            e.offset += before;
            wrap(Box::new(e))
        })
    }
    /// Starts a JSON object.
    pub fn object(&mut self) -> ObjectWriter<'_> {
        ObjectWriter {
            s: self,
            first: true,
        }
    }
    /// Writes the elements of a sequence as a JSON array.
    pub fn write_array<'a, T, I>(&mut self, items: I) -> Result<(), Error>
    where
        T: Serialize + ?Sized + 'a,
        I: IntoIterator<Item = &'a T>,
    {
        self.out.push(b'[');
        for (i, item) in items.into_iter().enumerate() {
            if i > 0 {
                self.out.push(b',');
            }
            item.serialize(self)?;
        }
        self.out.push(b']');
        Ok(())
    }
}

/// Writes the members of a JSON object.
pub struct ObjectWriter<'a> {
    s: &'a mut Serializer,
    first: bool,
}

impl ObjectWriter<'_> {
    fn separator(&mut self) {
        self.s.out.push(if self.first { b'{' } else { b',' });
        self.first = false;
    }
    /// Writes a struct field, honouring its `omitempty`, `omitzero` and
    /// `string` options.
    pub fn field<T: Serialize + ?Sized>(&mut self, f: &Field, v: &T) -> Result<(), Error> {
        if f.omit_zero && v.is_zero_value() {
            return Ok(());
        }
        let legacy_omit = self.s.legacy_omit_empty;
        if f.omit_empty && legacy_omit && v.is_empty_value() {
            return Ok(());
        }
        let name_at = self.s.out.len();
        let was_first = self.first;
        self.separator();
        self.s.write_string(&f.name, false);
        self.s.out.push(b':');
        let direct = (legacy_omit || !f.omit_empty) && (!f.string || self.s.legacy_stringify);
        if direct {
            return if f.string {
                v.serialize_quoted(self.s)
            } else {
                v.serialize(self.s)
            };
        }
        // v2 decides from the finished encoding: `omitempty` omits an empty
        // JSON value and `string` quotes only numbers.
        let mut tmp = self.s.scratch_at(self.s.base + self.s.out.len());
        if !f.string {
            v.serialize(&mut tmp)?;
        } else if self.s.legacy_stringify {
            v.serialize_quoted(&mut tmp)?;
        } else {
            v.serialize(&mut tmp)?;
            if v.is_json_number() {
                tmp.out.insert(0, b'"');
                tmp.out.push(b'"');
            }
        }
        if f.omit_empty
            && !legacy_omit
            && matches!(tmp.out.as_slice(), b"null" | b"\"\"" | b"[]" | b"{}")
        {
            self.s.out.truncate(name_at);
            self.first = was_first;
            return Ok(());
        }
        self.s.out.extend_from_slice(&tmp.out);
        Ok(())
    }
    /// Writes a member with an arbitrary key (as for maps).
    pub fn member<T: Serialize + ?Sized>(&mut self, key: &str, v: &T) -> Result<(), Error> {
        self.separator();
        self.s.write_string(key, false);
        self.s.out.push(b':');
        v.serialize(self.s)
    }
    /// Ends the object.
    pub fn finish(self) {
        if self.first {
            self.s.out.extend_from_slice(b"{}");
        } else {
            self.s.out.push(b'}');
        }
    }
}

/// Go's `appendString`: quotes `src`, escaping control characters, `"` and
/// `\`; `<`, `>`, `&` when `escape_html`; U+2028 and U+2029; and replacing
/// invalid UTF-8 with `�`.
pub(crate) fn append_string(dst: &mut Vec<u8>, src: &[u8], escape_html: bool) {
    dst.push(b'"');
    let mut start = 0;
    let mut i = 0;
    while i < src.len() {
        let b = src[i];
        if b < 0x80 {
            let safe = b >= 0x20
                && b != b'"'
                && b != b'\\'
                && !(escape_html && (b == b'<' || b == b'>' || b == b'&'));
            if safe {
                i += 1;
                continue;
            }
            dst.extend_from_slice(&src[start..i]);
            match b {
                b'\\' | b'"' => dst.extend_from_slice(&[b'\\', b]),
                0x08 => dst.extend_from_slice(b"\\b"),
                0x0c => dst.extend_from_slice(b"\\f"),
                b'\n' => dst.extend_from_slice(b"\\n"),
                b'\r' => dst.extend_from_slice(b"\\r"),
                b'\t' => dst.extend_from_slice(b"\\t"),
                _ => dst.extend_from_slice(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[usize::from(b >> 4)],
                    HEX[usize::from(b & 0xf)],
                ]),
            }
            i += 1;
            start = i;
            continue;
        }
        let (r, size) = crate::unicode::rune::decode_rune(&src[i..]);
        if r == 0xFFFD && size == 1 {
            dst.extend_from_slice(&src[start..i]);
            dst.extend_from_slice(b"\\ufffd");
            i += 1;
            start = i;
            continue;
        }
        if r == 0x2028 || r == 0x2029 {
            dst.extend_from_slice(&src[start..i]);
            dst.extend_from_slice(&[b'\\', b'u', b'2', b'0', b'2', HEX[(r & 0xf) as usize]]);
            i += size;
            start = i;
            continue;
        }
        i += size;
    }
    dst.extend_from_slice(&src[start..]);
    dst.push(b'"');
}

/// What Go's `Marshal` reports for a `json.Number` that is not a JSON number.
pub(crate) fn invalid_number(text: &str) -> Error {
    let mut e = MarshalerError::new(
        "*json.Number",
        format!(
            "cannot parse {} as JSON number: invalid syntax",
            quote(text)
        )
        .into(),
    );
    e.source_func = "MarshalJSONTo";
    e.into()
}

/// Go's `isValidNumber`.
pub(crate) fn is_valid_number(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if b.first() == Some(&b'-') {
        i = 1;
    }
    match b.get(i) {
        Some(b'0') => i += 1,
        Some(b'1'..=b'9') => {
            i += 1;
            while b.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
        }
        _ => return false,
    }
    if b.len() >= i + 2 && b[i] == b'.' && b[i + 1].is_ascii_digit() {
        i += 2;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    if b.len() >= i + 2 && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if b[i] == b'+' || b[i] == b'-' {
            i += 1;
            if i == b.len() {
                return false;
            }
        }
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
    }
    i == b.len()
}

/// `strconv.FormatFloat(f, 'g', -1, 64)` for the values the encoder rejects.
fn go_float_g(f: f64) -> String {
    if f.is_nan() {
        "NaN".into()
    } else if f > 0.0 {
        "+Inf".into()
    } else {
        "-Inf".into()
    }
}

/// Formats a finite float as Go's JSON encoder does: shortest digits, `'f'`
/// notation unless the magnitude is below 1e-6 or at least 1e21, when
/// `'e'` notation with Go's cleaned-up exponent (`1e-7`, `1e+21`) is used.
pub fn format_float(f: f64, bits: u32) -> String {
    let abs = f.abs();
    let exponential = abs != 0.0
        && if bits == 32 {
            (abs as f32) < 1e-6 || (abs as f32) >= 1e21
        } else {
            abs < 1e-6 || abs >= 1e21
        };
    if !exponential {
        return if bits == 32 {
            (f as f32).to_string()
        } else {
            f.to_string()
        };
    }
    let text = if bits == 32 {
        format!("{:e}", f as f32)
    } else {
        format!("{f:e}")
    };
    let (mantissa, exp) = text.split_once('e').expect("exponent form");
    let exp: i32 = exp.parse().expect("exponent digits");
    // Go writes at least two exponent digits and then drops a leading zero
    // from negative exponents, so only positive ones keep their sign.
    format!(
        "{mantissa}e{}{}",
        if exp < 0 { '-' } else { '+' },
        exp.abs()
    )
}

/// Returns the JSON encoding of `v`, as Go's `Marshal` does.
pub fn marshal<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>, Error> {
    marshal_with(v, true)
}

/// Like [`marshal`], with HTML escaping selectable (as `Encoder` allows).
pub(crate) fn marshal_with<T: Serialize + ?Sized>(
    v: &T,
    escape_html: bool,
) -> Result<Vec<u8>, Error> {
    let mut s = Serializer::new(escape_html);
    v.serialize(&mut s)?;
    Ok(s.into_bytes())
}

/// Like [`marshal`], with options changing v1 behaviour, as in
/// `jsonv2.Marshal(v, json.DefaultOptionsV1(), options...)`.
pub fn marshal_with_options<T: Serialize + ?Sized>(
    v: &T,
    options: Options,
) -> Result<Vec<u8>, Error> {
    let mut s = Serializer::new(true);
    s.set_options(options);
    v.serialize(&mut s)?;
    Ok(s.into_bytes())
}

/// Like [`marshal`], but applies [`indent`](super::indent()) to the output.
pub fn marshal_indent<T: Serialize + ?Sized>(
    v: &T,
    prefix: &str,
    indent: &str,
) -> Result<Vec<u8>, Error> {
    let b = marshal(v)?;
    let mut out = Vec::with_capacity(2 * b.len());
    append_indent(&mut out, &b, prefix, indent)?;
    Ok(out)
}

/// A raw encoded JSON value (Go's `RawMessage`). It implements [`Marshaler`]
/// and [`Unmarshaler`](super::Unmarshaler) so that it can delay decoding or
/// precompute an encoding. Empty marshals as `null`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawMessage(pub Vec<u8>);

impl Marshaler for RawMessage {
    fn marshal_json(&self) -> Result<Vec<u8>, Error> {
        if self.0.is_empty() {
            Ok(b"null".to_vec())
        } else {
            Ok(self.0.clone())
        }
    }
}
impl Serialize for RawMessage {
    fn to_json(&self) -> Result<Value, Error> {
        let mut s = Serializer::new(false);
        self.serialize(&mut s)?;
        super::unmarshal_with_number(s.as_bytes())
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        s.marshaler("jsontext.Value", self.marshal_json())
    }
    fn is_empty_value(&self) -> bool {
        self.0.is_empty()
    }
    fn is_zero_value(&self) -> bool {
        self.0.is_empty()
    }
}

/// A byte slice that encodes as a base64 string, as Go's `[]byte` does
/// (`Vec<u8>` encodes as an array of numbers, like any other `Vec`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bytes(pub Vec<u8>);

impl Serialize for Bytes {
    fn to_json(&self) -> Result<Value, Error> {
        Ok(Value::String(
            super::super::base64::STANDARD.encode(&self.0),
        ))
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        s.write_raw(b"\"");
        s.write_raw(super::super::base64::STANDARD.encode(&self.0).as_bytes());
        s.write_raw(b"\"");
        Ok(())
    }
    fn is_empty_value(&self) -> bool {
        self.0.is_empty()
    }
    fn is_zero_value(&self) -> bool {
        self.0.is_empty()
    }
}

/// Map keys: strings and integers, as in Go.
pub trait MapKey: Sized {
    /// The JSON object key.
    fn to_key(&self) -> String;
    /// Parses an object key; the error is the Go type name for diagnostics.
    fn from_key(key: &str) -> Option<Self>;
    /// Go's name of the key type.
    fn key_type_name() -> &'static str;
}
impl MapKey for String {
    fn to_key(&self) -> String {
        self.clone()
    }
    fn from_key(key: &str) -> Option<Self> {
        Some(key.to_string())
    }
    fn key_type_name() -> &'static str {
        "string"
    }
}
macro_rules! integer_keys {
    ($($t:ty => $name:expr),+ $(,)?) => { $(
        impl MapKey for $t {
            fn to_key(&self) -> String { self.to_string() }
            fn from_key(key: &str) -> Option<Self> { key.parse().ok() }
            fn key_type_name() -> &'static str { $name }
        }
    )+ };
}
integer_keys!(
    i8 => "int8", i16 => "int16", i32 => "int32", i64 => "int64", isize => "int",
    u8 => "uint8", u16 => "uint16", u32 => "uint32", u64 => "uint64", usize => "uint"
);

// ---- Serialize for standard types -----------------------------------------

impl Serialize for Value {
    fn to_json(&self) -> Result<Value, Error> {
        Ok(self.clone())
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        s.write_value(self)
    }
    fn is_empty_value(&self) -> bool {
        matches!(self, Value::Null)
    }
    fn is_zero_value(&self) -> bool {
        matches!(self, Value::Null)
    }
}
impl Serialize for Number {
    fn to_json(&self) -> Result<Value, Error> {
        Ok(Value::Number(self.clone()))
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        s.write_number(self, false)
    }
    fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
        s.write_number(self, true)
    }
    fn is_empty_value(&self) -> bool {
        self.0.is_empty()
    }
    fn is_zero_value(&self) -> bool {
        self.0.is_empty()
    }
    fn is_json_number(&self) -> bool {
        true
    }
}
impl Serialize for str {
    fn to_json(&self) -> Result<Value, Error> {
        Ok(Value::from(self))
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        s.write_string(self, false);
        Ok(())
    }
    fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
        s.write_string(self, true);
        Ok(())
    }
    fn is_empty_value(&self) -> bool {
        self.is_empty()
    }
    fn is_zero_value(&self) -> bool {
        self.is_empty()
    }
}
impl Serialize for String {
    fn to_json(&self) -> Result<Value, Error> {
        self.as_str().to_json()
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        self.as_str().serialize(s)
    }
    fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
        self.as_str().serialize_quoted(s)
    }
    fn is_empty_value(&self) -> bool {
        self.is_empty()
    }
    fn is_zero_value(&self) -> bool {
        self.is_empty()
    }
}
impl Serialize for bool {
    fn to_json(&self) -> Result<Value, Error> {
        Ok(Value::Bool(*self))
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        s.write_literal(if *self { "true" } else { "false" }, false);
        Ok(())
    }
    fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
        s.write_literal(if *self { "true" } else { "false" }, true);
        Ok(())
    }
    fn is_empty_value(&self) -> bool {
        !*self
    }
    fn is_zero_value(&self) -> bool {
        !*self
    }
}
macro_rules! integer_serialize {
    ($($t:ty),+ $(,)?) => { $(
        impl Serialize for $t {
            fn to_json(&self) -> Result<Value, Error> { Ok(Value::from(*self)) }
            fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
                s.write_literal(&self.to_string(), false);
                Ok(())
            }
            fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
                s.write_literal(&self.to_string(), true);
                Ok(())
            }
            fn is_empty_value(&self) -> bool { *self == 0 }
            fn is_zero_value(&self) -> bool { *self == 0 }
            fn is_json_number(&self) -> bool { true }
        }
    )+ };
}
integer_serialize!(i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);
macro_rules! float_serialize {
    ($($t:ty => $bits:expr),+ $(,)?) => { $(
        impl Serialize for $t {
            fn to_json(&self) -> Result<Value, Error> {
                if !self.is_finite() {
                    return Err(UnsupportedValueError {
                        value: self.to_string(),
                        str: go_float_g(f64::from(*self)),
                    }
                    .into());
                }
                Ok(Value::Number(Number(format_float(f64::from(*self), $bits))))
            }
            fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
                s.write_float(f64::from(*self), $bits, false)
            }
            fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
                s.write_float(f64::from(*self), $bits, true)
            }
            fn is_empty_value(&self) -> bool { *self == 0.0 }
            fn is_zero_value(&self) -> bool { *self == 0.0 }
            fn is_json_number(&self) -> bool { true }
        }
    )+ };
}
float_serialize!(f32 => 32, f64 => 64);

impl<T: Serialize> Serialize for [T] {
    fn to_json(&self) -> Result<Value, Error> {
        self.iter()
            .map(Serialize::to_json)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array)
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        s.write_array(self)
    }
    fn is_empty_value(&self) -> bool {
        self.is_empty()
    }
    fn is_zero_value(&self) -> bool {
        self.is_empty()
    }
}
impl<T: Serialize> Serialize for Vec<T> {
    fn to_json(&self) -> Result<Value, Error> {
        self.as_slice().to_json()
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        self.as_slice().serialize(s)
    }
    fn is_empty_value(&self) -> bool {
        self.is_empty()
    }
    fn is_zero_value(&self) -> bool {
        self.is_empty()
    }
}
impl<T: Serialize, const N: usize> Serialize for [T; N] {
    fn to_json(&self) -> Result<Value, Error> {
        self.as_slice().to_json()
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        self.as_slice().serialize(s)
    }
    fn is_empty_value(&self) -> bool {
        N == 0
    }
    fn is_zero_value(&self) -> bool {
        self.iter().all(Serialize::is_zero_value)
    }
}
impl<T: Serialize> Serialize for Option<T> {
    fn to_json(&self) -> Result<Value, Error> {
        match self {
            Some(v) => v.to_json(),
            None => Ok(Value::Null),
        }
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        match self {
            Some(v) => v.serialize(s),
            None => {
                s.write_null();
                Ok(())
            }
        }
    }
    fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
        match self {
            Some(v) => v.serialize_quoted(s),
            None => {
                s.write_null();
                Ok(())
            }
        }
    }
    fn is_empty_value(&self) -> bool {
        self.is_none()
    }
    fn is_zero_value(&self) -> bool {
        self.is_none()
    }
    fn is_json_number(&self) -> bool {
        self.as_ref().is_some_and(Serialize::is_json_number)
    }
}
impl<T: Serialize + ?Sized> Serialize for Box<T> {
    fn to_json(&self) -> Result<Value, Error> {
        (**self).to_json()
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        (**self).serialize(s)
    }
    fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
        (**self).serialize_quoted(s)
    }
    fn is_empty_value(&self) -> bool {
        (**self).is_empty_value()
    }
    fn is_zero_value(&self) -> bool {
        (**self).is_zero_value()
    }
    fn is_json_number(&self) -> bool {
        (**self).is_json_number()
    }
}
impl<T: Serialize + ?Sized> Serialize for &T {
    fn to_json(&self) -> Result<Value, Error> {
        (**self).to_json()
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        (**self).serialize(s)
    }
    fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
        (**self).serialize_quoted(s)
    }
    fn is_empty_value(&self) -> bool {
        (**self).is_empty_value()
    }
    fn is_zero_value(&self) -> bool {
        (**self).is_zero_value()
    }
    fn is_json_number(&self) -> bool {
        (**self).is_json_number()
    }
}

/// Encodes map entries in sorted key order, as Go does.
fn serialize_entries<'a, K, V, I>(entries: I, s: &mut Serializer) -> Result<(), Error>
where
    K: MapKey + 'a,
    V: Serialize + 'a,
    I: IntoIterator<Item = (&'a K, &'a V)>,
{
    let mut sorted: Vec<(String, &V)> = entries.into_iter().map(|(k, v)| (k.to_key(), v)).collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut w = s.object();
    for (k, v) in sorted {
        w.member(&k, v)?;
    }
    w.finish();
    Ok(())
}
fn entries_to_json<'a, K, V, I>(entries: I) -> Result<Value, Error>
where
    K: MapKey + 'a,
    V: Serialize + 'a,
    I: IntoIterator<Item = (&'a K, &'a V)>,
{
    let entries = entries
        .into_iter()
        .map(|(k, v)| Ok((k.to_key(), v.to_json()?)))
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(Value::Object(Map::from_unsorted(entries)))
}
impl<K: MapKey, V: Serialize> Serialize for BTreeMap<K, V> {
    fn to_json(&self) -> Result<Value, Error> {
        entries_to_json(self)
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        serialize_entries(self, s)
    }
    fn is_empty_value(&self) -> bool {
        self.is_empty()
    }
    fn is_zero_value(&self) -> bool {
        self.is_empty()
    }
}
impl<K: MapKey, V: Serialize, S> Serialize for HashMap<K, V, S> {
    fn to_json(&self) -> Result<Value, Error> {
        entries_to_json(self)
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        serialize_entries(self, s)
    }
    fn is_empty_value(&self) -> bool {
        self.is_empty()
    }
    fn is_zero_value(&self) -> bool {
        self.is_empty()
    }
}

impl fmt::Debug for Serializer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Serializer")
            .field("len", &self.out.len())
            .field("escape_html", &self.escape_html)
            .finish()
    }
}

/// The error for a duration under `FormatDurationAsNano(false)`, as Go's v2
/// default reports it.
fn no_duration_form() -> Error {
    UnsupportedValueError {
        value: "time.Duration".into(),
        str: "no default representation".into(),
    }
    .into()
}

/// Durations encode as a number of nanoseconds, as Go's `time.Duration` does.
impl Serialize for std::time::Duration {
    fn to_json(&self) -> Result<Value, Error> {
        Ok(Value::from(self.as_nanos()))
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        if !s.duration_nano {
            return Err(no_duration_form());
        }
        s.write_literal(&self.as_nanos().to_string(), false);
        Ok(())
    }
    fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
        if !s.duration_nano {
            return Err(no_duration_form());
        }
        s.write_literal(&self.as_nanos().to_string(), true);
        Ok(())
    }
    fn is_empty_value(&self) -> bool {
        self.is_zero()
    }
    fn is_zero_value(&self) -> bool {
        self.is_zero()
    }
    fn is_json_number(&self) -> bool {
        true
    }
}

/// [`crate::time::Duration`] encodes as signed nanoseconds, as Go's
/// `time.Duration` does.
impl Serialize for crate::time::Duration {
    fn to_json(&self) -> Result<Value, Error> {
        Ok(Value::from(self.as_nanos()))
    }
    fn serialize(&self, s: &mut Serializer) -> Result<(), Error> {
        if !s.duration_nano {
            return Err(no_duration_form());
        }
        s.write_literal(&self.as_nanos().to_string(), false);
        Ok(())
    }
    fn serialize_quoted(&self, s: &mut Serializer) -> Result<(), Error> {
        if !s.duration_nano {
            return Err(no_duration_form());
        }
        s.write_literal(&self.as_nanos().to_string(), true);
        Ok(())
    }
    fn is_empty_value(&self) -> bool {
        self.as_nanos() == 0
    }
    fn is_zero_value(&self) -> bool {
        self.as_nanos() == 0
    }
    fn is_json_number(&self) -> bool {
        true
    }
}
