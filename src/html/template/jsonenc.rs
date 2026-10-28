//! A `json.Marshal` over template [`Value`]s, for the JavaScript value
//! escaper (Go `encoding/json` `encode.go`, with HTML escaping on).
//!
//! Supported: booleans, integers, floats, strings, byte slices (base64),
//! arrays, slices, maps with string/integer/`MarshalText` keys, structs
//! (exported fields, `json` tags with a name, `omitempty`, `omitzero` and
//! `-`, embedded struct promotion), pointers, interfaces, and the
//! `MarshalJSON` and `MarshalText` methods. The output of a `MarshalJSON`
//! method is compacted and HTML-escaped; it is not fully validated, so
//! malformed output of a custom marshaler is reported differently than Go.

use super::jsonscan::append_compact;
use crate::encoding::base64;
use crate::strconv;
use crate::text::template::value::{CallError, FuncSig, Kind, Type, Value};
use crate::unicode::rune::decode_rune;
use std::collections::BTreeMap;

/// A failure while marshaling.
pub(crate) enum EncErr {
    /// A `json` package error, with Go's text.
    Json(String),
    /// A panic raised by a custom marshaler method.
    Panic(String),
}

type R<T> = Result<T, EncErr>;

fn json_err<T>(s: String) -> R<T> {
    Err(EncErr::Json(s))
}

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Appends `src` as a JSON string, with HTML escaping.
fn append_string(dst: &mut Vec<u8>, src: &[u8], escape_html: bool) {
    dst.push(b'"');
    let mut start = 0;
    let mut i = 0;
    while i < src.len() {
        let b = src[i];
        if b < 0x80 {
            let safe = (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\' || b == 0x7f;
            let html_safe = safe && b != b'<' && b != b'>' && b != b'&';
            if html_safe || (!escape_html && safe) {
                i += 1;
                continue;
            }
            dst.extend_from_slice(&src[start..i]);
            match b {
                b'\\' | b'"' => {
                    dst.push(b'\\');
                    dst.push(b);
                }
                0x08 => dst.extend_from_slice(b"\\b"),
                0x0c => dst.extend_from_slice(b"\\f"),
                b'\n' => dst.extend_from_slice(b"\\n"),
                b'\r' => dst.extend_from_slice(b"\\r"),
                b'\t' => dst.extend_from_slice(b"\\t"),
                _ => {
                    // This encodes bytes < 0x20 except for \b, \f, \n, \r and \t.
                    // If escapeHTML is set, it also escapes <, >, and &
                    // because they can lead to security holes when
                    // user-controlled strings are rendered into JSON
                    // and served to some browsers.
                    dst.extend_from_slice(b"\\u00");
                    dst.push(HEX[usize::from(b >> 4)]);
                    dst.push(HEX[usize::from(b & 0xF)]);
                }
            }
            i += 1;
            start = i;
            continue;
        }
        let (c, size) = decode_rune(&src[i..]);
        if c == 0xFFFD && size == 1 {
            dst.extend_from_slice(&src[start..i]);
            dst.extend_from_slice(b"\\ufffd");
            i += size;
            start = i;
            continue;
        }
        // U+2028 is LINE SEPARATOR.
        // U+2029 is PARAGRAPH SEPARATOR.
        // They are both technically valid characters in JSON strings,
        // but don't work in JSONP, which has to be evaluated as JavaScript,
        // and can lead to security holes there. It is valid JSON to
        // escape them, so we do so unconditionally.
        if c == 0x2028 || c == 0x2029 {
            dst.extend_from_slice(&src[start..i]);
            dst.extend_from_slice(b"\\u202");
            dst.push(HEX[(c & 0xF) as usize]);
            i += size;
            start = i;
            continue;
        }
        i += size;
    }
    dst.extend_from_slice(&src[start..]);
    dst.push(b'"');
}

fn marshaler_sig(name: &str) -> FuncSig {
    let _ = name;
    FuncSig::new(
        vec![],
        vec![Type::slice_of(Type::uint8()), Type::error()],
        false,
    )
}

fn has_method(t: &Type, name: &str) -> bool {
    let sig = marshaler_sig(name);
    t.method_set().iter().any(|(n, s)| n == name && *s == sig)
}

fn is_marshaler(t: &Type) -> bool {
    has_method(t, "MarshalJSON")
}

fn is_text_marshaler(t: &Type) -> bool {
    has_method(t, "MarshalText")
}

fn bytes_of(v: &Value) -> Vec<u8> {
    v.items().iter().map(|b| b.as_uint() as u8).collect()
}

fn call_marshaler(v: &Value, method: &str, shown_type: &Type) -> R<Vec<u8>> {
    let m = v.method_by_name(method);
    match m.call(&[]) {
        Ok(b) => Ok(bytes_of(&b)),
        Err(CallError::Error(e)) => json_err(format!(
            "json: error calling {method} for type {}: {e}",
            shown_type.type_string()
        )),
        Err(CallError::Panic(p)) => Err(EncErr::Panic(p)),
    }
}

#[derive(Clone, Copy)]
struct Opts {
    quoted: bool,
    escape_html: bool,
}

struct Enc {
    buf: Vec<u8>,
}

/// Marshals the value as `json.Marshal` does.
pub(crate) fn marshal(v: &Value) -> R<Vec<u8>> {
    let mut e = Enc { buf: Vec::new() };
    e.value(
        v,
        Opts {
            quoted: false,
            escape_html: true,
        },
    )?;
    Ok(e.buf)
}

fn is_empty_value(v: &Value) -> bool {
    match v.kind() {
        Kind::Array | Kind::Map | Kind::Slice | Kind::String => v.is_empty(),
        Kind::Bool
        | Kind::Int
        | Kind::Int8
        | Kind::Int16
        | Kind::Int32
        | Kind::Int64
        | Kind::Uint
        | Kind::Uint8
        | Kind::Uint16
        | Kind::Uint32
        | Kind::Uint64
        | Kind::Uintptr
        | Kind::Float32
        | Kind::Float64
        | Kind::Interface
        | Kind::Pointer => is_zero_value(v),
        _ => false,
    }
}

fn is_zero_value(v: &Value) -> bool {
    match v.kind() {
        Kind::Bool => !v.as_bool(),
        k if k.is_int() => v.as_int() == 0,
        k if k.is_uint() => v.as_uint() == 0,
        Kind::Float32 | Kind::Float64 => v.as_float() == 0.0 && !v.as_float().is_sign_negative(),
        Kind::Complex64 | Kind::Complex128 => v.as_complex() == (0.0, 0.0),
        Kind::String => v.is_empty(),
        Kind::Array => v.items().iter().all(is_zero_value),
        Kind::Struct => v
            .type_()
            .map(|t| (0..t.fields().len()).all(|i| is_zero_value(&v.field(i))))
            .unwrap_or(true),
        _ => v.is_nil(),
    }
}

impl Enc {
    fn value(&mut self, v: &Value, opts: Opts) -> R<()> {
        let Some(t) = v.type_().cloned() else {
            self.buf.extend_from_slice(b"null");
            return Ok(());
        };
        // Marshalers take precedence over the kind of the value.
        if t.kind() != Kind::Pointer && v.can_addr() {
            let pt = Type::ptr_to(t.clone());
            if is_marshaler(&pt) {
                return self.marshaler(&v.addr(), opts, &t);
            }
        }
        if is_marshaler(&t) {
            return self.marshaler(v, opts, &t);
        }
        if t.kind() != Kind::Pointer && v.can_addr() {
            let pt = Type::ptr_to(t.clone());
            if is_text_marshaler(&pt) {
                return self.text_marshaler(&v.addr(), opts, &t);
            }
        }
        if is_text_marshaler(&t) {
            return self.text_marshaler(v, opts, &t);
        }
        match t.kind() {
            Kind::Bool => {
                self.quote(opts.quoted);
                self.buf
                    .extend_from_slice(if v.as_bool() { b"true" } else { b"false" });
                self.quote(opts.quoted);
            }
            k if k.is_int() => {
                self.quote(opts.quoted);
                self.buf
                    .extend_from_slice(v.as_int().to_string().as_bytes());
                self.quote(opts.quoted);
            }
            k if k.is_uint() => {
                self.quote(opts.quoted);
                self.buf
                    .extend_from_slice(v.as_uint().to_string().as_bytes());
                self.quote(opts.quoted);
            }
            Kind::Float32 => self.float(v, 32, opts)?,
            Kind::Float64 => self.float(v, 64, opts)?,
            Kind::String => {
                let s = v.as_string();
                if opts.quoted {
                    let mut inner = Vec::new();
                    append_string(&mut inner, s.as_bytes(), opts.escape_html);
                    append_string(&mut self.buf, &inner, false);
                } else {
                    append_string(&mut self.buf, s.as_bytes(), opts.escape_html);
                }
            }
            Kind::Interface => {
                if v.is_nil() {
                    self.buf.extend_from_slice(b"null");
                } else {
                    self.value(&v.elem(), opts)?;
                }
            }
            Kind::Struct => self.struct_(v, &t, opts)?,
            Kind::Map => self.map(v, &t, opts)?,
            Kind::Slice => {
                if v.is_nil() {
                    self.buf.extend_from_slice(b"null");
                    return Ok(());
                }
                let elem = t.elem().expect("slice");
                if elem.kind() == Kind::Uint8 {
                    let p = Type::ptr_to(elem.clone());
                    if !is_marshaler(&p) && !is_text_marshaler(&p) {
                        let bytes = bytes_of(v);
                        self.buf.push(b'"');
                        self.buf
                            .extend_from_slice(base64::STANDARD.encode(&bytes).as_bytes());
                        self.buf.push(b'"');
                        return Ok(());
                    }
                }
                self.array(v, opts)?;
            }
            Kind::Array => self.array(v, opts)?,
            Kind::Pointer => {
                if v.is_nil() {
                    self.buf.extend_from_slice(b"null");
                } else {
                    self.value(&v.elem(), opts)?;
                }
            }
            _ => return json_err(format!("json: unsupported type: {}", t.type_string())),
        }
        Ok(())
    }

    fn quote(&mut self, quoted: bool) {
        if quoted {
            self.buf.push(b'"');
        }
    }

    fn float(&mut self, v: &Value, bits: i32, opts: Opts) -> R<()> {
        let f = v.as_float();
        if f.is_infinite() || f.is_nan() {
            return json_err(format!(
                "json: unsupported value: {}",
                strconv::format_float(f, b'g', -1, bits)
            ));
        }
        self.quote(opts.quoted);
        let abs = f.abs();
        let mut fmt = b'f';
        if abs != 0.0
            && ((bits == 64 && (abs < 1e-6 || abs >= 1e21))
                || (bits == 32 && ((abs as f32) < 1e-6 || (abs as f32) >= 1e21)))
        {
            fmt = b'e';
        }
        let mut b = strconv::format_float(f, fmt, -1, bits).into_bytes();
        if fmt == b'e' {
            // clean up e-09 to e-9
            let n = b.len();
            if n >= 4 && b[n - 4] == b'e' && b[n - 3] == b'-' && b[n - 2] == b'0' {
                b[n - 2] = b[n - 1];
                b.truncate(n - 1);
            }
        }
        self.buf.extend_from_slice(&b);
        self.quote(opts.quoted);
        Ok(())
    }

    fn marshaler(&mut self, v: &Value, opts: Opts, shown: &Type) -> R<()> {
        if v.kind() == Kind::Pointer && v.is_nil() {
            self.buf.extend_from_slice(b"null");
            return Ok(());
        }
        let b = call_marshaler(v, "MarshalJSON", shown)?;
        if let Err(e) = append_compact(&mut self.buf, &b, opts.escape_html) {
            return json_err(format!(
                "json: error calling MarshalJSON for type {}: {e}",
                shown.type_string()
            ));
        }
        Ok(())
    }

    fn text_marshaler(&mut self, v: &Value, opts: Opts, shown: &Type) -> R<()> {
        if v.kind() == Kind::Pointer && v.is_nil() {
            self.buf.extend_from_slice(b"null");
            return Ok(());
        }
        let b = call_marshaler(v, "MarshalText", shown)?;
        append_string(&mut self.buf, &b, opts.escape_html);
        Ok(())
    }

    fn array(&mut self, v: &Value, opts: Opts) -> R<()> {
        self.buf.push(b'[');
        for i in 0..v.len() {
            if i > 0 {
                self.buf.push(b',');
            }
            self.value(&v.index(i), opts)?;
        }
        self.buf.push(b']');
        Ok(())
    }

    fn map(&mut self, v: &Value, t: &Type, opts: Opts) -> R<()> {
        let key_t = t.key().expect("map");
        match key_t.kind() {
            Kind::String => {}
            k if k.int_like() => {}
            _ => {
                if !is_text_marshaler(&key_t) {
                    return json_err(format!("json: unsupported type: {}", t.type_string()));
                }
            }
        }
        if v.is_nil() {
            self.buf.extend_from_slice(b"null");
            return Ok(());
        }
        self.buf.push(b'{');
        let mut entries: Vec<(Vec<u8>, Value)> = Vec::new();
        for (k, val) in v.map_entries() {
            let ks = match resolve_key_name(&k) {
                Ok(s) => s,
                Err(EncErr::Json(e)) => {
                    return json_err(format!(
                        "json: encoding error for type {}: {}",
                        strconv::quote(t.type_string()),
                        strconv::quote(e)
                    ))
                }
                Err(p) => return Err(p),
            };
            entries.push((ks, val));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        for (i, (ks, val)) in entries.iter().enumerate() {
            if i > 0 {
                self.buf.push(b',');
            }
            append_string(&mut self.buf, ks, opts.escape_html);
            self.buf.push(b':');
            self.value(val, opts)?;
        }
        self.buf.push(b'}');
        Ok(())
    }

    fn struct_(&mut self, v: &Value, t: &Type, opts: Opts) -> R<()> {
        let fields = type_fields(t);
        let mut next = b'{';
        'fields: for f in &fields {
            let mut fv = v.clone();
            for &i in &f.index {
                if fv.kind() == Kind::Pointer {
                    if fv.is_nil() {
                        continue 'fields;
                    }
                    fv = fv.elem();
                }
                fv = fv.field(i);
            }
            if (f.omit_empty && is_empty_value(&fv)) || (f.omit_zero && is_zero_value(&fv)) {
                continue;
            }
            self.buf.push(next);
            next = b',';
            append_string(&mut self.buf, f.name.as_bytes(), opts.escape_html);
            self.buf.push(b':');
            self.value(
                &fv,
                Opts {
                    quoted: f.quoted,
                    escape_html: opts.escape_html,
                },
            )?;
        }
        if next == b'{' {
            self.buf.extend_from_slice(b"{}");
        } else {
            self.buf.push(b'}');
        }
        Ok(())
    }
}

fn resolve_key_name(k: &Value) -> R<Vec<u8>> {
    if k.kind() == Kind::String {
        return Ok(k.as_string().into_bytes());
    }
    if let Some(t) = k.type_() {
        if is_text_marshaler(t) {
            if k.kind() == Kind::Pointer && k.is_nil() {
                return Ok(Vec::new());
            }
            return call_marshaler(k, "MarshalText", t);
        }
    }
    match k.kind() {
        kind if kind.is_int() => Ok(k.as_int().to_string().into_bytes()),
        kind if kind.is_uint() => Ok(k.as_uint().to_string().into_bytes()),
        _ => json_err("unexpected map key type".to_owned()),
    }
}

#[derive(Clone)]
struct JsonField {
    name: String,
    tag: bool,
    index: Vec<usize>,
    omit_empty: bool,
    omit_zero: bool,
    quoted: bool,
}

/// The value of the `json` key in a Go struct tag.
fn tag_get(tag: &str, key: &str) -> String {
    let mut tag = tag;
    while !tag.is_empty() {
        tag = tag.trim_start_matches(' ');
        if tag.is_empty() {
            break;
        }
        let Some(colon) = tag.find(':') else { break };
        let name = &tag[..colon];
        if name.is_empty()
            || name
                .bytes()
                .any(|c| c <= b' ' || c == b':' || c == b'"' || c == 0x7f)
            || !tag[colon + 1..].starts_with('"')
        {
            break;
        }
        let rest = &tag[colon + 1..];
        // Scan the quoted string.
        let mut i = 1;
        let bytes = rest.as_bytes();
        while i < bytes.len() && bytes[i] != b'"' {
            if bytes[i] == b'\\' {
                i += 1;
            }
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let qvalue = &rest[..=i];
        tag = &rest[i + 1..];
        if name == key {
            return strconv::unquote(qvalue)
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default();
        }
    }
    String::new()
}

fn is_valid_tag(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    for c in s.chars() {
        if "!#$%&()*+-./:;<=>?@[]^_{|}~ ".contains(c) {
            // Backslash and quote chars are reserved, but otherwise any
            // punctuation chars are allowed in a tag name.
        } else if !crate::unicode::is_letter(c as i32) && !crate::unicode::is_digit(c as i32) {
            return false;
        }
    }
    true
}

/// The exported fields of a struct that `json` encodes, in index order, with
/// embedded structs promoted and conflicting names resolved by Go's rules.
fn type_fields(t: &Type) -> Vec<JsonField> {
    struct Cand {
        typ: Type,
        index: Vec<usize>,
    }
    let mut current: Vec<Cand>;
    let mut next = vec![Cand {
        typ: t.clone(),
        index: vec![],
    }];
    let mut count: BTreeMap<String, usize> = BTreeMap::new();
    let mut visited: Vec<Type> = Vec::new();
    let mut fields: Vec<JsonField> = Vec::new();

    while !next.is_empty() {
        current = std::mem::take(&mut next);
        let cur_count = std::mem::take(&mut count);
        let mut next_count: BTreeMap<String, usize> = BTreeMap::new();
        for f in &current {
            if visited.contains(&f.typ) {
                continue;
            }
            visited.push(f.typ.clone());
            for (i, sf) in f.typ.fields().iter().enumerate() {
                if sf.embedded {
                    let mut st = sf.ty.clone();
                    if st.kind() == Kind::Pointer {
                        st = st.elem().expect("elem");
                    }
                    if !sf.is_exported() && st.kind() != Kind::Struct {
                        // Ignore embedded fields of unexported non-struct types.
                        continue;
                    }
                    // Do not ignore embedded fields of unexported struct
                    // types since they may have exported fields.
                } else if !sf.is_exported() {
                    // Ignore unexported non-embedded fields.
                    continue;
                }
                let tag = tag_get(&sf.tag, "json");
                if tag == "-" {
                    continue;
                }
                let mut parts = tag.split(',');
                let mut name = parts.next().unwrap_or("").to_owned();
                let opts: Vec<&str> = parts.collect();
                if !is_valid_tag(&name) {
                    name = String::new();
                }
                let mut index = f.index.clone();
                index.push(i);

                let mut ft = sf.ty.clone();
                if !ft.has_name() && ft.kind() == Kind::Pointer {
                    // Follow pointer.
                    ft = ft.elem().expect("elem");
                }

                // Only strings, floats, integers, and booleans can be quoted.
                let mut quoted = false;
                if opts.contains(&"string")
                    && (matches!(
                        ft.kind(),
                        Kind::Bool | Kind::Float32 | Kind::Float64 | Kind::String
                    ) || ft.kind().int_like())
                {
                    quoted = true;
                }

                // Record found field and index sequence.
                if !name.is_empty() || !sf.embedded || ft.kind() != Kind::Struct {
                    let tagged = !name.is_empty();
                    if name.is_empty() {
                        name = sf.name.clone();
                    }
                    let field = JsonField {
                        name: name.clone(),
                        tag: tagged,
                        index,
                        omit_empty: opts.contains(&"omitempty"),
                        omit_zero: opts.contains(&"omitzero"),
                        quoted,
                    };
                    fields.push(field.clone());
                    if cur_count.get(&type_key(&f.typ)).copied().unwrap_or(0) > 1 {
                        // If there were multiple instances, add a second,
                        // so that the annihilation code will see a duplicate.
                        // It only cares about the distinction between 1 and 2,
                        // so don't bother generating any more copies.
                        fields.push(field);
                    }
                    continue;
                }

                // Record new anonymous struct to explore in next round.
                let key = type_key(&ft);
                let c = next_count.entry(key).or_insert(0);
                *c += 1;
                if *c == 1 {
                    next.push(Cand {
                        typ: ft.clone(),
                        index,
                    });
                }
            }
        }
        count = next_count;
    }

    fields.sort_by(|a, b| {
        // sort field by name, breaking ties with depth, then breaking ties
        // with "name came from json tag", then breaking ties with index
        // sequence.
        a.name
            .cmp(&b.name)
            .then(a.index.len().cmp(&b.index.len()))
            .then(b.tag.cmp(&a.tag))
            .then(a.index.cmp(&b.index))
    });

    // Delete all fields that are hidden by the Go rules for embedded fields,
    // except that fields with JSON tags are promoted.
    let mut out: Vec<JsonField> = Vec::new();
    let mut i = 0;
    while i < fields.len() {
        let name = fields[i].name.clone();
        let mut advance = 1;
        while i + advance < fields.len() && fields[i + advance].name == name {
            advance += 1;
        }
        if advance == 1 {
            // Only one field with this name
            out.push(fields[i].clone());
        } else if let Some(d) = dominant_field(&fields[i..i + advance]) {
            out.push(d);
        }
        i += advance;
    }
    out.sort_by(|a, b| a.index.cmp(&b.index));
    out
}

fn type_key(t: &Type) -> String {
    t.type_string()
}

/// The field to use among fields with the same name, if one dominates.
fn dominant_field(fields: &[JsonField]) -> Option<JsonField> {
    // The fields are sorted in increasing index-length order, then by presence
    // of tag. That means that the first field is the dominant one. We need
    // only check for error cases: two fields at top level, either both tagged
    // or neither tagged.
    if fields.len() > 1
        && fields[0].index.len() == fields[1].index.len()
        && fields[0].tag == fields[1].tag
    {
        return None;
    }
    Some(fields[0].clone())
}
