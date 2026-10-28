//! `encoding/json` over `reflect` values: what `net/rpc/jsonrpc` needs of
//! `json.Marshal` and `json.Unmarshal` for the arguments and replies of
//! registered methods. Structs follow their `json` tags, maps sort their
//! keys, `[]byte` is base64, and the output is HTML-escaped as `Encoder`'s is.

use super::parse::{parse, Json, Node};
use crate::reflect::{self, Kind, StructField, Type, Value};

// ---- encoding ----

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Go's `encodeState.string` with `escapeHTML` set.
pub(crate) fn write_string(out: &mut Vec<u8>, s: &[u8]) {
    out.push(b'"');
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b < 0x80 {
            match b {
                b'"' => out.extend_from_slice(b"\\\""),
                b'\\' => out.extend_from_slice(b"\\\\"),
                0x08 => out.extend_from_slice(b"\\b"),
                0x0c => out.extend_from_slice(b"\\f"),
                b'\n' => out.extend_from_slice(b"\\n"),
                b'\r' => out.extend_from_slice(b"\\r"),
                b'\t' => out.extend_from_slice(b"\\t"),
                b if b < 0x20 || b == b'<' || b == b'>' || b == b'&' => {
                    out.extend_from_slice(b"\\u00");
                    out.push(HEX[(b >> 4) as usize]);
                    out.push(HEX[(b & 15) as usize]);
                }
                b => out.push(b),
            }
            i += 1;
            continue;
        }
        let end = (i + 4).min(s.len());
        let ch = match std::str::from_utf8(&s[i..end]) {
            Ok(t) => t.chars().next(),
            Err(e) if e.valid_up_to() > 0 => std::str::from_utf8(&s[i..i + e.valid_up_to()])
                .ok()
                .and_then(|t| t.chars().next()),
            Err(_) => None,
        };
        match ch {
            None => {
                out.extend_from_slice(b"\\ufffd");
                i += 1;
            }
            Some(c) if c == '\u{2028}' || c == '\u{2029}' => {
                out.extend_from_slice(b"\\u202");
                out.push(HEX[(c as u32 & 15) as usize]);
                i += 3;
            }
            Some(c) => {
                out.extend_from_slice(&s[i..i + c.len_utf8()]);
                i += c.len_utf8();
            }
        }
    }
    out.push(b'"');
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(out: &mut Vec<u8>, data: &[u8]) {
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        out.push(B64[(n >> 18) as usize & 63]);
        out.push(B64[(n >> 12) as usize & 63]);
        out.push(if c.len() > 1 {
            B64[(n >> 6) as usize & 63]
        } else {
            b'='
        });
        out.push(if c.len() > 2 {
            B64[n as usize & 63]
        } else {
            b'='
        });
    }
}

fn unbase64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    if !b.len().is_multiple_of(4) {
        return None;
    }
    for c in b.chunks(4) {
        let mut n = 0u32;
        let mut pad = 0;
        for (i, &x) in c.iter().enumerate() {
            let v = if x == b'=' {
                if i < 2 {
                    return None;
                }
                pad += 1;
                0
            } else if pad > 0 {
                return None;
            } else {
                B64.iter().position(|&y| y == x)? as u32
            };
            n = n << 6 | v;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// A struct field as `encoding/json` sees it.
pub(crate) struct JsonField {
    name: String,
    index: Vec<usize>,
    omit_empty: bool,
    omit_zero: bool,
    quoted: bool,
    typ: Type,
}

fn tag_parts(tag: &str) -> (String, Vec<String>) {
    let mut it = tag.split(',');
    let name = it.next().unwrap_or("").to_string();
    (name, it.map(str::to_string).collect())
}

fn is_valid_tag(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| "!#$%&()*+-./:;<=>?@[]^_{|}~ ".contains(c) || c.is_alphanumeric())
}

/// The fields of a struct type, embedded structs promoted, with Go's
/// dominance rule (the shallowest wins; a tagged name wins among equals;
/// otherwise the name is dropped).
pub(crate) fn json_fields(t: &Type) -> Vec<JsonField> {
    struct Cand {
        f: JsonField,
        depth: usize,
        tagged: bool,
    }
    let mut cands: Vec<Cand> = Vec::new();
    fn walk(
        t: &Type,
        prefix: &[usize],
        depth: usize,
        out: &mut Vec<Cand>,
        visited: &mut Vec<Type>,
    ) {
        if visited.contains(t) {
            return;
        }
        visited.push(t.clone());
        for i in 0..t.num_field() {
            let sf: StructField = t.field(i);
            let mut index = prefix.to_vec();
            index.push(i);
            let tag = sf.tag.get("json");
            if tag == "-" {
                continue;
            }
            let (tname, opts) = tag_parts(&tag);
            let mut ft = sf.type_.clone();
            if sf.anonymous {
                let mut u = ft.clone();
                if u.kind() == Kind::Pointer {
                    u = u.elem();
                }
                if !sf.is_exported() && u.kind() != Kind::Struct {
                    continue;
                }
                if tname.is_empty() && u.kind() == Kind::Struct {
                    walk(&u, &index, depth + 1, out, visited);
                    continue;
                }
            } else if !sf.is_exported() {
                continue;
            }
            let tagged = is_valid_tag(&tname);
            let name = if tagged { tname } else { sf.name.clone() };
            let quoted = opts.iter().any(|o| o == "string")
                && matches!(
                    {
                        while ft.kind() == Kind::Pointer {
                            ft = ft.elem();
                        }
                        ft.kind()
                    },
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
                        | Kind::String
                );
            out.push(Cand {
                f: JsonField {
                    name,
                    index,
                    omit_empty: opts.iter().any(|o| o == "omitempty"),
                    omit_zero: opts.iter().any(|o| o == "omitzero"),
                    quoted,
                    typ: sf.type_.clone(),
                },
                depth,
                tagged,
            });
        }
        visited.pop();
    }
    walk(t, &[], 0, &mut cands, &mut Vec::new());
    // Dominant field per name.
    let mut result: Vec<Cand> = Vec::new();
    let mut names: Vec<String> = cands.iter().map(|c| c.f.name.clone()).collect();
    names.dedup();
    let mut seen = std::collections::HashSet::new();
    for n in names {
        if !seen.insert(n.clone()) {
            continue;
        }
        let group: Vec<&Cand> = cands.iter().filter(|c| c.f.name == n).collect();
        let min = group.iter().map(|c| c.depth).min().unwrap_or(0);
        let top: Vec<&&Cand> = group.iter().filter(|c| c.depth == min).collect();
        let pick = if top.len() == 1 {
            Some(top[0])
        } else {
            let tagged: Vec<&&&Cand> = top.iter().filter(|c| c.tagged).collect();
            if tagged.len() == 1 {
                Some(*tagged[0])
            } else {
                None
            }
        };
        if let Some(p) = pick {
            result.push(Cand {
                f: JsonField {
                    name: p.f.name.clone(),
                    index: p.f.index.clone(),
                    omit_empty: p.f.omit_empty,
                    omit_zero: p.f.omit_zero,
                    quoted: p.f.quoted,
                    typ: p.f.typ.clone(),
                },
                depth: p.depth,
                tagged: p.tagged,
            });
        }
    }
    result.sort_by(|a, b| a.f.index.cmp(&b.f.index));
    result.into_iter().map(|c| c.f).collect()
}

fn is_empty_value(v: &Value) -> bool {
    match v.kind() {
        Kind::Array | Kind::Map | Kind::Slice | Kind::String => v.len() == 0,
        Kind::Bool => !v.bool(),
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => v.int() == 0,
        Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 | Kind::Uintptr => {
            v.uint() == 0
        }
        Kind::Float32 | Kind::Float64 => v.float() == 0.0,
        Kind::Interface | Kind::Pointer => v.is_nil(),
        _ => false,
    }
}

fn json_text<T: crate::encoding::json::Serialize>(v: &T) -> Result<String, String> {
    crate::encoding::json::marshal(v)
        .map_err(|e| e.to_string())
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn float_text(f: f64, bits32: bool) -> Result<String, String> {
    if f.is_nan() || f.is_infinite() {
        return Err(format!(
            "json: unsupported value: {}",
            crate::strconv::format_float(f, b'g', -1, 64)
        ));
    }
    if bits32 {
        json_text(&(f as f32))
    } else {
        json_text(&f)
    }
}

thread_local! {
    /// The JSON pointer of the value being written, for Go's `jsontext`
    /// errors (`within "/params/0/M"`).
    static PATH: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// `json.Marshal` of a reflect value, HTML-escaped, appended to `out`. The
/// value sits at the JSON pointer `path` of a document `out` holds the start
/// of: the length of `out` is the byte offset Go's errors report.
pub(crate) fn marshal_at(out: &mut Vec<u8>, v: &Value, path: &[&str]) -> Result<(), String> {
    PATH.with(|p| *p.borrow_mut() = path.iter().map(|s| (*s).to_owned()).collect());
    let r = marshal_inner(out, v, false);
    PATH.with(|p| p.borrow_mut().clear());
    r
}

fn path_push(name: String) {
    PATH.with(|p| p.borrow_mut().push(name));
}

fn path_pop() {
    PATH.with(|p| {
        p.borrow_mut().pop();
    });
}

/// Go's error for a map key that `jsontext` cannot write as a member name.
fn member_name_error(offset: usize) -> String {
    let path = PATH.with(|p| {
        p.borrow()
            .iter()
            .map(|s| format!("/{}", s.replace('~', "~0").replace('/', "~1")))
            .collect::<String>()
    });
    let within = if path.is_empty() {
        String::new()
    } else {
        format!(" within {}", crate::strconv::quote(&path))
    };
    format!("json: unsupported value: jsontext: object member name must be a string{within} after offset {offset}")
}

fn marshal_inner(out: &mut Vec<u8>, v: &Value, quoted: bool) -> Result<(), String> {
    if !v.is_valid() {
        out.extend_from_slice(b"null");
        return Ok(());
    }
    let t = v.type_();
    // Go's marshalerEncoder and textMarshalerEncoder: a nil pointer is null
    // without calling a method, and a JSON method wins over a text method.
    if v.kind() != Kind::Interface && !(v.kind() == Kind::Pointer && v.is_nil()) {
        if let Some(m) = json_method(v, "MarshalJSON", marshal_shape) {
            return marshal_method(out, &method_error_type(v), &m);
        }
        if let Some(m) = json_method(v, "MarshalText", marshal_shape) {
            return marshal_text(out, &method_error_type(v), &m);
        }
    }
    let wrap = |out: &mut Vec<u8>, text: &str| {
        if quoted {
            write_string(out, text.as_bytes());
        } else {
            out.extend_from_slice(text.as_bytes());
        }
    };
    match v.kind() {
        Kind::Bool => wrap(out, if v.bool() { "true" } else { "false" }),
        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
            wrap(out, &v.int().to_string())
        }
        Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 | Kind::Uintptr => {
            wrap(out, &v.uint().to_string())
        }
        Kind::Float32 | Kind::Float64 => {
            let text = float_text(v.float(), v.kind() == Kind::Float32)?;
            wrap(out, &text)
        }
        Kind::String => {
            if quoted {
                let mut inner = Vec::new();
                write_string(&mut inner, &v.string_bytes());
                write_string(out, &inner);
            } else {
                write_string(out, &v.string_bytes());
            }
        }
        Kind::Interface | Kind::Pointer => {
            if v.is_nil() {
                out.extend_from_slice(b"null");
            } else {
                marshal_inner(out, &v.elem(), quoted)?;
            }
        }
        Kind::Struct => {
            out.push(b'{');
            let mut first = true;
            for f in json_fields(&t) {
                let mut fv = v.clone();
                let mut nil_embedded = false;
                for (k, &i) in f.index.iter().enumerate() {
                    if k > 0 && fv.kind() == Kind::Pointer {
                        if fv.is_nil() {
                            nil_embedded = true;
                            break;
                        }
                        fv = fv.elem();
                    }
                    fv = fv.field(i);
                }
                if nil_embedded {
                    continue;
                }
                if (f.omit_empty && is_empty_value(&fv)) || (f.omit_zero && fv.is_zero()) {
                    continue;
                }
                if !first {
                    out.push(b',');
                }
                first = false;
                write_string(out, f.name.as_bytes());
                out.push(b':');
                path_push(f.name.clone());
                let r = marshal_inner(out, &fv, f.quoted);
                path_pop();
                r?;
            }
            out.push(b'}');
        }
        Kind::Map => {
            if v.is_nil() {
                out.extend_from_slice(b"null");
                return Ok(());
            }
            // Go's resolveKeyName: a key type whose value method set has
            // MarshalText is written as its text, before its kind is looked at.
            // A nil pointer key is the empty name.
            let text_key = has_method(&t.key(), "MarshalText", marshal_shape);
            let mut items: Vec<(Vec<u8>, Value)> = Vec::new();
            for (k, e) in v.entries() {
                let key = if text_key {
                    if k.kind() == Kind::Pointer && k.is_nil() {
                        Vec::new()
                    } else {
                        let res = k.method_by_name("MarshalText").call(&[]);
                        if !res[1].is_nil() {
                            let msg = error_text(&res[1]);
                            return Err(method_error(&method_error_type(&k), "MarshalText", &msg));
                        }
                        res[0].bytes()
                    }
                } else {
                    match k.kind() {
                        Kind::String => k.string_bytes(),
                        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
                            k.int().to_string().into_bytes()
                        }
                        Kind::Uint
                        | Kind::Uint8
                        | Kind::Uint16
                        | Kind::Uint32
                        | Kind::Uint64
                        | Kind::Uintptr => k.uint().to_string().into_bytes(),
                        // A key whose pointer has MarshalText passes Go's type
                        // check and fails when the name is written.
                        _ if has_method(
                            &reflect::pointer_to(&t.key()),
                            "MarshalText",
                            marshal_shape,
                        ) =>
                        {
                            return Err(member_name_error(out.len() + 2));
                        }
                        _ => {
                            return Err(format!("json: unsupported type: {t}"));
                        }
                    }
                };
                items.push((key, e));
            }
            items.sort_by(|a, b| a.0.cmp(&b.0));
            out.push(b'{');
            for (i, (k, e)) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(out, k);
                out.push(b':');
                path_push(String::from_utf8_lossy(k).into_owned());
                let r = marshal_inner(out, e, false);
                path_pop();
                r?;
            }
            out.push(b'}');
        }
        Kind::Slice | Kind::Array => {
            if v.kind() == Kind::Slice && v.is_nil() {
                out.extend_from_slice(b"null");
                return Ok(());
            }
            // Go's newSliceEncoder: bytes are base64 unless *E has a marshaler.
            let elem_ptr = reflect::pointer_to(&t.elem());
            let marshals = has_method(&elem_ptr, "MarshalJSON", marshal_shape)
                || has_method(&elem_ptr, "MarshalText", marshal_shape);
            if v.kind() == Kind::Slice && t.elem().kind() == Kind::Uint8 && !marshals {
                out.push(b'"');
                base64(out, &v.bytes());
                out.push(b'"');
                return Ok(());
            }
            out.push(b'[');
            for i in 0..v.len() {
                if i > 0 {
                    out.push(b',');
                }
                path_push(i.to_string());
                let r = marshal_inner(out, &v.index(i), false);
                path_pop();
                r?;
            }
            out.push(b']');
        }
        _ => return Err(format!("json: unsupported type: {t}")),
    }
    Ok(())
}

/// `[]byte`: the result of `MarshalJSON` and the argument of `UnmarshalJSON`.
fn bytes_type() -> Type {
    reflect::slice_of(&Type::basic(Kind::Uint8))
}

/// `MarshalJSON() ([]byte, error)`; `f` is the method type, receiver first.
fn marshal_shape(f: &Type) -> bool {
    f.num_in() == 1
        && f.num_out() == 2
        && f.out(0) == bytes_type()
        && f.out(1) == Type::error_type()
}

/// `UnmarshalJSON([]byte) error`; `f` is the method type, receiver first.
fn unmarshal_shape(f: &Type) -> bool {
    f.num_in() == 2
        && f.in_(1) == bytes_type()
        && f.num_out() == 1
        && f.out(0) == Type::error_type()
}

/// Whether the method set of type `t` has the method `name` with the shape.
fn has_method(t: &Type, name: &str, shape: fn(&Type) -> bool) -> bool {
    t.method_by_name(name).is_some_and(|m| shape(&m.type_))
}

/// The bound method `name` that encoding/json calls on `v`: one in the method
/// set of its type, else (when `v` is addressable) one in the method set of
/// its address.
fn json_method(v: &Value, name: &str, shape: fn(&Type) -> bool) -> Option<Value> {
    if has_method(&v.type_(), name, shape) {
        return Some(v.method_by_name(name));
    }
    let addr = v.can_addr().then(|| v.addr());
    addr.filter(|a| has_method(&a.type_(), name, shape))
        .map(|a| a.method_by_name(name))
}

/// The text of a non-nil `error` value.
fn error_text(e: &Value) -> String {
    let res = e.method_by_name("Error").call(&[]);
    String::from_utf8_lossy(&res[0].string_bytes()).into_owned()
}

/// The type a marshaler error names: Go reports the error against the pointer
/// the method was called through, so a value T is named *T.
fn method_error_type(v: &Value) -> Type {
    let t = v.type_();
    let base = if v.kind() == Kind::Pointer {
        t.elem()
    } else {
        t
    };
    reflect::pointer_to(&base)
}

fn method_error(t: &Type, name: &str, msg: &str) -> String {
    format!("json: error calling {name} for type {t}: {msg}")
}

/// Go's `marshalerEncoder`: the output of `MarshalJSON`, compacted.
fn marshal_method(out: &mut Vec<u8>, t: &Type, m: &Value) -> Result<(), String> {
    let res = m.call(&[]);
    if !res[1].is_nil() {
        return Err(method_error(t, "MarshalJSON", &error_text(&res[1])));
    }
    compact(out, &res[0].bytes()).map_err(|e| method_error(t, "MarshalJSON", &e))
}

/// Go's `textMarshalerEncoder`: the output of `MarshalText` as a JSON string.
fn marshal_text(out: &mut Vec<u8>, t: &Type, m: &Value) -> Result<(), String> {
    let res = m.call(&[]);
    if !res[1].is_nil() {
        return Err(method_error(t, "MarshalText", &error_text(&res[1])));
    }
    write_string(out, &res[0].bytes());
    Ok(())
}

/// Go's `compact` with `escapeHTML`: `src` as one JSON value without
/// insignificant white space, with <, >, &, U+2028 and U+2029 escaped in
/// strings.
fn compact(out: &mut Vec<u8>, src: &[u8]) -> Result<(), String> {
    parse(src)?;
    let (mut in_string, mut escaped) = (false, false);
    let mut i = 0;
    while i < src.len() {
        let c = src[i];
        if !in_string {
            match c {
                b' ' | b'\t' | b'\r' | b'\n' => {}
                b'"' => {
                    in_string = true;
                    out.push(c);
                }
                _ => out.push(c),
            }
        } else if escaped {
            escaped = false;
            out.push(c);
        } else {
            match c {
                b'\\' => {
                    escaped = true;
                    out.push(c);
                }
                b'"' => {
                    in_string = false;
                    out.push(c);
                }
                b'<' | b'>' | b'&' => out.extend_from_slice(format!("\\u00{c:02x}").as_bytes()),
                0xe2 if src[i + 1..].starts_with(&[0x80, 0xa8]) => {
                    out.extend_from_slice(b"\\u2028");
                    i += 2;
                }
                0xe2 if src[i + 1..].starts_with(&[0x80, 0xa9]) => {
                    out.extend_from_slice(b"\\u2029");
                    i += 2;
                }
                _ => out.push(c),
            }
        }
        i += 1;
    }
    Ok(())
}

// ---- decoding ----

/// What `Unmarshal` reports, saved while decoding continues (Go's
/// `saveError`).
struct Ctx {
    err: Option<String>,
    /// Set when a value was not stored: a type error or a method error. A map
    /// entry whose key fails is left out.
    failed: bool,
    /// The JSON path from the root to the value being decoded.
    path: Vec<String>,
    /// The name of the root type.
    root: String,
}

fn kind_word(j: &Json) -> String {
    match j {
        Json::Null => "null".into(),
        Json::Bool(_) => "bool".into(),
        Json::Number(_) => "number".into(),
        Json::String(_) => "string".into(),
        Json::Array(_) => "array".into(),
        Json::Object(_) => "object".into(),
    }
}

impl Ctx {
    /// The error of an `UnmarshalJSON` or `UnmarshalText` method. Go saves it
    /// like a type error: the first error is kept and decoding goes on.
    fn method_error(&mut self, e: &Value) {
        self.failed = true;
        if self.err.is_none() {
            self.err = Some(error_text(e));
        }
    }

    fn type_error(&mut self, what: &str, t: &Type) {
        self.type_error_note(what, t, "");
    }

    /// `type_error` with a suffix, as Go adds to the text of an
    /// `UnmarshalText` target that is given a non-string.
    fn type_error_note(&mut self, what: &str, t: &Type, note: &str) {
        self.failed = true;
        if self.err.is_some() {
            return;
        }
        let msg = match self.path.last() {
            None => format!("json: cannot unmarshal {what} into Go value of type {t}{note}"),
            Some(last) => {
                let into = if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
                    ""
                } else {
                    "Go struct field "
                };
                format!(
                    "json: cannot unmarshal {what} into {into}{}.{} of type {t}{note}",
                    self.root,
                    self.path.join(".")
                )
            }
        };
        self.err = Some(msg);
    }
}

/// `json.Unmarshal(data, v)` for a pointer value `v`.
pub(crate) fn unmarshal(data: &[u8], v: &Value) -> Result<(), String> {
    let tree = parse(data)?;
    unmarshal_tree(data, &tree, v, &[])
}

/// Decodes a parsed value into the pointer `v`. `src` is the input `tree` was
/// parsed from. `prefix` is the path from the root of the JSON text to `tree`
/// when it sits inside an array (`jsonrpc` decodes into `[1]any{v}`), in which
/// case the root has no name.
pub(crate) fn unmarshal_tree(
    src: &[u8],
    tree: &Node,
    v: &Value,
    prefix: &[&str],
) -> Result<(), String> {
    if v.kind() != Kind::Pointer || v.is_nil() {
        return Err(format!("json: Unmarshal(non-pointer {})", v.type_()));
    }
    let mut cx = Ctx {
        err: None,
        failed: false,
        path: prefix.iter().map(|s| s.to_string()).collect(),
        root: if prefix.is_empty() {
            v.type_().elem().name()
        } else {
            String::new()
        },
    };
    if prefix.is_empty() {
        // The path is empty at the root: the message names a Go value.
        cx.path.clear();
    }
    store(&mut cx, src, tree, &v.elem());
    match cx.err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn int_in_range(kind: Kind, n: i64) -> bool {
    match kind {
        Kind::Int8 => i8::try_from(n).is_ok(),
        Kind::Int16 => i16::try_from(n).is_ok(),
        Kind::Int32 => i32::try_from(n).is_ok(),
        _ => true,
    }
}

fn uint_in_range(kind: Kind, n: u64) -> bool {
    match kind {
        Kind::Uint8 => u8::try_from(n).is_ok(),
        Kind::Uint16 => u16::try_from(n).is_ok(),
        Kind::Uint32 => u32::try_from(n).is_ok(),
        _ => true,
    }
}

fn generic(j: &Node) -> Value {
    let any = Type::any_type();
    let wrap = |v: Value| Value::from_interface(&any, &v);
    match &j.json {
        Json::Null => reflect::zero(&any),
        Json::Bool(b) => wrap(Value::from_bool(&Type::basic(Kind::Bool), *b)),
        Json::Number(n) => wrap(Value::from_float(
            &Type::basic(Kind::Float64),
            n.parse::<f64>().unwrap_or(0.0),
        )),
        Json::String(s) => wrap(Value::from_string(&Type::basic(Kind::String), s.as_bytes())),
        Json::Array(a) => {
            let t = reflect::slice_of(&any);
            let items: Vec<Value> = a.iter().map(generic).collect();
            wrap(Value::from_items(&t, &items))
        }
        Json::Object(o) => {
            let t = reflect::map_of(&Type::basic(Kind::String), &any);
            // Later duplicates win.
            let mut last: Vec<(&String, &Node)> = Vec::new();
            for (k, e) in o {
                match last.iter_mut().find(|(lk, _)| *lk == k) {
                    Some(slot) => slot.1 = e,
                    None => last.push((k, e)),
                }
            }
            let entries: Vec<(Value, Value)> = last
                .iter()
                .map(|(k, e)| {
                    (
                        Value::from_string(&Type::basic(Kind::String), k.as_bytes()),
                        generic(e),
                    )
                })
                .collect();
            wrap(Value::from_entries(&t, &entries))
        }
    }
}

/// Go's `UnmarshalJSON` call: the raw JSON text goes to the method.
fn unmarshal_method(cx: &mut Ctx, raw: &[u8], m: &Value) {
    let arg = reflect::new(&bytes_type()).elem();
    arg.set_bytes(raw);
    let res = m.call(&[arg]);
    if !res[0].is_nil() {
        cx.method_error(&res[0]);
    }
}

/// Go's `UnmarshalText` call: a JSON string's unquoted text goes to the method.
/// Other JSON kinds are type errors, which Go words with a note about strings.
fn unmarshal_text(cx: &mut Ctx, j: &Node, m: &Value, t: &Type) {
    let s = match &j.json {
        Json::String(s) => s,
        other => {
            cx.type_error_note(&kind_word(other), t, ": JSON value must be string type");
            return;
        }
    };
    let arg = reflect::new(&bytes_type()).elem();
    arg.set_bytes(s.as_bytes());
    let res = m.call(&[arg]);
    if !res[0].is_nil() {
        cx.method_error(&res[0]);
    }
}

fn store(cx: &mut Ctx, src: &[u8], j: &Node, v: &Value) {
    let t = v.type_();
    // Pointers allocate on demand; null clears them.
    if v.kind() == Kind::Pointer {
        if matches!(j.json, Json::Null) {
            v.set_zero();
            return;
        }
        if v.is_nil() {
            v.set(&reflect::new(&t.elem()));
        }
    }
    if v.kind() != Kind::Interface {
        if let Some(m) = json_method(v, "UnmarshalJSON", unmarshal_shape) {
            unmarshal_method(cx, &src[j.span.clone()], &m);
            return;
        }
        // Go's indirect skips UnmarshalText for null.
        if !matches!(j.json, Json::Null) {
            if let Some(m) = json_method(v, "UnmarshalText", unmarshal_shape) {
                unmarshal_text(cx, j, &m, &t);
                return;
            }
        }
    }
    if v.kind() == Kind::Pointer {
        store(cx, src, j, &v.elem());
        return;
    }
    if v.kind() == Kind::Interface {
        if matches!(j.json, Json::Null) {
            v.set_zero();
            return;
        }
        if !v.is_nil() && v.elem().kind() == Kind::Pointer && !v.elem().is_nil() {
            store(cx, src, j, &v.elem());
            return;
        }
        if t.num_method() == 0 {
            v.set(&generic(j));
        } else {
            cx.type_error(&kind_word(&j.json), &t);
        }
        return;
    }
    match (&j.json, v.kind()) {
        (Json::Null, _) => {
            if matches!(v.kind(), Kind::Map | Kind::Slice) {
                v.set_zero();
            }
        }
        (Json::Bool(b), Kind::Bool) => v.set_bool(*b),
        (Json::String(s), Kind::String) => v.set_string(s.as_bytes()),
        (Json::String(s), Kind::Slice) if t.elem().kind() == Kind::Uint8 => match unbase64(s) {
            Some(b) => v.set_bytes(&b),
            None => {
                if cx.err.is_none() {
                    cx.type_error("string", &t);
                    if let Some(e) = cx.err.as_mut() {
                        e.push_str(": illegal base64 data at input byte 0");
                    }
                }
            }
        },
        (Json::Number(n), Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64) => {
            match n.parse::<i64>() {
                Ok(x) if int_in_range(v.kind(), x) => v.set_int(x),
                _ => cx.type_error(&format!("number {n}"), &t),
            }
        }
        (
            Json::Number(n),
            Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 | Kind::Uintptr,
        ) => match n.parse::<u64>() {
            Ok(x) if uint_in_range(v.kind(), x) => v.set_uint(x),
            _ => cx.type_error(&format!("number {n}"), &t),
        },
        (Json::Number(n), Kind::Float32 | Kind::Float64) => match n.parse::<f64>() {
            Ok(x)
                if !x.is_infinite() && (v.kind() == Kind::Float64 || !(x as f32).is_infinite()) =>
            {
                v.set_float(x)
            }
            _ => cx.type_error(&format!("number {n}"), &t),
        },
        (Json::Array(a), Kind::Slice) => {
            let items = reflect::make_slice(&t, a.len() as isize, a.len() as isize);
            for (i, e) in a.iter().enumerate() {
                cx.path.push(i.to_string());
                store(cx, src, e, &items.index(i));
                cx.path.pop();
            }
            v.set(&items);
        }
        (Json::Array(a), Kind::Array) => {
            for i in 0..v.len() {
                match a.get(i) {
                    Some(e) => {
                        cx.path.push(i.to_string());
                        store(cx, src, e, &v.index(i));
                        cx.path.pop();
                    }
                    None => v.index(i).set_zero(),
                }
            }
        }
        (Json::Object(o), Kind::Map) => {
            let kt = t.key();
            let kk = kt.kind();
            // A key type whose pointer has UnmarshalText is decoded through it,
            // before the key's kind is looked at.
            let text_key = has_method(&reflect::pointer_to(&kt), "UnmarshalText", unmarshal_shape);
            if !text_key
                && !matches!(
                    kk,
                    Kind::String
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
                )
            {
                cx.type_error("object", &t);
                return;
            }
            if v.is_nil() {
                v.set(&reflect::make_map(&t));
            }
            for (k, e) in o {
                // As Go does, the value is decoded before the key.
                let elem = reflect::new(&t.elem()).elem();
                cx.path.push(k.clone());
                store(cx, src, e, &elem);
                cx.path.pop();
                let key = if text_key {
                    // The key's JSON text is its quoted name.
                    let mut raw = Vec::new();
                    write_string(&mut raw, k.as_bytes());
                    let node = Node {
                        json: Json::String(k.clone()),
                        span: 0..raw.len(),
                    };
                    let kv = reflect::new(&kt);
                    cx.failed = false;
                    // Go reads a key only through UnmarshalText, which gets the
                    // unquoted name; a JSON method on the key type is ignored.
                    if let Some(m) = json_method(&kv.elem(), "UnmarshalText", unmarshal_shape) {
                        unmarshal_text(cx, &node, &m, &kt);
                    }
                    let _ = &raw;
                    if cx.failed {
                        continue;
                    }
                    kv.elem()
                } else {
                    let key = reflect::new(&kt).elem();
                    match kk {
                        Kind::String => key.set_string(k.as_bytes()),
                        Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64 => {
                            match k.parse::<i64>() {
                                Ok(x) if int_in_range(kk, x) => key.set_int(x),
                                _ => {
                                    cx.type_error(&format!("number {k}"), &kt);
                                    continue;
                                }
                            }
                        }
                        _ => match k.parse::<u64>() {
                            Ok(x) if uint_in_range(kk, x) => key.set_uint(x),
                            _ => {
                                cx.type_error(&format!("number {k}"), &kt);
                                continue;
                            }
                        },
                    }
                    key
                };
                v.set_map_index(&key, &elem);
            }
        }
        (Json::Object(o), Kind::Struct) => {
            let fields = json_fields(&t);
            for (k, e) in o {
                let f = fields
                    .iter()
                    .find(|f| f.name == *k)
                    .or_else(|| fields.iter().find(|f| f.name.eq_ignore_ascii_case(k)));
                let Some(f) = f else { continue };
                let mut fv = v.clone();
                let mut ok = true;
                for (n, &i) in f.index.iter().enumerate() {
                    if n > 0 && fv.kind() == Kind::Pointer {
                        if fv.is_nil() {
                            fv.set(&reflect::new(&fv.type_().elem()));
                        }
                        fv = fv.elem();
                    }
                    if !fv.type_().field(i).is_exported() {
                        ok = false;
                        break;
                    }
                    fv = fv.field(i);
                }
                if !ok {
                    continue;
                }
                cx.path.push(f.name.clone());
                // The option does not apply where a method reads the value.
                let ft = fv.type_();
                let base = if ft.kind() == Kind::Pointer {
                    ft.elem()
                } else {
                    ft
                };
                let by_method = {
                    let p = reflect::pointer_to(&base);
                    has_method(&p, "UnmarshalJSON", unmarshal_shape)
                        || has_method(&p, "UnmarshalText", unmarshal_shape)
                };
                if f.quoted && !by_method {
                    let numeric = matches!(
                        fv.kind(),
                        Kind::Int
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
                    );
                    match &e.json {
                        // A number must be quoted.
                        Json::Number(_) | Json::Bool(_) | Json::Array(_) | Json::Object(_)
                            if numeric =>
                        {
                            cx.type_error(&kind_word(&e.json), &fv.type_());
                        }
                        Json::String(s) => match parse(s.as_bytes()) {
                            Ok(inner) => store(cx, s.as_bytes(), &inner, &fv),
                            Err(_) if numeric => cx.type_error(&format!("number {s}"), &fv.type_()),
                            Err(_) => {
                                if cx.err.is_none() {
                                    cx.err = Some(format!(
                                        "json: invalid use of ,string struct tag, trying to unmarshal {} into {}",
                                        crate::strconv::quote(s),
                                        fv.type_()
                                    ));
                                }
                            }
                        },
                        _ => store(cx, src, e, &fv),
                    }
                } else {
                    store(cx, src, e, &fv);
                }
                cx.path.pop();
            }
        }
        (other, _) => cx.type_error(&kind_word(other), &t),
    }
}
