//! `jsontext.Value` and the package-level formatting helpers.
use super::decode::DecoderState;
use super::encode::{value_kind, EncoderState};
use super::errors::{Error, SyntacticError};
use super::flags;
use super::options::{
    allow_duplicate_names, allow_invalid_utf8, canonicalize_raw_floats, canonicalize_raw_ints,
    multiline, preserve_raw_strings, reorder_raw_objects, Options,
};
use super::token::{Kind, KIND_BEGIN_ARRAY, KIND_BEGIN_OBJECT, KIND_END_ARRAY, KIND_END_OBJECT};
use super::wire::{self, ValueFlags};

/// `jsontext.Value`: the raw text of one JSON value.
///
/// A Go `Value` can be `nil` or empty; here an empty value stands for both.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Value(pub Vec<u8>);

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Value {
        Value(v)
    }
}
impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Value {
        Value(v.to_vec())
    }
}
impl From<&str> for Value {
    fn from(v: &str) -> Value {
        Value(v.as_bytes().to_vec())
    }
}

/// The text of the value, or `null` when empty.
impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.is_empty() {
            return f.write_str("null");
        }
        f.write_str(&String::from_utf8_lossy(&self.0))
    }
}

impl Value {
    /// Go's `Value.IsValid`: reports whether the value is exactly one valid
    /// JSON value, with optional surrounding whitespace.
    pub fn is_valid(&self, opts: &[Options]) -> bool {
        let mut d = DecoderState::buffered(&self.0, opts);
        let mut f = ValueFlags::default();
        let val = d.read_value(&mut f);
        let eof = d.read_token();
        val.is_ok() && matches!(eof, Err(Error::Eof))
    }

    /// Go's `Value.Format`: reformats the value in place per `opts`.
    pub fn format(&mut self, opts: &[Options]) -> Result<(), Error> {
        self.format_with(opts, &[])
    }

    fn format_with(&mut self, opts1: &[Options], opts2: &[Options]) -> Result<(), Error> {
        let mut e = EncoderState::buffered(opts1);
        e.opts.join_all(opts2);
        e.opts.flags.set(flags::OMIT_TOP_LEVEL_NEWLINE, true);
        e.write_value(&self.0)?;
        if self.0 != e.buf {
            self.0 = e.buf;
        }
        Ok(())
    }

    /// Go's `Value.Compact`: removes whitespace and keeps strings as written.
    pub fn compact(&mut self, opts: &[Options]) -> Result<(), Error> {
        self.format_with(
            &[
                allow_duplicate_names(true),
                allow_invalid_utf8(true),
                preserve_raw_strings(true),
            ],
            opts,
        )
    }

    /// Go's `Value.Indent`: formats the value over multiple lines.
    pub fn indent(&mut self, opts: &[Options]) -> Result<(), Error> {
        self.format_with(
            &[
                allow_duplicate_names(true),
                allow_invalid_utf8(true),
                preserve_raw_strings(true),
                multiline(true),
            ],
            opts,
        )
    }

    /// Go's `Value.Canonicalize`: puts the value in the JSON Canonicalization
    /// Scheme form of RFC 8785.
    pub fn canonicalize(&mut self, opts: &[Options]) -> Result<(), Error> {
        self.format_with(
            &[
                canonicalize_raw_ints(true),
                canonicalize_raw_floats(true),
                reorder_raw_objects(true),
            ],
            opts,
        )
    }

    /// Go's `Value.MarshalJSON`: the value itself, or `null` when empty.
    pub fn marshal_json(&self) -> Vec<u8> {
        if self.0.is_empty() {
            return b"null".to_vec();
        }
        self.0.clone()
    }

    /// Go's `Value.UnmarshalJSON`: stores a copy of `b`.
    pub fn unmarshal_json(&mut self, b: &[u8]) {
        self.0.clear();
        self.0.extend_from_slice(b);
    }

    /// Go's `Value.Kind`: the kind of the value, or invalid when empty.
    pub fn kind(&self) -> Kind {
        value_kind(&self.0)
    }
}

/// Go's `AppendFormat`: appends `src` reformatted per `opts` to `dst`. On
/// error `src` is appended as it is.
pub fn append_format(dst: &mut Vec<u8>, src: &[u8], opts: &[Options]) -> Result<(), Error> {
    let mut e = EncoderState::buffered(opts);
    e.opts.flags.set(flags::OMIT_TOP_LEVEL_NEWLINE, true);
    match e.write_value(src) {
        Ok(()) => {
            dst.extend_from_slice(&e.buf);
            Ok(())
        }
        Err(err) => {
            dst.extend_from_slice(src);
            Err(err)
        }
    }
}

/// Go's `AppendFloat`: appends `src` formatted as an ECMAScript number
/// (RFC 8785, section 3.2.2.3). Panics unless `bits` is 32 or 64.
pub fn append_float(dst: &mut Vec<u8>, src: f64, bits: i32) {
    if bits != 32 && bits != 64 {
        panic!("illegal AppendFloat bit size");
    }
    wire::append_float(dst, src, bits);
}

/// Go's `AppendQuote`: appends `src` as a quoted JSON string. Invalid UTF-8
/// is replaced with U+FFFD and reported.
pub fn append_quote(dst: &mut Vec<u8>, src: &[u8]) -> Result<(), Error> {
    match wire::append_quote(dst, src, &flags::Flags::default()) {
        Some(err) => Err(Error::from(SyntacticError {
            err: Some(err),
            ..Default::default()
        })),
        None => Ok(()),
    }
}

/// Go's `AppendUnquote`: appends the decoded content of the JSON string
/// `src` to `dst`. Invalid input is replaced with U+FFFD where possible and
/// reported.
pub fn append_unquote(dst: &mut Vec<u8>, src: &[u8]) -> Result<(), Error> {
    match wire::append_unquote(dst, src) {
        Some(err) => Err(Error::from(SyntacticError {
            err: Some(err),
            ..Default::default()
        })),
        None => Ok(()),
    }
}

// ---------------------------------------------------------- RFC 8785 order

const COMMA_AND_WHITESPACE: &[u8] = b", \n\r\t";

fn trim_left(b: &[u8]) -> &[u8] {
    let n = b
        .iter()
        .take_while(|c| COMMA_AND_WHITESPACE.contains(c))
        .count();
    &b[n..]
}

struct Member {
    name: Vec<u8>,
    /// `, \n\r\t"name": "value"`: the member with the separator before it.
    buffer: Vec<u8>,
    /// Position among the members before sorting.
    orig: usize,
}

fn compare_members(x: &Member, y: &Member) -> std::cmp::Ordering {
    let c = wire::compare_utf16(&x.name, &y.name);
    let c = if c != 0 {
        c
    } else {
        wire::compare_utf16(trim_left(&x.buffer), trim_left(&y.buffer))
    };
    c.cmp(&0)
}

/// `mustReorderObjects`: sorts the members of every object in `b`, a valid
/// JSON value, by name per RFC 8785, section 3.2.3.
pub(crate) fn must_reorder_objects(b: &mut [u8]) {
    let mut d = DecoderState::buffered(b, &[allow_duplicate_names(true), allow_invalid_utf8(true)]);
    let mut scratch = Vec::new();
    reorder_from_decoder(&mut d, &mut scratch);
    b.copy_from_slice(d.buf());
}

fn reorder_from_decoder(d: &mut DecoderState<'_>, scratch: &mut Vec<u8>) {
    let (tok, err) = match d.read_token() {
        Ok(t) => (t, None),
        Err(e) => (Default::default(), Some(e)),
    };
    match tok.kind() {
        KIND_BEGIN_OBJECT => {
            let mut members: Vec<Member> = Vec::new();
            let mut is_sorted = true;
            let before_body = d.previous_offset_end() as usize;
            while d.peek_kind() != KIND_END_OBJECT {
                let before_name = d.previous_offset_end() as usize;
                let mut vf = ValueFlags::default();
                let name = d.read_value(&mut vf).unwrap_or_default();
                let name = wire::unquote_may_copy(&name, vf.is_verbatim());
                reorder_from_decoder(d, scratch);
                let after_value = d.previous_offset_end() as usize;
                let curr = Member {
                    name,
                    buffer: d.buf()[before_name..after_value].to_vec(),
                    orig: members.len(),
                };
                if is_sorted {
                    if let Some(prev) = members.last() {
                        is_sorted = compare_members(prev, &curr) == std::cmp::Ordering::Less;
                    }
                }
                members.push(curr);
            }
            let after_body = d.previous_offset_end() as usize;
            let _ = d.read_token();
            if is_sorted {
                return;
            }
            let first_before = members[0].buffer.clone();
            members.sort_by(compare_members);
            let first_after = members[0].buffer.clone();
            let prefix = |b: &[u8]| b[..b.len() - trim_left(b).len()].to_vec();
            let mut sorted: Vec<u8> = Vec::with_capacity(after_body - before_body);
            for (i, m) in members.iter().enumerate() {
                if i == 0 && m.orig != 0 {
                    sorted.extend_from_slice(&prefix(&first_before));
                    sorted.extend_from_slice(trim_left(&m.buffer));
                } else if i != 0 && m.orig == 0 {
                    sorted.extend_from_slice(&prefix(&first_after));
                    sorted.extend_from_slice(trim_left(&m.buffer));
                } else {
                    sorted.extend_from_slice(&m.buffer);
                }
            }
            if after_body - before_body != sorted.len() {
                panic!("BUG: length invariant violated");
            }
            d.buf_mut()[before_body..after_body].copy_from_slice(&sorted);
            if sorted.len() > scratch.len() {
                *scratch = sorted;
            }
        }
        KIND_BEGIN_ARRAY => {
            while d.peek_kind() != KIND_END_ARRAY {
                reorder_from_decoder(d, scratch);
            }
            let _ = d.read_token();
        }
        _ => {
            if let Some(err) = err {
                panic!("BUG: {err}");
            }
        }
    }
}
