//! `SemanticError` and the constructors that position it in the coder's
//! stream, ported from Go's `encoding/json/v2/errors.go`.
use std::fmt;
use std::sync::LazyLock;

use super::typeinfo::TypeInfo;
use crate::encoding::json::jsontext::{
    self, Decoder, Encoder, Error, Kind, Pointer, Value, KIND_BEGIN_ARRAY, KIND_BEGIN_OBJECT,
    KIND_END_ARRAY, KIND_END_OBJECT, KIND_FALSE, KIND_NULL, KIND_NUMBER, KIND_STRING, KIND_TRUE,
};
use crate::strconv;

const ERROR_PREFIX: &str = "json: ";

macro_rules! sentinels {
    ($($(#[$doc:meta])* $name:ident, $fn:ident => $text:expr;)+) => { $(
        static $name: LazyLock<Error> = LazyLock::new(|| Error::msg($text));
        $(#[$doc])*
        pub(crate) fn $fn() -> Error {
            $name.clone()
        }
    )+ };
}

sentinels! {
    ERR_UNSUPPORTED_MUTATION, err_unsupported_mutation => "unsupported calls must not read or write any tokens";
    ERR_NON_SINGULAR_VALUE, err_non_singular_value => "must read or write exactly one value";
    ERR_CHANGING_DUPLICATE_NAMES, err_changing_duplicate_names => "cannot change duplicate name checks after a JSON object has already begun processing";
    ERR_CHANGING_INVALID_UTF8, err_changing_invalid_utf8 => "cannot change UTF-8 checks after a JSON object has already begun processing";
    ERR_CHANGING_WHITESPACE, err_changing_whitespace => "cannot change whitespace formatting within a MarshalEncode call";
    ERR_INVALID_STRING_TAG, err_invalid_string_tag => "invalid use of `string` tag option";
    ERR_NIL_FIELD, err_nil_field => "cannot set embedded pointer to unexported struct type";
    ERR_NON_STRING_VALUE, err_non_string_value => "JSON value must be string type";
    ERR_ARRAY_UNDERFLOW, err_array_underflow => "too few array elements";
    ERR_ARRAY_OVERFLOW, err_array_overflow => "too many array elements";
    ERR_RAW_EMBED_NOT_OBJECT, err_raw_embed_not_object => "embedded raw value must be a JSON object";
    ERR_NO_EXPORTED_FIELDS, err_no_exported_fields => "Go struct has no exported fields";
}

/// Go's `ErrUnknownName`: an object member name that no struct field matches.
pub const ERR_UNKNOWN_NAME: Error = Error::UnknownName;

/// `SemanticError` describes an error determining the meaning of JSON data
/// as Go data or vice-versa: a mismatch between JSON and a Go type, or a
/// failure of a user's marshal or unmarshal function.
#[derive(Clone, Debug, Default)]
pub struct SemanticError {
    /// Either "marshal" or "unmarshal" (unexported in Go).
    pub(crate) action: &'static str,
    /// The byte offset after which the error occurred.
    pub byte_offset: i64,
    /// The JSON Pointer of the value where the error occurred.
    pub json_pointer: Pointer,
    /// The kind of the JSON value, or invalid if unknown.
    pub json_kind: Kind,
    /// The JSON value, if relevant and short; empty if unknown.
    pub json_value: Value,
    /// The Go type involved, if known.
    pub type_info: Option<TypeInfo>,
    /// The underlying error, if any.
    pub err: Option<Error>,
}

impl fmt::Display for SemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sb = String::from(ERROR_PREFIX);
        sb.push_str("cannot");
        let mut preposition = match self.action {
            "marshal" => {
                sb.push_str(" marshal");
                " from"
            }
            "unmarshal" => {
                sb.push_str(" unmarshal");
                " into"
            }
            _ => {
                sb.push_str(" handle");
                " with"
            }
        };
        match self.json_kind {
            KIND_NULL => sb.push_str(" JSON null"),
            KIND_FALSE | KIND_TRUE => sb.push_str(" JSON boolean"),
            KIND_STRING => sb.push_str(" JSON string"),
            KIND_NUMBER => sb.push_str(" JSON number"),
            KIND_BEGIN_OBJECT | KIND_END_OBJECT => sb.push_str(" JSON object"),
            KIND_BEGIN_ARRAY | KIND_END_ARRAY => sb.push_str(" JSON array"),
            _ => {
                if self.action.is_empty() {
                    preposition = "";
                }
            }
        }
        if !self.json_value.0.is_empty() && self.json_value.0.len() < 100 {
            sb.push(' ');
            sb.push_str(&jsontext::lossy_string(&self.json_value.0));
        }
        if let Some(t) = &self.type_info {
            let mut type_string = t.name.clone();
            if type_string.len() > 100 {
                type_string = t.kind.to_string();
            }
            sb.push_str(preposition);
            sb.push_str(" Go ");
            sb.push_str(&type_string);
        }
        if matches!(self.err, Some(Error::UnknownName | Error::AmbiguousName)) {
            sb.push_str(": ");
            sb.push_str(&self.err.as_ref().expect("error").to_string());
            sb.push(' ');
            sb.push_str(&strconv::quote(self.json_pointer.last_token()));
            let parent = self.json_pointer.parent();
            if !parent.as_str().is_empty() {
                sb.push_str(" within ");
                sb.push_str(&strconv::quote(jsontext::truncate_pointer(
                    parent.as_str(),
                    100,
                )));
            }
            return f.write_str(&sb);
        }
        let serr = match &self.err {
            Some(Error::Syntactic(s)) => Some(s),
            _ => None,
        };
        if !self.json_pointer.as_str().is_empty() {
            if serr.is_none_or(|s| !self.json_pointer.contains(&s.json_pointer)) {
                sb.push_str(" within ");
                sb.push_str(&strconv::quote(jsontext::truncate_pointer(
                    self.json_pointer.as_str(),
                    100,
                )));
            }
        } else if self.byte_offset > 0 && serr.is_none_or(|s| self.byte_offset > s.byte_offset) {
            sb.push_str(" after offset ");
            sb.push_str(&self.byte_offset.to_string());
        }
        if let Some(err) = &self.err {
            let mut s = err.to_string();
            if matches!(err, Error::Syntactic(_)) {
                if let Some(rest) = s.strip_prefix("jsontext: ") {
                    s = rest.to_string();
                }
            }
            sb.push_str(": ");
            sb.push_str(&s);
        }
        f.write_str(&sb)
    }
}

impl std::error::Error for SemanticError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.err.as_ref().map(|e| e as _)
    }
}

pub(crate) fn is_semantic_error(err: &Error) -> bool {
    matches!(err, Error::Semantic(_))
}

pub(crate) fn is_syntactic_error(err: &Error) -> bool {
    matches!(err, Error::Syntactic(_))
}

fn to_unexpected_eof(err: Option<Error>) -> Option<Error> {
    match err {
        Some(Error::Eof) => Some(Error::UnexpectedEof),
        other => other,
    }
}

/// `newMarshalErrorBefore`: an error positioned just before the next value.
pub(crate) fn marshal_error_before(
    enc: &mut Encoder<'_>,
    t: Option<TypeInfo>,
    err: Option<Error>,
) -> Error {
    let mut ptr = Vec::new();
    enc.s.append_stack_pointer(&mut ptr, 1);
    Error::Semantic(Box::new(SemanticError {
        action: "marshal",
        type_info: t,
        err: to_unexpected_eof(err),
        byte_offset: enc.output_offset() + enc.s.count_next_delim_whitespace() as i64,
        json_pointer: Pointer::from(String::from_utf8_lossy(&ptr).into_owned()),
        ..Default::default()
    }))
}

/// `newUnmarshalErrorBefore`: an error positioned just before the next value.
pub(crate) fn unmarshal_error_before(
    dec: &mut Decoder<'_>,
    t: Option<TypeInfo>,
    err: Option<Error>,
) -> Error {
    let offset = dec.input_offset() + dec.s.count_next_delim_whitespace() as i64;
    let mut ptr = Vec::new();
    dec.s.append_stack_pointer(&mut ptr, 1);
    Error::Semantic(Box::new(SemanticError {
        action: "unmarshal",
        type_info: t,
        err: to_unexpected_eof(err),
        byte_offset: offset,
        json_pointer: Pointer::from(String::from_utf8_lossy(&ptr).into_owned()),
        ..Default::default()
    }))
}

/// `newUnmarshalErrorAfter`: an error positioned at the last token or value.
pub(crate) fn unmarshal_error_after(
    dec: &mut Decoder<'_>,
    t: Option<TypeInfo>,
    err: Option<Error>,
) -> Error {
    let tok_or_val = dec.s.previous_token_or_value().to_vec();
    let byte_offset = dec.input_offset() - tok_or_val.len() as i64;
    let mut ptr = Vec::new();
    dec.s.append_stack_pointer(&mut ptr, -1);
    Error::Semantic(Box::new(SemanticError {
        action: "unmarshal",
        type_info: t,
        err: to_unexpected_eof(err),
        byte_offset,
        json_pointer: Pointer::from(String::from_utf8_lossy(&ptr).into_owned()),
        json_kind: Value(tok_or_val).kind(),
        ..Default::default()
    }))
}

/// `newUnmarshalErrorAfterWithValue`: like [`unmarshal_error_after`],
/// keeping the text of a string or number value.
pub(crate) fn unmarshal_error_after_with_value(
    dec: &mut Decoder<'_>,
    t: Option<TypeInfo>,
    err: Option<Error>,
) -> Error {
    let Error::Semantic(mut serr) = unmarshal_error_after(dec, t, err) else {
        unreachable!("newUnmarshalErrorAfter returns a SemanticError");
    };
    if serr.json_kind == KIND_STRING || serr.json_kind == KIND_NUMBER {
        serr.json_value = Value(dec.s.previous_token_or_value().to_vec());
    }
    Error::Semantic(serr)
}

/// `newSemanticErrorWithPosition`: positions an error returned by user code
/// from the state of the coder before and after the call.
pub(crate) fn semantic_error_with_position_enc(
    enc: &mut Encoder<'_>,
    t: Option<TypeInfo>,
    prev_depth: usize,
    prev_length: i64,
    err: Error,
) -> Error {
    let mut serr = match err {
        Error::Semantic(s) => *s,
        other => SemanticError {
            err: Some(other),
            ..Default::default()
        },
    };
    serr.err = to_unexpected_eof(serr.err.take());
    if serr.action.is_empty() {
        serr.action = "marshal";
    }
    let (curr_depth, curr_length) = enc.s.state.tokens.depth_length();
    let offset = enc.output_offset() + enc.s.count_next_delim_whitespace() as i64;
    if serr.byte_offset == 0 {
        serr.byte_offset = offset;
    }
    if serr.json_pointer.as_str().is_empty() {
        let mut where_ = 0;
        if prev_depth == curr_depth && prev_length == curr_length {
            where_ = 1;
        } else if prev_depth == curr_depth && prev_length + 1 == curr_length {
            where_ = -1;
        }
        let mut ptr = Vec::new();
        enc.s.append_stack_pointer(&mut ptr, where_);
        serr.json_pointer = Pointer::from(String::from_utf8_lossy(&ptr).into_owned());
    }
    if serr.type_info.is_none() {
        serr.type_info = t;
    }
    Error::Semantic(Box::new(serr))
}

/// The decoder counterpart of [`semantic_error_with_position_enc`].
pub(crate) fn semantic_error_with_position_dec(
    dec: &mut Decoder<'_>,
    t: Option<TypeInfo>,
    prev_depth: usize,
    prev_length: i64,
    err: Error,
) -> Error {
    let mut serr = match err {
        Error::Semantic(s) => *s,
        other => SemanticError {
            err: Some(other),
            ..Default::default()
        },
    };
    serr.err = to_unexpected_eof(serr.err.take());
    if serr.action.is_empty() {
        serr.action = "unmarshal";
    }
    let (curr_depth, curr_length) = dec.s.state.tokens.depth_length();
    let tok_or_val_len = dec.s.previous_token_or_value().len() as i64;
    let mut offset = dec.input_offset() - tok_or_val_len;
    if (prev_depth == curr_depth && prev_length == curr_length) || tok_or_val_len == 0 {
        offset = dec.input_offset() + dec.s.count_next_delim_whitespace() as i64;
    }
    if serr.byte_offset == 0 {
        serr.byte_offset = offset;
    }
    if serr.json_pointer.as_str().is_empty() {
        let mut where_ = 0;
        if prev_depth == curr_depth && prev_length == curr_length {
            where_ = 1;
        } else if prev_depth == curr_depth && prev_length + 1 == curr_length {
            where_ = -1;
        }
        let mut ptr = Vec::new();
        dec.s.append_stack_pointer(&mut ptr, where_);
        serr.json_pointer = Pointer::from(String::from_utf8_lossy(&ptr).into_owned());
    }
    if serr.type_info.is_none() {
        serr.type_info = t;
    }
    Error::Semantic(Box::new(serr))
}

/// `collapseSemanticErrors`: merges a `SemanticError` wrapping another one.
pub(crate) fn collapse_semantic_errors(err: Error) -> Error {
    if let Error::Semantic(mut serr1) = err {
        if matches!(serr1.err, Some(Error::Semantic(_))) {
            let Some(Error::Semantic(serr2)) = serr1.err.take() else {
                unreachable!("checked above");
            };
            let mut serr2 = *serr2;
            serr2.byte_offset += serr1.byte_offset;
            let joined = format!("{}{}", serr1.json_pointer, serr2.json_pointer);
            serr2.json_pointer = Pointer::from(joined);
            return Error::Semantic(Box::new(serr2));
        }
        return Error::Semantic(serr1);
    }
    err
}

/// `wrapErrUnsupported`: user code may not return `errors.ErrUnsupported`
/// from these functions.
pub(crate) fn wrap_err_unsupported(err: Error, what: &str) -> Error {
    if is_unsupported(&err) {
        return Error::msg(&format!("{what} may not return errors.ErrUnsupported"));
    }
    err
}

/// Reports whether the error is `errors.ErrUnsupported` or wraps it.
pub(crate) fn is_unsupported(err: &Error) -> bool {
    let target = crate::error::Message::unsupported();
    let mut cur = Some(err);
    while let Some(e) = cur {
        if let Error::Other(o) = e {
            if crate::error::is(o.as_ref(), &target) {
                return true;
            }
        }
        cur = e.inner();
    }
    false
}

/// `newDuplicateNameError`.
pub(crate) fn duplicate_name_error_at(
    ptr: Pointer,
    quoted_name: Option<&[u8]>,
    offset: i64,
) -> Error {
    let mut ptr = ptr;
    if let Some(q) = quoted_name {
        let mut name = Vec::new();
        let _ = jsontext::append_unquote(&mut name, q);
        ptr = ptr.append_token(&String::from_utf8_lossy(&name));
    }
    Error::Syntactic(Box::new(jsontext::SyntacticError {
        byte_offset: offset,
        json_pointer: ptr,
        err: Some(Error::DuplicateName),
    }))
}
