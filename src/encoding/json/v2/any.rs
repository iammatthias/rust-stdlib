//! Go's `any`: the dynamic JSON value ([`Any`]), and `jsontext.Value` as a
//! field type, ported from Go's `arshal_any.go` and the interface part of
//! `arshal_default.go`.
use std::collections::BTreeMap;

use super::arshal::{marshal_value, unmarshal_value, MarshalTo, UnmarshalFrom};
use super::errors::{
    duplicate_name_error_at, err_invalid_string_tag, marshal_error_before,
    unmarshal_error_after_with_value, unmarshal_error_before,
};
use super::methods::{Marshaler, Unmarshaler};
use super::scalars::{invalid_format_error_dec, invalid_format_error_enc};
use super::structs::{jsontext_value_type, FallbackMarshal, FallbackUnmarshal};
use super::typeinfo::{TypeInfo, TypeKind};
use crate::encoding::json::jsontext::flags;
use crate::encoding::json::jsontext::{
    self, Decoder, Encoder, Error, Value, ValueFlags, KIND_BEGIN_ARRAY, KIND_BEGIN_OBJECT,
    KIND_FALSE, KIND_NULL, KIND_NUMBER, KIND_STRING, KIND_TRUE,
};

/// A dynamically typed JSON value: Go's `any` as `encoding/json` fills it
/// (`nil`, `bool`, `float64`, `string`, `[]any`, `map[string]any`).
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Any {
    /// JSON `null` (a nil `any`).
    #[default]
    Null,
    Bool(bool),
    String(String),
    Number(f64),
    Array(Vec<Any>),
    Object(BTreeMap<String, Any>),
}

fn any_type() -> TypeInfo {
    TypeInfo::of::<Any>("interface {}", TypeKind::Interface)
}

impl MarshalTo for Any {
    fn type_info() -> TypeInfo {
        any_type()
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        if enc.s.opts.flags.has(flags::TAG_FLAGS) {
            if enc.s.opts.flags.get(flags::STRING_TAG) {
                return Err(marshal_error_before(
                    enc,
                    Some(any_type()),
                    Some(err_invalid_string_tag()),
                ));
            }
            if enc.s.opts.flags.has(flags::FORMAT_TAG) {
                return Err(invalid_format_error_enc(enc, any_type()));
            }
        }
        match self {
            Any::Null => enc.write_token(&jsontext::null()),
            Any::Bool(b) => marshal_value(enc, b),
            Any::String(s) => marshal_value(enc, s),
            Any::Number(n) => marshal_value(enc, n),
            // The arrays and objects of a decoded `any` are never nil, so
            // the options that write nil as null do not apply to them.
            Any::Array(a) => {
                let saved = enc.s.opts.flags;
                enc.s
                    .opts
                    .flags
                    .clear(flags::FORMAT_NIL_SLICE_AS_NULL | flags::FORMAT_NIL_MAP_AS_NULL);
                let r = marshal_value(enc, a);
                enc.s.opts.flags = saved;
                r
            }
            Any::Object(m) => {
                let saved = enc.s.opts.flags;
                enc.s
                    .opts
                    .flags
                    .clear(flags::FORMAT_NIL_SLICE_AS_NULL | flags::FORMAT_NIL_MAP_AS_NULL);
                let r = marshal_value(enc, m);
                enc.s.opts.flags = saved;
                r
            }
        }
    }
    fn is_zero_value(&self) -> bool {
        matches!(self, Any::Null)
    }
    fn is_empty_value(&self) -> Option<bool> {
        Some(matches!(self, Any::Null))
    }
    fn marshal_to(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        // An interface has no methods of its own: the dynamic value's apply.
        self.marshal_default(enc)
    }
}

impl UnmarshalFrom for Any {
    fn type_info() -> TypeInfo {
        any_type()
    }
    fn zero() -> Self {
        Any::Null
    }
    fn set_zero(&mut self) {
        *self = Any::Null;
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        if dec.s.opts.flags.has(flags::TAG_FLAGS) {
            if dec.s.opts.flags.get(flags::STRING_TAG) {
                return Err(unmarshal_error_before(
                    dec,
                    Some(any_type()),
                    Some(err_invalid_string_tag()),
                ));
            }
            if dec.s.opts.flags.has(flags::FORMAT_TAG) {
                return Err(invalid_format_error_dec(dec, any_type()));
            }
        }
        if dec.peek_kind() == KIND_NULL {
            dec.read_token()?;
            *self = Any::Null;
            return Ok(());
        }
        // A nil `any` is filled by a dedicated, cheaper path unless duplicate
        // names are allowed or a user function may apply to what it holds.
        if matches!(self, Any::Null)
            && !dec
                .s
                .opts
                .flags
                .get(flags::ALLOW_DUPLICATE_NAMES | flags::FORMAT_TAG)
            && !dec.s.opts.unmarshalers.as_ref().is_some_and(|u| u.from_any)
        {
            let (v, err) = unmarshal_value_any(dec);
            if !matches!(v, Any::Null) {
                *self = v;
            }
            return err.map_or(Ok(()), Err);
        }
        // A nil interface takes the type of the JSON value; otherwise the
        // value it holds is unmarshaled into.
        let mut current = std::mem::take(self);
        if matches!(current, Any::Null) {
            current = match dec.peek_kind() {
                KIND_FALSE | KIND_TRUE => Any::Bool(false),
                KIND_STRING => Any::String(String::new()),
                KIND_NUMBER => Any::Number(0.0),
                KIND_BEGIN_OBJECT => Any::Object(BTreeMap::new()),
                KIND_BEGIN_ARRAY => Any::Array(Vec::new()),
                _ => {
                    dec.read_value()?;
                    return Ok(());
                }
            };
        }
        let r = match &mut current {
            Any::Null => Ok(()),
            Any::Bool(v) => unmarshal_value(dec, v),
            Any::String(v) => unmarshal_value(dec, v),
            Any::Number(v) => unmarshal_value(dec, v),
            Any::Array(v) => unmarshal_value(dec, v),
            Any::Object(v) => unmarshal_value(dec, v),
        };
        *self = current;
        r
    }
    fn unmarshal_from(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        self.unmarshal_default(dec)
    }
}

// ------------------------------------------------------ jsontext.Value

impl Marshaler for Value {
    fn marshal_json(&self) -> Result<Vec<u8>, Error> {
        Ok(Value::marshal_json(self))
    }
}

impl Unmarshaler for Value {
    fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), Error> {
        Value::unmarshal_json(self, data);
        Ok(())
    }
}

impl MarshalTo for Value {
    fn type_info() -> TypeInfo {
        jsontext_value_type()
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        enc.write_value(&Value(Value::marshal_json(self)))
    }
    fn is_zero_value(&self) -> bool {
        self.0.is_empty()
    }
    fn is_empty_value(&self) -> Option<bool> {
        Some(self.0.is_empty())
    }
    fn as_marshaler(&self) -> Option<&dyn Marshaler> {
        Some(self)
    }
    fn as_fallback(&self) -> Option<&dyn FallbackMarshal> {
        Some(self)
    }
}

impl UnmarshalFrom for Value {
    fn type_info() -> TypeInfo {
        jsontext_value_type()
    }
    fn zero() -> Self {
        Value(Vec::new())
    }
    fn set_zero(&mut self) {
        self.0.clear();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        *self = dec.read_value()?;
        Ok(())
    }
    fn as_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        Some(self)
    }
    fn as_fallback_mut(&mut self) -> Option<&mut dyn FallbackUnmarshal> {
        Some(self)
    }
}

/// `unmarshalValueAny`: reads one value into a new `any`, returning what was
/// read even when it fails.
fn unmarshal_value_any(dec: &mut Decoder<'_>) -> (Any, Option<Error>) {
    match dec.peek_kind() {
        KIND_BEGIN_OBJECT => unmarshal_object_any(dec),
        KIND_BEGIN_ARRAY => unmarshal_array_any(dec),
        _ => {
            let mut vf = ValueFlags::default();
            let val = match dec.s.read_value(&mut vf) {
                Ok(v) => v,
                Err(e) => return (Any::Null, Some(e)),
            };
            match Value(val.clone()).kind() {
                KIND_NULL => (Any::Null, None),
                KIND_FALSE => (Any::Bool(false), None),
                KIND_TRUE => (Any::Bool(true), None),
                KIND_STRING => {
                    let s = jsontext::wire::unquote_may_copy(&val, vf.is_verbatim());
                    (Any::String(String::from_utf8_lossy(&s).into_owned()), None)
                }
                KIND_NUMBER => {
                    let text = String::from_utf8_lossy(&val).into_owned();
                    let (fv, err) = match crate::strconv::parse_float(&text, 64) {
                        Ok(v) => (v, None),
                        Err(e) => (e.float_value(), Some(e)),
                    };
                    if let Some(e) = err {
                        let err = unmarshal_error_after_with_value(
                            dec,
                            Some(<f64 as UnmarshalFrom>::type_info()),
                            Some(Error::other(e.err)),
                        );
                        return (Any::Number(fv), Some(err));
                    }
                    (Any::Number(fv), None)
                }
                k => panic!("BUG: invalid kind: {}", k),
            }
        }
    }
}

/// `unmarshalObjectAny`.
fn unmarshal_object_any(dec: &mut Decoder<'_>) -> (Any, Option<Error>) {
    if let Err(e) = dec.read_token() {
        return (Any::Null, Some(e));
    }
    let mut obj: BTreeMap<String, Any> = BTreeMap::new();
    if !dec.s.opts.flags.get(flags::ALLOW_INVALID_UTF8) {
        dec.s.state.tokens.last.disable_namespace();
    }
    while dec.peek_kind() != jsontext::KIND_END_OBJECT {
        let tok = match dec.read_token() {
            Ok(t) => t,
            Err(e) => return (Any::Object(obj), Some(e)),
        };
        let name = tok.to_string();
        if obj.contains_key(&name) {
            let name_len = dec.s.previous_token_or_value().len() as i64;
            let mut ptr = Vec::new();
            dec.s.append_stack_pointer(&mut ptr, -1);
            let err = duplicate_name_error_at(
                jsontext::Pointer::from(String::from_utf8_lossy(&ptr).into_owned()),
                None,
                dec.input_offset() - name_len,
            );
            return (Any::Object(obj), Some(err));
        }
        let (val, err) = unmarshal_value_any(dec);
        obj.insert(name, val);
        if let Some(e) = err {
            return (Any::Object(obj), Some(e));
        }
    }
    if let Err(e) = dec.read_token() {
        return (Any::Object(obj), Some(e));
    }
    (Any::Object(obj), None)
}

/// `unmarshalArrayAny`.
fn unmarshal_array_any(dec: &mut Decoder<'_>) -> (Any, Option<Error>) {
    if let Err(e) = dec.read_token() {
        return (Any::Null, Some(e));
    }
    let mut arr: Vec<Any> = Vec::new();
    while dec.peek_kind() != jsontext::KIND_END_ARRAY {
        let (val, err) = unmarshal_value_any(dec);
        arr.push(val);
        if let Some(e) = err {
            return (Any::Array(arr), Some(e));
        }
    }
    if let Err(e) = dec.read_token() {
        return (Any::Array(arr), Some(e));
    }
    (Any::Array(arr), None)
}
