//! Types that customize their own JSON: the [`Marshaler`], [`MarshalerTo`],
//! [`Unmarshaler`] and [`UnmarshalerFrom`] traits, and the logic that calls
//! them, ported from Go's `arshal_methods.go`.
use super::arshal::{MarshalTo, UnmarshalFrom};
use super::errors::{
    collapse_semantic_errors, err_non_singular_value, err_non_string_value,
    err_unsupported_mutation, is_semantic_error, is_syntactic_error, is_unsupported,
    marshal_error_before, semantic_error_with_position_dec, semantic_error_with_position_enc,
    unmarshal_error_after, wrap_err_unsupported,
};
use crate::encoding::json::jsontext::flags;
use crate::encoding::json::jsontext::{
    self, Decoder, Encoder, Error, Value, ValueFlags, KIND_NULL, KIND_STRING,
};

pub use crate::encoding::{TextAppender, TextMarshaler, TextUnmarshaler};

/// Go's `json.Marshaler`: a type that produces its own JSON text.
pub trait Marshaler {
    /// Go's `MarshalJSON`: returns exactly one JSON value.
    fn marshal_json(&self) -> Result<Vec<u8>, Error>;
}

/// Go's `json.MarshalerTo`: a type that writes its own JSON to an encoder.
pub trait MarshalerTo {
    /// Go's `MarshalJSONTo`: writes exactly one JSON value to `enc`. It may
    /// return `errors.ErrUnsupported` before writing anything to defer to the
    /// default behaviour.
    fn marshal_json_to(&self, enc: &mut Encoder<'_>) -> Result<(), Error>;
}

/// Go's `json.Unmarshaler`: a type that parses its own JSON text.
pub trait Unmarshaler {
    /// Go's `UnmarshalJSON`: receives exactly one JSON value.
    fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), Error>;
}

/// Go's `json.UnmarshalerFrom`: a type that reads its own JSON from a
/// decoder.
pub trait UnmarshalerFrom {
    /// Go's `UnmarshalJSONFrom`: reads exactly one JSON value from `dec`. It
    /// may return `errors.ErrUnsupported` before reading anything to defer to
    /// the default behaviour.
    fn unmarshal_json_from(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error>;
}

fn boxed(e: Box<dyn std::error::Error>) -> Error {
    Error::msg(&e.to_string())
}

/// The marshal function of a type with methods (`makeMethodArshaler`).
pub(crate) fn marshal<T: MarshalTo>(v: &T, enc: &mut Encoder<'_>) -> Result<(), Error> {
    marshal_level(v, enc, 4)
}

fn marshal_level<T: MarshalTo>(v: &T, enc: &mut Encoder<'_>, level: u8) -> Result<(), Error> {
    let t = Some(T::type_info());
    match level {
        4 => {
            let Some(m) = v.as_marshaler_to() else {
                return marshal_level(v, enc, 3);
            };
            let (prev_depth, prev_length) = enc.s.state.tokens.depth_length();
            enc.s.opts.flags.set(flags::WITHIN_ARSHAL_CALL, true);
            let mut err = m.marshal_json_to(enc).err();
            enc.s.opts.flags.set(flags::WITHIN_ARSHAL_CALL, false);
            let (curr_depth, curr_length) = enc.s.state.tokens.depth_length();
            if err.is_none() && (prev_depth != curr_depth || prev_length + 1 != curr_length) {
                err = Some(err_non_singular_value());
            }
            if let Some(mut e) = err {
                if is_unsupported(&e) {
                    if prev_depth == curr_depth && prev_length == curr_length {
                        return marshal_level(v, enc, 3);
                    }
                    e = err_unsupported_mutation();
                }
                if !e.is_io_error() {
                    e = semantic_error_with_position_enc(enc, t, prev_depth, prev_length, e);
                }
                return Err(e);
            }
            Ok(())
        }
        3 => {
            let Some(m) = v.as_marshaler() else {
                return marshal_level(v, enc, 2);
            };
            let val = match m.marshal_json() {
                Ok(val) => val,
                Err(err) => {
                    let err = wrap_err_unsupported(err, "MarshalJSON method");
                    let err = marshal_error_before(enc, t, Some(err));
                    return Err(collapse_semantic_errors(err));
                }
            };
            if let Err(mut err) = enc.write_value(&Value(val)) {
                if is_syntactic_error(&err) {
                    err = marshal_error_before(enc, t, Some(err));
                }
                return Err(err);
            }
            Ok(())
        }
        2 => {
            let Some(a) = v.as_text_appender() else {
                return marshal_level(v, enc, 1);
            };
            let r = enc.s.append_raw(jsontext::KIND_STRING, false, |b| {
                a.append_text(b).map_err(boxed)
            });
            wrap_text_marshal_error(enc, t, r, "AppendText method")
        }
        1 => {
            let Some(m) = v.as_text_marshaler() else {
                return marshal_level(v, enc, 0);
            };
            let r = enc.s.append_raw(jsontext::KIND_STRING, false, |b| {
                let b2 = m.marshal_text().map_err(boxed)?;
                b.extend_from_slice(&b2);
                Ok(())
            });
            wrap_text_marshal_error(enc, t, r, "MarshalText method")
        }
        _ => v.marshal_default(enc),
    }
}

fn wrap_text_marshal_error(
    enc: &mut Encoder<'_>,
    t: Option<super::typeinfo::TypeInfo>,
    r: Result<(), Error>,
    what: &str,
) -> Result<(), Error> {
    match r {
        Ok(()) => Ok(()),
        Err(err) => {
            let mut err = wrap_err_unsupported(err, what);
            if !is_semantic_error(&err) && !err.is_io_error() {
                err = marshal_error_before(enc, t, Some(err));
            }
            Err(err)
        }
    }
}

/// The unmarshal function of a type with methods.
pub(crate) fn unmarshal<T: UnmarshalFrom>(v: &mut T, dec: &mut Decoder<'_>) -> Result<(), Error> {
    unmarshal_level(v, dec, 3)
}

fn unmarshal_level<T: UnmarshalFrom>(
    v: &mut T,
    dec: &mut Decoder<'_>,
    level: u8,
) -> Result<(), Error> {
    let t = Some(T::type_info());
    match level {
        3 => {
            if v.as_unmarshaler_from().is_none() {
                return unmarshal_level(v, dec, 2);
            }
            let (prev_depth, prev_length) = dec.s.state.tokens.depth_length();
            if prev_depth == 1 && dec.s.at_eof() {
                return Err(Error::Eof);
            }
            dec.s.opts.flags.set(flags::WITHIN_ARSHAL_CALL, true);
            let m = v.as_unmarshaler_from().expect("checked above");
            let mut err = m.unmarshal_json_from(dec).err();
            dec.s.opts.flags.set(flags::WITHIN_ARSHAL_CALL, false);
            let (curr_depth, curr_length) = dec.s.state.tokens.depth_length();
            if err.is_none() && (prev_depth != curr_depth || prev_length + 1 != curr_length) {
                err = Some(err_non_singular_value());
            }
            if let Some(mut e) = err {
                if is_unsupported(&e) {
                    if prev_depth == curr_depth && prev_length == curr_length {
                        return unmarshal_level(v, dec, 2);
                    }
                    e = err_unsupported_mutation();
                }
                if !is_syntactic_error(&e) && !e.is_io_error() {
                    e = semantic_error_with_position_dec(dec, t, prev_depth, prev_length, e);
                }
                return Err(e);
            }
            Ok(())
        }
        2 => {
            if v.as_unmarshaler().is_none() {
                return unmarshal_level(v, dec, 1);
            }
            let val = dec.read_value()?;
            let m = v.as_unmarshaler().expect("checked above");
            if let Err(err) = m.unmarshal_json(&val.0) {
                let err = wrap_err_unsupported(err, "UnmarshalJSON method");
                let err = unmarshal_error_after(dec, t, Some(err));
                return Err(collapse_semantic_errors(err));
            }
            Ok(())
        }
        1 => {
            if v.as_text_unmarshaler().is_none() {
                return v.unmarshal_default(dec);
            }
            let mut flags = ValueFlags::default();
            let val = dec.s.read_value(&mut flags)?;
            let kind = Value(val.clone()).kind();
            if kind == KIND_NULL {
                v.set_zero();
                return Ok(());
            }
            if kind != KIND_STRING {
                return Err(unmarshal_error_after(dec, t, Some(err_non_string_value())));
            }
            let s = jsontext::wire::unquote_may_copy(&val, flags.is_verbatim());
            let m = v.as_text_unmarshaler().expect("checked above");
            if let Err(err) = m.unmarshal_text(&s) {
                let mut err = wrap_err_unsupported(boxed(err), "UnmarshalText method");
                if !is_semantic_error(&err) && !is_syntactic_error(&err) && !err.is_io_error() {
                    err = unmarshal_error_after(dec, t, Some(err));
                }
                return Err(err);
            }
            Ok(())
        }
        _ => v.unmarshal_default(dec),
    }
}
