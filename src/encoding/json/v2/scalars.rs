//! The default arshalers of booleans, strings, integers and floating-point
//! numbers, ported from Go's `arshal_default.go`.
use super::arshal::{MarshalTo, UnmarshalFrom};
use super::errors::{
    err_invalid_string_tag, marshal_error_before, unmarshal_error_after,
    unmarshal_error_after_with_value, unmarshal_error_before,
};
use super::typeinfo::{TypeInfo, TypeKind};
use crate::encoding::json::jsontext::flags;
use crate::encoding::json::jsontext::{
    self, wire, Decoder, Encoder, Error, Value, ValueFlags, KIND_NULL, KIND_NUMBER, KIND_STRING,
};
use crate::strconv;

/// Go's `fmt.Errorf("invalid format flag %q", format)`, positioned before
/// the next value of an encoder.
pub(crate) fn invalid_format_error_enc(enc: &mut Encoder<'_>, t: TypeInfo) -> Error {
    let err = Error::msg(&format!(
        "invalid format flag {}",
        strconv::quote(&enc.s.opts.format)
    ));
    marshal_error_before(enc, Some(t), Some(err))
}

/// Like [`invalid_format_error_enc`], for a decoder.
pub(crate) fn invalid_format_error_dec(dec: &mut Decoder<'_>, t: TypeInfo) -> Error {
    let err = Error::msg(&format!(
        "invalid format flag {}",
        strconv::quote(&dec.s.opts.format)
    ));
    unmarshal_error_before(dec, Some(t), Some(err))
}

/// The tag checks of the kinds that accept neither the `string` nor the
/// `format` tag option: bool, string, struct and array.
pub(crate) fn reject_tags_enc(enc: &mut Encoder<'_>, t: &TypeInfo) -> Result<(), Error> {
    if enc.s.opts.flags.has(flags::TAG_FLAGS) {
        if enc.s.opts.flags.get(flags::STRING_TAG) {
            return Err(marshal_error_before(
                enc,
                Some(t.clone()),
                Some(err_invalid_string_tag()),
            ));
        }
        if enc.s.opts.flags.has(flags::FORMAT_TAG) {
            return Err(invalid_format_error_enc(enc, t.clone()));
        }
    }
    Ok(())
}

/// Like [`reject_tags_enc`], for a decoder.
pub(crate) fn reject_tags_dec(dec: &mut Decoder<'_>, t: &TypeInfo) -> Result<(), Error> {
    if dec.s.opts.flags.has(flags::TAG_FLAGS) {
        if dec.s.opts.flags.get(flags::STRING_TAG) {
            return Err(unmarshal_error_before(
                dec,
                Some(t.clone()),
                Some(err_invalid_string_tag()),
            ));
        }
        if dec.s.opts.flags.has(flags::FORMAT_TAG) {
            return Err(invalid_format_error_dec(dec, t.clone()));
        }
    }
    Ok(())
}

fn strconv_error(e: strconv::Error) -> Error {
    Error::other(e)
}

// ------------------------------------------------------------------- bool

impl MarshalTo for bool {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<bool>("bool", TypeKind::Bool)
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        reject_tags_enc(enc, &<Self as MarshalTo>::type_info())?;
        enc.write_token(&jsontext::bool(*self))
    }
    fn is_zero_value(&self) -> bool {
        !*self
    }
}

impl UnmarshalFrom for bool {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<bool>("bool", TypeKind::Bool)
    }
    fn zero() -> Self {
        false
    }
    fn set_zero(&mut self) {
        *self = false;
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = <Self as UnmarshalFrom>::type_info();
        reject_tags_dec(dec, &t)?;
        let tok = dec.read_token()?;
        match tok.kind() {
            jsontext::KIND_NULL => {
                *self = false;
                Ok(())
            }
            jsontext::KIND_TRUE | jsontext::KIND_FALSE => {
                *self = tok.bool();
                Ok(())
            }
            _ => Err(unmarshal_error_after(dec, Some(t), None)),
        }
    }
}

// ----------------------------------------------------------------- string

impl MarshalTo for String {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<String>("string", TypeKind::String)
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        reject_tags_enc(enc, &<Self as MarshalTo>::type_info())?;
        enc.write_token(&jsontext::string(self))
    }
    fn is_zero_value(&self) -> bool {
        self.is_empty()
    }
    fn is_empty_value(&self) -> Option<bool> {
        Some(self.is_empty())
    }
    fn as_str_key(&self) -> Option<&str> {
        Some(self)
    }
}

impl UnmarshalFrom for String {
    fn from_str_key(s: &str) -> Option<Self> {
        Some(s.to_string())
    }
    fn type_info() -> TypeInfo {
        TypeInfo::of::<String>("string", TypeKind::String)
    }
    fn zero() -> Self {
        String::new()
    }
    fn set_zero(&mut self) {
        self.clear();
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = <Self as UnmarshalFrom>::type_info();
        reject_tags_dec(dec, &t)?;
        let mut vf = ValueFlags::default();
        let val = dec.s.read_value(&mut vf)?;
        match Value(val.clone()).kind() {
            KIND_NULL => {
                self.clear();
                Ok(())
            }
            KIND_STRING => {
                let s = wire::unquote_may_copy(&val, vf.is_verbatim());
                *self = String::from_utf8_lossy(&s).into_owned();
                Ok(())
            }
            _ => Err(unmarshal_error_after(dec, Some(t), None)),
        }
    }
}

// --------------------------------------------------------------- integers

macro_rules! int_arshaler {
    ($($ty:ty, $name:expr, $kind:ident, $bits:expr, signed);+ $(;)?) => { $(
        impl MarshalTo for $ty {
            fn type_info() -> TypeInfo {
                TypeInfo::of::<$ty>($name, TypeKind::$kind)
            }
            fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
                let stringify = enc.s.state.tokens.last.need_object_name()
                    || enc.s.opts.flags.get(flags::STRINGIFY_NUMBERS | flags::STRING_TAG);
                if enc.s.opts.flags.has(flags::FORMAT_TAG) {
                    return Err(invalid_format_error_enc(enc, <Self as MarshalTo>::type_info()));
                }
                let k = if stringify { KIND_STRING } else { KIND_NUMBER };
                let v = *self as i64;
                enc.s.append_raw(k, true, |b| {
                    strconv::append_int(b, v, 10);
                    Ok(())
                })
            }
            fn is_zero_value(&self) -> bool {
                *self == 0
            }
        }
        impl UnmarshalFrom for $ty {
            fn type_info() -> TypeInfo {
                TypeInfo::of::<$ty>($name, TypeKind::$kind)
            }
            fn zero() -> Self {
                0
            }
            fn set_zero(&mut self) {
                *self = 0;
            }
            fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
                let t = <Self as UnmarshalFrom>::type_info();
                match unmarshal_int(dec, &t, $bits)? {
                    Some(n) => *self = n as $ty,
                    None => *self = 0,
                }
                Ok(())
            }
        }
    )+ };
}

macro_rules! uint_arshaler {
    ($($ty:ty, $name:expr, $kind:ident, $bits:expr);+ $(;)?) => { $(
        impl MarshalTo for $ty {
            fn type_info() -> TypeInfo {
                TypeInfo::of::<$ty>($name, TypeKind::$kind)
            }
            fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
                let stringify = enc.s.state.tokens.last.need_object_name()
                    || enc.s.opts.flags.get(flags::STRINGIFY_NUMBERS | flags::STRING_TAG);
                if enc.s.opts.flags.has(flags::FORMAT_TAG) {
                    return Err(invalid_format_error_enc(enc, <Self as MarshalTo>::type_info()));
                }
                let k = if stringify { KIND_STRING } else { KIND_NUMBER };
                let v = *self as u64;
                enc.s.append_raw(k, true, |b| {
                    strconv::append_uint(b, v, 10);
                    Ok(())
                })
            }
            fn is_zero_value(&self) -> bool {
                *self == 0
            }
        }
        impl UnmarshalFrom for $ty {
            fn type_info() -> TypeInfo {
                TypeInfo::of::<$ty>($name, TypeKind::$kind)
            }
            fn zero() -> Self {
                0
            }
            fn set_zero(&mut self) {
                *self = 0;
            }
            fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
                let t = <Self as UnmarshalFrom>::type_info();
                match unmarshal_uint(dec, &t, $bits)? {
                    Some(n) => *self = n as $ty,
                    None => *self = 0,
                }
                Ok(())
            }
        }
    )+ };
}

int_arshaler!(
    i8, "int8", Int8, 8, signed;
    i16, "int16", Int16, 16, signed;
    i32, "int32", Int32, 32, signed;
    i64, "int64", Int64, 64, signed;
    isize, "int", Int, 64, signed;
);
uint_arshaler!(
    u8, "uint8", Uint8, 8;
    u16, "uint16", Uint16, 16;
    u32, "uint32", Uint32, 32;
    u64, "uint64", Uint64, 64;
    usize, "uint", Uint, 64;
);

/// The integer unmarshal of Go's `makeIntArshaler`. `None` means JSON null.
fn unmarshal_int(dec: &mut Decoder<'_>, t: &TypeInfo, bits: u32) -> Result<Option<i64>, Error> {
    let stringify = dec.s.state.tokens.last.need_object_name()
        || dec
            .s
            .opts
            .flags
            .get(flags::STRINGIFY_NUMBERS | flags::STRING_TAG);
    if dec.s.opts.flags.has(flags::FORMAT_TAG) {
        return Err(invalid_format_error_dec(dec, t.clone()));
    }
    let mut vf = ValueFlags::default();
    let mut val = dec.s.read_value(&mut vf)?;
    let k = Value(val.clone()).kind();
    match k {
        KIND_NULL => Ok(None),
        KIND_STRING | KIND_NUMBER => {
            if k == KIND_STRING {
                if !stringify {
                    return Err(unmarshal_error_after(dec, Some(t.clone()), None));
                }
                val = wire::unquote_may_copy(&val, vf.is_verbatim());
            } else if stringify {
                return Err(unmarshal_error_after(dec, Some(t.clone()), None));
            }
            let neg = val.first() == Some(&b'-');
            let (n, ok) = wire::parse_uint(&val[neg as usize..]);
            let max_int = 1u64 << (bits - 1);
            let mut overflow = (neg && n > max_int) || (!neg && n > max_int - 1);
            if !ok {
                if n != u64::MAX {
                    return Err(unmarshal_error_after_with_value(
                        dec,
                        Some(t.clone()),
                        Some(strconv_error(strconv::ERR_SYNTAX)),
                    ));
                }
                overflow = true;
            }
            if overflow {
                return Err(unmarshal_error_after_with_value(
                    dec,
                    Some(t.clone()),
                    Some(strconv_error(strconv::ERR_RANGE)),
                ));
            }
            Ok(Some(if neg {
                (n as i64).wrapping_neg()
            } else {
                n as i64
            }))
        }
        _ => Err(unmarshal_error_after(dec, Some(t.clone()), None)),
    }
}

/// The unsigned integer unmarshal of Go's `makeUintArshaler`.
fn unmarshal_uint(dec: &mut Decoder<'_>, t: &TypeInfo, bits: u32) -> Result<Option<u64>, Error> {
    let stringify = dec.s.state.tokens.last.need_object_name()
        || dec
            .s
            .opts
            .flags
            .get(flags::STRINGIFY_NUMBERS | flags::STRING_TAG);
    if dec.s.opts.flags.has(flags::FORMAT_TAG) {
        return Err(invalid_format_error_dec(dec, t.clone()));
    }
    let mut vf = ValueFlags::default();
    let mut val = dec.s.read_value(&mut vf)?;
    let k = Value(val.clone()).kind();
    match k {
        KIND_NULL => Ok(None),
        KIND_STRING | KIND_NUMBER => {
            if k == KIND_STRING {
                if !stringify {
                    return Err(unmarshal_error_after(dec, Some(t.clone()), None));
                }
                val = wire::unquote_may_copy(&val, vf.is_verbatim());
            } else if stringify {
                return Err(unmarshal_error_after(dec, Some(t.clone()), None));
            }
            let (n, ok) = wire::parse_uint(&val);
            let mut overflow = bits < 64 && n > (1u64 << bits) - 1;
            if !ok {
                if n != u64::MAX {
                    return Err(unmarshal_error_after_with_value(
                        dec,
                        Some(t.clone()),
                        Some(strconv_error(strconv::ERR_SYNTAX)),
                    ));
                }
                overflow = true;
            }
            if overflow {
                return Err(unmarshal_error_after_with_value(
                    dec,
                    Some(t.clone()),
                    Some(strconv_error(strconv::ERR_RANGE)),
                ));
            }
            Ok(Some(n))
        }
        _ => Err(unmarshal_error_after(dec, Some(t.clone()), None)),
    }
}

// ----------------------------------------------------------------- floats

/// Go's `%v` of a non-finite `float64`.
fn non_finite_text(f: f64) -> &'static str {
    if f.is_nan() {
        "NaN"
    } else if f > 0.0 {
        "+Inf"
    } else {
        "-Inf"
    }
}

fn marshal_float(enc: &mut Encoder<'_>, t: TypeInfo, fv: f64, bits: i32) -> Result<(), Error> {
    let stringify = enc.s.state.tokens.last.need_object_name()
        || enc
            .s
            .opts
            .flags
            .get(flags::STRINGIFY_NUMBERS | flags::STRING_TAG);
    let mut allow_non_finite = false;
    if enc.s.opts.flags.has(flags::FORMAT_TAG) {
        if enc.s.opts.format == "nonfinite" {
            allow_non_finite = true;
        } else {
            return Err(invalid_format_error_enc(enc, t));
        }
    }
    if fv.is_nan() || fv.is_infinite() {
        if !allow_non_finite {
            let err = Error::msg(&format!("unsupported value: {}", non_finite_text(fv)));
            return Err(marshal_error_before(enc, Some(t), Some(err)));
        }
        return enc.write_token(&jsontext::float(fv));
    }
    let k = if stringify { KIND_STRING } else { KIND_NUMBER };
    enc.s.append_raw(k, true, |b| {
        wire::append_float(b, fv, bits);
        Ok(())
    })
}

/// The float unmarshal of Go's `makeFloatArshaler`. `Ok(None)` means JSON
/// null; an error may come with the value Go stores before returning it.
fn unmarshal_float(
    dec: &mut Decoder<'_>,
    t: &TypeInfo,
    bits: i32,
) -> Result<Option<f64>, (Option<f64>, Error)> {
    let stringify = dec.s.state.tokens.last.need_object_name()
        || dec
            .s
            .opts
            .flags
            .get(flags::STRINGIFY_NUMBERS | flags::STRING_TAG);
    let mut allow_non_finite = false;
    if dec.s.opts.flags.has(flags::FORMAT_TAG) {
        if dec.s.opts.format == "nonfinite" {
            allow_non_finite = true;
        } else {
            return Err((None, invalid_format_error_dec(dec, t.clone())));
        }
    }
    let mut vf = ValueFlags::default();
    let mut val = dec.s.read_value(&mut vf).map_err(|e| (None, e))?;
    let k = Value(val.clone()).kind();
    match k {
        KIND_NULL => Ok(None),
        KIND_STRING | KIND_NUMBER => {
            if k == KIND_STRING {
                val = wire::unquote_may_copy(&val, vf.is_verbatim());
                if allow_non_finite {
                    match val.as_slice() {
                        b"NaN" => return Ok(Some(jsontext::NAN)),
                        b"Infinity" => return Ok(Some(f64::INFINITY)),
                        b"-Infinity" => return Ok(Some(f64::NEG_INFINITY)),
                        _ => {}
                    }
                }
                if !stringify {
                    return Err((None, unmarshal_error_after(dec, Some(t.clone()), None)));
                }
                let (n, err) = wire::consume_number(&val);
                if n != val.len() || err.is_some() {
                    return Err((
                        None,
                        unmarshal_error_after_with_value(
                            dec,
                            Some(t.clone()),
                            Some(strconv_error(strconv::ERR_SYNTAX)),
                        ),
                    ));
                }
            } else if stringify {
                return Err((None, unmarshal_error_after(dec, Some(t.clone()), None)));
            }
            let text = String::from_utf8_lossy(&val).into_owned();
            let (fv, err) = match strconv::parse_float(&text, bits) {
                Ok(v) => (v, None),
                Err(e) => (e.float_value(), Some(e)),
            };
            if let Some(e) = err {
                // Go stores the (infinite) result before reporting the error.
                return Err((
                    Some(fv),
                    unmarshal_error_after_with_value(
                        dec,
                        Some(t.clone()),
                        Some(strconv_error(e.err)),
                    ),
                ));
            }
            Ok(Some(fv))
        }
        _ => Err((None, unmarshal_error_after(dec, Some(t.clone()), None))),
    }
}

impl MarshalTo for f64 {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<f64>("float64", TypeKind::Float64)
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        marshal_float(enc, <Self as MarshalTo>::type_info(), *self, 64)
    }
    fn is_zero_value(&self) -> bool {
        *self == 0.0
    }
}

impl UnmarshalFrom for f64 {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<f64>("float64", TypeKind::Float64)
    }
    fn zero() -> Self {
        0.0
    }
    fn set_zero(&mut self) {
        *self = 0.0;
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = <Self as UnmarshalFrom>::type_info();
        match unmarshal_float(dec, &t, 64) {
            Ok(Some(v)) => *self = v,
            Ok(None) => *self = 0.0,
            Err((v, e)) => {
                if let Some(v) = v {
                    *self = v;
                }
                return Err(e);
            }
        }
        Ok(())
    }
}

impl MarshalTo for f32 {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<f32>("float32", TypeKind::Float32)
    }
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error> {
        marshal_float(enc, <Self as MarshalTo>::type_info(), f64::from(*self), 32)
    }
    fn is_zero_value(&self) -> bool {
        *self == 0.0
    }
}

impl UnmarshalFrom for f32 {
    fn type_info() -> TypeInfo {
        TypeInfo::of::<f32>("float32", TypeKind::Float32)
    }
    fn zero() -> Self {
        0.0
    }
    fn set_zero(&mut self) {
        *self = 0.0;
    }
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        let t = <Self as UnmarshalFrom>::type_info();
        match unmarshal_float(dec, &t, 32) {
            Ok(Some(v)) => *self = v as f32,
            Ok(None) => *self = 0.0,
            Err((v, e)) => {
                if let Some(v) = v {
                    *self = v as f32;
                }
                return Err(e);
            }
        }
        Ok(())
    }
}
