//! User-supplied marshal and unmarshal functions (`Marshalers` and
//! `Unmarshalers`), ported from Go's `arshal_funcs.go`.
//!
//! Go selects a function by whether the value's type is assignable to the
//! function's parameter type, which can be an interface. Rust has no
//! interfaces over arbitrary types, so a function applies to values whose
//! type is exactly `T`.
use std::any::{Any, TypeId};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use super::any::Any as AnyValue;
use super::arshal::{MarshalTo, UnmarshalFrom};
use super::errors::{
    collapse_semantic_errors, err_non_singular_value, err_unsupported_mutation, is_syntactic_error,
    is_unsupported, marshal_error_before, semantic_error_with_position_dec,
    semantic_error_with_position_enc, unmarshal_error_after, wrap_err_unsupported,
};
use super::typeinfo::{TypeInfo, TypeKind};
use crate::encoding::json::jsontext::flags;
use crate::encoding::json::jsontext::{Decoder, Encoder, Error, Value};

type MarshalFn = Arc<dyn Fn(&mut Encoder<'_>, &dyn Any) -> Result<(), Error> + Send + Sync>;
type UnmarshalFn = Arc<dyn Fn(&mut Decoder<'_>, &mut dyn Any) -> Result<(), Error> + Send + Sync>;

#[derive(Clone)]
struct TypedMarshaler {
    type_id: TypeId,
    fnc: MarshalFn,
    may_skip: bool,
}

#[derive(Clone)]
struct TypedUnmarshaler {
    type_id: TypeId,
    fnc: UnmarshalFn,
    may_skip: bool,
}

/// Go's `Marshalers`: a list of marshal functions, tried in order.
#[derive(Clone, Default)]
pub struct Marshalers {
    fncs: Vec<TypedMarshaler>,
    /// Whether any function applies to a type a dynamic `any` can hold.
    pub(crate) from_any: bool,
}

/// Go's `Unmarshalers`: a list of unmarshal functions, tried in order.
#[derive(Clone, Default)]
pub struct Unmarshalers {
    fncs: Vec<TypedUnmarshaler>,
    /// Whether any function applies to a type a dynamic `any` can hold.
    pub(crate) from_any: bool,
}

impl fmt::Debug for Marshalers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Marshalers({} functions)", self.fncs.len())
    }
}

impl fmt::Debug for Unmarshalers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unmarshalers({} functions)", self.fncs.len())
    }
}

/// Go's `JoinMarshalers`: the functions of each, in order. A function
/// earlier in the list takes precedence; one that returns
/// `errors.ErrUnsupported` defers to the next.
pub fn join_marshalers(ms: &[Marshalers]) -> Marshalers {
    Marshalers {
        fncs: ms.iter().flat_map(|m| m.fncs.iter().cloned()).collect(),
        from_any: ms.iter().any(|m| m.from_any),
    }
}

/// Go's `JoinUnmarshalers`: the functions of each, in order.
pub fn join_unmarshalers(us: &[Unmarshalers]) -> Unmarshalers {
    Unmarshalers {
        fncs: us.iter().flat_map(|u| u.fncs.iter().cloned()).collect(),
        from_any: us.iter().any(|u| u.from_any),
    }
}

impl Marshalers {
    /// The functions that apply to values of type `id`, up to and including
    /// the first that cannot defer.
    pub(crate) fn lookup(&self, id: TypeId) -> Vec<MarshalFn> {
        let mut out = Vec::new();
        for f in &self.fncs {
            if f.type_id != id {
                continue;
            }
            out.push(f.fnc.clone());
            if !f.may_skip {
                break;
            }
        }
        out
    }
}

impl Unmarshalers {
    /// The functions that apply to values of type `id`.
    pub(crate) fn lookup(&self, id: TypeId) -> Vec<UnmarshalFn> {
        let mut out = Vec::new();
        for f in &self.fncs {
            if f.type_id != id {
                continue;
            }
            out.push(f.fnc.clone());
            if !f.may_skip {
                break;
            }
        }
        out
    }
}

/// `*T` for the Go type `T`: the type Go's unmarshal functions receive.
fn pointer_to(t: TypeInfo) -> TypeInfo {
    TypeInfo {
        name: format!("*{}", t.name),
        kind: TypeKind::Pointer,
        id: None,
        elem: Some(Box::new(t)),
        key: None,
    }
}

/// Reports whether values of type `T` can be what a dynamic `any` holds
/// (Go's `castableToFromAny`).
fn from_any<T: 'static>() -> bool {
    let id = TypeId::of::<T>();
    [
        TypeId::of::<AnyValue>(),
        TypeId::of::<bool>(),
        TypeId::of::<String>(),
        TypeId::of::<f64>(),
        TypeId::of::<BTreeMap<String, AnyValue>>(),
        TypeId::of::<Vec<AnyValue>>(),
    ]
    .contains(&id)
}

/// Go's `MarshalFunc`: a marshaler of values of type `T` from a function
/// that returns the JSON text. The text must be exactly one JSON value.
pub fn marshal_func<T, F>(fnc: F) -> Marshalers
where
    T: MarshalTo,
    F: Fn(&T) -> Result<Vec<u8>, Error> + Send + Sync + 'static,
{
    let t = T::type_info();
    let f: MarshalFn = Arc::new(move |enc, v| {
        let v = v.downcast_ref::<T>().expect("function type matches value");
        let val = match fnc(v) {
            Ok(val) => val,
            Err(err) => {
                let err =
                    wrap_err_unsupported(err, "marshal function of type func(T) ([]byte, error)");
                let err = marshal_error_before(enc, Some(t.clone()), Some(err));
                return Err(collapse_semantic_errors(err));
            }
        };
        if let Err(mut err) = enc.write_value(&Value(val)) {
            if is_syntactic_error(&err) {
                err = marshal_error_before(enc, Some(t.clone()), Some(err));
            }
            return Err(err);
        }
        Ok(())
    });
    Marshalers {
        fncs: vec![TypedMarshaler {
            type_id: TypeId::of::<T>(),
            fnc: f,
            may_skip: false,
        }],
        from_any: from_any::<T>(),
    }
}

/// Go's `MarshalToFunc`: a marshaler of values of type `T` from a function
/// that writes exactly one value to the encoder. It may return
/// `errors.ErrUnsupported` (without writing) to defer to the next marshaler.
pub fn marshal_to_func<T, F>(fnc: F) -> Marshalers
where
    T: MarshalTo,
    F: Fn(&mut Encoder<'_>, &T) -> Result<(), Error> + Send + Sync + 'static,
{
    let t = T::type_info();
    let f: MarshalFn = Arc::new(move |enc, v| {
        let v = v.downcast_ref::<T>().expect("function type matches value");
        let (prev_depth, prev_length) = enc.s.state.tokens.depth_length();
        enc.s.opts.flags.set(flags::WITHIN_ARSHAL_CALL, true);
        let mut err = fnc(enc, v).err();
        enc.s.opts.flags.set(flags::WITHIN_ARSHAL_CALL, false);
        let (curr_depth, curr_length) = enc.s.state.tokens.depth_length();
        if err.is_none() && (prev_depth != curr_depth || prev_length + 1 != curr_length) {
            err = Some(err_non_singular_value());
        }
        if let Some(mut e) = err {
            if is_unsupported(&e) {
                if prev_depth == curr_depth && prev_length == curr_length {
                    return Err(e);
                }
                e = err_unsupported_mutation();
            }
            if !e.is_io_error() {
                e = semantic_error_with_position_enc(
                    enc,
                    Some(t.clone()),
                    prev_depth,
                    prev_length,
                    e,
                );
            }
            return Err(e);
        }
        Ok(())
    });
    Marshalers {
        fncs: vec![TypedMarshaler {
            type_id: TypeId::of::<T>(),
            fnc: f,
            may_skip: true,
        }],
        from_any: from_any::<T>(),
    }
}

/// Go's `UnmarshalFunc`: an unmarshaler into values of type `T` from a
/// function that receives the JSON text of one value.
pub fn unmarshal_func<T, F>(fnc: F) -> Unmarshalers
where
    T: UnmarshalFrom,
    F: Fn(&[u8], &mut T) -> Result<(), Error> + Send + Sync + 'static,
{
    let t = pointer_to(T::type_info());
    let f: UnmarshalFn = Arc::new(move |dec, v| {
        let v = v.downcast_mut::<T>().expect("function type matches value");
        let val = dec.read_value()?;
        if let Err(err) = fnc(&val.0, v) {
            let err = wrap_err_unsupported(err, "unmarshal function of type func([]byte, T) error");
            let err = unmarshal_error_after(dec, Some(t.clone()), Some(err));
            return Err(collapse_semantic_errors(err));
        }
        Ok(())
    });
    Unmarshalers {
        fncs: vec![TypedUnmarshaler {
            type_id: TypeId::of::<T>(),
            fnc: f,
            may_skip: false,
        }],
        from_any: from_any::<T>(),
    }
}

/// Go's `UnmarshalFromFunc`: an unmarshaler into values of type `T` from a
/// function that reads exactly one value from the decoder. It may return
/// `errors.ErrUnsupported` (without reading) to defer to the next
/// unmarshaler.
pub fn unmarshal_from_func<T, F>(fnc: F) -> Unmarshalers
where
    T: UnmarshalFrom,
    F: Fn(&mut Decoder<'_>, &mut T) -> Result<(), Error> + Send + Sync + 'static,
{
    let t = pointer_to(T::type_info());
    let f: UnmarshalFn = Arc::new(move |dec, v| {
        let v = v.downcast_mut::<T>().expect("function type matches value");
        let (prev_depth, prev_length) = dec.s.state.tokens.depth_length();
        if prev_depth == 1 && dec.s.at_eof() {
            return Err(Error::Eof);
        }
        dec.s.opts.flags.set(flags::WITHIN_ARSHAL_CALL, true);
        let mut err = fnc(dec, v).err();
        dec.s.opts.flags.set(flags::WITHIN_ARSHAL_CALL, false);
        let (curr_depth, curr_length) = dec.s.state.tokens.depth_length();
        if err.is_none() && (prev_depth != curr_depth || prev_length + 1 != curr_length) {
            err = Some(err_non_singular_value());
        }
        if let Some(mut e) = err {
            if is_unsupported(&e) {
                if prev_depth == curr_depth && prev_length == curr_length {
                    return Err(e);
                }
                e = err_unsupported_mutation();
            }
            if !is_syntactic_error(&e) && !e.is_io_error() {
                e = semantic_error_with_position_dec(
                    dec,
                    Some(t.clone()),
                    prev_depth,
                    prev_length,
                    e,
                );
            }
            return Err(e);
        }
        Ok(())
    });
    Unmarshalers {
        fncs: vec![TypedUnmarshaler {
            type_id: TypeId::of::<T>(),
            fnc: f,
            may_skip: true,
        }],
        from_any: from_any::<T>(),
    }
}
