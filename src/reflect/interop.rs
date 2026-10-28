//! Conversions from `reflect::Value` to the other dynamic value models of this
//! crate: `fmt`'s operand model and `text/template`'s typed values.
//!
//! `encoding/json` has no conversion: its `Value` is a JSON tree, and turning a
//! reflect value into one would re-implement `Marshal` (struct tags,
//! `omitempty`, embedding, `MarshalJSON`), which the typed
//! `Serialize`/`#[derive(Serialize)]` path already does.

use std::collections::HashMap;
use std::fmt;

use super::kind::Kind;
use super::typ::{Body, Type};
use super::value::Value;
use crate::printf as gofmt;
use crate::text::template::value::{
    CallError, Field as TField, FuncSig, Type as TType, Value as TValue,
};

/// A Go-flavoured rendering used by `Debug`: Go's `%v` of the value.
pub(crate) fn debug_text(v: &Value) -> String {
    gofmt::sprintf("%v", &[gofmt::Value::from(v)])
}

// ---------------------------------------------------------------------------
// fmt

struct MethodStringer(Value, &'static str);

impl fmt::Display for MethodStringer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&call_string(&self.0, self.1))
    }
}

impl fmt::Debug for MethodStringer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&call_string(&self.0, self.1))
    }
}

struct MethodError(Value);

impl fmt::Display for MethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&call_string(&self.0, "Error"))
    }
}

impl fmt::Debug for MethodError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for MethodError {}

fn call_string(v: &Value, method: &str) -> String {
    let m = v.method_by_name(method);
    m.call(&[])
        .first()
        .map(|r| String::from_utf8_lossy(&r.string_bytes()).into_owned())
        .unwrap_or_default()
}

/// Whether the type has an exported `name() string` method.
fn has_string_method(t: &Type, name: &str) -> bool {
    t.method_by_name(name).is_some_and(|m| {
        let mt = &m.type_;
        // The method type has the receiver as its first parameter.
        mt.num_in() == 1 && mt.num_out() == 1 && mt.out(0).kind() == Kind::String
    })
}

fn int_kind(k: Kind) -> gofmt::IntKind {
    match k {
        Kind::Int8 => gofmt::IntKind::Int8,
        Kind::Int16 => gofmt::IntKind::Int16,
        Kind::Int32 => gofmt::IntKind::Int32,
        Kind::Int64 => gofmt::IntKind::Int64,
        _ => gofmt::IntKind::Int,
    }
}

fn uint_kind(k: Kind) -> gofmt::UintKind {
    match k {
        Kind::Uint8 => gofmt::UintKind::Uint8,
        Kind::Uint16 => gofmt::UintKind::Uint16,
        Kind::Uint32 => gofmt::UintKind::Uint32,
        Kind::Uint64 => gofmt::UintKind::Uint64,
        Kind::Uintptr => gofmt::UintKind::Uintptr,
        _ => gofmt::UintKind::Uint,
    }
}

fn to_fmt(v: &Value) -> gofmt::Value {
    to_fmt_at(v, true)
}

/// `top` is true for an operand itself and false for parts of it: a nil
/// interface prints `<nil>` as an operand but as a typed nil inside a value.
fn to_fmt_at(v: &Value, top: bool) -> gofmt::Value {
    use gofmt::Value as F;
    if !v.is_valid() {
        // Go prints the zero reflect.Value as <invalid reflect.Value>.
        return F::NilIface(String::new());
    }
    let t = v.type_();
    let k = t.kind();
    let named = t.pkg_path() != "" || (t.name() != "" && t.name() != k.name() && k <= Kind::String);
    let inner = match k {
        Kind::Bool => F::Bool(v.bool()),
        k if k.is_int() => F::Int(v.int(), int_kind(k)),
        k if k.is_uint() => F::Uint(v.uint(), uint_kind(k)),
        Kind::Float32 => F::Float32(v.float() as f32),
        Kind::Float64 => F::Float64(v.float()),
        Kind::Complex64 => {
            let c = v.complex();
            F::Complex64(c.re as f32, c.im as f32)
        }
        Kind::Complex128 => {
            let c = v.complex();
            F::Complex128(c.re, c.im)
        }
        Kind::String => F::String(v.string_bytes()),
        Kind::Array | Kind::Slice => {
            let nil = k == Kind::Slice && v.is_nil();
            let items: Vec<F> = if nil {
                Vec::new()
            } else {
                (0..v.len())
                    .map(|i| to_fmt_at(&v.index(i), false))
                    .collect()
            };
            F::Slice(Box::new(gofmt::Seq {
                type_name: t.to_string(),
                elem: t.elem().to_string(),
                items,
                bytes: t.elem().kind() == Kind::Uint8,
                array: k == Kind::Array,
                nil,
                addr: if nil || k == Kind::Array {
                    0
                } else {
                    v.pointer()
                },
            }))
        }
        Kind::Map => {
            let nil = v.is_nil();
            let entries = if nil {
                Vec::new()
            } else {
                v.map_keys()
                    .iter()
                    .map(|key| (to_fmt_at(key, false), to_fmt_at(&v.map_index(key), false)))
                    .collect()
            };
            F::Map(Box::new(gofmt::MapV {
                type_name: t.to_string(),
                entries,
                nil,
                addr: if nil { 0 } else { v.pointer() },
            }))
        }
        Kind::Struct => F::Struct(Box::new(gofmt::StructV {
            type_name: t.to_string(),
            fields: (0..v.num_field())
                .map(|i| (t.field(i).name, to_fmt_at(&v.field(i), false)))
                .collect(),
        })),
        Kind::Pointer => {
            let nil = v.is_nil();
            F::Pointer(Box::new(gofmt::Ptr {
                type_name: t.to_string(),
                addr: if nil { 0 } else { v.pointer() },
                // Go prints a nested pointer as an address, so only an operand's
                // own pointee is converted (this also keeps cycles finite).
                elem: if nil || !top {
                    None
                } else {
                    Some(to_fmt_at(&v.elem(), false))
                },
            }))
        }
        Kind::Interface => {
            if v.is_nil() {
                return if top {
                    F::Nil
                } else {
                    F::NilIface(t.to_string())
                };
            }
            return to_fmt_at(&v.elem(), top);
        }
        Kind::Chan | Kind::Func | Kind::UnsafePointer => F::Pointer(Box::new(gofmt::Ptr {
            type_name: t.to_string(),
            addr: if v.is_nil() { 0 } else { v.pointer() },
            elem: None,
        })),
        _ => F::Nil,
    };
    let mut out = if named
        && !matches!(
            inner,
            F::Slice(_) | F::Map(_) | F::Struct(_) | F::Pointer(_)
        ) {
        F::named(&t.to_string(), inner)
    } else {
        inner
    };
    if has_string_method(&t, "Error") {
        out = out.with_error(MethodError(v.clone()));
    }
    if has_string_method(&t, "String") {
        out = out.with_display(MethodStringer(v.clone(), "String"));
    }
    if has_string_method(&t, "GoString") {
        out = out.with_debug(MethodStringer(v.clone(), "GoString"));
    }
    out
}

impl From<Value> for gofmt::Value {
    /// The operand `fmt` would receive for this value (`&Value` converts too,
    /// through fmt's blanket reference conversion): kinds map to the matching
    /// variants, named types carry their Go type name for `%T` and `%#v`, and
    /// exported `String`, `GoString` and `Error` methods that take no
    /// arguments are called by the verbs that use them.
    fn from(v: Value) -> gofmt::Value {
        to_fmt(&v)
    }
}

// ---------------------------------------------------------------------------
// text/template

type Memo = HashMap<usize, TType>;

fn body_to_template(b: &Body, memo: &mut Memo) -> TType {
    match b {
        Body::Basic(k) => basic_to_template(*k),
        Body::Array { len, elem } => TType::array_of(*len, type_to_template(elem, memo)),
        Body::Slice(e) => TType::slice_of(type_to_template(e, memo)),
        Body::Pointer(e) => TType::ptr_to(type_to_template(e, memo)),
        Body::Chan { dir, elem } => {
            let d = match dir {
                super::ChanDir::Recv => crate::text::template::value::ChanDir::Recv,
                super::ChanDir::Send => crate::text::template::value::ChanDir::Send,
                super::ChanDir::Both => crate::text::template::value::ChanDir::Both,
            };
            TType::chan_of(d, type_to_template(elem, memo))
        }
        Body::Map { key, elem } => {
            TType::map_of(type_to_template(key, memo), type_to_template(elem, memo))
        }
        Body::Func {
            ins,
            outs,
            variadic,
        } => TType::func_of(FuncSig::new(
            ins.iter().map(|t| type_to_template(t, memo)).collect(),
            outs.iter().map(|t| type_to_template(t, memo)).collect(),
            *variadic,
        )),
        Body::Interface { methods } => TType::interface_of(
            methods
                .iter()
                .map(|m| {
                    let (ins, outs, variadic) = m.ty.func_parts();
                    (
                        m.name.clone(),
                        FuncSig::new(
                            ins.iter().map(|t| type_to_template(t, memo)).collect(),
                            outs.iter().map(|t| type_to_template(t, memo)).collect(),
                            variadic,
                        ),
                    )
                })
                .collect(),
        ),
        Body::Struct { fields, .. } => TType::struct_of(
            fields
                .iter()
                .map(|f| {
                    let mut tf = TField::new(&f.name, type_to_template(&f.type_, memo));
                    tf.embedded = f.anonymous;
                    tf.tag = f.tag.0.clone();
                    tf
                })
                .collect(),
        ),
    }
}

fn basic_to_template(k: Kind) -> TType {
    match k {
        Kind::Bool => TType::bool_(),
        Kind::Int => TType::int(),
        Kind::Int8 => TType::int8(),
        Kind::Int16 => TType::int16(),
        Kind::Int32 => TType::int32(),
        Kind::Int64 => TType::int64(),
        Kind::Uint => TType::uint(),
        Kind::Uint8 => TType::uint8(),
        Kind::Uint16 => TType::uint16(),
        Kind::Uint32 => TType::uint32(),
        Kind::Uint64 => TType::uint64(),
        Kind::Uintptr => TType::uintptr(),
        Kind::Float32 => TType::float32(),
        Kind::Float64 => TType::float64(),
        Kind::Complex64 => TType::complex64(),
        Kind::Complex128 => TType::complex128(),
        Kind::String => TType::string(),
        _ => TType::unsafe_pointer(),
    }
}

/// The package prefix of a type's `String()` (Go prints the short package
/// name), for naming template types.
fn short_pkg(t: &Type) -> String {
    let s = t.to_string();
    let name = t.name();
    s.strip_suffix(&name)
        .and_then(|p| p.strip_suffix('.'))
        .unwrap_or("")
        .to_string()
}

fn type_to_template(t: &Type, memo: &mut Memo) -> TType {
    if *t == Type::error_type() {
        return TType::error();
    }
    if *t == Type::any_type() {
        return TType::any();
    }
    let basic = matches!(t.body(), Body::Basic(_));
    if basic {
        return basic_to_template(t.kind());
    }
    if t.name().is_empty() {
        return body_to_template(t.body(), memo);
    }
    if let Some(done) = memo.get(&t.addr()) {
        return done.clone();
    }
    let named = TType::named_deferred(&short_pkg(t), &t.name());
    memo.insert(t.addr(), named.clone());
    let under = body_to_template(t.body(), memo);
    named.set_underlying(under);
    named.set_methods(Vec::new());
    named
}

impl From<&Type> for TType {
    /// The `text/template` type for a reflect type. Defined types keep their
    /// package-qualified name; their methods are not carried over.
    fn from(t: &Type) -> TType {
        type_to_template(t, &mut HashMap::new())
    }
}

/// Template values are trees, so cycles through pointers, maps or interfaces
/// are cut off at this depth, where the part becomes the zero value.
const MAX_DEPTH: usize = 100;

fn value_to_template(v: &Value, memo: &mut Memo) -> TValue {
    value_to_template_at(v, memo, 0)
}

fn value_to_template_at(v: &Value, memo: &mut Memo, depth: usize) -> TValue {
    if !v.is_valid() {
        return TValue::nil();
    }
    let t = v.type_();
    let tt = type_to_template(&t, memo);
    if depth > MAX_DEPTH {
        return TValue::zero(&tt);
    }
    let depth = depth + 1;
    let k = t.kind();
    let wrap = |basic: TValue| -> TValue {
        if basic.type_() == Some(&tt) {
            basic
        } else {
            TValue::named(&tt, basic)
        }
    };
    match k {
        Kind::Bool => wrap(TValue::bool_(v.bool())),
        k if k.is_int() => TValue::int_of(&tt, v.int()),
        k if k.is_uint() => TValue::uint_of(&tt, v.uint()),
        Kind::Float32 | Kind::Float64 => TValue::float_of(&tt, v.float()),
        Kind::Complex64 | Kind::Complex128 => {
            let c = v.complex();
            TValue::complex_of(&tt, c.re, c.im)
        }
        Kind::String => TValue::string_of(&tt, String::from_utf8_lossy(&v.string_bytes())),
        Kind::Array => TValue::array(
            &tt,
            (0..v.len())
                .map(|i| value_to_template_at(&v.index(i), memo, depth))
                .collect(),
        ),
        Kind::Slice => {
            if v.is_nil() {
                TValue::nil_slice(&tt)
            } else {
                let items = (0..v.len())
                    .map(|i| value_to_template_at(&v.index(i), memo, depth))
                    .collect();
                TValue::slice_typed(&tt, items, v.cap())
            }
        }
        Kind::Map => {
            if v.is_nil() {
                TValue::nil_map(&tt)
            } else {
                let entries = v
                    .map_keys()
                    .iter()
                    .map(|key| {
                        (
                            value_to_template_at(key, memo, depth),
                            value_to_template_at(&v.map_index(key), memo, depth),
                        )
                    })
                    .collect();
                TValue::map(&tt, entries)
            }
        }
        Kind::Struct => TValue::struct_(
            &tt,
            (0..v.num_field())
                .map(|i| value_to_template_at(&v.field(i), memo, depth))
                .collect(),
        ),
        Kind::Pointer => {
            if v.is_nil() {
                TValue::nil_ptr(&tt)
            } else {
                TValue::ptr_typed(&tt, value_to_template_at(&v.elem(), memo, depth))
            }
        }
        Kind::Interface => {
            if v.is_nil() {
                TValue::iface(&tt, None)
            } else {
                TValue::iface(&tt, Some(value_to_template_at(&v.elem(), memo, depth)))
            }
        }
        Kind::Func => {
            if v.is_nil() {
                TValue::nil_func(&tt)
            } else {
                // Template values are data; reflect functions need reflect
                // arguments, so the converted function reports an error.
                let (ins, outs, variadic) = t.func_parts();
                let sig = FuncSig::new(
                    ins.iter().map(|x| type_to_template(x, memo)).collect(),
                    outs.iter().map(|x| type_to_template(x, memo)).collect(),
                    variadic,
                );
                TValue::func_of(sig, |_| {
                    Err(CallError::msg(
                        "reflect function values cannot be called from templates",
                    ))
                })
            }
        }
        Kind::Chan => {
            if v.is_nil() {
                TValue::nil_chan(&tt)
            } else {
                let ch = v.clone();
                TValue::chan(&tt, move || {
                    let (x, ok) = ch.recv();
                    ok.then(|| value_to_template(&x, &mut HashMap::new()))
                })
            }
        }
        _ => TValue::unsafe_pointer(if v.is_nil() { None } else { Some(v.pointer()) }),
    }
}

impl From<&Value> for TValue {
    /// The `text/template` value for a reflect value, so a reflect-described
    /// value can be the data of a template. Types and data are carried over;
    /// methods of defined types are not.
    fn from(v: &Value) -> TValue {
        value_to_template(v, &mut HashMap::new())
    }
}
