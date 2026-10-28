//! The predefined template functions and escapers (Go `text/template`
//! `funcs.go`).

use super::value::{CallError, FuncSig, Kind, Type, Value};
use super::verbs;
use super::Template;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::sync::OnceLock;

/// A map of function names to function values (Go `template.FuncMap`). The
/// values must be function values (see [`Value::func_of`] and
/// [`super::func1`]) with one result, or two when the second is
/// an `error`.
pub type FuncMap = BTreeMap<String, Value>;

fn rv() -> Type {
    Type::reflect_value()
}

fn sig(ins: Vec<Type>, outs: Vec<Type>, variadic: bool) -> FuncSig {
    FuncSig::new(ins, outs, variadic)
}

fn rv_slice() -> Type {
    Type::slice_of(rv())
}

fn any_slice() -> Type {
    Type::slice_of(Type::any())
}

/// The table of predefined functions.
pub(crate) fn builtins() -> &'static FuncMap {
    static B: OnceLock<FuncMap> = OnceLock::new();
    B.get_or_init(|| {
        let mut m = FuncMap::new();
        let mut add = |name: &str, s: FuncSig, f: fn(&[Value]) -> Result<Value, CallError>| {
            m.insert(name.to_owned(), Value::func_of(s, f));
        };
        let err = Type::error();
        add("and", sig(vec![rv(), rv_slice()], vec![rv()], true), |_| {
            Err(CallError::Panic("unreachable".into()))
        });
        add(
            "call",
            sig(vec![rv(), rv_slice()], vec![rv()], true),
            |_| Err(CallError::Panic("unreachable".into())),
        );
        add(
            "html",
            sig(vec![any_slice()], vec![Type::string()], true),
            |a| Ok(Value::string(html_escaper(a))),
        );
        add(
            "index",
            sig(vec![rv(), rv_slice()], vec![rv(), err.clone()], true),
            |a| index(&a[0], &a[1..]),
        );
        add(
            "slice",
            sig(vec![rv(), rv_slice()], vec![rv(), err.clone()], true),
            |a| slice(&a[0], &a[1..]),
        );
        add(
            "js",
            sig(vec![any_slice()], vec![Type::string()], true),
            |a| Ok(Value::string(js_escaper(a))),
        );
        add(
            "len",
            sig(vec![rv()], vec![Type::int(), err.clone()], false),
            |a| length(&a[0]),
        );
        add("not", sig(vec![rv()], vec![Type::bool_()], false), |a| {
            Ok(Value::bool_(!truth(&a[0])))
        });
        add("or", sig(vec![rv(), rv_slice()], vec![rv()], true), |_| {
            Err(CallError::Panic("unreachable".into()))
        });
        add(
            "print",
            sig(vec![any_slice()], vec![Type::string()], true),
            |a| Ok(Value::string(verbs::sprint(a))),
        );
        add(
            "printf",
            sig(
                vec![Type::string(), any_slice()],
                vec![Type::string()],
                true,
            ),
            |a| Ok(Value::string(verbs::sprintf(&a[0].as_string(), &a[1..]))),
        );
        add(
            "println",
            sig(vec![any_slice()], vec![Type::string()], true),
            |a| Ok(Value::string(verbs::sprintln(a))),
        );
        add(
            "urlquery",
            sig(vec![any_slice()], vec![Type::string()], true),
            |a| Ok(Value::string(url_query_escaper(a))),
        );
        let cmp_variadic = sig(
            vec![rv(), rv_slice()],
            vec![Type::bool_(), err.clone()],
            true,
        );
        add("eq", cmp_variadic, |a| eq(&a[0], &a[1..]).map(Value::bool_));
        let cmp2 = sig(vec![rv(), rv()], vec![Type::bool_(), err], false);
        add("ge", cmp2.clone(), |a| ge(&a[0], &a[1]).map(Value::bool_));
        add("gt", cmp2.clone(), |a| gt(&a[0], &a[1]).map(Value::bool_));
        add("le", cmp2.clone(), |a| le(&a[0], &a[1]).map(Value::bool_));
        add("lt", cmp2.clone(), |a| lt(&a[0], &a[1]).map(Value::bool_));
        add("ne", cmp2, |a| ne(&a[0], &a[1]).map(Value::bool_));
        m
    })
}

/// Reports whether `name` is a valid function name: a letter or underscore
/// followed by letters, digits and underscores.
pub(crate) fn good_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    for (i, r) in name.chars().enumerate() {
        let letter = crate::unicode::is_letter(r as i32);
        let digit = crate::unicode::is_digit(r as i32);
        if r == '_' {
            continue;
        }
        if i == 0 && !letter {
            return false;
        }
        if !letter && !digit {
            return false;
        }
    }
    true
}

/// Reports whether the function signature is usable from a template: one
/// result, or two with the second an `error`.
pub(crate) fn good_func(name: &str, sig: &FuncSig) -> Result<(), String> {
    match sig.outs.len() {
        1 => Ok(()),
        2 if sig.outs[1] == Type::error() => Ok(()),
        2 => Err(format!(
            "invalid function signature for {name}: second return value should be error; is {}",
            sig.outs[1].type_string()
        )),
        n => Err(format!(
            "function {name} has {n} return values; should be 1 or 2"
        )),
    }
}

pub(crate) fn add_value_funcs(out: &mut FuncMap, input: &FuncMap) {
    for (name, f) in input {
        if !good_name(name) {
            panic!(
                "function name {} is not a valid identifier",
                crate::strconv::quote(name)
            );
        }
        let Some(sig) = f.type_().and_then(Type::sig) else {
            panic!("value for {name} not a function");
        };
        if let Err(e) = good_func(name, &sig) {
            panic!("{e}");
        }
        out.insert(name.clone(), f.clone());
    }
}

/// Looks up a function: the template's own, then the predefined ones. The
/// boolean reports a predefined function.
pub(crate) fn find_function(name: &str, tmpl: &Template) -> Option<(Value, bool)> {
    if let Some(f) = tmpl.func(name) {
        return Some((f, false));
    }
    builtins().get(name).map(|f| (f.clone(), true))
}

pub(crate) fn can_be_nil(typ: &Type) -> bool {
    match typ.kind() {
        Kind::Chan | Kind::Func | Kind::Interface | Kind::Map | Kind::Pointer | Kind::Slice => true,
        Kind::Struct => typ.is_reflect_value(),
        _ => false,
    }
}

/// Converts a value for a call: nil to the zero of the parameter type, or an
/// integer to another integer type (Go `prepareArg`).
fn prepare_arg(value: &Value, arg_type: &Type) -> Result<Value, String> {
    let mut value = value.clone();
    if !value.is_valid() {
        if !can_be_nil(arg_type) {
            return Err(format!(
                "value is nil; should be of type {}",
                arg_type.type_string()
            ));
        }
        value = Value::zero(arg_type);
    }
    let vt = value.type_().expect("valid").clone();
    if vt.assignable_to(arg_type) {
        return Ok(value);
    }
    if value.kind().int_like() && arg_type.kind().int_like() && vt.convertible_to(arg_type) {
        return Ok(value.convert(arg_type));
    }
    Err(format!(
        "value has type {}; should be {}",
        vt.type_string(),
        arg_type.type_string()
    ))
}

/// Validates a slice index argument (Go `indexArg`).
fn index_arg(index: &Value, cap: usize) -> Result<usize, String> {
    let x: i64 = match index.kind() {
        k if k.is_int() => index.as_int(),
        k if k.is_uint() => index.as_uint() as i64,
        Kind::Invalid => return Err("cannot index slice/array with nil".to_owned()),
        _ => {
            return Err(format!(
                "cannot index slice/array with type {}",
                index.type_().expect("valid").type_string()
            ))
        }
    };
    if x < 0 || x as u64 > cap as u64 {
        return Err(format!("index out of range: {x}"));
    }
    Ok(x as usize)
}

/// Follows pointers and interfaces; the boolean reports hitting a nil.
pub(crate) fn indirect(v: &Value) -> (Value, bool) {
    let mut v = v.clone();
    while matches!(v.kind(), Kind::Pointer | Kind::Interface) {
        if v.is_nil() {
            return (v, true);
        }
        v = v.elem();
    }
    (v, false)
}

/// Unwraps an interface value; a nil interface becomes the invalid value.
pub(crate) fn indirect_interface(v: &Value) -> Value {
    if v.kind() != Kind::Interface {
        return v.clone();
    }
    if v.is_nil() {
        return Value::nil();
    }
    v.elem()
}

fn err(s: impl Into<String>) -> CallError {
    CallError::msg(s)
}

/// The `index` builtin.
fn index(item: &Value, indexes: &[Value]) -> Result<Value, CallError> {
    let mut item = indirect_interface(item);
    if !item.is_valid() {
        return Err(err("index of untyped nil"));
    }
    for index in indexes {
        let index = indirect_interface(index);
        let (it, is_nil) = indirect(&item);
        if is_nil {
            return Err(err("index of nil pointer"));
        }
        item = it;
        match item.kind() {
            Kind::Array | Kind::Slice | Kind::String => {
                let x = index_arg(&index, item.len()).map_err(err)?;
                if x >= item.len() {
                    let what = match item.kind() {
                        Kind::Array => "array",
                        Kind::Slice => "slice",
                        _ => "string",
                    };
                    return Err(err(format!("reflect: {what} index out of range")));
                }
                item = item.index(x);
            }
            Kind::Map => {
                let key_t = item.type_().expect("valid").key().expect("map");
                let idx = prepare_arg(&index, &key_t).map_err(err)?;
                let x = item.map_index(&idx);
                item = if x.is_valid() {
                    x
                } else {
                    Value::zero(&item.type_().expect("valid").elem().expect("map"))
                };
            }
            _ => {
                return Err(err(format!(
                    "can't index item of type {}",
                    item.type_().expect("valid").type_string()
                )))
            }
        }
    }
    Ok(item)
}

/// The `slice` builtin.
fn slice(item: &Value, indexes: &[Value]) -> Result<Value, CallError> {
    let item = indirect_interface(item);
    if !item.is_valid() {
        return Err(err("slice of untyped nil"));
    }
    let (item, is_nil) = indirect(&item);
    if is_nil {
        return Err(err("slice of nil pointer"));
    }
    if indexes.len() > 3 {
        return Err(err(format!("too many slice indexes: {}", indexes.len())));
    }
    let cap = match item.kind() {
        Kind::String => {
            if indexes.len() == 3 {
                return Err(err("cannot 3-index slice a string"));
            }
            item.len()
        }
        Kind::Array | Kind::Slice => item.cap(),
        _ => {
            return Err(err(format!(
                "can't slice item of type {}",
                item.type_().expect("valid").type_string()
            )))
        }
    };
    let mut idx = [0usize, item.len(), 0];
    for (i, index) in indexes.iter().enumerate() {
        idx[i] = index_arg(index, cap).map_err(err)?;
    }
    if idx[0] > idx[1] {
        return Err(err(format!("invalid slice index: {} > {}", idx[0], idx[1])));
    }
    // An array must be addressable to be sliced; templates treat it as such.
    let item = if item.kind() == Kind::Array {
        item.with_addr(true)
    } else {
        item
    };
    if indexes.len() < 3 {
        if idx[1] > cap {
            return Err(err("reflect.Value.Slice: slice index out of bounds"));
        }
        return Ok(item.slice_range(idx[0], idx[1]));
    }
    if idx[1] > idx[2] {
        return Err(err(format!("invalid slice index: {} > {}", idx[1], idx[2])));
    }
    Ok(item.slice3(idx[0], idx[1], idx[2]))
}

/// The `len` builtin.
fn length(item: &Value) -> Result<Value, CallError> {
    let (item, is_nil) = indirect(item);
    if is_nil {
        return Err(err("len of nil pointer"));
    }
    match item.kind() {
        Kind::Array | Kind::Chan | Kind::Map | Kind::Slice | Kind::String => {
            Ok(Value::int(item.len() as i64))
        }
        _ => match item.type_() {
            // item.Type() panics on the zero Value; the call recovers it.
            None => Err(CallError::Panic(
                "reflect: call of reflect.Value.Type on zero Value".to_owned(),
            )),
            Some(t) => Err(err(format!("len of type {}", t.type_string()))),
        },
    }
}

/// The `call` builtin once its arguments are evaluated.
pub(crate) fn call(name: &str, f: &Value, args: &[Value]) -> Result<Value, CallError> {
    let f = indirect_interface(f);
    if !f.is_valid() {
        return Err(err("call of nil"));
    }
    let typ = f.type_().expect("valid").clone();
    if typ.kind() != Kind::Func {
        return Err(err(format!(
            "non-function {name} of type {}",
            typ.type_string()
        )));
    }
    let sig = typ.sig().expect("func");
    good_func(name, &sig).map_err(err)?;
    let num_in = sig.ins.len();
    let ddd_type = if sig.variadic {
        if args.len() < num_in - 1 {
            return Err(err(format!(
                "wrong number of args for {name}: got {} want at least {}",
                args.len(),
                num_in - 1
            )));
        }
        sig.ins[num_in - 1].elem()
    } else {
        if args.len() != num_in {
            return Err(err(format!(
                "wrong number of args for {name}: got {} want {num_in}",
                args.len()
            )));
        }
        None
    };
    let mut argv = Vec::with_capacity(args.len());
    for (i, arg) in args.iter().enumerate() {
        let arg = indirect_interface(arg);
        let arg_type = if !sig.variadic || i < num_in - 1 {
            sig.ins[i].clone()
        } else {
            ddd_type.clone().expect("variadic elem")
        };
        match prepare_arg(&arg, &arg_type) {
            Ok(v) => argv.push(v),
            Err(e) => return Err(err(format!("arg {i}: {e}"))),
        }
    }
    f.call(&argv)
}

/// The truth of a value as `and`, `or` and `not` see it.
pub(crate) fn truth(arg: &Value) -> bool {
    is_true_value(&indirect_interface(arg)).0
}

/// Go `isTrue`: the truth of a value and whether it has one.
pub(crate) fn is_true_value(val: &Value) -> (bool, bool) {
    if !val.is_valid() {
        // Something like var x interface{}, never set. It's a form of nil.
        return (false, true);
    }
    let truth = match val.kind() {
        Kind::Array | Kind::Map | Kind::Slice | Kind::String => !val.is_empty(),
        Kind::Bool => val.as_bool(),
        Kind::Complex64 | Kind::Complex128 => {
            let (re, im) = val.as_complex();
            re != 0.0 || im != 0.0
        }
        Kind::Chan | Kind::Func | Kind::Pointer | Kind::UnsafePointer | Kind::Interface => {
            !val.is_nil()
        }
        k if k.is_int() => val.as_int() != 0,
        Kind::Float32 | Kind::Float64 => val.as_float() != 0.0,
        k if k.is_uint() => val.as_uint() != 0,
        Kind::Struct => true, // Struct values are always true.
        _ => return (false, false),
    };
    (truth, true)
}

/// Reports whether a value is true, and whether it has a truth value at all
/// (Go `template.IsTrue`).
pub fn is_true(val: &Value) -> (bool, bool) {
    is_true_value(val)
}

// ---- comparison -------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum BasicKind {
    Invalid,
    Bool,
    Complex,
    Int,
    Float,
    String,
    Uint,
}

fn basic_kind(v: &Value) -> Result<BasicKind, ()> {
    Ok(match v.kind() {
        Kind::Bool => BasicKind::Bool,
        k if k.is_int() => BasicKind::Int,
        k if k.is_uint() => BasicKind::Uint,
        Kind::Float32 | Kind::Float64 => BasicKind::Float,
        Kind::Complex64 | Kind::Complex128 => BasicKind::Complex,
        Kind::String => BasicKind::String,
        _ => return Err(()),
    })
}

fn is_nil(v: &Value) -> bool {
    if !v.is_valid() {
        return true;
    }
    match v.kind() {
        Kind::Chan | Kind::Func | Kind::Interface | Kind::Map | Kind::Pointer | Kind::Slice => {
            v.is_nil()
        }
        _ => false,
    }
}

fn can_compare(v1: &Value, v2: &Value) -> bool {
    let (k1, k2) = (v1.kind(), v2.kind());
    k1 == k2 || k1 == Kind::Invalid || k2 == Kind::Invalid
}

fn fmt_s(v: &Value) -> String {
    verbs::sprintf("%s", std::slice::from_ref(v))
}

fn type_str(v: &Value) -> String {
    v.type_()
        .map(Type::type_string)
        .unwrap_or_else(|| "<nil>".to_owned())
}

fn eq(arg1: &Value, arg2: &[Value]) -> Result<bool, CallError> {
    let arg1 = indirect_interface(arg1);
    if arg2.is_empty() {
        return Err(err("missing argument for comparison"));
    }
    let k1 = basic_kind(&arg1).unwrap_or(BasicKind::Invalid);
    for arg in arg2 {
        let arg = indirect_interface(arg);
        let k2 = basic_kind(&arg).unwrap_or(BasicKind::Invalid);
        let truth;
        if k1 != k2 {
            // Special case: Can compare integer values regardless of type's
            // sign.
            if k1 == BasicKind::Int && k2 == BasicKind::Uint {
                truth = arg1.as_int() >= 0 && arg1.as_int() as u64 == arg.as_uint();
            } else if k1 == BasicKind::Uint && k2 == BasicKind::Int {
                truth = arg.as_int() >= 0 && arg1.as_uint() == arg.as_int() as u64;
            } else {
                if arg1.is_valid() && arg.is_valid() {
                    return Err(err(format!(
                        "incompatible types for comparison: {} and {}",
                        type_str(&arg1),
                        type_str(&arg)
                    )));
                }
                truth = false;
            }
        } else {
            truth = match k1 {
                BasicKind::Bool => arg1.as_bool() == arg.as_bool(),
                BasicKind::Complex => arg1.as_complex() == arg.as_complex(),
                BasicKind::Float => arg1.as_float() == arg.as_float(),
                BasicKind::Int => arg1.as_int() == arg.as_int(),
                BasicKind::String => arg1.as_string() == arg.as_string(),
                BasicKind::Uint => arg1.as_uint() == arg.as_uint(),
                BasicKind::Invalid => {
                    if !can_compare(&arg1, &arg) {
                        return Err(err(format!(
                            "non-comparable types {}: {}, {}: {}",
                            fmt_s(&arg1),
                            type_str(&arg1),
                            type_str(&arg),
                            verbs::sprintf("%v", std::slice::from_ref(&arg))
                        )));
                    }
                    if is_nil(&arg1) || is_nil(&arg) {
                        is_nil(&arg) == is_nil(&arg1)
                    } else {
                        if !arg.type_().expect("valid").comparable() {
                            return Err(err(format!(
                                "non-comparable type {}: {}",
                                fmt_s(&arg),
                                type_str(&arg)
                            )));
                        }
                        arg1.equal(&arg)
                    }
                }
            };
        }
        if truth {
            return Ok(true);
        }
    }
    Ok(false)
}

fn ne(arg1: &Value, arg2: &Value) -> Result<bool, CallError> {
    // != is the inverse of ==.
    let equal = eq(arg1, std::slice::from_ref(arg2))?;
    Ok(!equal)
}

fn lt(arg1: &Value, arg2: &Value) -> Result<bool, CallError> {
    let arg1 = indirect_interface(arg1);
    let k1 = basic_kind(&arg1).map_err(|()| err("invalid type for comparison"))?;
    let arg2 = indirect_interface(arg2);
    let k2 = basic_kind(&arg2).map_err(|()| err("invalid type for comparison"))?;
    if k1 != k2 {
        // Special case: Can compare integer values regardless of type's sign.
        if k1 == BasicKind::Int && k2 == BasicKind::Uint {
            Ok(arg1.as_int() < 0 || (arg1.as_int() as u64) < arg2.as_uint())
        } else if k1 == BasicKind::Uint && k2 == BasicKind::Int {
            Ok(arg2.as_int() >= 0 && arg1.as_uint() < arg2.as_int() as u64)
        } else {
            Err(err(format!(
                "incompatible types for comparison: {} and {}",
                type_str(&arg1),
                type_str(&arg2)
            )))
        }
    } else {
        match k1 {
            BasicKind::Bool | BasicKind::Complex => Err(err("invalid type for comparison")),
            BasicKind::Float => Ok(arg1.as_float() < arg2.as_float()),
            BasicKind::Int => Ok(arg1.as_int() < arg2.as_int()),
            BasicKind::String => Ok(arg1.as_string().as_bytes() < arg2.as_string().as_bytes()),
            BasicKind::Uint => Ok(arg1.as_uint() < arg2.as_uint()),
            BasicKind::Invalid => Err(CallError::Panic("invalid kind".to_owned())),
        }
    }
}

fn le(arg1: &Value, arg2: &Value) -> Result<bool, CallError> {
    // <= is < or ==.
    let less_than = lt(arg1, arg2)?;
    if less_than {
        return Ok(true);
    }
    eq(arg1, std::slice::from_ref(arg2))
}

fn gt(arg1: &Value, arg2: &Value) -> Result<bool, CallError> {
    // > is the inverse of <=.
    let less_or_equal = le(arg1, arg2)?;
    Ok(!less_or_equal)
}

fn ge(arg1: &Value, arg2: &Value) -> Result<bool, CallError> {
    // >= is the inverse of <.
    let less_than = lt(arg1, arg2)?;
    Ok(!less_than)
}

// ---- escapers ----------------------------------------------------------

/// Writes to `w` the escaped HTML equivalent of the plain text data `b` (Go
/// `template.HTMLEscape`).
pub fn html_escape<W: Write + ?Sized>(w: &mut W, b: &[u8]) -> io::Result<()> {
    let mut last = 0;
    for (i, &c) in b.iter().enumerate() {
        let html: &[u8] = match c {
            0 => "\u{FFFD}".as_bytes(),
            b'"' => b"&#34;",
            b'\'' => b"&#39;",
            b'&' => b"&amp;",
            b'<' => b"&lt;",
            b'>' => b"&gt;",
            _ => continue,
        };
        w.write_all(&b[last..i])?;
        w.write_all(html)?;
        last = i + 1;
    }
    w.write_all(&b[last..])
}

/// Returns the escaped HTML equivalent of the plain text data `s` (Go
/// `template.HTMLEscapeString`).
pub fn html_escape_string(s: &str) -> String {
    if !s.contains(['\'', '"', '&', '<', '>', '\0']) {
        return s.to_owned();
    }
    let mut out = Vec::new();
    html_escape(&mut out, s.as_bytes()).expect("vec write");
    String::from_utf8(out).expect("escaped utf-8")
}

/// Returns the escaped HTML equivalent of the textual representation of its
/// arguments (Go `template.HTMLEscaper`).
pub fn html_escaper(args: &[Value]) -> String {
    html_escape_string(&eval_args(args))
}

fn js_is_special(r: u32) -> bool {
    matches!(r, 0x5C | 0x27 | 0x22 | 0x3C | 0x3E | 0x26 | 0x3D) || !(0x20..0x80).contains(&r)
}

/// Writes to `w` the escaped JavaScript equivalent of the plain text data `b`
/// (Go `template.JSEscape`).
pub fn js_escape<W: Write + ?Sized>(w: &mut W, b: &[u8]) -> io::Result<()> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut last = 0;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if !js_is_special(u32::from(c)) {
            i += 1;
            continue;
        }
        w.write_all(&b[last..i])?;
        if c < 0x80 {
            match c {
                b'\\' => w.write_all(b"\\\\")?,
                b'\'' => w.write_all(b"\\'")?,
                b'"' => w.write_all(b"\\\"")?,
                b'<' => w.write_all(b"\\u003C")?,
                b'>' => w.write_all(b"\\u003E")?,
                b'&' => w.write_all(b"\\u0026")?,
                b'=' => w.write_all(b"\\u003D")?,
                _ => {
                    w.write_all(b"\\u00")?;
                    w.write_all(&[HEX[usize::from(c >> 4)], HEX[usize::from(c & 0x0F)]])?;
                }
            }
            i += 1;
        } else {
            let (r, size) = crate::unicode::rune::decode_rune(&b[i..]);
            if crate::unicode::is_print(r) {
                w.write_all(&b[i..i + size])?;
            } else {
                w.write_all(format!("\\u{:04X}", r as u32).as_bytes())?;
            }
            i += size;
        }
        last = i;
    }
    w.write_all(&b[last..])
}

/// Returns the escaped JavaScript equivalent of the plain text data `s` (Go
/// `template.JSEscapeString`).
pub fn js_escape_string(s: &str) -> String {
    if !s.chars().any(|c| js_is_special(c as u32)) {
        return s.to_owned();
    }
    let mut out = Vec::new();
    js_escape(&mut out, s.as_bytes()).expect("vec write");
    String::from_utf8(out).expect("escaped utf-8")
}

/// Returns the escaped JavaScript equivalent of the textual representation of
/// its arguments (Go `template.JSEscaper`).
pub fn js_escaper(args: &[Value]) -> String {
    js_escape_string(&eval_args(args))
}

/// Returns the escaped value of the textual representation of its arguments
/// in a form suitable for embedding in a URL query (Go
/// `template.URLQueryEscaper`).
pub fn url_query_escaper(args: &[Value]) -> String {
    crate::net::url::query_escape(&eval_args(args))
}

/// The textual representation of the arguments, as `fmt.Sprint` renders them,
/// except that a lone string is used as is.
pub(crate) fn eval_args(args: &[Value]) -> String {
    if args.len() == 1 {
        let a = args[0].interface();
        if a.is_valid() && a.type_() == Some(&Type::string()) {
            return a.as_string();
        }
    }
    let converted: Vec<Value> = args
        .iter()
        .map(|arg| match super::exec::printable_value(&arg.interface()) {
            Some(v) => v,
            None => arg.clone(),
        })
        .collect();
    verbs::sprint(&converted)
}
