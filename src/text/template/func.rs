//! Typed Rust closures as template functions.
//!
//! A [`FuncMap`](super::FuncMap) holds function [`Value`]s. [`func0`] to
//! [`func4`] build one from an ordinary Rust closure whose parameters
//! implement [`FromValue`] and whose result implements [`IntoResult`]; the Go
//! signature (and so the argument checking templates perform) is derived from
//! the Rust types. [`variadic`] builds a variadic function over a slice of
//! arguments.
//!
//! ```
//! use rust_stdlib::text::template::{func2, FuncMap, Template};
//!
//! let mut funcs = FuncMap::new();
//! funcs.insert("add".into(), func2(|a: i64, b: i64| a + b));
//! let t = Template::new("t").funcs(&funcs).parse("{{add 1 2}}").unwrap();
//! let mut out = Vec::new();
//! t.execute(&mut out, &()).unwrap();
//! assert_eq!(out, b"3");
//! ```

use super::value::{CallError, FuncError, FuncSig, Kind, ToValue, Type, Value};
use std::fmt::Display;

/// Conversion of a template argument to a Rust parameter.
pub trait FromValue: Sized {
    /// The Go type of the parameter.
    fn go_type() -> Type;
    /// Converts the argument; the error says why it cannot be.
    fn from_value(v: &Value) -> Result<Self, String>;
}

macro_rules! from_value_int {
    ($($t:ty => $f:ident),+ $(,)?) => { $(
        impl FromValue for $t {
            fn go_type() -> Type { Type::$f() }
            fn from_value(v: &Value) -> Result<Self, String> { Ok(v.as_int() as $t) }
        }
    )+ };
}
from_value_int!(i8 => int8, i16 => int16, i32 => int32, i64 => int64, isize => int);

macro_rules! from_value_uint {
    ($($t:ty => $f:ident),+ $(,)?) => { $(
        impl FromValue for $t {
            fn go_type() -> Type { Type::$f() }
            fn from_value(v: &Value) -> Result<Self, String> { Ok(v.as_uint() as $t) }
        }
    )+ };
}
from_value_uint!(u8 => uint8, u16 => uint16, u32 => uint32, u64 => uint64, usize => uint);

impl FromValue for f64 {
    fn go_type() -> Type {
        Type::float64()
    }
    fn from_value(v: &Value) -> Result<Self, String> {
        Ok(v.as_float())
    }
}

impl FromValue for bool {
    fn go_type() -> Type {
        Type::bool_()
    }
    fn from_value(v: &Value) -> Result<Self, String> {
        Ok(v.as_bool())
    }
}

impl FromValue for String {
    fn go_type() -> Type {
        Type::string()
    }
    fn from_value(v: &Value) -> Result<Self, String> {
        Ok(v.as_string())
    }
}

/// Any value (a Go `interface{}` parameter). The closure receives the dynamic
/// value, as a Go function over `any` does; a nil interface stays as is. Elements of a `Vec<Value>`
/// parameter are unwrapped the same way.
impl FromValue for Value {
    fn go_type() -> Type {
        Type::any()
    }
    fn from_value(v: &Value) -> Result<Self, String> {
        if v.kind() == Kind::Interface && !v.is_nil() {
            return Ok(v.interface());
        }
        Ok(v.clone())
    }
}

/// A slice parameter.
impl<T: FromValue> FromValue for Vec<T> {
    fn go_type() -> Type {
        Type::slice_of(T::go_type())
    }
    fn from_value(v: &Value) -> Result<Self, String> {
        v.items().iter().map(T::from_value).collect()
    }
}

/// What a template function may return: a value, or a value or an error.
pub trait IntoResult {
    /// The Go result types.
    fn out_types() -> Vec<Type>;
    /// The result as a value, or the error to report.
    fn into_result(self) -> Result<Value, CallError>;
}

impl<T: ToValue> IntoResult for T {
    fn out_types() -> Vec<Type> {
        vec![T::go_type()]
    }
    fn into_result(self) -> Result<Value, CallError> {
        Ok(self.to_value())
    }
}

/// A function returning `Result<T, E>` is the Go `(T, error)`.
pub struct Fallible<T, E>(pub Result<T, E>);

impl<T: ToValue, E: Display> IntoResult for Fallible<T, E> {
    fn out_types() -> Vec<Type> {
        vec![T::go_type(), Type::error()]
    }
    fn into_result(self) -> Result<Value, CallError> {
        match self.0 {
            Ok(v) => Ok(v.to_value()),
            Err(e) => Err(CallError::Error(FuncError::new(e.to_string()))),
        }
    }
}

fn arg<A: FromValue>(args: &[Value], i: usize) -> Result<A, CallError> {
    A::from_value(&args[i]).map_err(CallError::msg)
}

/// A function with no parameters.
pub fn func0<R: IntoResult>(f: impl Fn() -> R + Send + Sync + 'static) -> Value {
    Value::func_of(FuncSig::new(vec![], R::out_types(), false), move |_| {
        f().into_result()
    })
}

/// A function with one parameter.
pub fn func1<A: FromValue, R: IntoResult>(f: impl Fn(A) -> R + Send + Sync + 'static) -> Value {
    Value::func_of(
        FuncSig::new(vec![A::go_type()], R::out_types(), false),
        move |a| f(arg(a, 0)?).into_result(),
    )
}

/// A function with two parameters.
pub fn func2<A: FromValue, B: FromValue, R: IntoResult>(
    f: impl Fn(A, B) -> R + Send + Sync + 'static,
) -> Value {
    Value::func_of(
        FuncSig::new(vec![A::go_type(), B::go_type()], R::out_types(), false),
        move |a| f(arg(a, 0)?, arg(a, 1)?).into_result(),
    )
}

/// A function with three parameters.
pub fn func3<A: FromValue, B: FromValue, C: FromValue, R: IntoResult>(
    f: impl Fn(A, B, C) -> R + Send + Sync + 'static,
) -> Value {
    Value::func_of(
        FuncSig::new(
            vec![A::go_type(), B::go_type(), C::go_type()],
            R::out_types(),
            false,
        ),
        move |a| f(arg(a, 0)?, arg(a, 1)?, arg(a, 2)?).into_result(),
    )
}

/// A function with four parameters.
pub fn func4<A: FromValue, B: FromValue, C: FromValue, D: FromValue, R: IntoResult>(
    f: impl Fn(A, B, C, D) -> R + Send + Sync + 'static,
) -> Value {
    Value::func_of(
        FuncSig::new(
            vec![A::go_type(), B::go_type(), C::go_type(), D::go_type()],
            R::out_types(),
            false,
        ),
        move |a| f(arg(a, 0)?, arg(a, 1)?, arg(a, 2)?, arg(a, 3)?).into_result(),
    )
}

/// A variadic function `func(...T) R`: the closure receives every argument.
pub fn variadic<T: FromValue, R: IntoResult>(
    f: impl Fn(Vec<T>) -> R + Send + Sync + 'static,
) -> Value {
    Value::func_of(
        FuncSig::new(vec![Type::slice_of(T::go_type())], R::out_types(), true),
        move |a| {
            let items: Result<Vec<T>, CallError> = (0..a.len()).map(|i| arg::<T>(a, i)).collect();
            f(items?).into_result()
        },
    )
}
