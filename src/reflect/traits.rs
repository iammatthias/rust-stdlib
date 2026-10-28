//! The `Reflect` traits: how Rust types describe themselves to this package.
//!
//! Go reads types out of the running program; Rust cannot, so a type opts in
//! with [`Reflect`] (`#[derive(Reflect)]` in `rust-stdlib-derive`, or one of the
//! implementations here for the standard types). `reflect_type` names the Go
//! type a Rust type corresponds to, `to_value` copies a Rust value into the
//! dynamic store ("ValueOf"), and `from_value` copies a dynamic value back out.
//!
//! Mapping of standard types:
//!
//! | Rust | Go |
//! |---|---|
//! | `bool`, `i8`..`i64`, `u8`..`u64`, `f32`, `f64`, `String` | the same-named kind |
//! | `isize`, `usize` | `int`, `uint` |
//! | `char` | `int32` (Go's `rune`) |
//! | `strconv::Complex` | `complex128` |
//! | `Vec<T>` | `[]T` |
//! | `[T; N]` | `[N]T` |
//! | `HashMap<K, V>`, `BTreeMap<K, V>` | `map[K]V` |
//! | `Option<T>` | `*T` (`None` is the nil pointer) |
//! | `Box<T>`, `Rc<T>`, `Arc<T>` | `T` (owning indirection is transparent) |
//! | tuples | `struct { F0 A; F1 B }` |
//! | `reflect::Value` | `interface {}` (Go's `any`) |

use std::any::TypeId;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasher, Hash};
use std::rc::Rc;
use std::sync::{Arc, LazyLock, Mutex};

use super::data::{lock, UnsafePointer};
use super::kind::Kind;
use super::typ::{
    array_of, func_of, map_of, pointer_to, slice_of, Body, MethodDef, StructField, Type,
};
use super::value::{make_map, Value};
use super::Error;
use crate::strconv::Complex;

/// A Rust type that corresponds to a Go type, possibly unsized (a `dyn Trait`
/// maps to an interface type).
pub trait ReflectType: 'static {
    /// The Go type this Rust type maps to.
    fn reflect_type() -> Type;
}

/// A Rust type whose values can be copied into and out of [`Value`]s.
pub trait Reflect: ReflectType + Sized {
    /// Go `ValueOf`: a non-addressable copy of `self` in the dynamic store.
    fn to_value(&self) -> Value;

    /// Builds a Rust value from a dynamic value of this type.
    fn from_value(v: &Value) -> Result<Self, Error>;
}

fn unwrap_iface(v: &Value) -> Value {
    if v.kind() == Kind::Interface {
        v.elem()
    } else {
        v.clone()
    }
}

fn expect(v: &Value, k: Kind) -> Result<Value, Error> {
    let v = unwrap_iface(v);
    if !v.is_valid() {
        return Err(Error::new("reflect: invalid Value"));
    }
    if v.kind() != k {
        return Err(Error::new(format!(
            "reflect: cannot use a value of type {} as {}",
            v.type_(),
            k
        )));
    }
    Ok(v)
}

macro_rules! reflect_int {
    ($($t:ty => $k:ident),* $(,)?) => { $(
        impl ReflectType for $t {
            fn reflect_type() -> Type {
                Type::basic(Kind::$k)
            }
        }
        impl Reflect for $t {
            fn to_value(&self) -> Value {
                Value::from_int(&Type::basic(Kind::$k), *self as i64)
            }
            fn from_value(v: &Value) -> Result<Self, Error> {
                let v = expect(v, Kind::$k)?;
                <$t>::try_from(v.int()).map_err(|e| Error::new(e.to_string()))
            }
        }
    )* };
}

macro_rules! reflect_uint {
    ($($t:ty => $k:ident),* $(,)?) => { $(
        impl ReflectType for $t {
            fn reflect_type() -> Type {
                Type::basic(Kind::$k)
            }
        }
        impl Reflect for $t {
            fn to_value(&self) -> Value {
                Value::from_uint(&Type::basic(Kind::$k), *self as u64)
            }
            fn from_value(v: &Value) -> Result<Self, Error> {
                let v = expect(v, Kind::$k)?;
                <$t>::try_from(v.uint()).map_err(|e| Error::new(e.to_string()))
            }
        }
    )* };
}

reflect_int!(i8 => Int8, i16 => Int16, i32 => Int32, i64 => Int64, isize => Int);
reflect_uint!(u8 => Uint8, u16 => Uint16, u32 => Uint32, u64 => Uint64, usize => Uint);

impl ReflectType for bool {
    fn reflect_type() -> Type {
        Type::basic(Kind::Bool)
    }
}

impl Reflect for bool {
    fn to_value(&self) -> Value {
        Value::from_bool(&Type::basic(Kind::Bool), *self)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        Ok(expect(v, Kind::Bool)?.bool())
    }
}

impl ReflectType for f32 {
    fn reflect_type() -> Type {
        Type::basic(Kind::Float32)
    }
}

impl Reflect for f32 {
    fn to_value(&self) -> Value {
        Value::from_float(&Type::basic(Kind::Float32), *self as f64)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        Ok(expect(v, Kind::Float32)?.float() as f32)
    }
}

impl ReflectType for f64 {
    fn reflect_type() -> Type {
        Type::basic(Kind::Float64)
    }
}

impl Reflect for f64 {
    fn to_value(&self) -> Value {
        Value::from_float(&Type::basic(Kind::Float64), *self)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        Ok(expect(v, Kind::Float64)?.float())
    }
}

impl ReflectType for Complex {
    fn reflect_type() -> Type {
        Type::basic(Kind::Complex128)
    }
}

impl Reflect for Complex {
    fn to_value(&self) -> Value {
        Value::from_complex(&Type::basic(Kind::Complex128), *self)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        Ok(expect(v, Kind::Complex128)?.complex())
    }
}

impl ReflectType for char {
    fn reflect_type() -> Type {
        Type::basic(Kind::Int32)
    }
}

impl Reflect for char {
    fn to_value(&self) -> Value {
        Value::from_int(&Type::basic(Kind::Int32), *self as i64)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        let n = expect(v, Kind::Int32)?.int();
        u32::try_from(n)
            .ok()
            .and_then(char::from_u32)
            .ok_or_else(|| Error::new(format!("reflect: {n} is not a Unicode scalar value")))
    }
}

impl ReflectType for String {
    fn reflect_type() -> Type {
        Type::basic(Kind::String)
    }
}

impl Reflect for String {
    fn to_value(&self) -> Value {
        Value::from_string(&Type::basic(Kind::String), self)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        String::from_utf8(expect(v, Kind::String)?.string_bytes())
            .map_err(|_| Error::new("reflect: string is not valid UTF-8"))
    }
}

impl ReflectType for UnsafePointer {
    fn reflect_type() -> Type {
        Type::basic(Kind::UnsafePointer)
    }
}

impl Reflect for UnsafePointer {
    fn to_value(&self) -> Value {
        Value::from_unsafe_pointer(self)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        Ok(expect(v, Kind::UnsafePointer)?.unsafe_pointer())
    }
}

impl<T: ReflectType> ReflectType for Vec<T> {
    fn reflect_type() -> Type {
        slice_of(&T::reflect_type())
    }
}

impl<T: Reflect> Reflect for Vec<T> {
    fn to_value(&self) -> Value {
        let items: Vec<Value> = self.iter().map(Reflect::to_value).collect();
        Value::from_items(&Self::reflect_type(), &items)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        let v = expect(v, Kind::Slice)?;
        (0..v.len()).map(|i| T::from_value(&v.index(i))).collect()
    }
}

impl<T: ReflectType, const N: usize> ReflectType for [T; N] {
    fn reflect_type() -> Type {
        array_of(N as isize, &T::reflect_type())
    }
}

impl<T: Reflect, const N: usize> Reflect for [T; N] {
    fn to_value(&self) -> Value {
        let items: Vec<Value> = self.iter().map(Reflect::to_value).collect();
        Value::from_parts(&Self::reflect_type(), &items)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        let v = expect(v, Kind::Array)?;
        let items: Result<Vec<T>, Error> =
            (0..v.len()).map(|i| T::from_value(&v.index(i))).collect();
        items?
            .try_into()
            .map_err(|_| Error::new("reflect: array length mismatch"))
    }
}

impl<K: ReflectType, V: ReflectType, S: 'static> ReflectType for HashMap<K, V, S> {
    fn reflect_type() -> Type {
        map_of(&K::reflect_type(), &V::reflect_type())
    }
}

impl<K: Reflect + Eq + Hash, V: Reflect, S: BuildHasher + Default + 'static> Reflect
    for HashMap<K, V, S>
{
    fn to_value(&self) -> Value {
        let m = make_map(&Self::reflect_type());
        for (k, v) in self {
            m.set_map_index(&k.to_value(), &v.to_value());
        }
        m
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        let v = expect(v, Kind::Map)?;
        let mut out = HashMap::default();
        for (k, x) in v.entries() {
            out.insert(K::from_value(&k)?, V::from_value(&x)?);
        }
        Ok(out)
    }
}

impl<K: ReflectType, V: ReflectType> ReflectType for BTreeMap<K, V> {
    fn reflect_type() -> Type {
        map_of(&K::reflect_type(), &V::reflect_type())
    }
}

impl<K: Reflect + Ord, V: Reflect> Reflect for BTreeMap<K, V> {
    fn to_value(&self) -> Value {
        let m = make_map(&Self::reflect_type());
        for (k, v) in self {
            m.set_map_index(&k.to_value(), &v.to_value());
        }
        m
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        let v = expect(v, Kind::Map)?;
        let mut out = BTreeMap::new();
        for (k, x) in v.entries() {
            out.insert(K::from_value(&k)?, V::from_value(&x)?);
        }
        Ok(out)
    }
}

impl<T: ReflectType> ReflectType for Option<T> {
    fn reflect_type() -> Type {
        pointer_to(&T::reflect_type())
    }
}

impl<T: Reflect> Reflect for Option<T> {
    fn to_value(&self) -> Value {
        match self {
            None => Value::from_pointer(&Self::reflect_type(), None),
            Some(x) => Value::from_pointer(&Self::reflect_type(), Some(&x.to_value())),
        }
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        let v = expect(v, Kind::Pointer)?;
        if v.is_nil() {
            return Ok(None);
        }
        Ok(Some(T::from_value(&v.elem())?))
    }
}

macro_rules! reflect_owner {
    ($($p:ident),*) => { $(
        impl<T: ReflectType> ReflectType for $p<T> {
            fn reflect_type() -> Type {
                T::reflect_type()
            }
        }
        impl<T: Reflect> Reflect for $p<T> {
            fn to_value(&self) -> Value {
                (**self).to_value()
            }
            fn from_value(v: &Value) -> Result<Self, Error> {
                Ok($p::new(T::from_value(v)?))
            }
        }
    )* };
}

reflect_owner!(Box, Rc, Arc);

/// A Rust value held in a struct field of Go type `interface {}`: the field
/// holds a [`Value`] (or nothing).
impl ReflectType for Value {
    fn reflect_type() -> Type {
        Type::any_type()
    }
}

impl Reflect for Value {
    fn to_value(&self) -> Value {
        Value::from_interface(&Type::any_type(), self)
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        Ok(unwrap_iface(v))
    }
}

/// The concrete Go type `errors.errorString` that carries an error text.
fn error_string_type() -> Type {
    static T: LazyLock<Type> = LazyLock::new(|| {
        let under = super::typ::struct_of(&[
            StructField::new("s", Type::basic(Kind::String)).with_pkg_path("errors")
        ]);
        let method = MethodDef {
            name: "Error".into(),
            pkg_path: String::new(),
            ty: func_of(&[], &[Type::basic(Kind::String)], false),
            ptr_recv: true,
            call: Arc::new(|rv: &Value, _args: &[Value]| {
                let target = if rv.kind() == Kind::Pointer {
                    rv.elem()
                } else {
                    rv.clone()
                };
                vec![target.part(0)]
            }),
        };
        Type::named("errors", "errorString", &under, vec![method])
    });
    T.clone()
}

/// A Go `error` result: `Ok(())` is the nil error and `Err(text)` a non-nil
/// error whose `Error()` is `text`. This is how a method registered with
/// `#[reflect_methods]` returns Go's `error`.
impl ReflectType for Result<(), String> {
    fn reflect_type() -> Type {
        Type::error_type()
    }
}

impl Reflect for Result<(), String> {
    fn to_value(&self) -> Value {
        match self {
            Ok(()) => super::value::zero(&Type::error_type()),
            Err(text) => {
                let t = error_string_type();
                let p = super::value::new(&t);
                p.elem()
                    .overwrite(&Value::from_parts(&t, &[text.to_value()]));
                Value::from_interface(&Type::error_type(), &p)
            }
        }
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        if !v.is_valid() || (v.kind() == Kind::Interface && v.is_nil()) {
            return Ok(Ok(()));
        }
        let m = v.method_by_name("Error");
        match m.call(&[]).first() {
            Some(r) => Ok(Err(String::from_utf8_lossy(&r.string_bytes()).into_owned())),
            None => Err(Error::new("reflect: error value has no Error method")),
        }
    }
}

/// A `&mut T` method parameter, which is Go's `*T`: the caller passes a
/// pointer and the method's changes are written back through it.
#[doc(hidden)]
pub struct PtrArg<T>(Value, std::marker::PhantomData<T>);

impl<T: ReflectType> ReflectType for PtrArg<T> {
    fn reflect_type() -> Type {
        pointer_to(&T::reflect_type())
    }
}

impl<T: Reflect> Reflect for PtrArg<T> {
    fn to_value(&self) -> Value {
        self.0.clone()
    }
    fn from_value(v: &Value) -> Result<Self, Error> {
        Ok(PtrArg(expect(v, Kind::Pointer)?, std::marker::PhantomData))
    }
}

impl<T: Reflect> PtrArg<T> {
    /// Copies the pointee out (the zero value of a nil pointer is not
    /// representable, so a nil pointer panics as Go's dereference would).
    pub fn load(&self) -> T {
        match T::from_value(&self.0.elem()) {
            Ok(t) => t,
            Err(e) => panic!("reflect: method pointer argument: {e}"),
        }
    }

    /// Writes the value back through the pointer.
    pub fn store(&self, t: &T) {
        self.0.elem().overwrite(&t.to_value());
    }
}

macro_rules! reflect_tuple {
    ($($name:ident : $idx:tt),+) => {
        impl<$($name: ReflectType),+> ReflectType for ($($name,)+) {
            fn reflect_type() -> Type {
                tuple_type(&[$($name::reflect_type()),+])
            }
        }
        impl<$($name: Reflect),+> Reflect for ($($name,)+) {
            fn to_value(&self) -> Value {
                Value::from_parts(&Self::reflect_type(), &[$(self.$idx.to_value()),+])
            }
            fn from_value(v: &Value) -> Result<Self, Error> {
                let v = expect(v, Kind::Struct)?;
                Ok(($($name::from_value(&v.field($idx))?,)+))
            }
        }
    };
}

fn tuple_type(types: &[Type]) -> Type {
    let fields: Vec<StructField> = types
        .iter()
        .enumerate()
        .map(|(i, t)| StructField::new(&format!("F{i}"), t.clone()))
        .collect();
    super::typ::struct_of(&fields)
}

reflect_tuple!(A: 0);
reflect_tuple!(A: 0, B: 1);
reflect_tuple!(A: 0, B: 1, C: 2);
reflect_tuple!(A: 0, B: 1, C: 2, D: 3);
reflect_tuple!(A: 0, B: 1, C: 2, D: 3, E: 4);
reflect_tuple!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5);

// ---------------------------------------------------------------------------
// Function values.

/// The parameter list of a Rust function that is exposed as a Go function
/// value: a tuple of [`Reflect`] types.
pub trait ArgList: Sized {
    /// The parameter types.
    fn types() -> Vec<Type>;
    /// Reads the arguments from dynamic values.
    fn from_args(args: &[Value]) -> Result<Self, Error>;
}

/// The result list of a Rust function that is exposed as a Go function value.
pub trait RetList {
    /// The result types.
    fn types() -> Vec<Type>;
    /// Converts the results to dynamic values.
    fn into_values(self) -> Vec<Value>;
}

/// A function with no results.
impl RetList for () {
    fn types() -> Vec<Type> {
        Vec::new()
    }
    fn into_values(self) -> Vec<Value> {
        Vec::new()
    }
}

/// A function with a single result.
pub struct One<T>(pub T);

impl<T: Reflect> RetList for One<T> {
    fn types() -> Vec<Type> {
        vec![T::reflect_type()]
    }
    fn into_values(self) -> Vec<Value> {
        vec![self.0.to_value()]
    }
}

/// A function with several results, given as a tuple.
pub struct Multi<T>(pub T);

macro_rules! args_tuple {
    ($($name:ident : $idx:tt),*) => {
        impl<$($name: Reflect),*> ArgList for ($($name,)*) {
            fn types() -> Vec<Type> {
                vec![$($name::reflect_type()),*]
            }
            #[allow(unused_variables)]
            fn from_args(args: &[Value]) -> Result<Self, Error> {
                Ok(($($name::from_value(&args[$idx])?,)*))
            }
        }
        impl<$($name: Reflect),*> RetList for Multi<($($name,)*)> {
            fn types() -> Vec<Type> {
                vec![$($name::reflect_type()),*]
            }
            fn into_values(self) -> Vec<Value> {
                vec![$(self.0.$idx.to_value()),*]
            }
        }
    };
}

args_tuple!();
args_tuple!(A: 0);
args_tuple!(A: 0, B: 1);
args_tuple!(A: 0, B: 1, C: 2);
args_tuple!(A: 0, B: 1, C: 2, D: 3);
args_tuple!(A: 0, B: 1, C: 2, D: 3, E: 4);
args_tuple!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5);
args_tuple!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6);
args_tuple!(A: 0, B: 1, C: 2, D: 3, E: 4, F: 5, G: 6, H: 7);

/// Wraps a Rust closure as a Go function value. `A` is the tuple of parameter
/// types and `R` the result list (`()`, [`One`] or [`Multi`]).
///
/// ```
/// use rust_stdlib::reflect::{self, One, Reflect};
/// let add = reflect::func(|(a, b): (i64, i64)| One(a + b));
/// let out = add.call(&[7i64.to_value(), 5i64.to_value()]);
/// assert_eq!(out[0].int(), 12);
/// ```
pub fn func<A: ArgList, R: RetList>(f: impl Fn(A) -> R + Send + Sync + 'static) -> Value {
    let ty = func_of(&A::types(), &R::types(), false);
    super::value::make_func(&ty, move |args| match A::from_args(args) {
        Ok(a) => f(a).into_values(),
        Err(e) => panic!("{e}"),
    })
}

/// Like [`func`] for a variadic function: the last element of the tuple `A` is
/// the `Vec<T>` that collects the variadic arguments.
pub fn func_variadic<A: ArgList, R: RetList>(f: impl Fn(A) -> R + Send + Sync + 'static) -> Value {
    let ty = func_of(&A::types(), &R::types(), true);
    super::value::make_func(&ty, move |args| match A::from_args(args) {
        Ok(a) => f(a).into_values(),
        Err(e) => panic!("{e}"),
    })
}

// ---------------------------------------------------------------------------
// Support for generated code.

/// Support for `#[derive(Reflect)]`, `#[reflect_methods]` and
/// `#[reflect_trait]`. Not part of the stable API.
#[doc(hidden)]
pub mod private {
    use super::*;

    pub use super::PtrArg;
    pub use crate::reflect::typ::Body;

    static REGISTRY: LazyLock<Mutex<HashMap<TypeId, Type>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    /// The named type for Rust type `T`, created on first use.
    pub fn named_type<T: ?Sized + 'static>(
        pkg_path: &str,
        name: impl FnOnce() -> String,
        init: fn() -> Body,
        methods: Option<fn() -> Vec<MethodDef>>,
    ) -> Type {
        let id = TypeId::of::<T>();
        if let Some(t) = lock(&REGISTRY).get(&id) {
            return t.clone();
        }
        let t = Type::declare(pkg_path, &name(), init, methods);
        lock(&REGISTRY).entry(id).or_insert(t).clone()
    }

    /// The methods of a type, registered by `#[reflect_methods]`.
    pub trait ReflectMethods {
        /// The method descriptions.
        fn reflect_methods() -> Vec<MethodDef>;
    }

    /// Probe for the optional [`ReflectMethods`] implementation of `T` using
    /// autoref specialization.
    pub struct Probe<T>(std::marker::PhantomData<T>);

    impl<T> Probe<T> {
        /// A probe for `T`.
        pub fn new() -> Probe<T> {
            Probe(std::marker::PhantomData)
        }
    }

    impl<T> Default for Probe<T> {
        fn default() -> Probe<T> {
            Probe::new()
        }
    }

    /// Chosen when `T: ReflectMethods`.
    pub trait ViaHas {
        /// The registered methods.
        fn reflect_methods_probe(&self) -> Vec<MethodDef>;
    }

    impl<T: ReflectMethods> ViaHas for Probe<T> {
        fn reflect_methods_probe(&self) -> Vec<MethodDef> {
            T::reflect_methods()
        }
    }

    /// The fallback: no registered methods.
    pub trait ViaNone {
        /// No methods.
        fn reflect_methods_probe(&self) -> Vec<MethodDef>;
    }

    impl<T> ViaNone for &Probe<T> {
        fn reflect_methods_probe(&self) -> Vec<MethodDef> {
            Vec::new()
        }
    }

    /// The error for a value of the wrong kind in a derived `from_value`.
    pub fn mismatch(v: &Value, want: &str) -> Error {
        if v.is_valid() {
            Error::new(format!(
                "reflect: cannot use a value of type {} as a {want}",
                v.type_()
            ))
        } else {
            Error::new("reflect: invalid Value")
        }
    }

    /// The error for an out-of-range enum discriminant.
    pub fn bad_variant(name: &str, n: i64) -> Error {
        Error::new(format!("reflect: {n} is not a variant of {name}"))
    }

    /// The body of a struct type.
    pub fn struct_body(fields: Vec<StructField>, pkg_path: &str) -> Body {
        Type::struct_body_fields(fields, pkg_path)
    }

    /// The body of a basic kind (for unit-only enums, which are Go ints).
    pub fn basic_body(kind: Kind) -> Body {
        Type::basic_body(kind)
    }

    /// The body of an interface type with the given methods (name, signature).
    pub fn interface_body(methods: &[(&str, Type)]) -> Body {
        Type::interface_body(methods)
    }

    /// A struct field description.
    pub fn field(name: &str, ty: Type, tag: &str, embedded: bool, pkg_path: &str) -> StructField {
        let mut f = StructField::new(name, ty).with_pkg_path(pkg_path);
        f.tag = super::super::StructTag::new(tag);
        f.anonymous = embedded;
        f
    }

    /// The kind of receiver a registered method has.
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub enum Recv {
        /// `&self`
        Shared,
        /// `&mut self`
        Mutable,
    }

    /// Registers a method of `T`. `f` receives the receiver and the decoded
    /// arguments. For `Recv::Mutable` methods the receiver is written back.
    pub fn method<T: Reflect, A: ArgList, R: RetList>(
        name: &str,
        exported: bool,
        pkg_path: &str,
        recv: Recv,
        f: impl Fn(&mut T, A) -> R + Send + Sync + 'static,
    ) -> MethodDef {
        let ty = func_of(&A::types(), &R::types(), false);
        MethodDef {
            name: name.to_string(),
            pkg_path: if exported {
                String::new()
            } else {
                pkg_path.to_string()
            },
            ty,
            ptr_recv: recv == Recv::Mutable,
            call: Arc::new(move |rv: &Value, args: &[Value]| {
                let target = if rv.kind() == Kind::Pointer {
                    rv.elem()
                } else {
                    rv.clone()
                };
                let mut me = match T::from_value(&target) {
                    Ok(t) => t,
                    Err(e) => panic!("reflect: method receiver: {e}"),
                };
                let a = match A::from_args(args) {
                    Ok(a) => a,
                    Err(e) => panic!("reflect: method arguments: {e}"),
                };
                let out = f(&mut me, a);
                if recv == Recv::Mutable {
                    target.overwrite(&me.to_value());
                }
                out.into_values()
            }),
        }
    }
}

impl Type {
    #[doc(hidden)]
    pub fn basic_body(kind: Kind) -> Body {
        Body::Basic(kind)
    }

    #[doc(hidden)]
    pub fn interface_body(methods: &[(&str, Type)]) -> Body {
        let t = super::typ::interface_of(methods);
        Type::underlying_body(&t)
    }
}
