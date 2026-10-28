//! The argument model: Go's `fmt` is driven by reflection over `any`
//! operands, so this module spells out what reflection would have seen.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use std::fmt::{Debug, Display};

use super::Formatter;

/// The error type stored by [`Methods::error`].
pub type DynError = Arc<dyn std::error::Error + Send + Sync + 'static>;

/// Which Go signed integer type an [`Value::Int`] has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntKind {
    Int,
    Int8,
    Int16,
    Int32,
    Int64,
}

/// Which Go unsigned integer type a [`Value::Uint`] has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UintKind {
    Uint,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uintptr,
}

/// The methods a Go type brings to formatting. `handleMethods` consults them
/// in Go's order: `Formatter`, then (for `%#v`) the [`Debug`] implementation
/// (Go's `GoStringer`), then for the verbs `%v %s %x %X %q` `error` and the
/// [`Display`] implementation (Go's `Stringer`).
#[derive(Clone, Default)]
pub struct Methods {
    pub formatter: Option<Arc<dyn Formatter + Send + Sync>>,
    pub debug: Option<Arc<dyn Debug + Send + Sync>>,
    pub error: Option<DynError>,
    pub display: Option<Arc<dyn Display + Send + Sync>>,
}

/// A value of a named Go type: carries the type name (`%T`), methods and the
/// underlying value that is printed when no method applies.
#[derive(Clone)]
pub struct Named {
    pub type_name: String,
    pub value: Value,
    pub methods: Methods,
}

/// A Go slice or array.
#[derive(Clone, Debug)]
pub struct Seq {
    /// The full Go type, for example `[]int` or `[3]string`.
    pub type_name: String,
    /// The element type, for example `int`.
    pub elem: String,
    pub items: Vec<Value>,
    /// The element kind is `uint8` (also for named byte types): `%s %q %x %X`
    /// then format the elements as bytes.
    pub bytes: bool,
    pub array: bool,
    /// A nil slice (`[]int(nil)` under `%#v`).
    pub nil: bool,
    /// The address `%p` prints; 0 for a nil slice.
    pub addr: usize,
}

/// A Go map. Entries are printed sorted by key, as `internal/fmtsort` does.
#[derive(Clone, Debug)]
pub struct MapV {
    pub type_name: String,
    pub entries: Vec<(Value, Value)>,
    pub nil: bool,
    pub addr: usize,
}

/// A Go struct. A field is exported when its name starts with an upper-case
/// letter; methods of values reached through unexported fields are ignored.
#[derive(Clone, Debug)]
pub struct StructV {
    pub type_name: String,
    pub fields: Vec<(String, Value)>,
}

/// A Go pointer, channel, function or `unsafe.Pointer`: an address and, for
/// pointers, the value pointed to.
#[derive(Clone, Debug)]
pub struct Ptr {
    pub type_name: String,
    pub addr: usize,
    pub elem: Option<Value>,
}

/// One operand of the print and scan families (Go's `any`).
#[derive(Clone)]
pub enum Value {
    /// The untyped `nil` interface.
    Nil,
    /// A nil interface-typed slot of the given interface type (`error`, ...).
    NilIface(String),
    Bool(bool),
    Int(i64, IntKind),
    Uint(u64, UintKind),
    Float32(f32),
    Float64(f64),
    Complex64(f32, f32),
    Complex128(f64, f64),
    /// A Go string: bytes that need not be UTF-8.
    String(Vec<u8>),
    Slice(Box<Seq>),
    Map(Box<MapV>),
    Struct(Box<StructV>),
    Pointer(Box<Ptr>),
    Named(Box<Named>),
}

/// An alias for [`Value`]: the operand type of the print functions.
pub type Arg = Value;

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Named(n) => write!(f, "Named({}, {:?})", n.type_name, n.value),
            Value::Nil => f.write_str("Nil"),
            Value::NilIface(t) => write!(f, "NilIface({t})"),
            Value::Bool(b) => write!(f, "Bool({b})"),
            Value::Int(i, k) => write!(f, "Int({i}, {k:?})"),
            Value::Uint(i, k) => write!(f, "Uint({i}, {k:?})"),
            Value::Float32(x) => write!(f, "Float32({x})"),
            Value::Float64(x) => write!(f, "Float64({x})"),
            Value::Complex64(a, b) => write!(f, "Complex64({a}, {b})"),
            Value::Complex128(a, b) => write!(f, "Complex128({a}, {b})"),
            Value::String(s) => write!(f, "String({:?})", String::from_utf8_lossy(s)),
            Value::Slice(s) => s.fmt(f),
            Value::Map(m) => m.fmt(f),
            Value::Struct(s) => s.fmt(f),
            Value::Pointer(p) => p.fmt(f),
        }
    }
}

impl Value {
    /// A Go `int`.
    pub fn int(v: i64) -> Value {
        Value::Int(v, IntKind::Int)
    }

    /// A Go `uint`.
    pub fn uint(v: u64) -> Value {
        Value::Uint(v, UintKind::Uint)
    }

    /// A Go string from bytes that need not be valid UTF-8.
    pub fn bytes_string(b: impl Into<Vec<u8>>) -> Value {
        Value::String(b.into())
    }

    /// A Go slice with the given element type and items.
    pub fn slice(elem: &str, items: Vec<Value>) -> Value {
        let addr = if items.is_empty() {
            0xc0_0001_0000
        } else {
            0xc0_0001_2000
        };
        Value::Slice(Box::new(Seq {
            type_name: format!("[]{elem}"),
            elem: elem.to_string(),
            items,
            bytes: elem == "uint8",
            array: false,
            nil: false,
            addr,
        }))
    }

    /// A nil Go slice (`[]T(nil)`).
    pub fn nil_slice(elem: &str) -> Value {
        Value::Slice(Box::new(Seq {
            type_name: format!("[]{elem}"),
            elem: elem.to_string(),
            items: Vec::new(),
            bytes: elem == "uint8",
            array: false,
            nil: true,
            addr: 0,
        }))
    }

    /// A Go array `[N]T`.
    pub fn array(elem: &str, items: Vec<Value>) -> Value {
        Value::Slice(Box::new(Seq {
            type_name: format!("[{}]{elem}", items.len()),
            elem: elem.to_string(),
            items,
            bytes: elem == "uint8",
            array: true,
            nil: false,
            addr: 0xc0_0002_0000,
        }))
    }

    /// A Go `[]byte`.
    pub fn bytes(b: impl AsRef<[u8]>) -> Value {
        Value::slice(
            "uint8",
            b.as_ref()
                .iter()
                .map(|&c| Value::Uint(c as u64, UintKind::Uint8))
                .collect(),
        )
    }

    /// A Go `map[K]V`.
    pub fn map(key: &str, val: &str, entries: Vec<(Value, Value)>) -> Value {
        Value::Map(Box::new(MapV {
            type_name: format!("map[{key}]{val}"),
            entries,
            nil: false,
            addr: 0xc0_0003_0000,
        }))
    }

    /// A nil Go map.
    pub fn nil_map(key: &str, val: &str) -> Value {
        Value::Map(Box::new(MapV {
            type_name: format!("map[{key}]{val}"),
            entries: Vec::new(),
            nil: true,
            addr: 0,
        }))
    }

    /// A Go struct value; `type_name` is printed by `%T` and `%#v`.
    pub fn strukt(type_name: &str, fields: Vec<(&str, Value)>) -> Value {
        Value::Struct(Box::new(StructV {
            type_name: type_name.to_string(),
            fields: fields
                .into_iter()
                .map(|(n, v)| (n.to_string(), v))
                .collect(),
        }))
    }

    /// A non-nil Go pointer of type `type_name` (for example `*main.T`) to
    /// `elem`, at the given address.
    pub fn pointer(type_name: &str, addr: usize, elem: Value) -> Value {
        Value::Pointer(Box::new(Ptr {
            type_name: type_name.to_string(),
            addr,
            elem: Some(elem),
        }))
    }

    /// A nil Go pointer of type `type_name`.
    pub fn nil_pointer(type_name: &str) -> Value {
        Value::Pointer(Box::new(Ptr {
            type_name: type_name.to_string(),
            addr: 0,
            elem: None,
        }))
    }

    /// A pointer-like value without a pointee (channel, function,
    /// `unsafe.Pointer`) of the given type and address.
    pub fn raw_pointer(type_name: &str, addr: usize) -> Value {
        Value::Pointer(Box::new(Ptr {
            type_name: type_name.to_string(),
            addr,
            elem: None,
        }))
    }

    /// Wraps `inner` as a value of the named Go type `type_name`.
    pub fn named(type_name: &str, inner: Value) -> Value {
        Value::Named(Box::new(Named {
            type_name: type_name.to_string(),
            value: inner,
            methods: Methods::default(),
        }))
    }

    fn methods_mut(&mut self) -> &mut Methods {
        if !matches!(self, Value::Named(_)) {
            let name = super::print::type_string(self);
            let inner = std::mem::replace(self, Value::Nil);
            *self = Value::named(&name, inner);
        }
        match self {
            Value::Named(n) => &mut n.methods,
            _ => unreachable!(),
        }
    }

    /// Gives the value a `String() string` method: its [`Display`] output.
    pub fn with_display(mut self, s: impl Display + Send + Sync + 'static) -> Value {
        self.methods_mut().display = Some(Arc::new(s));
        self
    }

    /// Gives the value a `GoString() string` method: its [`Debug`] output,
    /// used for `%#v`.
    pub fn with_debug(mut self, s: impl Debug + Send + Sync + 'static) -> Value {
        self.methods_mut().debug = Some(Arc::new(s));
        self
    }

    /// Gives the value a `Format(State, rune)` method.
    pub fn with_formatter(mut self, f: impl Formatter + Send + Sync + 'static) -> Value {
        self.methods_mut().formatter = Some(Arc::new(f));
        self
    }

    /// Gives the value an `Error() string` method.
    pub fn with_error(mut self, e: impl std::error::Error + Send + Sync + 'static) -> Value {
        self.methods_mut().error = Some(Arc::new(e));
        self
    }

    /// An operand that is an error value of Rust type `E`; the Go type name
    /// is the Rust type name.
    pub fn from_error<E: std::error::Error + Send + Sync + 'static>(e: E) -> Value {
        Value::from_dyn_error(Arc::new(e), std::any::type_name::<E>())
    }

    /// An error operand from a shared error object.
    pub fn from_dyn_error(e: DynError, type_name: &str) -> Value {
        let inner = Value::strukt(type_name, Vec::new());
        Value::Named(Box::new(Named {
            type_name: type_name.to_string(),
            value: inner,
            methods: Methods {
                error: Some(e),
                ..Methods::default()
            },
        }))
    }

    /// An operand whose type has a `String` method.
    pub fn from_display<S: Display + Send + Sync + 'static>(s: S) -> Value {
        let name = std::any::type_name::<S>();
        Value::strukt(name, Vec::new()).with_display(s)
    }

    /// The value with any [`Value::Named`] wrapper removed.
    pub fn underlying(&self) -> &Value {
        match self {
            Value::Named(n) => n.value.underlying(),
            v => v,
        }
    }

    /// The methods of the value, if it is a named type.
    pub fn methods(&self) -> Option<&Methods> {
        match self {
            Value::Named(n) => Some(&n.methods),
            _ => None,
        }
    }

    /// The error object when the operand implements `error`.
    pub fn as_error(&self) -> Option<DynError> {
        self.methods().and_then(|m| m.error.clone())
    }
}

/// The Go type name of a Rust type, for typing the elements of generated
/// slices, arrays and maps.
pub trait OperandType {
    fn operand_type() -> String;
}

macro_rules! scalar {
    ($($t:ty => $name:expr, $ctor:expr;)*) => {$(
        impl OperandType for $t { fn operand_type() -> String { $name.to_string() } }
        impl From<$t> for Value { fn from(v: $t) -> Value { $ctor(v) } }
    )*};
}

scalar! {
    bool => "bool", Value::Bool;
    i8 => "int8", |v| Value::Int(v as i64, IntKind::Int8);
    i16 => "int16", |v| Value::Int(v as i64, IntKind::Int16);
    i32 => "int32", |v| Value::Int(v as i64, IntKind::Int32);
    i64 => "int64", |v| Value::Int(v, IntKind::Int64);
    isize => "int", |v| Value::Int(v as i64, IntKind::Int);
    u8 => "uint8", |v| Value::Uint(v as u64, UintKind::Uint8);
    u16 => "uint16", |v| Value::Uint(v as u64, UintKind::Uint16);
    u32 => "uint32", |v| Value::Uint(v as u64, UintKind::Uint32);
    u64 => "uint64", |v| Value::Uint(v, UintKind::Uint64);
    usize => "uint", |v| Value::Uint(v as u64, UintKind::Uint);
    f32 => "float32", Value::Float32;
    f64 => "float64", Value::Float64;
    char => "int32", |v| Value::Int(v as i64, IntKind::Int32);
    String => "string", |v: String| Value::String(v.into_bytes());
}

impl OperandType for &str {
    fn operand_type() -> String {
        "string".into()
    }
}
impl OperandType for Value {
    fn operand_type() -> String {
        "interface {}".into()
    }
}
impl OperandType for () {
    fn operand_type() -> String {
        "struct {}".into()
    }
}
impl<T: OperandType> OperandType for Vec<T> {
    fn operand_type() -> String {
        format!("[]{}", T::operand_type())
    }
}
impl<T: OperandType> OperandType for &[T] {
    fn operand_type() -> String {
        format!("[]{}", T::operand_type())
    }
}
impl<T: OperandType, const N: usize> OperandType for [T; N] {
    fn operand_type() -> String {
        format!("[{N}]{}", T::operand_type())
    }
}
impl<T: OperandType> OperandType for Option<T> {
    fn operand_type() -> String {
        format!("*{}", T::operand_type())
    }
}
impl<T: OperandType> OperandType for Box<T> {
    fn operand_type() -> String {
        format!("*{}", T::operand_type())
    }
}
impl<K: OperandType, V: OperandType> OperandType for HashMap<K, V> {
    fn operand_type() -> String {
        format!("map[{}]{}", K::operand_type(), V::operand_type())
    }
}
impl<K: OperandType, V: OperandType> OperandType for BTreeMap<K, V> {
    fn operand_type() -> String {
        format!("map[{}]{}", K::operand_type(), V::operand_type())
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Value {
        Value::String(v.as_bytes().to_vec())
    }
}
impl From<std::borrow::Cow<'_, str>> for Value {
    fn from(v: std::borrow::Cow<'_, str>) -> Value {
        Value::String(v.into_owned().into_bytes())
    }
}
impl From<()> for Value {
    fn from(_: ()) -> Value {
        Value::strukt("struct {}", Vec::new())
    }
}
/// References convert like the value they point to (an `&i32` is an `int32`
/// operand, not a pointer; build pointers with [`Value::pointer`]).
impl<T: Clone + Into<Value>> From<&T> for Value {
    fn from(v: &T) -> Value {
        v.clone().into()
    }
}
impl<T: OperandType + Into<Value>> From<Vec<T>> for Value {
    fn from(v: Vec<T>) -> Value {
        Value::slice(&T::operand_type(), v.into_iter().map(Into::into).collect())
    }
}
impl<T: OperandType + Clone + Into<Value>> From<&[T]> for Value {
    fn from(v: &[T]) -> Value {
        Value::slice(
            &T::operand_type(),
            v.iter().cloned().map(Into::into).collect(),
        )
    }
}
impl<T: OperandType + Into<Value>, const N: usize> From<[T; N]> for Value {
    fn from(v: [T; N]) -> Value {
        Value::array(&T::operand_type(), v.into_iter().map(Into::into).collect())
    }
}
/// `Some(x)` is a non-nil pointer to `x`; `None` is a nil pointer.
impl<T: OperandType + Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Value {
        let name = format!("*{}", T::operand_type());
        match v {
            Some(x) => Value::pointer(&name, 0xc0_0004_0000, x.into()),
            None => Value::nil_pointer(&name),
        }
    }
}
impl<T: OperandType + Into<Value>> From<Box<T>> for Value {
    fn from(v: Box<T>) -> Value {
        let name = format!("*{}", T::operand_type());
        Value::pointer(&name, 0xc0_0004_0000, (*v).into())
    }
}
impl<K: OperandType + Into<Value>, V: OperandType + Into<Value>> From<HashMap<K, V>> for Value {
    fn from(m: HashMap<K, V>) -> Value {
        Value::map(
            &K::operand_type(),
            &V::operand_type(),
            m.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
        )
    }
}
impl<K: OperandType + Into<Value>, V: OperandType + Into<Value>> From<BTreeMap<K, V>> for Value {
    fn from(m: BTreeMap<K, V>) -> Value {
        Value::map(
            &K::operand_type(),
            &V::operand_type(),
            m.into_iter().map(|(k, v)| (k.into(), v.into())).collect(),
        )
    }
}
impl From<DynError> for Value {
    fn from(e: DynError) -> Value {
        Value::from_dyn_error(e, "*errors.errorString")
    }
}
impl From<Box<dyn std::error::Error + Send + Sync>> for Value {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Value {
        Value::from_dyn_error(Arc::from(e), "*errors.errorString")
    }
}
impl From<std::io::Error> for Value {
    fn from(e: std::io::Error) -> Value {
        Value::from_dyn_error(Arc::new(e), "*errors.errorString")
    }
}
impl From<super::WrapError> for Value {
    fn from(e: super::WrapError) -> Value {
        e.to_value()
    }
}
