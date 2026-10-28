//! The dynamic value model templates execute over.
//!
//! Go's templates walk data with `reflect`. This module is the Rust-native
//! counterpart: a [`Type`] describes a Go type (named types with method sets,
//! structs, maps, slices, pointers, interfaces, functions, channels, the sized
//! numeric kinds) and a [`Value`] is a typed, immutable datum. Values are
//! built from Rust data with [`ToValue`] or constructed directly. Methods are
//! registered callables on named types ([`Method`]); functions are callables
//! (`Value::func`). Maps keep their entries ordered the way Go's `fmtsort`
//! orders them, so ranging and printing are deterministic.

use std::fmt;
use std::sync::{Arc, OnceLock};

/// The kind of a [`Type`] or [`Value`] (Go `reflect.Kind`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Invalid,
    Bool,
    Int,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uintptr,
    Float32,
    Float64,
    Complex64,
    Complex128,
    Array,
    Chan,
    Func,
    Interface,
    Map,
    Pointer,
    Slice,
    String,
    Struct,
    UnsafePointer,
}

impl Kind {
    /// Reports whether the kind is a signed integer kind.
    pub fn is_int(self) -> bool {
        matches!(
            self,
            Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64
        )
    }
    /// Reports whether the kind is an unsigned integer kind.
    pub fn is_uint(self) -> bool {
        matches!(
            self,
            Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 | Kind::Uintptr
        )
    }
    pub(crate) fn int_like(self) -> bool {
        self.is_int() || self.is_uint()
    }
    fn basic_name(self) -> &'static str {
        match self {
            Kind::Bool => "bool",
            Kind::Int => "int",
            Kind::Int8 => "int8",
            Kind::Int16 => "int16",
            Kind::Int32 => "int32",
            Kind::Int64 => "int64",
            Kind::Uint => "uint",
            Kind::Uint8 => "uint8",
            Kind::Uint16 => "uint16",
            Kind::Uint32 => "uint32",
            Kind::Uint64 => "uint64",
            Kind::Uintptr => "uintptr",
            Kind::Float32 => "float32",
            Kind::Float64 => "float64",
            Kind::Complex64 => "complex64",
            Kind::Complex128 => "complex128",
            Kind::String => "string",
            Kind::UnsafePointer => "unsafe.Pointer",
            _ => "invalid",
        }
    }
}

/// The direction of a channel type (Go `reflect.ChanDir`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChanDir {
    Recv,
    Send,
    Both,
}

/// The signature of a function or method (receiver excluded).
#[derive(Clone, Debug, PartialEq)]
pub struct FuncSig {
    pub ins: Vec<Type>,
    pub outs: Vec<Type>,
    /// Whether the last parameter, a slice type, is variadic.
    pub variadic: bool,
}

impl FuncSig {
    /// Builds a signature.
    pub fn new(ins: Vec<Type>, outs: Vec<Type>, variadic: bool) -> FuncSig {
        FuncSig {
            ins,
            outs,
            variadic,
        }
    }
}

/// A struct field.
#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub name: String,
    pub ty: Type,
    pub embedded: bool,
    /// The raw struct tag, such as `json:"name,omitempty"`.
    pub tag: String,
}

impl Field {
    /// A named field.
    pub fn new(name: &str, ty: Type) -> Field {
        Field {
            name: name.to_owned(),
            ty,
            embedded: false,
            tag: String::new(),
        }
    }
    /// The field with the given struct tag.
    pub fn with_tag(mut self, tag: &str) -> Field {
        self.tag = tag.to_owned();
        self
    }
    /// An embedded field, named after its type.
    pub fn embedded(ty: Type) -> Field {
        let mut t = ty.clone();
        if t.kind() == Kind::Pointer {
            t = t.elem().expect("pointer elem");
        }
        let name = t.name().unwrap_or_default();
        Field {
            name,
            ty,
            embedded: true,
            tag: String::new(),
        }
    }
    /// Reports whether the field name is exported.
    pub fn is_exported(&self) -> bool {
        self.name.chars().next().is_some_and(|c| {
            if c.is_ascii() {
                c.is_ascii_uppercase()
            } else {
                crate::unicode::is_upper(c as i32)
            }
        })
    }
}

/// The error a callable returns instead of a value.
#[derive(Clone, Debug)]
pub enum CallError {
    /// A returned Go `error`.
    Error(FuncError),
    /// A recovered panic.
    Panic(String),
}

impl From<FuncError> for CallError {
    fn from(e: FuncError) -> CallError {
        CallError::Error(e)
    }
}

impl CallError {
    /// An error with the given message.
    pub fn msg(s: impl Into<String>) -> CallError {
        CallError::Error(FuncError::new(s))
    }
}

/// A Go `error` value: a message and, optionally, a wrapped cause.
#[derive(Clone, Debug)]
pub struct FuncError {
    msg: Arc<str>,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl FuncError {
    /// An error with the given message (Go `errors.New`).
    pub fn new(msg: impl Into<String>) -> FuncError {
        FuncError {
            msg: msg.into().into(),
            source: None,
        }
    }
    /// An error with a message that wraps a cause (Go `fmt.Errorf("%w")`).
    pub fn wrap(
        msg: impl Into<String>,
        source: Arc<dyn std::error::Error + Send + Sync>,
    ) -> FuncError {
        FuncError {
            msg: msg.into().into(),
            source: Some(source),
        }
    }
}

impl fmt::Display for FuncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for FuncError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| {
            let r: &(dyn std::error::Error + 'static) = &**e;
            r
        })
    }
}

/// A function body: arguments in, one result or an error out. A Go function
/// returning `(T, error)` returns `Ok(T)` or `Err`; a function with no result
/// returns `Ok(Value::nil())`.
pub type Callable = Arc<dyn Fn(&[Value]) -> Result<Value, CallError> + Send + Sync>;

/// A method body: receiver, then arguments.
pub type MethodFn = Arc<dyn Fn(&Value, &[Value]) -> Result<Value, CallError> + Send + Sync>;

/// A method of a named type.
#[derive(Clone)]
pub struct Method {
    pub name: String,
    /// Whether the receiver is a pointer (`func (t *T) M()`).
    pub ptr_recv: bool,
    pub sig: FuncSig,
    pub f: MethodFn,
}

impl Method {
    /// A method with the given receiver kind, signature and body.
    pub fn new(
        name: &str,
        ptr_recv: bool,
        sig: FuncSig,
        f: impl Fn(&Value, &[Value]) -> Result<Value, CallError> + Send + Sync + 'static,
    ) -> Method {
        Method {
            name: name.to_owned(),
            ptr_recv,
            sig,
            f: Arc::new(f),
        }
    }
}

impl fmt::Debug for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Method({})", self.name)
    }
}

pub(crate) struct NamedData {
    pkg: String,
    name: String,
    under: OnceLock<Type>,
    methods: OnceLock<Vec<Method>>,
}

pub(crate) enum TypeData {
    Basic(Kind),
    Slice(Type),
    Array(usize, Type),
    Map(Type, Type),
    Ptr(Type),
    Chan(ChanDir, Type),
    Func(FuncSig),
    Interface(Vec<(String, FuncSig)>),
    Struct(Vec<Field>),
    Named(NamedData),
}

/// A Go type (Go `reflect.Type`). Cloning is cheap.
#[derive(Clone)]
pub struct Type(pub(crate) Arc<TypeData>);

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.type_string())
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.type_string())
    }
}

impl PartialEq for Type {
    fn eq(&self, other: &Type) -> bool {
        if Arc::ptr_eq(&self.0, &other.0) {
            return true;
        }
        match (&*self.0, &*other.0) {
            (TypeData::Basic(a), TypeData::Basic(b)) => a == b,
            (TypeData::Slice(a), TypeData::Slice(b)) => a == b,
            (TypeData::Array(n, a), TypeData::Array(m, b)) => n == m && a == b,
            (TypeData::Map(k, v), TypeData::Map(k2, v2)) => k == k2 && v == v2,
            (TypeData::Ptr(a), TypeData::Ptr(b)) => a == b,
            (TypeData::Chan(d, a), TypeData::Chan(d2, b)) => d == d2 && a == b,
            (TypeData::Func(a), TypeData::Func(b)) => a == b,
            (TypeData::Interface(a), TypeData::Interface(b)) => a == b,
            (TypeData::Struct(a), TypeData::Struct(b)) => a == b,
            (TypeData::Named(a), TypeData::Named(b)) => a.pkg == b.pkg && a.name == b.name,
            _ => false,
        }
    }
}

fn basic(k: Kind) -> Type {
    Type(Arc::new(TypeData::Basic(k)))
}

macro_rules! basic_types {
    ($($fn:ident => $k:ident),+ $(,)?) => { $(
        #[doc = concat!("The Go `", stringify!($fn), "` type.")]
        pub fn $fn() -> Type {
            static T: OnceLock<Type> = OnceLock::new();
            T.get_or_init(|| basic(Kind::$k)).clone()
        }
    )+ };
}

impl Type {
    basic_types! {
        bool_ => Bool, int => Int, int8 => Int8, int16 => Int16, int32 => Int32, int64 => Int64,
        uint => Uint, uint8 => Uint8, uint16 => Uint16, uint32 => Uint32, uint64 => Uint64,
        uintptr => Uintptr, float32 => Float32, float64 => Float64, complex64 => Complex64,
        complex128 => Complex128, string => String, unsafe_pointer => UnsafePointer,
    }
}

impl Type {
    /// `[]elem`.
    pub fn slice_of(elem: Type) -> Type {
        Type(Arc::new(TypeData::Slice(elem)))
    }
    /// `[n]elem`.
    pub fn array_of(n: usize, elem: Type) -> Type {
        Type(Arc::new(TypeData::Array(n, elem)))
    }
    /// `map[key]elem`.
    pub fn map_of(key: Type, elem: Type) -> Type {
        Type(Arc::new(TypeData::Map(key, elem)))
    }
    /// `*elem`.
    pub fn ptr_to(elem: Type) -> Type {
        Type(Arc::new(TypeData::Ptr(elem)))
    }
    /// `chan elem` in the given direction.
    pub fn chan_of(dir: ChanDir, elem: Type) -> Type {
        Type(Arc::new(TypeData::Chan(dir, elem)))
    }
    /// `func(ins...) outs`.
    pub fn func_of(sig: FuncSig) -> Type {
        Type(Arc::new(TypeData::Func(sig)))
    }
    /// An interface type with the given methods.
    pub fn interface_of(mut methods: Vec<(String, FuncSig)>) -> Type {
        methods.sort_by(|a, b| a.0.cmp(&b.0));
        Type(Arc::new(TypeData::Interface(methods)))
    }
    /// `interface {}` (Go `any`).
    pub fn any() -> Type {
        static T: OnceLock<Type> = OnceLock::new();
        T.get_or_init(|| Type::interface_of(Vec::new())).clone()
    }
    /// The predeclared `error` interface.
    pub fn error() -> Type {
        static T: OnceLock<Type> = OnceLock::new();
        T.get_or_init(|| {
            let under = Type::interface_of(vec![(
                "Error".to_owned(),
                FuncSig::new(vec![], vec![Type::string()], false),
            )]);
            let t = Type::named_deferred("", "error");
            t.set_underlying(under);
            t.set_methods(Vec::new());
            t
        })
        .clone()
    }
    /// The `fmt.Stringer` interface.
    pub fn stringer() -> Type {
        static T: OnceLock<Type> = OnceLock::new();
        T.get_or_init(|| {
            let under = Type::interface_of(vec![(
                "String".to_owned(),
                FuncSig::new(vec![], vec![Type::string()], false),
            )]);
            let t = Type::named_deferred("fmt", "Stringer");
            t.set_underlying(under);
            t.set_methods(Vec::new());
            t
        })
        .clone()
    }
    /// The type of `reflect.Value`, the parameter type that passes any
    /// argument through unchanged (used by the builtin functions).
    pub fn reflect_value() -> Type {
        static T: OnceLock<Type> = OnceLock::new();
        T.get_or_init(|| {
            let t = Type::named_deferred("reflect", "Value");
            t.set_underlying(Type::struct_of(Vec::new()));
            t.set_methods(Vec::new());
            t
        })
        .clone()
    }
    /// An anonymous struct type.
    pub fn struct_of(fields: Vec<Field>) -> Type {
        Type(Arc::new(TypeData::Struct(fields)))
    }
    /// A defined type `pkg.name` with the given underlying type and methods.
    pub fn named(pkg: &str, name: &str, under: Type, methods: Vec<Method>) -> Type {
        let t = Type::named_deferred(pkg, name);
        t.set_underlying(under);
        t.set_methods(methods);
        t
    }
    /// A defined type whose underlying type and methods are supplied later,
    /// so that recursive types can be built.
    pub fn named_deferred(pkg: &str, name: &str) -> Type {
        Type(Arc::new(TypeData::Named(NamedData {
            pkg: pkg.to_owned(),
            name: name.to_owned(),
            under: OnceLock::new(),
            methods: OnceLock::new(),
        })))
    }
    /// Sets the underlying type of a deferred named type (once).
    pub fn set_underlying(&self, under: Type) {
        if let TypeData::Named(n) = &*self.0 {
            let _ = n.under.set(under.underlying());
        }
    }
    /// Sets the methods of a deferred named type (once).
    pub fn set_methods(&self, methods: Vec<Method>) {
        if let TypeData::Named(n) = &*self.0 {
            let _ = n.methods.set(methods);
        }
    }

    /// The type's underlying type.
    pub fn underlying(&self) -> Type {
        match &*self.0 {
            TypeData::Named(n) => n
                .under
                .get()
                .cloned()
                .unwrap_or_else(|| Type::struct_of(Vec::new())),
            _ => self.clone(),
        }
    }

    /// The type's kind.
    pub fn kind(&self) -> Kind {
        match &*self.0 {
            TypeData::Basic(k) => *k,
            TypeData::Slice(_) => Kind::Slice,
            TypeData::Array(..) => Kind::Array,
            TypeData::Map(..) => Kind::Map,
            TypeData::Ptr(_) => Kind::Pointer,
            TypeData::Chan(..) => Kind::Chan,
            TypeData::Func(_) => Kind::Func,
            TypeData::Interface(_) => Kind::Interface,
            TypeData::Struct(_) => Kind::Struct,
            TypeData::Named(_) => self.underlying().kind(),
        }
    }

    /// The name of a defined type, without its package.
    pub fn name(&self) -> Option<String> {
        match &*self.0 {
            TypeData::Named(n) => Some(n.name.clone()),
            TypeData::Basic(k) => Some(k.basic_name().to_owned()),
            _ => None,
        }
    }

    /// Reports whether the type is a defined (named) type.
    pub fn has_name(&self) -> bool {
        matches!(&*self.0, TypeData::Named(_) | TypeData::Basic(_))
    }

    /// The element type of an array, chan, map, pointer or slice.
    pub fn elem(&self) -> Option<Type> {
        match &*self.underlying().0 {
            TypeData::Slice(e)
            | TypeData::Array(_, e)
            | TypeData::Ptr(e)
            | TypeData::Chan(_, e) => Some(e.clone()),
            TypeData::Map(_, e) => Some(e.clone()),
            _ => None,
        }
    }

    /// The key type of a map.
    pub fn key(&self) -> Option<Type> {
        match &*self.underlying().0 {
            TypeData::Map(k, _) => Some(k.clone()),
            _ => None,
        }
    }

    /// The channel direction of a channel type.
    pub fn chan_dir(&self) -> Option<ChanDir> {
        match &*self.underlying().0 {
            TypeData::Chan(d, _) => Some(*d),
            _ => None,
        }
    }

    /// The length of an array type.
    pub fn array_len(&self) -> usize {
        match &*self.underlying().0 {
            TypeData::Array(n, _) => *n,
            _ => 0,
        }
    }

    /// The fields of a struct type.
    pub fn fields(&self) -> Vec<Field> {
        match &*self.underlying().0 {
            TypeData::Struct(f) => f.clone(),
            _ => Vec::new(),
        }
    }

    /// The signature of a function type.
    pub fn sig(&self) -> Option<FuncSig> {
        match &*self.underlying().0 {
            TypeData::Func(s) => Some(s.clone()),
            _ => None,
        }
    }

    /// The Go spelling of the type (Go `Type.String`).
    pub fn type_string(&self) -> String {
        match &*self.0 {
            TypeData::Basic(k) => k.basic_name().to_owned(),
            TypeData::Slice(e) => format!("[]{}", e.type_string()),
            TypeData::Array(n, e) => format!("[{n}]{}", e.type_string()),
            TypeData::Map(k, v) => format!("map[{}]{}", k.type_string(), v.type_string()),
            TypeData::Ptr(e) => format!("*{}", e.type_string()),
            TypeData::Chan(d, e) => match d {
                ChanDir::Both => format!("chan {}", e.type_string()),
                ChanDir::Recv => format!("<-chan {}", e.type_string()),
                ChanDir::Send => format!("chan<- {}", e.type_string()),
            },
            TypeData::Func(s) => format!("func{}", s.type_string()),
            TypeData::Interface(ms) => {
                if ms.is_empty() {
                    "interface {}".to_owned()
                } else {
                    let parts: Vec<String> = ms
                        .iter()
                        .map(|(n, s)| format!("{n}{}", s.type_string()))
                        .collect();
                    format!("interface {{ {} }}", parts.join("; "))
                }
            }
            TypeData::Struct(fs) => {
                if fs.is_empty() {
                    "struct {}".to_owned()
                } else {
                    let parts: Vec<String> = fs
                        .iter()
                        .map(|f| {
                            if f.embedded {
                                f.ty.type_string()
                            } else {
                                format!("{} {}", f.name, f.ty.type_string())
                            }
                        })
                        .collect();
                    format!("struct {{ {} }}", parts.join("; "))
                }
            }
            TypeData::Named(n) => {
                if n.pkg.is_empty() {
                    n.name.clone()
                } else {
                    format!("{}.{}", n.pkg, n.name)
                }
            }
        }
    }

    fn own_methods(&self) -> &[Method] {
        match &*self.0 {
            TypeData::Named(n) => n.methods.get().map(Vec::as_slice).unwrap_or(&[]),
            _ => &[],
        }
    }

    /// The method set of the type, as (name, signature) pairs sorted by name.
    pub fn method_set(&self) -> Vec<(String, FuncSig)> {
        let mut out: Vec<(String, FuncSig)> = Vec::new();
        match &*self.underlying().0 {
            TypeData::Interface(ms) => out = ms.clone(),
            TypeData::Ptr(e) if !matches!(&*self.0, TypeData::Named(_)) => {
                // *T has all methods of T, pointer receivers included.
                for m in e.own_methods() {
                    out.push((m.name.clone(), m.sig.clone()));
                }
                out.extend(e.promoted_methods(true));
            }
            _ => {
                for m in self.own_methods() {
                    if !m.ptr_recv {
                        out.push((m.name.clone(), m.sig.clone()));
                    }
                }
                out.extend(self.promoted_methods(false));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out.dedup_by(|a, b| a.0 == b.0);
        out
    }

    fn promoted_methods(&self, ptr: bool) -> Vec<(String, FuncSig)> {
        let mut out = Vec::new();
        for f in self.fields() {
            if !f.embedded {
                continue;
            }
            let (ft, via_ptr) = if f.ty.kind() == Kind::Pointer {
                (f.ty.elem().expect("elem"), true)
            } else {
                (f.ty.clone(), false)
            };
            for m in ft.own_methods() {
                if !m.ptr_recv || via_ptr || ptr {
                    out.push((m.name.clone(), m.sig.clone()));
                }
            }
            out.extend(ft.promoted_methods(ptr || via_ptr));
        }
        out
    }

    /// Reports whether the type implements the interface type `iface`.
    pub fn implements(&self, iface: &Type) -> bool {
        let TypeData::Interface(want) = &*iface.underlying().0 else {
            return false;
        };
        let have = self.method_set();
        want.iter()
            .all(|(n, s)| have.iter().any(|(hn, hs)| hn == n && hs == s))
    }

    /// Reports whether a value of the type is assignable to `u`.
    pub fn assignable_to(&self, u: &Type) -> bool {
        if self == u {
            return true;
        }
        if u.kind() == Kind::Interface && self.implements(u) {
            return true;
        }
        let (a, b) = (self.underlying(), u.underlying());
        if a == b && (!self.has_name() || !u.has_name()) && a.kind() != Kind::Interface {
            return true;
        }
        if a.kind() == Kind::Chan && b.kind() == Kind::Chan && a.chan_dir() == Some(ChanDir::Both) {
            return a.elem() == b.elem() && (!self.has_name() || !u.has_name());
        }
        false
    }

    /// Reports whether a value of the type is convertible to `u` (limited to
    /// what templates need: numeric kinds among themselves, plus assignable).
    pub fn convertible_to(&self, u: &Type) -> bool {
        if self.assignable_to(u) {
            return true;
        }
        let (a, b) = (self.kind(), u.kind());
        let numeric = |k: Kind| k.int_like() || matches!(k, Kind::Float32 | Kind::Float64);
        if numeric(a) && numeric(b) {
            return true;
        }
        if a.int_like() && b == Kind::String {
            return true;
        }
        self.underlying() == u.underlying()
    }

    /// Reports whether values of the type are comparable with `==`.
    pub fn comparable(&self) -> bool {
        match &*self.underlying().0 {
            TypeData::Slice(_) | TypeData::Map(..) | TypeData::Func(_) => false,
            TypeData::Array(_, e) => e.comparable(),
            TypeData::Struct(fs) => fs.iter().all(|f| f.ty.comparable()),
            _ => true,
        }
    }

    /// The number of methods in the type's method set.
    pub fn num_method(&self) -> usize {
        self.method_set().len()
    }

    /// The type of `reflect.Value`.
    pub(crate) fn is_reflect_value(&self) -> bool {
        *self == Type::reflect_value()
    }

    /// Finds a field of a struct type by name, searching embedded structs.
    /// Returns the index path.
    pub(crate) fn field_by_name(&self, name: &str) -> Option<Vec<usize>> {
        let mut level: Vec<(Type, Vec<usize>)> = vec![(self.clone(), Vec::new())];
        let mut seen: Vec<Type> = Vec::new();
        while !level.is_empty() {
            let mut next = Vec::new();
            let mut found: Option<Vec<usize>> = None;
            let mut count = 0;
            for (t, path) in &level {
                if seen.contains(t) {
                    continue;
                }
                seen.push(t.clone());
                for (i, f) in t.fields().iter().enumerate() {
                    let mut p = path.clone();
                    p.push(i);
                    if f.name == name {
                        count += 1;
                        found = Some(p.clone());
                        continue;
                    }
                    if f.embedded {
                        let ft = if f.ty.kind() == Kind::Pointer {
                            f.ty.elem().expect("elem")
                        } else {
                            f.ty.clone()
                        };
                        if ft.kind() == Kind::Struct {
                            next.push((ft, p));
                        }
                    }
                }
            }
            if count == 1 {
                return found;
            }
            if count > 1 {
                return None;
            }
            level = next;
        }
        None
    }
}

impl FuncSig {
    /// `(a, b) r` formatting as Go writes function types after `func`.
    pub fn type_string(&self) -> String {
        let mut parts = Vec::new();
        for (i, t) in self.ins.iter().enumerate() {
            if self.variadic && i == self.ins.len() - 1 {
                parts.push(format!(
                    "...{}",
                    t.elem().map(|e| e.type_string()).unwrap_or_default()
                ));
            } else {
                parts.push(t.type_string());
            }
        }
        let mut s = format!("({})", parts.join(", "));
        match self.outs.len() {
            0 => {}
            1 => s.push_str(&format!(" {}", self.outs[0].type_string())),
            _ => {
                let o: Vec<String> = self.outs.iter().map(Type::type_string).collect();
                s.push_str(&format!(" ({})", o.join(", ")));
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------

/// The channel/iterator source behind a channel value.
pub type RecvFn = Arc<dyn Fn() -> Option<Value> + Send + Sync>;
/// An `iter.Seq`: calls the callback for each element until it returns false.
pub type SeqFn = Arc<dyn Fn(&mut dyn FnMut(Value) -> bool) + Send + Sync>;
/// An `iter.Seq2`.
pub type Seq2Fn = Arc<dyn Fn(&mut dyn FnMut(Value, Value) -> bool) + Send + Sync>;

#[derive(Clone)]
pub(crate) enum Repr {
    Invalid,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    Complex(f64, f64),
    Str(Arc<str>),
    Slice {
        buf: Option<Arc<Vec<Value>>>,
        off: usize,
        len: usize,
        cap: usize,
    },
    Array(Arc<Vec<Value>>),
    Map(Option<Arc<Vec<(Value, Value)>>>),
    Ptr(Option<Arc<Value>>),
    Struct(Arc<Vec<Value>>),
    Iface(Option<Box<Value>>),
    Func(Option<Callable>),
    Chan(Option<RecvFn>),
    Seq(SeqFn),
    Seq2(Seq2Fn),
    UnsafePtr(Option<usize>),
}

/// A typed Go value (Go `reflect.Value`). The zero [`Value::nil`] is the
/// invalid value, which stands for an untyped `nil`.
#[derive(Clone)]
pub struct Value {
    pub(crate) ty: Option<Type>,
    pub(crate) r: Repr,
    pub(crate) addr: bool,
    pub(crate) ro: bool,
}

impl Default for Value {
    fn default() -> Value {
        Value::nil()
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.ty {
            None => f.write_str("<invalid Value>"),
            Some(t) => write!(
                f,
                "{}({})",
                t,
                crate::text::template::verbs::sprint(std::slice::from_ref(self))
            ),
        }
    }
}

fn wrap_bits_i(x: i64, kind: Kind) -> i64 {
    match kind {
        Kind::Int8 => x as i8 as i64,
        Kind::Int16 => x as i16 as i64,
        Kind::Int32 => x as i32 as i64,
        _ => x,
    }
}

fn wrap_bits_u(x: u64, kind: Kind) -> u64 {
    match kind {
        Kind::Uint8 => x as u8 as u64,
        Kind::Uint16 => x as u16 as u64,
        Kind::Uint32 => x as u32 as u64,
        _ => x,
    }
}

impl Value {
    pub(crate) fn new(ty: Type, r: Repr) -> Value {
        Value {
            ty: Some(ty),
            r,
            addr: false,
            ro: false,
        }
    }

    /// The invalid value: an untyped `nil` (Go `reflect.Value{}`).
    pub fn nil() -> Value {
        Value {
            ty: None,
            r: Repr::Invalid,
            addr: false,
            ro: false,
        }
    }

    /// A `bool`.
    pub fn bool_(b: bool) -> Value {
        Value::new(Type::bool_(), Repr::Bool(b))
    }
    /// An `int`.
    pub fn int(i: i64) -> Value {
        Value::new(Type::int(), Repr::Int(i))
    }
    /// A signed integer of the given type; the value wraps to its width.
    pub fn int_of(ty: &Type, i: i64) -> Value {
        Value::new(ty.clone(), Repr::Int(wrap_bits_i(i, ty.kind())))
    }
    /// A `uint`.
    pub fn uint(u: u64) -> Value {
        Value::new(Type::uint(), Repr::Uint(u))
    }
    /// An unsigned integer of the given type; the value wraps to its width.
    pub fn uint_of(ty: &Type, u: u64) -> Value {
        Value::new(ty.clone(), Repr::Uint(wrap_bits_u(u, ty.kind())))
    }
    /// A `float64`.
    pub fn float64(f: f64) -> Value {
        Value::new(Type::float64(), Repr::Float(f))
    }
    /// A float of the given type (`float32` values are rounded).
    pub fn float_of(ty: &Type, f: f64) -> Value {
        let f = if ty.kind() == Kind::Float32 {
            f as f32 as f64
        } else {
            f
        };
        Value::new(ty.clone(), Repr::Float(f))
    }
    /// A `complex128`.
    pub fn complex128(re: f64, im: f64) -> Value {
        Value::new(Type::complex128(), Repr::Complex(re, im))
    }
    /// A complex number of the given type.
    pub fn complex_of(ty: &Type, re: f64, im: f64) -> Value {
        if ty.kind() == Kind::Complex64 {
            Value::new(
                ty.clone(),
                Repr::Complex(re as f32 as f64, im as f32 as f64),
            )
        } else {
            Value::new(ty.clone(), Repr::Complex(re, im))
        }
    }
    /// A `string`.
    pub fn string(s: impl AsRef<str>) -> Value {
        Value::new(Type::string(), Repr::Str(Arc::from(s.as_ref())))
    }
    /// A string of the given (string-kinded) type.
    pub fn string_of(ty: &Type, s: impl AsRef<str>) -> Value {
        Value::new(ty.clone(), Repr::Str(Arc::from(s.as_ref())))
    }
    /// A slice of `elem` holding `items`. Items are converted to the element
    /// type with [`Value::assign_to`].
    pub fn slice(elem: &Type, items: Vec<Value>) -> Value {
        Value::slice_with_cap(elem, items, 0)
    }
    /// A slice whose capacity is at least `cap` (extra elements are zero).
    pub fn slice_with_cap(elem: &Type, items: Vec<Value>, cap: usize) -> Value {
        Value::slice_typed(&Type::slice_of(elem.clone()), items, cap)
    }
    /// A slice of the given slice type (possibly a named type).
    pub fn slice_typed(ty: &Type, items: Vec<Value>, cap: usize) -> Value {
        let elem = ty.elem().expect("slice type");
        let len = items.len();
        let mut buf: Vec<Value> = items.into_iter().map(|v| v.assign_to(&elem)).collect();
        let cap = cap.max(len);
        while buf.len() < cap {
            buf.push(Value::zero(&elem));
        }
        Value::new(
            ty.clone(),
            Repr::Slice {
                buf: Some(Arc::new(buf)),
                off: 0,
                len,
                cap,
            },
        )
    }
    /// A nil slice of the given slice type.
    pub fn nil_slice(ty: &Type) -> Value {
        Value::new(
            ty.clone(),
            Repr::Slice {
                buf: None,
                off: 0,
                len: 0,
                cap: 0,
            },
        )
    }
    /// An array of the given array type.
    pub fn array(ty: &Type, items: Vec<Value>) -> Value {
        let elem = ty.elem().expect("array type");
        let mut buf: Vec<Value> = items.into_iter().map(|v| v.assign_to(&elem)).collect();
        while buf.len() < ty.array_len() {
            buf.push(Value::zero(&elem));
        }
        Value::new(ty.clone(), Repr::Array(Arc::new(buf)))
    }
    /// A map of the given map type. Later entries replace earlier ones with
    /// the same key.
    pub fn map(ty: &Type, entries: Vec<(Value, Value)>) -> Value {
        let (kt, et) = (ty.key().expect("map type"), ty.elem().expect("map type"));
        let mut out: Vec<(Value, Value)> = Vec::new();
        for (k, v) in entries {
            let (k, v) = (k.assign_to(&kt), v.assign_to(&et));
            if let Some(slot) = out.iter_mut().find(|(ek, _)| ek.equal(&k)) {
                slot.1 = v;
            } else {
                out.push((k, v));
            }
        }
        out.sort_by(|a, b| crate::text::template::verbs::compare_keys(&a.0, &b.0));
        Value::new(ty.clone(), Repr::Map(Some(Arc::new(out))))
    }
    /// A nil map of the given map type.
    pub fn nil_map(ty: &Type) -> Value {
        Value::new(ty.clone(), Repr::Map(None))
    }
    /// A struct of the given struct type with the fields in order.
    pub fn struct_(ty: &Type, fields: Vec<Value>) -> Value {
        let defs = ty.fields();
        let mut vals: Vec<Value> = fields
            .into_iter()
            .zip(defs.iter())
            .map(|(v, f)| v.assign_to(&f.ty))
            .collect();
        for f in defs.iter().skip(vals.len()) {
            vals.push(Value::zero(&f.ty));
        }
        Value::new(ty.clone(), Repr::Struct(Arc::new(vals)))
    }
    /// A pointer to `v`.
    pub fn ptr(v: Value) -> Value {
        let ty = Type::ptr_to(v.ty.clone().expect("pointer to a valid value"));
        Value::new(ty, Repr::Ptr(Some(Arc::new(v))))
    }
    /// A pointer of the given pointer type to `v` (the pointee is converted).
    pub fn ptr_typed(ty: &Type, v: Value) -> Value {
        let elem = ty.elem().expect("pointer type");
        Value::new(ty.clone(), Repr::Ptr(Some(Arc::new(v.assign_to(&elem)))))
    }
    /// A nil pointer of the given pointer type.
    pub fn nil_ptr(ty: &Type) -> Value {
        Value::new(ty.clone(), Repr::Ptr(None))
    }
    /// An interface-typed value holding `inner` (`None` for a nil interface).
    pub fn iface(ty: &Type, inner: Option<Value>) -> Value {
        Value::new(ty.clone(), Repr::Iface(inner.map(Box::new)))
    }
    /// `v` stored in an `interface {}`; the invalid value gives a nil
    /// `interface {}`.
    pub fn any(v: Value) -> Value {
        if v.ty.is_none() {
            return Value::iface(&Type::any(), None);
        }
        if v.kind() == Kind::Interface {
            return v;
        }
        Value::iface(&Type::any(), Some(v))
    }
    /// A function value of the given function type.
    pub fn func_of(
        sig: FuncSig,
        f: impl Fn(&[Value]) -> Result<Value, CallError> + Send + Sync + 'static,
    ) -> Value {
        Value::new(Type::func_of(sig), Repr::Func(Some(Arc::new(f))))
    }
    /// A nil function of the given function type.
    pub fn nil_func(ty: &Type) -> Value {
        Value::new(ty.clone(), Repr::Func(None))
    }
    /// A function value that can be ranged over, as a Go `iter.Seq[T]`.
    pub fn seq(
        elem: &Type,
        f: impl Fn(&mut dyn FnMut(Value) -> bool) + Send + Sync + 'static,
    ) -> Value {
        let yield_t = Type::func_of(FuncSig::new(vec![elem.clone()], vec![Type::bool_()], false));
        let ty = Type::func_of(FuncSig::new(vec![yield_t], vec![], false));
        Value::new(ty, Repr::Seq(Arc::new(f)))
    }
    /// A function value that can be ranged over, as a Go `iter.Seq2[K, V]`.
    pub fn seq2(
        key: &Type,
        elem: &Type,
        f: impl Fn(&mut dyn FnMut(Value, Value) -> bool) + Send + Sync + 'static,
    ) -> Value {
        let yield_t = Type::func_of(FuncSig::new(
            vec![key.clone(), elem.clone()],
            vec![Type::bool_()],
            false,
        ));
        let ty = Type::func_of(FuncSig::new(vec![yield_t], vec![], false));
        Value::new(ty, Repr::Seq2(Arc::new(f)))
    }
    /// A channel of the given channel type whose receives call `recv` until
    /// it returns `None` (closed and drained).
    pub fn chan(ty: &Type, recv: impl Fn() -> Option<Value> + Send + Sync + 'static) -> Value {
        Value::new(ty.clone(), Repr::Chan(Some(Arc::new(recv))))
    }
    /// A nil channel of the given type.
    pub fn nil_chan(ty: &Type) -> Value {
        Value::new(ty.clone(), Repr::Chan(None))
    }
    /// An `unsafe.Pointer`; `None` is nil.
    pub fn unsafe_pointer(addr: Option<usize>) -> Value {
        Value::new(Type::unsafe_pointer(), Repr::UnsafePtr(addr))
    }
    /// A value of a named type wrapping a value of its underlying type.
    pub fn named(ty: &Type, v: Value) -> Value {
        Value {
            ty: Some(ty.clone()),
            r: v.r,
            addr: v.addr,
            ro: v.ro,
        }
    }
    /// An error value: an `error` interface holding a Go error.
    pub fn error(e: FuncError) -> Value {
        Value::iface(
            &Type::error(),
            Some(Value::new(
                go_error_type(),
                Repr::Struct(Arc::new(vec![Value::string(e.to_string())])),
            )),
        )
    }

    /// The zero value of the type (Go `reflect.Zero`).
    pub fn zero(ty: &Type) -> Value {
        let r = match ty.kind() {
            Kind::Invalid => Repr::Invalid,
            Kind::Bool => Repr::Bool(false),
            k if k.is_int() => Repr::Int(0),
            k if k.is_uint() => Repr::Uint(0),
            Kind::Float32 | Kind::Float64 => Repr::Float(0.0),
            Kind::Complex64 | Kind::Complex128 => Repr::Complex(0.0, 0.0),
            Kind::String => Repr::Str(Arc::from("")),
            Kind::Slice => Repr::Slice {
                buf: None,
                off: 0,
                len: 0,
                cap: 0,
            },
            Kind::Array => {
                let e = ty.elem().expect("elem");
                Repr::Array(Arc::new(
                    (0..ty.array_len()).map(|_| Value::zero(&e)).collect(),
                ))
            }
            Kind::Map => Repr::Map(None),
            Kind::Pointer => Repr::Ptr(None),
            Kind::Struct => Repr::Struct(Arc::new(
                ty.fields().iter().map(|f| Value::zero(&f.ty)).collect(),
            )),
            Kind::Interface => Repr::Iface(None),
            Kind::Func => Repr::Func(None),
            Kind::Chan => Repr::Chan(None),
            Kind::UnsafePointer => Repr::UnsafePtr(None),
            _ => Repr::Invalid,
        };
        Value::new(ty.clone(), r)
    }

    /// Converts the value for storage in a slot of type `ty`: a value stored
    /// in an interface slot is wrapped; a nil value becomes the slot's zero.
    pub fn assign_to(self, ty: &Type) -> Value {
        if ty.kind() == Kind::Interface {
            if self.ty.is_none() {
                return Value::zero(ty);
            }
            if self.kind() == Kind::Interface {
                return Value {
                    ty: Some(ty.clone()),
                    ..self
                };
            }
            return Value::iface(ty, Some(self));
        }
        if self.ty.is_none() {
            return Value::zero(ty);
        }
        if self.ty.as_ref() != Some(ty) && self.kind() == ty.kind() {
            return Value::named(ty, self);
        }
        self
    }

    // ---- inspection --------------------------------------------------

    /// Reports whether the value is valid (not the untyped nil).
    pub fn is_valid(&self) -> bool {
        self.ty.is_some()
    }
    /// The value's type; `None` for the invalid value.
    pub fn type_(&self) -> Option<&Type> {
        self.ty.as_ref()
    }
    /// The kind of the value.
    pub fn kind(&self) -> Kind {
        match &self.ty {
            None => Kind::Invalid,
            Some(t) => t.kind(),
        }
    }
    /// Reports whether the value can be addressed.
    pub fn can_addr(&self) -> bool {
        self.addr
    }
    pub(crate) fn with_addr(mut self, addr: bool) -> Value {
        self.addr = addr;
        self
    }

    /// Reports whether a chan, func, interface, map, pointer or slice value
    /// is nil. The invalid value is nil.
    pub fn is_nil(&self) -> bool {
        match &self.r {
            Repr::Invalid => true,
            Repr::Slice { buf, .. } => buf.is_none(),
            Repr::Map(m) => m.is_none(),
            Repr::Ptr(p) => p.is_none(),
            Repr::Iface(i) => i.is_none(),
            Repr::Func(f) => f.is_none(),
            Repr::Chan(c) => c.is_none(),
            Repr::UnsafePtr(p) => p.is_none(),
            _ => false,
        }
    }

    /// The length of an array, chan, map, slice or string.
    pub fn len(&self) -> usize {
        match &self.r {
            Repr::Slice { len, .. } => *len,
            Repr::Array(a) => a.len(),
            Repr::Map(m) => m.as_ref().map_or(0, |m| m.len()),
            Repr::Str(s) => s.len(),
            Repr::Ptr(Some(p)) if p.kind() == Kind::Array => p.len(),
            _ => 0,
        }
    }

    /// Reports whether `len` is zero.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The capacity of a slice or array.
    pub fn cap(&self) -> usize {
        match &self.r {
            Repr::Slice { cap, .. } => *cap,
            Repr::Array(a) => a.len(),
            _ => 0,
        }
    }

    /// The boolean held by a `bool` value.
    pub fn as_bool(&self) -> bool {
        matches!(self.r, Repr::Bool(true))
    }
    /// The integer held by a signed integer value.
    pub fn as_int(&self) -> i64 {
        match self.r {
            Repr::Int(i) => i,
            _ => 0,
        }
    }
    /// The integer held by an unsigned integer value.
    pub fn as_uint(&self) -> u64 {
        match self.r {
            Repr::Uint(u) => u,
            _ => 0,
        }
    }
    /// The float held by a float value.
    pub fn as_float(&self) -> f64 {
        match self.r {
            Repr::Float(f) => f,
            _ => 0.0,
        }
    }
    /// The (real, imaginary) parts of a complex value.
    pub fn as_complex(&self) -> (f64, f64) {
        match self.r {
            Repr::Complex(a, b) => (a, b),
            _ => (0.0, 0.0),
        }
    }
    /// The string held by a string value (Go `Value.String`, which returns
    /// `<T Value>` for other kinds).
    pub fn as_string(&self) -> String {
        match &self.r {
            Repr::Str(s) => s.to_string(),
            Repr::Invalid => "<invalid Value>".to_owned(),
            _ => format!(
                "<{} Value>",
                self.ty.as_ref().map(Type::type_string).unwrap_or_default()
            ),
        }
    }

    /// Element `i` of an array, slice or string (a byte), as Go's `Index`.
    /// Panics when out of range.
    pub fn index(&self, i: usize) -> Value {
        match &self.r {
            Repr::Slice { buf, off, len, .. } => {
                assert!(i < *len, "reflect: slice index out of range");
                let mut v = buf.as_ref().expect("non-nil")[off + i].clone();
                v.addr = true;
                v.ro = self.ro;
                v
            }
            Repr::Array(a) => {
                let mut v = a[i].clone();
                v.addr = self.addr;
                v.ro = self.ro;
                v
            }
            Repr::Str(s) => Value::uint_of(&Type::uint8(), u64::from(s.as_bytes()[i])),
            _ => panic!("reflect: call of Index on {:?} Value", self.kind()),
        }
    }

    /// The pointee of a pointer, or the value inside an interface (Go `Elem`).
    /// A nil pointer or interface gives the invalid value.
    pub fn elem(&self) -> Value {
        match &self.r {
            Repr::Ptr(Some(p)) => {
                let mut v = (**p).clone();
                v.addr = true;
                v.ro = self.ro;
                v
            }
            Repr::Iface(Some(v)) => {
                let mut v = (**v).clone();
                v.addr = false;
                v.ro = self.ro;
                v
            }
            Repr::Ptr(None) | Repr::Iface(None) => Value::nil(),
            _ => panic!("reflect: call of Elem on {:?} Value", self.kind()),
        }
    }

    /// The address of an addressable value (Go `Addr`).
    pub fn addr(&self) -> Value {
        let mut v = self.clone();
        v.addr = false;
        let ty = Type::ptr_to(self.ty.clone().expect("valid"));
        Value {
            ty: Some(ty),
            r: Repr::Ptr(Some(Arc::new(v))),
            addr: false,
            ro: self.ro,
        }
    }

    /// Looks up a map entry (Go `MapIndex`); the invalid value when absent.
    pub fn map_index(&self, key: &Value) -> Value {
        let Repr::Map(Some(m)) = &self.r else {
            return Value::nil();
        };
        for (k, v) in m.iter() {
            if k.equal(key) {
                let mut v = v.clone();
                v.addr = false;
                v.ro = self.ro;
                return v;
            }
        }
        Value::nil()
    }

    /// The entries of a map in Go's `fmtsort` order (keys ascending).
    pub fn map_entries(&self) -> Vec<(Value, Value)> {
        match &self.r {
            Repr::Map(Some(m)) => m
                .iter()
                .map(|(k, v)| {
                    let mut k = k.clone();
                    let mut v = v.clone();
                    k.ro = self.ro;
                    v.ro = self.ro;
                    (k, v)
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    /// A struct's field values in declaration order.
    pub(crate) fn field_values(&self) -> Option<&Vec<Value>> {
        match &self.r {
            Repr::Struct(f) => Some(f),
            _ => None,
        }
    }

    /// Field `i` of a struct.
    pub fn field(&self, i: usize) -> Value {
        let Repr::Struct(f) = &self.r else {
            panic!("reflect: call of Field on {:?} Value", self.kind());
        };
        let mut v = f[i].clone();
        v.addr = self.addr;
        let exported = self.ty.as_ref().expect("valid").fields()[i].is_exported();
        v.ro = self.ro || !exported;
        v
    }

    /// Reports whether `Interface()` is permitted (the value was not reached
    /// through an unexported struct field).
    pub fn can_interface(&self) -> bool {
        !self.ro
    }

    /// Follows an index path through (possibly pointer) embedded fields. The
    /// error is Go's `reflect: indirection through nil pointer to embedded
    /// struct field NAME`.
    pub(crate) fn field_by_index_err(&self, path: &[usize]) -> Result<Value, String> {
        let mut v = self.clone();
        for (n, &i) in path.iter().enumerate() {
            if n > 0 && v.kind() == Kind::Pointer {
                let et = v.ty.as_ref().expect("valid").elem().expect("elem");
                if et.kind() == Kind::Struct {
                    if v.is_nil() {
                        return Err(format!(
                            "reflect: indirection through nil pointer to embedded struct field {}",
                            et.name().unwrap_or_default()
                        ));
                    }
                    v = v.elem();
                }
            }
            v = v.field(i);
        }
        Ok(v)
    }

    /// Slices an array, slice or string (Go `Slice`). Panics when out of
    /// range.
    pub fn slice_range(&self, i: usize, j: usize) -> Value {
        match &self.r {
            Repr::Str(s) => {
                assert!(
                    i <= j && j <= s.len(),
                    "reflect.Value.Slice: string slice index out of bounds"
                );
                Value::new(
                    self.ty.clone().expect("valid"),
                    Repr::Str(Arc::from(
                        String::from_utf8_lossy(&s.as_bytes()[i..j]).as_ref(),
                    )),
                )
            }
            Repr::Slice { buf, off, cap, .. } => {
                assert!(
                    i <= j && j <= *cap,
                    "reflect.Value.Slice: slice index out of bounds"
                );
                Value {
                    ty: self.ty.clone(),
                    r: Repr::Slice {
                        buf: buf.clone(),
                        off: off + i,
                        len: j - i,
                        cap: cap - i,
                    },
                    addr: false,
                    ro: self.ro,
                }
            }
            Repr::Array(a) => {
                assert!(
                    self.addr,
                    "reflect.Value.Slice: slice of unaddressable array"
                );
                let elem = self.ty.as_ref().expect("valid").elem().expect("elem");
                assert!(
                    i <= j && j <= a.len(),
                    "reflect.Value.Slice: slice index out of bounds"
                );
                Value {
                    ty: Some(Type::slice_of(elem)),
                    r: Repr::Slice {
                        buf: Some(a.clone()),
                        off: i,
                        len: j - i,
                        cap: a.len() - i,
                    },
                    addr: false,
                    ro: self.ro,
                }
            }
            _ => panic!(
                "reflect.Value.Slice: call of Slice on {:?} Value",
                self.kind()
            ),
        }
    }

    /// Slices with an explicit capacity (Go `Slice3`).
    pub fn slice3(&self, i: usize, j: usize, k: usize) -> Value {
        match &self.r {
            Repr::Slice { buf, off, cap, .. } => {
                assert!(
                    i <= j && j <= k && k <= *cap,
                    "reflect.Value.Slice3: slice index out of bounds"
                );
                Value {
                    ty: self.ty.clone(),
                    r: Repr::Slice {
                        buf: buf.clone(),
                        off: off + i,
                        len: j - i,
                        cap: k - i,
                    },
                    addr: false,
                    ro: self.ro,
                }
            }
            Repr::Array(a) => {
                assert!(
                    self.addr,
                    "reflect.Value.Slice3: slice of unaddressable array"
                );
                let elem = self.ty.as_ref().expect("valid").elem().expect("elem");
                assert!(
                    i <= j && j <= k && k <= a.len(),
                    "reflect.Value.Slice3: slice index out of bounds"
                );
                Value {
                    ty: Some(Type::slice_of(elem)),
                    r: Repr::Slice {
                        buf: Some(a.clone()),
                        off: i,
                        len: j - i,
                        cap: k - i,
                    },
                    addr: false,
                    ro: self.ro,
                }
            }
            _ => panic!(
                "reflect.Value.Slice3: call of Slice3 on {:?} Value",
                self.kind()
            ),
        }
    }

    /// The elements of an array or slice.
    pub fn items(&self) -> Vec<Value> {
        (0..self.len()).map(|i| self.index(i)).collect()
    }

    /// The value as Go's `Interface()` would return it: the dynamic value
    /// inside an interface, else the value itself.
    pub fn interface(&self) -> Value {
        if let Repr::Iface(i) = &self.r {
            return match i {
                Some(v) => (**v).clone(),
                None => Value::nil(),
            };
        }
        self.clone()
    }

    /// Converts a numeric value to another numeric type (Go `Convert`).
    pub fn convert(&self, ty: &Type) -> Value {
        let k = ty.kind();
        let v = if k.is_int() {
            let i = match &self.r {
                Repr::Int(i) => *i,
                Repr::Uint(u) => *u as i64,
                Repr::Float(f) => *f as i64,
                _ => 0,
            };
            Repr::Int(wrap_bits_i(i, k))
        } else if k.is_uint() {
            let u = match &self.r {
                Repr::Int(i) => *i as u64,
                Repr::Uint(u) => *u,
                Repr::Float(f) => *f as u64,
                _ => 0,
            };
            Repr::Uint(wrap_bits_u(u, k))
        } else if matches!(k, Kind::Float32 | Kind::Float64) {
            let f = match &self.r {
                Repr::Int(i) => *i as f64,
                Repr::Uint(u) => *u as f64,
                Repr::Float(f) => *f,
                _ => 0.0,
            };
            Repr::Float(if k == Kind::Float32 {
                f as f32 as f64
            } else {
                f
            })
        } else {
            self.r.clone()
        };
        Value {
            ty: Some(ty.clone()),
            r: v,
            addr: false,
            ro: self.ro,
        }
    }

    /// Reports whether the two values are equal as Go's `==` on their
    /// interface values (and `Value.Equal` for the invalid value).
    pub fn equal(&self, other: &Value) -> bool {
        match (&self.ty, &other.ty) {
            (None, None) => return true,
            (None, _) | (_, None) => return false,
            _ => {}
        }
        let (a, b) = (self.interface(), other.interface());
        if a.ty.is_none() || b.ty.is_none() {
            return a.ty.is_none() && b.ty.is_none();
        }
        if a.ty != b.ty {
            return false;
        }
        match (&a.r, &b.r) {
            (Repr::Bool(x), Repr::Bool(y)) => x == y,
            (Repr::Int(x), Repr::Int(y)) => x == y,
            (Repr::Uint(x), Repr::Uint(y)) => x == y,
            (Repr::Float(x), Repr::Float(y)) => x == y,
            (Repr::Complex(x, i), Repr::Complex(y, j)) => x == y && i == j,
            (Repr::Str(x), Repr::Str(y)) => x == y,
            (Repr::Ptr(x), Repr::Ptr(y)) => match (x, y) {
                (None, None) => true,
                (Some(x), Some(y)) => Arc::ptr_eq(x, y),
                _ => false,
            },
            (Repr::Array(x), Repr::Array(y)) => x.iter().zip(y.iter()).all(|(p, q)| p.equal(q)),
            (Repr::Struct(x), Repr::Struct(y)) => x.iter().zip(y.iter()).all(|(p, q)| p.equal(q)),
            (Repr::Iface(x), Repr::Iface(y)) => match (x, y) {
                (None, None) => true,
                (Some(x), Some(y)) => x.equal(y),
                _ => false,
            },
            (Repr::Chan(None), Repr::Chan(None)) => true,
            (Repr::UnsafePtr(x), Repr::UnsafePtr(y)) => x == y,
            _ => false,
        }
    }

    // ---- methods -----------------------------------------------------

    /// Finds the method `name` in the value's method set and binds the
    /// receiver (Go `Value.MethodByName`). The invalid value is returned
    /// when there is no such method.
    pub fn method_by_name(&self, name: &str) -> Value {
        let Some(ty) = &self.ty else {
            return Value::nil();
        };
        if self.kind() == Kind::Interface {
            let inner = self.elem();
            if !inner.is_valid() {
                return Value::nil();
            }
            return inner.method_by_name(name);
        }
        let is_ptr = ty.kind() == Kind::Pointer && !matches!(&*ty.0, TypeData::Named(_));
        let base = if is_ptr {
            ty.elem().expect("elem")
        } else {
            ty.clone()
        };
        if let Some(m) = find_method(&base, name, is_ptr) {
            let recv = self.clone();
            let sig = m.sig.clone();
            let f = m.f.clone();
            let named = base.name().unwrap_or_default();
            let recv_nil = is_ptr && self.is_nil();
            let m_ptr = m.ptr_recv;
            let mname = m.name.clone();
            let pkg_name = base.type_string();
            return Value::func_of(sig, move |args| {
                if recv_nil && !m_ptr {
                    let _ = &named;
                    return Err(CallError::Panic(format!(
                        "value method {pkg_name}.{mname} called using nil *{named} pointer"
                    )));
                }
                let r = if is_ptr && !m_ptr {
                    recv.elem()
                } else {
                    recv.clone()
                };
                f(&r, args)
            });
        }
        if let Some((path, m)) = find_promoted_method(&base, name, is_ptr) {
            let recv = self.clone();
            let sig = m.sig.clone();
            let f = m.f.clone();
            return Value::func_of(sig, move |args| {
                let mut v = if recv.kind() == Kind::Pointer {
                    recv.elem()
                } else {
                    recv.clone()
                };
                let mut last_ptr = false;
                for &i in &path {
                    if v.kind() == Kind::Pointer {
                        v = v.elem();
                    }
                    v = v.field(i);
                    last_ptr = v.kind() == Kind::Pointer;
                }
                let r = if last_ptr && !m.ptr_recv { v.elem() } else { v };
                f(&r, args)
            });
        }
        Value::nil()
    }

    /// Receives the next value from a channel; `None` when it is closed and
    /// drained (Go `Value.Recv`).
    pub fn recv(&self) -> Option<Value> {
        match &self.r {
            Repr::Chan(Some(f)) => f(),
            _ => None,
        }
    }

    /// The iterator of a function value that is an `iter.Seq`.
    pub(crate) fn as_seq(&self) -> Option<SeqFn> {
        match &self.r {
            Repr::Seq(f) => Some(f.clone()),
            _ => None,
        }
    }

    /// The iterator of a function value that is an `iter.Seq2`.
    pub(crate) fn as_seq2(&self) -> Option<Seq2Fn> {
        match &self.r {
            Repr::Seq2(f) => Some(f.clone()),
            _ => None,
        }
    }

    /// Calls a function value (Go `Value.Call`). Panics inside the callable
    /// are returned as errors. The result is converted to the function's
    /// declared result type, so a function declared to return an interface
    /// yields an interface value.
    pub fn call(&self, args: &[Value]) -> Result<Value, CallError> {
        match &self.r {
            Repr::Func(Some(f)) => {
                let f = f.clone();
                let args = args.to_vec();
                let out0 = self
                    .ty
                    .as_ref()
                    .and_then(Type::sig)
                    .and_then(|s| s.outs.first().cloned());
                let r = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                    f(&args)
                })) {
                    Ok(r) => r,
                    Err(p) => Err(CallError::Panic(panic_message(&*p))),
                };
                match (r, out0) {
                    (Ok(v), Some(t)) if !t.is_reflect_value() => Ok(v.assign_to(&t)),
                    (r, _) => r,
                }
            }
            Repr::Func(None) => Err(CallError::Panic("reflect: call of nil function".to_owned())),
            _ => Err(CallError::Panic("reflect: call of non-function".to_owned())),
        }
    }
}

fn panic_message(p: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic".to_owned()
    }
}

fn find_method(base: &Type, name: &str, via_ptr: bool) -> Option<Method> {
    base.own_methods()
        .iter()
        .find(|m| m.name == name && (via_ptr || !m.ptr_recv))
        .cloned()
}

fn find_promoted_method(base: &Type, name: &str, via_ptr: bool) -> Option<(Vec<usize>, Method)> {
    for (i, f) in base.fields().iter().enumerate() {
        if !f.embedded {
            continue;
        }
        let (ft, fptr) = if f.ty.kind() == Kind::Pointer {
            (f.ty.elem().expect("elem"), true)
        } else {
            (f.ty.clone(), false)
        };
        if let Some(m) = find_method(&ft, name, via_ptr || fptr) {
            return Some((vec![i], m));
        }
        if let Some((mut path, m)) = find_promoted_method(&ft, name, via_ptr || fptr) {
            path.insert(0, i);
            return Some((path, m));
        }
    }
    None
}

fn go_error_type() -> Type {
    static T: OnceLock<Type> = OnceLock::new();
    T.get_or_init(|| {
        let under = Type::struct_of(vec![Field::new("s", Type::string())]);
        let m = Method::new(
            "Error",
            false,
            FuncSig::new(vec![], vec![Type::string()], false),
            |recv, _| {
                Ok(recv
                    .field_values()
                    .map(|f| f[0].clone())
                    .unwrap_or_default())
            },
        );
        Type::named("errors", "errorString", under, vec![m])
    })
    .clone()
}

// ---------------------------------------------------------------------------

/// Conversion of Rust data into template values.
pub trait ToValue {
    /// The Go type of values produced.
    fn go_type() -> Type
    where
        Self: Sized;
    /// The value for `self`.
    fn to_value(&self) -> Value;
}

impl ToValue for Value {
    fn go_type() -> Type {
        Type::any()
    }
    fn to_value(&self) -> Value {
        self.clone()
    }
}

macro_rules! to_value_int {
    ($($t:ty => $f:ident),+ $(,)?) => { $(
        impl ToValue for $t {
            fn go_type() -> Type { Type::$f() }
            fn to_value(&self) -> Value { Value::int_of(&Type::$f(), *self as i64) }
        }
    )+ };
}
to_value_int!(i8 => int8, i16 => int16, i32 => int32, i64 => int64, isize => int);

macro_rules! to_value_uint {
    ($($t:ty => $f:ident),+ $(,)?) => { $(
        impl ToValue for $t {
            fn go_type() -> Type { Type::$f() }
            fn to_value(&self) -> Value { Value::uint_of(&Type::$f(), *self as u64) }
        }
    )+ };
}
to_value_uint!(u8 => uint8, u16 => uint16, u32 => uint32, u64 => uint64, usize => uint);

impl ToValue for bool {
    fn go_type() -> Type {
        Type::bool_()
    }
    fn to_value(&self) -> Value {
        Value::bool_(*self)
    }
}
impl ToValue for f64 {
    fn go_type() -> Type {
        Type::float64()
    }
    fn to_value(&self) -> Value {
        Value::float64(*self)
    }
}
impl ToValue for f32 {
    fn go_type() -> Type {
        Type::float32()
    }
    fn to_value(&self) -> Value {
        Value::float_of(&Type::float32(), f64::from(*self))
    }
}
impl ToValue for char {
    fn go_type() -> Type {
        Type::int32()
    }
    fn to_value(&self) -> Value {
        Value::int_of(&Type::int32(), *self as i64)
    }
}
impl ToValue for str {
    #[allow(dead_code)] // `str` is unsized: only reachable through `&str`
    fn go_type() -> Type {
        Type::string()
    }
    fn to_value(&self) -> Value {
        Value::string(self)
    }
}
impl ToValue for String {
    fn go_type() -> Type {
        Type::string()
    }
    fn to_value(&self) -> Value {
        Value::string(self)
    }
}
impl<T: ToValue> ToValue for &T {
    fn go_type() -> Type {
        T::go_type()
    }
    fn to_value(&self) -> Value {
        (**self).to_value()
    }
}
impl ToValue for &str {
    fn go_type() -> Type {
        Type::string()
    }
    fn to_value(&self) -> Value {
        Value::string(self)
    }
}
impl<T: ToValue> ToValue for Vec<T> {
    fn go_type() -> Type {
        Type::slice_of(T::go_type())
    }
    fn to_value(&self) -> Value {
        Value::slice(&T::go_type(), self.iter().map(ToValue::to_value).collect())
    }
}
impl<T: ToValue> ToValue for [T] {
    #[allow(dead_code)] // `[T]` is unsized: only reachable through a reference
    fn go_type() -> Type
    where
        Self: Sized,
    {
        Type::slice_of(T::go_type())
    }
    fn to_value(&self) -> Value {
        Value::slice(&T::go_type(), self.iter().map(ToValue::to_value).collect())
    }
}
impl<T: ToValue, const N: usize> ToValue for [T; N] {
    fn go_type() -> Type {
        Type::array_of(N, T::go_type())
    }
    fn to_value(&self) -> Value {
        Value::array(
            &Type::array_of(N, T::go_type()),
            self.iter().map(ToValue::to_value).collect(),
        )
    }
}
impl<T: ToValue> ToValue for Option<T> {
    fn go_type() -> Type {
        Type::ptr_to(T::go_type())
    }
    fn to_value(&self) -> Value {
        match self {
            Some(v) => Value::ptr_typed(&Type::ptr_to(T::go_type()), v.to_value()),
            None => Value::nil_ptr(&Type::ptr_to(T::go_type())),
        }
    }
}
impl<T: ToValue> ToValue for Box<T> {
    fn go_type() -> Type {
        T::go_type()
    }
    fn to_value(&self) -> Value {
        (**self).to_value()
    }
}
impl<T: ToValue> ToValue for std::sync::Arc<T> {
    fn go_type() -> Type {
        T::go_type()
    }
    fn to_value(&self) -> Value {
        (**self).to_value()
    }
}
impl<K: ToValue, V: ToValue> ToValue for std::collections::BTreeMap<K, V> {
    fn go_type() -> Type {
        Type::map_of(K::go_type(), V::go_type())
    }
    fn to_value(&self) -> Value {
        Value::map(
            &Type::map_of(K::go_type(), V::go_type()),
            self.iter()
                .map(|(k, v)| (k.to_value(), v.to_value()))
                .collect(),
        )
    }
}
impl<K: ToValue, V: ToValue, S> ToValue for std::collections::HashMap<K, V, S> {
    fn go_type() -> Type {
        Type::map_of(K::go_type(), V::go_type())
    }
    fn to_value(&self) -> Value {
        Value::map(
            &Type::map_of(K::go_type(), V::go_type()),
            self.iter()
                .map(|(k, v)| (k.to_value(), v.to_value()))
                .collect(),
        )
    }
}
