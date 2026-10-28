//! `Type`: the descriptor of a Go type.
//!
//! Rust has no run-time type information, so every `Type` is built from static
//! facts: the primitives, the `Reflect` implementations of the standard types,
//! `#[derive(Reflect)]`, or the run-time constructors (`slice_of`,
//! `struct_of`, ...). Unnamed composite types are interned, so two `Type`s
//! are equal exactly when Go would call the types identical (pointer
//! comparison), and `Type` can be a map key.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};

use super::kind::{value_error, ChanDir, Kind};
use super::tag::StructTag;
use super::value::Value;
use super::Seq;
use crate::strconv;

/// A method registered for a named type.
///
/// `call` receives the receiver as a [`Value`] of the named type (or a pointer
/// to it) and the arguments, and returns the results.
#[doc(hidden)]
/// A method body: receiver and arguments in, results out.
pub type MethodFn = Arc<dyn Fn(&Value, &[Value]) -> Vec<Value> + Send + Sync>;

#[doc(hidden)]
pub struct MethodDef {
    pub name: String,
    /// Empty when the method is exported (Rust `pub fn`).
    pub pkg_path: String,
    /// The signature without the receiver: a function type.
    pub ty: Type,
    /// Whether the method needs a pointer receiver (`&mut self`).
    pub ptr_recv: bool,
    pub call: MethodFn,
}

/// A method of a type (Go `reflect.Method`).
#[derive(Clone, Debug)]
pub struct Method {
    /// The method name.
    pub name: String,
    /// The package path for unexported methods; empty for exported ones.
    pub pkg_path: String,
    /// The method type. For a non-interface type it is a function type whose
    /// first parameter is the receiver; for an interface it is the signature.
    pub type_: Type,
    /// The function with the receiver as first argument (invalid for
    /// interface types).
    pub func: Value,
    /// The index of the method in the type's method set.
    pub index: usize,
}

impl Method {
    /// Go `Method.IsExported`.
    pub fn is_exported(&self) -> bool {
        self.pkg_path.is_empty()
    }
}

/// A single field of a struct type (Go `reflect.StructField`).
#[derive(Clone, Debug)]
pub struct StructField {
    /// The field name.
    pub name: String,
    /// The package path that qualifies an unexported field name; empty for
    /// exported fields.
    pub pkg_path: String,
    /// The field type.
    pub type_: Type,
    /// The field tag string.
    pub tag: StructTag,
    /// The offset within the struct, in bytes (Go's amd64 layout).
    pub offset: usize,
    /// The index sequence for [`Type::field_by_index`].
    pub index: Vec<usize>,
    /// Whether the field is embedded.
    pub anonymous: bool,
}

impl StructField {
    /// A field with a name and type, for [`struct_of`].
    pub fn new(name: &str, type_: Type) -> StructField {
        StructField {
            name: name.to_string(),
            pkg_path: String::new(),
            type_,
            tag: StructTag::default(),
            offset: 0,
            index: Vec::new(),
            anonymous: false,
        }
    }

    /// Sets the tag string.
    pub fn with_tag(mut self, tag: &str) -> StructField {
        self.tag = StructTag::new(tag);
        self
    }

    /// Marks the field embedded.
    pub fn embedded(mut self) -> StructField {
        self.anonymous = true;
        self
    }

    /// Sets the package path of an unexported field.
    pub fn with_pkg_path(mut self, pkg_path: &str) -> StructField {
        self.pkg_path = pkg_path.to_string();
        self
    }

    /// Go `StructField.IsExported`.
    pub fn is_exported(&self) -> bool {
        self.pkg_path.is_empty()
    }
}

#[derive(Clone)]
#[doc(hidden)]
pub struct IMethod {
    pub name: String,
    pub pkg_path: String,
    pub ty: Type,
}

#[doc(hidden)]
pub enum Body {
    Basic(Kind),
    Array {
        len: usize,
        elem: Type,
    },
    Chan {
        dir: ChanDir,
        elem: Type,
    },
    Func {
        ins: Vec<Type>,
        outs: Vec<Type>,
        variadic: bool,
    },
    Interface {
        methods: Vec<IMethod>,
    },
    Map {
        key: Type,
        elem: Type,
    },
    Pointer(Type),
    Slice(Type),
    Struct {
        fields: Vec<StructField>,
        pkg_path: String,
    },
}

pub(crate) struct Layout {
    pub size: usize,
    pub align: usize,
    pub offsets: Vec<usize>,
}

/// One entry of a type's method set, possibly promoted from an embedded field.
pub(crate) struct MethodEntry {
    pub name: String,
    pub pkg_path: String,
    pub ty: Type,
    /// Embedded field indices leading to the method's receiver.
    pub path: Vec<usize>,
    /// `None` for a method of an embedded interface.
    pub def: Option<Arc<MethodDef>>,
}

pub(crate) struct TypeInner {
    pub(crate) name: Option<(String, String)>,
    pub(crate) string: String,
    body: OnceLock<Body>,
    init: Option<fn() -> Body>,
    methods: OnceLock<Vec<Arc<MethodDef>>>,
    methods_init: Option<fn() -> Vec<MethodDef>>,
    layout: OnceLock<Layout>,
    mset: OnceLock<Arc<Vec<MethodEntry>>>,
    comparable: OnceLock<bool>,
}

/// The representation of a Go type (Go `reflect.Type`). Cloning is cheap and
/// two `Type`s are equal exactly when they represent identical types.
#[derive(Clone)]
pub struct Type(pub(crate) &'static dyn TypeAccess);

/// Access to a type's data; a trait so that `Type` (a map key by identity)
/// does not expose the lazily initialised state to lints about mutable keys.
pub(crate) trait TypeAccess: Send + Sync {
    fn inner(&self) -> &TypeInner;
}

impl TypeAccess for TypeInner {
    fn inner(&self) -> &TypeInner {
        self
    }
}

impl Type {
    pub(crate) fn inner(&self) -> &TypeInner {
        self.0.inner()
    }
}

impl PartialEq for Type {
    fn eq(&self, other: &Type) -> bool {
        self.addr() == other.addr()
    }
}

impl Eq for Type {}

impl Hash for Type {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr().hash(state);
    }
}

impl fmt::Debug for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner().string)
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner().string)
    }
}

fn panic_str(msg: String) -> ! {
    panic!("{msg}")
}

// ---------------------------------------------------------------------------
// Construction and interning.

#[derive(PartialEq, Eq, Hash)]
enum Key {
    Slice(usize),
    Array(usize, usize),
    Pointer(usize),
    Chan(i32, usize),
    Map(usize, usize),
    Func(Vec<usize>, Vec<usize>, bool),
    Struct(String, Vec<(String, usize, String, bool)>),
    Interface(Vec<(String, String, usize)>),
}

static INTERN: LazyLock<Mutex<HashMap<Key, Type>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Type {
    pub(crate) fn addr(&self) -> usize {
        (self.0 as *const dyn TypeAccess).cast::<()>() as usize
    }

    fn build(
        name: Option<(String, String)>,
        string: String,
        body: Option<Body>,
        init: Option<fn() -> Body>,
        methods_init: Option<fn() -> Vec<MethodDef>>,
    ) -> Type {
        let cell = OnceLock::new();
        if let Some(b) = body {
            let _ = cell.set(b);
        }
        Type(Box::leak(Box::new(TypeInner {
            name,
            string,
            body: cell,
            init,
            methods: OnceLock::new(),
            methods_init,
            layout: OnceLock::new(),
            mset: OnceLock::new(),
            comparable: OnceLock::new(),
        })))
    }

    fn interned(key: Key, string: impl FnOnce() -> String, body: impl FnOnce() -> Body) -> Type {
        let mut map = lock(&INTERN);
        if let Some(t) = map.get(&key) {
            return t.clone();
        }
        let t = Type::build(None, string(), Some(body()), None, None);
        map.insert(key, t.clone());
        t
    }

    pub(crate) fn body(&self) -> &Body {
        if let Some(b) = self.inner().body.get() {
            return b;
        }
        match self.inner().init {
            Some(init) => self.inner().body.get_or_init(init),
            None => panic_str("reflect: type has no representation".into()),
        }
    }

    /// The predeclared type of a basic kind (`Kind::Int` is `int`, and so on),
    /// including kinds with no Rust primitive such as `uintptr` and
    /// `complex64`. It panics for kinds that are not basic.
    pub fn basic(kind: Kind) -> Type {
        static BASICS: LazyLock<Vec<Type>> = LazyLock::new(|| {
            (0..27u8)
                .map(|n| {
                    let k = Kind::from_u8(n).unwrap_or_default();
                    let (pkg, name) = match k {
                        Kind::UnsafePointer => ("unsafe", "Pointer".to_string()),
                        _ => ("", k.name().to_string()),
                    };
                    let string = if pkg.is_empty() {
                        name.clone()
                    } else {
                        format!("{pkg}.{name}")
                    };
                    Type::build(
                        Some((pkg.to_string(), name)),
                        string,
                        Some(Body::Basic(k)),
                        None,
                        None,
                    )
                })
                .collect()
        });
        match kind {
            Kind::Invalid
            | Kind::Array
            | Kind::Chan
            | Kind::Func
            | Kind::Interface
            | Kind::Map
            | Kind::Pointer
            | Kind::Slice
            | Kind::Struct => panic_str(format!("reflect: no basic type of kind {kind}")),
            _ => BASICS[kind as usize].clone(),
        }
    }

    /// The predeclared `error` interface type.
    pub fn error_type() -> Type {
        static T: LazyLock<Type> = LazyLock::new(|| {
            let sig = func_of(&[], &[Type::basic(Kind::String)], false);
            Type::build(
                Some((String::new(), "error".to_string())),
                "error".to_string(),
                Some(Body::Interface {
                    methods: vec![IMethod {
                        name: "Error".into(),
                        pkg_path: String::new(),
                        ty: sig,
                    }],
                }),
                None,
                None,
            )
        });
        T.clone()
    }

    /// The empty interface type `interface {}` (Go's `any`).
    pub fn any_type() -> Type {
        interface_of(&[])
    }

    /// Creates a defined (named) type with the given underlying type and
    /// methods. Go cannot create defined types at run time; Rust has no
    /// declarations to read them from, so `#[derive(Reflect)]` and hand-written
    /// [`Reflect`](super::Reflect) implementations use this.
    #[doc(hidden)]
    pub fn declare(
        pkg_path: &str,
        name: &str,
        init: fn() -> Body,
        methods: Option<fn() -> Vec<MethodDef>>,
    ) -> Type {
        let short = pkg_short(pkg_path);
        let string = if short.is_empty() {
            name.to_string()
        } else {
            format!("{short}.{name}")
        };
        Type::build(
            Some((pkg_path.to_string(), name.to_string())),
            string,
            None,
            Some(init),
            methods,
        )
    }

    /// A named type whose underlying type is already known.
    pub fn named(pkg_path: &str, name: &str, underlying: &Type, methods: Vec<MethodDef>) -> Type {
        let short = pkg_short(pkg_path);
        let string = if short.is_empty() {
            name.to_string()
        } else {
            format!("{short}.{name}")
        };
        let t = Type::build(
            Some((pkg_path.to_string(), name.to_string())),
            string,
            Some(underlying.clone_body()),
            None,
            None,
        );
        let _ = t
            .inner()
            .methods
            .set(methods.into_iter().map(Arc::new).collect());
        t
    }

    fn clone_body(&self) -> Body {
        match self.body() {
            Body::Basic(k) => Body::Basic(*k),
            Body::Array { len, elem } => Body::Array {
                len: *len,
                elem: elem.clone(),
            },
            Body::Chan { dir, elem } => Body::Chan {
                dir: *dir,
                elem: elem.clone(),
            },
            Body::Func {
                ins,
                outs,
                variadic,
            } => Body::Func {
                ins: ins.clone(),
                outs: outs.clone(),
                variadic: *variadic,
            },
            Body::Interface { methods } => Body::Interface {
                methods: methods.clone(),
            },
            Body::Map { key, elem } => Body::Map {
                key: key.clone(),
                elem: elem.clone(),
            },
            Body::Pointer(e) => Body::Pointer(e.clone()),
            Body::Slice(e) => Body::Slice(e.clone()),
            Body::Struct { fields, pkg_path } => Body::Struct {
                fields: fields.clone(),
                pkg_path: pkg_path.clone(),
            },
        }
    }

    fn declared_methods(&self) -> &[Arc<MethodDef>] {
        if self.inner().name.is_none() {
            return &[];
        }
        let v = self
            .inner()
            .methods
            .get_or_init(|| match self.inner().methods_init {
                Some(f) => {
                    let mut v: Vec<Arc<MethodDef>> = f().into_iter().map(Arc::new).collect();
                    v.sort_by(|a, b| a.name.cmp(&b.name));
                    v
                }
                None => Vec::new(),
            });
        v
    }
}

fn pkg_short(pkg_path: &str) -> &str {
    let s = pkg_path.rsplit('/').next().unwrap_or(pkg_path);
    s.rsplit("::").next().unwrap_or(s)
}

fn is_letter(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || (!c.is_ascii() && crate::unicode::is_letter(c as i32))
}

fn is_valid_field_name(name: &str) -> bool {
    for (i, c) in name.chars().enumerate() {
        if i == 0 && !is_letter(c) {
            return false;
        }
        if !(is_letter(c) || crate::unicode::is_digit(c as i32)) {
            return false;
        }
    }
    !name.is_empty()
}

/// Go `reflect.SliceOf`: the slice type with element type `t`.
pub fn slice_of(t: &Type) -> Type {
    Type::interned(
        Key::Slice(t.addr()),
        || format!("[]{}", t.inner().string),
        || Body::Slice(t.clone()),
    )
}

/// Go `reflect.ArrayOf`: the array type with the given length and element type.
pub fn array_of(length: isize, elem: &Type) -> Type {
    if length < 0 {
        panic_str("reflect: negative length passed to ArrayOf".into());
    }
    let length = length as usize;
    Type::interned(
        Key::Array(length, elem.addr()),
        || format!("[{}]{}", length, elem.inner().string),
        || Body::Array {
            len: length,
            elem: elem.clone(),
        },
    )
}

/// Go `reflect.PointerTo`.
pub fn pointer_to(t: &Type) -> Type {
    Type::interned(
        Key::Pointer(t.addr()),
        || format!("*{}", t.inner().string),
        || Body::Pointer(t.clone()),
    )
}

/// Go `reflect.PtrTo` (deprecated alias of [`pointer_to`]).
pub fn ptr_to(t: &Type) -> Type {
    pointer_to(t)
}

/// Go `reflect.ChanOf`.
pub fn chan_of(dir: ChanDir, t: &Type) -> Type {
    if t.size() >= 1 << 16 {
        panic_str("reflect.ChanOf: element size too large".into());
    }
    Type::interned(
        Key::Chan(dir as i32, t.addr()),
        || {
            let es = &t.inner().string;
            match dir {
                ChanDir::Send => format!("chan<- {es}"),
                ChanDir::Recv => format!("<-chan {es}"),
                ChanDir::Both => {
                    if es.starts_with('<') {
                        format!("chan ({es})")
                    } else {
                        format!("chan {es}")
                    }
                }
            }
        },
        || Body::Chan {
            dir,
            elem: t.clone(),
        },
    )
}

/// Go `reflect.MapOf`. It panics if `key` is not comparable.
pub fn map_of(key: &Type, elem: &Type) -> Type {
    if !key.comparable() {
        panic_str(format!(
            "reflect.MapOf: invalid key type {}",
            key.inner().string
        ));
    }
    Type::interned(
        Key::Map(key.addr(), elem.addr()),
        || format!("map[{}]{}", key.inner().string, elem.inner().string),
        || Body::Map {
            key: key.clone(),
            elem: elem.clone(),
        },
    )
}

fn func_string(ins: &[Type], outs: &[Type], variadic: bool) -> String {
    let mut s = String::from("func(");
    for (i, t) in ins.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        if variadic && i == ins.len() - 1 {
            s.push_str("...");
            match t.body() {
                Body::Slice(e) => s.push_str(&e.inner().string),
                _ => s.push_str(&t.inner().string),
            }
        } else {
            s.push_str(&t.inner().string);
        }
    }
    s.push(')');
    match outs.len() {
        0 => {}
        1 => {
            s.push(' ');
            s.push_str(&outs[0].inner().string);
        }
        _ => {
            s.push_str(" (");
            for (i, t) in outs.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&t.inner().string);
            }
            s.push(')');
        }
    }
    s
}

/// Go `reflect.FuncOf`: the function type with the given parameter and result
/// types. It panics if `variadic` is set and the last parameter is not a slice.
pub fn func_of(ins: &[Type], outs: &[Type], variadic: bool) -> Type {
    if variadic && ins.last().is_none_or(|t| t.kind() != Kind::Slice) {
        panic_str("reflect.FuncOf: last arg of variadic func must be slice".into());
    }
    if ins.len() + outs.len() > 128 {
        panic_str("reflect.FuncOf: too many arguments".into());
    }
    Type::interned(
        Key::Func(
            ins.iter().map(Type::addr).collect(),
            outs.iter().map(Type::addr).collect(),
            variadic,
        ),
        || func_string(ins, outs, variadic),
        || Body::Func {
            ins: ins.to_vec(),
            outs: outs.to_vec(),
            variadic,
        },
    )
}

/// An unnamed interface type with the given methods (name, signature). Go
/// writes these as `interface { M() }` literals; the methods are sorted by name
/// as Go does.
pub fn interface_of(methods: &[(&str, Type)]) -> Type {
    let mut ms: Vec<IMethod> = methods
        .iter()
        .map(|(n, t)| IMethod {
            name: n.to_string(),
            pkg_path: String::new(),
            ty: t.clone(),
        })
        .collect();
    interface_from(&mut ms)
}

pub(crate) fn interface_from(ms: &mut Vec<IMethod>) -> Type {
    ms.sort_by(|a, b| a.name.cmp(&b.name));
    ms.dedup_by(|a, b| a.name == b.name);
    let key = Key::Interface(
        ms.iter()
            .map(|m| (m.name.clone(), m.pkg_path.clone(), m.ty.addr()))
            .collect(),
    );
    let ms = ms.clone();
    Type::interned(
        key,
        || {
            if ms.is_empty() {
                return "interface {}".to_string();
            }
            let mut s = String::from("interface { ");
            for (i, m) in ms.iter().enumerate() {
                if i > 0 {
                    s.push_str("; ");
                }
                s.push_str(&m.name);
                s.push_str(
                    m.ty.inner()
                        .string
                        .strip_prefix("func")
                        .unwrap_or(&m.ty.inner().string),
                );
            }
            s.push_str(" }");
            s
        },
        || Body::Interface {
            methods: ms.clone(),
        },
    )
}

pub(crate) fn struct_string(fields: &[StructField]) -> String {
    let mut s = String::from("struct {");
    for (i, f) in fields.iter().enumerate() {
        if !f.anonymous {
            s.push(' ');
            s.push_str(&f.name);
        }
        s.push(' ');
        s.push_str(&f.type_.inner().string);
        if !f.tag.0.is_empty() {
            s.push(' ');
            s.push_str(&strconv::quote(&f.tag.0));
        }
        if i + 1 < fields.len() {
            s.push(';');
        }
    }
    if !fields.is_empty() {
        s.push(' ');
    }
    s.push('}');
    s
}

/// Go `reflect.StructOf`: the struct type containing `fields`. `offset` and
/// `index` are ignored and computed as Go's compiler would on amd64.
pub fn struct_of(fields: &[StructField]) -> Type {
    let mut pkg_path = String::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut fs: Vec<StructField> = Vec::with_capacity(fields.len());
    for (i, field) in fields.iter().enumerate() {
        if field.name.is_empty() {
            panic_str(format!("reflect.StructOf: field {i} has no name"));
        }
        if !is_valid_field_name(&field.name) {
            panic_str(format!("reflect.StructOf: field {i} has invalid name"));
        }
        if field.anonymous && !field.pkg_path.is_empty() {
            panic_str(format!(
                "reflect.StructOf: field \"{}\" is anonymous but has PkgPath set",
                field.name
            ));
        }
        if field.is_exported() {
            let c = field.name.as_bytes()[0];
            if c.is_ascii_lowercase() || c == b'_' {
                panic_str(format!(
                    "reflect.StructOf: field \"{}\" is unexported but missing PkgPath",
                    field.name
                ));
            }
        }
        if !field.pkg_path.is_empty() {
            if pkg_path.is_empty() {
                pkg_path = field.pkg_path.clone();
            } else if pkg_path != field.pkg_path {
                panic_str(format!(
                    "reflect.StructOf: fields with different PkgPath {} and {}",
                    pkg_path, field.pkg_path
                ));
            }
        }
        if field.anonymous && field.type_.kind() == Kind::Pointer {
            let k = field.type_.elem().kind();
            if k == Kind::Pointer || k == Kind::Interface {
                panic_str(format!(
                    "reflect.StructOf: illegal embedded field type {}",
                    field.type_.inner().string
                ));
            }
        }
        if !seen.insert(&field.name) && field.name != "_" {
            panic_str(format!("reflect.StructOf: duplicate field {}", field.name));
        }
        let mut f = field.clone();
        f.offset = 0;
        f.index = vec![i];
        fs.push(f);
    }
    Type::from_fields(fs, pkg_path)
}

impl Type {
    pub(crate) fn from_fields(fs: Vec<StructField>, pkg_path: String) -> Type {
        let key = Key::Struct(
            pkg_path.clone(),
            fs.iter()
                .map(|f| (f.name.clone(), f.type_.addr(), f.tag.0.clone(), f.anonymous))
                .collect(),
        );
        Type::interned(
            key,
            || struct_string(&fs),
            || Body::Struct {
                fields: fs.clone(),
                pkg_path: pkg_path.clone(),
            },
        )
    }

    /// A defined struct type body for derived types.
    #[doc(hidden)]
    pub fn struct_body_fields(fields: Vec<StructField>, pkg_path: &str) -> Body {
        Body::Struct {
            fields,
            pkg_path: pkg_path.to_string(),
        }
    }

    /// The `Body` of the underlying type, for building named types.
    #[doc(hidden)]
    pub fn underlying_body(under: &Type) -> Body {
        under.clone_body()
    }
}

// ---------------------------------------------------------------------------
// Queries.

impl Type {
    /// Go `Type.Kind`.
    pub fn kind(&self) -> Kind {
        match self.body() {
            Body::Basic(k) => *k,
            Body::Array { .. } => Kind::Array,
            Body::Chan { .. } => Kind::Chan,
            Body::Func { .. } => Kind::Func,
            Body::Interface { .. } => Kind::Interface,
            Body::Map { .. } => Kind::Map,
            Body::Pointer(_) => Kind::Pointer,
            Body::Slice(_) => Kind::Slice,
            Body::Struct { .. } => Kind::Struct,
        }
    }

    /// Go `Type.Name`: the name of a defined type, or the empty string.
    pub fn name(&self) -> String {
        self.inner()
            .name
            .as_ref()
            .map(|(_, n)| n.clone())
            .unwrap_or_default()
    }

    /// Go `Type.PkgPath`: the package path of a defined type, or the empty
    /// string for predeclared and unnamed types.
    pub fn pkg_path(&self) -> String {
        self.inner()
            .name
            .as_ref()
            .map(|(p, _)| p.clone())
            .unwrap_or_default()
    }

    pub(crate) fn has_name(&self) -> bool {
        self.inner().name.is_some()
    }

    fn layout(&self) -> &Layout {
        self.inner().layout.get_or_init(|| match self.body() {
            Body::Basic(k) => {
                let (size, align) = match k {
                    Kind::Bool | Kind::Int8 | Kind::Uint8 => (1, 1),
                    Kind::Int16 | Kind::Uint16 => (2, 2),
                    Kind::Int32 | Kind::Uint32 | Kind::Float32 => (4, 4),
                    Kind::Complex64 => (8, 4),
                    Kind::Complex128 => (16, 8),
                    Kind::String => (16, 8),
                    _ => (8, 8),
                };
                Layout {
                    size,
                    align,
                    offsets: Vec::new(),
                }
            }
            Body::Array { len, elem } => Layout {
                size: len.saturating_mul(elem.size()),
                align: elem.align(),
                offsets: Vec::new(),
            },
            Body::Slice(_) => Layout {
                size: 24,
                align: 8,
                offsets: Vec::new(),
            },
            Body::Interface { .. } => Layout {
                size: 16,
                align: 8,
                offsets: Vec::new(),
            },
            Body::Chan { .. } | Body::Func { .. } | Body::Map { .. } | Body::Pointer(_) => Layout {
                size: 8,
                align: 8,
                offsets: Vec::new(),
            },
            Body::Struct { fields, .. } => {
                let mut size = 0usize;
                let mut align = 1usize;
                let mut lastzero = 0usize;
                let mut offsets = Vec::with_capacity(fields.len());
                for f in fields {
                    let a = f.type_.align();
                    let off = size.div_ceil(a) * a;
                    offsets.push(off);
                    align = align.max(a);
                    size = off + f.type_.size();
                    if f.type_.size() == 0 {
                        lastzero = size;
                    }
                }
                if size > 0 && lastzero == size {
                    size += 1;
                }
                size = size.div_ceil(align) * align;
                Layout {
                    size,
                    align,
                    offsets,
                }
            }
        })
    }

    /// Go `Type.Size`: the size in bytes of a value of the type, for Go's
    /// amd64/arm64 layout (not Rust's).
    pub fn size(&self) -> usize {
        self.layout().size
    }

    /// Go `Type.Align`.
    pub fn align(&self) -> usize {
        self.layout().align
    }

    /// Go `Type.FieldAlign`.
    pub fn field_align(&self) -> usize {
        self.layout().align
    }

    /// Go `Type.Bits`: the size in bits of an arithmetic type.
    pub fn bits(&self) -> usize {
        let k = self.kind();
        if k < Kind::Int || k > Kind::Complex128 {
            panic_str(format!(
                "reflect: Bits of non-arithmetic Type {}",
                self.inner().string
            ));
        }
        self.size() * 8
    }

    /// Go `Type.ChanDir`.
    pub fn chan_dir(&self) -> ChanDir {
        match self.body() {
            Body::Chan { dir, .. } => *dir,
            _ => panic_str(format!(
                "reflect: ChanDir of non-chan type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.IsVariadic`.
    pub fn is_variadic(&self) -> bool {
        match self.body() {
            Body::Func { variadic, .. } => *variadic,
            _ => panic_str(format!(
                "reflect: IsVariadic of non-func type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.Elem`: the element type of an array, channel, map, pointer or
    /// slice type.
    pub fn elem(&self) -> Type {
        match self.body() {
            Body::Array { elem, .. }
            | Body::Chan { elem, .. }
            | Body::Map { elem, .. }
            | Body::Pointer(elem)
            | Body::Slice(elem) => elem.clone(),
            _ => panic_str(format!(
                "reflect: Elem of invalid type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.Key`: the key type of a map type.
    pub fn key(&self) -> Type {
        match self.body() {
            Body::Map { key, .. } => key.clone(),
            _ => panic_str(format!(
                "reflect: Key of non-map type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.Len`: the length of an array type.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self.body() {
            Body::Array { len, .. } => *len,
            _ => panic_str(format!(
                "reflect: Len of non-array type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.NumField`.
    pub fn num_field(&self) -> usize {
        match self.body() {
            Body::Struct { fields, .. } => fields.len(),
            _ => panic_str(format!(
                "reflect: NumField of non-struct type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.Field`: the i'th struct field.
    pub fn field(&self, i: usize) -> StructField {
        match self.body() {
            Body::Struct { fields, .. } => {
                if i >= fields.len() {
                    panic_str("reflect: Field index out of bounds".into());
                }
                let mut f = fields[i].clone();
                f.offset = self.layout().offsets[i];
                f.index = vec![i];
                f
            }
            _ => panic_str(format!(
                "reflect: Field of non-struct type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.Fields`: the struct fields in order.
    pub fn fields(&self) -> Seq<'static, StructField> {
        if self.kind() != Kind::Struct {
            panic_str(format!(
                "reflect: Fields of non-struct type {}",
                self.inner().string
            ));
        }
        let t = self.clone();
        Box::new((0..self.num_field()).map(move |i| t.field(i)))
    }

    /// Go `Type.FieldByIndex`: the nested field for an index sequence.
    pub fn field_by_index(&self, index: &[usize]) -> StructField {
        if self.kind() != Kind::Struct {
            panic_str(format!(
                "reflect: FieldByIndex of non-struct type {}",
                self.inner().string
            ));
        }
        let mut ty = self.clone();
        let mut f = None;
        for (i, &x) in index.iter().enumerate() {
            if i > 0 && ty.kind() == Kind::Pointer && ty.elem().kind() == Kind::Struct {
                ty = ty.elem();
            }
            let field = ty.field(x);
            ty = field.type_.clone();
            f = Some(field);
        }
        f.unwrap_or_else(|| StructField::new("", self.clone()))
    }

    /// Go `Type.FieldByName`: the field with the given name, searching
    /// embedded structs breadth first as Go's selector rules do.
    pub fn field_by_name(&self, name: &str) -> Option<StructField> {
        if self.kind() != Kind::Struct {
            panic_str(format!(
                "reflect: FieldByName of non-struct type {}",
                self.inner().string
            ));
        }
        let mut has_embeds = false;
        if !name.is_empty() {
            if let Body::Struct { fields, .. } = self.body() {
                for (i, tf) in fields.iter().enumerate() {
                    if tf.name == name {
                        return Some(self.field(i));
                    }
                    if tf.anonymous {
                        has_embeds = true;
                    }
                }
            }
        }
        if !has_embeds {
            return None;
        }
        self.field_by_name_func(|s| s == name)
    }

    /// Go `Type.FieldByNameFunc`.
    pub fn field_by_name_func(&self, mut matches: impl FnMut(&str) -> bool) -> Option<StructField> {
        if self.kind() != Kind::Struct {
            panic_str(format!(
                "reflect: FieldByNameFunc of non-struct type {}",
                self.inner().string
            ));
        }
        struct Scan {
            typ: Type,
            index: Vec<usize>,
        }
        let mut result: Option<StructField> = None;
        let mut current: Vec<Scan>;
        let mut next = vec![Scan {
            typ: self.clone(),
            index: Vec::new(),
        }];
        let mut next_count: HashMap<usize, i32> = HashMap::new();
        let mut visited: HashSet<usize> = HashSet::new();
        while !next.is_empty() {
            current = std::mem::take(&mut next);
            let count = std::mem::take(&mut next_count);
            for scan in &current {
                let t = &scan.typ;
                if visited.contains(&t.addr()) {
                    continue;
                }
                visited.insert(t.addr());
                let Body::Struct { fields, .. } = t.body() else {
                    continue;
                };
                for (i, f) in fields.iter().enumerate() {
                    let mut ntyp: Option<Type> = None;
                    if f.anonymous {
                        let mut n = f.type_.clone();
                        if n.kind() == Kind::Pointer {
                            n = n.elem();
                        }
                        ntyp = Some(n);
                    }
                    if matches(&f.name) {
                        if count.get(&t.addr()).copied().unwrap_or(0) > 1 || result.is_some() {
                            return None;
                        }
                        let mut r = t.field(i);
                        let mut idx = scan.index.clone();
                        idx.push(i);
                        r.index = idx;
                        result = Some(r);
                        continue;
                    }
                    let Some(styp) = ntyp else { continue };
                    if result.is_some() || styp.kind() != Kind::Struct {
                        continue;
                    }
                    if next_count.get(&styp.addr()).copied().unwrap_or(0) > 0 {
                        next_count.insert(styp.addr(), 2);
                        continue;
                    }
                    next_count.insert(styp.addr(), 1);
                    if count.get(&t.addr()).copied().unwrap_or(0) > 1 {
                        next_count.insert(styp.addr(), 2);
                    }
                    let mut idx = scan.index.clone();
                    idx.push(i);
                    next.push(Scan {
                        typ: styp,
                        index: idx,
                    });
                }
            }
            if result.is_some() {
                break;
            }
        }
        result
    }

    /// Go `Type.NumIn`.
    pub fn num_in(&self) -> usize {
        match self.body() {
            Body::Func { ins, .. } => ins.len(),
            _ => panic_str(format!(
                "reflect: NumIn of non-func type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.NumOut`.
    pub fn num_out(&self) -> usize {
        match self.body() {
            Body::Func { outs, .. } => outs.len(),
            _ => panic_str(format!(
                "reflect: NumOut of non-func type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.In`: the type of the i'th parameter.
    pub fn in_(&self, i: usize) -> Type {
        match self.body() {
            Body::Func { ins, .. } => match ins.get(i) {
                Some(t) => t.clone(),
                None => panic_str("index out of range".into()),
            },
            _ => panic_str(format!(
                "reflect: In of non-func type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.Out`: the type of the i'th result.
    pub fn out(&self, i: usize) -> Type {
        match self.body() {
            Body::Func { outs, .. } => match outs.get(i) {
                Some(t) => t.clone(),
                None => panic_str("index out of range".into()),
            },
            _ => panic_str(format!(
                "reflect: Out of non-func type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.Ins`: the parameter types in order.
    pub fn ins(&self) -> Seq<'static, Type> {
        match self.body() {
            Body::Func { ins, .. } => Box::new(ins.clone().into_iter()),
            _ => panic_str(format!(
                "reflect: Ins of non-func type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.Outs`: the result types in order.
    pub fn outs(&self) -> Seq<'static, Type> {
        match self.body() {
            Body::Func { outs, .. } => Box::new(outs.clone().into_iter()),
            _ => panic_str(format!(
                "reflect: Outs of non-func type {}",
                self.inner().string
            )),
        }
    }

    pub(crate) fn func_parts(&self) -> (&[Type], &[Type], bool) {
        match self.body() {
            Body::Func {
                ins,
                outs,
                variadic,
            } => (ins, outs, *variadic),
            _ => panic_str(format!("reflect: not a func type {}", self.inner().string)),
        }
    }

    /// Go `Type.Comparable`: whether values of the type can be compared with
    /// `==`.
    pub fn comparable(&self) -> bool {
        *self.inner().comparable.get_or_init(|| match self.body() {
            Body::Basic(_) | Body::Chan { .. } | Body::Pointer(_) | Body::Interface { .. } => true,
            Body::Func { .. } | Body::Map { .. } | Body::Slice(_) => false,
            Body::Array { elem, .. } => elem.comparable(),
            Body::Struct { fields, .. } => fields.iter().all(|f| f.type_.comparable()),
        })
    }

    /// Go `Type.OverflowComplex`.
    pub fn overflow_complex(&self, re: f64, im: f64) -> bool {
        match self.kind() {
            Kind::Complex64 => overflow_float32(re) || overflow_float32(im),
            Kind::Complex128 => false,
            _ => panic_str(format!(
                "reflect: OverflowComplex of non-complex type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.OverflowFloat`.
    pub fn overflow_float(&self, x: f64) -> bool {
        match self.kind() {
            Kind::Float32 => overflow_float32(x),
            Kind::Float64 => false,
            _ => panic_str(format!(
                "reflect: OverflowFloat of non-float type {}",
                self.inner().string
            )),
        }
    }

    /// Go `Type.OverflowInt`.
    pub fn overflow_int(&self, x: i64) -> bool {
        if self.kind().is_int() {
            let bits = (self.size() * 8) as u32;
            let trunc = (x << (64 - bits)) >> (64 - bits);
            return x != trunc;
        }
        panic_str(format!(
            "reflect: OverflowInt of non-int type {}",
            self.inner().string
        ))
    }

    /// Go `Type.OverflowUint`.
    pub fn overflow_uint(&self, x: u64) -> bool {
        if self.kind().is_uint() {
            let bits = (self.size() * 8) as u32;
            let trunc = (x << (64 - bits)) >> (64 - bits);
            return x != trunc;
        }
        panic_str(format!(
            "reflect: OverflowUint of non-uint type {}",
            self.inner().string
        ))
    }

    /// Go `Type.CanSeq`: whether `Value::seq` works on values of the type.
    pub fn can_seq(&self) -> bool {
        match self.kind() {
            Kind::Int8
            | Kind::Int16
            | Kind::Int32
            | Kind::Int64
            | Kind::Int
            | Kind::Uint8
            | Kind::Uint16
            | Kind::Uint32
            | Kind::Uint64
            | Kind::Uint
            | Kind::Uintptr
            | Kind::Array
            | Kind::Slice
            | Kind::Chan
            | Kind::String
            | Kind::Map => true,
            Kind::Func => self.can_range_func(1),
            Kind::Pointer => self.elem().kind() == Kind::Array,
            _ => false,
        }
    }

    /// Go `Type.CanSeq2`: whether `Value::seq2` works on values of the type.
    pub fn can_seq2(&self) -> bool {
        match self.kind() {
            Kind::Array | Kind::Slice | Kind::String | Kind::Map => true,
            Kind::Func => self.can_range_func(2),
            Kind::Pointer => self.elem().kind() == Kind::Array,
            _ => false,
        }
    }

    pub(crate) fn can_range_func(&self, seq: usize) -> bool {
        let Body::Func { ins, outs, .. } = self.body() else {
            return false;
        };
        if ins.len() != 1 || !outs.is_empty() {
            return false;
        }
        let Body::Func {
            ins: yin,
            outs: yout,
            ..
        } = ins[0].body()
        else {
            return false;
        };
        yin.len() == seq
            && yout.len() == 1
            && yout[0].kind() == Kind::Bool
            && yout[0].pkg_path().is_empty()
    }
}

pub(crate) fn overflow_float32(x: f64) -> bool {
    let x = x.abs();
    (f32::MAX as f64) < x && x <= f64::MAX
}

// ---------------------------------------------------------------------------
// Method sets.

impl Type {
    fn declared(&self) -> &[Arc<MethodDef>] {
        self.declared_methods()
    }

    pub(crate) fn method_set(&self) -> Arc<Vec<MethodEntry>> {
        self.inner()
            .mset
            .get_or_init(|| Arc::new(self.compute_method_set()))
            .clone()
    }

    fn compute_method_set(&self) -> Vec<MethodEntry> {
        if let Body::Interface { methods } = self.body() {
            let mut v: Vec<MethodEntry> = methods
                .iter()
                .map(|m| MethodEntry {
                    name: m.name.clone(),
                    pkg_path: m.pkg_path.clone(),
                    ty: m.ty.clone(),
                    path: Vec::new(),
                    def: None,
                })
                .collect();
            v.sort_by(|a, b| a.name.cmp(&b.name));
            return v;
        }
        let (base, ptr) = match self.body() {
            Body::Pointer(e) => (e.clone(), true),
            _ => (self.clone(), false),
        };
        if base.kind() == Kind::Pointer || base.kind() == Kind::Interface {
            return Vec::new();
        }
        struct Cand {
            ty: Type,
            path: Vec<usize>,
            ptr: bool,
        }
        // Each name maps to the candidates found at one depth: `None` marks a
        // field or an excluded method that still occupies the name.
        let mut found: HashMap<String, Option<MethodEntry>> = HashMap::new();
        let mut seen: HashSet<usize> = HashSet::new();
        let mut level = vec![Cand {
            ty: base,
            path: Vec::new(),
            ptr,
        }];
        while !level.is_empty() {
            let mut names: HashMap<String, Vec<Option<MethodEntry>>> = HashMap::new();
            let mut next: Vec<Cand> = Vec::new();
            for cand in &level {
                if !seen.insert(cand.ty.addr()) {
                    continue;
                }
                for d in cand.ty.declared() {
                    let entry = if d.ptr_recv && !cand.ptr {
                        None
                    } else {
                        Some(MethodEntry {
                            name: d.name.clone(),
                            pkg_path: d.pkg_path.clone(),
                            ty: d.ty.clone(),
                            path: cand.path.clone(),
                            def: Some(d.clone()),
                        })
                    };
                    names.entry(d.name.clone()).or_default().push(entry);
                }
                match cand.ty.body() {
                    Body::Interface { methods } if !cand.path.is_empty() => {
                        for m in methods {
                            names
                                .entry(m.name.clone())
                                .or_default()
                                .push(Some(MethodEntry {
                                    name: m.name.clone(),
                                    pkg_path: m.pkg_path.clone(),
                                    ty: m.ty.clone(),
                                    path: cand.path.clone(),
                                    def: None,
                                }));
                        }
                    }
                    Body::Struct { fields, .. } => {
                        for (i, f) in fields.iter().enumerate() {
                            names.entry(f.name.clone()).or_default().push(None);
                            if f.anonymous {
                                let (p2, e) = if f.type_.kind() == Kind::Pointer {
                                    (true, f.type_.elem())
                                } else {
                                    (false, f.type_.clone())
                                };
                                let mut path = cand.path.clone();
                                path.push(i);
                                next.push(Cand {
                                    ty: e,
                                    path,
                                    ptr: cand.ptr || p2,
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
            for (name, mut cands) in names {
                if found.contains_key(&name) {
                    continue;
                }
                if cands.len() == 1 {
                    found.insert(name, cands.pop().flatten());
                } else {
                    found.insert(name, None);
                }
            }
            level = next;
        }
        let mut v: Vec<MethodEntry> = found.into_values().flatten().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// The methods that count for `num_method` and `method`: exported ones for
    /// concrete types, all for interfaces.
    pub(crate) fn visible_methods(&self) -> Vec<usize> {
        let ms = self.method_set();
        let iface = self.kind() == Kind::Interface;
        ms.iter()
            .enumerate()
            .filter(|(_, m)| iface || m.pkg_path.is_empty())
            .map(|(i, _)| i)
            .collect()
    }

    /// Go `Type.NumMethod`.
    pub fn num_method(&self) -> usize {
        self.visible_methods().len()
    }

    /// Go `Type.Method`: the i'th method of the method set, sorted by name.
    pub fn method(&self, i: usize) -> Method {
        let vis = self.visible_methods();
        if i >= vis.len() {
            if self.kind() == Kind::Interface {
                return Method {
                    name: String::new(),
                    pkg_path: String::new(),
                    type_: Type::any_type(),
                    func: Value::default(),
                    index: 0,
                };
            }
            panic_str("reflect: Method index out of range".into());
        }
        let ms = self.method_set();
        let e = &ms[vis[i]];
        if self.kind() == Kind::Interface {
            return Method {
                name: e.name.clone(),
                pkg_path: e.pkg_path.clone(),
                type_: e.ty.clone(),
                func: Value::default(),
                index: i,
            };
        }
        let (ins, outs, variadic) = e.ty.func_parts();
        let mut all_ins = Vec::with_capacity(ins.len() + 1);
        all_ins.push(self.clone());
        all_ins.extend(ins.iter().cloned());
        let mt = func_of(&all_ins, outs, variadic);
        let func = Value::method_func(self, vis[i], &mt);
        Method {
            name: e.name.clone(),
            pkg_path: e.pkg_path.clone(),
            type_: mt,
            func,
            index: i,
        }
    }

    /// Go `Type.Methods`: the methods of the method set in order.
    pub fn methods(&self) -> Seq<'static, Method> {
        let t = self.clone();
        Box::new((0..self.num_method()).map(move |i| t.method(i)))
    }

    /// Go `Type.MethodByName`.
    pub fn method_by_name(&self, name: &str) -> Option<Method> {
        let vis = self.visible_methods();
        let ms = self.method_set();
        vis.iter()
            .position(|&j| ms[j].name == name)
            .map(|i| self.method(i))
    }
}

// ---------------------------------------------------------------------------
// Relations between types.

impl Type {
    /// Go `Type.Implements`: whether the type implements the interface type
    /// `u`. It panics if `u` is not an interface type.
    pub fn implements(&self, u: &Type) -> bool {
        if u.kind() != Kind::Interface {
            panic_str("reflect: non-interface type passed to Type.Implements".into());
        }
        implements(u, self)
    }

    /// Go `Type.AssignableTo`.
    pub fn assignable_to(&self, u: &Type) -> bool {
        directly_assignable(u, self) || implements(u, self)
    }

    /// Go `Type.ConvertibleTo`. Even when it returns true the conversion may
    /// still panic (a slice converted to a longer array).
    pub fn convertible_to(&self, u: &Type) -> bool {
        convert_op(u, self).is_some()
    }
}

pub(crate) fn implements(t: &Type, v: &Type) -> bool {
    let Body::Interface { methods } = t.body() else {
        return false;
    };
    if methods.is_empty() {
        return true;
    }
    let vset = v.method_set();
    for tm in methods {
        // Unexported methods match only within one package.
        let ok = vset.iter().any(|vm| {
            vm.name == tm.name
                && vm.ty == tm.ty
                && (tm.pkg_path.is_empty() || tm.pkg_path == vm.pkg_path)
        });
        if !ok {
            return false;
        }
    }
    true
}

pub(crate) fn special_channel_assignability(t: &Type, v: &Type) -> bool {
    v.chan_dir() == ChanDir::Both
        && (!t.has_name() || !v.has_name())
        && have_identical_type(&t.elem(), &v.elem(), true)
}

pub(crate) fn directly_assignable(t: &Type, v: &Type) -> bool {
    if t == v {
        return true;
    }
    if t.has_name() && v.has_name() || t.kind() != v.kind() {
        return false;
    }
    if t.kind() == Kind::Chan && special_channel_assignability(t, v) {
        return true;
    }
    have_identical_underlying_type(t, v, true)
}

pub(crate) fn have_identical_type(t: &Type, v: &Type, cmp_tags: bool) -> bool {
    if cmp_tags {
        return t == v;
    }
    if t.name() != v.name() || t.kind() != v.kind() || t.pkg_path() != v.pkg_path() {
        return false;
    }
    have_identical_underlying_type(t, v, false)
}

pub(crate) fn have_identical_underlying_type(t: &Type, v: &Type, cmp_tags: bool) -> bool {
    if t == v {
        return true;
    }
    let kind = t.kind();
    if kind != v.kind() {
        return false;
    }
    if (Kind::Bool..=Kind::Complex128).contains(&kind)
        || kind == Kind::String
        || kind == Kind::UnsafePointer
    {
        return true;
    }
    match (t.body(), v.body()) {
        (Body::Array { len: l1, elem: e1 }, Body::Array { len: l2, elem: e2 }) => {
            l1 == l2 && have_identical_type(e1, e2, cmp_tags)
        }
        (Body::Chan { dir: d1, elem: e1 }, Body::Chan { dir: d2, elem: e2 }) => {
            d1 == d2 && have_identical_type(e1, e2, cmp_tags)
        }
        (
            Body::Func {
                ins: i1,
                outs: o1,
                variadic: v1,
            },
            Body::Func {
                ins: i2,
                outs: o2,
                variadic: v2,
            },
        ) => {
            if i1.len() != i2.len() || o1.len() != o2.len() || v1 != v2 {
                return false;
            }
            i1.iter()
                .zip(i2)
                .all(|(a, b)| have_identical_type(a, b, cmp_tags))
                && o1
                    .iter()
                    .zip(o2)
                    .all(|(a, b)| have_identical_type(a, b, cmp_tags))
        }
        (Body::Interface { methods: m1 }, Body::Interface { methods: m2 }) => {
            m1.is_empty() && m2.is_empty()
        }
        (Body::Map { key: k1, elem: e1 }, Body::Map { key: k2, elem: e2 }) => {
            have_identical_type(k1, k2, cmp_tags) && have_identical_type(e1, e2, cmp_tags)
        }
        (Body::Pointer(e1), Body::Pointer(e2)) | (Body::Slice(e1), Body::Slice(e2)) => {
            have_identical_type(e1, e2, cmp_tags)
        }
        (
            Body::Struct {
                fields: f1,
                pkg_path: p1,
            },
            Body::Struct {
                fields: f2,
                pkg_path: p2,
            },
        ) => {
            if f1.len() != f2.len() || p1 != p2 {
                return false;
            }
            let (l1, l2) = (t.layout(), v.layout());
            for (i, (a, b)) in f1.iter().zip(f2).enumerate() {
                if a.name != b.name
                    || !have_identical_type(&a.type_, &b.type_, cmp_tags)
                    || (cmp_tags && a.tag != b.tag)
                    || l1.offsets[i] != l2.offsets[i]
                    || a.anonymous != b.anonymous
                {
                    return false;
                }
            }
            true
        }
        _ => false,
    }
}

/// How `Value::convert` turns a value of one type into another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConvOp {
    Int,
    Uint,
    FloatInt,
    FloatUint,
    IntFloat,
    UintFloat,
    Float,
    Complex,
    IntString,
    UintString,
    BytesString,
    StringBytes,
    RunesString,
    StringRunes,
    SliceArrayPtr,
    SliceArray,
    Direct,
    ToInterface,
    InterfaceToInterface,
}

pub(crate) fn convert_op(dst: &Type, src: &Type) -> Option<ConvOp> {
    let (dk, sk) = (dst.kind(), src.kind());
    match sk {
        k if k.is_int() => match dk {
            d if d.is_int() || d.is_uint() => return Some(ConvOp::Int),
            d if d.is_float() => return Some(ConvOp::IntFloat),
            Kind::String => return Some(ConvOp::IntString),
            _ => {}
        },
        k if k.is_uint() => match dk {
            d if d.is_int() || d.is_uint() => return Some(ConvOp::Uint),
            d if d.is_float() => return Some(ConvOp::UintFloat),
            Kind::String => return Some(ConvOp::UintString),
            _ => {}
        },
        k if k.is_float() => match dk {
            d if d.is_int() => return Some(ConvOp::FloatInt),
            d if d.is_uint() => return Some(ConvOp::FloatUint),
            d if d.is_float() => return Some(ConvOp::Float),
            _ => {}
        },
        k if k.is_complex() => {
            if dk.is_complex() {
                return Some(ConvOp::Complex);
            }
        }
        Kind::String => {
            if dk == Kind::Slice {
                match dst.elem().kind() {
                    Kind::Uint8 => return Some(ConvOp::StringBytes),
                    Kind::Int32 => return Some(ConvOp::StringRunes),
                    _ => {}
                }
            }
        }
        Kind::Slice => {
            if dk == Kind::String {
                match src.elem().kind() {
                    Kind::Uint8 => return Some(ConvOp::BytesString),
                    Kind::Int32 => return Some(ConvOp::RunesString),
                    _ => {}
                }
            }
            if dk == Kind::Pointer
                && dst.elem().kind() == Kind::Array
                && src.elem() == dst.elem().elem()
            {
                return Some(ConvOp::SliceArrayPtr);
            }
            if dk == Kind::Array && src.elem() == dst.elem() {
                return Some(ConvOp::SliceArray);
            }
        }
        Kind::Chan if dk == Kind::Chan && special_channel_assignability(dst, src) => {
            return Some(ConvOp::Direct);
        }
        _ => {}
    }
    if have_identical_underlying_type(dst, src, false) {
        return Some(ConvOp::Direct);
    }
    if dk == Kind::Pointer
        && !dst.has_name()
        && sk == Kind::Pointer
        && !src.has_name()
        && have_identical_underlying_type(&dst.elem(), &src.elem(), false)
    {
        return Some(ConvOp::Direct);
    }
    if implements(dst, src) {
        return Some(if sk == Kind::Interface {
            ConvOp::InterfaceToInterface
        } else {
            ConvOp::ToInterface
        });
    }
    None
}

/// Panics like Go when a type is nil; kept for symmetry with `value_error`.
#[allow(dead_code)]
pub(crate) fn must_be_kind(t: &Type, k: Kind, method: &str) {
    if t.kind() != k {
        value_error(method, t.kind());
    }
}
