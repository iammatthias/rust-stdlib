//! The descriptions of Go types that `SemanticError` reports.
//!
//! Go's `reflect.Type` names the type a value was being converted from or
//! into. Rust has no such name, so the types that can be marshaled describe
//! themselves with a [`TypeInfo`]: the text `reflect.Type.String()` would give
//! (`int64`, `[]string`, `map[string]int`, `*main.T`) and its [`TypeKind`].
use std::any::TypeId;
use std::fmt;

/// Go's `reflect.Kind`, for the kinds JSON handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypeKind {
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
    Array,
    Interface,
    Map,
    Pointer,
    Slice,
    String,
    Struct,
}

/// Go's `Kind.String`.
impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TypeKind::Invalid => "invalid",
            TypeKind::Bool => "bool",
            TypeKind::Int => "int",
            TypeKind::Int8 => "int8",
            TypeKind::Int16 => "int16",
            TypeKind::Int32 => "int32",
            TypeKind::Int64 => "int64",
            TypeKind::Uint => "uint",
            TypeKind::Uint8 => "uint8",
            TypeKind::Uint16 => "uint16",
            TypeKind::Uint32 => "uint32",
            TypeKind::Uint64 => "uint64",
            TypeKind::Uintptr => "uintptr",
            TypeKind::Float32 => "float32",
            TypeKind::Float64 => "float64",
            TypeKind::Array => "array",
            TypeKind::Interface => "interface",
            TypeKind::Map => "map",
            TypeKind::Pointer => "ptr",
            TypeKind::Slice => "slice",
            TypeKind::String => "string",
            TypeKind::Struct => "struct",
        })
    }
}

/// A Go type, as `SemanticError.TypeInfo` (a `reflect.Type`) reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeInfo {
    /// `reflect.Type.String()`.
    pub name: String,
    /// `reflect.Type.Kind()`.
    pub kind: TypeKind,
    /// The Rust type, when known.
    pub id: Option<TypeId>,
    /// `reflect.Type.Elem()` of a pointer, slice, array or map.
    pub elem: Option<Box<TypeInfo>>,
    /// `reflect.Type.Key()` of a map.
    pub key: Option<Box<TypeInfo>>,
}

impl TypeInfo {
    /// A type with the given name and kind, for the Rust type `T`.
    pub fn of<T: 'static>(name: &str, kind: TypeKind) -> TypeInfo {
        TypeInfo {
            name: name.to_string(),
            kind,
            id: Some(TypeId::of::<T>()),
            elem: None,
            key: None,
        }
    }

    /// Sets the element type.
    #[must_use]
    pub fn with_elem(mut self, elem: TypeInfo) -> TypeInfo {
        self.elem = Some(Box::new(elem));
        self
    }

    /// Sets the key type.
    #[must_use]
    pub fn with_key(mut self, key: TypeInfo) -> TypeInfo {
        self.key = Some(Box::new(key));
        self
    }

    /// Go's `Type.Kind`.
    pub fn kind(&self) -> TypeKind {
        self.kind
    }
}

impl fmt::Display for TypeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}
