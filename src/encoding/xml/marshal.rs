//! The data-model side of marshaling: what Go reads through `reflect`.
use super::{
    typeinfo::{FieldSpec, StructSpec},
    Attr, Encoder, Error, Name, StartElement,
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    rc::Rc,
    sync::Arc,
};

/// An object that can marshal itself into valid XML elements (Go `Marshaler`).
///
/// `marshal_xml` encodes the receiver as zero or more XML elements. Using
/// `start` as the element tag is not required, but doing so lets [`unmarshal`]
/// match the elements to the correct struct field. A type opts in by returning
/// itself from [`Marshal::xml_marshaler`].
///
/// [`unmarshal`]: super::unmarshal
pub trait Marshaler {
    /// Go's `MarshalXML`.
    fn marshal_xml(&self, e: &mut Encoder<'_>, start: StartElement) -> Result<(), Error>;
}

/// An object that can marshal itself into a valid XML attribute (Go
/// `MarshalerAttr`). If `marshal_xml_attr` returns an [`Attr`] with an empty
/// local name, no attribute is generated. Opt in with
/// [`Marshal::xml_attr_marshaler`].
pub trait MarshalerAttr {
    /// Go's `MarshalXMLAttr`.
    fn marshal_xml_attr(&self, name: Name) -> Result<Attr, Error>;
}

/// Go's `encoding.TextMarshaler`: a value encoded as text. Opt in with
/// [`Marshal::xml_text_marshaler`].
pub trait TextMarshaler {
    /// Go's `MarshalText`.
    fn marshal_text(&self) -> Result<Vec<u8>, Error>;
}

/// Go's `encoding.TextUnmarshaler`. Opt in with
/// [`Unmarshal::xml_text_unmarshaler`](super::Unmarshal::xml_text_unmarshaler).
pub trait TextUnmarshaler {
    /// Go's `UnmarshalText`.
    fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Error>;
}

/// What Go's marshaler sees through `reflect.Value`.
pub enum View<'a> {
    /// A nil pointer or interface: marshals to nothing.
    Nil,
    /// A non-nil pointer or interface: marshal the pointee.
    Ptr(&'a dyn Marshal),
    /// A `bool`.
    Bool(bool),
    /// A signed integer of any width.
    Int(i64),
    /// An unsigned integer of any width.
    Uint(u64),
    /// A float and its bit size (32 or 64).
    Float(f64, u32),
    /// A string.
    Str(&'a str),
    /// A byte slice or array (`[]byte`, `[N]byte`).
    Bytes(Cow<'a, [u8]>),
    /// A slice or array of non-bytes: each element is its own element.
    Seq(Vec<&'a dyn Marshal>),
    /// A struct with the given field description; fields come from
    /// [`Marshal::xml_field`].
    Struct(&'static StructSpec),
    /// A map (Go cannot marshal them); `len` serves `omitempty`.
    Map {
        /// Number of entries.
        len: usize,
    },
    /// Any other kind Go cannot marshal (channel, function, ...).
    Unsupported,
}

/// A value that can be written as XML (the Rust counterpart of what Go's
/// `Marshal` does through reflection). Implemented for the primitive types,
/// strings, byte and element sequences, `Option`, smart pointers, [`Name`] and
/// [`Attr`], and by `#[derive(Marshal)]` for structs.
pub trait Marshal {
    /// Describes the value's kind and content.
    fn xml_view(&self) -> View<'_>;

    /// Go's `typ.Name()`: the default element name; empty for unnamed types.
    fn xml_type_name(&self) -> &'static str {
        ""
    }

    /// Go's `typ.String()`, used in error messages.
    fn xml_type_string(&self) -> String {
        std::any::type_name_of_val(self).to_string()
    }

    /// The value of field `i` of a struct view.
    fn xml_field(&self, _i: usize) -> Option<&dyn Marshal> {
        None
    }

    /// The value as a [`Marshaler`], if its type implements one.
    fn xml_marshaler(&self) -> Option<&dyn Marshaler> {
        None
    }

    /// The value as a [`MarshalerAttr`], if its type implements one.
    fn xml_attr_marshaler(&self) -> Option<&dyn MarshalerAttr> {
        None
    }

    /// The value as a [`TextMarshaler`], if its type implements one.
    fn xml_text_marshaler(&self) -> Option<&dyn TextMarshaler> {
        None
    }

    /// This value as a [`Name`] (Go's `XMLName` field type check).
    fn xml_as_name(&self) -> Option<&Name> {
        None
    }

    /// This value as an [`Attr`] (Go's `val.Type() == attrType`).
    fn xml_as_attr(&self) -> Option<&Attr> {
        None
    }

    /// Whether the type is `u8`, which makes sequences of it byte slices.
    fn xml_is_byte() -> bool
    where
        Self: Sized,
    {
        false
    }

    /// The byte value when `xml_is_byte`.
    fn xml_to_byte(&self) -> u8 {
        0
    }

    /// The struct description when the type is a struct, looking through
    /// pointers (what `lookupXMLName` and embedding need).
    fn xml_struct_spec() -> Option<&'static StructSpec>
    where
        Self: Sized,
    {
        None
    }

    /// Go's type string of `Self` as an element of a slice or map.
    fn xml_elem_type_string() -> String
    where
        Self: Sized,
    {
        std::any::type_name::<Self>().to_string()
    }
}

macro_rules! int_impl {
    ($($t:ty => $name:expr, $go:expr, $view:ident, $as:ty;)*) => {$(
        impl Marshal for $t {
            fn xml_view(&self) -> View<'_> { View::$view(*self as $as) }
            fn xml_type_name(&self) -> &'static str { $name }
            fn xml_type_string(&self) -> String { $go.to_string() }
            fn xml_elem_type_string() -> String { $go.to_string() }
        }
    )*};
}
int_impl! {
    i8 => "int8", "int8", Int, i64;
    i16 => "int16", "int16", Int, i64;
    i32 => "int32", "int32", Int, i64;
    i64 => "int64", "int64", Int, i64;
    isize => "int", "int", Int, i64;
    u16 => "uint16", "uint16", Uint, u64;
    u32 => "uint32", "uint32", Uint, u64;
    u64 => "uint64", "uint64", Uint, u64;
    usize => "uint", "uint", Uint, u64;
}

impl Marshal for u8 {
    fn xml_view(&self) -> View<'_> {
        View::Uint(u64::from(*self))
    }
    fn xml_type_name(&self) -> &'static str {
        "uint8"
    }
    fn xml_type_string(&self) -> String {
        "uint8".into()
    }
    fn xml_elem_type_string() -> String {
        "uint8".into()
    }
    fn xml_is_byte() -> bool {
        true
    }
    fn xml_to_byte(&self) -> u8 {
        *self
    }
}

impl Marshal for bool {
    fn xml_view(&self) -> View<'_> {
        View::Bool(*self)
    }
    fn xml_type_name(&self) -> &'static str {
        "bool"
    }
    fn xml_type_string(&self) -> String {
        "bool".into()
    }
    fn xml_elem_type_string() -> String {
        "bool".into()
    }
}

impl Marshal for f32 {
    fn xml_view(&self) -> View<'_> {
        View::Float(f64::from(*self), 32)
    }
    fn xml_type_name(&self) -> &'static str {
        "float32"
    }
    fn xml_type_string(&self) -> String {
        "float32".into()
    }
    fn xml_elem_type_string() -> String {
        "float32".into()
    }
}

impl Marshal for f64 {
    fn xml_view(&self) -> View<'_> {
        View::Float(*self, 64)
    }
    fn xml_type_name(&self) -> &'static str {
        "float64"
    }
    fn xml_type_string(&self) -> String {
        "float64".into()
    }
    fn xml_elem_type_string() -> String {
        "float64".into()
    }
}

impl Marshal for str {
    fn xml_view(&self) -> View<'_> {
        View::Str(self)
    }
    fn xml_type_name(&self) -> &'static str {
        "string"
    }
    fn xml_type_string(&self) -> String {
        "string".into()
    }
}

impl Marshal for String {
    fn xml_view(&self) -> View<'_> {
        View::Str(self)
    }
    fn xml_type_name(&self) -> &'static str {
        "string"
    }
    fn xml_type_string(&self) -> String {
        "string".into()
    }
    fn xml_elem_type_string() -> String {
        "string".into()
    }
}

/// A nil interface value: marshals to nothing.
impl Marshal for () {
    fn xml_view(&self) -> View<'_> {
        View::Nil
    }
}

macro_rules! pointer_impl {
    ($($ptr:ty),*) => {$(
        impl<T: Marshal> Marshal for $ptr {
            fn xml_view(&self) -> View<'_> {
                View::Ptr(&**self)
            }
            fn xml_attr_marshaler(&self) -> Option<&dyn MarshalerAttr> {
                (**self).xml_attr_marshaler()
            }
            fn xml_text_marshaler(&self) -> Option<&dyn TextMarshaler> {
                (**self).xml_text_marshaler()
            }
            fn xml_struct_spec() -> Option<&'static StructSpec> {
                T::xml_struct_spec()
            }
        }
    )*};
}
pointer_impl!(Box<T>, Rc<T>, Arc<T>, &T, &mut T);

/// A string slice is a Go string value.
impl Marshal for &str {
    fn xml_view(&self) -> View<'_> {
        View::Str(self)
    }
    fn xml_type_name(&self) -> &'static str {
        "string"
    }
    fn xml_type_string(&self) -> String {
        "string".into()
    }
    fn xml_elem_type_string() -> String {
        "string".into()
    }
}

/// A slice reference is a Go slice value.
impl<T: Marshal> Marshal for &[T] {
    fn xml_view(&self) -> View<'_> {
        seq_view(self)
    }
    fn xml_type_string(&self) -> String {
        seq_type_string::<T>("[]")
    }
    fn xml_elem_type_string() -> String {
        seq_type_string::<T>("[]")
    }
}

/// `Box<dyn Marshal>` stands in for a Go interface value.
impl Marshal for Box<dyn Marshal> {
    fn xml_view(&self) -> View<'_> {
        View::Ptr(&**self)
    }
}
/// `None` is a nil pointer; `Some` is a pointer to the value.
impl<T: Marshal> Marshal for Option<T> {
    fn xml_view(&self) -> View<'_> {
        match self {
            Some(v) => View::Ptr(v),
            None => View::Nil,
        }
    }
    fn xml_attr_marshaler(&self) -> Option<&dyn MarshalerAttr> {
        self.as_ref().and_then(Marshal::xml_attr_marshaler)
    }
    fn xml_text_marshaler(&self) -> Option<&dyn TextMarshaler> {
        self.as_ref().and_then(Marshal::xml_text_marshaler)
    }
    fn xml_struct_spec() -> Option<&'static StructSpec> {
        T::xml_struct_spec()
    }
}

fn seq_view<'a, T: Marshal>(items: &'a [T]) -> View<'a> {
    if T::xml_is_byte() {
        View::Bytes(Cow::Owned(items.iter().map(Marshal::xml_to_byte).collect()))
    } else {
        View::Seq(items.iter().map(|v| v as &dyn Marshal).collect())
    }
}

fn seq_type_string<T: Marshal>(prefix: &str) -> String {
    format!("{prefix}{}", T::xml_elem_type_string())
}

impl<T: Marshal> Marshal for Vec<T> {
    fn xml_view(&self) -> View<'_> {
        seq_view(self)
    }
    fn xml_type_string(&self) -> String {
        seq_type_string::<T>("[]")
    }
    fn xml_elem_type_string() -> String {
        seq_type_string::<T>("[]")
    }
}

impl<T: Marshal> Marshal for [T] {
    fn xml_view(&self) -> View<'_> {
        seq_view(self)
    }
    fn xml_type_string(&self) -> String {
        seq_type_string::<T>("[]")
    }
}

impl<T: Marshal, const N: usize> Marshal for [T; N] {
    fn xml_view(&self) -> View<'_> {
        seq_view(self)
    }
    fn xml_type_string(&self) -> String {
        seq_type_string::<T>(&format!("[{N}]"))
    }
    fn xml_elem_type_string() -> String {
        seq_type_string::<T>(&format!("[{N}]"))
    }
}

impl<K: Marshal, V: Marshal, S> Marshal for HashMap<K, V, S> {
    fn xml_view(&self) -> View<'_> {
        View::Map { len: self.len() }
    }
    fn xml_type_string(&self) -> String {
        format!(
            "map[{}]{}",
            K::xml_elem_type_string(),
            V::xml_elem_type_string()
        )
    }
}

impl<K: Marshal, V: Marshal> Marshal for BTreeMap<K, V> {
    fn xml_view(&self) -> View<'_> {
        View::Map { len: self.len() }
    }
    fn xml_type_string(&self) -> String {
        format!(
            "map[{}]{}",
            K::xml_elem_type_string(),
            V::xml_elem_type_string()
        )
    }
}

static NAME_SPEC: StructSpec = StructSpec {
    name: "Name",
    type_string: "xml.Name",
    fields: &[],
};

fn string_spec() -> Option<&'static StructSpec> {
    None
}

fn name_spec() -> Option<&'static StructSpec> {
    None
}

pub(super) static ATTR_SPEC: StructSpec = StructSpec {
    name: "Attr",
    type_string: "xml.Attr",
    fields: &[
        FieldSpec {
            name: "Name",
            tag: "",
            anonymous: false,
            type_string: "xml.Name",
            type_spec: name_spec,
        },
        FieldSpec {
            name: "Value",
            tag: "",
            anonymous: false,
            type_string: "string",
            type_spec: string_spec,
        },
    ],
};

/// Go treats `xml.Name` as a struct without fields (`getTypeInfo` skips it).
impl Marshal for Name {
    fn xml_view(&self) -> View<'_> {
        View::Struct(&NAME_SPEC)
    }
    fn xml_type_name(&self) -> &'static str {
        "Name"
    }
    fn xml_type_string(&self) -> String {
        "xml.Name".into()
    }
    fn xml_elem_type_string() -> String {
        "xml.Name".into()
    }
    fn xml_as_name(&self) -> Option<&Name> {
        Some(self)
    }
}

impl Marshal for Attr {
    fn xml_view(&self) -> View<'_> {
        View::Struct(&ATTR_SPEC)
    }
    fn xml_type_name(&self) -> &'static str {
        "Attr"
    }
    fn xml_type_string(&self) -> String {
        "xml.Attr".into()
    }
    fn xml_elem_type_string() -> String {
        "xml.Attr".into()
    }
    fn xml_field(&self, i: usize) -> Option<&dyn Marshal> {
        match i {
            0 => Some(&self.name),
            1 => Some(&self.value),
            _ => None,
        }
    }
    fn xml_as_attr(&self) -> Option<&Attr> {
        Some(self)
    }
}
