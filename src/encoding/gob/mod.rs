//! Go's `encoding/gob`: a self-describing binary encoding of typed values,
//! byte-identical with Go's for the same values and registrations.
//!
//! Go reads the shape of a value with reflection; here the shape comes from
//! [`crate::reflect`]: any type that implements [`Reflect`]
//! (`#[derive(Reflect)]` from `rust-stdlib-derive`, or the implementations for
//! the standard types) can be encoded and decoded. Struct fields are sent by
//! name when they are exported, interface values (a [`reflect::Value`](crate::reflect::Value) field,
//! Go's `any`) carry the name of a type registered with [`register`] or
//! [`register_name`], and pointers are flattened as in Go.
//!
//! ```
//! use rust_stdlib::encoding::gob::{Decoder, Encoder};
//! use std::collections::BTreeMap;
//! use std::sync::{Arc, Mutex};
//!
//! #[derive(Clone, Default)]
//! struct Shared(Arc<Mutex<Vec<u8>>>);
//! impl std::io::Write for Shared {
//!     fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
//!         self.0.lock().unwrap().extend_from_slice(b);
//!         Ok(b.len())
//!     }
//!     fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
//! }
//!
//! let wire = Shared::default();
//! let enc = Encoder::new(wire.clone());
//! let mut m = BTreeMap::new();
//! m.insert("a".to_string(), vec![1i64, 2, 3]);
//! enc.encode(&m)?;
//!
//! let bytes = wire.0.lock().unwrap().clone();
//! let dec = Decoder::new(std::io::Cursor::new(bytes));
//! let mut out: BTreeMap<String, Vec<i64>> = BTreeMap::new();
//! dec.decode(&mut out)?;
//! assert_eq!(out, m);
//! # Ok::<(), std::io::Error>(())
//! ```
//!
//! # Deviations from Go
//!
//! - `Encode(e any)` and `Decode(e any)` take any [`Reflect`]
//!   type (`encode`, `decode`); `decode` copies the value in, decodes through a
//!   pointer and copies it back (so, as in Go, fields absent from the stream
//!   keep their old values). `EncodeValue`/`DecodeValue` take a
//!   [`reflect::Value`](crate::reflect::Value); `Decode(nil)` is [`Decoder::decode_discard`].
//! - Errors are `std::io::Error`; Go's `io.EOF` and `io.ErrUnexpectedEOF` are
//!   the sentinels of [`crate::io`].
//! - A type provides `GobEncode`/`GobDecode` (or `MarshalBinary`/
//!   `UnmarshalBinary`) by registering methods of those names with
//!   `#[reflect_methods]`, returning `(Vec<u8>, Result<(), String>)` and
//!   `Result<(), String>`; [`GobEncoder`] and [`GobDecoder`] spell the same
//!   contract as traits, with the same method names.
//! - Go's map iteration order is random, so streams with more than one map
//!   entry are not byte-for-byte reproducible even in Go; here the order is
//!   the reflect map's.
//! - `NewDecoder` wraps a reader that is not an `io.ByteReader` in a
//!   `bufio.Reader`; [`Decoder::new`] always buffers and
//!   [`Decoder::from_byte_reader`] never does.

use crate::reflect::{Reflect, Value};

mod decode;
mod encode;
mod types;
mod wire;

pub use decode::Decoder;
pub use encode::Encoder;
pub use wire::CommonType;

pub(crate) use encode::error_text;

/// Go `isExported` for a name (the first rune is upper case).
pub(crate) fn is_exported_name(name: &str) -> bool {
    types::is_exported(name)
}

/// Go `gob.GobEncoder`: data that provides its own representation for
/// encoding values for transmission to a [`GobDecoder`].
///
/// A type that implements `GobEncoder` and `GobDecoder` has complete control
/// over the representation of its data and may therefore contain things such
/// as private fields, channels, and functions, which are not usually
/// transmissible in gob streams.
///
/// Gob finds the method by reflection, as Go does, so the signature is the one
/// `#[reflect_methods]` registers (the Go result pair `([]byte, error)` is a
/// tuple whose error is `Result<(), String>`): put the method in a
/// `#[reflect_methods]` impl block, either of this trait or, for a type that
/// is also a [`GobDecoder`] (a type can register one impl block), of the type.
///
/// ```ignore
/// #[reflect_methods]
/// impl Temp {
///     pub fn GobEncode(&self) -> (Vec<u8>, Result<(), String>) { /* ... */ }
///     pub fn GobDecode(&mut self, data: &[u8]) -> Result<(), String> { /* ... */ }
/// }
/// ```
#[allow(non_snake_case)]
pub trait GobEncoder {
    /// Go `GobEncode`: the encoding of the receiver for transmission to a
    /// [`GobDecoder`], usually of the same concrete type.
    fn GobEncode(&self) -> (Vec<u8>, Result<(), String>);
}

/// Go `gob.GobDecoder`: data that provides its own routine for decoding
/// values sent by a [`GobEncoder`]. See [`GobEncoder`] for how a type takes
/// part.
#[allow(non_snake_case)]
pub trait GobDecoder {
    /// Go `GobDecode`: overwrites the receiver with the value represented by
    /// the byte slice, which was written by `GobEncode`, usually for the same
    /// concrete type.
    fn GobDecode(&mut self, data: &[u8]) -> Result<(), String>;
}

/// Go `gob.Register`: records a type, identified by a value for that type,
/// under its internal type name. That name will identify the concrete type of
/// a value sent or received as an interface variable. Only types that will be
/// transferred as implementations of interface values need to be registered.
/// Expecting to be used only during initialization, it panics if the mapping
/// between types and names is not a bijection.
///
/// A pointer type is registered by passing an `Option<T>` (Go's `*T`).
pub fn register<T: Reflect>(value: &T) {
    register_value(&value.to_value());
}

/// Go `gob.Register` for a [`reflect::Value`](crate::reflect::Value); the
/// registered type is the value's type.
pub fn register_value(value: &Value) {
    types::register_type(&value.type_());
}

/// Go `gob.RegisterName`: like [`register`] but uses the provided name rather
/// than the type's default.
pub fn register_name<T: Reflect>(name: &str, value: &T) {
    register_name_value(name, &value.to_value());
}

/// Go `gob.RegisterName` for a [`reflect::Value`](crate::reflect::Value).
pub fn register_name_value(name: &str, value: &Value) {
    types::register_type_name(name, &value.type_());
}

#[cfg(test)]
mod tests {
    //! `type_test.go`: the type descriptors and their printed forms.
    use super::types::{
        get_type_info, table, user_type, T_BOOL, T_BYTES, T_FLOAT, T_INT, T_STRING, T_UINT,
    };
    use crate::reflect::{self, Kind, StructField, Type};

    fn id_of(t: &Type) -> i32 {
        let ut = user_type(t).expect("user type");
        get_type_info(&ut).expect("type info").id
    }

    fn string_of(t: &Type) -> String {
        let id = id_of(t);
        table().id_string(id)
    }

    #[test]
    fn basic_types() {
        for (id, s) in [
            (T_BOOL, "bool"),
            (T_INT, "int"),
            (T_UINT, "uint"),
            (T_FLOAT, "float"),
            (T_BYTES, "bytes"),
            (T_STRING, "string"),
        ] {
            assert_eq!(table().id_string(id), s);
        }
        // The predefined wire types come right after the reserved ids.
        for (id, name) in [
            (16, "wireType"),
            (17, "arrayType"),
            (18, "CommonType"),
            (19, "sliceType"),
            (20, "structType"),
            (21, "fieldType"),
            (23, "mapType"),
        ] {
            let s = table().id_string(id);
            assert_eq!(s.split(' ').next(), Some(name), "{s}");
        }
    }

    #[test]
    fn reregistration_is_idempotent() {
        let int = Type::basic(Kind::Int);
        assert_eq!(id_of(&int), T_INT);
        assert_eq!(id_of(&Type::basic(Kind::Uint)), T_UINT);
        assert_eq!(id_of(&Type::basic(Kind::String)), T_STRING);
    }

    #[test]
    fn array_slice_and_map_types() {
        let (int, boolean) = (Type::basic(Kind::Int), Type::basic(Kind::Bool));
        let a3 = reflect::array_of(3, &int);
        let a4 = reflect::array_of(4, &int);
        assert_eq!(id_of(&a3), id_of(&a3));
        assert_ne!(id_of(&a3), id_of(&a4));
        assert_eq!(string_of(&reflect::array_of(3, &boolean)), "[3]bool");
        let s = reflect::slice_of(&int);
        assert_ne!(id_of(&s), id_of(&reflect::slice_of(&boolean)));
        assert_eq!(string_of(&reflect::slice_of(&boolean)), "[]bool");
        let string = Type::basic(Kind::String);
        let m = reflect::map_of(&string, &int);
        assert_ne!(id_of(&m), id_of(&reflect::map_of(&string, &boolean)));
        assert_eq!(
            string_of(&reflect::map_of(&string, &boolean)),
            "map[string]bool"
        );
    }

    #[test]
    fn struct_type_prints_like_go() {
        let b = Type::basic;
        let ptr = |t: &Type| reflect::pointer_to(t);
        let bar = Type::named(
            "encoding/gob",
            "Bar",
            &reflect::struct_of(&[StructField::new("X", b(Kind::String))]),
            Vec::new(),
        );
        let f = b(Kind::Float64);
        let foo = Type::named(
            "encoding/gob",
            "Foo",
            &reflect::struct_of(&[
                StructField::new("A", b(Kind::Int)),
                StructField::new("B", b(Kind::Int32)),
                StructField::new("C", b(Kind::String)),
                StructField::new("D", reflect::slice_of(&b(Kind::Uint8))),
                StructField::new("E", ptr(&f)),
                StructField::new("F", ptr(&ptr(&ptr(&ptr(&f))))),
                StructField::new("G", ptr(&bar)),
                StructField::new("H", ptr(&bar)),
            ]),
            Vec::new(),
        );
        assert_eq!(
            string_of(&foo),
            "Foo = struct { A int; B int; C string; D bytes; E float; F float; G Bar = struct { X string; }; H Bar; }"
        );
    }
}
