//! Go's `reflect` package, built on opt-in static type information.
//!
//! Rust has no run-time reflection, so a type takes part by implementing
//! [`Reflect`]: `#[derive(Reflect)]` from `rust-stdlib-derive` writes the
//! implementation for structs and unit-only enums, `#[reflect_methods]`
//! registers the methods of an `impl` block, and this module implements it for
//! the primitives, `String`, `Vec`, arrays, maps, `Option` (as a pointer),
//! `Box`/`Rc`/`Arc` (transparent) and tuples. [`Type`] and [`Value`] then behave as Go's do:
//! [`Type`] describes a Go type (with Go's `String()`, struct tags, method
//! sets, `Implements`, `AssignableTo`, `ConvertibleTo`, Go's amd64 layout for
//! `Size`/`Align`/`Offset`), and [`Value`] reads and writes data with Go's
//! addressability and `CanSet` rules, calls functions and methods, converts
//! between kinds, and works with maps, slices and channels.
//!
//! ```
//! use rust_stdlib::reflect::{self, Kind, Reflect};
//!
//! let v = vec![1i32, 2, 3].to_value();
//! assert_eq!(v.type_().to_string(), "[]int32");
//! assert_eq!(v.kind(), Kind::Slice);
//! assert_eq!(v.index(1).int(), 2);
//!
//! // Rust data is copied in: edit() copies it in, runs the closure on a
//! // pointer value, and copies the result back out.
//! let mut x = 41i64;
//! reflect::edit(&mut x, |p| p.elem().set_int(42))?;
//! assert_eq!(x, 42);
//! # Ok::<(), reflect::Error>(())
//! ```
//!
//! # Deviations from Go
//!
//! - Values are copies in a dynamic store. A [`Value`] made by
//!   [`Reflect::to_value`] never aliases the Rust variable it came from;
//!   [`edit`] is the copy-in/copy-out idiom for `ValueOf(&x).Elem().Set(...)`.
//! - `Value::pointer`, `unsafe_addr` and friends return identity numbers, not
//!   machine addresses, and `value_at`/`slice_at` accept only an
//!   [`UnsafePointer`] obtained from this package.
//! - `make_func` produces function values that can be called through
//!   [`Value::call`] but cannot be converted back to a Rust `fn`.
//! - Methods panic where Go's do; misuse of a kind panics with a
//!   [`ValueError`] payload (`std::panic::panic_any`).
//! - `Value::bytes` returns a copy rather than an alias.
//! - `Size`, `Align`, `Offset` report Go's layout for the corresponding Go
//!   type, not Rust's `size_of`.

/// A sequence of values (Go's `iter.Seq`); any `Iterator` is one.
pub type Seq<'a, V> = Box<dyn Iterator<Item = V> + 'a>;

mod data;
mod deep;
mod interop;
mod kind;
mod tag;
mod traits;
mod typ;
mod value;

pub use data::UnsafePointer;
pub use deep::{deep_equal, deep_equal_values, visible_fields};
pub use kind::{ChanDir, Kind, SelectDir, ValueError};
pub use tag::StructTag;
pub use traits::{func, func_variadic, ArgList, Multi, One, Reflect, ReflectType, RetList};
pub use typ::{
    array_of, chan_of, func_of, interface_of, map_of, pointer_to, ptr_to, slice_of, struct_of,
    Method, MethodDef, StructField, Type,
};
pub use value::{
    append, append_slice, copy, indirect, make_chan, make_func, make_map, make_map_with_size,
    make_slice, new, select, slice_at, swapper, type_assert, value_at, zero, MapIter, SelectCase,
    Value,
};

#[doc(hidden)]
pub use traits::private as __private;

use std::fmt;

/// An error from the fallible parts of this package (`from_value`,
/// `field_by_index_err`, `edit`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    message: String,
}

impl Error {
    pub(crate) fn new(message: impl Into<String>) -> Error {
        Error {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// Go `reflect.TypeOf`: the type of a value.
pub fn type_of<T: Reflect>(_x: &T) -> Type {
    T::reflect_type()
}

/// Go `reflect.TypeFor`: the type of `T`, which may be a `dyn Trait` registered
/// with `#[reflect_trait]`.
pub fn type_for<T: ReflectType + ?Sized>() -> Type {
    T::reflect_type()
}

/// Go `reflect.ValueOf`: a copy of `x` in the dynamic store.
pub fn value_of<T: Reflect>(x: &T) -> Value {
    x.to_value()
}

/// Copies `x` into an addressable variable, runs `f` with a pointer `Value`
/// to it (Go's `ValueOf(&x)`), then copies the result back into `x`. This is
/// how writes made through `Value::set_*` reach a Rust variable.
pub fn edit<T: Reflect, R>(x: &mut T, f: impl FnOnce(&Value) -> R) -> Result<R, Error> {
    let p = new(&T::reflect_type());
    p.elem().overwrite(&x.to_value());
    let r = f(&p);
    *x = T::from_value(&p.elem())?;
    Ok(r)
}

/// The runtime representation of a string (Go `reflect.StringHeader`,
/// deprecated). Rust strings have no such header; the type exists for source
/// compatibility only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StringHeader {
    /// The address of the data.
    pub data: usize,
    /// The length in bytes.
    pub len: isize,
}

/// The runtime representation of a slice (Go `reflect.SliceHeader`,
/// deprecated). Rust slices have no such header; the type exists for source
/// compatibility only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SliceHeader {
    /// The address of the data.
    pub data: usize,
    /// The length.
    pub len: isize,
    /// The capacity.
    pub cap: isize,
}
