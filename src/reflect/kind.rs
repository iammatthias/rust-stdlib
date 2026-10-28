//! Kinds, channel directions, select directions and `ValueError`.

use std::fmt;

/// A Go `reflect.Kind`: the specific kind of a [`Type`](super::Type) or
/// [`Value`](super::Value). The zero kind, [`Kind::Invalid`], is not a valid
/// kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum Kind {
    #[default]
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

#[allow(non_upper_case_globals)]
impl Kind {
    /// The old name for [`Kind::Pointer`] (Go `reflect.Ptr`, deprecated).
    pub const Ptr: Kind = Kind::Pointer;

    const NAMES: [&'static str; 27] = [
        "invalid",
        "bool",
        "int",
        "int8",
        "int16",
        "int32",
        "int64",
        "uint",
        "uint8",
        "uint16",
        "uint32",
        "uint64",
        "uintptr",
        "float32",
        "float64",
        "complex64",
        "complex128",
        "array",
        "chan",
        "func",
        "interface",
        "map",
        "ptr",
        "slice",
        "string",
        "struct",
        "unsafe.Pointer",
    ];

    pub(crate) fn name(self) -> &'static str {
        Kind::NAMES[self as usize]
    }

    /// Builds a kind from Go's numeric value. `Kind(n)` of an unknown `n` has
    /// no variant, so `None` is returned (Go prints it as `kind` plus `n`).
    pub fn from_u8(n: u8) -> Option<Kind> {
        const ALL: [Kind; 27] = [
            Kind::Invalid,
            Kind::Bool,
            Kind::Int,
            Kind::Int8,
            Kind::Int16,
            Kind::Int32,
            Kind::Int64,
            Kind::Uint,
            Kind::Uint8,
            Kind::Uint16,
            Kind::Uint32,
            Kind::Uint64,
            Kind::Uintptr,
            Kind::Float32,
            Kind::Float64,
            Kind::Complex64,
            Kind::Complex128,
            Kind::Array,
            Kind::Chan,
            Kind::Func,
            Kind::Interface,
            Kind::Map,
            Kind::Pointer,
            Kind::Slice,
            Kind::String,
            Kind::Struct,
            Kind::UnsafePointer,
        ];
        ALL.get(n as usize).copied()
    }

    pub(crate) fn is_int(self) -> bool {
        matches!(
            self,
            Kind::Int | Kind::Int8 | Kind::Int16 | Kind::Int32 | Kind::Int64
        )
    }

    pub(crate) fn is_uint(self) -> bool {
        matches!(
            self,
            Kind::Uint | Kind::Uint8 | Kind::Uint16 | Kind::Uint32 | Kind::Uint64 | Kind::Uintptr
        )
    }

    pub(crate) fn is_float(self) -> bool {
        matches!(self, Kind::Float32 | Kind::Float64)
    }

    pub(crate) fn is_complex(self) -> bool {
        matches!(self, Kind::Complex64 | Kind::Complex128)
    }
}

/// The name of the kind, such as `"ptr"` (Go `Kind.String`).
impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A channel type's direction (Go `reflect.ChanDir`). The numeric values are
/// Go's: receive is 1, send is 2 and both is 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum ChanDir {
    /// `<-chan` (Go `RecvDir`).
    Recv = 1,
    /// `chan<-` (Go `SendDir`).
    Send = 2,
    /// `chan` (Go `BothDir`).
    Both = 3,
}

impl ChanDir {
    pub(crate) fn can_recv(self) -> bool {
        self as i32 & 1 != 0
    }

    pub(crate) fn can_send(self) -> bool {
        self as i32 & 2 != 0
    }
}

/// Go `ChanDir.String`.
impl fmt::Display for ChanDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ChanDir::Send => "chan<-",
            ChanDir::Recv => "<-chan",
            ChanDir::Both => "chan",
        })
    }
}

/// The direction of a [`SelectCase`](super::SelectCase) (Go `reflect.SelectDir`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SelectDir {
    /// A send case (Go `SelectSend`).
    Send = 1,
    /// A receive case (Go `SelectRecv`).
    Recv = 2,
    /// The default case (Go `SelectDefault`).
    Default = 3,
}

/// Go's `*ValueError`: a `Value` method was used on a `Value` of the wrong
/// kind. Like Go, the methods panic with this value
/// (`std::panic::panic_any`), so `catch_unwind` payloads can be downcast to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValueError {
    /// The name of the method, such as `"reflect.Value.Int"`.
    pub method: String,
    /// The kind of the `Value` the method was called on.
    pub kind: Kind,
}

impl ValueError {
    /// Go `ValueError.Error`.
    pub fn error(&self) -> String {
        if self.kind == Kind::Invalid {
            format!("reflect: call of {} on zero Value", self.method)
        } else {
            format!("reflect: call of {} on {} Value", self.method, self.kind)
        }
    }
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.error())
    }
}

impl std::error::Error for ValueError {}

/// Panics with Go's `*ValueError`.
pub(crate) fn value_error(method: &str, kind: Kind) -> ! {
    std::panic::panic_any(ValueError {
        method: method.to_string(),
        kind,
    })
}
