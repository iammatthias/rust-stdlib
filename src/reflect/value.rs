//! `Value`: a typed handle on a piece of (copied) Rust data.
//!
//! A `Value` is a type, a place in shared storage and a few flags (addressable,
//! obtained through an unexported field). Reading goes through the place;
//! writing is allowed only when Go would allow it (`can_set`). Because Rust
//! data is copied in by [`Reflect::to_value`](super::Reflect::to_value),
//! writes never reach the original Rust variable by themselves; see
//! [`edit`](super::edit) for the copy-in/copy-out helper.

use std::fmt;
use std::sync::Arc;

use super::data::{
    data_eq, hash_data, lock, run_select, str_data, zero_data, CaseOp, Chan, Data, FuncImpl,
    MapData, Place, SelCase, SliceH, UnsafePointer,
};
use super::kind::{value_error, ChanDir, Kind, SelectDir};
use super::typ::{
    convert_op, directly_assignable, func_of, implements, pointer_to, slice_of, Body, ConvOp,
    StructField, Type,
};
use super::Error;
use super::Seq;
use crate::strconv::Complex;

const ADDR: u8 = 1;
const STICKY_RO: u8 = 2;
const EMBED_RO: u8 = 4;
const RO: u8 = STICKY_RO | EMBED_RO;

/// The reflection interface to a value (Go `reflect.Value`).
///
/// Cloning is cheap and clones share storage, like copies of a Go `Value`.
/// The default `Value` is the invalid zero value. Methods panic exactly where
/// Go's do; kind mismatches panic with a [`ValueError`](super::ValueError).
#[derive(Clone, Default)]
pub struct Value {
    pub(crate) ty: Option<Type>,
    pub(crate) place: Option<Place>,
    pub(crate) flag: u8,
}

pub(crate) fn panic_msg(msg: impl Into<String>) -> ! {
    let m: String = msg.into();
    panic!("{m}")
}

fn wrap_int(k: Kind, x: i64) -> i64 {
    match k {
        Kind::Int8 => x as i8 as i64,
        Kind::Int16 => x as i16 as i64,
        Kind::Int32 => x as i32 as i64,
        _ => x,
    }
}

fn wrap_uint(k: Kind, x: u64) -> u64 {
    match k {
        Kind::Uint8 => x as u8 as u64,
        Kind::Uint16 => x as u16 as u64,
        Kind::Uint32 => x as u32 as u64,
        _ => x,
    }
}

fn round_float(k: Kind, x: f64) -> f64 {
    if k == Kind::Float32 {
        x as f32 as f64
    } else {
        x
    }
}

fn round_complex(k: Kind, re: f64, im: f64) -> (f64, f64) {
    if k == Kind::Complex64 {
        (re as f32 as f64, im as f32 as f64)
    } else {
        (re, im)
    }
}

fn ro_of(flag: u8) -> u8 {
    if flag & RO != 0 {
        STICKY_RO
    } else {
        0
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.ty {
            None => f.write_str("<invalid Value>"),
            Some(t) => write!(f, "{}({})", t, super::interop::debug_text(self)),
        }
    }
}

// ---------------------------------------------------------------------------
// Internal construction and access.

impl Value {
    pub(crate) fn mk(ty: Type, data: Data, flag: u8) -> Value {
        Value {
            ty: Some(ty),
            place: Some(Place::new(data)),
            flag,
        }
    }

    pub(crate) fn at(ty: Type, place: Place, flag: u8) -> Value {
        Value {
            ty: Some(ty),
            place: Some(place),
            flag,
        }
    }

    pub(crate) fn typ(&self) -> &Type {
        match &self.ty {
            Some(t) => t,
            None => panic_msg("reflect: use of invalid Value"),
        }
    }

    pub(crate) fn pl(&self) -> &Place {
        match &self.place {
            Some(p) => p,
            None => panic_msg("reflect: use of invalid Value"),
        }
    }

    pub(crate) fn data(&self) -> Data {
        self.pl().read()
    }

    fn must_be(&self, method: &str, k: Kind) {
        if self.kind() != k {
            value_error(method, self.kind());
        }
    }

    fn must_be_exported(&self, method: &str) {
        if self.ty.is_none() {
            value_error(method, Kind::Invalid);
        }
        if self.flag & RO != 0 {
            panic_msg(format!(
                "reflect: {method} using value obtained using unexported field"
            ));
        }
    }

    fn must_be_assignable(&self, method: &str) {
        if self.ty.is_none() {
            value_error(method, Kind::Invalid);
        }
        if self.flag & RO != 0 {
            panic_msg(format!(
                "reflect: {method} using value obtained using unexported field"
            ));
        }
        if self.flag & ADDR == 0 {
            panic_msg(format!("reflect: {method} using unaddressable value"));
        }
    }

    // Typed scalar accessors without kind checks.

    fn raw_int(&self) -> i64 {
        self.pl().with(|d| match d {
            Data::Int(i) => *i,
            _ => 0,
        })
    }

    fn raw_uint(&self) -> u64 {
        self.pl().with(|d| match d {
            Data::Uint(i) => *i,
            _ => 0,
        })
    }

    fn raw_float(&self) -> f64 {
        self.pl().with(|d| match d {
            Data::Float(i) => *i,
            _ => 0.0,
        })
    }

    fn raw_complex(&self) -> (f64, f64) {
        self.pl().with(|d| match d {
            Data::Complex(a, b) => (*a, *b),
            _ => (0.0, 0.0),
        })
    }

    fn raw_str(&self) -> Arc<[u8]> {
        self.pl().with(|d| match d {
            Data::Str(s) => s.clone(),
            _ => Arc::from(Vec::new()),
        })
    }

    fn slice_h(&self) -> SliceH {
        self.pl().with(|d| match d {
            Data::Slice(h) => h.clone(),
            _ => SliceH::nil(),
        })
    }

    fn write(&self, d: Data) {
        self.pl().write(d);
    }

    // Constructors used by the Reflect implementations and the derive.

    /// A non-addressable `bool` value of type `t`.
    #[doc(hidden)]
    pub fn from_bool(t: &Type, b: bool) -> Value {
        Value::mk(t.clone(), Data::Bool(b), 0)
    }

    /// A signed integer value of type `t`, wrapped to the type's size.
    #[doc(hidden)]
    pub fn from_int(t: &Type, x: i64) -> Value {
        Value::mk(t.clone(), Data::Int(wrap_int(t.kind(), x)), 0)
    }

    /// An unsigned integer value of type `t`, wrapped to the type's size.
    #[doc(hidden)]
    pub fn from_uint(t: &Type, x: u64) -> Value {
        Value::mk(t.clone(), Data::Uint(wrap_uint(t.kind(), x)), 0)
    }

    /// A floating-point value of type `t`.
    #[doc(hidden)]
    pub fn from_float(t: &Type, x: f64) -> Value {
        Value::mk(t.clone(), Data::Float(round_float(t.kind(), x)), 0)
    }

    /// A complex value of type `t`.
    #[doc(hidden)]
    pub fn from_complex(t: &Type, c: Complex) -> Value {
        let (re, im) = round_complex(t.kind(), c.re, c.im);
        Value::mk(t.clone(), Data::Complex(re, im), 0)
    }

    /// A string value of type `t` from bytes.
    #[doc(hidden)]
    pub fn from_string(t: &Type, s: impl AsRef<[u8]>) -> Value {
        Value::mk(t.clone(), str_data(s.as_ref()), 0)
    }

    /// A struct or array value of type `t` from its field/element values.
    #[doc(hidden)]
    pub fn from_parts(t: &Type, parts: &[Value]) -> Value {
        Value::mk(
            t.clone(),
            Data::Agg(parts.iter().map(|p| p.data()).collect()),
            0,
        )
    }

    /// A slice value of type `t` holding `items`.
    #[doc(hidden)]
    pub fn from_items(t: &Type, items: &[Value]) -> Value {
        let n = items.len();
        let buf = Place::new(Data::Agg(items.iter().map(|p| p.data()).collect()));
        Value::mk(
            t.clone(),
            Data::Slice(SliceH {
                buf: Some(buf),
                off: 0,
                len: n,
                cap: n,
            }),
            0,
        )
    }

    /// A map value of type `t` holding `entries`.
    #[doc(hidden)]
    pub fn from_entries(t: &Type, entries: &[(Value, Value)]) -> Value {
        let m = make_map(t);
        for (k, v) in entries {
            m.set_map_index(k, v);
        }
        m
    }

    /// A pointer value of type `t` to a copy of `target` (a nil pointer when
    /// `target` is `None`).
    #[doc(hidden)]
    pub fn from_pointer(t: &Type, target: Option<&Value>) -> Value {
        match target {
            None => Value::mk(t.clone(), Data::Ptr(None), 0),
            Some(v) => Value::mk(t.clone(), Data::Ptr(Some(Place::new(v.data()))), 0),
        }
    }

    /// An interface-typed value of type `t` holding `inner` (nil when
    /// `inner` is invalid).
    #[doc(hidden)]
    pub fn from_interface(t: &Type, inner: &Value) -> Value {
        if !inner.is_valid() {
            return Value::mk(t.clone(), Data::Iface(None), 0);
        }
        if inner.kind() == Kind::Interface {
            return Value::mk(t.clone(), inner.data(), 0);
        }
        Value::mk(
            t.clone(),
            Data::Iface(Some(Box::new((inner.typ().clone(), inner.data())))),
            0,
        )
    }

    /// An `unsafe.Pointer` value.
    #[doc(hidden)]
    pub fn from_unsafe_pointer(p: &UnsafePointer) -> Value {
        Value::mk(Type::basic(Kind::UnsafePointer), Data::UPtr(p.clone()), 0)
    }

    /// Replaces the contents with those of `x`, ignoring `can_set` (the
    /// caller owns the value).
    #[doc(hidden)]
    pub fn overwrite(&self, x: &Value) {
        self.write(x.data());
    }

    /// The dereferenced target of a pointer value as a plain value, or `None`
    /// for a nil pointer.
    #[doc(hidden)]
    pub fn pointee(&self) -> Option<Value> {
        let t = self.typ();
        // Read the pointer first: the target may live in the same cell.
        match self.data() {
            Data::Ptr(Some(p)) => Some(Value::mk(t.elem(), p.read(), 0)),
            _ => None,
        }
    }

    /// The elements of a slice or array value as plain values.
    #[doc(hidden)]
    pub fn items(&self) -> Vec<Value> {
        (0..self.len()).map(|i| self.index(i).detach()).collect()
    }

    /// The entries of a map value as plain values.
    #[doc(hidden)]
    pub fn entries(&self) -> Vec<(Value, Value)> {
        let t = self.typ().clone();
        let (kt, et) = (t.key(), t.elem());
        let snapshot: Vec<(Data, Data)> = match self.data() {
            Data::Map(Some(m)) => lock(&m)
                .entries
                .iter()
                .map(|(_, k, v)| (k.clone(), v.clone()))
                .collect(),
            _ => Vec::new(),
        };
        snapshot
            .into_iter()
            .map(|(k, v)| (Value::mk(kt.clone(), k, 0), Value::mk(et.clone(), v, 0)))
            .collect()
    }

    /// The i'th field of a struct value as a plain value.
    #[doc(hidden)]
    pub fn part(&self, i: usize) -> Value {
        self.field(i).detach()
    }

    /// A copy that is neither addressable nor read-only.
    pub(crate) fn detach(&self) -> Value {
        Value::mk(self.typ().clone(), self.data(), 0)
    }

    /// The value inside an interface, or the value itself.
    #[doc(hidden)]
    pub fn dynamic(&self) -> Value {
        if self.kind() == Kind::Interface {
            self.elem()
        } else {
            self.clone()
        }
    }
}

// ---------------------------------------------------------------------------
// Value methods.

impl Value {
    /// Go `Value.Addr`: a pointer to `self`, which must be addressable.
    pub fn addr(&self) -> Value {
        if self.flag & ADDR == 0 {
            panic_msg("reflect.Value.Addr of unaddressable value");
        }
        Value::mk(
            pointer_to(self.typ()),
            Data::Ptr(Some(self.pl().clone())),
            self.flag & RO,
        )
    }

    /// Go `Value.Bool`.
    pub fn bool(&self) -> bool {
        if self.kind() != Kind::Bool {
            value_error("reflect.Value.Bool", self.kind());
        }
        self.pl().with(|d| matches!(d, Data::Bool(true)))
    }

    /// Go `Value.Bytes`: a copy of a byte slice or addressable byte array. Go
    /// returns an alias of the storage; use [`Value::set_bytes`] or `index` to
    /// write.
    pub fn bytes(&self) -> Vec<u8> {
        match self.kind() {
            Kind::Slice => {
                if self.typ().elem().kind() != Kind::Uint8 {
                    panic_msg("reflect.Value.Bytes of non-byte slice");
                }
                self.slice_bytes()
            }
            Kind::Array => {
                if self.typ().elem().kind() != Kind::Uint8 {
                    panic_msg("reflect.Value.Bytes of non-byte array");
                }
                if !self.can_addr() {
                    panic_msg("reflect.Value.Bytes of unaddressable byte array");
                }
                self.slice_bytes()
            }
            k => value_error("reflect.Value.Bytes", k),
        }
    }

    fn slice_bytes(&self) -> Vec<u8> {
        match self.data() {
            Data::Slice(h) => match &h.buf {
                None => Vec::new(),
                Some(b) => b.with(|d| match d {
                    Data::Agg(v) => v[h.off..h.off + h.len]
                        .iter()
                        .map(|x| match x {
                            Data::Uint(u) => *u as u8,
                            _ => 0,
                        })
                        .collect(),
                    _ => Vec::new(),
                }),
            },
            Data::Agg(v) => v
                .iter()
                .map(|x| match x {
                    Data::Uint(u) => *u as u8,
                    _ => 0,
                })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn runes(&self) -> Vec<i32> {
        self.must_be("reflect.Value.runes", Kind::Slice);
        if self.typ().elem().kind() != Kind::Int32 {
            panic_msg("reflect.Value.Bytes of non-rune slice");
        }
        match self.data() {
            Data::Slice(h) => match &h.buf {
                None => Vec::new(),
                Some(b) => b.with(|d| match d {
                    Data::Agg(v) => v[h.off..h.off + h.len]
                        .iter()
                        .map(|x| match x {
                            Data::Int(i) => *i as i32,
                            _ => 0,
                        })
                        .collect(),
                    _ => Vec::new(),
                }),
            },
            _ => Vec::new(),
        }
    }

    /// Go `Value.CanAddr`.
    pub fn can_addr(&self) -> bool {
        self.flag & ADDR != 0
    }

    /// Go `Value.CanSet`: addressable and not obtained through an unexported
    /// field.
    pub fn can_set(&self) -> bool {
        self.flag & (ADDR | RO) == ADDR
    }

    /// Go `Value.CanInterface`.
    pub fn can_interface(&self) -> bool {
        if self.ty.is_none() {
            value_error("reflect.Value.CanInterface", Kind::Invalid);
        }
        self.flag & RO == 0
    }

    /// Go `Value.CanInt`.
    pub fn can_int(&self) -> bool {
        self.kind().is_int()
    }

    /// Go `Value.CanUint`.
    pub fn can_uint(&self) -> bool {
        self.kind().is_uint()
    }

    /// Go `Value.CanFloat`.
    pub fn can_float(&self) -> bool {
        self.kind().is_float()
    }

    /// Go `Value.CanComplex`.
    pub fn can_complex(&self) -> bool {
        self.kind().is_complex()
    }

    /// Go `Value.Cap`.
    pub fn cap(&self) -> usize {
        match self.kind() {
            Kind::Slice => self.slice_h().cap,
            Kind::Array => self.typ().len(),
            Kind::Chan => match self.data() {
                Data::Chan(Some(c)) => c.cap,
                _ => 0,
            },
            Kind::Pointer => {
                if self.typ().elem().kind() == Kind::Array {
                    return self.typ().elem().len();
                }
                panic_msg("reflect: call of reflect.Value.Cap on ptr to non-array Value")
            }
            k => value_error("reflect.Value.Cap", k),
        }
    }

    /// Go `Value.Clear`: zeroes the elements of a slice or empties a map.
    pub fn clear(&self) {
        match self.kind() {
            Kind::Slice => {
                let et = self.typ().elem();
                let h = self.slice_h();
                if let Some(b) = &h.buf {
                    b.with_mut(|d| {
                        if let Data::Agg(v) = d {
                            for x in &mut v[h.off..h.off + h.len] {
                                *x = zero_data(&et);
                            }
                        }
                    });
                }
            }
            Kind::Map => {
                if let Data::Map(Some(m)) = self.data() {
                    lock(&m).entries.clear();
                }
            }
            k => value_error("reflect.Value.Clear", k),
        }
    }

    /// Go `Value.Close`.
    pub fn close(&self) {
        self.must_be("reflect.Value.Close", Kind::Chan);
        self.must_be_exported("reflect.Value.Close");
        if !self.typ().chan_dir().can_send() {
            panic_msg("reflect: close of receive-only channel");
        }
        match self.data() {
            Data::Chan(Some(c)) => c.close(),
            _ => panic_msg("close of nil channel"),
        }
    }

    /// Go `Value.Complex`.
    pub fn complex(&self) -> Complex {
        if !self.kind().is_complex() {
            value_error("reflect.Value.Complex", self.kind());
        }
        let (re, im) = self.raw_complex();
        Complex { re, im }
    }

    /// Go `Value.Elem`: the value an interface holds or a pointer points to.
    /// It returns the invalid value for a nil interface or pointer.
    pub fn elem(&self) -> Value {
        match self.kind() {
            Kind::Interface => match self.data() {
                Data::Iface(None) => Value::default(),
                Data::Iface(Some(b)) => {
                    let (t, d) = *b;
                    Value::mk(t, d, ro_of(self.flag))
                }
                _ => Value::default(),
            },
            Kind::Pointer => {
                let et = self.typ().elem();
                match self.data() {
                    Data::Ptr(Some(p)) => Value::at(et, p, (self.flag & RO) | ADDR),
                    _ => Value::default(),
                }
            }
            k => value_error("reflect.Value.Elem", k),
        }
    }

    /// Go `Value.Field`: the i'th field of a struct value.
    pub fn field(&self, i: usize) -> Value {
        if self.kind() != Kind::Struct {
            value_error("reflect.Value.Field", self.kind());
        }
        let t = self.typ();
        if i >= t.num_field() {
            panic_msg("reflect: Field index out of range");
        }
        let f = t.field(i);
        let mut fl = self.flag & (STICKY_RO | ADDR);
        if !f.is_exported() {
            fl |= if f.anonymous { EMBED_RO } else { STICKY_RO };
        }
        Value::at(f.type_, self.pl().child(i), fl)
    }

    /// Go `Value.FieldByIndex`.
    pub fn field_by_index(&self, index: &[usize]) -> Value {
        if index.len() == 1 {
            return self.field(index[0]);
        }
        self.must_be("reflect.Value.FieldByIndex", Kind::Struct);
        let mut v = self.clone();
        for (i, &x) in index.iter().enumerate() {
            if i > 0 && v.kind() == Kind::Pointer && v.typ().elem().kind() == Kind::Struct {
                if v.is_nil() {
                    panic_msg("reflect: indirection through nil pointer to embedded struct");
                }
                v = v.elem();
            }
            v = v.field(x);
        }
        v
    }

    /// Go `Value.FieldByIndexErr`: like [`Value::field_by_index`] but an error
    /// instead of a panic for a nil embedded pointer.
    pub fn field_by_index_err(&self, index: &[usize]) -> Result<Value, Error> {
        if index.len() == 1 {
            return Ok(self.field(index[0]));
        }
        self.must_be("reflect.Value.FieldByIndexErr", Kind::Struct);
        let mut v = self.clone();
        for (i, &x) in index.iter().enumerate() {
            if i > 0 && v.kind() == Kind::Pointer && v.typ().elem().kind() == Kind::Struct {
                if v.is_nil() {
                    return Err(Error::new(format!(
                        "reflect: indirection through nil pointer to embedded struct field {}",
                        v.typ().elem().name()
                    )));
                }
                v = v.elem();
            }
            v = v.field(x);
        }
        Ok(v)
    }

    /// Go `Value.FieldByName`: the invalid value if there is no such field.
    pub fn field_by_name(&self, name: &str) -> Value {
        self.must_be("reflect.Value.FieldByName", Kind::Struct);
        match self.typ().field_by_name(name) {
            Some(f) => self.field_by_index(&f.index),
            None => Value::default(),
        }
    }

    /// Go `Value.FieldByNameFunc`.
    pub fn field_by_name_func(&self, matches: impl FnMut(&str) -> bool) -> Value {
        match self.typ().field_by_name_func(matches) {
            Some(f) => self.field_by_index(&f.index),
            None => Value::default(),
        }
    }

    /// Go `Value.Fields`: each field of a struct value with its descriptor.
    pub fn fields(&self) -> Seq<'static, (StructField, Value)> {
        let t = self.typ().clone();
        if t.kind() != Kind::Struct {
            panic_msg(format!("reflect: Fields of non-struct type {t}"));
        }
        let v = self.clone();
        Box::new((0..self.num_field()).map(move |i| (t.field(i), v.field(i))))
    }

    /// Go `Value.Float`.
    pub fn float(&self) -> f64 {
        if !self.kind().is_float() {
            value_error("reflect.Value.Float", self.kind());
        }
        self.raw_float()
    }

    /// Go `Value.Index`.
    pub fn index(&self, i: usize) -> Value {
        match self.kind() {
            Kind::Array => {
                let t = self.typ();
                if i >= t.len() {
                    panic_msg("reflect: array index out of range");
                }
                Value::at(
                    t.elem(),
                    self.pl().child(i),
                    (self.flag & (ADDR | RO)) | ro_of(self.flag),
                )
            }
            Kind::Slice => {
                let h = self.slice_h();
                if i >= h.len {
                    panic_msg("reflect: slice index out of range");
                }
                let buf = h.buf.expect("non-empty slice has storage");
                Value::at(
                    self.typ().elem(),
                    buf.child(h.off + i),
                    ADDR | ro_of(self.flag),
                )
            }
            Kind::String => {
                let s = self.raw_str();
                if i >= s.len() {
                    panic_msg("reflect: string index out of range");
                }
                Value::mk(
                    Type::basic(Kind::Uint8),
                    Data::Uint(s[i] as u64),
                    ro_of(self.flag),
                )
            }
            k => value_error("reflect.Value.Index", k),
        }
    }

    /// Go `Value.Int`.
    pub fn int(&self) -> i64 {
        if !self.kind().is_int() {
            value_error("reflect.Value.Int", self.kind());
        }
        self.raw_int()
    }

    /// Go `Value.Interface`, typed: the value as Rust type `T`. It panics if
    /// the value was obtained through an unexported field or does not have
    /// the type of `T`.
    pub fn interface<T: super::Reflect>(&self) -> T {
        self.interface_check("reflect.Value.Interface");
        match self.try_interface::<T>() {
            Some(x) => x,
            None => {
                let dynamic = self.dynamic();
                if dynamic.is_valid() {
                    panic_msg(format!(
                        "interface conversion: interface {{}} is {}, not {}",
                        dynamic.type_(),
                        T::reflect_type()
                    ))
                }
                panic_msg(format!(
                    "interface conversion: interface is nil, not {}",
                    T::reflect_type()
                ))
            }
        }
    }

    /// Like [`Value::interface`] but `None` when the value does not have the
    /// type of `T`.
    pub fn try_interface<T: super::Reflect>(&self) -> Option<T> {
        self.interface_check("reflect.Value.Interface");
        let mut v = self.clone();
        if v.kind() == Kind::Interface && T::reflect_type().kind() != Kind::Interface {
            v = v.elem();
            if !v.is_valid() {
                return None;
            }
        }
        if v.typ() != &T::reflect_type() {
            return None;
        }
        T::from_value(&v).ok()
    }

    fn interface_check(&self, method: &str) {
        if self.ty.is_none() {
            value_error(method, Kind::Invalid);
        }
        if self.flag & RO != 0 {
            panic_msg(format!(
                "{method}: cannot return value obtained from unexported field or method"
            ));
        }
    }

    /// Go `Value.InterfaceData` (deprecated): the two words of an interface
    /// value. The words are the type's and data's identity, not machine
    /// pointers.
    pub fn interface_data(&self) -> [usize; 2] {
        self.must_be("reflect.Value.InterfaceData", Kind::Interface);
        match self.data() {
            Data::Iface(Some(b)) => [b.0.addr(), data_ident(&b.1)],
            _ => [0, 0],
        }
    }

    /// Go `Value.IsNil`.
    pub fn is_nil(&self) -> bool {
        match self.kind() {
            Kind::Chan
            | Kind::Func
            | Kind::Map
            | Kind::Pointer
            | Kind::UnsafePointer
            | Kind::Interface
            | Kind::Slice => self.pl().with(|d| match d {
                Data::Chan(c) => c.is_none(),
                Data::Func(f) => f.is_none(),
                Data::Map(m) => m.is_none(),
                Data::Ptr(p) => p.is_none(),
                Data::UPtr(p) => p.is_nil(),
                Data::Iface(i) => i.is_none(),
                Data::Slice(h) => h.buf.is_none(),
                _ => false,
            }),
            k => value_error("reflect.Value.IsNil", k),
        }
    }

    /// Go `Value.IsValid`.
    pub fn is_valid(&self) -> bool {
        self.ty.is_some()
    }

    /// Go `Value.IsZero`.
    pub fn is_zero(&self) -> bool {
        match self.kind() {
            Kind::Invalid => value_error("reflect.Value.IsZero", Kind::Invalid),
            _ => {
                let t = self.typ().clone();
                self.pl().with(|d| is_zero_data(&t, d))
            }
        }
    }

    /// Go `Value.SetZero`.
    pub fn set_zero(&self) {
        self.must_be_assignable("reflect.Value.SetZero");
        self.write(zero_data(self.typ()));
    }

    /// Go `Value.Kind`.
    pub fn kind(&self) -> Kind {
        match &self.ty {
            Some(t) => t.kind(),
            None => Kind::Invalid,
        }
    }

    /// Go `Value.Len`.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self.kind() {
            Kind::Slice => self.slice_h().len,
            Kind::Array => self.typ().len(),
            Kind::Chan => match self.data() {
                Data::Chan(Some(c)) => c.len(),
                _ => 0,
            },
            Kind::Map => match self.data() {
                Data::Map(Some(m)) => lock(&m).entries.len(),
                _ => 0,
            },
            Kind::String => self.raw_str().len(),
            Kind::Pointer => {
                if self.typ().elem().kind() == Kind::Array {
                    return self.typ().elem().len();
                }
                panic_msg("reflect: call of reflect.Value.Len on ptr to non-array Value")
            }
            k => value_error("reflect.Value.Len", k),
        }
    }

    /// Go `Value.MapIndex`: the value for `key`, or the invalid value.
    pub fn map_index(&self, key: &Value) -> Value {
        self.must_be("reflect.Value.MapIndex", Kind::Map);
        let t = self.typ().clone();
        let kt = t.key();
        let key = key.assign_to("reflect.Value.MapIndex", &kt);
        let kd = key.data();
        let found = match self.data() {
            Data::Map(Some(m)) => {
                let h = hash_data(&kt, &kd);
                let g = lock(&m);
                g.find(&kt, h, &kd).map(|i| g.entries[i].2.clone())
            }
            _ => None,
        };
        match found {
            Some(v) => Value::mk(t.elem(), v, ro_of(self.flag | key.flag)),
            None => Value::default(),
        }
    }

    /// Go `Value.MapKeys`: the keys, in insertion order (Go's order is
    /// unspecified).
    pub fn map_keys(&self) -> Vec<Value> {
        self.must_be("reflect.Value.MapKeys", Kind::Map);
        let kt = self.typ().key();
        let fl = ro_of(self.flag);
        match self.data() {
            Data::Map(Some(m)) => lock(&m)
                .entries
                .iter()
                .map(|(_, k, _)| Value::mk(kt.clone(), k.clone(), fl))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Go `Value.MapRange`.
    pub fn map_range(&self) -> MapIter {
        if self.kind() != Kind::Map {
            value_error("reflect.Value.MapRange", self.kind());
        }
        MapIter {
            m: self.clone(),
            keys: Vec::new(),
            pos: 0,
            started: false,
            cur: None,
        }
    }

    /// Go `Value.SetMapIndex`: sets the entry for `key`, or deletes it when
    /// `elem` is the invalid value.
    pub fn set_map_index(&self, key: &Value, elem: &Value) {
        self.must_be("reflect.Value.SetMapIndex", Kind::Map);
        self.must_be_exported("reflect.Value.SetMapIndex");
        key.must_be_exported("reflect.Value.SetMapIndex");
        let t = self.typ().clone();
        let kt = t.key();
        let key = key.assign_to("reflect.Value.SetMapIndex", &kt);
        let kd = key.data();
        let h = hash_data(&kt, &kd);
        let Data::Map(m) = self.data() else { return };
        if !elem.is_valid() {
            if let Some(m) = m {
                let mut g = lock(&m);
                if let Some(i) = g.find(&kt, h, &kd) {
                    g.entries.remove(i);
                }
            }
            return;
        }
        elem.must_be_exported("reflect.Value.SetMapIndex");
        let ed = elem
            .assign_to("reflect.Value.SetMapIndex", &t.elem())
            .data();
        let Some(m) = m else {
            panic_msg("assignment to entry in nil map");
        };
        let mut g = lock(&m);
        match g.find(&kt, h, &kd) {
            Some(i) => g.entries[i].2 = ed,
            None => g.entries.push((h, kd, ed)),
        }
    }

    /// Go `Value.SetIterKey`.
    pub fn set_iter_key(&self, iter: &MapIter) {
        let key = iter.cur_key("reflect: Value.SetIterKey");
        self.must_be_assignable("reflect.Value.SetIterKey");
        iter.m.must_be_exported("reflect.Value.SetIterKey");
        let x = key.assign_to("reflect.MapIter.SetKey", self.typ());
        self.write(x.data());
    }

    /// Go `Value.SetIterValue`.
    pub fn set_iter_value(&self, iter: &MapIter) {
        let val = iter.cur_value("reflect: Value.SetIterValue");
        self.must_be_assignable("reflect.Value.SetIterValue");
        iter.m.must_be_exported("reflect.Value.SetIterValue");
        let x = val.assign_to("reflect.MapIter.SetValue", self.typ());
        self.write(x.data());
    }

    /// Go `Value.NumField`.
    pub fn num_field(&self) -> usize {
        self.must_be("reflect.Value.NumField", Kind::Struct);
        self.typ().num_field()
    }

    /// Go `Value.NumMethod`.
    pub fn num_method(&self) -> usize {
        if self.ty.is_none() {
            value_error("reflect.Value.NumMethod", Kind::Invalid);
        }
        self.typ().num_method()
    }

    /// Go `Value.OverflowComplex`.
    pub fn overflow_complex(&self, x: Complex) -> bool {
        match self.kind() {
            Kind::Complex64 | Kind::Complex128 => self.typ().overflow_complex(x.re, x.im),
            k => value_error("reflect.Value.OverflowComplex", k),
        }
    }

    /// Go `Value.OverflowFloat`.
    pub fn overflow_float(&self, x: f64) -> bool {
        match self.kind() {
            Kind::Float32 | Kind::Float64 => self.typ().overflow_float(x),
            k => value_error("reflect.Value.OverflowFloat", k),
        }
    }

    /// Go `Value.OverflowInt`.
    pub fn overflow_int(&self, x: i64) -> bool {
        if self.kind().is_int() {
            return self.typ().overflow_int(x);
        }
        value_error("reflect.Value.OverflowInt", self.kind())
    }

    /// Go `Value.OverflowUint`.
    pub fn overflow_uint(&self, x: u64) -> bool {
        if self.kind().is_uint() {
            return self.typ().overflow_uint(x);
        }
        value_error("reflect.Value.OverflowUint", self.kind())
    }

    /// Go `Value.Pointer`: an identity number for a pointer, channel, map,
    /// function, slice or string. It is not a machine address.
    pub fn pointer(&self) -> usize {
        match self.kind() {
            Kind::Pointer
            | Kind::Chan
            | Kind::Map
            | Kind::UnsafePointer
            | Kind::Func
            | Kind::Slice
            | Kind::String => self.data_pointer(),
            k => value_error("reflect.Value.Pointer", k),
        }
    }

    fn data_pointer(&self) -> usize {
        let esize = |t: &Type| t.elem().size().max(1);
        match self.data() {
            Data::Ptr(p) => p.map_or(0, |p| p.addr()),
            Data::Chan(c) => c.map_or(0, |c| Arc::as_ptr(&c) as usize),
            Data::Map(m) => m.map_or(0, |m| Arc::as_ptr(&m) as usize),
            Data::Func(f) => f.map_or(0, |f| Arc::as_ptr(&f) as *const () as usize),
            Data::UPtr(p) => p.addr(),
            Data::Slice(h) => h.buf.map_or(0, |b| b.addr() + h.off * esize(self.typ())),
            Data::Str(s) => {
                if s.is_empty() {
                    0
                } else {
                    s.as_ptr() as usize
                }
            }
            _ => 0,
        }
    }

    /// Go `Value.UnsafePointer`.
    pub fn unsafe_pointer(&self) -> UnsafePointer {
        match self.kind() {
            Kind::Pointer => match self.data() {
                Data::Ptr(p) => UnsafePointer { place: p, raw: 0 },
                _ => UnsafePointer::nil(),
            },
            Kind::UnsafePointer => match self.data() {
                Data::UPtr(p) => p,
                _ => UnsafePointer::nil(),
            },
            Kind::Slice => {
                let h = self.slice_h();
                match h.buf {
                    Some(b) => UnsafePointer {
                        place: Some(b.child(h.off)),
                        raw: 0,
                    },
                    None => UnsafePointer::nil(),
                }
            }
            Kind::Chan | Kind::Map | Kind::Func | Kind::String => UnsafePointer {
                place: None,
                raw: self.data_pointer(),
            },
            k => value_error("reflect.Value.UnsafePointer", k),
        }
    }

    /// Go `Value.UnsafeAddr`.
    pub fn unsafe_addr(&self) -> usize {
        if self.ty.is_none() {
            value_error("reflect.Value.UnsafeAddr", Kind::Invalid);
        }
        if self.flag & ADDR == 0 {
            panic_msg("reflect.Value.UnsafeAddr of unaddressable value");
        }
        self.pl().addr()
    }

    /// Go `Value.SetPointer`.
    pub fn set_pointer(&self, x: &UnsafePointer) {
        self.must_be_assignable("reflect.Value.SetPointer");
        self.must_be("reflect.Value.SetPointer", Kind::UnsafePointer);
        self.write(Data::UPtr(x.clone()));
    }

    /// Go `Value.Recv`: receives from a channel, blocking. The boolean is
    /// false when the channel is closed and drained.
    pub fn recv(&self) -> (Value, bool) {
        self.must_be("reflect.Value.Recv", Kind::Chan);
        self.must_be_exported("reflect.Value.Recv");
        self.recv_impl(false)
    }

    /// Go `Value.TryRecv`: a non-blocking receive. The returned value is
    /// invalid when nothing is ready.
    pub fn try_recv(&self) -> (Value, bool) {
        self.must_be("reflect.Value.TryRecv", Kind::Chan);
        self.must_be_exported("reflect.Value.TryRecv");
        self.recv_impl(true)
    }

    fn recv_impl(&self, nb: bool) -> (Value, bool) {
        let t = self.typ().clone();
        if !t.chan_dir().can_recv() {
            panic_msg("reflect: recv on send-only channel");
        }
        let et = t.elem();
        let ch = match self.data() {
            Data::Chan(c) => c,
            _ => None,
        };
        let mut cases = [SelCase {
            chan: ch,
            op: CaseOp::Recv,
        }];
        match run_select(&mut cases, nb) {
            None => (Value::default(), false),
            Some(sel) => match sel.recv {
                Some(Some(d)) => (Value::mk(et, d, 0), true),
                _ => (Value::mk(et.clone(), zero_data(&et), 0), false),
            },
        }
    }

    /// Go `Value.Send`.
    pub fn send(&self, x: &Value) {
        self.must_be("reflect.Value.Send", Kind::Chan);
        self.must_be_exported("reflect.Value.Send");
        self.send_impl(x, false);
    }

    /// Go `Value.TrySend`: a non-blocking send; false when it would block.
    pub fn try_send(&self, x: &Value) -> bool {
        self.must_be("reflect.Value.TrySend", Kind::Chan);
        self.must_be_exported("reflect.Value.TrySend");
        self.send_impl(x, true)
    }

    fn send_impl(&self, x: &Value, nb: bool) -> bool {
        let t = self.typ().clone();
        if !t.chan_dir().can_send() {
            panic_msg("reflect: send on recv-only channel");
        }
        x.must_be_exported("reflect.Value.Send");
        let x = x.assign_to("reflect.Value.Send", &t.elem());
        let ch = match self.data() {
            Data::Chan(c) => c,
            _ => None,
        };
        let mut cases = [SelCase {
            chan: ch,
            op: CaseOp::Send(x.data()),
        }];
        run_select(&mut cases, nb).is_some()
    }

    /// Go `Value.Set`: assigns `x` to the value, which must be settable.
    pub fn set(&self, x: &Value) {
        self.must_be_assignable("reflect.Value.Set");
        x.must_be_exported("reflect.Value.Set");
        let x = x.assign_to("reflect.Set", self.typ());
        self.write(x.data());
    }

    /// Go `Value.SetBool`.
    pub fn set_bool(&self, x: bool) {
        self.must_be_assignable("reflect.Value.SetBool");
        self.must_be("reflect.Value.SetBool", Kind::Bool);
        self.write(Data::Bool(x));
    }

    /// Go `Value.SetBytes`.
    pub fn set_bytes(&self, x: &[u8]) {
        self.must_be_assignable("reflect.Value.SetBytes");
        self.must_be("reflect.Value.SetBytes", Kind::Slice);
        if self.typ().elem().kind() != Kind::Uint8 {
            panic_msg("reflect.Value.SetBytes of non-byte slice");
        }
        let items: Vec<Data> = x.iter().map(|&b| Data::Uint(b as u64)).collect();
        let n = items.len();
        self.write(Data::Slice(SliceH {
            buf: Some(Place::new(Data::Agg(items))),
            off: 0,
            len: n,
            cap: n,
        }));
    }

    fn set_runes(&self, x: &[i32]) {
        let items: Vec<Data> = x.iter().map(|&b| Data::Int(b as i64)).collect();
        let n = items.len();
        self.write(Data::Slice(SliceH {
            buf: Some(Place::new(Data::Agg(items))),
            off: 0,
            len: n,
            cap: n,
        }));
    }

    /// Go `Value.SetComplex`.
    pub fn set_complex(&self, x: Complex) {
        self.must_be_assignable("reflect.Value.SetComplex");
        if !self.kind().is_complex() {
            value_error("reflect.Value.SetComplex", self.kind());
        }
        let (re, im) = round_complex(self.kind(), x.re, x.im);
        self.write(Data::Complex(re, im));
    }

    /// Go `Value.SetFloat`.
    pub fn set_float(&self, x: f64) {
        self.must_be_assignable("reflect.Value.SetFloat");
        if !self.kind().is_float() {
            value_error("reflect.Value.SetFloat", self.kind());
        }
        self.write(Data::Float(round_float(self.kind(), x)));
    }

    /// Go `Value.SetInt`.
    pub fn set_int(&self, x: i64) {
        self.must_be_assignable("reflect.Value.SetInt");
        if !self.kind().is_int() {
            value_error("reflect.Value.SetInt", self.kind());
        }
        self.write(Data::Int(wrap_int(self.kind(), x)));
    }

    /// Go `Value.SetUint`.
    pub fn set_uint(&self, x: u64) {
        self.must_be_assignable("reflect.Value.SetUint");
        if !self.kind().is_uint() {
            value_error("reflect.Value.SetUint", self.kind());
        }
        self.write(Data::Uint(wrap_uint(self.kind(), x)));
    }

    /// Go `Value.SetString`.
    pub fn set_string(&self, x: impl AsRef<[u8]>) {
        self.must_be_assignable("reflect.Value.SetString");
        self.must_be("reflect.Value.SetString", Kind::String);
        self.write(str_data(x.as_ref()));
    }

    /// Go `Value.SetLen`.
    pub fn set_len(&self, n: isize) {
        self.must_be_assignable("reflect.Value.SetLen");
        self.must_be("reflect.Value.SetLen", Kind::Slice);
        let cap = self.slice_h().cap;
        if n < 0 || n as usize > cap {
            panic_msg("reflect: slice length out of range in SetLen");
        }
        self.pl().with_mut(|d| {
            if let Data::Slice(h) = d {
                h.len = n as usize;
            }
        });
    }

    /// Go `Value.SetCap`.
    pub fn set_cap(&self, n: isize) {
        self.must_be_assignable("reflect.Value.SetCap");
        self.must_be("reflect.Value.SetCap", Kind::Slice);
        let h = self.slice_h();
        if n < h.len as isize || n > h.cap as isize {
            panic_msg("reflect: slice capacity out of range in SetCap");
        }
        self.pl().with_mut(|d| {
            if let Data::Slice(h) = d {
                h.cap = n as usize;
            }
        });
    }

    /// Go `Value.Grow`: ensures room for `n` more elements.
    pub fn grow(&self, n: isize) {
        self.must_be_assignable("reflect.Value.Grow");
        self.must_be("reflect.Value.Grow", Kind::Slice);
        self.grow_impl(n);
    }

    fn grow_impl(&self, n: isize) {
        if n < 0 {
            panic_msg("reflect.Value.Grow: negative len");
        }
        let h = self.slice_h();
        let n = n as usize;
        if h.len + n > h.cap {
            let et = self.typ().elem();
            let nh = grow_slice(&et, &h, n);
            self.write(Data::Slice(nh));
        }
    }

    /// Go `Value.Slice`.
    pub fn slice(&self, i: isize, j: isize) -> Value {
        let (cap, base_off, buf, st): (usize, usize, Option<Place>, Type) = match self.kind() {
            Kind::Array => {
                if self.flag & ADDR == 0 {
                    panic_msg("reflect.Value.Slice: slice of unaddressable array");
                }
                let t = self.typ();
                (t.len(), 0, Some(self.pl().clone()), slice_of(&t.elem()))
            }
            Kind::Slice => {
                let h = self.slice_h();
                (h.cap, h.off, h.buf, self.typ().clone())
            }
            Kind::String => {
                let s = self.raw_str();
                if i < 0 || j < i || j as usize > s.len() {
                    panic_msg("reflect.Value.Slice: string slice index out of bounds");
                }
                return Value::mk(
                    self.typ().clone(),
                    str_data(&s[i as usize..j as usize]),
                    self.flag & RO,
                );
            }
            k => value_error("reflect.Value.Slice", k),
        };
        if i < 0 || j < i || j as usize > cap {
            panic_msg("reflect.Value.Slice: slice index out of bounds");
        }
        let (i, j) = (i as usize, j as usize);
        Value::mk(
            st,
            Data::Slice(SliceH {
                buf,
                // Like Go, an empty-capacity result keeps the base pointer.
                off: if cap > i { base_off + i } else { base_off },
                len: j - i,
                cap: cap - i,
            }),
            ro_of(self.flag),
        )
    }

    /// Go `Value.Slice3`.
    pub fn slice3(&self, i: isize, j: isize, k: isize) -> Value {
        let (cap, base_off, buf, st): (usize, usize, Option<Place>, Type) = match self.kind() {
            Kind::Array => {
                if self.flag & ADDR == 0 {
                    panic_msg("reflect.Value.Slice3: slice of unaddressable array");
                }
                let t = self.typ();
                (t.len(), 0, Some(self.pl().clone()), slice_of(&t.elem()))
            }
            Kind::Slice => {
                let h = self.slice_h();
                (h.cap, h.off, h.buf, self.typ().clone())
            }
            kind => value_error("reflect.Value.Slice3", kind),
        };
        if i < 0 || j < i || k < j || k as usize > cap {
            panic_msg("reflect.Value.Slice3: slice index out of bounds");
        }
        let (i, j, k) = (i as usize, j as usize, k as usize);
        Value::mk(
            st,
            Data::Slice(SliceH {
                buf,
                off: if k > i { base_off + i } else { base_off },
                len: j - i,
                cap: k - i,
            }),
            ro_of(self.flag),
        )
    }

    /// Go `Value.String`: the string a string value holds; for other kinds
    /// `<T Value>` (not an error), and `<invalid Value>` for the zero value.
    pub fn text(&self) -> String {
        match self.kind() {
            Kind::String => String::from_utf8_lossy(&self.raw_str()).into_owned(),
            Kind::Invalid => "<invalid Value>".to_string(),
            _ => format!("<{} Value>", self.typ()),
        }
    }

    /// The bytes of a string value (Go strings need not be valid UTF-8).
    pub fn string_bytes(&self) -> Vec<u8> {
        if self.kind() != Kind::String {
            value_error("reflect.Value.String", self.kind());
        }
        self.raw_str().to_vec()
    }

    /// Go `Value.Type`.
    pub fn type_(&self) -> Type {
        match &self.ty {
            Some(t) => t.clone(),
            None => value_error("reflect.Value.Type", Kind::Invalid),
        }
    }

    /// Go `Value.Uint`.
    pub fn uint(&self) -> u64 {
        if !self.kind().is_uint() {
            value_error("reflect.Value.Uint", self.kind());
        }
        self.raw_uint()
    }

    /// Go `Value.Comparable`: whether `equal` can compare the value without
    /// panicking.
    pub fn comparable(&self) -> bool {
        match self.kind() {
            Kind::Invalid => false,
            Kind::Array => {
                let et = self.typ().elem();
                match et.kind() {
                    Kind::Interface | Kind::Array | Kind::Struct => {
                        (0..self.typ().len()).all(|i| self.index(i).comparable())
                    }
                    _ => et.comparable() || self.typ().comparable(),
                }
            }
            Kind::Interface => self.is_nil() || self.elem().comparable(),
            Kind::Struct => self.fields().all(|(_, v)| v.comparable()),
            _ => self.typ().comparable(),
        }
    }

    /// Go `Value.Equal`: Go's `==` on two values, for comparable types.
    pub fn equal(&self, u: &Value) -> bool {
        let mut v = self.clone();
        let mut u = u.clone();
        if v.kind() == Kind::Interface {
            v = v.elem();
        }
        if u.kind() == Kind::Interface {
            u = u.elem();
        }
        if !v.is_valid() || !u.is_valid() {
            return v.is_valid() == u.is_valid();
        }
        if v.kind() != u.kind() || v.typ() != u.typ() {
            return false;
        }
        match v.kind() {
            Kind::Bool => v.bool() == u.bool(),
            k if k.is_int() => v.int() == u.int(),
            k if k.is_uint() => v.uint() == u.uint(),
            k if k.is_float() => v.float() == u.float(),
            k if k.is_complex() => v.complex() == u.complex(),
            Kind::String => v.raw_str() == u.raw_str(),
            Kind::Chan | Kind::Pointer | Kind::UnsafePointer => {
                data_eq(v.typ(), &v.data(), &u.data())
            }
            Kind::Array => {
                let vl = v.len();
                if vl == 0 {
                    if !v.typ().elem().comparable() {
                        panic_msg(format!(
                            "reflect.Value.Equal: values of type {} are not comparable",
                            v.typ()
                        ));
                    }
                    return true;
                }
                (0..vl).all(|i| v.index(i).equal(&u.index(i)))
            }
            Kind::Struct => (0..v.num_field()).all(|i| v.field(i).equal(&u.field(i))),
            Kind::Func | Kind::Map | Kind::Slice => panic_msg(format!(
                "reflect.Value.Equal: values of type {} are not comparable",
                v.typ()
            )),
            _ => panic_msg("reflect.Value.Equal: invalid Kind"),
        }
    }

    /// Go `Value.Convert`: the value converted to type `t`, with Go's rules
    /// for numeric wraparound, string and slice conversions.
    pub fn convert(&self, t: &Type) -> Value {
        if self.ty.is_none() {
            value_error("reflect.Value.Convert", Kind::Invalid);
        }
        match convert_op(t, self.typ()) {
            None => panic_msg(format!(
                "reflect.Value.Convert: value of type {} cannot be converted to type {}",
                self.typ(),
                t
            )),
            Some(op) => self.apply_conv(op, t),
        }
    }

    /// Go `Value.CanConvert`.
    pub fn can_convert(&self, t: &Type) -> bool {
        let vt = self.type_();
        if !vt.convertible_to(t) {
            return false;
        }
        match (vt.kind(), t.kind()) {
            (Kind::Slice, Kind::Array) => t.len() <= self.len(),
            (Kind::Slice, Kind::Pointer) if t.elem().kind() == Kind::Array => {
                t.elem().len() <= self.len()
            }
            _ => true,
        }
    }

    fn apply_conv(&self, op: ConvOp, t: &Type) -> Value {
        let fl = ro_of(self.flag);
        let tk = t.kind();
        let make = |d: Data| Value::mk(t.clone(), d, fl);
        match op {
            ConvOp::Int => {
                let x = self.raw_int();
                if tk.is_int() {
                    make(Data::Int(wrap_int(tk, x)))
                } else {
                    make(Data::Uint(wrap_uint(tk, x as u64)))
                }
            }
            ConvOp::Uint => {
                let x = self.raw_uint();
                if tk.is_int() {
                    make(Data::Int(wrap_int(tk, x as i64)))
                } else {
                    make(Data::Uint(wrap_uint(tk, x)))
                }
            }
            ConvOp::FloatInt => {
                let x = self.raw_float() as i64;
                make(Data::Int(wrap_int(tk, x)))
            }
            ConvOp::FloatUint => {
                let x = self.raw_float() as u64;
                make(Data::Uint(wrap_uint(tk, x)))
            }
            ConvOp::IntFloat => make(Data::Float(round_float(tk, self.raw_int() as f64))),
            ConvOp::UintFloat => make(Data::Float(round_float(tk, self.raw_uint() as f64))),
            ConvOp::Float => make(Data::Float(round_float(tk, self.raw_float()))),
            ConvOp::Complex => {
                let (re, im) = self.raw_complex();
                let (re, im) = round_complex(tk, re, im);
                make(Data::Complex(re, im))
            }
            ConvOp::IntString => {
                let x = self.raw_int();
                let s = if x == x as i32 as i64 {
                    rune_string(x as i32)
                } else {
                    "\u{FFFD}".to_string()
                };
                make(str_data(s.as_bytes()))
            }
            ConvOp::UintString => {
                let x = self.raw_uint();
                let s = if x <= i32::MAX as u64 {
                    rune_string(x as i32)
                } else {
                    "\u{FFFD}".to_string()
                };
                make(str_data(s.as_bytes()))
            }
            ConvOp::BytesString => make(str_data(&self.slice_bytes())),
            ConvOp::StringBytes => {
                let r = Value::mk(t.clone(), zero_data(t), fl);
                let items: Vec<Data> = self
                    .raw_str()
                    .iter()
                    .map(|&b| Data::Uint(b as u64))
                    .collect();
                let n = items.len();
                r.write(Data::Slice(SliceH {
                    buf: Some(Place::new(Data::Agg(items))),
                    off: 0,
                    len: n,
                    cap: n,
                }));
                r
            }
            ConvOp::RunesString => {
                let s: String = self.runes().iter().map(|&r| rune_string(r)).collect();
                make(str_data(s.as_bytes()))
            }
            ConvOp::StringRunes => {
                let r = Value::mk(t.clone(), zero_data(t), fl);
                r.set_runes(&decode_runes(&self.raw_str()));
                r
            }
            ConvOp::SliceArrayPtr => {
                let n = t.elem().len();
                if n > self.len() {
                    panic_msg(format!(
                        "reflect: cannot convert slice with length {} to pointer to array with length {}",
                        self.len(),
                        n
                    ));
                }
                let h = self.slice_h();
                let items: Vec<Data> = match &h.buf {
                    Some(b) => b.with(|d| match d {
                        Data::Agg(v) => v[h.off..h.off + n].to_vec(),
                        _ => Vec::new(),
                    }),
                    None => Vec::new(),
                };
                make(Data::Ptr(Some(Place::new(Data::Agg(items)))))
            }
            ConvOp::SliceArray => {
                let n = t.len();
                if n > self.len() {
                    panic_msg(format!(
                        "reflect: cannot convert slice with length {} to array with length {}",
                        self.len(),
                        n
                    ));
                }
                let h = self.slice_h();
                let items: Vec<Data> = match &h.buf {
                    Some(b) => b.with(|d| match d {
                        Data::Agg(v) => v[h.off..h.off + n].to_vec(),
                        _ => Vec::new(),
                    }),
                    None => Vec::new(),
                };
                make(Data::Agg(items))
            }
            ConvOp::Direct => make(self.data()),
            ConvOp::ToInterface => make(Data::Iface(Some(Box::new((
                self.typ().clone(),
                self.data(),
            ))))),
            ConvOp::InterfaceToInterface => {
                if self.is_nil() {
                    make(zero_data(t))
                } else {
                    make(self.data())
                }
            }
        }
    }

    /// Converts the value for assignment to type `dst`, or panics with Go's
    /// message.
    pub(crate) fn assign_to(&self, context: &str, dst: &Type) -> Value {
        if self.ty.is_none() {
            value_error(context, Kind::Invalid);
        }
        let st = self.typ();
        if directly_assignable(dst, st) {
            return Value::mk(dst.clone(), self.data(), self.flag & RO);
        }
        if implements(dst, st) {
            if self.kind() == Kind::Interface && self.is_nil() {
                return Value::mk(dst.clone(), Data::Iface(None), self.flag & RO);
            }
            let d = if self.kind() == Kind::Interface {
                self.data()
            } else {
                Data::Iface(Some(Box::new((st.clone(), self.data()))))
            };
            return Value::mk(dst.clone(), d, self.flag & RO);
        }
        panic_msg(format!(
            "{context}: value of type {st} is not assignable to type {dst}"
        ))
    }
}

fn rune_string(r: i32) -> String {
    u32::try_from(r)
        .ok()
        .and_then(char::from_u32)
        .unwrap_or('\u{FFFD}')
        .to_string()
}

/// Decodes bytes as Go's `[]rune(s)` does: each invalid byte is U+FFFD.
fn decode_runes(b: &[u8]) -> Vec<i32> {
    let mut out = Vec::new();
    let mut rest = b;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.extend(s.chars().map(|c| c as i32));
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                out.extend(String::from_utf8_lossy(good).chars().map(|c| c as i32));
                out.push(0xFFFD);
                let skip = e.error_len().unwrap_or(bad.len());
                // Go decodes each byte of an invalid sequence separately.
                out.extend(std::iter::repeat_n(0xFFFD, skip - 1));
                rest = &bad[skip..];
            }
        }
    }
    out
}

fn data_ident(d: &Data) -> usize {
    match d {
        Data::Ptr(Some(p)) => p.addr(),
        Data::Map(Some(m)) => Arc::as_ptr(m) as usize,
        Data::Chan(Some(c)) => Arc::as_ptr(c) as usize,
        Data::Func(Some(f)) => Arc::as_ptr(f) as *const () as usize,
        _ => 0,
    }
}

pub(crate) fn is_zero_data(t: &Type, d: &Data) -> bool {
    match d {
        Data::Bool(b) => !*b,
        Data::Int(i) => *i == 0,
        Data::Uint(u) => *u == 0,
        Data::Float(f) => *f == 0.0,
        Data::Complex(a, b) => *a == 0.0 && *b == 0.0,
        Data::Str(s) => s.is_empty(),
        Data::Agg(v) => match t.body() {
            Body::Array { elem, .. } => v.iter().all(|x| is_zero_data(elem, x)),
            Body::Struct { fields, .. } => v
                .iter()
                .zip(fields.iter())
                .all(|(x, f)| f.name == "_" || is_zero_data(&f.type_, x)),
            _ => false,
        },
        Data::Slice(h) => h.buf.is_none(),
        Data::Map(m) => m.is_none(),
        Data::Ptr(p) => p.is_none(),
        Data::Chan(c) => c.is_none(),
        Data::Func(f) => f.is_none(),
        Data::Iface(i) => i.is_none(),
        Data::UPtr(p) => p.is_nil(),
    }
}

/// The amd64 malloc size classes (`internal/runtime/gc.SizeClassToSize`).
const SIZE_CLASSES: [usize; 68] = [
    0, 8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240, 256, 288, 320,
    352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024, 1152, 1280, 1408, 1536, 1792,
    2048, 2304, 2688, 3072, 3200, 3456, 4096, 4864, 5376, 6144, 6528, 6784, 6912, 8192, 9472, 9728,
    10240, 10880, 12288, 13568, 14336, 16384, 18432, 19072, 20480, 21760, 24576, 27264, 28672,
    32768,
];

/// Whether a value of type `t` contains pointers (Go's `PtrBytes != 0`).
fn type_has_pointers(t: &Type) -> bool {
    match t.kind() {
        Kind::Chan
        | Kind::Func
        | Kind::Interface
        | Kind::Map
        | Kind::Pointer
        | Kind::Slice
        | Kind::String
        | Kind::UnsafePointer => true,
        Kind::Array => t.len() > 0 && type_has_pointers(&t.elem()),
        Kind::Struct => (0..t.num_field()).any(|i| type_has_pointers(&t.field(i).type_)),
        _ => false,
    }
}

/// Go's runtime `roundupsize`: the usable size of the block `mallocgc`
/// allocates for `size` bytes (64-bit, 8 KiB pages, 8-byte malloc header).
fn roundup_size(size: usize, noscan: bool) -> usize {
    const MAX_SMALL_SIZE: usize = 32768;
    const MALLOC_HEADER_SIZE: usize = 8;
    const MIN_SIZE_FOR_MALLOC_HEADER: usize = 512;
    const PAGE_SIZE: usize = 8192;
    let mut req = size;
    if req <= MAX_SMALL_SIZE - MALLOC_HEADER_SIZE {
        if !noscan && req > MIN_SIZE_FOR_MALLOC_HEADER {
            req += MALLOC_HEADER_SIZE;
        }
        let class = SIZE_CLASSES.partition_point(|&c| c < req);
        return SIZE_CLASSES[class] - (req - size);
    }
    match req.checked_add(PAGE_SIZE - 1) {
        Some(r) => r & !(PAGE_SIZE - 1),
        None => size,
    }
}

/// Go's `growslice` capacity rule, including malloc size-class rounding.
fn grow_slice(et: &Type, h: &SliceH, extra: usize) -> SliceH {
    let need = h.len + extra;
    let old = h.cap;
    let mut newcap = old;
    let double = old + old;
    if need > double {
        newcap = need;
    } else {
        const THRESHOLD: usize = 256;
        if old < THRESHOLD {
            newcap = double;
        } else {
            while newcap < need {
                newcap += (newcap + 3 * THRESHOLD) >> 2;
            }
        }
    }
    let newcap = newcap.max(need);
    let esize = et.size();
    let newcap = roundup_size(newcap * esize, !type_has_pointers(et))
        .checked_div(esize)
        .unwrap_or(need);
    let mut items: Vec<Data> = match &h.buf {
        Some(b) => b.with(|d| match d {
            Data::Agg(v) => v[h.off..h.off + h.len].to_vec(),
            _ => Vec::new(),
        }),
        None => Vec::new(),
    };
    items.resize_with(newcap, || zero_data(et));
    SliceH {
        buf: Some(Place::new(Data::Agg(items))),
        off: 0,
        len: h.len,
        cap: newcap,
    }
}

// ---------------------------------------------------------------------------
// Calls and methods.

impl Value {
    /// Go `Value.Call`: calls the function value with the given arguments.
    pub fn call(&self, in_: &[Value]) -> Vec<Value> {
        self.must_be("reflect.Value.Call", Kind::Func);
        self.must_be_exported("reflect.Value.Call");
        self.call_impl("Call", in_)
    }

    /// Go `Value.CallSlice`: calls a variadic function with the final argument
    /// as the variadic slice.
    pub fn call_slice(&self, in_: &[Value]) -> Vec<Value> {
        self.must_be("reflect.Value.CallSlice", Kind::Func);
        self.must_be_exported("reflect.Value.CallSlice");
        self.call_impl("CallSlice", in_)
    }

    fn call_impl(&self, op: &str, in_: &[Value]) -> Vec<Value> {
        let t = self.typ().clone();
        let f: FuncImpl = match self.data() {
            Data::Func(Some(f)) => f,
            _ => panic_msg("reflect.Value.Call: call of nil function"),
        };
        let (ins, outs, variadic) = t.func_parts();
        let is_slice = op == "CallSlice";
        let mut n = ins.len();
        if is_slice {
            if !variadic {
                panic_msg("reflect: CallSlice of non-variadic function");
            }
            if in_.len() < n {
                panic_msg("reflect: CallSlice with too few input arguments");
            }
            if in_.len() > n {
                panic_msg("reflect: CallSlice with too many input arguments");
            }
        } else {
            if variadic {
                n -= 1;
            }
            if in_.len() < n {
                panic_msg("reflect: Call with too few input arguments");
            }
            if !variadic && in_.len() > n {
                panic_msg("reflect: Call with too many input arguments");
            }
        }
        for x in in_ {
            if x.kind() == Kind::Invalid {
                panic_msg(format!("reflect: {op} using zero Value argument"));
            }
        }
        for i in 0..n {
            let xt = in_[i].typ();
            if !xt.assignable_to(&ins[i]) {
                panic_msg(format!("reflect: {op} using {xt} as type {}", ins[i]));
            }
        }
        let mut args: Vec<Value> = Vec::with_capacity(ins.len());
        if !is_slice && variadic {
            let m = in_.len() - n;
            let slice = make_slice(&ins[n], m as isize, m as isize);
            let elem = ins[n].elem();
            for i in 0..m {
                let x = &in_[n + i];
                let xt = x.typ();
                if !xt.assignable_to(&elem) {
                    panic_msg(format!("reflect: cannot use {xt} as type {elem} in {op}"));
                }
                slice.index(i).set(x);
            }
            for x in &in_[..n] {
                args.push(x.clone());
            }
            args.push(slice);
        } else {
            args.extend(in_.iter().cloned());
        }
        for (i, a) in args.iter_mut().enumerate() {
            a.must_be_exported("reflect.Value.Call");
            *a = a.assign_to("reflect.Value.Call", &ins[i]);
        }
        let res = f(&args);
        if res.len() != outs.len() {
            panic_msg("reflect: wrong return count from function");
        }
        res.into_iter()
            .zip(outs)
            .map(|(r, ot)| {
                if !r.is_valid() {
                    panic_msg("reflect: function returned zero Value");
                }
                r.assign_to("reflect.Value.Call", ot).detach()
            })
            .collect()
    }

    /// Go `Value.Method`: the i'th method as a function value bound to this
    /// receiver.
    pub fn method(&self, i: usize) -> Value {
        if self.ty.is_none() {
            value_error("reflect.Value.Method", Kind::Invalid);
        }
        let t = self.typ().clone();
        let vis = t.visible_methods();
        if i >= vis.len() {
            panic_msg("reflect: Method index out of range");
        }
        if t.kind() == Kind::Interface && self.is_nil() {
            panic_msg("reflect: Method on nil interface value");
        }
        let set = t.method_set();
        let ty = set[vis[i]].ty.clone();
        let recv = self.clone();
        let idx = vis[i];
        let f: FuncImpl = Arc::new(move |args: &[Value]| invoke_method(&recv, idx, args));
        Value::mk(ty, Data::Func(Some(f)), ro_of(self.flag))
    }

    /// Go `Value.MethodByName`: the invalid value if there is no such method.
    pub fn method_by_name(&self, name: &str) -> Value {
        if self.ty.is_none() {
            value_error("reflect.Value.MethodByName", Kind::Invalid);
        }
        match self.typ().method_by_name(name) {
            Some(m) => self.method(m.index),
            None => Value::default(),
        }
    }

    /// Go `Value.Methods`: every method with its bound function value.
    pub fn methods(&self) -> Seq<'static, (super::Method, Value)> {
        let t = self.type_();
        let n = self.num_method();
        let v = self.clone();
        Box::new((0..n).map(move |i| (t.method(i), v.method(i))))
    }

    /// The function with the receiver as first argument, for `Type::method`.
    pub(crate) fn method_func(t: &Type, set_index: usize, mt: &Type) -> Value {
        let t = t.clone();
        let f: FuncImpl = Arc::new(move |args: &[Value]| {
            let recv = args[0].clone();
            invoke_method_on(&t, &recv, set_index, &args[1..])
        });
        Value::mk(mt.clone(), Data::Func(Some(f)), 0)
    }

    /// Go `reflect.MakeFunc`: a function value of type `typ` implemented by `f`.
    fn make_func_value(typ: &Type, f: FuncImpl) -> Value {
        Value::mk(typ.clone(), Data::Func(Some(f)), 0)
    }
}

fn invoke_method(recv: &Value, set_index: usize, args: &[Value]) -> Vec<Value> {
    invoke_method_on(recv.typ(), recv, set_index, args)
}

fn invoke_method_on(t: &Type, recv: &Value, set_index: usize, args: &[Value]) -> Vec<Value> {
    let recv = recv.assign_to("reflect.Value.Call", t);
    let set = t.method_set();
    let e = &set[set_index];
    let mut cur = recv.clone();
    for &idx in &e.path {
        if cur.kind() == Kind::Pointer {
            if cur.is_nil() {
                panic_msg("reflect: indirection through nil pointer to embedded struct");
            }
            cur = cur.elem();
        }
        cur = cur.field_unchecked(idx);
    }
    match &e.def {
        Some(def) => {
            if cur.kind() == Kind::Pointer && cur.is_nil() {
                panic_msg("reflect: indirection through nil pointer to embedded struct");
            }
            (def.call)(&cur, args)
        }
        None => {
            if cur.kind() == Kind::Pointer {
                cur = cur.elem();
            }
            if cur.kind() == Kind::Interface {
                if cur.is_nil() {
                    panic_msg("reflect: Method on nil interface value");
                }
                cur = cur.elem();
            }
            let mt = cur.typ().clone();
            match mt.method_by_name(&e.name) {
                Some(m) => {
                    let f = cur.method(m.index);
                    f.call(args)
                }
                None => panic_msg(format!("reflect: method {} not found", e.name)),
            }
        }
    }
}

impl Value {
    /// `Field` that ignores the read-only restriction, for method promotion.
    fn field_unchecked(&self, i: usize) -> Value {
        let f = self.typ().field(i);
        Value::at(f.type_, self.pl().child(i), self.flag & (ADDR | STICKY_RO))
    }
}

// ---------------------------------------------------------------------------
// MapIter.

/// An iterator over a map (Go `*reflect.MapIter`), created by
/// [`Value::map_range`].
pub struct MapIter {
    m: Value,
    keys: Vec<(Data, Data)>,
    pos: usize,
    started: bool,
    cur: Option<(Data, Data)>,
}

impl MapIter {
    /// Go `MapIter.Next`: advances the iterator and reports whether there is
    /// an entry.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> bool {
        if !self.m.is_valid() {
            panic_msg(
                "MapIter.Next called on an iterator that does not have an associated map Value",
            );
        }
        if !self.started {
            self.started = true;
            self.keys = match self.m.data() {
                Data::Map(Some(m)) => lock(&m)
                    .entries
                    .iter()
                    .map(|(_, k, v)| (k.clone(), v.clone()))
                    .collect(),
                _ => Vec::new(),
            };
            self.pos = 0;
        } else if self.cur.is_none() {
            panic_msg("MapIter.Next called on exhausted iterator");
        }
        let t = self.m.typ().clone();
        let kt = t.key();
        while self.pos < self.keys.len() {
            let (k, _) = self.keys[self.pos].clone();
            self.pos += 1;
            // Entries deleted since the iteration started are skipped.
            let live = match self.m.data() {
                Data::Map(Some(m)) => {
                    let h = hash_data(&kt, &k);
                    let g = lock(&m);
                    g.find(&kt, h, &k).map(|i| g.entries[i].2.clone())
                }
                _ => None,
            };
            if let Some(v) = live {
                self.cur = Some((k, v));
                return true;
            }
        }
        self.cur = None;
        false
    }

    fn cur_key(&self, what: &str) -> Value {
        if !self.started {
            panic_msg(format!("{what} called before Next"));
        }
        match &self.cur {
            None => panic_msg(format!("{what} called on exhausted iterator")),
            Some((k, _)) => Value::mk(self.m.typ().key(), k.clone(), ro_of(self.m.flag)),
        }
    }

    fn cur_value(&self, what: &str) -> Value {
        if !self.started {
            panic_msg(format!("{what} called before Next"));
        }
        match &self.cur {
            None => panic_msg(format!("{what} called on exhausted iterator")),
            Some((_, v)) => Value::mk(self.m.typ().elem(), v.clone(), ro_of(self.m.flag)),
        }
    }

    /// Go `MapIter.Key`.
    pub fn key(&self) -> Value {
        self.cur_key("MapIter.Key")
    }

    /// Go `MapIter.Value`.
    pub fn value(&self) -> Value {
        self.cur_value("MapIter.Value")
    }

    /// Go `MapIter.Reset`: points the iterator at map `v` (or detaches it when
    /// `v` is invalid).
    pub fn reset(&mut self, v: &Value) {
        if v.is_valid() {
            v.must_be("reflect.MapIter.Reset", Kind::Map);
        }
        self.m = v.clone();
        self.keys = Vec::new();
        self.pos = 0;
        self.started = false;
        self.cur = None;
    }
}

// ---------------------------------------------------------------------------
// Iteration (Seq, Seq2).

impl Value {
    /// Go `Value.Seq`: the values produced by ranging over the value.
    pub fn seq(&self) -> Seq<'static, Value> {
        let t = self.type_();
        if t.can_range_func(1) {
            return Box::new(FuncSeq::start(self.clone(), 1).map(|mut a| a.remove(0)));
        }
        let v = self.clone();
        match self.kind() {
            k if k.is_int() || k.is_uint() => {
                let signed = k.is_int();
                let n_i = if signed { self.raw_int() } else { 0 };
                let n_u = if signed { 0 } else { self.raw_uint() };
                let basic = Type::basic(k);
                let named = !t.pkg_path().is_empty();
                let count = if signed {
                    // for i := T(0); i < T(num); i++ with the number wrapped to T.
                    wrap_int(k, n_i)
                } else {
                    0
                };
                let count_u = wrap_uint(k, n_u);
                let mut i = 0i64;
                let mut iu = 0u64;
                Box::new(std::iter::from_fn(move || {
                    let item = if signed {
                        if i >= count {
                            return None;
                        }
                        let x = Value::from_int(&basic, i);
                        i += 1;
                        x
                    } else {
                        if iu >= count_u {
                            return None;
                        }
                        let x = Value::from_uint(&basic, iu);
                        iu += 1;
                        x
                    };
                    Some(if named { item.convert(&t) } else { item })
                }))
            }
            Kind::Pointer if t.elem().kind() == Kind::Array => {
                let n = t.elem().len();
                Box::new((0..n).map(|i| int_value(i as i64)))
            }
            Kind::Array | Kind::Slice => {
                let n = self.len();
                Box::new((0..n).map(|i| int_value(i as i64)))
            }
            Kind::String => {
                let s = self.raw_str().to_vec();
                Box::new(
                    string_indices(s)
                        .into_iter()
                        .map(|(i, _)| int_value(i as i64)),
                )
            }
            Kind::Map => {
                let mut it = v.map_range();
                Box::new(std::iter::from_fn(move || {
                    if it.next() {
                        Some(it.key())
                    } else {
                        None
                    }
                }))
            }
            Kind::Chan => Box::new(std::iter::from_fn(move || {
                let (x, ok) = v.recv();
                if ok {
                    Some(x)
                } else {
                    None
                }
            })),
            _ => panic_msg(format!("reflect: {t} cannot produce iter.Seq[Value]")),
        }
    }

    /// Go `Value.Seq2`: the key/value pairs produced by ranging over the value.
    pub fn seq2(&self) -> Seq<'static, (Value, Value)> {
        let t = self.type_();
        if t.can_range_func(2) {
            return Box::new(FuncSeq::start(self.clone(), 2).map(|mut a| {
                let b = a.remove(1);
                (a.remove(0), b)
            }));
        }
        let v = self.clone();
        match self.kind() {
            Kind::Pointer if self.elem().kind() == Kind::Array => {
                let arr = self.elem();
                let n = arr.len();
                Box::new((0..n).map(move |i| (int_value(i as i64), arr.index(i))))
            }
            Kind::Array | Kind::Slice => {
                let n = self.len();
                Box::new((0..n).map(move |i| (int_value(i as i64), v.index(i))))
            }
            Kind::String => {
                let s = self.raw_str().to_vec();
                Box::new(string_indices(s).into_iter().map(|(i, r)| {
                    (
                        int_value(i as i64),
                        Value::from_int(&Type::basic(Kind::Int32), r as i64),
                    )
                }))
            }
            Kind::Map => {
                let mut it = v.map_range();
                Box::new(std::iter::from_fn(move || {
                    if it.next() {
                        Some((it.key(), it.value()))
                    } else {
                        None
                    }
                }))
            }
            _ => panic_msg(format!(
                "reflect: {t} cannot produce iter.Seq2[Value, Value]"
            )),
        }
    }
}

fn int_value(i: i64) -> Value {
    Value::from_int(&Type::basic(Kind::Int), i)
}

/// `for i, r := range s`: byte offsets and runes, invalid bytes as U+FFFD.
fn string_indices(s: Vec<u8>) -> Vec<(usize, i32)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        let len = match std::str::from_utf8(&rest[..rest.len().min(4)]) {
            Ok(_) => None,
            Err(e) => Some(e.valid_up_to()),
        };
        let valid_len = match len {
            None => rest.len().min(4),
            Some(n) => n,
        };
        if valid_len > 0 {
            let ch = std::str::from_utf8(&rest[..valid_len])
                .ok()
                .and_then(|t| t.chars().next());
            if let Some(c) = ch {
                out.push((i, c as i32));
                i += c.len_utf8();
                continue;
            }
        }
        out.push((i, 0xFFFD));
        i += 1;
    }
    out
}

/// A pull iterator over a push-style function value (`iter.Seq`), run on its
/// own thread so that stopping early stops the producer, like Go's range-over-func.
struct FuncSeq {
    rx: std::sync::mpsc::Receiver<Vec<Value>>,
    ack: Option<std::sync::mpsc::SyncSender<bool>>,
    pending: bool,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl FuncSeq {
    fn start(f: Value, n: usize) -> FuncSeq {
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<Value>>(0);
        let (ack_tx, ack_rx) = std::sync::mpsc::sync_channel::<bool>(0);
        let yield_t = f.typ().in_(0);
        let handle = std::thread::spawn(move || {
            let ack_rx = std::sync::Mutex::new(ack_rx);
            let tx2 = tx.clone();
            let yf: FuncImpl = Arc::new(move |args: &[Value]| {
                let _ = n;
                if tx2.send(args.to_vec()).is_err() {
                    return vec![bool_value(false)];
                }
                let go_on = lock(&ack_rx).recv().unwrap_or(false);
                vec![bool_value(go_on)]
            });
            let yv = Value::make_func_value(&yield_t, yf);
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                f.call(&[yv]);
            }));
            drop(tx);
        });
        FuncSeq {
            rx,
            ack: Some(ack_tx),
            pending: false,
            handle: Some(handle),
        }
    }
}

impl Iterator for FuncSeq {
    type Item = Vec<Value>;

    fn next(&mut self) -> Option<Vec<Value>> {
        if self.pending {
            self.pending = false;
            if let Some(a) = &self.ack {
                let _ = a.send(true);
            }
        }
        match self.rx.recv() {
            Ok(v) => {
                self.pending = true;
                Some(v)
            }
            Err(_) => None,
        }
    }
}

impl Drop for FuncSeq {
    fn drop(&mut self) {
        if self.pending {
            if let Some(a) = &self.ack {
                let _ = a.send(false);
            }
        }
        self.ack = None;
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn bool_value(b: bool) -> Value {
    Value::from_bool(&Type::basic(Kind::Bool), b)
}

// ---------------------------------------------------------------------------
// Constructors (package-level functions).

/// Go `reflect.Zero`: the zero value of type `typ`.
pub fn zero(typ: &Type) -> Value {
    Value::mk(typ.clone(), zero_data(typ), 0)
}

/// Go `reflect.New`: a pointer to a new zero value of type `typ`.
pub fn new(typ: &Type) -> Value {
    Value::mk(
        pointer_to(typ),
        Data::Ptr(Some(Place::new(zero_data(typ)))),
        0,
    )
}

/// Go `reflect.NewAt`: a pointer of type `*typ` to the memory `p` points to.
/// `p` must come from [`Value::unsafe_pointer`] of a pointer to a value of type
/// `typ`; Rust has no raw memory to reinterpret.
pub fn value_at(typ: &Type, p: &UnsafePointer) -> Value {
    Value::mk(pointer_to(typ), Data::Ptr(p.place.clone()), 0)
}

/// Go `reflect.Indirect`: the value a pointer points to, or `v` itself if it is
/// not a pointer.
pub fn indirect(v: &Value) -> Value {
    if v.kind() != Kind::Pointer {
        return v.clone();
    }
    v.elem()
}

/// Go `reflect.MakeSlice`.
pub fn make_slice(typ: &Type, len: isize, cap: isize) -> Value {
    if typ.kind() != Kind::Slice {
        panic_msg("reflect.MakeSlice of non-slice type");
    }
    if len < 0 {
        panic_msg("reflect.MakeSlice: negative len");
    }
    if cap < 0 {
        panic_msg("reflect.MakeSlice: negative cap");
    }
    if len > cap {
        panic_msg("reflect.MakeSlice: len > cap");
    }
    let et = typ.elem();
    let items: Vec<Data> = (0..cap).map(|_| zero_data(&et)).collect();
    Value::mk(
        typ.clone(),
        Data::Slice(SliceH {
            buf: Some(Place::new(Data::Agg(items))),
            off: 0,
            len: len as usize,
            cap: cap as usize,
        }),
        0,
    )
}

/// Go `reflect.SliceAt`: a slice of `n` elements of type `typ` starting at `p`,
/// which must come from [`Value::unsafe_pointer`] of a pointer to an element
/// of a slice or array.
pub fn slice_at(typ: &Type, p: &UnsafePointer, n: usize) -> Value {
    let st = slice_of(typ);
    let Some(place) = &p.place else {
        if n == 0 {
            return Value::mk(st.clone(), zero_data(&st), 0);
        }
        panic_msg("unsafe.Slice: ptr is nil and len is not zero");
    };
    if place.path.is_empty() {
        let buf = place.clone();
        let len = buf.with(|d| match d {
            Data::Agg(v) => v.len(),
            _ => 1,
        });
        if matches!(buf.read(), Data::Agg(_)) && n <= len {
            return Value::mk(
                st,
                Data::Slice(SliceH {
                    buf: Some(buf),
                    off: 0,
                    len: n,
                    cap: n,
                }),
                0,
            );
        }
        let one = Place::new(Data::Agg(vec![buf.read()]));
        if n <= 1 {
            return Value::mk(
                st,
                Data::Slice(SliceH {
                    buf: Some(one),
                    off: 0,
                    len: n,
                    cap: n,
                }),
                0,
            );
        }
        panic_msg("unsafe.Slice: len out of range");
    }
    let last = place.path[place.path.len() - 1] as usize;
    let parent = Place {
        cell: place.cell.clone(),
        path: Arc::from(&place.path[..place.path.len() - 1]),
    };
    let avail = parent.with(|d| match d {
        Data::Agg(v) => v.len().saturating_sub(last),
        _ => 0,
    });
    if n > avail {
        panic_msg("unsafe.Slice: len out of range");
    }
    Value::mk(
        st,
        Data::Slice(SliceH {
            buf: Some(parent),
            off: last,
            len: n,
            cap: avail,
        }),
        0,
    )
}

/// Go `reflect.MakeChan`.
pub fn make_chan(typ: &Type, buffer: isize) -> Value {
    if typ.kind() != Kind::Chan {
        panic_msg("reflect.MakeChan of non-chan type");
    }
    if buffer < 0 {
        panic_msg("reflect.MakeChan: negative buffer size");
    }
    if typ.chan_dir() != ChanDir::Both {
        panic_msg("reflect.MakeChan: unidirectional channel type");
    }
    Value::mk(typ.clone(), Data::Chan(Some(Chan::new(buffer as usize))), 0)
}

/// Go `reflect.MakeMap`.
pub fn make_map(typ: &Type) -> Value {
    make_map_with_size(typ, 0)
}

/// Go `reflect.MakeMapWithSize`.
pub fn make_map_with_size(typ: &Type, n: usize) -> Value {
    if typ.kind() != Kind::Map {
        panic_msg("reflect.MakeMapWithSize of non-map type");
    }
    let _ = n;
    Value::mk(
        typ.clone(),
        Data::Map(Some(Arc::new(std::sync::Mutex::new(MapData {
            entries: Vec::new(),
        })))),
        0,
    )
}

/// Go `reflect.MakeFunc`: a function value of type `typ` that calls `f` with
/// the arguments as `Value`s. The result cannot be turned back into a Rust
/// function pointer (`Value::interface`); it can be called with
/// [`Value::call`].
pub fn make_func(typ: &Type, f: impl Fn(&[Value]) -> Vec<Value> + Send + Sync + 'static) -> Value {
    if typ.kind() != Kind::Func {
        panic_msg("reflect: call of MakeFunc with non-Func type");
    }
    let t = typ.clone();
    let g: FuncImpl = Arc::new(move |args: &[Value]| {
        let (_, outs, _) = t.func_parts();
        let out = f(args);
        if out.len() != outs.len() {
            panic_msg("reflect: wrong return count from function created by MakeFunc");
        }
        out.into_iter()
            .zip(outs)
            .map(|(v, ot)| {
                if !v.is_valid() {
                    panic_msg("reflect: function created by MakeFunc using closure returned zero Value");
                }
                if v.flag & RO != 0 {
                    panic_msg(
                        "reflect: function created by MakeFunc using closure returned value obtained from unexported field",
                    );
                }
                v.assign_to("reflect.MakeFunc", ot)
            })
            .collect()
    });
    Value::make_func_value(typ, g)
}

/// Go `reflect.Append`: appends `x` to the slice `s`, returning the new slice.
pub fn append(s: &Value, x: &[Value]) -> Value {
    s.must_be("reflect.Append", Kind::Slice);
    let n = s.len();
    let ns = s.extend_slice(x.len());
    for (i, v) in x.iter().enumerate() {
        ns.index(n + i).set(v);
    }
    ns
}

/// Go `reflect.AppendSlice`: appends the elements of `t` to the slice `s`.
pub fn append_slice(s: &Value, t: &Value) -> Value {
    s.must_be("reflect.AppendSlice", Kind::Slice);
    t.must_be("reflect.AppendSlice", Kind::Slice);
    types_must_match("reflect.AppendSlice", &s.typ().elem(), &t.typ().elem());
    let ns = s.len();
    let nt = t.len();
    let r = s.extend_slice(nt);
    copy(&r.slice(ns as isize, (ns + nt) as isize), t);
    r
}

fn types_must_match(what: &str, t1: &Type, t2: &Type) {
    if t1 != t2 {
        panic_msg(format!("{what}: {t1} != {t2}"));
    }
}

impl Value {
    /// A new slice header (sharing storage) grown by `n` elements.
    fn extend_slice(&self, n: usize) -> Value {
        self.must_be_exported("reflect.Append");
        self.must_be("reflect.Append", Kind::Slice);
        let v = Value::mk(self.typ().clone(), self.data(), 0);
        v.grow_impl(n as isize);
        v.pl().with_mut(|d| {
            if let Data::Slice(h) = d {
                h.len += n;
            }
        });
        v
    }
}

/// Go `reflect.Copy`: copies elements from `src` to `dst` and returns the
/// number copied. `src` may also be a string when `dst` is a byte slice.
pub fn copy(dst: &Value, src: &Value) -> usize {
    let dk = dst.kind();
    if dk != Kind::Array && dk != Kind::Slice {
        value_error("reflect.Copy", dk);
    }
    if dk == Kind::Array {
        dst.must_be_assignable("reflect.Copy");
    }
    dst.must_be_exported("reflect.Copy");
    let sk = src.kind();
    let mut string_copy = false;
    if sk != Kind::Array && sk != Kind::Slice {
        string_copy = sk == Kind::String && dst.typ().elem().kind() == Kind::Uint8;
        if !string_copy {
            value_error("reflect.Copy", sk);
        }
    }
    src.must_be_exported("reflect.Copy");
    let de = dst.typ().elem();
    if !string_copy {
        types_must_match("reflect.Copy", &de, &src.typ().elem());
    }
    let items: Vec<Data> = if string_copy {
        src.raw_str()
            .iter()
            .map(|&b| Data::Uint(b as u64))
            .collect()
    } else {
        (0..src.len()).map(|i| src.index_unchecked(i)).collect()
    };
    let dn = dst.len();
    let n = items.len().min(dn);
    for (i, d) in items.into_iter().take(n).enumerate() {
        dst.place_of_index(i).write(d);
    }
    n
}

impl Value {
    fn index_unchecked(&self, i: usize) -> Data {
        self.place_of_index(i).read()
    }

    fn place_of_index(&self, i: usize) -> Place {
        match self.kind() {
            Kind::Array => self.pl().child(i),
            _ => {
                let h = self.slice_h();
                h.buf.expect("slice storage").child(h.off + i)
            }
        }
    }
}

/// A case of [`select()`] (Go `reflect.SelectCase`).
#[derive(Clone, Debug)]
pub struct SelectCase {
    /// The direction of the case.
    pub dir: SelectDir,
    /// The channel (a nil or invalid `Value` makes the case never ready).
    pub chan: Value,
    /// The value to send, for a send case.
    pub send: Value,
}

/// Go `reflect.Select`: executes a select operation. It returns the index of
/// the chosen case and, for a receive case, the value received and whether it
/// came from a send (false if the channel was closed).
pub fn select(cases: &[SelectCase]) -> (usize, Value, bool) {
    if cases.len() > 65536 {
        panic_msg("reflect.Select: too many cases (max 65536)");
    }
    let mut have_default = false;
    let mut default_index = 0;
    let mut real: Vec<usize> = Vec::new();
    let mut sel: Vec<SelCase> = Vec::new();
    let mut elems: Vec<Option<Type>> = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        match c.dir {
            SelectDir::Default => {
                if have_default {
                    panic_msg("reflect.Select: multiple default cases");
                }
                have_default = true;
                default_index = i;
                if c.chan.is_valid() {
                    panic_msg("reflect.Select: default case has Chan value");
                }
                if c.send.is_valid() {
                    panic_msg("reflect.Select: default case has Send value");
                }
            }
            SelectDir::Send => {
                let ch = &c.chan;
                if !ch.is_valid() {
                    continue;
                }
                ch.must_be("reflect.Select", Kind::Chan);
                ch.must_be_exported("reflect.Select");
                let tt = ch.typ().clone();
                if !tt.chan_dir().can_send() {
                    panic_msg("reflect.Select: SendDir case using recv-only channel");
                }
                if !c.send.is_valid() {
                    panic_msg("reflect.Select: SendDir case missing Send value");
                }
                c.send.must_be_exported("reflect.Select");
                let v = c.send.assign_to("reflect.Select", &tt.elem());
                let chan = match ch.data() {
                    Data::Chan(c) => c,
                    _ => None,
                };
                real.push(i);
                elems.push(None);
                sel.push(SelCase {
                    chan,
                    op: CaseOp::Send(v.data()),
                });
            }
            SelectDir::Recv => {
                if c.send.is_valid() {
                    panic_msg("reflect.Select: RecvDir case has Send value");
                }
                let ch = &c.chan;
                if !ch.is_valid() {
                    continue;
                }
                ch.must_be("reflect.Select", Kind::Chan);
                ch.must_be_exported("reflect.Select");
                let tt = ch.typ().clone();
                if !tt.chan_dir().can_recv() {
                    panic_msg("reflect.Select: RecvDir case using send-only channel");
                }
                let chan = match ch.data() {
                    Data::Chan(c) => c,
                    _ => None,
                };
                real.push(i);
                elems.push(Some(tt.elem()));
                sel.push(SelCase {
                    chan,
                    op: CaseOp::Recv,
                });
            }
        }
    }
    match run_select(&mut sel, have_default) {
        None => (default_index, Value::default(), false),
        Some(s) => {
            let idx = real[s.index];
            match (&elems[s.index], s.recv) {
                (Some(et), Some(Some(d))) => (idx, Value::mk(et.clone(), d, 0), true),
                (Some(et), _) => (idx, Value::mk(et.clone(), zero_data(et), 0), false),
                (None, _) => (idx, Value::default(), false),
            }
        }
    }
}

/// Go `reflect.Swapper`: a function that swaps the elements of the slice `s`.
pub fn swapper(s: &Value) -> Box<dyn Fn(usize, usize)> {
    if s.kind() != Kind::Slice {
        value_error("Swapper", s.kind());
    }
    let s = s.clone();
    match s.len() {
        0 => Box::new(|_, _| panic_msg("reflect: slice index out of range")),
        1 => Box::new(|i, j| {
            if i != 0 || j != 0 {
                panic_msg("reflect: slice index out of range");
            }
        }),
        _ => Box::new(move |i, j| {
            let n = s.len();
            if i >= n || j >= n {
                panic_msg("reflect: slice index out of range");
            }
            let (pi, pj) = (s.place_of_index(i), s.place_of_index(j));
            let (a, b) = (pi.read(), pj.read());
            pi.write(b);
            pj.write(a);
        }),
    }
}

/// Go `reflect.TypeAssert`: the value as `T` if it holds one (the dynamic
/// value for an interface), else `None`.
pub fn type_assert<T: super::Reflect>(v: &Value) -> Option<T> {
    if v.ty.is_none() {
        value_error("reflect.TypeAssert", Kind::Invalid);
    }
    if v.flag & RO != 0 {
        panic_msg(
            "reflect.TypeAssert: cannot return value obtained from unexported field or method",
        );
    }
    v.try_interface::<T>()
}

/// Type-level helper: the function type with a receiver prepended.
#[allow(dead_code)]
pub(crate) fn with_receiver(recv: &Type, f: &Type) -> Type {
    let (ins, outs, variadic) = f.func_parts();
    let mut all = vec![recv.clone()];
    all.extend(ins.iter().cloned());
    func_of(&all, outs, variadic)
}
