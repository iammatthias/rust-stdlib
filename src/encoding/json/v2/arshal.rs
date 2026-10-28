//! `Marshal` and `Unmarshal` and the traits that connect Rust types to them,
//! ported from Go's `encoding/json/v2/arshal.go`.
//!
//! Go finds the conversion for a value with `reflect`. Here a type is
//! marshaled when it implements [`MarshalTo`] and unmarshaled when it
//! implements [`UnmarshalFrom`]. The implementations for the standard types
//! are in this module's siblings, and the `Serialize` and `Deserialize`
//! derives of `rust-stdlib-derive` generate them for structs, so the same
//! `#[json(...)]` field options drive both versions of the package.
use std::any::{Any, TypeId};
use std::io::{Read, Write};

use super::errors::{
    err_changing_duplicate_names, err_changing_invalid_utf8, err_changing_whitespace,
    marshal_error_before, unmarshal_error_before,
};
use super::methods::{
    self, Marshaler, MarshalerTo, TextAppender, TextMarshaler, Unmarshaler, UnmarshalerFrom,
};
use super::structs::{FallbackMarshal, FallbackUnmarshal, StructDesc};
use super::typeinfo::TypeInfo;
use crate::encoding::json::jsontext::flags;
use crate::encoding::json::jsontext::{Decoder, Encoder, Error, Options, SyntacticError};

/// A Rust type that can be marshaled to JSON (the counterpart of the types
/// `reflect` can walk in Go).
///
/// Implement it for your own types with the `Serialize` derive of
/// `rust-stdlib-derive`, or by hand: [`marshal_default`](Self::marshal_default)
/// writes the value as its kind dictates, and the `as_*` methods expose
/// [`Marshaler`], [`MarshalerTo`] and the text marshaling hooks, which take
/// precedence in the order Go gives them.
pub trait MarshalTo: Any {
    /// The Go type this Rust type stands for, as errors report it.
    fn type_info() -> TypeInfo
    where
        Self: Sized;

    /// Writes the value according to its kind: the arshaler Go builds for
    /// the type before any methods are considered.
    fn marshal_default(&self, enc: &mut Encoder<'_>) -> Result<(), Error>;

    /// Go's `reflect.Value.IsZero`. The `omitzero` tag option uses it
    /// through [`is_zero_field`](Self::is_zero_field), unless the type has
    /// an `IsZero` method.
    fn is_zero_value(&self) -> bool;

    /// Whether the type has an `IsZero() bool` method (Go's `isZeroer`),
    /// which `omitzero` also calls through a pointer to the type.
    fn has_is_zero_method() -> bool
    where
        Self: Sized,
    {
        false
    }

    /// Whether `omitzero` omits a struct field holding this value: the
    /// type's `IsZero` method if it has one (also through a pointer, which
    /// is then zero when nil or when the method reports zero), otherwise
    /// [`is_zero_value`](Self::is_zero_value). A type with an `IsZero`
    /// method overrides this and keeps `is_zero_value` as Go's
    /// `reflect.Value.IsZero`, which a struct containing the type uses.
    fn is_zero_field(&self) -> bool {
        self.is_zero_value()
    }

    /// For strings, maps, arrays, slices and pointers, whether the value is
    /// empty or nil: the `omitempty` shortcut. `None` for other kinds.
    fn is_empty_value(&self) -> Option<bool> {
        None
    }

    /// For a Go struct, the description of its fields; `None` for other
    /// types. The `Serialize` derive generates it.
    fn struct_desc() -> Option<StructDesc>
    where
        Self: Sized,
    {
        None
    }

    /// For string-like types, the string (used to order map keys).
    fn as_str_key(&self) -> Option<&str> {
        None
    }

    /// For the types that can be an embedded fallback (maps with string
    /// keys and `jsontext::Value`), the fallback view of the value.
    fn as_fallback(&self) -> Option<&dyn FallbackMarshal> {
        None
    }

    /// The type's `MarshalJSON` method, if it has one.
    fn as_marshaler(&self) -> Option<&dyn Marshaler> {
        None
    }
    /// The type's `MarshalJSONTo` method, if it has one.
    fn as_marshaler_to(&self) -> Option<&dyn MarshalerTo> {
        None
    }
    /// The type's `MarshalText` method, if it has one.
    fn as_text_marshaler(&self) -> Option<&dyn TextMarshaler> {
        None
    }
    /// The type's `AppendText` method, if it has one.
    fn as_text_appender(&self) -> Option<&dyn TextAppender> {
        None
    }

    /// Writes the value: through its methods when it has them (Go's
    /// `makeMethodArshaler`), otherwise as its kind dictates.
    fn marshal_to(&self, enc: &mut Encoder<'_>) -> Result<(), Error>
    where
        Self: Sized,
    {
        methods::marshal(self, enc)
    }

    /// Reports whether the type has any method that replaces the default
    /// (Go's `nonDefault`).
    fn has_methods(&self) -> bool {
        self.as_marshaler().is_some()
            || self.as_marshaler_to().is_some()
            || self.as_text_marshaler().is_some()
            || self.as_text_appender().is_some()
    }
}

/// A Rust type that JSON can be unmarshaled into.
///
/// Implement it with the `Deserialize` derive of `rust-stdlib-derive` or by
/// hand, like [`MarshalTo`].
pub trait UnmarshalFrom: Any + Sized {
    /// The Go type this Rust type stands for, as errors report it.
    fn type_info() -> TypeInfo;

    /// A zero value (Go's `reflect.Zero`).
    fn zero() -> Self;

    /// Sets the value to its zero value (Go's `reflect.Value.SetZero`).
    fn set_zero(&mut self);

    /// Reads one JSON value into `self` according to the type's kind.
    fn unmarshal_default(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error>;

    /// For a Go struct, the description of its fields; `None` for other
    /// types. The `Deserialize` derive generates it.
    fn struct_desc() -> Option<StructDesc> {
        None
    }

    /// For string-like types, the value with the given text.
    fn from_str_key(_s: &str) -> Option<Self> {
        None
    }

    /// For the types that can be an embedded fallback, the fallback view of
    /// the value (allocating a missing pointee).
    fn as_fallback_mut(&mut self) -> Option<&mut dyn FallbackUnmarshal> {
        None
    }

    /// The type's `UnmarshalJSON` method, if it has one.
    fn as_unmarshaler(&mut self) -> Option<&mut dyn Unmarshaler> {
        None
    }
    /// The type's `UnmarshalJSONFrom` method, if it has one.
    fn as_unmarshaler_from(&mut self) -> Option<&mut dyn UnmarshalerFrom> {
        None
    }
    /// The type's `UnmarshalText` method, if it has one.
    fn as_text_unmarshaler(&mut self) -> Option<&mut dyn super::methods::TextUnmarshaler> {
        None
    }

    /// Reads one JSON value into `self`: through the type's methods when it
    /// has them, otherwise as its kind dictates.
    fn unmarshal_from(&mut self, dec: &mut Decoder<'_>) -> Result<(), Error> {
        methods::unmarshal(self, dec)
    }

    /// Reports whether the type has any method that replaces the default.
    fn has_methods(&mut self) -> bool {
        self.as_unmarshaler().is_some()
            || self.as_unmarshaler_from().is_some()
            || self.as_text_unmarshaler().is_some()
    }
}

/// Marshals `v` to `enc`: through the user's [`Marshalers`](super::Marshalers)
/// for its type if there are any, then through the type itself.
pub fn marshal_value<T: MarshalTo>(enc: &mut Encoder<'_>, v: &T) -> Result<(), Error> {
    if let Some(ms) = enc.s.opts.marshalers.clone() {
        for f in ms.lookup(TypeId::of::<T>()) {
            match f(enc, v as &dyn Any) {
                Err(e) if super::errors::is_unsupported(&e) => {}
                other => return other,
            }
        }
    }
    v.marshal_to(enc)
}

/// Unmarshals one JSON value from `dec` into `v`: through the user's
/// [`Unmarshalers`](super::Unmarshalers) for its type if there are any, then
/// through the type itself.
pub fn unmarshal_value<T: UnmarshalFrom>(dec: &mut Decoder<'_>, v: &mut T) -> Result<(), Error> {
    if let Some(us) = dec.s.opts.unmarshalers.clone() {
        for f in us.lookup(TypeId::of::<T>()) {
            match f(dec, v as &mut dyn Any) {
                Err(e) if super::errors::is_unsupported(&e) => {}
                other => return other,
            }
        }
    }
    v.unmarshal_from(dec)
}

fn marshal_encode_inner<T: MarshalTo>(out: &mut Encoder<'_>, v: &T) -> Result<(), Error> {
    let r = marshal_value(out, v);
    if r.is_err() && !out.s.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES) {
        out.s.state.tokens.invalidate_disabled_namespaces();
    }
    r
}

/// Go's `Marshal`: the JSON encoding of `v` per `opts`.
///
/// Unlike Go's, the result is only the error when marshaling fails; the
/// partial output Go returns alongside it is dropped.
pub fn marshal<T: MarshalTo>(v: &T, opts: &[Options]) -> Result<Vec<u8>, Error> {
    let mut enc = Encoder::buffered(opts);
    enc.s.opts.flags.set(flags::OMIT_TOP_LEVEL_NEWLINE, true);
    marshal_encode_inner(&mut enc, v)?;
    Ok(std::mem::take(&mut enc.s.buf))
}

/// Go's `MarshalWrite`: writes the JSON encoding of `v` per `opts` to `out`.
pub fn marshal_write<W: Write, T: MarshalTo>(out: W, v: &T, opts: &[Options]) -> Result<(), Error> {
    let mut enc = Encoder::new(out, opts);
    enc.s.opts.flags.set(flags::OMIT_TOP_LEVEL_NEWLINE, true);
    marshal_encode_inner(&mut enc, v)
}

/// Go's `MarshalEncode`: writes the JSON encoding of `v` to `out`, with
/// `opts` joined to the encoder's own for this call.
pub fn marshal_encode<T: MarshalTo>(
    out: &mut Encoder<'_>,
    v: &T,
    opts: &[Options],
) -> Result<(), Error> {
    if opts.is_empty() {
        return marshal_encode_inner(out, v);
    }
    let original = out.s.opts.clone();
    out.s.opts.join_all(opts);
    let r = marshal_encode_options(out, v, &original);
    out.s.opts = original;
    r
}

fn marshal_encode_options<T: MarshalTo>(
    out: &mut Encoder<'_>,
    v: &T,
    original: &Options,
) -> Result<(), Error> {
    if out.s.state.tokens.last.need_object_name() {
        if original.flags.get(flags::ALLOW_DUPLICATE_NAMES)
            != out.s.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES)
        {
            return Err(marshal_error_before(
                out,
                Some(T::type_info()),
                Some(err_changing_duplicate_names()),
            ));
        }
        if original.flags.get(flags::ALLOW_INVALID_UTF8)
            != out.s.opts.flags.get(flags::ALLOW_INVALID_UTF8)
        {
            return Err(marshal_error_before(
                out,
                Some(T::type_info()),
                Some(err_changing_invalid_utf8()),
            ));
        }
    }
    if out.s.opts.flags.has(flags::ANY_WHITESPACE) {
        if out.s.opts.flags.get(flags::MULTILINE) {
            out.s.opts.initialize_multiline();
        }
        if Options::changed_whitespace(original, &out.s.opts) {
            return Err(marshal_error_before(
                out,
                Some(T::type_info()),
                Some(err_changing_whitespace()),
            ));
        }
    }
    marshal_encode_inner(out, v)
}

fn unmarshal_decode_inner<T: UnmarshalFrom>(
    dec: &mut Decoder<'_>,
    out: &mut T,
    last: bool,
) -> Result<(), Error> {
    if let Err(err) = unmarshal_value(dec, out) {
        if !dec.s.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES) {
            dec.s.state.tokens.invalidate_disabled_namespaces();
        }
        if matches!(err, Error::Eof) && last {
            let offset = dec.input_offset() + dec.unread_buffer().len() as i64;
            return Err(Error::Syntactic(Box::new(SyntacticError {
                byte_offset: offset,
                err: Some(Error::UnexpectedEof),
                ..Default::default()
            })));
        }
        return Err(err);
    }
    if last {
        return dec.s.check_eof();
    }
    Ok(())
}

/// Go's `Unmarshal`: parses the JSON `data` per `opts` into `out`. The
/// destination is updated in place, so values already in it can be merged
/// with or left in place as Go's rules say.
pub fn unmarshal<T: UnmarshalFrom>(
    data: &[u8],
    out: &mut T,
    opts: &[Options],
) -> Result<(), Error> {
    let mut dec = Decoder::buffered(data, opts);
    unmarshal_decode_inner(&mut dec, out, true)
}

/// Go's `UnmarshalRead`: parses the JSON read from `input` into `out`.
pub fn unmarshal_read<R: Read, T: UnmarshalFrom>(
    input: R,
    out: &mut T,
    opts: &[Options],
) -> Result<(), Error> {
    let mut dec = Decoder::new(input, opts);
    unmarshal_decode_inner(&mut dec, out, true)
}

/// Go's `UnmarshalDecode`: reads the next JSON value from `dec` into `out`,
/// with `opts` joined to the decoder's own for this call.
pub fn unmarshal_decode<T: UnmarshalFrom>(
    dec: &mut Decoder<'_>,
    out: &mut T,
    opts: &[Options],
) -> Result<(), Error> {
    if opts.is_empty() {
        return unmarshal_decode_inner(dec, out, false);
    }
    let original = dec.s.opts.clone();
    dec.s.opts.join_all(opts);
    let r = (|| {
        if dec.s.state.tokens.last.need_object_name() {
            if original.flags.get(flags::ALLOW_DUPLICATE_NAMES)
                != dec.s.opts.flags.get(flags::ALLOW_DUPLICATE_NAMES)
            {
                return Err(unmarshal_error_before(
                    dec,
                    Some(T::type_info()),
                    Some(err_changing_duplicate_names()),
                ));
            }
            if original.flags.get(flags::ALLOW_INVALID_UTF8)
                != dec.s.opts.flags.get(flags::ALLOW_INVALID_UTF8)
            {
                return Err(unmarshal_error_before(
                    dec,
                    Some(T::type_info()),
                    Some(err_changing_invalid_utf8()),
                ));
            }
        }
        unmarshal_decode_inner(dec, out, false)
    })();
    dec.s.opts = original;
    r
}
