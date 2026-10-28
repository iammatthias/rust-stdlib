//! Typed encoding, mirroring Go's `makeField` and `makeBody`.
use super::der::append_header;
use super::time::{append_generalized_time, append_utc_time, is_zero_time, outside_utc_range};
use super::types::{
    append_bmp, append_i64, append_object_identifier, append_t61, is_numeric, is_printable,
    BitString, Enumerated, Flag, Integer, Null, ObjectIdentifier, RawValue,
};
use super::*;
use crate::time::DateTime;

/// A type that can be encoded as DER.
///
/// Implement it for SEQUENCE structs by returning [`Asn1Type::SEQUENCE`] and
/// writing each field with an [`Encoder`]:
///
/// ```
/// use rust_stdlib::encoding::asn1::{self, Asn1Type, Encoder, Error, Marshal, Params};
///
/// struct Version { number: i64, name: String }
///
/// impl Marshal for Version {
///     fn asn1_type(&self) -> Asn1Type { Asn1Type::SEQUENCE }
///     fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
///         Encoder::new(out)
///             .field(&self.number, &Params::parse("explicit,tag:0,optional"))?
///             .field(&self.name, &Params::NONE)?;
///         Ok(())
///     }
/// }
///
/// let der = asn1::marshal(&Version { number: 2, name: "v3".into() }).unwrap();
/// assert_eq!(der, [0x30, 0x09, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x13, 0x02, b'v', b'3']);
/// ```
pub trait Marshal {
    /// The universal type of this value (Go's `getUniversalType`).
    fn asn1_type(&self) -> Asn1Type;
    /// Appends the content octets. For [`Asn1Type::Raw`] this writes the
    /// complete element instead.
    fn marshal_body(&self, params: &Params, out: &mut Vec<u8>) -> Result<(), Error>;
    /// The universal tag to emit. Strings and times choose a concrete type
    /// from the value and parameters; other types use [`Marshal::asn1_type`].
    fn universal_tag(&self, _params: &Params) -> u32 {
        match self.asn1_type() {
            Asn1Type::Universal { tag, .. } => tag,
            Asn1Type::String => TAG_PRINTABLE_STRING,
            Asn1Type::Time => TAG_UTC_TIME,
            Asn1Type::Flag => TAG_BOOLEAN,
            Asn1Type::Raw | Asn1Type::Any => 0,
        }
    }
    /// Whether this is the type's zero value. OPTIONAL fields without a
    /// `default:` are omitted when zero, as Go does.
    fn is_zero(&self) -> bool {
        false
    }
    /// Whether this equals an integer `default:`. Only integer-like types
    /// answer (Go's `canHaveDefaultValue`).
    fn equals_default(&self, _default: i64) -> Option<bool> {
        None
    }
    /// Whether this is an empty slice-like value, for `omitempty`.
    fn is_empty_slice(&self) -> bool {
        false
    }
}

impl<T: Marshal + ?Sized> Marshal for &T {
    fn asn1_type(&self) -> Asn1Type {
        (**self).asn1_type()
    }
    fn marshal_body(&self, params: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        (**self).marshal_body(params, out)
    }
    fn universal_tag(&self, params: &Params) -> u32 {
        (**self).universal_tag(params)
    }
    fn is_zero(&self) -> bool {
        (**self).is_zero()
    }
    fn equals_default(&self, default: i64) -> Option<bool> {
        (**self).equals_default(default)
    }
    fn is_empty_slice(&self) -> bool {
        (**self).is_empty_slice()
    }
}

/// Appends fields to the contents of a SEQUENCE or SET.
pub struct Encoder<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> Encoder<'a> {
    pub fn new(out: &'a mut Vec<u8>) -> Self {
        Self { out }
    }
    /// Encodes a field. OPTIONAL fields equal to their zero value (or to an
    /// integer `default:`) and empty `omitempty` slices are omitted.
    pub fn field<T: Marshal + ?Sized>(
        &mut self,
        value: &T,
        params: &Params,
    ) -> Result<&mut Self, Error> {
        marshal_field(value, params, self.out)?;
        Ok(self)
    }
    /// Omits `None` and always encodes `Some`, even a zero, default or empty
    /// value (the `optional`, `default:` and `omitempty` options are ignored).
    pub fn optional<T: Marshal + ?Sized>(
        &mut self,
        value: Option<&T>,
        params: &Params,
    ) -> Result<&mut Self, Error> {
        if let Some(value) = value {
            let params = Params {
                optional: false,
                default: None,
                omit_empty: false,
                ..*params
            };
            marshal_field(value, &params, self.out)?;
        }
        Ok(self)
    }
}

/// Go's makeField.
pub(crate) fn marshal_field<T: Marshal + ?Sized>(
    value: &T,
    params: &Params,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    if params.omit_empty && value.is_empty_slice() {
        return Ok(());
    }
    if params.optional {
        match params.default {
            Some(default) => {
                if value.equals_default(default) == Some(true) {
                    return Ok(());
                }
            }
            None => {
                if value.is_zero() {
                    return Ok(());
                }
            }
        }
    }
    let ty = value.asn1_type();
    if ty == Asn1Type::Raw {
        return value.marshal_body(params, out);
    }
    let compound = match ty {
        Asn1Type::Universal { compound, .. } => compound,
        Asn1Type::String | Asn1Type::Time | Asn1Type::Flag => false,
        Asn1Type::Raw | Asn1Type::Any => return Err(Error::structural("unknown Go type")),
    };
    if params.time_type.is_some() && ty != Asn1Type::Time {
        return Err(Error::structural(
            "explicit time type given to non-time member",
        ));
    }
    if params.string_type.is_some() && ty != Asn1Type::String {
        return Err(Error::structural(
            "explicit string type given to non-string member",
        ));
    }
    let mut tag = value.universal_tag(params);
    let mut body_params = *params;
    if params.set {
        if tag != TAG_SEQUENCE {
            return Err(Error::structural("non sequence tagged as set"));
        }
        tag = TAG_SET;
    }
    if tag == TAG_SET {
        body_params.set = true;
    }
    let mut body = Vec::new();
    value.marshal_body(&body_params, &mut body)?;

    if let Some(outer) = params.effective_tag() {
        let class = if params.application {
            Class::Application
        } else if params.private {
            Class::Private
        } else {
            Class::ContextSpecific
        };
        if params.explicit {
            let mut inner = Vec::with_capacity(8);
            append_header(&mut inner, Class::Universal, tag, compound, body.len());
            append_header(out, class, outer, true, inner.len() + body.len());
            out.extend_from_slice(&inner);
            out.extend_from_slice(&body);
            return Ok(());
        }
        append_header(out, class, outer, compound, body.len());
    } else {
        append_header(out, Class::Universal, tag, compound, body.len());
    }
    out.extend_from_slice(&body);
    Ok(())
}

impl Marshal for bool {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::universal(TAG_BOOLEAN)
    }
    fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        out.push(if *self { 0xff } else { 0 });
        Ok(())
    }
    fn is_zero(&self) -> bool {
        !*self
    }
}

impl Marshal for i64 {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::universal(TAG_INTEGER)
    }
    fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        append_i64(out, *self);
        Ok(())
    }
    fn is_zero(&self) -> bool {
        *self == 0
    }
    fn equals_default(&self, default: i64) -> Option<bool> {
        Some(*self == default)
    }
}

impl Marshal for i32 {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::universal(TAG_INTEGER)
    }
    fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        append_i64(out, i64::from(*self));
        Ok(())
    }
    fn is_zero(&self) -> bool {
        *self == 0
    }
    fn equals_default(&self, default: i64) -> Option<bool> {
        // reflect.Value.SetInt truncates the default to the field width.
        Some(*self == default as i32)
    }
}

impl Marshal for Integer {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::universal(TAG_INTEGER)
    }
    fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(self.as_twos_complement());
        Ok(())
    }
}

impl Marshal for Enumerated {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::universal(TAG_ENUM)
    }
    fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        append_i64(out, self.0);
        Ok(())
    }
    fn is_zero(&self) -> bool {
        self.0 == 0
    }
    fn equals_default(&self, default: i64) -> Option<bool> {
        Some(self.0 == default)
    }
}

impl Marshal for Flag {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::Flag
    }
    fn marshal_body(&self, _: &Params, _: &mut Vec<u8>) -> Result<(), Error> {
        Ok(())
    }
    fn is_zero(&self) -> bool {
        !self.0
    }
}

impl Marshal for Null {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::universal(TAG_NULL)
    }
    fn marshal_body(&self, _: &Params, _: &mut Vec<u8>) -> Result<(), Error> {
        Ok(())
    }
}

impl Marshal for BitString {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::universal(TAG_BIT_STRING)
    }
    /// As in Go, padding bits are written as stored (not masked).
    fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        out.push(((8 - self.bit_length % 8) % 8) as u8);
        out.extend_from_slice(&self.bytes);
        Ok(())
    }
    fn is_zero(&self) -> bool {
        self.bytes.is_empty() && self.bit_length == 0
    }
}

impl Marshal for ObjectIdentifier {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::universal(TAG_OID)
    }
    fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        append_object_identifier(out, self)
    }
    fn is_zero(&self) -> bool {
        self.0.is_empty()
    }
    fn is_empty_slice(&self) -> bool {
        self.0.is_empty()
    }
}

/// OCTET STRING. An empty value counts as Go's nil slice.
impl Marshal for [u8] {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::universal(TAG_OCTET_STRING)
    }
    fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(self);
        Ok(())
    }
    fn is_zero(&self) -> bool {
        self.is_empty()
    }
    fn is_empty_slice(&self) -> bool {
        self.is_empty()
    }
}

/// OCTET STRING.
impl Marshal for Vec<u8> {
    fn asn1_type(&self) -> Asn1Type {
        self.as_slice().asn1_type()
    }
    fn marshal_body(&self, params: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        self.as_slice().marshal_body(params, out)
    }
    fn is_zero(&self) -> bool {
        self.is_empty()
    }
    fn is_empty_slice(&self) -> bool {
        self.is_empty()
    }
}

/// Go's slice body: elements in order, or sorted by their encodings for SET OF.
pub(crate) fn marshal_elements<T: Marshal>(
    items: &[T],
    params: &Params,
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    if !params.set || items.len() < 2 {
        for item in items {
            marshal_field(item, &Params::NONE, out)?;
        }
        return Ok(());
    }
    let mut encoded = Vec::with_capacity(items.len());
    for item in items {
        let mut one = Vec::new();
        marshal_field(item, &Params::NONE, &mut one)?;
        encoded.push(one);
    }
    encoded.sort();
    for one in encoded {
        out.extend_from_slice(&one);
    }
    Ok(())
}

/// SEQUENCE OF (SET OF with the `set` parameter).
impl<T: Marshal> Marshal for [T] {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::SEQUENCE
    }
    fn marshal_body(&self, params: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        marshal_elements(self, params, out)
    }
    fn is_zero(&self) -> bool {
        self.is_empty()
    }
    fn is_empty_slice(&self) -> bool {
        self.is_empty()
    }
}

/// SEQUENCE OF (SET OF with the `set` parameter).
impl<T: Marshal> Marshal for Vec<T> {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::SEQUENCE
    }
    fn marshal_body(&self, params: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        marshal_elements(self, params, out)
    }
    fn is_zero(&self) -> bool {
        self.is_empty()
    }
    fn is_empty_slice(&self) -> bool {
        self.is_empty()
    }
}

/// SET OF: elements are sorted by their DER encodings.
impl<T: Marshal> Marshal for SetOf<T> {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::SET
    }
    fn marshal_body(&self, params: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        marshal_elements(&self.0, params, out)
    }
    fn is_zero(&self) -> bool {
        self.0.is_empty()
    }
    fn is_empty_slice(&self) -> bool {
        self.0.is_empty()
    }
}

/// Character strings. Without a string-type parameter the value is a
/// PrintableString when every character allows it, otherwise a UTF8String.
impl Marshal for str {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::String
    }
    fn universal_tag(&self, params: &Params) -> u32 {
        match params.string_type {
            Some(st) => st.tag(),
            None if self.bytes().all(|b| is_printable(b, false, false)) => TAG_PRINTABLE_STRING,
            None => TAG_UTF8_STRING,
        }
    }
    fn marshal_body(&self, params: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        match params.string_type {
            Some(StringType::Ia5) if !self.is_ascii() => {
                Err(Error::structural("IA5String contains invalid character"))
            }
            // An explicit PrintableString permits '*' but not '&'.
            Some(StringType::Printable) if !self.bytes().all(|b| is_printable(b, true, false)) => {
                Err(Error::structural(
                    "PrintableString contains invalid character",
                ))
            }
            Some(StringType::Numeric) if !self.bytes().all(is_numeric) => Err(Error::structural(
                "NumericString contains invalid character",
            )),
            Some(StringType::T61) => append_t61(out, self),
            Some(StringType::Bmp) => append_bmp(out, self),
            _ => {
                out.extend_from_slice(self.as_bytes());
                Ok(())
            }
        }
    }
    fn is_zero(&self) -> bool {
        self.is_empty()
    }
}

impl Marshal for String {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::String
    }
    fn universal_tag(&self, params: &Params) -> u32 {
        self.as_str().universal_tag(params)
    }
    fn marshal_body(&self, params: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        self.as_str().marshal_body(params, out)
    }
    fn is_zero(&self) -> bool {
        self.is_empty()
    }
}

fn use_generalized(t: &DateTime, params: &Params) -> bool {
    params.time_type == Some(TimeType::Generalized) || outside_utc_range(t)
}

/// UTCTime for 1950..2049 unless `generalized` is requested; GeneralizedTime
/// otherwise. Fractional seconds are not written.
impl Marshal for DateTime {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::Time
    }
    fn universal_tag(&self, params: &Params) -> u32 {
        if use_generalized(self, params) {
            TAG_GENERALIZED_TIME
        } else {
            TAG_UTC_TIME
        }
    }
    fn marshal_body(&self, params: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        if use_generalized(self, params) {
            append_generalized_time(out, self);
            Ok(())
        } else {
            append_utc_time(out, self)
        }
    }
    fn is_zero(&self) -> bool {
        is_zero_time(self)
    }
}

/// Writes `full_bytes` verbatim when non-empty; parameters are ignored.
impl Marshal for RawValue {
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::Raw
    }
    fn marshal_body(&self, _: &Params, out: &mut Vec<u8>) -> Result<(), Error> {
        if !self.full_bytes.is_empty() {
            out.extend_from_slice(&self.full_bytes);
            return Ok(());
        }
        append_header(
            out,
            self.class,
            self.tag,
            self.is_compound,
            self.bytes.len(),
        );
        out.extend_from_slice(&self.bytes);
        Ok(())
    }
    fn is_zero(&self) -> bool {
        *self == RawValue::default()
    }
}
