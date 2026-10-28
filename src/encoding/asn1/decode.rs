//! Typed decoding, mirroring Go's `parseField` and `parseSequenceOf`.
use super::der::{content_end, parse_header};
use super::time::{parse_generalized_time, parse_utc_time, zero_time};
use super::types::{
    parse_bit_string, parse_bmp, parse_bool, parse_i32, parse_i64, parse_ia5, parse_numeric,
    parse_object_identifier, parse_printable, parse_t61, parse_utf8, BitString, Enumerated, Flag,
    Integer, Null, ObjectIdentifier, RawValue,
};
use super::*;
use crate::time::DateTime;
use std::marker::PhantomData;

/// A decoded element handed to [`Unmarshal::decode`] / [`Decode::decode`].
///
/// `tag` and `class` are the wire values (after any explicit wrapper was
/// removed). `universal_tag` is the universal type Go selected for the field:
/// for strings and times it names the concrete string or time type to parse.
#[derive(Debug, Clone, Copy)]
pub struct Element<'a> {
    pub class: Class,
    pub tag: u32,
    pub is_compound: bool,
    /// Content octets.
    pub bytes: &'a [u8],
    /// Identifier, length and content octets (including an explicit wrapper
    /// when one was present, as in Go).
    pub full_bytes: &'a [u8],
    pub universal_tag: u32,
    depth: usize,
    options: Options,
}

impl<'a> Element<'a> {
    /// A decoder over the content octets, for SEQUENCE/SET fields. It shares
    /// the nesting depth and options of the enclosing decoder.
    pub fn contents(&self) -> Decoder<'a> {
        Decoder {
            input: self.bytes,
            offset: 0,
            depth: self.depth,
            options: self.options,
        }
    }
    /// The nesting depth of this element (the top-level element is 1).
    pub fn depth(&self) -> usize {
        self.depth
    }
    pub fn options(&self) -> Options {
        self.options
    }
}

/// A value-level decoding description. [`Unmarshal`] types get one through
/// [`Typed`]; schema-driven code can implement it directly.
pub trait Decode {
    type Output;
    /// The universal type this decoder expects (Go's `getUniversalType`).
    fn asn1_type(&self) -> Asn1Type;
    fn decode(&self, element: &Element<'_>) -> Result<Self::Output, Error>;
    /// The value of an absent OPTIONAL field (Go leaves the zero value).
    fn zero(&self) -> Self::Output;
    /// The value for an absent OPTIONAL field with `default:` set. Only
    /// integer-like types return `Some` (Go's `canHaveDefaultValue`).
    fn default_value(&self, _value: i64) -> Option<Self::Output> {
        None
    }
    /// The value for an explicit tag with empty contents (only [`Flag`]).
    fn empty_explicit(&self) -> Option<Self::Output> {
        None
    }
}

/// A type that can be decoded from DER. Implement it for SEQUENCE structs by
/// returning [`Asn1Type::SEQUENCE`] and reading fields from
/// [`Element::contents`]:
///
/// ```
/// use rust_stdlib::encoding::asn1::{self, Asn1Type, Element, Error, ObjectIdentifier, Params, RawValue, Unmarshal};
///
/// struct AlgorithmIdentifier { algorithm: ObjectIdentifier, parameters: Option<RawValue> }
///
/// impl Unmarshal for AlgorithmIdentifier {
///     fn asn1_type() -> Asn1Type { Asn1Type::SEQUENCE }
///     fn decode(element: &Element<'_>) -> Result<Self, Error> {
///         let mut fields = element.contents();
///         Ok(Self {
///             algorithm: fields.field(&Params::NONE)?,
///             parameters: fields.optional(&Params::NONE)?,
///         })
///     }
///     fn zero() -> Self { Self { algorithm: ObjectIdentifier::default(), parameters: None } }
/// }
///
/// let der = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00];
/// let (alg, rest) = asn1::unmarshal::<AlgorithmIdentifier>(&der).unwrap();
/// assert_eq!(alg.algorithm.to_string(), "1.2.840.113549.1.1.11");
/// assert_eq!(alg.parameters.unwrap().tag, asn1::TAG_NULL);
/// assert!(rest.is_empty());
/// ```
pub trait Unmarshal: Sized {
    fn asn1_type() -> Asn1Type;
    fn decode(element: &Element<'_>) -> Result<Self, Error>;
    fn zero() -> Self;
    fn default_value(_value: i64) -> Option<Self> {
        None
    }
    fn empty_explicit() -> Option<Self> {
        None
    }
}

/// Adapts an [`Unmarshal`] type to [`Decode`].
pub struct Typed<T>(PhantomData<fn() -> T>);

impl<T> Typed<T> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> Default for Typed<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Unmarshal> Decode for Typed<T> {
    type Output = T;
    fn asn1_type(&self) -> Asn1Type {
        T::asn1_type()
    }
    fn decode(&self, element: &Element<'_>) -> Result<T, Error> {
        T::decode(element)
    }
    fn zero(&self) -> T {
        T::zero()
    }
    fn default_value(&self, value: i64) -> Option<T> {
        T::default_value(value)
    }
    fn empty_explicit(&self) -> Option<T> {
        T::empty_explicit()
    }
}

impl<D: Decode + ?Sized> Decode for &D {
    type Output = D::Output;
    fn asn1_type(&self) -> Asn1Type {
        (**self).asn1_type()
    }
    fn decode(&self, element: &Element<'_>) -> Result<D::Output, Error> {
        (**self).decode(element)
    }
    fn zero(&self) -> D::Output {
        (**self).zero()
    }
    fn default_value(&self, value: i64) -> Option<D::Output> {
        (**self).default_value(value)
    }
    fn empty_explicit(&self) -> Option<D::Output> {
        (**self).empty_explicit()
    }
}

/// Reads consecutive elements from a byte slice: the top-level input, or the
/// contents of a SEQUENCE/SET obtained from [`Element::contents`].
///
/// As in Go, elements left over after the last field of a SEQUENCE are not an
/// error; inspect [`Decoder::remaining`] to reject them.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    depth: usize,
    options: Options,
}

impl<'a> Decoder<'a> {
    /// A top-level decoder with default [`Options`].
    pub fn new(input: &'a [u8]) -> Result<Self, Error> {
        Self::with_options(input, Options::default())
    }
    pub fn with_options(input: &'a [u8], options: Options) -> Result<Self, Error> {
        if input.len() > options.max_input_bytes {
            return Err(Error::limit("input exceeds max_input_bytes"));
        }
        Ok(Self {
            input,
            offset: 0,
            depth: 0,
            options,
        })
    }
    /// Bytes not yet consumed.
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.offset..]
    }
    pub fn is_empty(&self) -> bool {
        self.offset == self.input.len()
    }
    /// Decodes the next field. An absent OPTIONAL field yields the type's
    /// zero value, or its `default:` value, without consuming input.
    pub fn field<T: Unmarshal>(&mut self, params: &Params) -> Result<T, Error> {
        self.field_with(&Typed::<T>::new(), params)
    }
    /// Decodes the next field as OPTIONAL, reporting absence as `None`.
    pub fn optional<T: Unmarshal>(&mut self, params: &Params) -> Result<Option<T>, Error> {
        self.optional_with(&Typed::<T>::new(), params)
    }
    pub fn field_with<D: Decode + ?Sized>(
        &mut self,
        decoder: &D,
        params: &Params,
    ) -> Result<D::Output, Error> {
        let (value, offset) = parse_field(
            decoder,
            self.input,
            self.offset,
            params,
            self.depth,
            &self.options,
        )?;
        self.offset = offset;
        Ok(match value {
            Some(v) => v,
            None => params
                .default
                .and_then(|d| decoder.default_value(d))
                .unwrap_or_else(|| decoder.zero()),
        })
    }
    pub fn optional_with<D: Decode + ?Sized>(
        &mut self,
        decoder: &D,
        params: &Params,
    ) -> Result<Option<D::Output>, Error> {
        let params = Params {
            optional: true,
            ..*params
        };
        let (value, offset) = parse_field(
            decoder,
            self.input,
            self.offset,
            &params,
            self.depth,
            &self.options,
        )?;
        self.offset = offset;
        Ok(value)
    }
}

fn mismatch<T>(
    params: &Params,
    init: usize,
    message: &'static str,
) -> Result<(Option<T>, usize), Error> {
    if params.optional {
        Ok((None, init))
    } else {
        Err(Error::structural(message))
    }
}

/// Go's parseField. Returns `None` for an absent OPTIONAL field.
fn parse_field<D: Decode + ?Sized>(
    decoder: &D,
    bytes: &[u8],
    init: usize,
    params: &Params,
    depth: usize,
    options: &Options,
) -> Result<(Option<D::Output>, usize), Error> {
    let depth = depth + 1;
    if depth > options.max_depth {
        return Err(Error::structural("nesting depth exceeded"));
    }
    if init == bytes.len() {
        return if params.optional {
            Ok((None, init))
        } else {
            Err(Error::syntax("sequence truncated"))
        };
    }
    let ty = decoder.asn1_type();
    if ty == Asn1Type::Any {
        // Go's interface{} fields ignore all parameters.
        let (h, offset) = parse_header(bytes, init)?;
        let end =
            content_end(offset, h.length, bytes.len()).ok_or(Error::syntax("data truncated"))?;
        let element = element_at(bytes, init, offset, end, h, h.tag, depth, options);
        return Ok((Some(decoder.decode(&element)?), end));
    }
    let (mut h, mut offset) = parse_header(bytes, init)?;
    let mut scope_end = bytes.len();
    let mut wrapper_end = None;
    let tag_param = params.effective_tag();
    if params.explicit {
        // Go expects APPLICATION or CONTEXT-SPECIFIC here; `private` is not
        // honoured for explicit tags on decode.
        let expected_class = if params.application {
            Class::Application
        } else {
            Class::ContextSpecific
        };
        if offset == bytes.len() {
            return Err(Error::structural("explicit tag has no child"));
        }
        if h.class == expected_class && Some(h.tag) == tag_param && (h.length == 0 || h.compound) {
            if ty == Asn1Type::Raw {
                // The wrapper itself is the raw value.
            } else if h.length > 0 {
                if options.strict_explicit {
                    let end = content_end(offset, h.length, bytes.len())
                        .ok_or(Error::explicit_length())?;
                    scope_end = end;
                    wrapper_end = Some(end);
                }
                (h, offset) = match parse_header(&bytes[..scope_end], offset) {
                    Ok(parsed) => parsed,
                    // The inner header runs past the wrapper but not the parent.
                    Err(_) if parse_header(bytes, offset).is_ok() => {
                        return Err(Error::explicit_length())
                    }
                    Err(e) => return Err(e),
                };
            } else {
                return match decoder.empty_explicit() {
                    Some(v) => Ok((Some(v), offset)),
                    None => Err(Error::structural(
                        "zero length explicit tag was not an asn1.Flag",
                    )),
                };
            }
        } else {
            return mismatch(params, init, "explicitly tagged member didn't match");
        }
    }

    let (match_any, mut universal, compound) = match ty {
        Asn1Type::Raw => (true, 0, false),
        Asn1Type::String => (false, TAG_PRINTABLE_STRING, false),
        Asn1Type::Time => (false, TAG_UTC_TIME, false),
        Asn1Type::Flag => (false, TAG_BOOLEAN, false),
        Asn1Type::Universal { tag, compound } => (false, tag, compound),
        Asn1Type::Any => return Err(Error::structural("unknown type")),
    };
    if ty == Asn1Type::String {
        if h.class == Class::Universal {
            if matches!(
                h.tag,
                TAG_IA5_STRING
                    | TAG_GENERAL_STRING
                    | TAG_T61_STRING
                    | TAG_UTF8_STRING
                    | TAG_NUMERIC_STRING
                    | TAG_BMP_STRING
            ) {
                universal = h.tag;
            }
        } else if let Some(st) = params.string_type {
            universal = st.tag();
        }
    }
    if ty == Asn1Type::Time {
        if h.class == Class::Universal {
            if h.tag == TAG_GENERALIZED_TIME {
                universal = h.tag;
            }
        } else if let Some(tt) = params.time_type {
            universal = tt.tag();
        }
    }
    if params.set {
        universal = TAG_SET;
    }
    let mut match_any_class_and_tag = match_any;
    let mut expected_class = Class::Universal;
    let mut expected_tag = universal;
    if !params.explicit {
        if let Some(tag) = tag_param {
            expected_class = if params.private {
                Class::Private
            } else if params.application {
                Class::Application
            } else {
                Class::ContextSpecific
            };
            expected_tag = tag;
            match_any_class_and_tag = false;
        }
    }
    if (!match_any_class_and_tag && (h.class != expected_class || h.tag != expected_tag))
        || (!match_any && h.compound != compound)
    {
        return mismatch(params, init, "tags don't match");
    }
    let end = match content_end(offset, h.length, scope_end) {
        Some(end) => end,
        None if wrapper_end.is_some() => return Err(Error::explicit_length()),
        None => return Err(Error::syntax("data truncated")),
    };
    if wrapper_end.is_some_and(|w| w != end) {
        return Err(Error::explicit_length());
    }
    let element = element_at(bytes, init, offset, end, h, universal, depth, options);
    let value = decoder.decode(&element)?;
    Ok((Some(value), wrapper_end.unwrap_or(end)))
}

#[allow(clippy::too_many_arguments)]
fn element_at<'a>(
    bytes: &'a [u8],
    init: usize,
    offset: usize,
    end: usize,
    h: super::der::Header,
    universal_tag: u32,
    depth: usize,
    options: &Options,
) -> Element<'a> {
    Element {
        class: h.class,
        tag: h.tag,
        is_compound: h.compound,
        bytes: &bytes[offset..end],
        full_bytes: &bytes[init..end],
        universal_tag,
        depth,
        options: *options,
    }
}

/// Go's parseSequenceOf: element headers are checked against the element
/// type first (string and time tags are interchangeable), then each element
/// is decoded with empty parameters.
pub fn decode_sequence_of<D: Decode + ?Sized>(
    elem: &D,
    element: &Element<'_>,
) -> Result<Vec<D::Output>, Error> {
    let (match_any, expected_tag, compound) = match elem.asn1_type() {
        Asn1Type::Raw => (true, 0, false),
        Asn1Type::String => (false, TAG_PRINTABLE_STRING, false),
        Asn1Type::Time => (false, TAG_UTC_TIME, false),
        Asn1Type::Flag => (false, TAG_BOOLEAN, false),
        Asn1Type::Universal { tag, compound } => (false, tag, compound),
        Asn1Type::Any => return Err(Error::structural("unknown Go type for slice")),
    };
    let bytes = element.bytes;
    let mut count = 0usize;
    let mut offset = 0;
    while offset < bytes.len() {
        let (mut h, next) = parse_header(bytes, offset)?;
        h.tag = match h.tag {
            TAG_IA5_STRING | TAG_GENERAL_STRING | TAG_T61_STRING | TAG_UTF8_STRING
            | TAG_NUMERIC_STRING | TAG_BMP_STRING => TAG_PRINTABLE_STRING,
            TAG_GENERALIZED_TIME | TAG_UTC_TIME => TAG_UTC_TIME,
            tag => tag,
        };
        if !match_any
            && (h.class != Class::Universal || h.compound != compound || h.tag != expected_tag)
        {
            return Err(Error::structural("sequence tag mismatch"));
        }
        offset =
            content_end(next, h.length, bytes.len()).ok_or(Error::syntax("truncated sequence"))?;
        count += 1;
        if count > element.options.max_elements {
            return Err(Error::limit("sequence exceeds max_elements"));
        }
    }
    let mut decoder = element.contents();
    let mut out = Vec::new();
    for _ in 0..count {
        out.push(decoder.field_with(elem, &Params::NONE)?);
    }
    Ok(out)
}

/// Decodes SEQUENCE OF / SET OF with a [`Decode`] for the elements.
pub struct SequenceOfWith<D>(pub D);

impl<D: Decode> Decode for SequenceOfWith<D> {
    type Output = Vec<D::Output>;
    fn asn1_type(&self) -> Asn1Type {
        Asn1Type::SEQUENCE
    }
    fn decode(&self, element: &Element<'_>) -> Result<Self::Output, Error> {
        decode_sequence_of(&self.0, element)
    }
    fn zero(&self) -> Self::Output {
        Vec::new()
    }
}

// Unmarshal implementations for the built-in types.

impl Unmarshal for bool {
    fn asn1_type() -> Asn1Type {
        Asn1Type::universal(TAG_BOOLEAN)
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        parse_bool(e.bytes)
    }
    fn zero() -> Self {
        false
    }
}

impl Unmarshal for i64 {
    fn asn1_type() -> Asn1Type {
        Asn1Type::universal(TAG_INTEGER)
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        parse_i64(e.bytes)
    }
    fn zero() -> Self {
        0
    }
    fn default_value(value: i64) -> Option<Self> {
        Some(value)
    }
}

impl Unmarshal for i32 {
    fn asn1_type() -> Asn1Type {
        Asn1Type::universal(TAG_INTEGER)
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        parse_i32(e.bytes)
    }
    fn zero() -> Self {
        0
    }
    fn default_value(value: i64) -> Option<Self> {
        // reflect.Value.SetInt truncates to the field width.
        Some(value as i32)
    }
}

impl Unmarshal for Integer {
    fn asn1_type() -> Asn1Type {
        Asn1Type::universal(TAG_INTEGER)
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        Integer::from_twos_complement(e.bytes)
    }
    fn zero() -> Self {
        Integer::from_i64(0)
    }
}

impl Unmarshal for Enumerated {
    fn asn1_type() -> Asn1Type {
        Asn1Type::universal(TAG_ENUM)
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        Ok(Enumerated(i64::from(parse_i32(e.bytes)?)))
    }
    fn zero() -> Self {
        Enumerated(0)
    }
    fn default_value(value: i64) -> Option<Self> {
        Some(Enumerated(value))
    }
}

impl Unmarshal for Flag {
    fn asn1_type() -> Asn1Type {
        Asn1Type::Flag
    }
    fn decode(_: &Element<'_>) -> Result<Self, Error> {
        Ok(Flag(true))
    }
    fn zero() -> Self {
        Flag(false)
    }
    fn empty_explicit() -> Option<Self> {
        Some(Flag(true))
    }
}

impl Unmarshal for Null {
    fn asn1_type() -> Asn1Type {
        Asn1Type::universal(TAG_NULL)
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        if e.bytes.is_empty() {
            Ok(Null)
        } else {
            Err(Error::syntax("invalid NULL"))
        }
    }
    fn zero() -> Self {
        Null
    }
}

impl Unmarshal for BitString {
    fn asn1_type() -> Asn1Type {
        Asn1Type::universal(TAG_BIT_STRING)
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        parse_bit_string(e.bytes)
    }
    fn zero() -> Self {
        BitString::default()
    }
}

impl Unmarshal for ObjectIdentifier {
    fn asn1_type() -> Asn1Type {
        Asn1Type::universal(TAG_OID)
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        parse_object_identifier(e.bytes)
    }
    fn zero() -> Self {
        ObjectIdentifier::default()
    }
}

/// OCTET STRING.
impl Unmarshal for Vec<u8> {
    fn asn1_type() -> Asn1Type {
        Asn1Type::universal(TAG_OCTET_STRING)
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        Ok(e.bytes.to_vec())
    }
    fn zero() -> Self {
        Vec::new()
    }
}

/// SEQUENCE OF.
impl<T: Unmarshal> Unmarshal for Vec<T> {
    fn asn1_type() -> Asn1Type {
        Asn1Type::SEQUENCE
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        decode_sequence_of(&Typed::<T>::new(), e)
    }
    fn zero() -> Self {
        Vec::new()
    }
}

/// SET OF (Go's slice types whose name ends in `SET`).
impl<T: Unmarshal> Unmarshal for SetOf<T> {
    fn asn1_type() -> Asn1Type {
        Asn1Type::SET
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        decode_sequence_of(&Typed::<T>::new(), e).map(SetOf)
    }
    fn zero() -> Self {
        SetOf(Vec::new())
    }
}

pub(crate) fn decode_string(universal_tag: u32, bytes: &[u8]) -> Result<String, Error> {
    match universal_tag {
        TAG_PRINTABLE_STRING => parse_printable(bytes),
        TAG_NUMERIC_STRING => parse_numeric(bytes),
        TAG_IA5_STRING => parse_ia5(bytes),
        TAG_T61_STRING | TAG_GENERAL_STRING => Ok(parse_t61(bytes)),
        TAG_UTF8_STRING => parse_utf8(bytes),
        TAG_BMP_STRING => parse_bmp(bytes),
        _ => Err(Error::syntax("internal error: unknown string type")),
    }
}

impl Unmarshal for String {
    fn asn1_type() -> Asn1Type {
        Asn1Type::String
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        decode_string(e.universal_tag, e.bytes)
    }
    fn zero() -> Self {
        String::new()
    }
}

impl Unmarshal for DateTime {
    fn asn1_type() -> Asn1Type {
        Asn1Type::Time
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        if e.universal_tag == TAG_UTC_TIME {
            parse_utc_time(e.bytes)
        } else {
            parse_generalized_time(e.bytes)
        }
    }
    fn zero() -> Self {
        zero_time()
    }
}

impl Unmarshal for RawValue {
    fn asn1_type() -> Asn1Type {
        Asn1Type::Raw
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        Ok(RawValue {
            class: e.class,
            tag: e.tag,
            is_compound: e.is_compound,
            bytes: e.bytes.to_vec(),
            full_bytes: e.full_bytes.to_vec(),
        })
    }
    fn zero() -> Self {
        RawValue::default()
    }
}

/// A dynamically typed value, like decoding into Go's `interface{}`.
///
/// Universal primitive types Go recognizes are decoded; every other element
/// (compound, non-universal or unknown tags) is consumed and yields
/// [`Any::Other`], which corresponds to Go leaving the interface nil.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Any {
    Bool(bool),
    Integer(i64),
    BitString(BitString),
    ObjectIdentifier(ObjectIdentifier),
    Time(DateTime),
    String(String),
    OctetString(Vec<u8>),
    Other,
}

impl Unmarshal for Any {
    fn asn1_type() -> Asn1Type {
        Asn1Type::Any
    }
    fn decode(e: &Element<'_>) -> Result<Self, Error> {
        if e.is_compound || e.class != Class::Universal {
            return Ok(Any::Other);
        }
        let b = e.bytes;
        Ok(match e.tag {
            TAG_BOOLEAN => Any::Bool(parse_bool(b)?),
            TAG_PRINTABLE_STRING | TAG_NUMERIC_STRING | TAG_IA5_STRING | TAG_T61_STRING
            | TAG_UTF8_STRING | TAG_BMP_STRING => Any::String(decode_string(e.tag, b)?),
            TAG_INTEGER => Any::Integer(parse_i64(b)?),
            TAG_BIT_STRING => Any::BitString(parse_bit_string(b)?),
            TAG_OID => Any::ObjectIdentifier(parse_object_identifier(b)?),
            TAG_UTC_TIME => Any::Time(parse_utc_time(b)?),
            TAG_GENERALIZED_TIME => Any::Time(parse_generalized_time(b)?),
            TAG_OCTET_STRING => Any::OctetString(b.to_vec()),
            _ => Any::Other,
        })
    }
    fn zero() -> Self {
        Any::Other
    }
}
