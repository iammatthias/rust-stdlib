//! The structure checks of Go's `encoding/asn1.Unmarshal`, with its messages.
//!
//! `crypto/x509` hands several encodings (PKCS #1, PKCS #8, SEC 1 and PKIX
//! keys, certificate requests and the deprecated CRL type) to
//! `asn1.Unmarshal`, whose errors are part of what Go returns. This module
//! ports `parseField` and its helpers for the struct shapes x509 uses
//! (described by [`Ty`]), so that a malformed encoding is rejected with the
//! same text. Values are not kept: callers read them with [`super::asn1::Reader`]
//! once the encoding is known to be well formed. This is encoding, not
//! cryptography.

use std::fmt::Write as _;

/// A Go type as `asn1.Unmarshal` sees it.
#[derive(Clone, Copy)]
pub(crate) enum Ty {
    /// `asn1.RawValue`.
    Raw,
    /// `any`.
    Any,
    /// `int`.
    Int,
    /// `*big.Int`.
    Big,
    /// `bool`.
    Bool,
    /// `[]byte`.
    Octets,
    /// `asn1.ObjectIdentifier`.
    Oid,
    /// `asn1.BitString`.
    Bits,
    /// `time.Time`.
    Time,
    /// A struct type.
    Struct(&'static Struct),
    /// A slice type other than `[]byte`.
    Slice(&'static Slice),
}

/// A struct type: its Go name and its fields (a leading `asn1.RawContent`
/// field is left out).
pub(crate) struct Struct {
    pub name: &'static str,
    pub fields: &'static [Field],
}

/// A slice type: its Go name (empty for an unnamed type) and element type.
pub(crate) struct Slice {
    pub name: &'static str,
    pub elem: Ty,
}

/// A struct field and its `asn1` tag.
pub(crate) struct Field {
    pub ty: Ty,
    pub params: Params,
}

/// Go's `fieldParameters`, for the options x509 uses.
#[derive(Clone, Copy)]
pub(crate) struct Params {
    pub optional: bool,
    pub explicit: bool,
    pub has_default: bool,
    pub tag: Option<i64>,
    pub omit_empty: bool,
    pub set: bool,
}

impl Params {
    /// No `asn1` tag.
    pub const NONE: Params = Params {
        optional: false,
        explicit: false,
        has_default: false,
        tag: None,
        omit_empty: false,
        set: false,
    };
    /// `asn1:"optional"`.
    pub const OPTIONAL: Params = Params {
        optional: true,
        ..Params::NONE
    };
    /// `asn1:"set"`.
    pub const SET: Params = Params {
        set: true,
        ..Params::NONE
    };
    /// `asn1:"tag:n"`.
    pub const fn tag(n: i64) -> Params {
        Params {
            tag: Some(n),
            ..Params::NONE
        }
    }
    /// `asn1:"optional,explicit,tag:n"`.
    pub const fn optional_explicit(n: i64) -> Params {
        Params {
            optional: true,
            explicit: true,
            tag: Some(n),
            ..Params::NONE
        }
    }

    /// `%+v` of Go's `fieldParameters`. A non-nil pointer prints as an
    /// address in Go; `0xc000000000` stands in for it.
    fn go_string(&self) -> String {
        let pointer = |set: bool| if set { "0xc000000000" } else { "<nil>" };
        format!(
            "{{optional:{} explicit:{} application:false private:false defaultValue:{} tag:{} stringType:0 timeType:0 set:{} omitEmpty:{}}}",
            self.optional,
            self.explicit,
            pointer(self.has_default),
            pointer(self.tag.is_some()),
            self.set,
            self.omit_empty
        )
    }
}

const CLASS_UNIVERSAL: i64 = 0;
const CLASS_CONTEXT: i64 = 2;

const TAG_BOOLEAN: i64 = 1;
const TAG_INTEGER: i64 = 2;
const TAG_BIT_STRING: i64 = 3;
const TAG_OCTET_STRING: i64 = 4;
const TAG_OID: i64 = 6;
const TAG_UTF8_STRING: i64 = 12;
const TAG_SEQUENCE: i64 = 16;
const TAG_SET: i64 = 17;
const TAG_NUMERIC_STRING: i64 = 18;
const TAG_PRINTABLE_STRING: i64 = 19;
const TAG_T61_STRING: i64 = 20;
const TAG_IA5_STRING: i64 = 22;
const TAG_UTC_TIME: i64 = 23;
const TAG_GENERALIZED_TIME: i64 = 24;
const TAG_GENERAL_STRING: i64 = 27;
const TAG_BMP_STRING: i64 = 30;

fn structural(msg: &str) -> String {
    format!("asn1: structure error: {msg}")
}

fn syntax(msg: &str) -> String {
    format!("asn1: syntax error: {msg}")
}

/// `asn1.Unmarshal(b, &v)` for a value of type `ty`: the number of bytes of
/// `b` it consumed, or Go's error text.
pub(crate) fn unmarshal(b: &[u8], ty: Ty) -> Result<usize, String> {
    unmarshal_value(b, ty).map(|(used, _)| used)
}

/// [`unmarshal`] with the parsed value.
pub(crate) fn unmarshal_value(b: &[u8], ty: Ty) -> Result<(usize, Value<'_>), String> {
    parse_field(ty, &Params::NONE, b, 0, 0)
}

/// Reports whether `asn1.Unmarshal(b, &v)` succeeds, whatever it leaves over.
pub(crate) fn accepts(b: &[u8], ty: Ty) -> bool {
    unmarshal(b, ty).is_ok()
}

struct TagAndLength {
    class: i64,
    tag: i64,
    length: i64,
    is_compound: bool,
}

impl TagAndLength {
    fn go_string(&self) -> String {
        format!(
            "{{class:{} tag:{} length:{} isCompound:{}}}",
            self.class, self.tag, self.length, self.is_compound
        )
    }
}

fn parse_base128_int(bytes: &[u8], init_offset: usize) -> Result<(i64, usize), String> {
    let mut offset = init_offset;
    let mut ret64: i64 = 0;
    let mut shifted = 0;
    while offset < bytes.len() {
        // 5 * 7 bits per byte == 35 bits of data
        if shifted == 5 {
            return Err(structural("base 128 integer too large"));
        }
        ret64 <<= 7;
        let b = bytes[offset];
        // integers should be minimally encoded, so the leading octet should
        // never be 0x80
        if shifted == 0 && b == 0x80 {
            return Err(syntax("integer is not minimally encoded"));
        }
        ret64 |= i64::from(b & 0x7f);
        offset += 1;
        if b & 0x80 == 0 {
            if ret64 > i64::from(i32::MAX) {
                return Err(structural("base 128 integer too large"));
            }
            return Ok((ret64, offset));
        }
        shifted += 1;
    }
    Err(syntax("truncated base 128 integer"))
}

fn parse_tag_and_length(bytes: &[u8], init_offset: usize) -> Result<(TagAndLength, usize), String> {
    let mut offset = init_offset;
    let b = bytes[offset];
    offset += 1;
    let class = i64::from(b >> 6);
    let is_compound = b & 0x20 == 0x20;
    let mut tag = i64::from(b & 0x1f);
    // If the bottom five bits are set, then the tag number is actually base 128
    // encoded afterwards
    if tag == 0x1f {
        let (value, next) = parse_base128_int(bytes, offset)?;
        tag = value;
        offset = next;
        // Tags should be encoded in minimal form.
        if tag < 0x1f {
            return Err(syntax("non-minimal tag"));
        }
    }
    if offset >= bytes.len() {
        return Err(syntax("truncated tag or length"));
    }
    let b = bytes[offset];
    offset += 1;
    let length = if b & 0x80 == 0 {
        // The length is encoded in the bottom 7 bits.
        i64::from(b & 0x7f)
    } else {
        // Bottom 7 bits give the number of length bytes to follow.
        let num_bytes = usize::from(b & 0x7f);
        if num_bytes == 0 {
            return Err(syntax("indefinite length found (not DER)"));
        }
        let mut value: i64 = 0;
        for _ in 0..num_bytes {
            if offset >= bytes.len() {
                return Err(syntax("truncated tag or length"));
            }
            let b = bytes[offset];
            offset += 1;
            if value >= 1 << 23 {
                // We can't shift the length up without overflowing.
                return Err(structural("length too large"));
            }
            value <<= 8;
            value |= i64::from(b);
            if value == 0 {
                // DER requires that lengths be minimal.
                return Err(structural("superfluous leading zeros in length"));
            }
        }
        // Short lengths must be encoded in short form.
        if value < 0x80 {
            return Err(structural("non-minimal length"));
        }
        value
    };
    Ok((
        TagAndLength {
            class,
            tag,
            length,
            is_compound,
        },
        offset,
    ))
}

/// Go's `invalidLength`: whether `offset + length` passes `slice_length`.
fn invalid_length(offset: usize, length: i64, slice_length: usize) -> bool {
    match usize::try_from(length)
        .ok()
        .and_then(|length| offset.checked_add(length))
    {
        Some(end) => end > slice_length,
        None => true,
    }
}

fn check_integer(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err(structural("empty integer"));
    }
    if bytes.len() == 1 {
        return Ok(());
    }
    if (bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 == 0x80) {
        return Err(structural("integer not minimally-encoded"));
    }
    Ok(())
}

fn parse_int64(bytes: &[u8]) -> Result<(), String> {
    check_integer(bytes)?;
    if bytes.len() > 8 {
        // We'll overflow an int64 in this case.
        return Err(structural("integer too large"));
    }
    Ok(())
}

fn parse_bool(bytes: &[u8]) -> Result<(), String> {
    match bytes {
        [0] | [0xff] => Ok(()),
        _ => Err(syntax("invalid boolean")),
    }
}

fn parse_bit_string(bytes: &[u8]) -> Result<(), String> {
    let Some(&padding) = bytes.first() else {
        return Err(syntax("zero length BIT STRING"));
    };
    if padding > 7
        || bytes.len() == 1 && padding > 0
        || bytes[bytes.len() - 1] & ((1u8 << padding) - 1) != 0
    {
        return Err(syntax("invalid padding bits in BIT STRING"));
    }
    Ok(())
}

fn parse_object_identifier(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err(syntax("zero length OBJECT IDENTIFIER"));
    }
    let (_, mut offset) = parse_base128_int(bytes, 0)?;
    while offset < bytes.len() {
        offset = parse_base128_int(bytes, offset)?.1;
    }
    Ok(())
}

fn parse_numeric_string(bytes: &[u8]) -> Result<(), String> {
    if bytes.iter().all(|&b| b.is_ascii_digit() || b == b' ') {
        Ok(())
    } else {
        Err(syntax("NumericString contains invalid character"))
    }
}

fn is_printable(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || (b'\''..=b')').contains(&b)
        || (b'+'..=b'/').contains(&b)
        || matches!(b, b' ' | b':' | b'=' | b'?' | b'*' | b'&')
}

fn parse_printable_string(bytes: &[u8]) -> Result<(), String> {
    if bytes.iter().all(|&b| is_printable(b)) {
        Ok(())
    } else {
        Err(syntax("PrintableString contains invalid character"))
    }
}

fn parse_ia5_string(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_ascii() {
        Ok(())
    } else {
        Err(syntax("IA5String contains invalid character"))
    }
}

fn parse_utf8_string(bytes: &[u8]) -> Result<(), String> {
    if std::str::from_utf8(bytes).is_ok() {
        Ok(())
    } else {
        Err("asn1: invalid UTF-8 string".to_string())
    }
}

fn parse_bmp_string(bmp: &[u8]) -> Result<(), String> {
    if !bmp.len().is_multiple_of(2) {
        return Err("invalid BMPString".to_string());
    }
    // Strip terminator if present.
    let bmp = match bmp.len() {
        l if l >= 2 && bmp[l - 1] == 0 && bmp[l - 2] == 0 => &bmp[..l - 2],
        _ => bmp,
    };
    for pair in bmp.chunks(2) {
        let point = u16::from(pair[0]) << 8 | u16::from(pair[1]);
        if point == 0xfffe
            || point == 0xffff
            || (0xfdd0..=0xfdef).contains(&point)
            || (0xd800..=0xdfff).contains(&point)
        {
            return Err("invalid BMPString".to_string());
        }
    }
    Ok(())
}

/// Go's `getUniversalType`: whether any tag matches, the tag number and
/// whether the element is constructed; `None` for an unsupported type.
fn universal_type(ty: Ty) -> Option<(bool, i64, bool)> {
    Some(match ty {
        Ty::Raw => (true, -1, false),
        Ty::Oid => (false, TAG_OID, false),
        Ty::Bits => (false, TAG_BIT_STRING, false),
        Ty::Time => (false, TAG_UTC_TIME, false),
        Ty::Big | Ty::Int => (false, TAG_INTEGER, false),
        Ty::Bool => (false, TAG_BOOLEAN, false),
        Ty::Struct(_) => (false, TAG_SEQUENCE, true),
        Ty::Octets => (false, TAG_OCTET_STRING, false),
        Ty::Slice(slice) if slice.name.ends_with("SET") => (false, TAG_SET, true),
        Ty::Slice(_) => (false, TAG_SEQUENCE, true),
        Ty::Any => return None,
    })
}

/// The name `reflect.Type.Name()` gives the type.
fn type_name(ty: Ty) -> &'static str {
    match ty {
        Ty::Raw => "RawValue",
        Ty::Int => "int",
        Ty::Bool => "bool",
        Ty::Oid => "ObjectIdentifier",
        Ty::Bits => "BitString",
        Ty::Time => "Time",
        Ty::Struct(s) => s.name,
        Ty::Slice(s) => s.name,
        Ty::Any | Ty::Big | Ty::Octets => "",
    }
}

/// The header and contents of a parsed element.
#[derive(Clone, Copy)]
pub(crate) struct Node<'a> {
    /// The complete element, header included.
    pub full: &'a [u8],
    /// The contents octets.
    pub content: &'a [u8],
    pub class: i64,
    pub tag: i64,
    pub is_compound: bool,
}

/// What `asn1.Unmarshal` stored for a field, as slices of the input.
pub(crate) enum Value<'a> {
    /// An optional field that was not present.
    Absent,
    /// A field without structure to follow.
    Leaf(Node<'a>),
    /// A struct and its fields (a leading `asn1.RawContent` is left out).
    Struct(Node<'a>, Vec<Value<'a>>),
    /// A slice and its elements.
    List(Node<'a>, Vec<Value<'a>>),
}

impl<'a> Value<'a> {
    /// The element, or `None` for an absent optional field.
    pub fn node(&self) -> Option<&Node<'a>> {
        match self {
            Value::Absent => None,
            Value::Leaf(n) | Value::Struct(n, _) | Value::List(n, _) => Some(n),
        }
    }

    /// The fields of a struct (empty otherwise).
    pub fn fields(&self) -> &[Value<'a>] {
        match self {
            Value::Struct(_, fields) => fields,
            _ => &[],
        }
    }

    /// The elements of a slice (empty otherwise).
    pub fn items(&self) -> &[Value<'a>] {
        match self {
            Value::List(_, items) => items,
            _ => &[],
        }
    }
}

/// Go's `parseSequenceOf`, checking the elements.
fn parse_sequence_of<'a>(
    bytes: &'a [u8],
    elem: Ty,
    depth: usize,
) -> Result<Vec<Value<'a>>, String> {
    let Some((match_any, expected_tag, compound_type)) = universal_type(elem) else {
        return Err(structural("unknown Go type for slice"));
    };
    // First we iterate over the input and count the number of elements,
    // checking that the types are correct in each case.
    let mut count = 0;
    let mut offset = 0;
    while offset < bytes.len() {
        let (mut t, next) = parse_tag_and_length(bytes, offset)?;
        offset = next;
        match t.tag {
            // We pretend that various other string types are PRINTABLE
            // STRINGs so that a sequence of them can be parsed into a
            // []string.
            TAG_IA5_STRING | TAG_GENERAL_STRING | TAG_T61_STRING | TAG_UTF8_STRING
            | TAG_NUMERIC_STRING | TAG_BMP_STRING => t.tag = TAG_PRINTABLE_STRING,
            // Likewise, both time types are treated the same.
            TAG_GENERALIZED_TIME | TAG_UTC_TIME => t.tag = TAG_UTC_TIME,
            _ => {}
        }
        if !match_any
            && (t.class != CLASS_UNIVERSAL
                || t.is_compound != compound_type
                || t.tag != expected_tag)
        {
            return Err(structural("sequence tag mismatch"));
        }
        if invalid_length(offset, t.length, bytes.len()) {
            return Err(syntax("truncated sequence"));
        }
        offset += t.length as usize;
        count += 1;
    }
    let mut offset = 0;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let (next, value) = parse_field(elem, &Params::NONE, bytes, offset, depth)?;
        offset = next;
        items.push(value);
    }
    Ok(items)
}

/// Go's `parseField`: checks the value and returns it with the offset after
/// it.
fn parse_field<'a>(
    ty: Ty,
    params: &Params,
    bytes: &'a [u8],
    init_offset: usize,
    depth: usize,
) -> Result<(usize, Value<'a>), String> {
    let depth = depth + 1;
    let mut offset = init_offset;

    // If we have run out of data, it may be that there are optional elements
    // at the end.
    if offset == bytes.len() {
        return if params.optional {
            Ok((offset, Value::Absent))
        } else {
            Err(syntax("sequence truncated"))
        };
    }

    // Deal with the ANY type.
    if let Ty::Any = ty {
        let (t, next) = parse_tag_and_length(bytes, offset)?;
        offset = next;
        if invalid_length(offset, t.length, bytes.len()) {
            return Err(syntax("data truncated"));
        }
        let end = offset + t.length as usize;
        let mut result = Ok(());
        if !t.is_compound && t.class == CLASS_UNIVERSAL {
            let inner = &bytes[offset..end];
            result = match t.tag {
                TAG_BOOLEAN => parse_bool(inner),
                TAG_PRINTABLE_STRING => parse_printable_string(inner),
                TAG_NUMERIC_STRING => parse_numeric_string(inner),
                TAG_IA5_STRING => parse_ia5_string(inner),
                TAG_UTF8_STRING => parse_utf8_string(inner),
                TAG_INTEGER => parse_int64(inner),
                TAG_BIT_STRING => parse_bit_string(inner),
                TAG_OID => parse_object_identifier(inner),
                TAG_UTC_TIME => super::asn1_time::parse_utc_time(inner).map(drop),
                TAG_GENERALIZED_TIME => super::asn1_time::parse_generalized_time(inner).map(drop),
                TAG_BMP_STRING => parse_bmp_string(inner),
                // OCTET STRING and T61String cannot fail; other tags are
                // left as nil.
                _ => Ok(()),
            };
        }
        result?;
        let node = Node {
            full: &bytes[init_offset..end],
            content: &bytes[offset..end],
            class: t.class,
            tag: t.tag,
            is_compound: t.is_compound,
        };
        return Ok((end, Value::Leaf(node)));
    }

    let (mut t, next) = parse_tag_and_length(bytes, offset)?;
    offset = next;
    let mut tlv_start = init_offset;
    if params.explicit {
        if offset == bytes.len() {
            return Err(structural("explicit tag has no child"));
        }
        if t.class == CLASS_CONTEXT && Some(t.tag) == params.tag && (t.length == 0 || t.is_compound)
        {
            if let Ty::Raw = ty {
                // The inner element should not be parsed for RawValues.
            } else if t.length > 0 {
                tlv_start = offset;
                let (inner, next) = parse_tag_and_length(bytes, offset)?;
                t = inner;
                offset = next;
            } else {
                return Err(structural("zero length explicit tag was not an asn1.Flag"));
            }
        } else if params.optional {
            // The tags didn't match, it is an optional element.
            return Ok((init_offset, Value::Absent));
        } else {
            return Err(structural("explicitly tagged member didn't match"));
        }
    }

    let (match_any, mut universal_tag, compound_type) =
        universal_type(ty).ok_or_else(|| structural("unknown Go type"))?;

    // Special case for time: UTCTime and GeneralizedTime both map to the Go
    // type time.Time.
    if universal_tag == TAG_UTC_TIME && t.class == CLASS_UNIVERSAL && t.tag == TAG_GENERALIZED_TIME
    {
        universal_tag = t.tag;
    }

    if params.set {
        universal_tag = TAG_SET;
    }

    let mut match_any_class_and_tag = match_any;
    let mut expected_class = CLASS_UNIVERSAL;
    let mut expected_tag = universal_tag;
    if !params.explicit {
        if let Some(tag) = params.tag {
            expected_class = CLASS_CONTEXT;
            expected_tag = tag;
            match_any_class_and_tag = false;
        }
    }

    // We have unwrapped any explicit tagging at this point.
    if !match_any_class_and_tag && (t.class != expected_class || t.tag != expected_tag)
        || (!match_any && t.is_compound != compound_type)
    {
        // Tags don't match. Again, it could be an optional element.
        if params.optional {
            return Ok((init_offset, Value::Absent));
        }
        let mut msg = String::new();
        let _ = write!(
            msg,
            "tags don't match ({expected_tag} vs {}) {} {} @{offset}",
            t.go_string(),
            params.go_string(),
            type_name(ty)
        );
        return Err(structural(&msg));
    }
    if invalid_length(offset, t.length, bytes.len()) {
        return Err(syntax("data truncated"));
    }
    let end = offset + t.length as usize;
    let inner = &bytes[offset..end];
    let node = Node {
        full: &bytes[tlv_start..end],
        content: inner,
        class: t.class,
        tag: t.tag,
        is_compound: t.is_compound,
    };

    let value = match ty {
        Ty::Raw | Ty::Octets => Value::Leaf(node),
        Ty::Oid => {
            parse_object_identifier(inner)?;
            Value::Leaf(node)
        }
        Ty::Bits => {
            parse_bit_string(inner)?;
            Value::Leaf(node)
        }
        Ty::Time => {
            if universal_tag == TAG_UTC_TIME {
                super::asn1_time::parse_utc_time(inner)?;
            } else {
                super::asn1_time::parse_generalized_time(inner)?;
            }
            Value::Leaf(node)
        }
        Ty::Big => {
            check_integer(inner)?;
            Value::Leaf(node)
        }
        Ty::Int => {
            parse_int64(inner)?;
            Value::Leaf(node)
        }
        Ty::Bool => {
            parse_bool(inner)?;
            Value::Leaf(node)
        }
        Ty::Struct(s) => {
            let mut inner_offset = 0;
            let mut fields = Vec::with_capacity(s.fields.len());
            for field in s.fields {
                let (next, value) =
                    parse_field(field.ty, &field.params, inner, inner_offset, depth)?;
                inner_offset = next;
                fields.push(value);
            }
            // We allow extra bytes at the end of the SEQUENCE because adding
            // elements to the end has been used in X.509 as the version
            // numbers have increased.
            Value::Struct(node, fields)
        }
        Ty::Slice(s) => Value::List(node, parse_sequence_of(inner, s.elem, depth)?),
        Ty::Any => unreachable!("handled above"),
    };
    Ok((end, value))
}

/// The encoding/asn1 shapes of `crypto/x509` and `crypto/x509/pkix`.
pub(crate) mod shapes {
    use super::{Field, Params, Slice, Struct, Ty};

    const fn f(ty: Ty) -> Field {
        Field {
            ty,
            params: Params::NONE,
        }
    }

    const fn fp(ty: Ty, params: Params) -> Field {
        Field { ty, params }
    }

    /// `pkix.AlgorithmIdentifier`.
    pub static ALGORITHM_IDENTIFIER: Struct = Struct {
        name: "AlgorithmIdentifier",
        fields: &[f(Ty::Oid), fp(Ty::Raw, Params::OPTIONAL)],
    };

    static ADDITIONAL_PRIME: Struct = Struct {
        name: "pkcs1AdditionalRSAPrime",
        fields: &[f(Ty::Big), f(Ty::Big), f(Ty::Big)],
    };
    static ADDITIONAL_PRIMES: Slice = Slice {
        name: "",
        elem: Ty::Struct(&ADDITIONAL_PRIME),
    };

    /// `pkcs1PrivateKey`.
    pub static PKCS1_PRIVATE_KEY: Struct = Struct {
        name: "pkcs1PrivateKey",
        fields: &[
            f(Ty::Int),
            f(Ty::Big),
            f(Ty::Int),
            f(Ty::Big),
            f(Ty::Big),
            f(Ty::Big),
            fp(Ty::Big, Params::OPTIONAL),
            fp(Ty::Big, Params::OPTIONAL),
            fp(Ty::Big, Params::OPTIONAL),
            fp(
                Ty::Slice(&ADDITIONAL_PRIMES),
                Params {
                    optional: true,
                    omit_empty: true,
                    ..Params::NONE
                },
            ),
        ],
    };

    /// `pkcs1PublicKey`.
    pub static PKCS1_PUBLIC_KEY: Struct = Struct {
        name: "pkcs1PublicKey",
        fields: &[f(Ty::Big), f(Ty::Int)],
    };

    /// `pkcs8`.
    pub static PKCS8: Struct = Struct {
        name: "pkcs8",
        fields: &[
            f(Ty::Int),
            f(Ty::Struct(&ALGORITHM_IDENTIFIER)),
            f(Ty::Octets),
        ],
    };

    /// `ecPrivateKey`.
    pub static EC_PRIVATE_KEY: Struct = Struct {
        name: "ecPrivateKey",
        fields: &[
            f(Ty::Int),
            f(Ty::Octets),
            fp(Ty::Oid, Params::optional_explicit(0)),
            fp(Ty::Bits, Params::optional_explicit(1)),
        ],
    };

    /// `publicKeyInfo`.
    pub static PUBLIC_KEY_INFO: Struct = Struct {
        name: "publicKeyInfo",
        fields: &[f(Ty::Struct(&ALGORITHM_IDENTIFIER)), f(Ty::Bits)],
    };

    static RAW_VALUES: Slice = Slice {
        name: "",
        elem: Ty::Raw,
    };

    static TBS_CSR: Struct = Struct {
        name: "tbsCertificateRequest",
        fields: &[
            f(Ty::Int),
            f(Ty::Raw),
            f(Ty::Struct(&PUBLIC_KEY_INFO)),
            fp(Ty::Slice(&RAW_VALUES), Params::tag(0)),
        ],
    };

    static CSR_SIGNATURE_ALGORITHM: Struct = Struct {
        name: "",
        fields: &[f(Ty::Oid), fp(Ty::Raw, Params::OPTIONAL)],
    };

    /// `certificateRequest`.
    pub static CERTIFICATE_REQUEST: Struct = Struct {
        name: "certificateRequest",
        fields: &[
            f(Ty::Struct(&TBS_CSR)),
            f(Ty::Struct(&CSR_SIGNATURE_ALGORITHM)),
            f(Ty::Bits),
        ],
    };

    /// `pkix.Extension`.
    static EXTENSION: Struct = Struct {
        name: "Extension",
        fields: &[f(Ty::Oid), fp(Ty::Bool, Params::OPTIONAL), f(Ty::Octets)],
    };

    /// `[]pkix.Extension`.
    pub static EXTENSIONS: Slice = Slice {
        name: "",
        elem: Ty::Struct(&EXTENSION),
    };

    /// `pkcs10Attribute`.
    pub static PKCS10_ATTRIBUTE: Struct = Struct {
        name: "pkcs10Attribute",
        fields: &[f(Ty::Oid), fp(Ty::Slice(&RAW_VALUES), Params::SET)],
    };

    static ATTRIBUTE_TYPE_AND_VALUE: Struct = Struct {
        name: "AttributeTypeAndValue",
        fields: &[f(Ty::Oid), f(Ty::Any)],
    };
    static RELATIVE_DISTINGUISHED_NAME_SET: Slice = Slice {
        name: "RelativeDistinguishedNameSET",
        elem: Ty::Struct(&ATTRIBUTE_TYPE_AND_VALUE),
    };
    static ATTRIBUTE_TYPE_AND_VALUES: Slice = Slice {
        name: "",
        elem: Ty::Struct(&ATTRIBUTE_TYPE_AND_VALUE),
    };
    static ATTRIBUTE_TYPE_AND_VALUE_SETS: Slice = Slice {
        name: "",
        elem: Ty::Slice(&ATTRIBUTE_TYPE_AND_VALUES),
    };

    /// `pkix.AttributeTypeAndValueSET`.
    pub static ATTRIBUTE_TYPE_AND_VALUE_SET: Struct = Struct {
        name: "AttributeTypeAndValueSET",
        fields: &[
            f(Ty::Oid),
            fp(Ty::Slice(&ATTRIBUTE_TYPE_AND_VALUE_SETS), Params::SET),
        ],
    };

    static RDN_SEQUENCE: Slice = Slice {
        name: "RDNSequence",
        elem: Ty::Slice(&RELATIVE_DISTINGUISHED_NAME_SET),
    };

    static REVOKED_CERTIFICATE: Struct = Struct {
        name: "RevokedCertificate",
        fields: &[
            f(Ty::Big),
            f(Ty::Time),
            fp(Ty::Slice(&EXTENSIONS), Params::OPTIONAL),
        ],
    };
    static REVOKED_CERTIFICATES: Slice = Slice {
        name: "",
        elem: Ty::Struct(&REVOKED_CERTIFICATE),
    };

    static TBS_CERTIFICATE_LIST: Struct = Struct {
        name: "TBSCertificateList",
        fields: &[
            fp(
                Ty::Int,
                Params {
                    optional: true,
                    has_default: true,
                    ..Params::NONE
                },
            ),
            f(Ty::Struct(&ALGORITHM_IDENTIFIER)),
            f(Ty::Slice(&RDN_SEQUENCE)),
            f(Ty::Time),
            fp(Ty::Time, Params::OPTIONAL),
            fp(Ty::Slice(&REVOKED_CERTIFICATES), Params::OPTIONAL),
            fp(Ty::Slice(&EXTENSIONS), Params::optional_explicit(0)),
        ],
    };

    /// `pkix.CertificateList`.
    pub static CERTIFICATE_LIST: Struct = Struct {
        name: "CertificateList",
        fields: &[
            f(Ty::Struct(&TBS_CERTIFICATE_LIST)),
            f(Ty::Struct(&ALGORITHM_IDENTIFIER)),
            f(Ty::Bits),
        ],
    };
}
