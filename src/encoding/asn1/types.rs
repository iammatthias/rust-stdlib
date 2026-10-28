//! Value types and content-octet parsers for the universal primitives.
use super::{Class, Error};
use std::fmt;
use std::str::FromStr;

// BOOLEAN

pub(crate) fn parse_bool(bytes: &[u8]) -> Result<bool, Error> {
    match bytes {
        [0] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(Error::syntax("invalid boolean")),
    }
}

// INTEGER

/// Go's checkInteger: non-empty and minimally encoded.
pub(crate) fn check_integer(bytes: &[u8]) -> Result<(), Error> {
    match bytes {
        [] => Err(Error::structural("empty integer")),
        [0, b, ..] if b & 0x80 == 0 => Err(Error::structural("integer not minimally-encoded")),
        [0xff, b, ..] if b & 0x80 != 0 => Err(Error::structural("integer not minimally-encoded")),
        _ => Ok(()),
    }
}

pub(crate) fn parse_i64(bytes: &[u8]) -> Result<i64, Error> {
    check_integer(bytes)?;
    if bytes.len() > 8 {
        return Err(Error::structural("integer too large"));
    }
    let mut value: i64 = if bytes[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in bytes {
        value = (value << 8) | i64::from(b);
    }
    Ok(value)
}

pub(crate) fn parse_i32(bytes: &[u8]) -> Result<i32, Error> {
    i32::try_from(parse_i64(bytes)?).map_err(|_| Error::structural("integer too large"))
}

/// Go's int64Encoder: the shortest two's-complement big-endian form.
pub(crate) fn append_i64(out: &mut Vec<u8>, value: i64) {
    let mut n = 1;
    let mut v = value;
    while v > 127 {
        n += 1;
        v >>= 8;
    }
    while v < -128 {
        n += 1;
        v >>= 8;
    }
    for j in (0..n).rev() {
        out.push((value >> (j * 8)) as u8);
    }
}

/// An arbitrary-precision INTEGER held as minimal big-endian two's-complement
/// octets (Go's `*big.Int`). Zero is a single `0x00` octet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Integer(Vec<u8>);

impl Integer {
    /// Wraps DER content octets, rejecting empty or non-minimal encodings.
    pub fn from_twos_complement(bytes: &[u8]) -> Result<Self, Error> {
        check_integer(bytes)?;
        Ok(Self(bytes.to_vec()))
    }
    /// Builds a non-negative integer from an unsigned big-endian magnitude,
    /// stripping leading zeros and adding a 0x00 sign octet when needed.
    pub fn from_unsigned_bytes(magnitude: &[u8]) -> Self {
        let start = magnitude
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(magnitude.len());
        let digits = &magnitude[start..];
        let mut out = Vec::with_capacity(digits.len() + 1);
        if digits.first().is_none_or(|&b| b & 0x80 != 0) {
            out.push(0);
        }
        out.extend_from_slice(digits);
        Self(out)
    }
    pub fn from_i64(value: i64) -> Self {
        let mut out = Vec::with_capacity(8);
        append_i64(&mut out, value);
        Self(out)
    }
    /// The value when it fits in an `i64`.
    pub fn to_i64(&self) -> Option<i64> {
        parse_i64(&self.0).ok()
    }
    /// Minimal two's-complement big-endian octets (the DER content).
    pub fn as_twos_complement(&self) -> &[u8] {
        &self.0
    }
    pub fn is_negative(&self) -> bool {
        self.0[0] & 0x80 != 0
    }
}

impl From<i64> for Integer {
    fn from(value: i64) -> Self {
        Self::from_i64(value)
    }
}

/// An ENUMERATED value. Go parses it with 32-bit range and encodes 64 bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Enumerated(pub i64);

/// Go's `asn1.Flag`: decodes to `true` whenever the field is present. It is
/// encoded as a BOOLEAN with empty contents, typically under an explicit tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Flag(pub bool);

/// The ASN.1 NULL value. Go has no NULL type (it uses `NullRawValue`); this
/// type requires empty contents on decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Null;

/// DER encoding of NULL (Go's `NullBytes`).
pub const NULL_BYTES: [u8; 2] = [super::TAG_NULL as u8, 0];

// BIT STRING

/// A BIT STRING: bits packed most-significant first; padding bits are zero
/// when decoded.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct BitString {
    pub bytes: Vec<u8>,
    pub bit_length: usize,
}

impl BitString {
    pub fn new(bytes: Vec<u8>, bit_length: usize) -> Self {
        Self { bytes, bit_length }
    }
    /// The bit at `index`, or 0 when out of range.
    pub fn at(&self, index: usize) -> u8 {
        if index >= self.bit_length {
            return 0;
        }
        self.bytes
            .get(index / 8)
            .map_or(0, |b| (b >> (7 - index % 8)) & 1)
    }
    /// The bits shifted so that padding is at the start (Go's `RightAlign`).
    pub fn right_align(&self) -> Vec<u8> {
        let shift = 8 - (self.bit_length % 8);
        if shift == 8 || self.bytes.is_empty() {
            return self.bytes.clone();
        }
        let mut a = Vec::with_capacity(self.bytes.len());
        a.push(self.bytes[0] >> shift);
        for pair in self.bytes.windows(2) {
            a.push((pair[0] << (8 - shift)) | (pair[1] >> shift));
        }
        a
    }
}

pub(crate) fn parse_bit_string(bytes: &[u8]) -> Result<BitString, Error> {
    let Some((&padding, data)) = bytes.split_first() else {
        return Err(Error::syntax("zero length BIT STRING"));
    };
    if padding > 7
        || (data.is_empty() && padding > 0)
        || bytes[bytes.len() - 1] & ((1u8 << padding) - 1) != 0
    {
        return Err(Error::syntax("invalid padding bits in BIT STRING"));
    }
    Ok(BitString {
        bytes: data.to_vec(),
        bit_length: data.len() * 8 - usize::from(padding),
    })
}

// OBJECT IDENTIFIER

/// An OBJECT IDENTIFIER. Arcs are `i64` like Go's 64-bit `int`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct ObjectIdentifier(pub Vec<i64>);

impl ObjectIdentifier {
    pub fn new(arcs: impl Into<Vec<i64>>) -> Self {
        Self(arcs.into())
    }
    pub fn arcs(&self) -> &[i64] {
        &self.0
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arc) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

impl FromStr for ObjectIdentifier {
    type Err = Error;
    /// Parses dotted decimal such as `1.2.840.113549`.
    fn from_str(s: &str) -> Result<Self, Error> {
        let mut arcs = Vec::new();
        for part in s.split('.') {
            if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::syntax("invalid object identifier text"));
            }
            arcs.push(
                part.parse()
                    .map_err(|_| Error::syntax("invalid object identifier text"))?,
            );
        }
        Ok(Self(arcs))
    }
}

pub(crate) fn parse_object_identifier(bytes: &[u8]) -> Result<ObjectIdentifier, Error> {
    if bytes.is_empty() {
        return Err(Error::syntax("zero length OBJECT IDENTIFIER"));
    }
    let mut arcs = Vec::with_capacity(bytes.len() + 1);
    let (v, mut offset) = super::der::parse_base128(bytes, 0)?;
    let v = i64::from(v);
    if v < 80 {
        arcs.push(v / 40);
        arcs.push(v % 40);
    } else {
        arcs.push(2);
        arcs.push(v - 80);
    }
    while offset < bytes.len() {
        let (v, next) = super::der::parse_base128(bytes, offset)?;
        arcs.push(i64::from(v));
        offset = next;
    }
    Ok(ObjectIdentifier(arcs))
}

/// Go's makeObjectIdentifier, except negative arcs and an overflowing first
/// subidentifier are rejected (Go silently emits no octets for them).
pub(crate) fn append_object_identifier(
    out: &mut Vec<u8>,
    oid: &ObjectIdentifier,
) -> Result<(), Error> {
    let a = &oid.0;
    if a.len() < 2 || a[0] > 2 || (a[0] < 2 && a[1] >= 40) {
        return Err(Error::structural("invalid object identifier"));
    }
    if a.iter().any(|&arc| arc < 0) {
        return Err(Error::structural("negative object identifier arc"));
    }
    let first = a[0]
        .checked_mul(40)
        .and_then(|v| v.checked_add(a[1]))
        .ok_or(Error::structural("invalid object identifier"))?;
    super::der::append_base128(out, first as u64);
    for &arc in &a[2..] {
        super::der::append_base128(out, arc as u64);
    }
    Ok(())
}

// Character strings

pub(crate) fn is_numeric(b: u8) -> bool {
    b.is_ascii_digit() || b == b' '
}

pub(crate) fn is_printable(b: u8, asterisk: bool, ampersand: bool) -> bool {
    b.is_ascii_alphanumeric()
        || (b'\''..=b')').contains(&b)
        || (b'+'..=b'/').contains(&b)
        || matches!(b, b' ' | b':' | b'=' | b'?')
        || (asterisk && b == b'*')
        || (ampersand && b == b'&')
}

pub(crate) fn parse_printable(bytes: &[u8]) -> Result<String, Error> {
    if !bytes.iter().all(|&b| is_printable(b, true, true)) {
        return Err(Error::syntax("PrintableString contains invalid character"));
    }
    Ok(bytes.iter().map(|&b| char::from(b)).collect())
}

pub(crate) fn parse_numeric(bytes: &[u8]) -> Result<String, Error> {
    if !bytes.iter().all(|&b| is_numeric(b)) {
        return Err(Error::syntax("NumericString contains invalid character"));
    }
    Ok(bytes.iter().map(|&b| char::from(b)).collect())
}

pub(crate) fn parse_ia5(bytes: &[u8]) -> Result<String, Error> {
    if !bytes.is_ascii() {
        return Err(Error::syntax("IA5String contains invalid character"));
    }
    Ok(bytes.iter().map(|&b| char::from(b)).collect())
}

/// T61String and GeneralString are decoded as Latin-1, as Go does.
pub(crate) fn parse_t61(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

pub(crate) fn parse_utf8(bytes: &[u8]) -> Result<String, Error> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::string("invalid UTF-8 string"))
}

fn bmp_unit_allowed(unit: u16) -> bool {
    !(unit == 0xfffe || unit == 0xffff || (0xfdd0..=0xfdef).contains(&unit))
        && !(0xd800..=0xdfff).contains(&unit)
}

/// UCS-2 big-endian; a trailing 00 00 terminator is stripped, surrogates and
/// permanent noncharacters are rejected.
pub(crate) fn parse_bmp(bytes: &[u8]) -> Result<String, Error> {
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::string("invalid BMPString"));
    }
    let mut bytes = bytes;
    if bytes.ends_with(&[0, 0]) {
        bytes = &bytes[..bytes.len() - 2];
    }
    let mut out = String::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let unit = u16::from_be_bytes([pair[0], pair[1]]);
        if !bmp_unit_allowed(unit) {
            return Err(Error::string("invalid BMPString"));
        }
        out.push(char::from_u32(u32::from(unit)).ok_or(Error::string("invalid BMPString"))?);
    }
    Ok(out)
}

pub(crate) fn append_t61(out: &mut Vec<u8>, s: &str) -> Result<(), Error> {
    for c in s.chars() {
        out.push(
            u8::try_from(u32::from(c))
                .map_err(|_| Error::structural("T61String contains invalid character"))?,
        );
    }
    Ok(())
}

pub(crate) fn append_bmp(out: &mut Vec<u8>, s: &str) -> Result<(), Error> {
    for c in s.chars() {
        let unit = u16::try_from(u32::from(c))
            .ok()
            .filter(|&u| bmp_unit_allowed(u))
            .ok_or(Error::structural("BMPString contains invalid character"))?;
        out.extend_from_slice(&unit.to_be_bytes());
    }
    Ok(())
}

// Raw values

/// An undecoded ASN.1 element (Go's `RawValue`).
///
/// When marshaling, a non-empty `full_bytes` is written verbatim; otherwise a
/// header is built from `class`, `tag`, `is_compound` and `bytes`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct RawValue {
    pub class: Class,
    pub tag: u32,
    pub is_compound: bool,
    /// Content octets.
    pub bytes: Vec<u8>,
    /// Identifier, length and content octets as they appeared on the wire.
    pub full_bytes: Vec<u8>,
}

impl RawValue {
    /// Go's `NullRawValue`.
    pub fn null() -> Self {
        Self {
            tag: super::TAG_NULL,
            ..Self::default()
        }
    }
}
