//! A small DER layer for `crypto/x509`.
//!
//! Go parses certificates with `golang.org/x/crypto/cryptobyte` and builds them
//! with `encoding/asn1`. This crate cannot depend on the root crate's
//! `encoding/asn1` (docs/adr/0003), and the reviewed `der` crate is stricter
//! than cryptobyte in places that change what Go accepts, so [`Reader`]
//! reproduces cryptobyte's rules (single-byte tags, minimal definite lengths,
//! minimal integers) and the `append_*`/[`tlv`] helpers produce the DER that
//! `encoding/asn1.Marshal` produces. This is encoding, not cryptography.

use std::fmt;

use super::time::Time;
use super::Error;
use crate::bigint::Int;

pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const NULL: u8 = 0x05;
pub(crate) const OBJECT_IDENTIFIER: u8 = 0x06;
pub(crate) const ENUM: u8 = 0x0a;
pub(crate) const UTF8_STRING: u8 = 0x0c;
pub(crate) const NUMERIC_STRING: u8 = 0x12;
pub(crate) const PRINTABLE_STRING: u8 = 0x13;
pub(crate) const T61_STRING: u8 = 0x14;
pub(crate) const IA5_STRING: u8 = 0x16;
pub(crate) const UTC_TIME: u8 = 0x17;
pub(crate) const GENERALIZED_TIME: u8 = 0x18;
pub(crate) const BMP_STRING: u8 = 0x1e;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;

/// A context-specific primitive tag, `cryptobyte_asn1.Tag(n).ContextSpecific()`.
pub(crate) const fn context(n: u8) -> u8 {
    0x80 | n
}

/// A context-specific constructed tag.
pub(crate) const fn context_constructed(n: u8) -> u8 {
    0xa0 | n
}

/// Go's `asn1.ObjectIdentifier`: the components of an OBJECT IDENTIFIER that
/// fit an `int`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct ObjectIdentifier(pub Vec<i64>);

impl ObjectIdentifier {
    /// Builds an identifier from its components.
    pub fn new(arcs: impl Into<Vec<i64>>) -> ObjectIdentifier {
        ObjectIdentifier(arcs.into())
    }

    /// Go's `ObjectIdentifier.Equal`.
    pub fn equal(&self, other: &ObjectIdentifier) -> bool {
        self.0 == other.0
    }

    /// Whether the identifier equals `arcs`.
    pub(crate) fn is(&self, arcs: &[i64]) -> bool {
        self.0 == arcs
    }

    /// Go's `ObjectIdentifier.String`.
    fn string(&self) -> String {
        let mut out = String::new();
        for (index, arc) in self.0.iter().enumerate() {
            if index > 0 {
                out.push('.');
            }
            out.push_str(&arc.to_string());
        }
        out
    }
}

impl fmt::Display for ObjectIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

impl From<&[i64]> for ObjectIdentifier {
    fn from(arcs: &[i64]) -> ObjectIdentifier {
        ObjectIdentifier(arcs.to_vec())
    }
}

impl<const N: usize> From<[i64; N]> for ObjectIdentifier {
    fn from(arcs: [i64; N]) -> ObjectIdentifier {
        ObjectIdentifier(arcs.to_vec())
    }
}

/// Go's `asn1.BitString`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct BitString {
    /// The bits, padded with zero bits at the end.
    pub bytes: Vec<u8>,
    /// The length in bits.
    pub bit_length: usize,
}

impl BitString {
    /// Go's `BitString.At`: the bit at `i`, or 0 outside the string.
    pub fn at(&self, i: usize) -> u8 {
        if i >= self.bit_length {
            return 0;
        }
        let x = i / 8;
        let y = 7 - (i % 8);
        (self.bytes[x] >> y) & 1
    }

    /// Go's `BitString.RightAlign`.
    pub fn right_align(&self) -> Vec<u8> {
        let shift = 8 - (self.bit_length % 8) as u32;
        if shift == 8 || self.bytes.is_empty() {
            return self.bytes.clone();
        }
        let mut a = vec![0u8; self.bytes.len()];
        a[0] = self.bytes[0] >> shift;
        for (i, out) in a.iter_mut().enumerate().skip(1) {
            *out = self.bytes[i - 1] << (8 - shift);
            *out |= self.bytes[i] >> shift;
        }
        a
    }
}

/// Go's `asn1.RawValue`: an uninterpreted ASN.1 element.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct RawValue {
    /// The class, 0 to 3.
    pub class: i64,
    /// The tag number.
    pub tag: i64,
    /// Whether the encoding is constructed.
    pub is_compound: bool,
    /// The contents, without header.
    pub bytes: Vec<u8>,
    /// The complete encoding including the header.
    pub full_bytes: Vec<u8>,
}

impl RawValue {
    /// Go's `asn1.NullRawValue`.
    pub fn null() -> RawValue {
        RawValue {
            class: 0,
            tag: 5,
            is_compound: false,
            bytes: Vec::new(),
            full_bytes: vec![5, 0],
        }
    }

    /// A value holding only `full_bytes`, the way parameters are created.
    pub fn from_full_bytes(full_bytes: Vec<u8>) -> RawValue {
        RawValue {
            full_bytes,
            ..RawValue::default()
        }
    }
}

/// The DER encoding of NULL, `asn1.NullBytes`.
pub(crate) const NULL_BYTES: [u8; 2] = [5, 0];

/// An arbitrary-precision signed integer, Go's `*big.Int` as `crypto/x509`
/// uses it: the sign and a magnitude (see [`Int`]).
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct BigInt {
    negative: bool,
    magnitude: Int,
}

impl BigInt {
    /// The integer with the given value.
    pub fn from_i64(v: i64) -> BigInt {
        BigInt {
            negative: v < 0,
            magnitude: Int::from_u64(v.unsigned_abs()),
        }
    }

    /// The non-negative integer with the given big-endian bytes, like
    /// `new(big.Int).SetBytes`.
    pub fn from_be_bytes(bytes: &[u8]) -> BigInt {
        BigInt {
            negative: false,
            magnitude: Int::from_be_bytes(bytes),
        }
    }

    /// A non-negative integer.
    pub fn from_int(magnitude: Int) -> BigInt {
        BigInt {
            negative: false,
            magnitude,
        }
    }

    /// Parses a decimal string, like `big.Int.SetString(s, 10)`.
    pub fn from_decimal(s: &str) -> Option<BigInt> {
        let (negative, digits) = match s.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, s.strip_prefix('+').unwrap_or(s)),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let mut mag: Vec<u8> = Vec::new();
        for b in digits.bytes() {
            mul_add_small(&mut mag, 10, u32::from(b - b'0'));
        }
        let magnitude = Int::from_be_bytes(&mag);
        Some(BigInt {
            negative: negative && !magnitude.is_zero(),
            magnitude,
        })
    }

    /// Go's `big.Int.Sign`: -1, 0 or 1.
    pub fn sign(&self) -> i32 {
        if self.magnitude.is_zero() {
            0
        } else if self.negative {
            -1
        } else {
            1
        }
    }

    /// The absolute value, like `big.Int.Bytes`.
    pub fn bytes(&self) -> Vec<u8> {
        self.magnitude.to_be_bytes()
    }

    /// The absolute value.
    pub fn magnitude(&self) -> &Int {
        &self.magnitude
    }

    /// The value as an `i64` if it fits.
    pub fn to_i64(&self) -> Option<i64> {
        let m = self.magnitude.to_u64()?;
        if self.negative {
            if m <= i64::MAX as u64 + 1 {
                Some((m as i64).wrapping_neg())
            } else {
                None
            }
        } else {
            i64::try_from(m).ok()
        }
    }

    /// Parses minimal two's-complement DER integer contents (already
    /// validated by the caller).
    pub(crate) fn from_der_contents(bytes: &[u8]) -> BigInt {
        if bytes.first().is_some_and(|b| b & 0x80 != 0) {
            let neg: Vec<u8> = bytes.iter().map(|b| !b).collect();
            let mut mag = neg;
            mul_add_small(&mut mag, 1, 1);
            BigInt {
                negative: true,
                magnitude: Int::from_be_bytes(&mag),
            }
        } else {
            BigInt::from_be_bytes(bytes)
        }
    }

    /// The minimal two's-complement contents octets, like `asn1.makeBigInt`.
    pub(crate) fn der_contents(&self) -> Vec<u8> {
        if self.sign() == 0 {
            return vec![0];
        }
        if !self.negative {
            let mut out = Vec::new();
            let m = self.magnitude.as_be_bytes();
            if m[0] & 0x80 != 0 {
                out.push(0);
            }
            out.extend_from_slice(m);
            return out;
        }
        // -m: invert (m - 1).
        let mut m = self.magnitude.to_be_bytes();
        // m - 1
        for i in (0..m.len()).rev() {
            if m[i] == 0 {
                m[i] = 0xff;
            } else {
                m[i] -= 1;
                break;
            }
        }
        let mut out: Vec<u8> = m.iter().map(|b| !b).collect();
        if out.is_empty() || out[0] & 0x80 == 0 {
            out.insert(0, 0xff);
        }
        // Strip redundant leading 0xff bytes.
        while out.len() > 1 && out[0] == 0xff && out[1] & 0x80 != 0 {
            out.remove(0);
        }
        out
    }
}

impl fmt::Display for BigInt {
    /// Go's `big.Int.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative && self.sign() != 0 {
            f.write_str("-")?;
        }
        f.write_str(&decimal(self.magnitude.as_be_bytes()))
    }
}

impl From<i64> for BigInt {
    fn from(v: i64) -> BigInt {
        BigInt::from_i64(v)
    }
}

/// `mag = mag * mul + add` for a big-endian magnitude.
pub(crate) fn mul_add_small(mag: &mut Vec<u8>, mul: u32, add: u32) {
    let mut carry = u64::from(add);
    for byte in mag.iter_mut().rev() {
        let v = u64::from(*byte) * u64::from(mul) + carry;
        *byte = v as u8;
        carry = v >> 8;
    }
    while carry > 0 {
        mag.insert(0, carry as u8);
        carry >>= 8;
    }
}

/// The decimal text of a big-endian magnitude.
pub(crate) fn decimal(mag: &[u8]) -> String {
    let mut digits = mag.to_vec();
    while digits.first() == Some(&0) {
        digits.remove(0);
    }
    if digits.is_empty() {
        return "0".to_string();
    }
    let mut out = Vec::new();
    while !digits.is_empty() {
        let mut rem = 0u32;
        let mut quotient = Vec::with_capacity(digits.len());
        for &b in &digits {
            let cur = (rem << 8) | u32::from(b);
            let q = cur / 10;
            rem = cur % 10;
            if !(quotient.is_empty() && q == 0) {
                quotient.push(q as u8);
            }
        }
        out.push(b'0' + rem as u8);
        digits = quotient;
    }
    out.reverse();
    String::from_utf8(out).expect("ascii digits")
}

/// cryptobyte's `String`: a cursor over DER bytes whose reads fail (with
/// `None`) exactly where cryptobyte's return `false`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a>(pub &'a [u8]);

impl<'a> Reader<'a> {
    pub fn empty(&self) -> bool {
        self.0.is_empty()
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }

    /// cryptobyte's `readASN1`: returns the tag, the header length and the
    /// whole element.
    fn read_asn1(&mut self) -> Option<(u8, usize, &'a [u8])> {
        let s = self.0;
        if s.len() < 2 {
            return None;
        }
        let (tag, len_byte) = (s[0], s[1]);
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (header_len, length): (usize, usize);
        if len_byte & 0x80 == 0 {
            header_len = 2;
            length = 2 + len_byte as usize;
        } else {
            let len_len = (len_byte & 0x7f) as usize;
            if len_len == 0 || len_len > 4 || s.len() < 2 + len_len {
                return None;
            }
            let mut len32: u32 = 0;
            for &b in &s[2..2 + len_len] {
                len32 = (len32 << 8) | u32::from(b);
            }
            // DER requires the minimum number of length octets.
            if len32 < 128 {
                return None;
            }
            if len32 >> ((len_len - 1) * 8) == 0 {
                return None;
            }
            header_len = 2 + len_len;
            length = header_len.checked_add(len32 as usize)?;
        }
        let element = self.take(length)?;
        Some((tag, header_len, element))
    }

    /// `ReadAnyASN1Element`: the whole element including its header.
    pub fn read_any_element(&mut self) -> Option<(u8, &'a [u8])> {
        let (tag, _, element) = self.read_asn1()?;
        Some((tag, element))
    }

    /// `ReadAnyASN1`: the contents of the next element and its tag.
    pub fn read_any(&mut self) -> Option<(u8, &'a [u8])> {
        let (tag, header, element) = self.read_asn1()?;
        Some((tag, &element[header..]))
    }

    /// `ReadASN1`: the contents of the next element if it has `tag`.
    pub fn read(&mut self, tag: u8) -> Option<&'a [u8]> {
        let saved = self.0;
        match self.read_asn1() {
            Some((got, header, element)) if got == tag => Some(&element[header..]),
            _ => {
                self.0 = saved;
                None
            }
        }
    }

    /// `ReadASN1Element`: the whole next element if it has `tag`.
    pub fn read_element(&mut self, tag: u8) -> Option<&'a [u8]> {
        let saved = self.0;
        match self.read_asn1() {
            Some((got, _, element)) if got == tag => Some(element),
            _ => {
                self.0 = saved;
                None
            }
        }
    }

    /// `PeekASN1Tag`.
    pub fn peek_tag(&self, tag: u8) -> bool {
        self.0.first() == Some(&tag)
    }

    /// `ReadOptionalASN1`: `None` is failure, `Some(None)` an absent element.
    pub fn read_optional(&mut self, tag: u8) -> Option<Option<&'a [u8]>> {
        if !self.peek_tag(tag) {
            return Some(None);
        }
        self.read(tag).map(Some)
    }

    /// `SkipOptionalASN1`.
    pub fn skip_optional(&mut self, tag: u8) -> bool {
        if !self.peek_tag(tag) {
            return true;
        }
        self.read(tag).is_some()
    }

    /// `encoding/asn1`'s handling of an `explicit` tagged field: when the next
    /// element has `tag`, only its header is consumed and the caller parses the
    /// child from the bytes that follow. The length of the wrapper is not
    /// checked against the child, as in Go. `Some(false)` means another tag.
    pub fn read_explicit_header(&mut self, tag: u8) -> Option<bool> {
        let s = self.0;
        if s.len() < 2 || s[0] != tag {
            return Some(false);
        }
        let len_byte = s[1];
        let header_len = if len_byte & 0x80 == 0 {
            2
        } else {
            let len_len = (len_byte & 0x7f) as usize;
            if len_len == 0 || len_len > 4 || s.len() < 2 + len_len {
                return None;
            }
            2 + len_len
        };
        self.0 = &s[header_len..];
        // "explicit tag has no child"
        if self.0.is_empty() {
            return None;
        }
        Some(true)
    }

    /// `ReadASN1Integer` into a `*big.Int`.
    pub fn read_big_integer(&mut self) -> Option<BigInt> {
        let saved = self.0;
        let bytes = self.read(INTEGER)?;
        if !check_integer(bytes) {
            self.0 = saved;
            return None;
        }
        Some(BigInt::from_der_contents(bytes))
    }

    /// `ReadASN1Integer` into an `int64`.
    pub fn read_i64(&mut self) -> Option<i64> {
        self.read_i64_tagged(INTEGER)
    }

    /// `ReadASN1Int64WithTag`.
    pub fn read_i64_tagged(&mut self, tag: u8) -> Option<i64> {
        let saved = self.0;
        let bytes = self.read(tag)?;
        match (check_integer(bytes), signed(bytes)) {
            (true, Some(v)) => Some(v),
            _ => {
                self.0 = saved;
                None
            }
        }
    }

    /// `ReadASN1Integer` into a `uint`.
    pub fn read_u64(&mut self) -> Option<u64> {
        let saved = self.0;
        let bytes = self.read(INTEGER)?;
        if !check_integer(bytes) || bytes.len() > 9 || (bytes.len() == 9 && bytes[0] != 0) {
            self.0 = saved;
            return None;
        }
        if bytes[0] & 0x80 != 0 {
            self.0 = saved;
            return None;
        }
        Some(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    /// `ReadASN1Enum`.
    pub fn read_enum(&mut self) -> Option<i64> {
        let saved = self.0;
        let bytes = self.read(ENUM)?;
        match signed(bytes) {
            Some(v) if !bytes.is_empty() => Some(v),
            _ => {
                self.0 = saved;
                None
            }
        }
    }

    /// `ReadASN1Boolean`.
    pub fn read_boolean(&mut self) -> Option<bool> {
        let saved = self.0;
        let bytes = self.read(BOOLEAN)?;
        if bytes.len() != 1 {
            self.0 = saved;
            return None;
        }
        match bytes[0] {
            0 => Some(false),
            0xff => Some(true),
            _ => {
                self.0 = saved;
                None
            }
        }
    }

    /// `ReadASN1BitString`.
    pub fn read_bit_string(&mut self) -> Option<BitString> {
        let saved = self.0;
        let bytes = self.read(BIT_STRING)?;
        if bytes.is_empty() || bytes.len() == 1 && bytes[0] != 0 {
            self.0 = saved;
            return None;
        }
        let padding = bytes[0];
        if padding > 7 || (bytes.len() > 1 && bytes[bytes.len() - 1] & ((1u8 << padding) - 1) != 0)
        {
            self.0 = saved;
            return None;
        }
        Some(BitString {
            bytes: bytes[1..].to_vec(),
            bit_length: (bytes.len() - 1) * 8 - padding as usize,
        })
    }

    /// `ReadASN1ObjectIdentifier`.
    pub fn read_oid(&mut self) -> Option<ObjectIdentifier> {
        let saved = self.0;
        let bytes = self.read(OBJECT_IDENTIFIER)?;
        match parse_oid_contents(bytes) {
            Some(oid) => Some(oid),
            None => {
                self.0 = saved;
                None
            }
        }
    }

    /// `ReadASN1UTCTime`.
    pub fn read_utc_time(&mut self) -> Option<Time> {
        let saved = self.0;
        let bytes = self.read(UTC_TIME)?;
        match parse_utc_time(bytes) {
            Some(t) => Some(t),
            None => {
                self.0 = saved;
                None
            }
        }
    }

    /// `ReadASN1GeneralizedTime`.
    pub fn read_generalized_time(&mut self) -> Option<Time> {
        let saved = self.0;
        let bytes = self.read(GENERALIZED_TIME)?;
        match parse_generalized_time(bytes) {
            Some(t) => Some(t),
            None => {
                self.0 = saved;
                None
            }
        }
    }
}

/// cryptobyte's `checkASN1Integer`: the contents are non-empty and minimal.
pub(crate) fn check_integer(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    if (bytes[0] == 0 && bytes[1] & 0x80 == 0) || (bytes[0] == 0xff && bytes[1] & 0x80 == 0x80) {
        return false;
    }
    true
}

fn signed(bytes: &[u8]) -> Option<i64> {
    if bytes.len() > 8 {
        return None;
    }
    let mut v: i64 = 0;
    for &b in bytes {
        v = (v << 8) | i64::from(b);
    }
    let shift = 64 - (bytes.len() as u32) * 8;
    if shift == 64 {
        return Some(0);
    }
    Some((v << shift) >> shift)
}

/// cryptobyte's `readBase128Int`.
fn read_base128(bytes: &mut &[u8]) -> Option<i64> {
    let mut ret: i64 = 0;
    let mut i = 0;
    while !bytes.is_empty() {
        if i == 5 {
            return None;
        }
        // Avoid overflowing an int on a 32-bit platform.
        if ret >= 1 << (31 - 7) {
            return None;
        }
        ret <<= 7;
        let b = bytes[0];
        *bytes = &bytes[1..];
        // ITU-T X.690, section 8.19.2: the leading octet shall not be 0x80.
        if ret == 0 && b == 0x80 {
            return None;
        }
        ret |= i64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some(ret);
        }
        i += 1;
    }
    None
}

/// The components of OBJECT IDENTIFIER contents, cryptobyte's rules.
pub(crate) fn parse_oid_contents(mut bytes: &[u8]) -> Option<ObjectIdentifier> {
    if bytes.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() + 1);
    let v = read_base128(&mut bytes)?;
    if v < 80 {
        out.push(v / 40);
        out.push(v % 40);
    } else {
        out.push(2);
        out.push(v - 80);
    }
    while !bytes.is_empty() {
        out.push(read_base128(&mut bytes)?);
    }
    Some(ObjectIdentifier(out))
}

/// Two decimal digits.
fn two(b: &[u8]) -> Option<u32> {
    if b.len() != 2 || !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
        return None;
    }
    Some(u32::from(b[0] - b'0') * 10 + u32::from(b[1] - b'0'))
}

/// The `Z0700` zone of Go's reference layout, as it must round-trip through
/// `Format`: `Z`, or a non-zero `+hhmm`/`-hhmm` offset. Returns the offset in
/// seconds east of UTC.
fn zone(b: &[u8]) -> Option<i64> {
    if b == b"Z" {
        return Some(0);
    }
    if b.len() != 5 || (b[0] != b'+' && b[0] != b'-') {
        return None;
    }
    let hh = two(&b[1..3])?;
    let mm = two(&b[3..5])?;
    if hh > 24 || mm >= 60 {
        return None;
    }
    let secs = i64::from(hh * 3600 + mm * 60);
    // time.Format prints a zero offset as "Z", so "+0000" does not round-trip.
    if secs == 0 {
        return None;
    }
    Some(if b[0] == b'-' { -secs } else { secs })
}

fn parse_utc_time(t: &[u8]) -> Option<Time> {
    // "060102150405Z0700", falling back to minute precision.
    let (rest_at, with_seconds) = if t.len() >= 12 && t[10..12].iter().all(u8::is_ascii_digit) {
        (12, true)
    } else {
        (10, false)
    };
    if t.len() < rest_at {
        return None;
    }
    let yy = two(&t[0..2])?;
    let mo = two(&t[2..4])?;
    let dd = two(&t[4..6])?;
    let hh = two(&t[6..8])?;
    let mi = two(&t[8..10])?;
    let ss = if with_seconds { two(&t[10..12])? } else { 0 };
    let offset = zone(&t[rest_at..])?;
    // Go's two-digit year pivot, then the X.509 profile's.
    let mut year = i64::from(yy) + if yy >= 69 { 1900 } else { 2000 };
    let base = Time::date(year, mo, dd, hh, mi, ss)?;
    let mut res = base.add_secs(-offset);
    if year >= 2050 {
        res = res.add_years(-100);
        year -= 100;
    }
    let _ = year;
    Some(res)
}

fn parse_generalized_time(t: &[u8]) -> Option<Time> {
    // "20060102150405Z0700"
    if t.len() < 15 {
        return None;
    }
    if !t[0..4].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let year = i64::from(two(&t[0..2])?) * 100 + i64::from(two(&t[2..4])?);
    let mo = two(&t[4..6])?;
    let dd = two(&t[6..8])?;
    let hh = two(&t[8..10])?;
    let mi = two(&t[10..12])?;
    let ss = two(&t[12..14])?;
    let offset = zone(&t[14..])?;
    let base = Time::date(year, mo, dd, hh, mi, ss)?;
    Some(base.add_secs(-offset))
}

// ---- Building ---------------------------------------------------------

/// DER length octets for a content length.
pub(crate) fn append_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u64).to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (8 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// A complete element: tag, length and `content`.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    append_length(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

pub(crate) fn integer_i64(v: i64) -> Vec<u8> {
    tlv(INTEGER, &BigInt::from_i64(v).der_contents())
}

pub(crate) fn integer_big(v: &BigInt) -> Vec<u8> {
    tlv(INTEGER, &v.der_contents())
}

pub(crate) fn boolean(v: bool) -> Vec<u8> {
    tlv(BOOLEAN, &[if v { 0xff } else { 0 }])
}

pub(crate) fn octet_string(v: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, v)
}

pub(crate) fn bit_string(bytes: &[u8], bit_length: usize) -> Vec<u8> {
    let padding = (8 - bit_length % 8) % 8;
    let mut content = Vec::with_capacity(bytes.len() + 1);
    content.push(padding as u8);
    content.extend_from_slice(bytes);
    tlv(BIT_STRING, &content)
}

pub(crate) fn enumerated(v: i64) -> Vec<u8> {
    tlv(ENUM, &BigInt::from_i64(v).der_contents())
}

/// Base-128 encoding of one arc.
pub(crate) fn append_base128(out: &mut Vec<u8>, n: u64) {
    if n == 0 {
        out.push(0);
        return;
    }
    let bits = 64 - n.leading_zeros() as usize;
    let count = bits.div_ceil(7);
    for i in (0..count).rev() {
        let mut o = ((n >> (i * 7)) & 0x7f) as u8;
        if i != 0 {
            o |= 0x80;
        }
        out.push(o);
    }
}

/// `asn1.Marshal(ObjectIdentifier)`: `None` where Go returns "invalid object identifier".
pub(crate) fn oid_contents(oid: &[i64]) -> Option<Vec<u8>> {
    if oid.len() < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) || oid.iter().any(|&a| a < 0) {
        return None;
    }
    let mut out = Vec::new();
    append_base128(&mut out, (oid[0] * 40 + oid[1]) as u64);
    for &arc in &oid[2..] {
        append_base128(&mut out, arc as u64);
    }
    Some(out)
}

pub(crate) fn oid(oid_value: &[i64]) -> Option<Vec<u8>> {
    oid_contents(oid_value).map(|c| tlv(OBJECT_IDENTIFIER, &c))
}

/// `asn1.Marshal(time.Time)`: UTCTime for 1950 through 2049, GeneralizedTime
/// otherwise.
pub(crate) fn time(t: &Time) -> Option<Vec<u8>> {
    let (y, mo, d, hh, mi, ss) = t.civil();
    if !(0..10000).contains(&y) {
        return None;
    }
    if (1950..2050).contains(&y) {
        Some(tlv(
            UTC_TIME,
            format!("{:02}{mo:02}{d:02}{hh:02}{mi:02}{ss:02}Z", y % 100).as_bytes(),
        ))
    } else {
        Some(tlv(
            GENERALIZED_TIME,
            format!("{y:04}{mo:02}{d:02}{hh:02}{mi:02}{ss:02}Z").as_bytes(),
        ))
    }
}

/// `encoding/asn1.isPrintable` for marshaling (no `*` or `&`).
pub(crate) fn is_printable_strict(b: u8) -> bool {
    b.is_ascii_lowercase()
        || b.is_ascii_uppercase()
        || b.is_ascii_digit()
        || (b'\''..=b')').contains(&b)
        || (b'+'..=b'/').contains(&b)
        || b == b' '
        || b == b':'
        || b == b'='
        || b == b'?'
}

/// `asn1.Marshal(string)` without a string type parameter: PrintableString if
/// possible, otherwise UTF8String.
pub(crate) fn string_auto(s: &str) -> Vec<u8> {
    if s.bytes().all(is_printable_strict) {
        tlv(PRINTABLE_STRING, s.as_bytes())
    } else {
        tlv(UTF8_STRING, s.as_bytes())
    }
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Go's `asn1.StructuralError` for an invalid OBJECT IDENTIFIER.
pub(crate) fn err_oid() -> Error {
    Error::new("asn1: structure error: invalid object identifier")
}

/// Go's `asn1.StructuralError` for a time that neither UTCTime nor
/// GeneralizedTime can represent.
pub(crate) fn err_time() -> Error {
    Error::new("asn1: structure error: cannot represent time as UTCTime or GeneralizedTime")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_writes_integers() {
        for v in [
            0i64,
            1,
            127,
            128,
            255,
            256,
            -1,
            -128,
            -129,
            i64::MAX,
            i64::MIN,
        ] {
            let der = integer_i64(v);
            let mut r = Reader(&der);
            assert_eq!(r.read_i64(), Some(v), "{v}");
            let mut r = Reader(&der);
            assert_eq!(r.read_big_integer().unwrap().to_i64(), Some(v));
        }
        assert_eq!(
            BigInt::from_decimal("-12345678901234567890")
                .unwrap()
                .to_string(),
            "-12345678901234567890"
        );
    }

    #[test]
    fn times() {
        let mut r = Reader(b"\x17\x0d500101000000Z");
        assert_eq!(r.read_utc_time().unwrap().year(), 1950);
        let mut r = Reader(b"\x17\x0d490101000000Z");
        assert_eq!(r.read_utc_time().unwrap().year(), 2049);
        let t = Time::date(2030, 1, 2, 3, 4, 5).unwrap();
        assert_eq!(time(&t).unwrap(), b"\x17\x0d300102030405Z");
    }

    #[test]
    fn oids() {
        let der = oid(&[1, 2, 840, 113549, 1, 1, 11]).unwrap();
        let mut r = Reader(&der);
        assert_eq!(r.read_oid().unwrap().0, vec![1, 2, 840, 113549, 1, 1, 11]);
    }
}
