//! Go's `x509.OID`: an ASN.1 OBJECT IDENTIFIER with components of any size.

use std::fmt;

use super::asn1::{self, decimal, mul_add_small, BigInt, ObjectIdentifier};
use super::Error;

const ERR_INVALID_OID: &str = "invalid oid";

/// Go's `x509.OID`: an ASN.1 OBJECT IDENTIFIER, stored as its DER contents.
/// Unlike [`ObjectIdentifier`], components are not limited to an `int`.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Oid {
    der: Vec<u8>,
}

fn invalid() -> Error {
    Error::new(ERR_INVALID_OID)
}

/// Go's `ParseOID`: parses an Object Identifier string, ASCII numbers
/// separated by dots.
pub fn parse_oid(oid: &str) -> Result<Oid, Error> {
    let mut o = Oid::default();
    o.unmarshal_oid_text(oid)?;
    Ok(o)
}

/// Go's `OIDFromInts`: creates a new [`Oid`], each integer a component.
pub fn oid_from_ints(oid: &[u64]) -> Result<Oid, Error> {
    if oid.len() < 2 || oid[0] > 2 || (oid[0] < 2 && oid[1] >= 40) {
        return Err(invalid());
    }
    let mut der = Vec::new();
    // The first two components are one number; it can overflow u64 only for
    // an arc of 2 with a second component above u64::MAX - 80.
    let first = u128::from(oid[0]) * 40 + u128::from(oid[1]);
    append_base128_u128(&mut der, first);
    for &v in &oid[2..] {
        asn1::append_base128(&mut der, v);
    }
    Ok(Oid { der })
}

/// Go's `OIDFromASN1OID`: creates a new [`Oid`] from an
/// [`ObjectIdentifier`].
pub fn oid_from_asn1_oid(asn1_oid: &ObjectIdentifier) -> Result<Oid, Error> {
    let mut ints = Vec::with_capacity(asn1_oid.0.len());
    for &component in &asn1_oid.0 {
        if component < 0 {
            return Err(Error::new("x509: OID components must be non-negative"));
        }
        ints.push(component as u64);
    }
    oid_from_ints(&ints)
}

fn append_base128_u128(dst: &mut Vec<u8>, n: u128) {
    if n == 0 {
        dst.push(0);
        return;
    }
    let bits = 128 - n.leading_zeros() as usize;
    let count = bits.div_ceil(7);
    for i in (0..count).rev() {
        let mut o = ((n >> (i * 7)) & 0x7f) as u8;
        if i != 0 {
            o |= 0x80;
        }
        dst.push(o);
    }
}

/// Base-128 encoding of a big-endian magnitude.
fn append_base128_big(dst: &mut Vec<u8>, mag: &[u8]) {
    let mut mag = mag.to_vec();
    while mag.first() == Some(&0) {
        mag.remove(0);
    }
    if mag.is_empty() {
        dst.push(0);
        return;
    }
    let bit_len = mag.len() * 8 - mag[0].leading_zeros() as usize;
    let count = bit_len.div_ceil(7);
    for i in (0..count).rev() {
        let mut o = 0u8;
        for bit in 0..7 {
            let idx = i * 7 + bit;
            let byte = idx / 8;
            if byte < mag.len() {
                let v = (mag[mag.len() - 1 - byte] >> (idx % 8)) & 1;
                o |= v << bit;
            }
        }
        if i != 0 {
            o |= 0x80;
        }
        dst.push(o);
    }
}

impl Oid {
    /// The OID with the given DER contents (without tag and length), if they
    /// are a valid encoding (Go's `newOIDFromDER`).
    pub(crate) fn from_der(der: &[u8]) -> Option<Oid> {
        if der.is_empty() || der[der.len() - 1] & 0x80 != 0 {
            return None;
        }
        let mut start = 0;
        for (i, &v) in der.iter().enumerate() {
            // ITU-T X.690, section 8.19.2: the leading octet of a
            // subidentifier shall not have the value 0x80.
            if i == start && v == 0x80 {
                return None;
            }
            if v & 0x80 == 0 {
                start = i + 1;
            }
        }
        Some(Oid { der: der.to_vec() })
    }

    /// An OID holding `der` without validation (Go's `OID{der}`).
    pub(crate) fn from_raw(der: &[u8]) -> Oid {
        Oid { der: der.to_vec() }
    }

    /// The raw DER contents. Empty for the zero `OID`.
    pub(crate) fn der(&self) -> &[u8] {
        &self.der
    }

    /// Go's `OID.AppendText`.
    pub fn append_text(&self, b: &mut Vec<u8>) -> Result<(), Error> {
        b.extend_from_slice(self.string().as_bytes());
        Ok(())
    }

    /// Go's `OID.MarshalText`.
    pub fn marshal_text(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.append_text(&mut out)?;
        Ok(out)
    }

    /// Go's `OID.UnmarshalText`.
    pub fn unmarshal_text(&mut self, text: &[u8]) -> Result<(), Error> {
        // Go converts the bytes to a string; invalid UTF-8 contains
        // non-digit characters either way.
        match std::str::from_utf8(text) {
            Ok(s) => self.unmarshal_oid_text(s),
            Err(_) => Err(invalid()),
        }
    }

    fn unmarshal_oid_text(&mut self, oid: &str) -> Result<(), Error> {
        // big.Int.SetString allows +/- signs, which Object Identifier strings
        // must not have.
        if !oid.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return Err(invalid());
        }
        let (first_num, rest) = match oid.split_once('.') {
            Some(parts) => parts,
            None => return Err(invalid()),
        };
        let (second_num, mut rest, mut next_component_exists) = match rest.split_once('.') {
            Some((a, b)) => (a, b, true),
            None => (rest, "", false),
        };
        let first = BigInt::from_decimal(first_num).ok_or_else(invalid)?;
        let second = BigInt::from_decimal(second_num).ok_or_else(invalid)?;
        let first_small = first.to_i64();
        let second_small = second.to_i64();
        // first > 2, or first < 2 and second >= 40.
        match first_small {
            Some(f) if f > 2 => return Err(invalid()),
            Some(f) if f < 2 && second_small.is_none_or(|s| s >= 40) => return Err(invalid()),
            None => return Err(invalid()),
            _ => {}
        }
        let f = first_small.unwrap_or(0);
        let mut component = second.bytes();
        // first * 40 + second
        let mut base = (f as u32 * 40).to_be_bytes().to_vec();
        while base.first() == Some(&0) {
            base.remove(0);
        }
        component = add_magnitudes(&base, &component);
        let mut der = Vec::with_capacity(32);
        append_base128_big(&mut der, &component);

        while next_component_exists {
            let (str_num, tail, more) = match rest.split_once('.') {
                Some((a, b)) => (a, b, true),
                None => (rest, "", false),
            };
            rest = tail;
            next_component_exists = more;
            let b = BigInt::from_decimal(str_num).ok_or_else(invalid)?;
            append_base128_big(&mut der, &b.bytes());
        }
        self.der = der;
        Ok(())
    }

    /// Go's `OID.AppendBinary`.
    pub fn append_binary(&self, b: &mut Vec<u8>) -> Result<(), Error> {
        b.extend_from_slice(&self.der);
        Ok(())
    }

    /// Go's `OID.MarshalBinary`.
    pub fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        Ok(self.der.clone())
    }

    /// Go's `OID.UnmarshalBinary`.
    pub fn unmarshal_binary(&mut self, b: &[u8]) -> Result<(), Error> {
        *self = Oid::from_der(b).ok_or_else(invalid)?;
        Ok(())
    }

    /// Go's `OID.Equal`: whether `self` and `other` represent the same Object
    /// Identifier.
    pub fn equal(&self, other: &Oid) -> bool {
        self.der == other.der
    }

    /// Go's `OID.EqualASN1OID`: whether the OID equals an
    /// [`ObjectIdentifier`]. If the identifier cannot represent the OID,
    /// because a component needs more than 31 bits, it returns false.
    pub fn equal_asn1_oid(&self, other: &ObjectIdentifier) -> bool {
        let other = &other.0;
        if other.len() < 2 {
            return false;
        }
        let Some((v, mut offset)) = parse_base128_int(&self.der, 0) else {
            return false;
        };
        let (a, b) = if v < 80 {
            (v / 40, v % 40)
        } else {
            (2, v - 80)
        };
        if other[0] != a || other[1] != b {
            return false;
        }
        let mut i = 2;
        while offset < self.der.len() {
            let Some((v, next)) = parse_base128_int(&self.der, offset) else {
                return false;
            };
            offset = next;
            if i >= other.len() || v != other[i] {
                return false;
            }
            i += 1;
        }
        i == other.len()
    }

    /// Go's `OID.String`: the dotted decimal form.
    fn string(&self) -> String {
        let mut out = String::with_capacity(32);
        let mut start = 0usize;
        let mut val: Vec<u8> = Vec::new();
        for (i, &v) in self.der.iter().enumerate() {
            let cur = v & 0x7f;
            let val_end = v & 0x80 == 0;
            if val_end && start != 0 {
                out.push('.');
            }
            mul_add_small(&mut val, 128, u32::from(cur));
            if val_end {
                if start == 0 {
                    let mut trimmed = val.clone();
                    while trimmed.first() == Some(&0) {
                        trimmed.remove(0);
                    }
                    let small = if trimmed.len() <= 8 {
                        let mut b = [0u8; 8];
                        b[8 - trimmed.len()..].copy_from_slice(&trimmed);
                        Some(u64::from_be_bytes(b))
                    } else {
                        None
                    };
                    match small {
                        Some(s) if s < 80 => {
                            out.push_str(&(s / 40).to_string());
                            out.push('.');
                            out.push_str(&(s % 40).to_string());
                        }
                        _ => {
                            out.push_str("2.");
                            let mut m = trimmed;
                            sub_small(&mut m, 80);
                            out.push_str(&decimal(&m));
                        }
                    }
                } else {
                    out.push_str(&decimal(&val));
                }
                val.clear();
                start = i + 1;
            }
        }
        out
    }

    /// Go's `toASN1OID`: `None` if a component needs more than 31 bits.
    pub(crate) fn to_asn1_oid(&self) -> Option<ObjectIdentifier> {
        const MAX_VAL_SAFE_SHIFT: i64 = (1 << (31 - 7)) - 1;
        let mut out: Vec<i64> = Vec::with_capacity(self.der.len() + 1);
        let mut val: i64 = 0;
        for &v in &self.der {
            if val > MAX_VAL_SAFE_SHIFT {
                return None;
            }
            val <<= 7;
            val |= i64::from(v & 0x7f);
            if v & 0x80 == 0 {
                if out.is_empty() {
                    if val < 80 {
                        out.push(val / 40);
                        out.push(val % 40);
                    } else {
                        out.push(2);
                        out.push(val - 80);
                    }
                    val = 0;
                    continue;
                }
                out.push(val);
                val = 0;
            }
        }
        Some(ObjectIdentifier(out))
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string())
    }
}

/// Go's `parseBase128Int` of `oid.go`.
fn parse_base128_int(bytes: &[u8], init_offset: usize) -> Option<(i64, usize)> {
    let mut offset = init_offset;
    let mut ret64: i64 = 0;
    let mut shifted = 0;
    while offset < bytes.len() {
        // 5 * 7 bits per byte == 35 bits of data; the representation is
        // either non-minimal or too large for an int32.
        if shifted == 5 {
            return None;
        }
        ret64 <<= 7;
        let b = bytes[offset];
        if shifted == 0 && b == 0x80 {
            return None;
        }
        ret64 |= i64::from(b & 0x7f);
        offset += 1;
        if b & 0x80 == 0 {
            if ret64 > i64::from(i32::MAX) {
                return None;
            }
            return Some((ret64, offset));
        }
        shifted += 1;
    }
    None
}

fn add_magnitudes(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().max(b.len());
    let mut out = vec![0u8; n + 1];
    let mut carry = 0u16;
    for i in 0..n {
        let x = if i < a.len() {
            u16::from(a[a.len() - 1 - i])
        } else {
            0
        };
        let y = if i < b.len() {
            u16::from(b[b.len() - 1 - i])
        } else {
            0
        };
        let s = x + y + carry;
        out[n - i] = s as u8;
        carry = s >> 8;
    }
    out[0] = carry as u8;
    while out.first() == Some(&0) {
        out.remove(0);
    }
    out
}

fn sub_small(mag: &mut Vec<u8>, n: u8) {
    let mut borrow = u16::from(n);
    for byte in mag.iter_mut().rev() {
        let cur = u16::from(*byte);
        if cur >= borrow {
            *byte = (cur - borrow) as u8;
            break;
        }
        *byte = (cur + 256 - borrow) as u8;
        borrow = 1;
    }
    while mag.first() == Some(&0) {
        mag.remove(0);
    }
}

#[cfg(test)]
mod tests {
    //! Ported from Go's oid_test.go.
    use super::*;

    struct OidTest {
        raw: &'static [u8],
        valid: bool,
        string: &'static str,
        ints: Option<&'static [u64]>,
    }

    const fn t(
        raw: &'static [u8],
        valid: bool,
        string: &'static str,
        ints: Option<&'static [u64]>,
    ) -> OidTest {
        OidTest {
            raw,
            valid,
            string,
            ints,
        }
    }

    const OID_TESTS: &[OidTest] = &[
        t(&[], false, "", None),
        t(&[0x80, 0x01], false, "", None),
        t(&[0x01, 0x80, 0x01], false, "", None),
        t(&[1, 2, 3], true, "0.1.2.3", Some(&[0, 1, 2, 3])),
        t(&[41, 2, 3], true, "1.1.2.3", Some(&[1, 1, 2, 3])),
        t(&[86, 2, 3], true, "2.6.2.3", Some(&[2, 6, 2, 3])),
        t(
            &[41, 255, 255, 255, 127],
            true,
            "1.1.268435455",
            Some(&[1, 1, 268435455]),
        ),
        t(
            &[41, 0x87, 255, 255, 255, 127],
            true,
            "1.1.2147483647",
            Some(&[1, 1, 2147483647]),
        ),
        t(
            &[41, 255, 255, 255, 255, 127],
            true,
            "1.1.34359738367",
            Some(&[1, 1, 34359738367]),
        ),
        t(
            &[42, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "1.2.9223372036854775807",
            Some(&[1, 2, 9223372036854775807]),
        ),
        t(
            &[43, 0x81, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "1.3.18446744073709551615",
            Some(&[1, 3, 18446744073709551615]),
        ),
        t(
            &[44, 0x83, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "1.4.36893488147419103231",
            None,
        ),
        t(
            &[85, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "2.5.1180591620717411303423",
            None,
        ),
        t(
            &[
                85, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
            ],
            true,
            "2.5.19342813113834066795298815",
            None,
        ),
        t(
            &[255, 255, 255, 127],
            true,
            "2.268435375",
            Some(&[2, 268435375]),
        ),
        t(
            &[0x87, 255, 255, 255, 127],
            true,
            "2.2147483567",
            Some(&[2, 2147483567]),
        ),
        t(&[255, 127], true, "2.16303", Some(&[2, 16303])),
        t(
            &[255, 255, 255, 255, 127],
            true,
            "2.34359738287",
            Some(&[2, 34359738287]),
        ),
        t(
            &[255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "2.9223372036854775727",
            Some(&[2, 9223372036854775727]),
        ),
        t(
            &[0x81, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "2.18446744073709551535",
            Some(&[2, 18446744073709551535]),
        ),
        t(
            &[0x83, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "2.36893488147419103151",
            None,
        ),
        t(
            &[255, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "2.1180591620717411303343",
            None,
        ),
        t(
            &[255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "2.19342813113834066795298735",
            None,
        ),
        t(
            &[41, 0x80 | 66, 0x80 | 44, 0x80 | 11, 33],
            true,
            "1.1.139134369",
            Some(&[1, 1, 139134369]),
        ),
        t(
            &[0x80 | 66, 0x80 | 44, 0x80 | 11, 33],
            true,
            "2.139134289",
            Some(&[2, 139134289]),
        ),
    ];

    #[test]
    fn oid() {
        for v in OID_TESTS {
            let parsed = Oid::from_der(v.raw);
            assert_eq!(parsed.is_some(), v.valid, "from_der({:?})", v.raw);
            let Some(oid) = parsed else { continue };
            assert_eq!(oid.string(), v.string, "{:?}", v.raw);

            // asn1.ObjectIdentifier representable when every component fits an int32.
            let asn1_oid: Option<Vec<i64>> = v.ints.and_then(|ints| {
                if ints.iter().any(|&i| i > i32::MAX as u64) {
                    None
                } else {
                    Some(ints.iter().map(|&i| i as i64).collect())
                }
            });
            let converted = oid.to_asn1_oid();
            assert_eq!(converted.is_some(), asn1_oid.is_some(), "{:?}", v.raw);
            if let (Some(c), Some(a)) = (converted, asn1_oid) {
                assert_eq!(c.0, a, "{:?}", v.raw);
            }

            if let Some(ints) = v.ints {
                let oid2 = oid_from_ints(ints).unwrap();
                assert!(oid2.equal(&oid), "{ints:?}");
            }
        }
    }

    #[test]
    fn invalid_oid() {
        let cases: &[(&str, &[u64])] = &[
            ("", &[]),
            ("1", &[1]),
            ("3", &[3]),
            ("3.100.200", &[3, 100, 200]),
            ("1.81", &[1, 81]),
            ("1.81.200", &[1, 81, 200]),
        ];
        for (s, ints) in cases {
            assert!(oid_from_ints(ints).is_err(), "oid_from_ints({ints:?})");
            assert!(parse_oid(s).is_err(), "parse_oid({s:?})");
            assert!(
                Oid::default().unmarshal_text(s.as_bytes()).is_err(),
                "{s:?}"
            );
        }
    }

    #[test]
    fn oid_equal() {
        let m = |ints: &[u64]| oid_from_ints(ints).unwrap();
        assert!(m(&[1, 2, 3]).equal(&m(&[1, 2, 3])));
        assert!(!m(&[1, 2, 3]).equal(&m(&[1, 2, 4])));
        assert!(!m(&[1, 2, 3]).equal(&m(&[1, 2, 3, 4])));
        assert!(!m(&[2, 33, 22]).equal(&m(&[2, 33, 23])));
        assert!(Oid::default().equal(&Oid::default()));
        assert!(!Oid::default().equal(&m(&[2, 33, 23])));
    }

    #[test]
    fn oid_marshal() {
        let mut cases: Vec<(String, Option<Oid>)> = [
            "",
            "0",
            "1",
            ".1",
            ".1.",
            "1.",
            "1..",
            "1.2.",
            "1.2.333.",
            "1.2.333..",
            "1.2..",
            "+1.2",
            "-1.2",
            "1.-2",
            "1.2.+333",
        ]
        .iter()
        .map(|s| (s.to_string(), None))
        .collect();
        for v in OID_TESTS {
            if let Some(oid) = Oid::from_der(v.raw) {
                cases.push((v.string.to_string(), Some(oid)));
            }
        }
        for (input, expected) in cases {
            let parsed = parse_oid(&input);
            let mut o2 = Oid::default();
            let unmarshaled = o2.unmarshal_text(input.as_bytes());
            let Some(expected) = expected else {
                assert_eq!(parsed.unwrap_err().to_string(), "invalid oid", "{input:?}");
                assert_eq!(
                    unmarshaled.unwrap_err().to_string(),
                    "invalid oid",
                    "{input:?}"
                );
                continue;
            };
            let o = parsed.unwrap();
            unmarshaled.unwrap();
            assert!(o.equal(&expected), "{input:?}");
            assert!(o2.equal(&expected), "{input:?}");
            assert_eq!(o.marshal_text().unwrap(), input.as_bytes());
            let mut text = vec![0u8; 4];
            o.append_text(&mut text).unwrap();
            assert_eq!(&text[4..], input.as_bytes());

            let binary = o.marshal_binary().unwrap();
            let mut o3 = Oid::default();
            o3.unmarshal_binary(&binary).unwrap();
            assert!(o3.equal(&expected));
            let mut appended = vec![0u8; 4];
            o.append_binary(&mut appended).unwrap();
            let mut o4 = Oid::default();
            o4.unmarshal_binary(&appended[4..]).unwrap();
            assert!(o4.equal(&expected));
        }
    }

    #[test]
    fn oid_equal_asn1_oid() {
        let m = |ints: &[u64]| oid_from_ints(ints).unwrap();
        let a = |ints: &[i64]| ObjectIdentifier(ints.to_vec());
        let max = i64::from(i32::MAX);
        let cases: Vec<(Oid, ObjectIdentifier, bool)> = vec![
            (m(&[1, 2, 3]), a(&[1, 2, 3]), true),
            (m(&[1, 2, 3]), a(&[1, 2, 4]), false),
            (m(&[1, 2, 3]), a(&[1, 2, 3, 4]), false),
            (m(&[1, 33, 22]), a(&[1, 33, 23]), false),
            (m(&[1, 33, 23]), a(&[1, 33, 22]), false),
            (m(&[1, 33, 127]), a(&[1, 33, 127]), true),
            (m(&[1, 33, 128]), a(&[1, 33, 127]), false),
            (m(&[1, 33, 128]), a(&[1, 33, 128]), true),
            (m(&[1, 33, 129]), a(&[1, 33, 129]), true),
            (m(&[1, 33, 128]), a(&[1, 33, 129]), false),
            (m(&[1, 33, 129]), a(&[1, 33, 128]), false),
            (m(&[1, 33, 255]), a(&[1, 33, 255]), true),
            (m(&[1, 33, 256]), a(&[1, 33, 256]), true),
            (m(&[2, 33, 257]), a(&[2, 33, 256]), false),
            (m(&[2, 33, 256]), a(&[2, 33, 257]), false),
            (m(&[1, 33]), a(&[1, 33, max]), false),
            (m(&[1, 33, max as u64]), a(&[1, 33]), false),
            (m(&[1, 33, max as u64]), a(&[1, 33, max]), true),
            (m(&[1, 33, max as u64 + 1]), a(&[1, 33, max + 1]), false),
            (m(&[1, 33, 256]), a(&[]), false),
            (Oid::default(), a(&[1, 33, 256]), false),
            (Oid::default(), a(&[]), false),
        ];
        for (oid, other, eq) in cases {
            assert_eq!(oid.equal_asn1_oid(&other), eq, "{oid} vs {other}");
        }
    }

    #[test]
    fn oid_unmarshal_binary() {
        for tt in OID_TESTS {
            let mut o = Oid::default();
            let result = o.unmarshal_binary(tt.raw);
            assert_eq!(result.is_ok(), tt.valid, "{:?}", tt.raw);
            if let Err(e) = result {
                assert_eq!(e.to_string(), "invalid oid");
            }
        }
    }

    #[test]
    fn oid_from_asn1_oid_errors() {
        let err = oid_from_asn1_oid(&ObjectIdentifier(vec![-1])).unwrap_err();
        assert_eq!(err.to_string(), "x509: OID components must be non-negative");
        for bad in [vec![1], vec![255, 1], vec![1, 255]] {
            let err = oid_from_asn1_oid(&ObjectIdentifier(bad)).unwrap_err();
            assert_eq!(err.to_string(), "invalid oid");
        }
    }
}
