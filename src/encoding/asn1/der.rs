//! DER identifier/length octets and base-128 integers (X.690 §8.1).
use super::{Class, Error};

/// A parsed identifier and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Header {
    pub class: Class,
    pub tag: u32,
    pub compound: bool,
    pub length: usize,
}

/// Go's parseBase128Int: at most five octets, no leading 0x80, value <= i32::MAX.
pub(crate) fn parse_base128(bytes: &[u8], mut offset: usize) -> Result<(u32, usize), Error> {
    let mut value: i64 = 0;
    let mut shifted = 0;
    while offset < bytes.len() {
        if shifted == 5 {
            return Err(Error::structural("base 128 integer too large"));
        }
        value <<= 7;
        let b = bytes[offset];
        if shifted == 0 && b == 0x80 {
            return Err(Error::syntax("integer is not minimally encoded"));
        }
        value |= i64::from(b & 0x7f);
        offset += 1;
        if b & 0x80 == 0 {
            if value > i64::from(i32::MAX) {
                return Err(Error::structural("base 128 integer too large"));
            }
            return Ok((value as u32, offset));
        }
        shifted += 1;
    }
    Err(Error::syntax("truncated base 128 integer"))
}

/// Go's parseTagAndLength: rejects non-minimal tags, indefinite lengths,
/// leading zero length octets, long-form lengths below 128 and lengths >= 2^31.
pub(crate) fn parse_header(bytes: &[u8], mut offset: usize) -> Result<(Header, usize), Error> {
    let Some(&first) = bytes.get(offset) else {
        return Err(Error::syntax("truncated tag or length"));
    };
    offset += 1;
    let class = Class::from_bits(first >> 6);
    let compound = first & 0x20 != 0;
    let mut tag = u32::from(first & 0x1f);
    if tag == 0x1f {
        (tag, offset) = parse_base128(bytes, offset)?;
        if tag < 0x1f {
            return Err(Error::syntax("non-minimal tag"));
        }
    }
    let Some(&b) = bytes.get(offset) else {
        return Err(Error::syntax("truncated tag or length"));
    };
    offset += 1;
    let length = if b & 0x80 == 0 {
        usize::from(b & 0x7f)
    } else {
        let count = usize::from(b & 0x7f);
        if count == 0 {
            return Err(Error::syntax("indefinite length found (not DER)"));
        }
        let mut length: u64 = 0;
        for _ in 0..count {
            let Some(&b) = bytes.get(offset) else {
                return Err(Error::syntax("truncated tag or length"));
            };
            offset += 1;
            if length >= 1 << 23 {
                return Err(Error::structural("length too large"));
            }
            length = (length << 8) | u64::from(b);
            if length == 0 {
                return Err(Error::structural("superfluous leading zeros in length"));
            }
        }
        if length < 0x80 {
            return Err(Error::structural("non-minimal length"));
        }
        usize::try_from(length).map_err(|_| Error::structural("length too large"))?
    };
    Ok((
        Header {
            class,
            tag,
            compound,
            length,
        },
        offset,
    ))
}

/// Returns `offset + length` when it fits within `limit`.
pub(crate) fn content_end(offset: usize, length: usize, limit: usize) -> Option<usize> {
    offset.checked_add(length).filter(|&end| end <= limit)
}

pub(crate) fn base128_len(value: u64) -> usize {
    let mut n = 1;
    let mut v = value >> 7;
    while v > 0 {
        n += 1;
        v >>= 7;
    }
    n
}

pub(crate) fn append_base128(out: &mut Vec<u8>, value: u64) {
    let n = base128_len(value);
    for i in (0..n).rev() {
        let mut o = ((value >> (i * 7)) & 0x7f) as u8;
        if i != 0 {
            o |= 0x80;
        }
        out.push(o);
    }
}

/// Go's appendTagAndLength: high tag numbers in base 128, minimal lengths.
pub(crate) fn append_header(
    out: &mut Vec<u8>,
    class: Class,
    tag: u32,
    compound: bool,
    length: usize,
) {
    let mut b = class.bits() << 6;
    if compound {
        b |= 0x20;
    }
    if tag >= 31 {
        out.push(b | 0x1f);
        append_base128(out, u64::from(tag));
    } else {
        out.push(b | tag as u8);
    }
    if length >= 128 {
        let n = (usize::BITS - length.leading_zeros()).div_ceil(8) as usize;
        out.push(0x80 | n as u8);
        for i in (0..n).rev() {
            out.push((length >> (i * 8)) as u8);
        }
    } else {
        out.push(length as u8);
    }
}
