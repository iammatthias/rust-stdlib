//! The non-negative integer carried by the asymmetric key types.
//!
//! Go's `crypto/rsa`, `crypto/ecdsa`, `crypto/dsa` and `crypto/elliptic`
//! expose `*big.Int` fields. This crate has no dependency on the root crate's
//! `math::big` (docs/adr/0003), so those fields are [`Int`]: a normalized
//! big-endian magnitude that converts losslessly to and from bytes, which is
//! also how `rust_stdlib::math::big::Int` is built and read. [`Int`] does no
//! arithmetic; all number theory happens inside the reviewed crates.

use std::cmp::Ordering;
use std::fmt;

/// A non-negative integer stored as a big-endian magnitude without leading
/// zero bytes.
#[derive(Clone, Default, Eq, Hash, PartialEq)]
pub struct Int(Vec<u8>);

impl Int {
    /// Zero.
    pub const fn zero() -> Int {
        Int(Vec::new())
    }

    /// The integer with the given big-endian bytes, like `big.Int.SetBytes`.
    pub fn from_be_bytes(bytes: &[u8]) -> Int {
        let start = bytes.iter().take_while(|&&byte| byte == 0).count();
        Int(bytes[start..].to_vec())
    }

    /// The integer with the given value.
    pub fn from_u64(value: u64) -> Int {
        Int::from_be_bytes(&value.to_be_bytes())
    }

    /// Parses lowercase or uppercase hexadecimal text (no prefix), like
    /// `big.Int.SetString(s, 16)`.
    pub fn from_hex(text: &str) -> Option<Int> {
        if text.is_empty() {
            return None;
        }
        let mut digits = Vec::with_capacity(text.len());
        for c in text.chars() {
            digits.push(c.to_digit(16)? as u8);
        }
        if digits.len() % 2 == 1 {
            digits.insert(0, 0);
        }
        let bytes: Vec<u8> = digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect();
        Some(Int::from_be_bytes(&bytes))
    }

    /// The minimal big-endian bytes, empty for zero, like `big.Int.Bytes`.
    pub fn to_be_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Borrows the minimal big-endian bytes.
    pub fn as_be_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The big-endian bytes left-padded with zeros to `len` bytes, like
    /// `big.Int.FillBytes`; `None` if the value does not fit (Go panics).
    pub fn fill_bytes(&self, len: usize) -> Option<Vec<u8>> {
        if self.0.len() > len {
            return None;
        }
        let mut out = vec![0; len - self.0.len()];
        out.extend_from_slice(&self.0);
        Some(out)
    }

    /// Whether the value is zero, like `big.Int.Sign() == 0`.
    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    /// The length of the value in bits, like `big.Int.BitLen`.
    pub fn bit_len(&self) -> usize {
        match self.0.first() {
            None => 0,
            Some(top) => self.0.len() * 8 - top.leading_zeros() as usize,
        }
    }

    /// Bit `index` of the value (0 is the least significant), like
    /// `big.Int.Bit`.
    pub fn bit(&self, index: usize) -> u8 {
        let byte = index / 8;
        if byte >= self.0.len() {
            return 0;
        }
        (self.0[self.0.len() - 1 - byte] >> (index % 8)) & 1
    }

    /// The value as a `u64` if it fits, like `big.Int.Uint64` with
    /// `IsUint64`.
    pub fn to_u64(&self) -> Option<u64> {
        if self.0.len() > 8 {
            return None;
        }
        let mut bytes = [0u8; 8];
        bytes[8 - self.0.len()..].copy_from_slice(&self.0);
        Some(u64::from_be_bytes(bytes))
    }

    /// Lowercase hexadecimal text without prefix ("0" for zero).
    pub fn to_hex(&self) -> String {
        if self.0.is_empty() {
            return "0".to_string();
        }
        let mut out = String::with_capacity(self.0.len() * 2);
        for (index, byte) in self.0.iter().enumerate() {
            if index == 0 {
                out.push_str(&format!("{byte:x}"));
            } else {
                out.push_str(&format!("{byte:02x}"));
            }
        }
        out
    }
}

impl Ord for Int {
    fn cmp(&self, other: &Int) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for Int {
    fn partial_cmp(&self, other: &Int) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Debug for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Int(0x{})", self.to_hex())
    }
}

impl fmt::LowerHex for Int {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl From<u64> for Int {
    fn from(value: u64) -> Int {
        Int::from_u64(value)
    }
}

impl From<&[u8]> for Int {
    fn from(bytes: &[u8]) -> Int {
        Int::from_be_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_orders() {
        let a = Int::from_be_bytes(&[0, 0, 1, 2]);
        assert_eq!(a.as_be_bytes(), &[1, 2]);
        assert_eq!(a.bit_len(), 9);
        assert_eq!(a.bit(1), 1);
        assert_eq!(a.bit(0), 0);
        assert!(a > Int::from_u64(255));
        assert!(Int::zero().is_zero());
        assert_eq!(Int::zero().bit_len(), 0);
        assert_eq!(a.fill_bytes(4), Some(vec![0, 0, 1, 2]));
        assert_eq!(a.fill_bytes(1), None);
        assert_eq!(Int::from_hex("0102"), Some(a.clone()));
        assert_eq!(a.to_hex(), "102");
        assert_eq!(Int::from_hex("zz"), None);
        assert_eq!(a.to_u64(), Some(258));
    }
}
