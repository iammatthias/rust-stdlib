// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/big/int.go.

use super::nat::{self, Nat};
use super::{Accuracy, Float, RoundingMode};
use std::cmp::Ordering;
use std::ops;

/// Go's `big.Int`: a signed arbitrary-precision integer.
///
/// The value is a sign and a normalized magnitude, so derived equality and
/// hashing agree with numeric equality; zero is never negative.
#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct Int {
    pub(super) neg: bool,
    pub(super) abs: Nat,
}

impl Int {
    pub(super) fn from_parts(neg: bool, abs: Nat) -> Int {
        let neg = neg && !abs.is_empty();
        Int { neg, abs }
    }

    fn one() -> Int {
        Int::from_parts(false, vec![1])
    }

    /// Go's `NewInt(x)`.
    pub fn new(x: i64) -> Int {
        Int::from_parts(x < 0, nat::from_u64(x.unsigned_abs()))
    }

    /// Zero.
    pub fn zero() -> Int {
        Int::default()
    }

    /// Go's `SetUint64`.
    pub fn from_u64(x: u64) -> Int {
        Int::from_parts(false, nat::from_u64(x))
    }

    /// Go's `SetBits`: the non-negative value of little-endian `u64` limbs.
    pub fn from_bits(abs: &[super::Word]) -> Int {
        Int::from_parts(false, nat::normalized(abs.to_vec()))
    }

    /// Go's `Bits`: the little-endian `u64` limbs of |x|.
    pub fn bits(&self) -> &[super::Word] {
        &self.abs
    }

    /// Whether x == 0.
    pub fn is_zero(&self) -> bool {
        self.abs.is_empty()
    }

    /// Go's `Sign`: -1, 0 or +1.
    pub fn sign(&self) -> i32 {
        if self.abs.is_empty() {
            0
        } else if self.neg {
            -1
        } else {
            1
        }
    }

    /// Go's `Abs`.
    pub fn abs(&self) -> Int {
        Int::from_parts(false, self.abs.clone())
    }

    /// Go's `Neg`.
    pub fn neg(&self) -> Int {
        Int::from_parts(!self.neg, self.abs.clone())
    }

    /// Go's `Add`.
    fn plus(&self, y: &Int) -> Int {
        if self.neg == y.neg {
            return Int::from_parts(self.neg, nat::add(&self.abs, &y.abs));
        }
        if nat::cmp(&self.abs, &y.abs) != Ordering::Less {
            Int::from_parts(self.neg, nat::sub(&self.abs, &y.abs))
        } else {
            Int::from_parts(!self.neg, nat::sub(&y.abs, &self.abs))
        }
    }

    /// Go's `Sub`.
    fn minus(&self, y: &Int) -> Int {
        if self.neg != y.neg {
            return Int::from_parts(self.neg, nat::add(&self.abs, &y.abs));
        }
        if nat::cmp(&self.abs, &y.abs) != Ordering::Less {
            Int::from_parts(self.neg, nat::sub(&self.abs, &y.abs))
        } else {
            Int::from_parts(!self.neg, nat::sub(&y.abs, &self.abs))
        }
    }

    /// Go's `Mul`.
    fn times(&self, y: &Int) -> Int {
        Int::from_parts(self.neg != y.neg, nat::mul(&self.abs, &y.abs))
    }

    /// Go's `MulRange`: the product of all integers in [a, b].
    pub fn mul_range(a: i64, b: i64) -> Int {
        if a > b {
            return Int::new(1);
        }
        if a <= 0 && b >= 0 {
            return Int::zero();
        }
        let mut neg = false;
        let (mut a, mut b) = (a, b);
        if a < 0 {
            neg = (b - a) & 1 == 0;
            (a, b) = (-b, -a);
        }
        Int::from_parts(neg, nat::mul_range(a as u64, b as u64))
    }

    /// Go's `Binomial`: the binomial coefficient C(n, k).
    pub fn binomial(n: i64, k: i64) -> Int {
        if k > n || k < 0 {
            return Int::zero();
        }
        let k = if k > n - k { n - k } else { k };
        let big_n = Int::new(n);
        let big_k = Int::new(k);
        let mut z = Int::one();
        let mut i = Int::zero();
        while i < big_k {
            z = &z * &(&big_n - &i);
            i = &i + &Int::one();
            z = &z / &i;
        }
        z
    }

    /// Go's `Quo`: the quotient truncated toward zero. Panics if y == 0.
    fn quotient(&self, y: &Int) -> Int {
        let (q, _) = nat::div(&self.abs, &y.abs);
        Int::from_parts(self.neg != y.neg, q)
    }

    /// Go's `Rem`: the remainder with the sign of x. Panics if y == 0.
    fn remainder(&self, y: &Int) -> Int {
        let (_, r) = nat::div(&self.abs, &y.abs);
        Int::from_parts(self.neg, r)
    }

    /// Go's `QuoRem`: truncated quotient and remainder.
    pub fn quo_rem(&self, y: &Int) -> (Int, Int) {
        let (q, r) = nat::div(&self.abs, &y.abs);
        (
            Int::from_parts(self.neg != y.neg, q),
            Int::from_parts(self.neg, r),
        )
    }

    /// Go's `Div`: the Euclidean quotient. Panics if y == 0.
    pub fn div_euclid(&self, y: &Int) -> Int {
        self.div_mod(y).0
    }

    /// Go's `Mod`: the Euclidean modulus, always >= 0. Panics if y == 0.
    pub fn rem_euclid(&self, y: &Int) -> Int {
        self.div_mod(y).1
    }

    /// Go's `DivMod`: Euclidean quotient and modulus.
    pub fn div_mod(&self, y: &Int) -> (Int, Int) {
        let (q, r) = self.quo_rem(y);
        if r.neg {
            if y.neg {
                ((&q + &Int::one()), (&r - y))
            } else {
                ((&q - &Int::one()), (&r + y))
            }
        } else {
            (q, r)
        }
    }

    /// Go's `Divide`: the quotient rounded by mode (only `ToZero`,
    /// `ToNegativeInf`, `ToNearestEven` and `ToPositiveInf`; see
    /// [`RoundingMode::TRUNC`] and friends) and the matching remainder.
    /// Panics on y == 0 or an unsupported mode, as Go does.
    pub fn divide(&self, y: &Int, mode: RoundingMode) -> (Int, Int) {
        let neg = self.neg != y.neg;
        let (mut z, mut r) = nat::div(&self.abs, &y.abs);
        let mut r_neg = false;
        if !r.is_empty() {
            let flip = |z: &mut Nat, r: &mut Nat| {
                *z = nat::add_w(z, 1);
                *r = nat::sub(&y.abs, r);
            };
            match mode {
                RoundingMode::ToZero => r_neg = self.neg,
                RoundingMode::ToNegativeInf => {
                    r_neg = y.neg;
                    if neg {
                        flip(&mut z, &mut r);
                    }
                }
                RoundingMode::ToPositiveInf => {
                    r_neg = !y.neg;
                    if !neg {
                        flip(&mut z, &mut r);
                    }
                }
                RoundingMode::ToNearestEven => {
                    let c = nat::cmp(&nat::shl(&r, 1), &y.abs);
                    let even = z.first().is_none_or(|w| w & 1 == 0);
                    if c == Ordering::Less || c == Ordering::Equal && even {
                        r_neg = self.neg;
                    } else {
                        r_neg = !self.neg;
                        flip(&mut z, &mut r);
                    }
                }
                _ => panic!("unsupported rounding mode"),
            }
        }
        (Int::from_parts(neg, z), Int::from_parts(r_neg, r))
    }

    /// Go's `CmpAbs`: compare |x| and |y|.
    pub fn cmp_abs(&self, y: &Int) -> Ordering {
        nat::cmp(&self.abs, &y.abs)
    }

    /// Go's `Int64`: the low 64 bits as two's complement (undefined in Go
    /// when the value does not fit; this wraps like Go on 64-bit targets).
    pub fn int64(&self) -> i64 {
        let v = nat::low64(&self.abs) as i64;
        if self.neg {
            v.wrapping_neg()
        } else {
            v
        }
    }

    /// Go's `Uint64`: the low 64 bits of |x|.
    pub fn uint64(&self) -> u64 {
        nat::low64(&self.abs)
    }

    /// Go's `IsInt64`.
    pub fn is_int64(&self) -> bool {
        if self.abs.len() <= 1 {
            let w = nat::low64(&self.abs) as i64;
            return w >= 0 || self.neg && w == w.wrapping_neg();
        }
        false
    }

    /// Go's `IsUint64`.
    pub fn is_uint64(&self) -> bool {
        !self.neg && self.abs.len() <= 1
    }

    /// Go's `Float64`: the nearest `f64` (ties to even) and its accuracy.
    pub fn float64(&self) -> (f64, Accuracy) {
        let n = nat::bit_len(&self.abs);
        if n == 0 {
            return (0.0, Accuracy::Exact);
        }
        if n <= 53 || n < 64 && n - nat::trailing_zero_bits(&self.abs) <= 53 {
            let f = nat::low64(&self.abs) as f64;
            return (if self.neg { -f } else { f }, Accuracy::Exact);
        }
        let mut f = Float::new();
        f.set_int(self);
        f.float64()
    }

    /// Go's `SetBytes`: the non-negative big-endian value of buf.
    pub fn from_bytes(buf: &[u8]) -> Int {
        Int::from_parts(false, nat::set_bytes(buf))
    }

    /// Go's `Bytes`: |x| as minimal big-endian bytes.
    pub fn bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.abs.len() * 8];
        let i = nat::bytes(&self.abs, &mut buf);
        buf.split_off(i)
    }

    /// Go's `FillBytes`: |x| zero-extended big-endian into buf. Panics if
    /// buf is too small, as Go does.
    pub fn fill_bytes<'a>(&self, buf: &'a mut [u8]) -> &'a mut [u8] {
        buf.fill(0);
        nat::bytes(&self.abs, buf);
        buf
    }

    /// Go's `BitLen`: the length of |x| in bits.
    pub fn bit_len(&self) -> usize {
        nat::bit_len(&self.abs)
    }

    /// Go's `TrailingZeroBits` of |x|.
    pub fn trailing_zero_bits(&self) -> usize {
        nat::trailing_zero_bits(&self.abs)
    }

    /// Go's `Exp`: x**y mod |m|, or x**y without a modulus when m is `None`
    /// or zero (1 for y <= 0). For y < 0 with a modulus, the inverse of x is
    /// used and `None` is returned when it does not exist.
    pub fn exp(&self, y: &Int, m: Option<&Int>) -> Option<Int> {
        let m_abs: &[u64] = m.map(|m| m.abs.as_slice()).unwrap_or(&[]);
        let inverse;
        let mut x_abs: &[u64] = &self.abs;
        if y.neg {
            if m_abs.is_empty() {
                return Some(Int::one());
            }
            inverse = self.mod_inverse(m?)?;
            x_abs = &inverse.abs;
        }
        let z = nat::exp_nn(x_abs, &y.abs, m_abs);
        let neg = !z.is_empty() && self.neg && y.abs.first().is_some_and(|w| w & 1 == 1);
        if neg && !m_abs.is_empty() {
            return Some(Int::from_parts(false, nat::sub(m_abs, &z)));
        }
        Some(Int::from_parts(neg, z))
    }

    /// Go's `GCD` without cofactors: gcd(|a|, |b|) (zero if both are zero).
    pub fn gcd(a: &Int, b: &Int) -> Int {
        Int::gcd_impl(a, b, false).0
    }

    /// Go's `GCD(x, y, a, b)`: (g, x, y) with g = a·x + b·y, using Go's
    /// Lehmer algorithm so the cofactors match Go's.
    pub fn gcd_ext(a: &Int, b: &Int) -> (Int, Int, Int) {
        let (g, x, y) = Int::gcd_impl(a, b, true);
        (g, x.unwrap_or_default(), y.unwrap_or_default())
    }

    fn gcd_impl(a: &Int, b: &Int, extended: bool) -> (Int, Option<Int>, Option<Int>) {
        if a.abs.is_empty() || b.abs.is_empty() {
            let z = if a.abs.is_empty() { b.abs() } else { a.abs() };
            if !extended {
                return (z, None, None);
            }
            let x = if a.abs.is_empty() {
                Int::zero()
            } else {
                Int::from_parts(a.neg, vec![1])
            };
            let y = if b.abs.is_empty() {
                Int::zero()
            } else {
                Int::from_parts(b.neg, vec![1])
            };
            return (z, Some(x), Some(y));
        }
        lehmer_gcd(a, b, extended)
    }

    /// Go's `ModInverse`: the inverse of x in the ring ℤ/nℤ, or `None` when
    /// x and n are not relatively prime. Panics if n == 0 and x < 0.
    pub fn mod_inverse(&self, n: &Int) -> Option<Int> {
        let n = n.abs();
        let g = if self.neg {
            self.rem_euclid(&n)
        } else {
            self.clone()
        };
        let (d, x, _) = Int::gcd_impl(&g, &n, true);
        let x = x.unwrap_or_default();
        if d != Int::one() {
            return None;
        }
        Some(if x.neg { &x + &n } else { x })
    }

    /// Go's `ModSqrt`: a square root of x mod the odd prime p, or `None` if
    /// x is not a square mod p. The result for composite p is unspecified
    /// (but matches Go's). Panics if p is even.
    pub fn mod_sqrt(&self, p: &Int) -> Option<Int> {
        match jacobi(self, p) {
            -1 => return None,
            0 => return Some(Int::zero()),
            _ => {}
        }
        let x = if self.neg || self >= p {
            self.rem_euclid(p)
        } else {
            self.clone()
        };
        let p0 = p.abs[0];
        Some(if p0 % 4 == 3 {
            mod_sqrt_3mod4(&x, p)
        } else if p0 % 8 == 5 {
            mod_sqrt_5mod8(&x, p)
        } else {
            mod_sqrt_tonelli_shanks(&x, p)
        })
    }

    /// Go's `Lsh`: x << n.
    pub fn lsh(&self, n: usize) -> Int {
        // The sign is kept as is, even for a zero magnitude (a decoded negative zero).
        Int {
            neg: self.neg,
            abs: nat::shl(&self.abs, n),
        }
    }

    /// Go's `Rsh`: x >> n, rounding toward negative infinity for x < 0.
    pub fn rsh(&self, n: usize) -> Int {
        if self.neg {
            let t = nat::sub_w(&self.abs, 1);
            let t = nat::shr(&t, n);
            return Int::from_parts(true, nat::add_w(&t, 1));
        }
        Int::from_parts(false, nat::shr(&self.abs, n))
    }

    /// Go's `Bit`: bit i of x in two's complement.
    pub fn bit(&self, i: usize) -> u32 {
        if i == 0 {
            return nat::bit(&self.abs, 0);
        }
        if self.neg {
            let t = nat::sub_w(&self.abs, 1);
            return nat::bit(&t, i) ^ 1;
        }
        nat::bit(&self.abs, i)
    }

    /// Go's `SetBit`: x with bit i (two's complement) set to b (0 or 1).
    /// Panics if b is not 0 or 1.
    pub fn set_bit(&self, i: usize, b: u32) -> Int {
        if self.neg {
            let t = nat::sub_w(&self.abs, 1);
            let t = nat::set_bit(&t, i, b ^ 1);
            return Int::from_parts(true, nat::add_w(&t, 1));
        }
        Int::from_parts(false, nat::set_bit(&self.abs, i, b))
    }

    /// Go's `And` (two's complement semantics).
    fn bit_and(&self, y: &Int) -> Int {
        let (x, y) = (self, y);
        if x.neg == y.neg {
            if x.neg {
                let x1 = nat::sub_w(&x.abs, 1);
                let y1 = nat::sub_w(&y.abs, 1);
                return Int::from_parts(true, nat::add_w(&nat::or(&x1, &y1), 1));
            }
            return Int::from_parts(false, nat::and(&x.abs, &y.abs));
        }
        let (x, y) = if x.neg { (y, x) } else { (x, y) };
        let y1 = nat::sub_w(&y.abs, 1);
        Int::from_parts(false, nat::and_not(&x.abs, &y1))
    }

    /// Go's `AndNot`: x & ^y (two's complement semantics).
    pub fn and_not(&self, y: &Int) -> Int {
        let x = self;
        if x.neg == y.neg {
            if x.neg {
                let x1 = nat::sub_w(&x.abs, 1);
                let y1 = nat::sub_w(&y.abs, 1);
                return Int::from_parts(false, nat::and_not(&y1, &x1));
            }
            return Int::from_parts(false, nat::and_not(&x.abs, &y.abs));
        }
        if x.neg {
            let x1 = nat::sub_w(&x.abs, 1);
            return Int::from_parts(true, nat::add_w(&nat::or(&x1, &y.abs), 1));
        }
        let y1 = nat::sub_w(&y.abs, 1);
        Int::from_parts(false, nat::and(&x.abs, &y1))
    }

    /// Go's `Or` (two's complement semantics).
    fn bit_or(&self, y: &Int) -> Int {
        let x = self;
        if x.neg == y.neg {
            if x.neg {
                let x1 = nat::sub_w(&x.abs, 1);
                let y1 = nat::sub_w(&y.abs, 1);
                return Int::from_parts(true, nat::add_w(&nat::and(&x1, &y1), 1));
            }
            return Int::from_parts(false, nat::or(&x.abs, &y.abs));
        }
        let (x, y) = if x.neg { (y, x) } else { (x, y) };
        let y1 = nat::sub_w(&y.abs, 1);
        Int::from_parts(true, nat::add_w(&nat::and_not(&y1, &x.abs), 1))
    }

    /// Go's `Xor` (two's complement semantics).
    fn bit_xor(&self, y: &Int) -> Int {
        let x = self;
        if x.neg == y.neg {
            if x.neg {
                let x1 = nat::sub_w(&x.abs, 1);
                let y1 = nat::sub_w(&y.abs, 1);
                return Int::from_parts(false, nat::xor(&x1, &y1));
            }
            return Int::from_parts(false, nat::xor(&x.abs, &y.abs));
        }
        let (x, y) = if x.neg { (y, x) } else { (x, y) };
        let y1 = nat::sub_w(&y.abs, 1);
        Int::from_parts(true, nat::add_w(&nat::xor(&x.abs, &y1), 1))
    }

    /// Go's `Not`: -x - 1.
    pub fn not(&self) -> Int {
        if self.neg {
            return Int::from_parts(false, nat::sub_w(&self.abs, 1));
        }
        Int::from_parts(true, nat::add_w(&self.abs, 1))
    }

    /// Go's `Sqrt`: ⌊√x⌋. Panics if x < 0, as Go does.
    pub fn sqrt(&self) -> Int {
        assert!(!self.neg, "square root of negative number");
        Int::from_parts(false, nat::sqrt(&self.abs))
    }

    /// Go's `Rand`: a uniformly random value in [0, n) drawn from a Go
    /// `math/rand` generator exactly as Go draws it (zero if n <= 0).
    pub fn random<S: crate::math::rand::v1::Source>(
        rand: &mut crate::math::rand::v1::Rand<S>,
        n: &Int,
    ) -> Int {
        if n.neg || n.abs.is_empty() {
            return Int::zero();
        }
        Int::from_parts(false, nat::random(rand, &n.abs, nat::bit_len(&n.abs)))
    }
}

/// Go's `Jacobi(x, y)`: the Jacobi symbol (x/y), one of -1, 0, +1. Panics
/// unless y is odd, as Go does.
pub fn jacobi(x: &Int, y: &Int) -> i32 {
    if y.abs.is_empty() || y.abs[0] & 1 == 0 {
        panic!("big: invalid 2nd argument to Int.Jacobi: need odd integer but got {y}");
    }
    let mut a = x.clone();
    let mut b = y.clone();
    let mut j = 1;
    if b.neg {
        if a.neg {
            j = -1;
        }
        b.neg = false;
    }
    loop {
        if b.abs == [1] {
            return j;
        }
        if a.abs.is_empty() {
            return 0;
        }
        a = a.rem_euclid(&b);
        if a.abs.is_empty() {
            return 0;
        }
        let s = nat::trailing_zero_bits(&a.abs);
        if s & 1 != 0 {
            let bmod8 = b.abs[0] & 7;
            if bmod8 == 3 || bmod8 == 5 {
                j = -j;
            }
        }
        let c = a.rsh(s);
        if b.abs[0] & 3 == 3 && c.abs[0] & 3 == 3 {
            j = -j;
        }
        a = b;
        b = c;
    }
}

fn mod_sqrt_3mod4(x: &Int, p: &Int) -> Int {
    let e = (p + &Int::one()).rsh(2);
    x.exp(&e, Some(p)).unwrap_or_default()
}

fn mod_sqrt_5mod8(x: &Int, p: &Int) -> Int {
    let e = p.rsh(3);
    let tx = x.lsh(1);
    let alpha = tx.exp(&e, Some(p)).unwrap_or_default();
    let mut beta = (&alpha * &alpha).rem_euclid(p);
    beta = (&beta * &tx).rem_euclid(p);
    beta = &beta - &Int::one();
    beta = (&beta * x).rem_euclid(p);
    beta = &beta * &alpha;
    beta.rem_euclid(p)
}

fn mod_sqrt_tonelli_shanks(x: &Int, p: &Int) -> Int {
    let s = p - &Int::one();
    let e = s.trailing_zero_bits();
    let s = s.rsh(e);
    let mut n = Int::new(2);
    while jacobi(&n, p) != -1 {
        n = &n + &Int::one();
    }
    let pow = |a: &Int, b: &Int| a.exp(b, Some(p)).unwrap_or_default();
    let mut y = pow(x, &(&s + &Int::one()).rsh(1));
    let mut b = pow(x, &s);
    let mut g = pow(&n, &s);
    let mut r = e;
    loop {
        let mut m = 0usize;
        let mut t = b.clone();
        while t != Int::one() {
            t = (&t * &t).rem_euclid(p);
            m += 1;
        }
        if m == 0 {
            return y;
        }
        let t = pow(&g, &Int::zero().set_bit(r - m - 1, 1));
        g = (&t * &t).rem_euclid(p);
        y = (&y * &t).rem_euclid(p);
        b = (&b * &g).rem_euclid(p);
        r = m;
    }
}

/// x·w with sign x.neg XOR neg (Go's mulW).
fn mul_w(x: &Int, neg: bool, w: u64) -> Int {
    Int::from_parts(x.neg != neg, nat::mul_add_ww(&x.abs, w, 0))
}

/// Go's lehmerSimulate: single-word cofactors from the leading bits.
fn lehmer_simulate(a: &Int, b: &Int) -> (u64, u64, u64, u64, bool) {
    let m = b.abs.len();
    let n = a.abs.len();
    let h = a.abs[n - 1].leading_zeros();
    let lo = |w: u64| w.checked_shr(64 - h).unwrap_or(0);
    let mut a1 = (a.abs[n - 1] << h) | lo(a.abs[n - 2]);
    let mut a2 = if n == m {
        (b.abs[n - 1] << h) | lo(b.abs[n - 2])
    } else if n == m + 1 {
        lo(b.abs[n - 2])
    } else {
        0
    };
    let mut even = false;
    let (mut u0, mut u1, mut u2) = (0u64, 1u64, 0u64);
    let (mut v0, mut v1, mut v2) = (0u64, 0u64, 1u64);
    while a2 >= v2 && a1.wrapping_sub(a2) >= v1.wrapping_add(v2) {
        let (q, r) = (a1 / a2, a1 % a2);
        (a1, a2) = (a2, r);
        (u0, u1, u2) = (u1, u2, u1.wrapping_add(q.wrapping_mul(u2)));
        (v0, v1, v2) = (v1, v2, v1.wrapping_add(q.wrapping_mul(v2)));
        even = !even;
    }
    (u0, u1, v0, v1, even)
}

fn lehmer_update(a: &mut Int, b: &mut Int, u0: u64, u1: u64, v0: u64, v1: u64, even: bool) {
    let q = mul_w(b, even, v0);
    let r = mul_w(a, even, u1);
    let na = mul_w(a, !even, u0);
    let nb = mul_w(b, !even, v1);
    *a = &na + &q;
    *b = &nb + &r;
}

fn euclid_update(a: &mut Int, b: &mut Int, ua: &mut Int, ub: &mut Int, extended: bool) {
    let (q, r) = a.quo_rem(b);
    if extended {
        let q = &q * &*ub;
        let new_ub = &*ua - &q;
        *ua = std::mem::take(ub);
        *ub = new_ub;
    }
    *a = std::mem::replace(b, r);
}

/// Go's lehmerGCD (Jebelean's improved Lehmer GCD with cosequences).
fn lehmer_gcd(a0: &Int, b0: &Int, extended: bool) -> (Int, Option<Int>, Option<Int>) {
    let mut a = a0.abs();
    let mut b = b0.abs();
    let mut ua = Int::one();
    let mut ub = Int::zero();
    if nat::cmp(&a.abs, &b.abs) == Ordering::Less {
        std::mem::swap(&mut a, &mut b);
        std::mem::swap(&mut ua, &mut ub);
    }
    while b.abs.len() > 1 {
        let (u0, u1, v0, v1, even) = lehmer_simulate(&a, &b);
        if v0 != 0 {
            lehmer_update(&mut a, &mut b, u0, u1, v0, v1, even);
            if extended {
                lehmer_update(&mut ua, &mut ub, u0, u1, v0, v1, even);
            }
        } else {
            euclid_update(&mut a, &mut b, &mut ua, &mut ub, extended);
        }
    }
    if !b.abs.is_empty() {
        if a.abs.len() > 1 {
            euclid_update(&mut a, &mut b, &mut ua, &mut ub, extended);
        }
        if !b.abs.is_empty() {
            let (mut a_word, mut b_word) = (a.abs[0], b.abs[0]);
            if extended {
                let (mut ua_w, mut ub_w) = (1u64, 0u64);
                let (mut va_w, mut vb_w) = (0u64, 1u64);
                let mut even = true;
                while b_word != 0 {
                    let (q, r) = (a_word / b_word, a_word % b_word);
                    (a_word, b_word) = (b_word, r);
                    (ua_w, ub_w) = (ub_w, ua_w.wrapping_add(q.wrapping_mul(ub_w)));
                    (va_w, vb_w) = (vb_w, va_w.wrapping_add(q.wrapping_mul(vb_w)));
                    even = !even;
                }
                let t1 = mul_w(&ua, !even, ua_w);
                let t2 = mul_w(&ub, even, va_w);
                ua = &t1 + &t2;
            } else {
                while b_word != 0 {
                    (a_word, b_word) = (b_word, a_word % b_word);
                }
            }
            a = Int::from_u64(a_word);
        }
    }
    if !extended {
        return (a, None, None);
    }
    let mut y = a0 * &ua;
    if a0.neg {
        y = y.neg();
    }
    let y = (&a - &y).div_euclid(b0);
    let x = if a0.neg { ua.neg() } else { ua };
    (a, Some(x), Some(y))
}

impl Ord for Int {
    fn cmp(&self, y: &Int) -> Ordering {
        match (self.neg, y.neg) {
            (false, false) => nat::cmp(&self.abs, &y.abs),
            (true, true) => nat::cmp(&y.abs, &self.abs),
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
        }
    }
}

impl PartialOrd for Int {
    fn partial_cmp(&self, other: &Int) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

macro_rules! from_signed {
    ($($t:ty),*) => {$(
        impl From<$t> for Int {
            fn from(x: $t) -> Int {
                Int::new(i64::from(x))
            }
        }
    )*};
}
from_signed!(i8, i16, i32, i64);

macro_rules! from_unsigned {
    ($($t:ty),*) => {$(
        impl From<$t> for Int {
            fn from(x: $t) -> Int {
                Int::from_u64(u64::from(x))
            }
        }
    )*};
}
from_unsigned!(u8, u16, u32, u64);

impl From<u128> for Int {
    fn from(x: u128) -> Int {
        Int::from_parts(false, nat::normalized(vec![x as u64, (x >> 64) as u64]))
    }
}

impl From<i128> for Int {
    fn from(x: i128) -> Int {
        let u = x.unsigned_abs();
        Int::from_parts(x < 0, nat::normalized(vec![u as u64, (u >> 64) as u64]))
    }
}

/// Implements a binary operator for every owned/borrowed operand pairing,
/// delegating to the by-reference method.
macro_rules! int_binop {
    ($($trait:ident $method:ident => $imp:ident,)*) => {$(
        impl ops::$trait<&Int> for &Int {
            type Output = Int;
            fn $method(self, y: &Int) -> Int {
                self.$imp(y)
            }
        }
        impl ops::$trait<Int> for Int {
            type Output = Int;
            fn $method(self, y: Int) -> Int {
                self.$imp(&y)
            }
        }
        impl ops::$trait<&Int> for Int {
            type Output = Int;
            fn $method(self, y: &Int) -> Int {
                self.$imp(y)
            }
        }
        impl ops::$trait<Int> for &Int {
            type Output = Int;
            fn $method(self, y: Int) -> Int {
                self.$imp(&y)
            }
        }
    )*};
}

// `/` and `%` truncate toward zero (Go's `Quo` and `Rem`); the Euclidean
// forms are `Int::div_euclid` and `Int::rem_euclid`. Division by zero panics.
int_binop! {
    Add add => plus,
    Sub sub => minus,
    Mul mul => times,
    Div div => quotient,
    Rem rem => remainder,
    BitAnd bitand => bit_and,
    BitOr bitor => bit_or,
    BitXor bitxor => bit_xor,
}

impl ops::Neg for &Int {
    type Output = Int;
    fn neg(self) -> Int {
        Int::neg(self)
    }
}

impl ops::Neg for Int {
    type Output = Int;
    fn neg(self) -> Int {
        Int::neg(&self)
    }
}

impl ops::Not for &Int {
    type Output = Int;
    fn not(self) -> Int {
        Int::not(self)
    }
}

impl ops::Not for Int {
    type Output = Int;
    fn not(self) -> Int {
        Int::not(&self)
    }
}

impl ops::Shl<usize> for &Int {
    type Output = Int;
    fn shl(self, n: usize) -> Int {
        self.lsh(n)
    }
}

impl ops::Shr<usize> for &Int {
    type Output = Int;
    fn shr(self, n: usize) -> Int {
        self.rsh(n)
    }
}

impl ops::Shl<usize> for Int {
    type Output = Int;
    fn shl(self, n: usize) -> Int {
        self.lsh(n)
    }
}

impl ops::Shr<usize> for Int {
    type Output = Int;
    fn shr(self, n: usize) -> Int {
        self.rsh(n)
    }
}
