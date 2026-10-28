// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/big/rat.go.

use super::int::Int;
use super::nat::{self, Nat};
use std::cmp::Ordering;
use std::ops;

/// Go's `big.Rat`: an exact rational number a/b. Every operation returns a
/// normalized value (b > 0, gcd(a, b) == 1), but [`Rat::gob_decode`] stores
/// what it reads as Go does: the denominator may be empty (meaning 1), the
/// fraction unreduced, and a zero numerator negative. Equality is `Cmp == 0`.
pub struct Rat {
    pub(super) a: Int,
    pub(super) b: Int,
}

/// Go's `Set`: an empty denominator becomes 1.
impl Clone for Rat {
    fn clone(&self) -> Rat {
        Rat {
            a: self.a.clone(),
            b: self.den().clone(),
        }
    }
}

impl PartialEq for Rat {
    fn eq(&self, other: &Rat) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Rat {}

impl std::hash::Hash for Rat {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // Values that compare equal (an unreduced decoded 2/4 and 1/2) hash alike.
        let n = Rat::norm(self.a.clone(), self.den().clone());
        n.a.hash(state);
        n.b.hash(state);
    }
}

fn one() -> &'static Int {
    static ONE: std::sync::OnceLock<Int> = std::sync::OnceLock::new();
    ONE.get_or_init(|| Int::from_u64(1))
}

impl Default for Rat {
    fn default() -> Rat {
        Rat::from_int(&Int::zero())
    }
}

/// 2**e for -1022 <= e <= 1023.
fn pow2(e: i32) -> f64 {
    f64::from_bits(((e + 1023) as u64) << 52)
}

/// Go's math.Ldexp for the exactly representable results produced here
/// (at most one rounding step, at the end).
pub(super) fn ldexp(frac: f64, exp: i64) -> f64 {
    let mut x = frac;
    let mut e = exp;
    while e > 1000 {
        x *= pow2(1000);
        e -= 1000;
    }
    while e < -1000 {
        x *= pow2(-1000);
        e += 1000;
    }
    x * pow2(e as i32)
}

/// Go's quotToFloat64/quotToFloat32: the nearest float to a/b (ties to
/// even) and whether it is exact, for a float with `msize` explicit
/// mantissa bits and exponent bias `ebias`.
fn quot_to_float(a: &[u64], b: &[u64], msize: i64, ebias: i64) -> (f64, bool) {
    let msize1 = msize + 1;
    let msize2 = msize1 + 1;
    let emin = 1 - ebias;
    let alen = nat::bit_len(a) as i64;
    if alen == 0 {
        return (0.0, true);
    }
    let blen = nat::bit_len(b) as i64;
    assert!(blen != 0, "division by zero");
    let mut exp = alen - blen;
    let mut a2: Nat = a.to_vec();
    let mut b2: Nat = b.to_vec();
    let shift = msize2 - exp;
    if shift > 0 {
        a2 = nat::shl(&a2, shift as usize);
    } else if shift < 0 {
        b2 = nat::shl(&b2, (-shift) as usize);
    }
    let (q, r) = nat::div(&a2, &b2);
    let mut mantissa = nat::low64(&q);
    let mut have_rem = !r.is_empty();
    if mantissa >> msize2 == 1 {
        if mantissa & 1 == 1 {
            have_rem = true;
        }
        mantissa >>= 1;
        exp += 1;
    }
    assert!(
        mantissa >> msize1 == 1,
        "expected exactly {msize2} bits of result"
    );
    if emin - msize <= exp && exp <= emin {
        let shift = (emin - (exp - 1)) as u32;
        let lostbits = mantissa & ((1u64 << shift) - 1);
        have_rem = have_rem || lostbits != 0;
        mantissa >>= shift;
        exp = 2 - ebias;
    }
    let mut exact = !have_rem;
    if mantissa & 1 != 0 {
        exact = false;
        if have_rem || mantissa & 2 != 0 {
            mantissa += 1;
            if mantissa >= 1 << msize2 {
                mantissa >>= 1;
                exp += 1;
            }
        }
    }
    mantissa >>= 1;
    let f = ldexp(mantissa as f64, exp - msize1);
    (f, exact)
}

impl Rat {
    /// Normalize sign and reduce by the gcd, as Go's Rat.norm.
    fn norm(a: Int, b: Int) -> Rat {
        if a.abs.is_empty() {
            return Rat {
                a: Int::zero(),
                b: Int::from_u64(1),
            };
        }
        let neg = a.neg != b.neg;
        let (mut a_abs, mut b_abs) = (a.abs, b.abs);
        let f = Int::gcd(
            &Int::from_parts(false, a_abs.clone()),
            &Int::from_parts(false, b_abs.clone()),
        );
        if !nat::is_one(&f.abs) {
            a_abs = nat::div(&a_abs, &f.abs).0;
            b_abs = nat::div(&b_abs, &f.abs).0;
        }
        Rat {
            a: Int::from_parts(neg, a_abs),
            b: Int::from_parts(false, b_abs),
        }
    }

    /// Go's `NewRat(a, b)`. Panics if b == 0.
    pub fn new(a: i64, b: i64) -> Rat {
        assert!(b != 0, "division by zero");
        Rat::norm(Int::new(a), Int::new(b))
    }

    /// Go's `SetFrac(a, b)`. Panics if b == 0.
    pub fn from_frac(a: &Int, b: &Int) -> Rat {
        assert!(!b.abs.is_empty(), "division by zero");
        Rat::norm(a.clone(), b.clone())
    }

    /// Go's `SetInt`.
    pub fn from_int(x: &Int) -> Rat {
        Rat {
            a: x.clone(),
            b: Int::from_u64(1),
        }
    }

    /// Go's `SetInt64`.
    pub fn from_i64(x: i64) -> Rat {
        Rat::from_int(&Int::new(x))
    }

    /// Go's `SetUint64`.
    pub fn from_u64(x: u64) -> Rat {
        Rat::from_int(&Int::from_u64(x))
    }

    /// Go's `SetFloat64`: the exact value of f, or `None` if f is not
    /// finite.
    pub fn from_f64(f: f64) -> Option<Rat> {
        const EXP_MASK: u64 = (1 << 11) - 1;
        let bits = f.to_bits();
        let mut mantissa = bits & ((1 << 52) - 1);
        let mut exp = ((bits >> 52) & EXP_MASK) as i64;
        match exp as u64 {
            EXP_MASK => return None,
            0 => exp -= 1022,
            _ => {
                mantissa |= 1 << 52;
                exp -= 1023;
            }
        }
        let mut shift = 52 - exp;
        while mantissa & 1 == 0 && shift > 0 {
            mantissa >>= 1;
            shift -= 1;
        }
        let mut a = Int::from_parts(f < 0.0, nat::from_u64(mantissa));
        let mut b = Int::from_u64(1);
        if shift > 0 {
            b = b.lsh(shift as usize);
        } else {
            a = a.lsh((-shift) as usize);
        }
        Some(Rat::norm(a, b))
    }

    /// Go's `Float64`: the nearest `f64` and whether it is exact.
    pub fn float64(&self) -> (f64, bool) {
        let (f, exact) = quot_to_float(&self.a.abs, &self.den().abs, 52, 1023);
        (if self.a.neg { -f } else { f }, exact && f.is_finite())
    }

    /// Go's `Float32`: the nearest `f32` and whether it is exact.
    pub fn float32(&self) -> (f32, bool) {
        let (f, exact) = quot_to_float(&self.a.abs, &self.den().abs, 23, 127);
        let f = f as f32;
        (if self.a.neg { -f } else { f }, exact && f.is_finite())
    }

    /// Go's `Abs`.
    pub fn abs(&self) -> Rat {
        Rat {
            a: self.a.abs(),
            b: self.den().clone(),
        }
    }

    /// Go's `Neg`.
    pub fn neg(&self) -> Rat {
        Rat {
            a: self.a.neg(),
            b: self.den().clone(),
        }
    }

    /// Go's `Inv`: 1/x. Panics if x == 0.
    pub fn inv(&self) -> Rat {
        assert!(!self.a.abs.is_empty(), "division by zero");
        Rat {
            a: Int::from_parts(self.a.neg, self.den().abs.clone()),
            b: Int::from_parts(false, self.a.abs.clone()),
        }
    }

    /// Go's `Sign`.
    pub fn sign(&self) -> i32 {
        self.a.sign()
    }

    /// Go's `IsInt`: whether the denominator is 1.
    pub fn is_int(&self) -> bool {
        nat::is_one(&self.den().abs)
    }

    /// Go's `Num`: the numerator (with the sign of x).
    pub fn num(&self) -> &Int {
        &self.a
    }

    /// Go's `Denom`: the denominator (always > 0).
    pub fn denom(&self) -> &Int {
        self.den()
    }

    /// The denominator, where an empty one (which Go allows after a gob
    /// decode and for the zero value) is 1.
    pub(super) fn den(&self) -> &Int {
        if self.b.abs.is_empty() {
            one()
        } else {
            &self.b
        }
    }

    /// Go's `scaleDenom`: a·d for x = a/b and denominator d of the other
    /// operand. The sign of x is kept, even for a zero magnitude.
    fn scale(x: &Int, f: &Int) -> Int {
        Int {
            neg: x.neg,
            abs: nat::mul(&x.abs, &f.abs),
        }
    }

    /// Go's `Add`.
    fn plus(&self, y: &Rat) -> Rat {
        let a1 = Rat::scale(&self.a, y.den());
        let a2 = Rat::scale(&y.a, self.den());
        Rat::norm(&a1 + &a2, self.den() * y.den())
    }

    /// Go's `Sub`.
    fn minus(&self, y: &Rat) -> Rat {
        let a1 = Rat::scale(&self.a, y.den());
        let a2 = Rat::scale(&y.a, self.den());
        Rat::norm(&a1 - &a2, self.den() * y.den())
    }

    /// Go's `Mul`.
    fn times(&self, y: &Rat) -> Rat {
        Rat::norm(&self.a * &y.a, self.den() * y.den())
    }

    /// Go's `Quo`: x/y. Panics if y == 0.
    fn quotient(&self, y: &Rat) -> Rat {
        assert!(!y.a.abs.is_empty(), "division by zero");
        let a = Rat::scale(&self.a, y.den());
        let b = Rat::scale(&y.a, self.den());
        Rat::norm(a, b)
    }
}

impl Ord for Rat {
    fn cmp(&self, y: &Rat) -> Ordering {
        Rat::scale(&self.a, y.den()).cmp(&Rat::scale(&y.a, self.den()))
    }
}

impl PartialOrd for Rat {
    fn partial_cmp(&self, other: &Rat) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<Int> for Rat {
    fn from(x: Int) -> Rat {
        Rat::from_int(&x)
    }
}

impl From<i64> for Rat {
    fn from(x: i64) -> Rat {
        Rat::from_i64(x)
    }
}

/// Implements a binary operator for every owned/borrowed operand pairing,
/// delegating to the by-reference method.
macro_rules! rat_binop {
    ($($trait:ident $method:ident => $imp:ident,)*) => {$(
        impl ops::$trait<&Rat> for &Rat {
            type Output = Rat;
            fn $method(self, y: &Rat) -> Rat {
                self.$imp(y)
            }
        }
        impl ops::$trait<Rat> for Rat {
            type Output = Rat;
            fn $method(self, y: Rat) -> Rat {
                self.$imp(&y)
            }
        }
        impl ops::$trait<&Rat> for Rat {
            type Output = Rat;
            fn $method(self, y: &Rat) -> Rat {
                self.$imp(y)
            }
        }
        impl ops::$trait<Rat> for &Rat {
            type Output = Rat;
            fn $method(self, y: Rat) -> Rat {
                self.$imp(&y)
            }
        }
    )*};
}

// `/` is exact division (Go's `Quo`); dividing by zero panics.
rat_binop! {
    Add add => plus,
    Sub sub => minus,
    Mul mul => times,
    Div div => quotient,
}

impl ops::Neg for &Rat {
    type Output = Rat;
    fn neg(self) -> Rat {
        Rat::neg(self)
    }
}

impl ops::Neg for Rat {
    type Output = Rat;
    fn neg(self) -> Rat {
        Rat::neg(&self)
    }
}
