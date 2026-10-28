// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/big/{float,sqrt}.go.

use super::int::Int;
use super::nat::{self, Nat};
use super::rat::Rat;
use super::{Accuracy, ErrNaN, RoundingMode};
use std::cmp::Ordering;

/// Go's `MaxExp`: the largest supported exponent.
pub const MAX_EXP: i64 = i32::MAX as i64;
/// Go's `MinExp`: the smallest supported exponent.
pub const MIN_EXP: i64 = i32::MIN as i64;
/// Go's `MaxPrec`: the largest (theoretically) supported precision.
pub const MAX_PREC: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub(super) enum Form {
    #[default]
    Zero,
    Finite,
    Inf,
    /// Go's form value 3, which only `gob_decode` can produce (it stores the
    /// form bits unvalidated).
    Invalid,
}

/// Go's `big.Float`: a binary floating-point number sign × mantissa ×
/// 2**exponent with a per-value precision (mantissa bits), rounding mode
/// and accuracy of the last operation.
///
/// As in Go, the zero value (`Float::new()`) is +0 with precision 0 and
/// mode `ToNearestEven`; a receiver with precision 0 takes its precision
/// from the operands of the first operation that sets it (the larger
/// operand precision for arithmetic, 64 for integers, 53 for `f64`).
/// Results are rounded to the receiver's precision with its mode, and
/// [`Float::acc`] reports the direction of the rounding error.
///
/// Operations that are NaN in IEEE 754 return [`ErrNaN`] from the receiver
/// methods (`add_into` and friends) and from `checked_*`; the receiver is
/// then +0 with `Exact` accuracy, as Go leaves it. The operators (`+`, `-`,
/// `*`, `/`) panic with the [`ErrNaN`] message instead, as Go does.
#[derive(Clone, Debug, Default)]
pub struct Float {
    pub(super) prec: u32,
    pub(super) mode: RoundingMode,
    pub(super) acc: Accuracy,
    pub(super) form: Form,
    pub(super) neg: bool,
    pub(super) mant: Nat,
    pub(super) exp: i32,
}

const MSB: u64 = 1 << 63;

fn msb64(x: &[u64]) -> u64 {
    x.last().copied().unwrap_or(0)
}

fn msb32(x: &[u64]) -> u32 {
    (msb64(x) >> 32) as u32
}

impl Float {
    /// Go's `new(Float)`: +0 with precision 0 and `ToNearestEven`.
    pub fn new() -> Float {
        Float::default()
    }

    /// +0 with the given precision (`new(Float).SetPrec(prec)`).
    pub fn with_prec(prec: u32) -> Float {
        let mut z = Float::new();
        z.set_prec(prec);
        z
    }

    /// Go's `NewFloat(x)`: x with precision 53. NaN is an error.
    pub fn from_f64(x: f64) -> Result<Float, ErrNaN> {
        if x.is_nan() {
            return Err(ErrNaN::new("NewFloat(NaN)"));
        }
        let mut z = Float::new();
        z.set_float64(x)?;
        Ok(z)
    }

    /// `new(Float).SetInt64(x)`: precision 64.
    pub fn from_i64(x: i64) -> Float {
        let mut z = Float::new();
        z.set_int64(x);
        z
    }

    /// `new(Float).SetUint64(x)`: precision 64.
    pub fn from_u64(x: u64) -> Float {
        let mut z = Float::new();
        z.set_uint64(x);
        z
    }

    /// `new(Float).SetInt(x)`: precision max(bit length, 64), exact.
    pub fn from_int(x: &Int) -> Float {
        let mut z = Float::new();
        z.set_int(x);
        z
    }

    /// Go's `SetPrec`: set the precision, rounding the value if it shrinks.
    /// Precision 0 maps finite values to ±0 (with the matching accuracy);
    /// infinities are unchanged.
    pub fn set_prec(&mut self, prec: u32) -> &mut Float {
        self.acc = Accuracy::Exact;
        if prec == 0 {
            self.prec = 0;
            if self.form == Form::Finite {
                self.acc = Accuracy::from_above(self.neg);
                self.form = Form::Zero;
            }
            return self;
        }
        let old = self.prec;
        self.prec = prec;
        if self.prec < old {
            self.round(0);
        }
        self
    }

    /// Go's `SetMode`: set the rounding mode and reset accuracy to `Exact`.
    pub fn set_mode(&mut self, mode: RoundingMode) -> &mut Float {
        self.mode = mode;
        self.acc = Accuracy::Exact;
        self
    }

    /// Go's `Prec`: the mantissa precision in bits.
    pub fn prec(&self) -> u32 {
        self.prec
    }

    /// Go's `MinPrec`: the minimum precision that represents x exactly.
    pub fn min_prec(&self) -> u64 {
        if self.form != Form::Finite {
            return 0;
        }
        self.mant.len() as u64 * 64 - nat::trailing_zero_bits(&self.mant) as u64
    }

    /// Go's `Mode`.
    pub fn mode(&self) -> RoundingMode {
        self.mode
    }

    /// Go's `Acc`: the accuracy of the most recent operation.
    pub fn acc(&self) -> Accuracy {
        self.acc
    }

    /// Go's `Sign`: -1, 0 or +1 (0 for ±0).
    pub fn sign(&self) -> i32 {
        if self.form == Form::Zero {
            0
        } else if self.neg {
            -1
        } else {
            1
        }
    }

    /// Go's `MantExp`: the exponent e with x == mant × 2**e and
    /// 0.5 <= |mant| < 1.0 (0 for ±0 and ±Inf). If `mant` is given it
    /// receives a copy of x (precision and mode included) with exponent 0.
    pub fn mant_exp(&self, mant: Option<&mut Float>) -> i32 {
        let exp = if self.form == Form::Finite {
            self.exp
        } else {
            0
        };
        if let Some(m) = mant {
            m.copy_from(self);
            if m.form == Form::Finite {
                m.exp = 0;
            }
        }
        exp
    }

    fn set_exp_and_round(&mut self, exp: i64, sbit: u32) {
        if exp < MIN_EXP {
            self.acc = Accuracy::from_above(self.neg);
            self.form = Form::Zero;
            return;
        }
        if exp > MAX_EXP {
            self.acc = Accuracy::from_above(!self.neg);
            self.form = Form::Inf;
            return;
        }
        self.form = Form::Finite;
        self.exp = exp as i32;
        self.round(sbit);
    }

    /// Go's `SetMantExp`: mant × 2**exp, rounded to the receiver precision
    /// after a copy of mant (so a receiver with precision 0 takes mant's).
    pub fn set_mant_exp(&mut self, mant: &Float, exp: i64) -> &mut Float {
        self.copy_from(mant);
        self.scale_exp(exp);
        self
    }

    fn scale_exp(&mut self, exp: i64) {
        if self.form == Form::Finite {
            self.set_exp_and_round(i64::from(self.exp) + exp, 0);
        }
    }

    /// Go's `Signbit`: whether x is negative or -0.
    pub fn signbit(&self) -> bool {
        self.neg
    }

    /// Go's `IsInf`.
    pub fn is_inf(&self) -> bool {
        self.form == Form::Inf
    }

    /// Go's `IsInt`: whether x is an integer (±Inf are not).
    pub fn is_int(&self) -> bool {
        if self.form != Form::Finite {
            return self.form == Form::Zero;
        }
        if self.exp <= 0 {
            return false;
        }
        self.prec <= self.exp as u32 || self.min_prec() <= self.exp as u64
    }

    /// Round the mantissa to the receiver precision using its mode; sbit is
    /// a sticky bit for bits already discarded.
    pub(super) fn round(&mut self, mut sbit: u32) {
        self.acc = Accuracy::Exact;
        if self.form != Form::Finite {
            return;
        }
        let m = self.mant.len() as u64;
        let bits = m * 64;
        let prec = u64::from(self.prec);
        if bits <= prec {
            return;
        }
        let r = (bits - prec - 1) as usize;
        let rbit = nat::bit(&self.mant, r) & 1;
        if sbit == 0 && (rbit == 0 || self.mode == RoundingMode::ToNearestEven) {
            sbit = nat::sticky(&self.mant, r);
        }
        sbit &= 1;
        let n = prec.div_ceil(64);
        if m > n {
            self.mant.drain(..(m - n) as usize);
        }
        let n = n as usize;
        let ntz = n as u64 * 64 - prec;
        let lsb = 1u64 << ntz;
        if rbit | sbit != 0 {
            let inc = match self.mode {
                RoundingMode::ToNegativeInf => self.neg,
                RoundingMode::ToZero => false,
                RoundingMode::ToNearestEven => rbit != 0 && (sbit != 0 || self.mant[0] & lsb != 0),
                RoundingMode::ToNearestAway => rbit != 0,
                RoundingMode::AwayFromZero => true,
                RoundingMode::ToPositiveInf => !self.neg,
                _ => panic!("unreachable"),
            };
            self.acc = Accuracy::from_above(inc != self.neg);
            if inc {
                let mut carry = lsb;
                for w in self.mant.iter_mut() {
                    let (s, c) = w.overflowing_add(carry);
                    *w = s;
                    carry = u64::from(c);
                    if carry == 0 {
                        break;
                    }
                }
                if carry != 0 {
                    if i64::from(self.exp) >= MAX_EXP {
                        self.form = Form::Inf;
                        return;
                    }
                    self.exp += 1;
                    for i in 0..n {
                        let hi = if i + 1 < n { self.mant[i + 1] << 63 } else { 0 };
                        self.mant[i] = (self.mant[i] >> 1) | hi;
                    }
                    self.mant[n - 1] |= MSB;
                }
            }
        }
        self.mant[0] &= !(lsb - 1);
    }

    fn set_bits64(&mut self, neg: bool, x: u64) -> &mut Float {
        if self.prec == 0 {
            self.prec = 64;
        }
        self.acc = Accuracy::Exact;
        self.neg = neg;
        if x == 0 {
            self.form = Form::Zero;
            return self;
        }
        self.form = Form::Finite;
        let s = x.leading_zeros();
        self.mant = vec![x << s];
        self.exp = (64 - s) as i32;
        if self.prec < 64 {
            self.round(0);
        }
        self
    }

    /// Go's `SetUint64` (precision 64 if 0).
    pub fn set_uint64(&mut self, x: u64) -> &mut Float {
        self.set_bits64(false, x)
    }

    /// Go's `SetInt64` (precision 64 if 0).
    pub fn set_int64(&mut self, x: i64) -> &mut Float {
        self.set_bits64(x < 0, x.unsigned_abs())
    }

    /// Go's `SetFloat64` (precision 53 if 0). NaN is an error.
    pub fn set_float64(&mut self, x: f64) -> Result<&mut Float, ErrNaN> {
        if self.prec == 0 {
            self.prec = 53;
        }
        if x.is_nan() {
            return Err(ErrNaN::new("Float.SetFloat64(NaN)"));
        }
        self.acc = Accuracy::Exact;
        self.neg = x.is_sign_negative();
        if x == 0.0 {
            self.form = Form::Zero;
            return Ok(self);
        }
        if x.is_infinite() {
            self.form = Form::Inf;
            return Ok(self);
        }
        self.form = Form::Finite;
        let bits = x.to_bits();
        let e = ((bits >> 52) & 0x7ff) as i32;
        let frac = bits & ((1 << 52) - 1);
        if e == 0 {
            let lz = frac.leading_zeros();
            self.mant = vec![frac << lz];
            self.exp = -1010 - lz as i32;
        } else {
            self.mant = vec![(1 << 63) | (frac << 11)];
            self.exp = e - 1022;
        }
        if self.prec < 53 {
            self.round(0);
        }
        Ok(self)
    }

    /// Go's `SetInt` (precision max(bit length, 64) if 0).
    pub fn set_int(&mut self, x: &Int) -> &mut Float {
        let bits = x.bit_len() as u64;
        if self.prec == 0 {
            self.prec = bits.max(64).min(u64::from(MAX_PREC)) as u32;
        }
        self.acc = Accuracy::Exact;
        self.neg = x.neg;
        if x.abs.is_empty() {
            self.form = Form::Zero;
            return self;
        }
        self.mant = x.abs.clone();
        nat::fnorm(&mut self.mant);
        self.set_exp_and_round(bits as i64, 0);
        self
    }

    /// Go's `SetRat` (precision max of numerator and denominator
    /// precisions if 0).
    pub fn set_rat(&mut self, x: &Rat) -> &mut Float {
        if x.is_int() {
            return self.set_int(x.num());
        }
        let a = Float::from_int(x.num());
        let b = Float::from_int(x.denom());
        if self.prec == 0 {
            self.prec = a.prec.max(b.prec);
        }
        self.quo_finite(&a, &b);
        self
    }

    /// Go's `SetInf`: +Inf, or -Inf if signbit.
    pub fn set_inf(&mut self, signbit: bool) -> &mut Float {
        self.acc = Accuracy::Exact;
        self.form = Form::Inf;
        self.neg = signbit;
        self
    }

    /// Go's `Set`: x rounded to the receiver precision (which becomes x's
    /// precision if 0).
    pub fn set(&mut self, x: &Float) -> &mut Float {
        self.acc = Accuracy::Exact;
        self.form = x.form;
        self.neg = x.neg;
        if x.form == Form::Finite {
            self.exp = x.exp;
            self.mant = x.mant.clone();
        }
        if self.prec == 0 {
            self.prec = x.prec;
        } else if self.prec < x.prec {
            self.round(0);
        }
        self
    }

    /// Go's `Copy`: x exactly, including precision, mode and accuracy.
    pub fn copy_from(&mut self, x: &Float) -> &mut Float {
        self.prec = x.prec;
        self.mode = x.mode;
        self.acc = x.acc;
        self.form = x.form;
        self.neg = x.neg;
        if self.form == Form::Finite {
            self.mant = x.mant.clone();
            self.exp = x.exp;
        }
        self
    }

    /// Go's `Uint64`: x truncated toward zero, saturating, with accuracy.
    pub fn uint64(&self) -> (u64, Accuracy) {
        match self.form {
            Form::Invalid => panic!("unreachable"),
            Form::Finite => {
                if self.neg {
                    return (0, Accuracy::Above);
                }
                if self.exp <= 0 {
                    return (0, Accuracy::Below);
                }
                if self.exp <= 64 {
                    let u = msb64(&self.mant) >> (64 - self.exp as u32);
                    if self.min_prec() <= 64 {
                        return (u, Accuracy::Exact);
                    }
                    return (u, Accuracy::Below);
                }
                (u64::MAX, Accuracy::Below)
            }
            Form::Zero => (0, Accuracy::Exact),
            Form::Inf => {
                if self.neg {
                    (0, Accuracy::Above)
                } else {
                    (u64::MAX, Accuracy::Below)
                }
            }
        }
    }

    /// Go's `Int64`: x truncated toward zero, saturating, with accuracy.
    pub fn int64(&self) -> (i64, Accuracy) {
        match self.form {
            Form::Invalid => panic!("unreachable"),
            Form::Finite => {
                let mut acc = Accuracy::from_above(self.neg);
                if self.exp <= 0 {
                    return (0, acc);
                }
                if self.exp <= 63 {
                    let mut i = (msb64(&self.mant) >> (64 - self.exp as u32)) as i64;
                    if self.neg {
                        i = -i;
                    }
                    if self.min_prec() <= self.exp as u64 {
                        return (i, Accuracy::Exact);
                    }
                    return (i, acc);
                }
                if self.neg {
                    if self.exp == 64 && self.min_prec() == 1 {
                        acc = Accuracy::Exact;
                    }
                    return (i64::MIN, acc);
                }
                (i64::MAX, Accuracy::Below)
            }
            Form::Zero => (0, Accuracy::Exact),
            Form::Inf => {
                if self.neg {
                    (i64::MIN, Accuracy::Above)
                } else {
                    (i64::MAX, Accuracy::Below)
                }
            }
        }
    }

    /// Go's `Float32`: the nearest `f32` (ties to even) and accuracy.
    pub fn float32(&self) -> (f32, Accuracy) {
        match self.form {
            Form::Invalid => panic!("unreachable"),
            Form::Finite => {
                const FBITS: i32 = 32;
                const MBITS: i32 = 23;
                const EBITS: i32 = FBITS - MBITS - 1;
                const BIAS: i32 = (1 << (EBITS - 1)) - 1;
                const EMIN: i32 = 1 - BIAS;
                const EMAX: i32 = BIAS;
                let mut e = self.exp - 1;
                let mut p = MBITS + 1;
                if e < EMIN {
                    p = MBITS + 1 - EMIN + e;
                    if p < 0 || p == 0 && nat::sticky(&self.mant, self.mant.len() * 64 - 1) == 0 {
                        if self.neg {
                            return (-0.0, Accuracy::Above);
                        }
                        return (0.0, Accuracy::Below);
                    }
                    if p == 0 {
                        let tiny = f32::from_bits(1);
                        if self.neg {
                            return (-tiny, Accuracy::Below);
                        }
                        return (tiny, Accuracy::Above);
                    }
                }
                let mut r = Float::with_prec_raw(p as u32);
                r.set(self);
                e = r.exp - 1;
                if r.form == Form::Inf || e > EMAX {
                    if self.neg {
                        return (f32::NEG_INFINITY, Accuracy::Below);
                    }
                    return (f32::INFINITY, Accuracy::Above);
                }
                let sign: u32 = if self.neg { 1 << (FBITS - 1) } else { 0 };
                let (bexp, mant) = if e < EMIN {
                    let p = MBITS + 1 - EMIN + e;
                    (0, msb32(&r.mant) >> (FBITS - p) as u32)
                } else {
                    (
                        ((e + BIAS) as u32) << MBITS,
                        (msb32(&r.mant) >> EBITS) & ((1 << MBITS) - 1),
                    )
                };
                (f32::from_bits(sign | bexp | mant), r.acc)
            }
            Form::Zero => (if self.neg { -0.0 } else { 0.0 }, Accuracy::Exact),
            Form::Inf => (
                if self.neg {
                    f32::NEG_INFINITY
                } else {
                    f32::INFINITY
                },
                Accuracy::Exact,
            ),
        }
    }

    /// Go's `Float64`: the nearest `f64` (ties to even) and accuracy.
    pub fn float64(&self) -> (f64, Accuracy) {
        match self.form {
            Form::Invalid => panic!("unreachable"),
            Form::Finite => {
                const FBITS: i32 = 64;
                const MBITS: i32 = 52;
                const EBITS: i32 = FBITS - MBITS - 1;
                const BIAS: i32 = (1 << (EBITS - 1)) - 1;
                const EMIN: i32 = 1 - BIAS;
                const EMAX: i32 = BIAS;
                let mut e = self.exp - 1;
                let mut p = MBITS + 1;
                if e < EMIN {
                    p = MBITS + 1 - EMIN + e;
                    if p < 0 || p == 0 && nat::sticky(&self.mant, self.mant.len() * 64 - 1) == 0 {
                        if self.neg {
                            return (-0.0, Accuracy::Above);
                        }
                        return (0.0, Accuracy::Below);
                    }
                    if p == 0 {
                        let tiny = f64::from_bits(1);
                        if self.neg {
                            return (-tiny, Accuracy::Below);
                        }
                        return (tiny, Accuracy::Above);
                    }
                }
                let mut r = Float::with_prec_raw(p as u32);
                r.set(self);
                e = r.exp - 1;
                if r.form == Form::Inf || e > EMAX {
                    if self.neg {
                        return (f64::NEG_INFINITY, Accuracy::Below);
                    }
                    return (f64::INFINITY, Accuracy::Above);
                }
                let sign: u64 = if self.neg { 1 << (FBITS - 1) } else { 0 };
                let (bexp, mant) = if e < EMIN {
                    let p = MBITS + 1 - EMIN + e;
                    (0, msb64(&r.mant) >> (FBITS - p) as u32)
                } else {
                    (
                        ((e + BIAS) as u64) << MBITS,
                        (msb64(&r.mant) >> EBITS) & ((1 << MBITS) - 1),
                    )
                };
                (f64::from_bits(sign | bexp | mant), r.acc)
            }
            Form::Zero => (if self.neg { -0.0 } else { 0.0 }, Accuracy::Exact),
            Form::Inf => (
                if self.neg {
                    f64::NEG_INFINITY
                } else {
                    f64::INFINITY
                },
                Accuracy::Exact,
            ),
        }
    }

    /// A Float with the given precision and default mode, without rounding.
    fn with_prec_raw(prec: u32) -> Float {
        Float {
            prec,
            ..Float::default()
        }
    }

    /// Go's `Int`: x truncated toward zero, or `None` for ±Inf, with the
    /// accuracy of the truncation.
    pub fn int(&self) -> (Option<Int>, Accuracy) {
        match self.form {
            Form::Invalid => panic!("unreachable"),
            Form::Finite => {
                let mut acc = Accuracy::from_above(self.neg);
                if self.exp <= 0 {
                    return (Some(Int::zero()), acc);
                }
                let all_bits = self.mant.len() * 64;
                let exp = self.exp as usize;
                if self.min_prec() <= exp as u64 {
                    acc = Accuracy::Exact;
                }
                let abs = match exp.cmp(&all_bits) {
                    Ordering::Greater => nat::shl(&self.mant, exp - all_bits),
                    Ordering::Less => nat::shr(&self.mant, all_bits - exp),
                    Ordering::Equal => self.mant.clone(),
                };
                (Some(Int::from_parts(self.neg, abs)), acc)
            }
            Form::Zero => (Some(Int::zero()), Accuracy::Exact),
            Form::Inf => (None, Accuracy::from_above(self.neg)),
        }
    }

    /// Go's `Rat`: the exact value of x, or `None` for ±Inf.
    pub fn rat(&self) -> (Option<Rat>, Accuracy) {
        match self.form {
            Form::Invalid => panic!("unreachable"),
            Form::Finite => {
                let all_bits = self.mant.len() as i64 * 64;
                let exp = i64::from(self.exp);
                let (a, b) = match exp.cmp(&all_bits) {
                    Ordering::Greater => (nat::shl(&self.mant, (exp - all_bits) as usize), vec![1]),
                    Ordering::Equal => (self.mant.clone(), vec![1]),
                    Ordering::Less => {
                        (self.mant.clone(), nat::shl(&[1], (all_bits - exp) as usize))
                    }
                };
                let r = Rat::from_frac(&Int::from_parts(self.neg, a), &Int::from_parts(false, b));
                (Some(r), Accuracy::Exact)
            }
            Form::Zero => (Some(Rat::default()), Accuracy::Exact),
            Form::Inf => (None, Accuracy::from_above(self.neg)),
        }
    }

    /// Go's `Abs`: |x| rounded to the receiver.
    pub fn abs(&mut self, x: &Float) -> &mut Float {
        self.set(x);
        self.neg = false;
        self
    }

    /// Go's `Neg`: -x rounded to the receiver.
    pub fn neg_into(&mut self, x: &Float) -> &mut Float {
        self.set(x);
        self.neg = !self.neg;
        self
    }

    fn uadd(&mut self, x: &Float, y: &Float) {
        let mut ex = i64::from(x.exp) - x.mant.len() as i64 * 64;
        let ey = i64::from(y.exp) - y.mant.len() as i64 * 64;
        self.mant = match ex.cmp(&ey) {
            Ordering::Less => nat::add(&x.mant, &nat::shl(&y.mant, (ey - ex) as usize)),
            Ordering::Equal => nat::add(&x.mant, &y.mant),
            Ordering::Greater => {
                let t = nat::shl(&x.mant, (ex - ey) as usize);
                ex = ey;
                nat::add(&t, &y.mant)
            }
        };
        let shift = nat::fnorm(&mut self.mant);
        self.set_exp_and_round(ex + self.mant.len() as i64 * 64 - shift, 0);
    }

    fn usub(&mut self, x: &Float, y: &Float) {
        let mut ex = i64::from(x.exp) - x.mant.len() as i64 * 64;
        let ey = i64::from(y.exp) - y.mant.len() as i64 * 64;
        self.mant = match ex.cmp(&ey) {
            Ordering::Less => nat::sub(&x.mant, &nat::shl(&y.mant, (ey - ex) as usize)),
            Ordering::Equal => nat::sub(&x.mant, &y.mant),
            Ordering::Greater => {
                let t = nat::shl(&x.mant, (ex - ey) as usize);
                ex = ey;
                nat::sub(&t, &y.mant)
            }
        };
        if self.mant.is_empty() {
            self.acc = Accuracy::Exact;
            self.form = Form::Zero;
            self.neg = false;
            return;
        }
        let shift = nat::fnorm(&mut self.mant);
        self.set_exp_and_round(ex + self.mant.len() as i64 * 64 - shift, 0);
    }

    fn umul(&mut self, x: &Float, y: &Float) {
        let e = i64::from(x.exp) + i64::from(y.exp);
        self.mant = nat::mul(&x.mant, &y.mant);
        let shift = nat::fnorm(&mut self.mant);
        self.set_exp_and_round(e - shift, 0);
    }

    fn uquo(&mut self, x: &Float, y: &Float) {
        let n = (self.prec / 64) as usize + 1;
        let mut xadj: Nat = x.mant.clone();
        let d = n as i64 - x.mant.len() as i64 + y.mant.len() as i64;
        if d > 0 {
            let mut padded = vec![0u64; d as usize];
            padded.extend_from_slice(&x.mant);
            xadj = padded;
        }
        let d = xadj.len() as i64 - y.mant.len() as i64;
        let (q, r) = nat::div(&xadj, &y.mant);
        self.mant = q;
        let e = i64::from(x.exp) - i64::from(y.exp) - (d - self.mant.len() as i64) * 64;
        let sbit = u32::from(!r.is_empty());
        let shift = nat::fnorm(&mut self.mant);
        self.set_exp_and_round(e - shift, sbit);
    }

    fn ucmp(&self, y: &Float) -> Ordering {
        match self.exp.cmp(&y.exp) {
            Ordering::Equal => {}
            other => return other,
        }
        let (mut i, mut j) = (self.mant.len(), y.mant.len());
        while i > 0 || j > 0 {
            let mut xm = 0;
            let mut ym = 0;
            if i > 0 {
                i -= 1;
                xm = self.mant[i];
            }
            if j > 0 {
                j -= 1;
                ym = y.mant[j];
            }
            match xm.cmp(&ym) {
                Ordering::Equal => {}
                other => return other,
            }
        }
        Ordering::Equal
    }

    fn nan(&mut self, msg: &'static str) -> Result<&mut Float, ErrNaN> {
        self.acc = Accuracy::Exact;
        self.form = Form::Zero;
        self.neg = false;
        Err(ErrNaN::new(msg))
    }

    /// Go's `Add` (`z.add_into(&x, &y)`): x + y rounded to the receiver
    /// (precision max(x, y) if 0). The `+` operator and [`Float::checked_add`]
    /// use a fresh receiver. +Inf + -Inf is [`ErrNaN`].
    pub fn add_into(&mut self, x: &Float, y: &Float) -> Result<&mut Float, ErrNaN> {
        if self.prec == 0 {
            self.prec = x.prec.max(y.prec);
        }
        if x.form == Form::Finite && y.form == Form::Finite {
            self.neg = x.neg;
            if x.neg == y.neg {
                self.uadd(x, y);
            } else if x.ucmp(y) == Ordering::Greater {
                self.usub(x, y);
            } else {
                self.neg = !self.neg;
                self.usub(y, x);
            }
            if self.form == Form::Zero
                && self.mode == RoundingMode::ToNegativeInf
                && self.acc == Accuracy::Exact
            {
                self.neg = true;
            }
            return Ok(self);
        }
        if x.form == Form::Inf && y.form == Form::Inf && x.neg != y.neg {
            return self.nan("addition of infinities with opposite signs");
        }
        if x.form == Form::Zero && y.form == Form::Zero {
            self.acc = Accuracy::Exact;
            self.form = Form::Zero;
            self.neg = x.neg && y.neg;
            return Ok(self);
        }
        if x.form == Form::Inf || y.form == Form::Zero {
            return Ok(self.set(x));
        }
        Ok(self.set(y))
    }

    /// Go's `Sub`: x - y rounded to the receiver. +Inf - +Inf is
    /// [`ErrNaN`].
    pub fn sub_into(&mut self, x: &Float, y: &Float) -> Result<&mut Float, ErrNaN> {
        if self.prec == 0 {
            self.prec = x.prec.max(y.prec);
        }
        if x.form == Form::Finite && y.form == Form::Finite {
            self.neg = x.neg;
            if x.neg != y.neg {
                self.uadd(x, y);
            } else if x.ucmp(y) == Ordering::Greater {
                self.usub(x, y);
            } else {
                self.neg = !self.neg;
                self.usub(y, x);
            }
            if self.form == Form::Zero
                && self.mode == RoundingMode::ToNegativeInf
                && self.acc == Accuracy::Exact
            {
                self.neg = true;
            }
            return Ok(self);
        }
        if x.form == Form::Inf && y.form == Form::Inf && x.neg == y.neg {
            return self.nan("subtraction of infinities with equal signs");
        }
        if x.form == Form::Zero && y.form == Form::Zero {
            self.acc = Accuracy::Exact;
            self.form = Form::Zero;
            self.neg = x.neg && !y.neg;
            return Ok(self);
        }
        if x.form == Form::Inf || y.form == Form::Zero {
            return Ok(self.set(x));
        }
        Ok(self.neg_into(y))
    }

    /// Go's `Mul`: x × y rounded to the receiver. 0 × Inf is [`ErrNaN`].
    pub fn mul_into(&mut self, x: &Float, y: &Float) -> Result<&mut Float, ErrNaN> {
        if self.prec == 0 {
            self.prec = x.prec.max(y.prec);
        }
        self.neg = x.neg != y.neg;
        if x.form == Form::Finite && y.form == Form::Finite {
            self.umul(x, y);
            return Ok(self);
        }
        self.acc = Accuracy::Exact;
        if x.form == Form::Zero && y.form == Form::Inf
            || x.form == Form::Inf && y.form == Form::Zero
        {
            return self.nan("multiplication of zero with infinity");
        }
        self.form = if x.form == Form::Inf || y.form == Form::Inf {
            Form::Inf
        } else {
            Form::Zero
        };
        Ok(self)
    }

    /// Go's `Quo`: x / y rounded to the receiver. 0/0 and Inf/Inf are
    /// [`ErrNaN`].
    pub fn quo_into(&mut self, x: &Float, y: &Float) -> Result<&mut Float, ErrNaN> {
        if self.prec == 0 {
            self.prec = x.prec.max(y.prec);
        }
        self.neg = x.neg != y.neg;
        if x.form == Form::Finite && y.form == Form::Finite {
            self.uquo(x, y);
            return Ok(self);
        }
        self.acc = Accuracy::Exact;
        if x.form == Form::Zero && y.form == Form::Zero
            || x.form == Form::Inf && y.form == Form::Inf
        {
            return self.nan("division of zero by zero or infinity by infinity");
        }
        self.form = if x.form == Form::Zero || y.form == Form::Inf {
            Form::Zero
        } else {
            Form::Inf
        };
        Ok(self)
    }

    /// `self + rhs` at the larger operand precision, or [`ErrNaN`] for
    /// +Inf + -Inf. Use [`Float::add_into`] to round to a chosen precision.
    pub fn checked_add(&self, rhs: &Float) -> Result<Float, ErrNaN> {
        let mut z = Float::new();
        z.add_into(self, rhs)?;
        Ok(z)
    }

    /// `self - rhs` at the larger operand precision, or [`ErrNaN`] for
    /// +Inf - +Inf.
    pub fn checked_sub(&self, rhs: &Float) -> Result<Float, ErrNaN> {
        let mut z = Float::new();
        z.sub_into(self, rhs)?;
        Ok(z)
    }

    /// `self * rhs` at the larger operand precision, or [`ErrNaN`] for
    /// 0 * Inf.
    pub fn checked_mul(&self, rhs: &Float) -> Result<Float, ErrNaN> {
        let mut z = Float::new();
        z.mul_into(self, rhs)?;
        Ok(z)
    }

    /// `self / rhs` at the larger operand precision, or [`ErrNaN`] for 0/0
    /// and Inf/Inf.
    pub fn checked_div(&self, rhs: &Float) -> Result<Float, ErrNaN> {
        let mut z = Float::new();
        z.quo_into(self, rhs)?;
        Ok(z)
    }

    /// Quo for operands known not to produce NaN.
    fn quo_finite(&mut self, x: &Float, y: &Float) {
        let _ = self.quo_into(x, y);
    }

    fn mul_finite(&mut self, x: &Float, y: &Float) {
        let _ = self.mul_into(x, y);
    }

    fn ord(&self) -> i32 {
        let m = match self.form {
            Form::Finite => 1,
            Form::Zero => return 0,
            Form::Inf => 2,
            Form::Invalid => 0,
        };
        if self.neg {
            -m
        } else {
            m
        }
    }

    /// Go's `Sqrt`: √x rounded to the receiver (precision of x if 0). As
    /// in Go, the result is computed by Newton's method with 32 extra bits
    /// and the receiver's accuracy is not meaningful. x < 0 is [`ErrNaN`].
    pub fn sqrt(&mut self, x: &Float) -> Result<&mut Float, ErrNaN> {
        if self.prec == 0 {
            self.prec = x.prec;
        }
        if x.sign() == -1 {
            return Err(ErrNaN::new("square root of negative operand"));
        }
        if x.form != Form::Finite {
            self.acc = Accuracy::Exact;
            self.form = x.form;
            self.neg = x.neg;
            return Ok(self);
        }
        let prec = self.prec;
        let b = x.mant_exp(Some(self));
        self.prec = prec;
        match b % 2 {
            1 => self.exp += 1,
            -1 => self.exp -= 1,
            _ => {}
        }
        let xx = self.clone();
        self.sqrt_inverse(&xx);
        self.scale_exp(i64::from(b / 2));
        Ok(self)
    }

    /// z = √x via 1/√x Newton iterations, as Go's sqrtInverse.
    fn sqrt_inverse(&mut self, x: &Float) {
        let mut u = Float::new();
        let mut v = Float::new();
        let mut three = Float::new();
        three.set_float64(3.0).ok();
        let ng = |t: &mut Float, u: &mut Float, v: &mut Float| {
            u.prec = t.prec;
            v.prec = t.prec;
            u.mul_finite(t, t);
            let uu = u.clone();
            u.mul_finite(x, &uu);
            let _ = v.sub_into(&three, u);
            u.mul_finite(t, v);
            u.exp -= 1;
            t.set(u);
        };
        let xf = x.float64().0;
        let mut sqi = Float::new();
        sqi.set_float64(1.0 / xf.sqrt()).ok();
        let prec = u64::from(self.prec) + 32;
        while u64::from(sqi.prec) < prec {
            sqi.prec = sqi.prec.saturating_mul(2);
            ng(&mut sqi, &mut u, &mut v);
        }
        self.mul_finite(x, &sqi);
    }
}

/// Numeric equality as Go's `Cmp` (so -0 == +0; precision, mode and
/// accuracy are ignored).
impl PartialEq for Float {
    fn eq(&self, other: &Float) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Float {}

/// Go's `Cmp`: -Inf < finite values < +Inf, and -0 == +0. A Float is never
/// NaN, so the order is total.
impl Ord for Float {
    fn cmp(&self, y: &Float) -> Ordering {
        let (mx, my) = (self.ord(), y.ord());
        match mx.cmp(&my) {
            Ordering::Equal => {}
            other => return other,
        }
        match mx {
            -1 => y.ucmp(self),
            1 => self.ucmp(y),
            _ => Ordering::Equal,
        }
    }
}

impl PartialOrd for Float {
    fn partial_cmp(&self, other: &Float) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

macro_rules! float_op {
    ($Trait:ident, $method:ident, $checked:ident) => {
        impl std::ops::$Trait<&Float> for &Float {
            type Output = Float;
            fn $method(self, rhs: &Float) -> Float {
                self.$checked(rhs).unwrap_or_else(|e| panic!("{e}"))
            }
        }
        impl std::ops::$Trait<Float> for &Float {
            type Output = Float;
            fn $method(self, rhs: Float) -> Float {
                std::ops::$Trait::$method(self, &rhs)
            }
        }
        impl std::ops::$Trait<&Float> for Float {
            type Output = Float;
            fn $method(self, rhs: &Float) -> Float {
                std::ops::$Trait::$method(&self, rhs)
            }
        }
        impl std::ops::$Trait<Float> for Float {
            type Output = Float;
            fn $method(self, rhs: Float) -> Float {
                std::ops::$Trait::$method(&self, &rhs)
            }
        }
    };
}
// Like Go, the operators panic where IEEE 754 gives NaN; use the `checked_*`
// methods to get an `ErrNaN` instead.
float_op!(Add, add, checked_add);
float_op!(Sub, sub, checked_sub);
float_op!(Mul, mul, checked_mul);
float_op!(Div, div, checked_div);

impl std::ops::Neg for &Float {
    type Output = Float;
    fn neg(self) -> Float {
        let mut z = Float::new();
        z.neg_into(self);
        z
    }
}

impl std::ops::Neg for Float {
    type Output = Float;
    fn neg(self) -> Float {
        -&self
    }
}
