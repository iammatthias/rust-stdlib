//! Go's `math/cmplx`: elementary functions of a complex variable, with Go's
//! branch cuts and special values (ported from Go's package, which follows
//! the algorithms of Cephes and C99 Annex G; see NOTICE).
//!
//! Go's `complex128` is [`Complex`], the type `strconv` already uses. The
//! arithmetic operators follow Go: multiplication is the schoolbook formula
//! and division is the runtime's `complex128div` (Smith's algorithm with C99
//! corrections for infinities and zeros).
#![allow(
    clippy::many_single_char_names,
    clippy::manual_range_contains,
    clippy::neg_cmp_op_on_partial_ord
)]

use super::{inf as f_inf, nan as f_nan};
use crate::strconv::Complex;
use std::f64::consts::PI;
use std::ops::{Add, Div, Mul, Neg, Sub};

impl Complex {
    /// Go's `complex(re, im)`.
    pub const fn new(re: f64, im: f64) -> Self {
        Complex { re, im }
    }
}

impl Add for Complex {
    type Output = Complex;
    fn add(self, o: Complex) -> Complex {
        Complex::new(self.re + o.re, self.im + o.im)
    }
}

impl Sub for Complex {
    type Output = Complex;
    fn sub(self, o: Complex) -> Complex {
        Complex::new(self.re - o.re, self.im - o.im)
    }
}

impl Neg for Complex {
    type Output = Complex;
    fn neg(self) -> Complex {
        Complex::new(-self.re, -self.im)
    }
}

impl Mul for Complex {
    type Output = Complex;
    fn mul(self, o: Complex) -> Complex {
        Complex::new(
            self.re * o.re - self.im * o.im,
            self.re * o.im + self.im * o.re,
        )
    }
}

impl Div for Complex {
    type Output = Complex;
    /// Go's `complex128div`.
    fn div(self, m: Complex) -> Complex {
        let n = self;
        let (e, f);
        if m.re.abs() >= m.im.abs() {
            let ratio = m.im / m.re;
            let denom = m.re + ratio * m.im;
            e = (n.re + n.im * ratio) / denom;
            f = (n.im - n.re * ratio) / denom;
        } else {
            let ratio = m.re / m.im;
            let denom = m.im + ratio * m.re;
            e = (n.re * ratio + n.im) / denom;
            f = (n.im * ratio - n.re) / denom;
        }
        let (mut e, mut f) = (e, f);
        if e.is_nan() && f.is_nan() {
            // Correct final result to infinities and zeros if applicable.
            // Matches C99: ISO/IEC 9899:1999 - G.5.1 Multiplicative operators.
            let (mut a, mut b) = (n.re, n.im);
            let (mut c, mut d) = (m.re, m.im);
            let inf = f64::INFINITY;
            let inf2one = |x: f64| (if x.is_infinite() { 1.0f64 } else { 0.0 }).copysign(x);
            if c == 0.0 && d == 0.0 && (!a.is_nan() || !b.is_nan()) {
                e = inf.copysign(c) * a;
                f = inf.copysign(c) * b;
            } else if (a.is_infinite() || b.is_infinite()) && c.is_finite() && d.is_finite() {
                a = inf2one(a);
                b = inf2one(b);
                e = inf * (a * c + b * d);
                f = inf * (b * c - a * d);
            } else if (c.is_infinite() || d.is_infinite()) && a.is_finite() && b.is_finite() {
                c = inf2one(c);
                d = inf2one(d);
                e = 0.0 * (a * c + b * d);
                f = 0.0 * (b * c - a * d);
            }
        }
        Complex::new(e, f)
    }
}

const ZERO: Complex = Complex::new(0.0, 0.0);

fn c(re: f64, im: f64) -> Complex {
    Complex::new(re, im)
}

fn is_inf_f(x: f64) -> bool {
    x.is_infinite()
}

/// Go's `cmplx.Abs`: the absolute value (also called the modulus) of `x`.
pub fn abs(x: Complex) -> f64 {
    super::hypot(x.re, x.im)
}

/// Go's `cmplx.Phase`: the phase (also called the argument) of `x`, in the
/// range [-Pi, Pi].
pub fn phase(x: Complex) -> f64 {
    super::atan2(x.im, x.re)
}

/// Go's `cmplx.Polar`: the absolute value `r` and phase `θ` of `x`.
pub fn polar(x: Complex) -> (f64, f64) {
    (abs(x), phase(x))
}

/// Go's `cmplx.Rect`: the complex number `x` with polar coordinates `r`, `θ`.
pub fn rect(r: f64, theta: f64) -> Complex {
    let (s, co) = super::sincos(theta);
    c(r * co, r * s)
}

/// Go's `cmplx.Conj`: the complex conjugate of `x`.
pub fn conj(x: Complex) -> Complex {
    c(x.re, -x.im)
}

/// Go's `cmplx.Inf`: a complex infinity, `complex(+Inf, +Inf)`.
pub fn inf() -> Complex {
    let i = f_inf(1);
    c(i, i)
}

/// Go's `cmplx.NaN`: a complex "not-a-number" value.
pub fn nan() -> Complex {
    let n = f_nan();
    c(n, n)
}

/// Go's `cmplx.IsInf`: reports whether either component of `x` is an infinity.
pub fn is_inf(x: Complex) -> bool {
    is_inf_f(x.re) || is_inf_f(x.im)
}

/// Go's `cmplx.IsNaN`: reports whether either component of `x` is NaN and
/// neither is an infinity.
pub fn is_nan(x: Complex) -> bool {
    if is_inf_f(x.re) || is_inf_f(x.im) {
        false
    } else {
        x.re.is_nan() || x.im.is_nan()
    }
}

/// Go's `cmplx.Exp`: `e**x`, the base-e exponential of `x`.
pub fn exp(x: Complex) -> Complex {
    let (re, im) = (x.re, x.im);
    if re.is_infinite() {
        if re > 0.0 && im == 0.0 {
            return x;
        }
        if im.is_infinite() || im.is_nan() {
            return if re < 0.0 {
                c(0.0, 0.0f64.copysign(im))
            } else {
                c(f_inf(1), f_nan())
            };
        }
    } else if re.is_nan() && im == 0.0 {
        return c(f_nan(), im);
    }
    let r = super::exp(x.re);
    let (s, co) = super::sincos(x.im);
    c(r * co, r * s)
}

/// Go's `cmplx.Log`: the natural logarithm of `x`.
pub fn log(x: Complex) -> Complex {
    c(super::log(abs(x)), phase(x))
}

/// Go's `cmplx.Log10`: the decimal logarithm of `x`.
pub fn log10(x: Complex) -> Complex {
    let z = log(x);
    c(
        std::f64::consts::LOG10_E * z.re,
        std::f64::consts::LOG10_E * z.im,
    )
}

/// Go's `cmplx.Pow`: `x**y`, the base-`x` exponential of `y`. For `x == 0`:
/// `pow(0, ±0) = 1`, `pow(0, c) = (+Inf, 0)` for real `c < 0` and `Inf` for
/// complex ones, `pow(0, c) = 0` for `real(c) > 0`, `NaN` if `y` is NaN.
pub fn pow(x: Complex, y: Complex) -> Complex {
    if x == ZERO {
        // Guaranteed also true for x == -0.
        if is_nan(y) {
            return nan();
        }
        let (r, i) = (y.re, y.im);
        return if r == 0.0 {
            c(1.0, 0.0)
        } else if r < 0.0 {
            if i == 0.0 {
                c(f_inf(1), 0.0)
            } else {
                inf()
            }
        } else {
            ZERO
        };
    }
    let modulus = abs(x);
    if modulus == 0.0 {
        return c(0.0, 0.0);
    }
    let mut r = super::pow(modulus, y.re);
    let arg = phase(x);
    let mut theta = y.re * arg;
    if y.im != 0.0 {
        r *= super::exp(-y.im * arg);
        theta += y.im * super::log(modulus);
    }
    let (s, co) = super::sincos(theta);
    c(r * co, r * s)
}

/// Go's `cmplx.Sqrt`: the square root of `x`, with the branch cut along the
/// negative real axis; the real part of the result is non-negative.
pub fn sqrt(x: Complex) -> Complex {
    if x.im == 0.0 {
        if x.re == 0.0 {
            return c(0.0, x.im);
        }
        if x.re < 0.0 {
            return c(0.0, (-x.re).sqrt().copysign(x.im));
        }
        return c(x.re.sqrt(), x.im);
    } else if x.im.is_infinite() {
        return c(f_inf(1), x.im);
    }
    if x.re == 0.0 {
        if x.im < 0.0 {
            let r = (-0.5 * x.im).sqrt();
            return c(r, -r);
        }
        let r = (0.5 * x.im).sqrt();
        return c(r, r);
    }
    let mut a = x.re;
    let mut b = x.im;
    // Rescale to avoid internal overflow or underflow.
    let scale;
    if a.abs() > 4.0 || b.abs() > 4.0 {
        a *= 0.25;
        b *= 0.25;
        scale = 2.0;
    } else {
        a *= 1.8014398509481984e16; // 2**54
        b *= 1.8014398509481984e16;
        scale = 7.450580596923828125e-9; // 2**-27
    }
    let mut r = super::hypot(a, b);
    let mut t;
    if a > 0.0 {
        t = (0.5 * r + 0.5 * a).sqrt();
        r = scale * ((0.5 * b) / t).abs();
        t *= scale;
    } else {
        r = (0.5 * r - 0.5 * a).sqrt();
        t = scale * ((0.5 * b) / r).abs();
        r *= scale;
    }
    if b < 0.0 {
        c(t, -r)
    } else {
        c(t, r)
    }
}

/// Go's `cmplx.Asin`: the inverse sine of `x`.
pub fn asin(x: Complex) -> Complex {
    let (re, im) = (x.re, x.im);
    if im == 0.0 && re.abs() <= 1.0 {
        return c(super::asin(re), im);
    } else if re == 0.0 && im.abs() <= 1.0 {
        return c(re, super::asinh(im));
    } else if im.is_nan() {
        return if re == 0.0 {
            c(re, f_nan())
        } else if re.is_infinite() {
            c(f_nan(), re)
        } else {
            nan()
        };
    } else if im.is_infinite() {
        return if re.is_nan() {
            x
        } else if re.is_infinite() {
            c((PI / 4.0).copysign(re), im)
        } else {
            c(0.0f64.copysign(re), im)
        };
    } else if re.is_infinite() {
        return c((PI / 2.0).copysign(re), re.copysign(im));
    }
    let ct = c(-x.im, x.re); // i * x
    let xx = x * x;
    let x1 = c(1.0 - xx.re, -xx.im); // 1 - x*x
    let x2 = sqrt(x1); // x2 = sqrt(1 - x*x)
    let w = log(ct + x2);
    c(w.im, -w.re) // -i * w
}

/// Go's `cmplx.Asinh`: the inverse hyperbolic sine of `x`.
pub fn asinh(x: Complex) -> Complex {
    let (re, im) = (x.re, x.im);
    if im == 0.0 && re.abs() <= 1.0 {
        return c(super::asinh(re), im);
    } else if re == 0.0 && im.abs() <= 1.0 {
        return c(re, super::asin(im));
    } else if re.is_infinite() {
        return if im.is_infinite() {
            c(re, (PI / 4.0).copysign(im))
        } else if im.is_nan() {
            x
        } else {
            c(re, 0.0f64.copysign(im))
        };
    } else if re.is_nan() {
        return if im == 0.0 {
            x
        } else if im.is_infinite() {
            c(im, re)
        } else {
            nan()
        };
    } else if im.is_infinite() {
        return c(im.copysign(re), (PI / 2.0).copysign(im));
    }
    let xx = x * x;
    let x1 = c(1.0 + xx.re, xx.im); // 1 + x*x
    log(x + sqrt(x1)) // log(x + sqrt(1 + x*x))
}

/// Go's `cmplx.Acos`: the inverse cosine of `x`.
pub fn acos(x: Complex) -> Complex {
    let w = asin(x);
    c(PI / 2.0 - w.re, -w.im)
}

/// Go's `cmplx.Acosh`: the inverse hyperbolic cosine of `x`.
pub fn acosh(x: Complex) -> Complex {
    if x == ZERO {
        return c(0.0, (PI / 2.0).copysign(x.im));
    }
    let w = acos(x);
    if w.im <= 0.0 {
        c(-w.im, w.re) // i * w
    } else {
        c(w.im, -w.re) // -i * w
    }
}

/// Go's `cmplx.Atan`: the inverse tangent of `x`.
pub fn atan(x: Complex) -> Complex {
    let (re, im) = (x.re, x.im);
    if im == 0.0 {
        return c(super::atan(re), im);
    } else if re == 0.0 && im.abs() <= 1.0 {
        return c(re, super::atanh(im));
    } else if im.is_infinite() || re.is_infinite() {
        if re.is_nan() {
            return c(f_nan(), 0.0f64.copysign(im));
        }
        return c((PI / 2.0).copysign(re), 0.0f64.copysign(im));
    } else if re.is_nan() || im.is_nan() {
        return nan();
    }
    let x2 = x.re * x.re;
    let a = 1.0 - x2 - x.im * x.im;
    if a == 0.0 {
        return nan();
    }
    let mut t = 0.5 * super::atan2(2.0 * x.re, a);
    let w = reduce_pi(t);
    t = x.im - 1.0;
    let b = x2 + t * t;
    if b == 0.0 {
        return nan();
    }
    t = x.im + 1.0;
    let cc = (x2 + t * t) / b;
    c(w, 0.25 * super::log(cc))
}

/// Go's `cmplx.Atanh`: the inverse hyperbolic tangent of `x`.
pub fn atanh(x: Complex) -> Complex {
    let z = c(-x.im, x.re); // z = i * x
    let z = atan(z);
    c(z.im, -z.re) // z = -i * z
}

fn sinhcosh(x: f64) -> (f64, f64) {
    if x.abs() <= 0.5 {
        return (super::sinh(x), super::cosh(x));
    }
    let mut e = super::exp(x);
    let ei = 0.5 / e;
    e *= 0.5;
    (e - ei, e + ei)
}

/// Go's `cmplx.Sin`: the sine of `x`.
pub fn sin(x: Complex) -> Complex {
    let (re, im) = (x.re, x.im);
    if im == 0.0 && (re.is_infinite() || re.is_nan()) {
        return c(f_nan(), im);
    } else if im.is_infinite() {
        if re == 0.0 {
            return x;
        } else if re.is_infinite() || re.is_nan() {
            return c(f_nan(), im);
        }
    } else if re == 0.0 && im.is_nan() {
        return x;
    }
    let (s, co) = super::sincos(x.re);
    let (sh, ch) = sinhcosh(x.im);
    c(s * ch, co * sh)
}

/// Go's `cmplx.Sinh`: the hyperbolic sine of `x`.
pub fn sinh(x: Complex) -> Complex {
    let (re, im) = (x.re, x.im);
    if re == 0.0 && (im.is_infinite() || im.is_nan()) {
        return c(re, f_nan());
    } else if re.is_infinite() {
        if im == 0.0 {
            return c(re, im);
        } else if im.is_infinite() || im.is_nan() {
            return c(re, f_nan());
        }
    } else if im == 0.0 && re.is_nan() {
        return c(f_nan(), im);
    }
    let (s, co) = super::sincos(x.im);
    let (sh, ch) = sinhcosh(x.re);
    c(co * sh, s * ch)
}

/// Go's `cmplx.Cos`: the cosine of `x`.
pub fn cos(x: Complex) -> Complex {
    let (re, im) = (x.re, x.im);
    if im == 0.0 && (re.is_infinite() || re.is_nan()) {
        return c(f_nan(), -im * 0.0f64.copysign(re));
    } else if im.is_infinite() {
        if re == 0.0 {
            return c(f_inf(1), -re * 0.0f64.copysign(im));
        } else if re.is_infinite() || re.is_nan() {
            return c(f_inf(1), f_nan());
        }
    } else if re == 0.0 && im.is_nan() {
        return c(f_nan(), 0.0);
    }
    let (s, co) = super::sincos(x.re);
    let (sh, ch) = sinhcosh(x.im);
    c(co * ch, -s * sh)
}

/// Go's `cmplx.Cosh`: the hyperbolic cosine of `x`.
pub fn cosh(x: Complex) -> Complex {
    let (re, im) = (x.re, x.im);
    if re == 0.0 && (im.is_infinite() || im.is_nan()) {
        return c(f_nan(), re * 0.0f64.copysign(im));
    } else if re.is_infinite() {
        if im == 0.0 {
            return c(f_inf(1), im * 0.0f64.copysign(re));
        } else if im.is_infinite() || im.is_nan() {
            return c(f_inf(1), f_nan());
        }
    } else if im == 0.0 && re.is_nan() {
        return c(f_nan(), im);
    }
    let (s, co) = super::sincos(x.im);
    let (sh, ch) = sinhcosh(x.re);
    c(co * ch, s * sh)
}

/// Go's `cmplx.Tan`: the tangent of `x`.
pub fn tan(x: Complex) -> Complex {
    let (re, im) = (x.re, x.im);
    if im.is_infinite() {
        if re.is_infinite() || re.is_nan() {
            return c(0.0f64.copysign(re), 1.0f64.copysign(im));
        }
        return c(0.0f64.copysign(super::sin(2.0 * re)), 1.0f64.copysign(im));
    } else if re == 0.0 && im.is_nan() {
        return x;
    }
    let mut d = super::cos(2.0 * x.re) + super::cosh(2.0 * x.im);
    if d.abs() < 0.25 {
        d = tan_series(x);
    }
    if d == 0.0 {
        return inf();
    }
    c(super::sin(2.0 * x.re) / d, super::sinh(2.0 * x.im) / d)
}

/// Go's `cmplx.Tanh`: the hyperbolic tangent of `x`.
pub fn tanh(x: Complex) -> Complex {
    let (re, im) = (x.re, x.im);
    if re.is_infinite() {
        if im.is_infinite() || im.is_nan() {
            return c(1.0f64.copysign(re), 0.0f64.copysign(im));
        }
        return c(1.0f64.copysign(re), 0.0f64.copysign(super::sin(2.0 * im)));
    } else if im == 0.0 && re.is_nan() {
        return x;
    }
    let d = super::cosh(2.0 * x.re) + super::cos(2.0 * x.im);
    if d == 0.0 {
        return inf();
    }
    c(super::sinh(2.0 * x.re) / d, super::sin(2.0 * x.im) / d)
}

/// Go's `cmplx.Cot`: the cotangent of `x`.
pub fn cot(x: Complex) -> Complex {
    let mut d = super::cosh(2.0 * x.im) - super::cos(2.0 * x.re);
    if d.abs() < 0.25 {
        d = tan_series(x);
    }
    if d == 0.0 {
        return inf();
    }
    c(super::sin(2.0 * x.re) / d, -super::sinh(2.0 * x.im) / d)
}

/// Shifts `x` left (`s` < 64) with Go's semantics for oversized shifts.
fn shl(x: u64, s: u32) -> u64 {
    if s >= 64 {
        0
    } else {
        x << s
    }
}

fn shr(x: u64, s: u32) -> u64 {
    if s >= 64 {
        0
    } else {
        x >> s
    }
}

/// Reduces the argument to the range [-Pi/2, Pi/2], Cephes-style, with a
/// Payne-Hanek reduction for large arguments.
fn reduce_pi(mut x: f64) -> f64 {
    const REDUCE_THRESHOLD: f64 = (1u64 << 30) as f64;
    if x.abs() < REDUCE_THRESHOLD {
        // Use Cody-Waite reduction in three parts.
        const PI1: f64 = 3.141592502593994; // 0x400921fb40000000
        const PI2: f64 = 1.5099578831723193e-07; // 0x3e84442d00000000
        const PI3: f64 = 1.0780605716316238e-14; // 0x3d08469898cc5170
        let mut t = x / PI;
        t += 0.5;
        t = (t as i64) as f64; // the multiple
        return ((x - t * PI1) - t * PI2) - t * PI3;
    }
    // Must apply Payne-Hanek range reduction.
    const MASK: u64 = 0x7FF;
    const SHIFT: u32 = 64 - 11 - 1;
    const BIAS: i64 = 1023;
    const FRAC_MASK: u64 = (1u64 << SHIFT) - 1;
    let mut ix = x.to_bits();
    let exp = ((ix >> SHIFT) & MASK) as i64 - BIAS - SHIFT as i64;
    ix &= FRAC_MASK;
    ix |= 1 << SHIFT;
    // 2**-2 to 2**-1022 of the bits of 4/pi, 64-bit digits.
    const M_PI: [u64; 20] = [
        0x0000000000000000,
        0x517cc1b727220a94,
        0xfe13abe8fa9a6ee0,
        0x6db14acc9e21c820,
        0xff28b1d5ef5de2b0,
        0xdb92371d2126e970,
        0x0324977504e8c90e,
        0x7f0ef58e5894d39f,
        0x74411afa975da242,
        0x74ce38135a2fbf20,
        0x9cc8eb1cc1a99cfa,
        0x4e422fc5defc941d,
        0x8ffc4bffef02cc07,
        0xf79788c5ad05368f,
        0xb69b3f6793e584db,
        0xa7a31fb34f2ff516,
        0xba93dd63f5f2f8bd,
        0x9e839cfbc5294975,
        0x35fdafd88fc6ae84,
        0x2b0198237e3db5d5,
    ];
    let digit = ((exp + 64) as u64 / 64) as usize;
    let bitshift = ((exp + 64) as u64 % 64) as u32;
    let back = 64 - bitshift;
    let z0 = shl(M_PI[digit], bitshift) | shr(M_PI[digit + 1], back);
    let z1 = shl(M_PI[digit + 1], bitshift) | shr(M_PI[digit + 2], back);
    let z2 = shl(M_PI[digit + 2], bitshift) | shr(M_PI[digit + 3], back);
    // Multiply mantissa by the digits and extract the upper two digits (hi, lo).
    let z2hi = ((u128::from(z2) * u128::from(ix)) >> 64) as u64;
    let z1p = u128::from(z1) * u128::from(ix);
    let (z1hi, z1lo) = ((z1p >> 64) as u64, z1p as u64);
    let z0lo = z0.wrapping_mul(ix);
    let (lo, carry) = z1lo.overflowing_add(z2hi);
    let mut hi = z0lo.wrapping_add(z1hi).wrapping_add(u64::from(carry));
    // Find the magnitude of the fraction.
    let lz = hi.leading_zeros();
    let e = (BIAS as u64).wrapping_sub(u64::from(lz) + 1);
    // Clear implicit mantissa bit and shift into place.
    hi = shl(hi, lz + 1) | shr(lo, 64u32.wrapping_sub(lz + 1));
    hi >>= 64 - SHIFT;
    // Include the exponent and convert to a float.
    hi |= e << SHIFT;
    x = f64::from_bits(hi);
    // map to [-1/2, 1/2] (the result is in [0, 1) here)
    if x > 0.5 {
        x -= 1.0;
    }
    PI * x
}

/// Taylor series expansion for cosh(2y) - cos(2x) near the origin, used by
/// `tan` and `cot` when the denominator is small.
fn tan_series(z: Complex) -> f64 {
    const MACHEP: f64 = 1.0 / (1u64 << 53) as f64;
    let mut x = (2.0 * z.re).abs();
    let mut y = (2.0 * z.im).abs();
    x = reduce_pi(x);
    x *= x;
    y *= y;
    let mut x2 = 1.0;
    let mut y2 = 1.0;
    let mut f = 1.0;
    let mut rn = 0.0;
    let mut d = 0.0;
    loop {
        rn += 1.0;
        f *= rn;
        rn += 1.0;
        f *= rn;
        x2 *= x;
        y2 *= y;
        let mut t = y2 + x2;
        t /= f;
        d += t;

        rn += 1.0;
        f *= rn;
        rn += 1.0;
        f *= rn;
        x2 *= x;
        y2 *= y;
        t = y2 - x2;
        t /= f;
        d += t;
        if !((t / d).abs() > MACHEP) {
            // Note that this test is written to handle the NaN case; it must
            // not be rewritten as `<=`.
            break;
        }
    }
    d
}
