//! Go's `math` package and subpackages.
//!
//! `math/bits` is std's integer methods (`docs/api/math_bits.json`); [`compare`],
//! [`minimum`] and [`maximum`] are Go's NaN-aware float ordering, which std
//! lacks (`f64::total_cmp` orders NaN and signed zeros differently).
//!
//! Rust's `f64` and `f32` methods and associated constants are the
//! implementation wherever their results match Go's (`f64::sqrt`,
//! `f64::floor`, `f64::round`, `i64::MAX`, ...); `docs/api/math.json` maps each
//! Go symbol to the item that implements it. Where std's libm differs from
//! Go's (Go computes most transcendental functions in portable Go code, with
//! its own argument reduction and rounding), this module ports Go's
//! algorithms: trigonometry, `Pow`, `Log`/`Log1p`/`Expm1`/`Exp`, `Hypot`,
//! `Cbrt`, hyperbolics, the error, gamma and Bessel functions, plus the
//! pieces std lacks (`Frexp`/`Ldexp`/`Modf`, IEEE `Remainder`, `Nextafter`,
//! `Logb`/`Ilogb`, `Max`/`Min`/`Dim` NaN and signed-zero rules, `Pow10`) and
//! the constants Go defines beyond `std::f64::consts`.
//!
//! Results are bit-identical to Go's portable code. Go's `Exp` is assembly on
//! amd64 and arm64, with last-bit differences from that code, so `Exp` and
//! the functions built on it (`Cosh`, `Sinh`, `Tanh`, `Erfc`, `Gamma`, `Pow`)
//! can differ from a given Go build by a few ULP; the `notes` and `differs`
//! entries of `docs/api/math.json` list them.

// The ported kernels keep Go's literals and structure (see NOTICE) so they can
// be compared with the originals line by line.
#![allow(
    clippy::excessive_precision,
    clippy::needless_late_init,
    clippy::approx_constant
)]

pub mod big;
pub mod cmplx;
pub mod rand;

mod bessel;
mod erf;
mod exp;
mod gamma;
mod trig;

pub use bessel::{j0, j1, jn, y0, y1, yn};
pub use erf::{erf, erfc, erfcinv, erfinv};
pub use exp::{acosh, asinh, cbrt, exp, exp2, expm1, log1p};
pub use gamma::{gamma, lgamma};
use std::f64::consts::PI;
pub use trig::{cos, sin, sincos, tan};

/// Go's `math.Phi`: the golden ratio.
pub const PHI: f64 = 1.61803398874989484820458683436563811772030917980576286213544862;
/// Go's `math.SqrtE`.
pub const SQRT_E: f64 = 1.64872127070012814684865078781416357165377610071014801157507931;
/// Go's `math.SqrtPi`.
pub const SQRT_PI: f64 = 1.77245385090551602729816748334114518279754945612238712821380779;
/// Go's `math.SqrtPhi`.
pub const SQRT_PHI: f64 = 1.27201964951406896425242246173749149171560804184009624861664038;
/// Go's `math.MaxFloat32`, as a `f64`.
pub const MAX_FLOAT32: f64 = 3.40282346638528859811704183484516925440e+38;
/// Go's `math.SmallestNonzeroFloat32`, as a `f64`.
pub const SMALLEST_NONZERO_FLOAT32: f64 = 1.401298464324817070923729583289916131280e-45;
/// Go's `math.SmallestNonzeroFloat64`.
pub const SMALLEST_NONZERO_FLOAT64: f64 = 4.9406564584124654417656879286822137236505980e-324;

const UVNAN: u64 = 0x7FF8000000000001;
const UVINF: u64 = 0x7FF0000000000000;
const UVNEGINF: u64 = 0xFFF0000000000000;
const MASK: u64 = 0x7FF;
const SHIFT: u32 = 64 - 11 - 1;
const BIAS: i64 = 1023;

/// Go's `math.NaN`: an IEEE 754 "not-a-number" value (bits `0x7FF8000000000001`).
pub fn nan() -> f64 {
    f64::from_bits(UVNAN)
}

/// Go's `math.Inf`: positive infinity if `sign >= 0`, negative infinity if
/// `sign < 0`.
pub fn inf(sign: i32) -> f64 {
    f64::from_bits(if sign >= 0 { UVINF } else { UVNEGINF })
}

/// Go's `math.IsInf`: reports whether `f` is an infinity, according to
/// `sign`. If `sign > 0`, it reports positive infinity; if `sign < 0`,
/// negative infinity; if `sign == 0`, either.
pub fn is_inf(f: f64, sign: i32) -> bool {
    (sign >= 0 && f == f64::INFINITY) || (sign <= 0 && f == f64::NEG_INFINITY)
}

/// Go's `cmp.Compare`: orders NaN before every other value and equal to itself.
///
/// `f64::total_cmp` differs: it puts positive NaN last and orders `-0` before
/// `+0`. Works for any `PartialOrd` type, so integers and strings compare as
/// usual; use it as `v.sort_by(math::compare)`.
#[allow(clippy::eq_op)]
pub fn compare<T: PartialOrd>(x: &T, y: &T) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (x != x, y != y) {
        (true, true) => Ordering::Equal,
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => x.partial_cmp(y).unwrap_or(Ordering::Equal),
    }
}

/// Go's builtin `min` (and `slices.Min`) for floats: NaN if either is NaN, and
/// `-0` is smaller than `+0`. Unlike [`f64::min`], NaN propagates; unlike
/// [`min`], an infinity does not override NaN. The same as the unstable
/// `f64::minimum`.
pub fn minimum(x: f64, y: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if y.is_nan() {
        return y;
    }
    if x == 0.0 && y == 0.0 {
        return if x.is_sign_negative() { x } else { y };
    }
    if y < x {
        y
    } else {
        x
    }
}

/// Go's builtin `max` (and `slices.Max`) for floats: NaN if either is NaN, and
/// `+0` is larger than `-0`. The same as the unstable `f64::maximum`.
pub fn maximum(x: f64, y: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if y.is_nan() {
        return y;
    }
    if x == 0.0 && y == 0.0 {
        return if x.is_sign_negative() { y } else { x };
    }
    if y > x {
        y
    } else {
        x
    }
}

/// Go's `math.Max`: the larger of `x` or `y`.
///
/// Special cases: `max(x, +Inf) = max(+Inf, x) = +Inf`, `max(x, NaN) =
/// max(NaN, x) = NaN`, `max(+0, ±0) = max(±0, +0) = +0`, `max(-0, -0) = -0`.
pub fn max(x: f64, y: f64) -> f64 {
    if is_inf(x, 1) || is_inf(y, 1) {
        return inf(1);
    }
    if x.is_nan() || y.is_nan() {
        return nan();
    }
    if x == 0.0 && x == y {
        return if x.is_sign_negative() { y } else { x };
    }
    if x > y {
        x
    } else {
        y
    }
}

/// Go's `math.Min`: the smaller of `x` or `y`.
///
/// Special cases: `min(x, -Inf) = min(-Inf, x) = -Inf`, `min(x, NaN) =
/// min(NaN, x) = NaN`, `min(-0, ±0) = min(±0, -0) = -0`.
pub fn min(x: f64, y: f64) -> f64 {
    if is_inf(x, -1) || is_inf(y, -1) {
        return inf(-1);
    }
    if x.is_nan() || y.is_nan() {
        return nan();
    }
    if x == 0.0 && x == y {
        return if x.is_sign_negative() { x } else { y };
    }
    if x < y {
        x
    } else {
        y
    }
}

/// Go's `math.Dim`: the maximum of `x - y` or 0.
///
/// Special cases: `dim(+Inf, +Inf) = NaN`, `dim(-Inf, -Inf) = NaN`, `dim(x,
/// NaN) = dim(NaN, x) = NaN`.
pub fn dim(x: f64, y: f64) -> f64 {
    let v = x - y;
    if v <= 0.0 {
        0.0
    } else {
        v
    }
}

/// Returns a normal number `y` and exponent `exp` satisfying `x == y * 2**exp`.
fn normalize(x: f64) -> (f64, i64) {
    const SMALLEST_NORMAL: f64 = 2.2250738585072014e-308; // 2**-1022
    if x.abs() < SMALLEST_NORMAL {
        return (x * (1u64 << 52) as f64, -52);
    }
    (x, 0)
}

/// Go's `math.Frexp`: breaks `f` into a normalized fraction in [1/2, 1) and
/// an integral power of two, so that `f == frac * 2**exp`.
///
/// Special cases: `frexp(±0) = ±0, 0`, `frexp(±Inf) = ±Inf, 0`, `frexp(NaN) =
/// NaN, 0`.
pub fn frexp(f: f64) -> (f64, i64) {
    if f == 0.0 || f.is_infinite() || f.is_nan() {
        return (f, 0);
    }
    let (f, mut exp) = normalize(f);
    let mut x = f.to_bits();
    exp += ((x >> SHIFT) & MASK) as i64 - BIAS + 1;
    x &= !(MASK << SHIFT);
    x |= (BIAS as u64 - 1) << SHIFT;
    (f64::from_bits(x), exp)
}

/// Go's `math.Ldexp`: the inverse of [`frexp`], `frac × 2**exp`.
///
/// Special cases: `ldexp(±0, exp) = ±0`, `ldexp(±Inf, exp) = ±Inf`,
/// `ldexp(NaN, exp) = NaN`.
pub fn ldexp(frac: f64, exp: i64) -> f64 {
    if frac == 0.0 || frac.is_infinite() || frac.is_nan() {
        return frac;
    }
    let (frac, e) = normalize(frac);
    let mut exp = exp.wrapping_add(e);
    let mut x = frac.to_bits();
    exp = exp.wrapping_add(((x >> SHIFT) & MASK) as i64 - BIAS);
    if exp < -1075 {
        return 0.0f64.copysign(frac); // underflow
    }
    if exp > 1023 {
        // overflow
        return if frac < 0.0 { inf(-1) } else { inf(1) };
    }
    let mut m = 1.0;
    if exp < -1022 {
        // denormal
        exp += 53;
        m = 1.0 / (1u64 << 53) as f64; // 2**-53
    }
    x &= !(MASK << SHIFT);
    x |= ((exp + BIAS) as u64) << SHIFT;
    m * f64::from_bits(x)
}

/// Go's `math.Modf`: the integer and fractional floating-point parts of `f`,
/// both with the sign of `f`.
///
/// Special cases: `modf(±Inf) = ±Inf, NaN`, `modf(NaN) = NaN, NaN`.
pub fn modf(f: f64) -> (f64, f64) {
    let integer = f.trunc();
    (integer, (f - integer).copysign(f))
}

/// Go's `math.Nextafter`: the next representable value after `x` towards `y`.
///
/// Special cases: `nextafter(x, x) = x`, `nextafter(NaN, y) = nextafter(x,
/// NaN) = NaN`.
pub fn nextafter(x: f64, y: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        nan()
    } else if x == y {
        x
    } else if x == 0.0 {
        f64::from_bits(1).copysign(y)
    } else if (y > x) == (x > 0.0) {
        f64::from_bits(x.to_bits() + 1)
    } else {
        f64::from_bits(x.to_bits() - 1)
    }
}

/// Go's `math.Nextafter32`: the `f32` counterpart of [`nextafter`].
pub fn nextafter32(x: f32, y: f32) -> f32 {
    if x.is_nan() || y.is_nan() {
        f32::from_bits(0x7FC00001)
    } else if x == y {
        x
    } else if x == 0.0 {
        f32::from_bits(1).copysign(y)
    } else if (y > x) == (x > 0.0) {
        f32::from_bits(x.to_bits() + 1)
    } else {
        f32::from_bits(x.to_bits() - 1)
    }
}

/// Go's `math.Remainder`: the IEEE 754 floating-point remainder of `x/y`.
///
/// Special cases: `remainder(±Inf, y) = NaN`, `remainder(NaN, y) = NaN`,
/// `remainder(x, 0) = NaN`, `remainder(x, ±Inf) = x`, `remainder(x, NaN) =
/// NaN`.
pub fn remainder(mut x: f64, mut y: f64) -> f64 {
    const TINY: f64 = 4.45014771701440276618e-308; // 0x0020000000000000
    const HALF_MAX: f64 = f64::MAX / 2.0;
    if x.is_nan() || y.is_nan() || x.is_infinite() || y == 0.0 {
        return nan();
    }
    if y.is_infinite() {
        return x;
    }
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    if y < 0.0 {
        y = -y;
    }
    if x == y {
        return if sign { -0.0 } else { 0.0 };
    }
    if y <= HALF_MAX {
        x %= y + y; // now x < 2y
    }
    if y < TINY {
        if x + x > y {
            x -= y;
            if x + x >= y {
                x -= y;
            }
        }
    } else {
        let y_half = 0.5 * y;
        if x > y_half {
            x -= y;
            if x >= y_half {
                x -= y;
            }
        }
    }
    if sign {
        x = -x;
    }
    x
}

fn ilogb_finite(x: f64) -> i64 {
    let (x, exp) = normalize(x);
    ((x.to_bits() >> SHIFT) & MASK) as i64 - BIAS + exp
}

/// Go's `math.Logb`: the binary exponent of `x`.
///
/// Special cases: `logb(±Inf) = +Inf`, `logb(0) = -Inf`, `logb(NaN) = NaN`.
pub fn logb(x: f64) -> f64 {
    if x == 0.0 {
        inf(-1)
    } else if x.is_infinite() {
        inf(1)
    } else if x.is_nan() {
        x
    } else {
        ilogb_finite(x) as f64
    }
}

/// Go's `math.Ilogb`: the binary exponent of `x` as an integer.
///
/// Special cases: `ilogb(±Inf) = MaxInt32`, `ilogb(0) = MinInt32`,
/// `ilogb(NaN) = MaxInt32`.
pub fn ilogb(x: f64) -> i64 {
    if x == 0.0 {
        i64::from(i32::MIN)
    } else if x.is_nan() || x.is_infinite() {
        i64::from(i32::MAX)
    } else {
        ilogb_finite(x)
    }
}

/// Go's `math.Log2`: the binary logarithm of `x`, exact for powers of two.
pub fn log2(x: f64) -> f64 {
    let (frac, exp) = frexp(x);
    // Make sure exact powers of two give an exact answer.
    if frac == 0.5 {
        return (exp - 1) as f64;
    }
    log(frac) * std::f64::consts::LOG2_E + exp as f64
}

/// Go's `math.Log10`: the decimal logarithm of `x`, computed as
/// `ln(x) * (1/Ln10)` like Go (so `log10(1000)` is `2.9999999999999996`).
pub fn log10(x: f64) -> f64 {
    log(x) * std::f64::consts::LOG10_E
}

/// Go's `math.Pow10`: `10**n`, the base-10 exponential of `n`.
///
/// Special cases: `pow10(n) = 0` for `n < -323`, `pow10(n) = +Inf` for
/// `n > 308`.
pub fn pow10(n: i64) -> f64 {
    const TAB: [f64; 32] = [
        1e00, 1e01, 1e02, 1e03, 1e04, 1e05, 1e06, 1e07, 1e08, 1e09, 1e10, 1e11, 1e12, 1e13, 1e14,
        1e15, 1e16, 1e17, 1e18, 1e19, 1e20, 1e21, 1e22, 1e23, 1e24, 1e25, 1e26, 1e27, 1e28, 1e29,
        1e30, 1e31,
    ];
    const POS: [f64; 10] = [
        1e00, 1e32, 1e64, 1e96, 1e128, 1e160, 1e192, 1e224, 1e256, 1e288,
    ];
    const NEG: [f64; 11] = [
        1e-00, 1e-32, 1e-64, 1e-96, 1e-128, 1e-160, 1e-192, 1e-224, 1e-256, 1e-288, 1e-320,
    ];
    if (0..=308).contains(&n) {
        let n = n as usize;
        return POS[n / 32] * TAB[n % 32];
    }
    if (-323..0).contains(&n) {
        let n = n.unsigned_abs() as usize;
        return NEG[n / 32] / TAB[n % 32];
    }
    if n > 0 {
        inf(1)
    } else {
        0.0
    }
}

/// Go's `math.Atanh`: the inverse hyperbolic tangent of `x`.
///
/// Special cases: `atanh(1) = +Inf`, `atanh(±0) = ±0`, `atanh(-1) = -Inf`,
/// `atanh(x) = NaN` if `x < -1` or `x > 1`, `atanh(NaN) = NaN`.
pub fn atanh(mut x: f64) -> f64 {
    const NEAR_ZERO: f64 = 1.0 / (1u64 << 28) as f64; // 2**-28
    if !(-1.0..=1.0).contains(&x) || x.is_nan() {
        return nan();
    }
    if x == 1.0 {
        return inf(1);
    }
    if x == -1.0 {
        return inf(-1);
    }
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    let temp = if x < NEAR_ZERO {
        x
    } else if x < 0.5 {
        let t = x + x;
        0.5 * log1p(t + t * x / (1.0 - x))
    } else {
        0.5 * log1p((x + x) / (1.0 - x))
    };
    if sign {
        -temp
    } else {
        temp
    }
}

fn is_odd_int(x: f64) -> bool {
    if x.abs() >= (1u64 << 53) as f64 {
        return false;
    }
    let (xi, xf) = modf(x);
    xf == 0.0 && (xi as i64) & 1 == 1
}

/// Go's `math.Pow`: `x**y`, the base-`x` exponential of `y`, by Go's
/// algorithm (repeated squaring of the mantissa for the integer part of `y`).
///
/// Special cases follow C99 and Go's documentation: `pow(x, ±0) = 1`,
/// `pow(1, y) = 1`, `pow(x, 1) = x`, `pow(NaN, y) = NaN`, `pow(±0, y)` by the
/// sign and oddness of `y`, `pow(x, ±Inf)` by `|x|` against 1, `pow(-1, ±Inf)
/// = 1`, `pow(x < 0, finite non-integer) = NaN`.
pub fn pow(x: f64, y: f64) -> f64 {
    if y == 0.0 || x == 1.0 {
        return 1.0;
    }
    if y == 1.0 {
        return x;
    }
    if x.is_nan() || y.is_nan() {
        return nan();
    }
    if x == 0.0 {
        if y < 0.0 {
            return if x.is_sign_negative() && is_odd_int(y) {
                inf(-1)
            } else {
                inf(1)
            };
        }
        if y > 0.0 {
            return if x.is_sign_negative() && is_odd_int(y) {
                x
            } else {
                0.0
            };
        }
    } else if y.is_infinite() {
        return if x == -1.0 {
            1.0
        } else if (x.abs() < 1.0) == is_inf(y, 1) {
            0.0
        } else {
            inf(1)
        };
    } else if x.is_infinite() {
        if is_inf(x, -1) {
            return pow(1.0 / x, -y); // pow(-0, -y)
        }
        if y < 0.0 {
            return 0.0;
        }
        if y > 0.0 {
            return inf(1);
        }
    } else if y == 0.5 {
        return x.sqrt();
    } else if y == -0.5 {
        return 1.0 / x.sqrt();
    }

    let (mut yi, mut yf) = modf(y.abs());
    if yf != 0.0 && x < 0.0 {
        return nan();
    }
    if yi >= 9.223372036854775808e18 {
        // yi is a large even int that will lead to overflow (or underflow to 0)
        // for all x except -1 (x == 1 was handled earlier)
        return if x == -1.0 {
            1.0
        } else if (x.abs() < 1.0) == (y > 0.0) {
            0.0
        } else {
            inf(1)
        };
    }

    // ans = a1 * 2**ae (= 1 for now).
    let mut a1 = 1.0;
    let mut ae: i64 = 0;

    // ans *= x**yf
    if yf != 0.0 {
        if yf > 0.5 {
            yf -= 1.0;
            yi += 1.0;
        }
        a1 = exp(yf * log(x));
    }

    // ans *= x**yi
    let (mut x1, mut xe) = frexp(x);
    let mut i = yi as i64;
    while i != 0 {
        if !(-(1 << 12)..=(1 << 12)).contains(&xe) {
            // catastrophic overflow or underflow
            ae += xe;
            break;
        }
        if i & 1 == 1 {
            a1 *= x1;
            ae += xe;
        }
        x1 *= x1;
        xe <<= 1;
        if x1 < 0.5 {
            x1 += x1;
            xe -= 1;
        }
        i >>= 1;
    }

    // ans = a1 * 2**ae; if y < 0 { ans = 1 / ans }, but in the opposite order
    if y < 0.0 {
        a1 = 1.0 / a1;
        ae = -ae;
    }
    ldexp(a1, ae)
}

fn xatan(x: f64) -> f64 {
    const P0: f64 = -8.750608600031904122785e-01;
    const P1: f64 = -1.615753718733365076637e+01;
    const P2: f64 = -7.500855792314704667340e+01;
    const P3: f64 = -1.228866684490136173410e+02;
    const P4: f64 = -6.485021904942025371773e+01;
    const Q0: f64 = 2.485846490142306297962e+01;
    const Q1: f64 = 1.650270098316988542046e+02;
    const Q2: f64 = 4.328810604912902668951e+02;
    const Q3: f64 = 4.853903996359136964868e+02;
    const Q4: f64 = 1.945506571482613964425e+02;
    let mut z = x * x;
    z = z * ((((P0 * z + P1) * z + P2) * z + P3) * z + P4)
        / (((((z + Q0) * z + Q1) * z + Q2) * z + Q3) * z + Q4);
    x * z + x
}

fn satan(x: f64) -> f64 {
    const MOREBITS: f64 = 6.123233995736765886130e-17; // pi/2 = PIO2 + Morebits
    const TAN3PIO8: f64 = 2.41421356237309504880; // tan(3*pi/8)
    use std::f64::consts::{FRAC_PI_2, FRAC_PI_4};
    if x <= 0.66 {
        return xatan(x);
    }
    if x > TAN3PIO8 {
        return FRAC_PI_2 - xatan(1.0 / x) + MOREBITS;
    }
    FRAC_PI_4 + xatan((x - 1.0) / (x + 1.0)) + 0.5 * MOREBITS
}

/// Go's `math.Atan`: the arctangent, in radians, of `x`.
///
/// Special cases: `atan(±0) = ±0`, `atan(±Inf) = ±Pi/2`.
pub fn atan(x: f64) -> f64 {
    if x == 0.0 {
        return x;
    }
    if x > 0.0 {
        return satan(x);
    }
    -satan(-x)
}

/// Go's `math.Asin`: the arcsine, in radians, of `x`.
///
/// Special cases: `asin(±0) = ±0`, `asin(x) = NaN` if `x < -1` or `x > 1`.
pub fn asin(mut x: f64) -> f64 {
    if x == 0.0 {
        return x;
    }
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    if x > 1.0 {
        return nan();
    }
    let mut temp = (1.0 - x * x).sqrt();
    if x > 0.7 {
        temp = std::f64::consts::FRAC_PI_2 - satan(temp / x);
    } else {
        temp = satan(x / temp);
    }
    if sign {
        -temp
    } else {
        temp
    }
}

/// Go's `math.Acos`: the arccosine, in radians, of `x`, computed as
/// `Pi/2 - Asin(x)` like Go.
///
/// Special cases: `acos(x) = NaN` if `x < -1` or `x > 1`.
pub fn acos(x: f64) -> f64 {
    std::f64::consts::FRAC_PI_2 - asin(x)
}

/// Go's `math.Atan2`: the arc tangent of `y/x`, using the signs of the two to
/// determine the quadrant of the return value.
///
/// Special cases follow C99 Annex F: `atan2(±0, x >= +0) = ±0`, `atan2(±0, x
/// <= -0) = ±Pi`, `atan2(y, ±0) = ±Pi/2` for `y != 0`, infinities give
/// multiples of `Pi/4`, and NaN arguments give NaN.
pub fn atan2(y: f64, x: f64) -> f64 {
    use std::f64::consts::{FRAC_PI_2, FRAC_PI_4};
    if y.is_nan() || x.is_nan() {
        return nan();
    }
    if y == 0.0 {
        if x >= 0.0 && !x.is_sign_negative() {
            return 0.0f64.copysign(y);
        }
        return PI.copysign(y);
    }
    if x == 0.0 {
        return FRAC_PI_2.copysign(y);
    }
    if x.is_infinite() {
        if is_inf(x, 1) {
            return if y.is_infinite() {
                FRAC_PI_4.copysign(y)
            } else {
                0.0f64.copysign(y)
            };
        }
        return if y.is_infinite() {
            (3.0 * PI / 4.0).copysign(y)
        } else {
            PI.copysign(y)
        };
    }
    if y.is_infinite() {
        return FRAC_PI_2.copysign(y);
    }
    // Call atan and determine the quadrant.
    let q = atan(y / x);
    if x < 0.0 {
        if q <= 0.0 {
            return q + PI;
        }
        return q - PI;
    }
    q
}

/// Go's `math.Sinh`: the hyperbolic sine of `x`.
///
/// Special cases: `sinh(±0) = ±0`, `sinh(±Inf) = ±Inf`, `sinh(NaN) = NaN`.
pub fn sinh(mut x: f64) -> f64 {
    // The coefficients are #2029 from Hart & Cheney. (20.36D)
    const P0: f64 = -0.6307673640497716991184787251e+6;
    const P1: f64 = -0.8991272022039509355398013511e+5;
    const P2: f64 = -0.2894211355989563807284660366e+4;
    const P3: f64 = -0.2630563213397497062819489e+2;
    const Q0: f64 = -0.6307673640497716991212077277e+6;
    const Q1: f64 = 0.1521517378790019070696485176e+5;
    const Q2: f64 = -0.173678953558233699533450911e+3;
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    let mut temp;
    if x > 21.0 {
        temp = exp(x) * 0.5;
    } else if x > 0.5 {
        let ex = exp(x);
        temp = (ex - 1.0 / ex) * 0.5;
    } else {
        let sq = x * x;
        temp = (((P3 * sq + P2) * sq + P1) * sq + P0) * x;
        temp /= ((sq + Q2) * sq + Q1) * sq + Q0;
    }
    if sign {
        -temp
    } else {
        temp
    }
}

/// Go's `math.Cosh`: the hyperbolic cosine of `x`.
///
/// Special cases: `cosh(±0) = 1`, `cosh(±Inf) = +Inf`, `cosh(NaN) = NaN`.
pub fn cosh(x: f64) -> f64 {
    let x = x.abs();
    if x > 21.0 {
        return exp(x) * 0.5;
    }
    let ex = exp(x);
    (ex + 1.0 / ex) * 0.5
}

/// Go's `math.Tanh`: the hyperbolic tangent of `x`.
///
/// Special cases: `tanh(±0) = ±0`, `tanh(±Inf) = ±1`, `tanh(NaN) = NaN`.
pub fn tanh(x: f64) -> f64 {
    const P: [f64; 3] = [
        -9.64399179425052238628e-1,
        -9.92877231001918586564e1,
        -1.61468768441708447952e3,
    ];
    const Q: [f64; 3] = [
        1.12811678491632931402e2,
        2.23548839060100448583e3,
        4.84406305325125486048e3,
    ];
    const MAXLOG: f64 = 8.8029691931113054295988e+01; // log(2**127)
    let mut z = x.abs();
    if z > 0.5 * MAXLOG {
        return if x < 0.0 { -1.0 } else { 1.0 };
    }
    if z >= 0.625 {
        let s = exp(2.0 * z);
        z = 1.0 - 2.0 / (s + 1.0);
        if x < 0.0 {
            z = -z;
        }
        return z;
    }
    if x == 0.0 {
        return x;
    }
    let s = x * x;
    x + x * s * ((P[0] * s + P[1]) * s + P[2]) / (((s + Q[0]) * s + Q[1]) * s + Q[2])
}

/// Go's `math.Hypot`: `sqrt(p*p + q*q)`, taking care to avoid unnecessary
/// overflow and underflow.
///
/// Special cases: `hypot(±Inf, q) = hypot(p, ±Inf) = +Inf` (even for NaN),
/// `hypot(NaN, q) = hypot(p, NaN) = NaN`.
pub fn hypot(p: f64, q: f64) -> f64 {
    let (mut p, mut q) = (p.abs(), q.abs());
    if is_inf(p, 1) || is_inf(q, 1) {
        return inf(1);
    }
    if p.is_nan() || q.is_nan() {
        return nan();
    }
    if p < q {
        std::mem::swap(&mut p, &mut q);
    }
    if p == 0.0 {
        return 0.0;
    }
    q /= p;
    p * (1.0 + q * q).sqrt()
}

/// Go's `math.Log`: the natural logarithm of `x` (FreeBSD's `e_log.c`, as Go
/// ports it).
///
/// Special cases: `log(+Inf) = +Inf`, `log(0) = -Inf`, `log(x < 0) = NaN`,
/// `log(NaN) = NaN`.
pub fn log(x: f64) -> f64 {
    const LN2_HI: f64 = 6.93147180369123816490e-01; // 3fe62e42 fee00000
    const LN2_LO: f64 = 1.90821492927058770002e-10; // 3dea39ef 35793c76
    const L1: f64 = 6.666666666666735130e-01; // 3FE55555 55555593
    const L2: f64 = 3.999999999940941908e-01; // 3FD99999 9997FA04
    const L3: f64 = 2.857142874366239149e-01; // 3FD24924 94229359
    const L4: f64 = 2.222219843214978396e-01; // 3FCC71C5 1D8E78AF
    const L5: f64 = 1.818357216161805012e-01; // 3FC74664 96CB03DE
    const L6: f64 = 1.531383769920937332e-01; // 3FC39A09 D078C69F
    const L7: f64 = 1.479819860511658591e-01; // 3FC2F112 DF3E5244
    if x.is_nan() || is_inf(x, 1) {
        return x;
    }
    if x < 0.0 {
        return nan();
    }
    if x == 0.0 {
        return inf(-1);
    }
    // reduce
    let (mut f1, mut ki) = frexp(x);
    if f1 < std::f64::consts::SQRT_2 / 2.0 {
        f1 *= 2.0;
        ki -= 1;
    }
    let f = f1 - 1.0;
    let k = ki as f64;
    // compute
    let s = f / (2.0 + f);
    let s2 = s * s;
    let s4 = s2 * s2;
    let t1 = s2 * (L1 + s4 * (L3 + s4 * (L5 + s4 * L7)));
    let t2 = s4 * (L2 + s4 * (L4 + s4 * L6));
    let r = t1 + t2;
    let hfsq = 0.5 * f * f;
    k * LN2_HI - ((hfsq - (s * (hfsq + r) + k * LN2_LO)) - f)
}
