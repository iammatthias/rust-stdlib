//! Exponential and logarithmic functions of FreeBSD's msun (`e_exp.c`,
//! `s_expm1.c`, `s_log1p.c`) as Go ports them (see NOTICE). The platform
//! libm rounds the last bit differently, so these are not mapped to
//! `f64::exp` and friends.
#![allow(clippy::excessive_precision, clippy::approx_constant)]

use super::{inf, is_inf, ldexp, nan};

const LN2_HI: f64 = 6.93147180369123816490e-01;
const LN2_LO: f64 = 1.90821492927058770002e-10;

fn expmulti(hi: f64, lo: f64, k: i64) -> f64 {
    const P1: f64 = 1.66666666666666657415e-01; // 0x3FC55555; 0x55555555
    const P2: f64 = -2.77777777770155933842e-03; // 0xBF66C16C; 0x16BEBD93
    const P3: f64 = 6.61375632143793436117e-05; // 0x3F11566A; 0xAF25DE2C
    const P4: f64 = -1.65339022054652515390e-06; // 0xBEBBBD41; 0xC5D26BF1
    const P5: f64 = 4.13813679705723846039e-08; // 0x3E663769; 0x72BEA4D0
    let r = hi - lo;
    let t = r * r;
    let c = r - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t * P5))));
    let y = 1.0 - ((lo - (r * c) / (2.0 - c)) - hi);
    ldexp(y, k)
}

/// Go's `math.Exp`: `e**x`, the base-e exponential of `x`.
///
/// Special cases: `exp(+Inf) = +Inf`, `exp(NaN) = NaN`; very large values
/// overflow to `+Inf` and very small values underflow to 0.
pub fn exp(x: f64) -> f64 {
    const LOG2E: f64 = 1.44269504088896338700e+00;
    const OVERFLOW: f64 = 7.09782712893383973096e+02;
    const UNDERFLOW: f64 = -7.45133219101941108420e+02;
    const NEAR_ZERO: f64 = 1.0 / (1u64 << 28) as f64; // 2**-28
    if x.is_nan() {
        return x;
    }
    if x > OVERFLOW {
        return inf(1);
    }
    if x < UNDERFLOW {
        return 0.0;
    }
    if -NEAR_ZERO < x && x < NEAR_ZERO {
        return 1.0 + x;
    }
    // reduce; computed as r = hi - lo for extra precision.
    let k = if x < 0.0 {
        (LOG2E * x - 0.5) as i64
    } else if x > 0.0 {
        (LOG2E * x + 0.5) as i64
    } else {
        0
    };
    let hi = x - k as f64 * LN2_HI;
    let lo = k as f64 * LN2_LO;
    expmulti(hi, lo, k)
}

/// Go's `math.Exp2`: `2**x`, the base-2 exponential of `x`.
///
/// Special cases are the same as [`exp`].
pub fn exp2(x: f64) -> f64 {
    const OVERFLOW: f64 = 1.0239999999999999e+03;
    const UNDERFLOW: f64 = -1.0740e+03;
    if x.is_nan() {
        return x;
    }
    if x > OVERFLOW {
        return inf(1);
    }
    if x < UNDERFLOW {
        return 0.0;
    }
    // argument reduction; x = k + t, with t in [-0.5, 0.5]
    let k = if x > 0.0 {
        (x + 0.5) as i64
    } else if x < 0.0 {
        (x - 0.5) as i64
    } else {
        0
    };
    let t = x - k as f64;
    let hi = t * LN2_HI; // t * Ln2Hi is exact here
    let lo = -t * LN2_LO;
    expmulti(hi, lo, k)
}

/// Go's `math.Expm1`: `e**x - 1`, accurate even when `x` is near zero.
///
/// Special cases: `expm1(+Inf) = +Inf`, `expm1(-Inf) = -1`, `expm1(NaN) = NaN`,
/// very large values overflow to `+Inf`.
pub fn expm1(mut x: f64) -> f64 {
    const OTHRESHOLD: f64 = 7.09782712893383973096e+02; // 0x40862E42FEFA39EF
    const LN2_X56: f64 = 3.88162421113569373274e+01; // 0x4043687a9f1af2b1
    const LN2_HALF_X3: f64 = 1.03972077083991796413e+00; // 0x3ff0a2b23f3bab73
    const LN2_HALF: f64 = 3.46573590279972654709e-01; // 0x3fd62e42fefa39ef
    const INV_LN2: f64 = 1.44269504088896338700e+00; // 0x3ff71547652b82fe
    const TINY: f64 = 1.0 / (1u64 << 54) as f64; // 2**-54 = 0x3c90000000000000
                                                 // scaled coefficients related to expm1
    const Q1: f64 = -3.33333333333331316428e-02; // 0xBFA11111111110F4
    const Q2: f64 = 1.58730158725481460165e-03; // 0x3F5A01A019FE5585
    const Q3: f64 = -7.93650757867487942473e-05; // 0xBF14CE199EAADBB7
    const Q4: f64 = 4.00821782732936239552e-06; // 0x3ED0CFCA86E65239
    const Q5: f64 = -2.01099218183624371326e-07; // 0xBE8AFDB76E09C32D
    if is_inf(x, 1) || x.is_nan() {
        return x;
    }
    if is_inf(x, -1) {
        return -1.0;
    }
    let mut absx = x;
    let mut sign = false;
    if x < 0.0 {
        absx = -absx;
        sign = true;
    }
    // filter out huge argument
    if absx >= LN2_X56 {
        // if |x| >= 56 * ln2
        if sign {
            return -1.0; // x < -56*ln2, return -1
        }
        if absx >= OTHRESHOLD {
            return inf(1);
        }
    }
    // argument reduction
    let mut c = 0.0;
    let k: i64;
    if absx > LN2_HALF {
        // if |x| > 0.5 * ln2
        let (hi, lo);
        if absx < LN2_HALF_X3 {
            // and |x| < 1.5 * ln2
            if !sign {
                hi = x - LN2_HI;
                lo = LN2_LO;
                k = 1;
            } else {
                hi = x + LN2_HI;
                lo = -LN2_LO;
                k = -1;
            }
        } else {
            k = if !sign {
                (INV_LN2 * x + 0.5) as i64
            } else {
                (INV_LN2 * x - 0.5) as i64
            };
            let t = k as f64;
            hi = x - t * LN2_HI; // t * Ln2Hi is exact here
            lo = t * LN2_LO;
        }
        x = hi - lo;
        c = (hi - x) - lo;
    } else if absx < TINY {
        // when |x| < 2**-54, return x
        return x;
    } else {
        k = 0;
    }
    // x is now in primary range
    let hfx = 0.5 * x;
    let hxs = x * hfx;
    let r1 = 1.0 + hxs * (Q1 + hxs * (Q2 + hxs * (Q3 + hxs * (Q4 + hxs * Q5))));
    let t = 3.0 - r1 * hfx;
    let mut e = hxs * ((r1 - t) / (6.0 - x * t));
    if k == 0 {
        return x - (x * e - hxs); // c is 0
    }
    e = x * (e - c) - c;
    e -= hxs;
    if k == -1 {
        return 0.5 * (x - e) - 0.5;
    }
    if k == 1 {
        if x < -0.25 {
            return -2.0 * (e - (x + 0.5));
        }
        return 1.0 + 2.0 * (x - e);
    }
    let add_k = |y: f64| f64::from_bits(y.to_bits().wrapping_add((k as u64) << 52));
    if k <= -2 || k > 56 {
        // suffice to return exp(x)-1
        let y = 1.0 - (e - x);
        return add_k(y) - 1.0;
    }
    if k < 20 {
        let t = f64::from_bits(0x3ff0000000000000 - (0x20000000000000u64 >> k)); // t=1-2**-k
        let y = t - (e - x);
        return add_k(y);
    }
    let t = f64::from_bits(((0x3ff - k) as u64) << 52); // 2**-k
    let mut y = x - (e + t);
    y += 1.0;
    add_k(y)
}

/// Go's `math.Log1p`: the natural logarithm of `1 + x`, accurate even when
/// `x` is near zero.
///
/// Special cases: `log1p(+Inf) = +Inf`, `log1p(±0) = ±0`, `log1p(-1) = -Inf`,
/// `log1p(x < -1) = NaN`, `log1p(NaN) = NaN`.
pub fn log1p(x: f64) -> f64 {
    const SQRT2_M1: f64 = 4.142135623730950488017e-01; // Sqrt(2)-1 = 0x3fda827999fcef34
    const SQRT2_HALF_M1: f64 = -2.928932188134524755992e-01; // Sqrt(2)/2-1 = 0xbfd2bec333018866
    const SMALL: f64 = 1.0 / (1u64 << 29) as f64; // 2**-29 = 0x3e20000000000000
    const TINY: f64 = 1.0 / (1u64 << 54) as f64; // 2**-54
    const TWO53: f64 = (1u64 << 53) as f64; // 2**53
    const LP1: f64 = 6.666666666666735130e-01; // 3FE5555555555593
    const LP2: f64 = 3.999999999940941908e-01; // 3FD999999997FA04
    const LP3: f64 = 2.857142874366239149e-01; // 3FD2492494229359
    const LP4: f64 = 2.222219843214978396e-01; // 3FCC71C51D8E78AF
    const LP5: f64 = 1.818357216161805012e-01; // 3FC7466496CB03DE
    const LP6: f64 = 1.531383769920937332e-01; // 3FC39A09D078C69F
    const LP7: f64 = 1.479819860511658591e-01; // 3FC2F112DF3E5244
    if x < -1.0 || x.is_nan() {
        return nan();
    }
    if x == -1.0 {
        return inf(-1);
    }
    if is_inf(x, 1) {
        return inf(1);
    }
    let absx = x.abs();
    let mut f = 0.0;
    let mut iu: u64 = 0;
    let mut k: i64 = 1;
    if absx < SQRT2_M1 {
        // |x| < Sqrt(2)-1
        if absx < SMALL {
            // |x| < 2**-29
            if absx < TINY {
                // |x| < 2**-54
                return x;
            }
            return x - x * x * 0.5;
        }
        if x > SQRT2_HALF_M1 {
            // Sqrt(2)/2-1 < x
            // (Sqrt(2)/2-1) < x < (Sqrt(2)-1)
            k = 0;
            f = x;
            iu = 1;
        }
    }
    let mut c = 0.0;
    if k != 0 {
        let mut u;
        if absx < TWO53 {
            // 1<<53
            u = 1.0 + x;
            iu = u.to_bits();
            k = ((iu >> 52) as i64) - 1023;
            // correction term
            if k > 0 {
                c = 1.0 - (u - x);
            } else {
                c = x - (u - 1.0);
            }
            c /= u;
        } else {
            u = x;
            iu = u.to_bits();
            k = ((iu >> 52) as i64) - 1023;
            c = 0.0;
        }
        iu &= 0x000fffffffffffff;
        if iu < 0x0006a09e667f3bcd {
            // mantissa of Sqrt(2)
            u = f64::from_bits(iu | 0x3ff0000000000000); // normalize u
        } else {
            k += 1;
            u = f64::from_bits(iu | 0x3fe0000000000000); // normalize u/2
            iu = (0x0010000000000000 - iu) >> 2;
        }
        f = u - 1.0; // Sqrt(2)/2 < u < Sqrt(2)
    }
    let hfsq = 0.5 * f * f;
    let kf = k as f64;
    if iu == 0 {
        // |f| < 2**-20
        if f == 0.0 {
            if k == 0 {
                return 0.0;
            }
            c += kf * LN2_LO;
            return kf * LN2_HI + c;
        }
        let r = hfsq * (1.0 - 0.66666666666666666 * f); // avoid division
        if k == 0 {
            return f - r;
        }
        return kf * LN2_HI - ((r - (kf * LN2_LO + c)) - f);
    }
    let s = f / (2.0 + f);
    let z = s * s;
    let r = z * (LP1 + z * (LP2 + z * (LP3 + z * (LP4 + z * (LP5 + z * (LP6 + z * LP7))))));
    if k == 0 {
        return f - (hfsq - s * (hfsq + r));
    }
    kf * LN2_HI - ((hfsq - (s * (hfsq + r) + (kf * LN2_LO + c))) - f)
}

/// Go's `math.Cbrt`: the cube root of `x`.
///
/// Special cases: `cbrt(±0) = ±0`, `cbrt(±Inf) = ±Inf`, `cbrt(NaN) = NaN`.
pub fn cbrt(mut x: f64) -> f64 {
    const B1: u64 = 715094163; // (682-0.03306235651)*2**20
    const B2: u64 = 696219795; // (664-0.03306235651)*2**20
    const C: f64 = 5.42857142857142815906e-01; // 19/35     = 0x3FE15F15F15F15F1
    const D: f64 = -7.05306122448979611050e-01; // -864/1225 = 0xBFE691DE2532C834
    const E: f64 = 1.41428571428571436819e+00; // 99/70     = 0x3FF6A0EA0EA0EA0F
    const F: f64 = 1.60714285714285720630e+00; // 45/28     = 0x3FF9B6DB6DB6DB6E
    const G: f64 = 3.57142857142857150787e-01; // 5/14      = 0x3FD6DB6DB6DB6DB7
    const SMALLEST_NORMAL: f64 = 2.22507385850720138309e-308; // 2**-1022
    if x == 0.0 || x.is_nan() || x.is_infinite() {
        return x;
    }
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    // rough cbrt to 5 bits
    let mut t = f64::from_bits(x.to_bits() / 3 + (B1 << 32));
    if x < SMALLEST_NORMAL {
        // subnormal number
        t = (1u64 << 54) as f64; // set t= 2**54
        t *= x;
        t = f64::from_bits(t.to_bits() / 3 + (B2 << 32));
    }
    // new cbrt to 23 bits
    let mut r = t * t / x;
    let mut s = C + r * t;
    t *= G + F / (s + E + D / s);
    // chop to 22 bits, then add one to get 23 bits
    t = f64::from_bits((t.to_bits() & (0xFFFFFFFFCu64 << 28)) + (1 << 30));
    // one step newton iteration to 53 bits with error less than 0.667 ulps
    s = t * t; // t*t is exact
    r = x / s;
    let w = t + t;
    r = (r - t) / (w + r); // r-s is exact
    t += t * r;
    if sign {
        -t
    } else {
        t
    }
}

/// Go's `math.Asinh`: the inverse hyperbolic sine of `x`.
///
/// Special cases: `asinh(±0) = ±0`, `asinh(±Inf) = ±Inf`, `asinh(NaN) = NaN`.
pub fn asinh(mut x: f64) -> f64 {
    const LN2: f64 = 6.93147180559945286227e-01; // 0x3FE62E42FEFA39EF
    const NEAR_ZERO: f64 = 1.0 / (1u64 << 28) as f64; // 2**-28
    const LARGE: f64 = (1u64 << 28) as f64; // 2**28
    if x.is_nan() || x.is_infinite() {
        return x;
    }
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    let temp = if x > LARGE {
        super::log(x) + LN2 // |x| > 2**28
    } else if x > 2.0 {
        super::log(2.0 * x + 1.0 / ((x * x + 1.0).sqrt() + x)) // 2**28 > |x| > 2.0
    } else if x < NEAR_ZERO {
        x // |x| < 2**-28
    } else {
        log1p(x + x * x / (1.0 + (1.0 + x * x).sqrt())) // 2.0 > |x| > 2**28
    };
    if sign {
        -temp
    } else {
        temp
    }
}

/// Go's `math.Acosh`: the inverse hyperbolic cosine of `x`.
///
/// Special cases: `acosh(+Inf) = +Inf`, `acosh(x) = NaN` if `x < 1`,
/// `acosh(NaN) = NaN`.
pub fn acosh(x: f64) -> f64 {
    const LARGE: f64 = (1u64 << 28) as f64; // 2**28
    if x < 1.0 || x.is_nan() {
        return nan();
    }
    if x == 1.0 {
        return 0.0;
    }
    if x >= LARGE {
        return super::log(x) + std::f64::consts::LN_2; // x > 2**28
    }
    if x > 2.0 {
        return super::log(2.0 * x - 1.0 / (x + (x * x - 1.0).sqrt())); // 2**28 > x > 2
    }
    let t = x - 1.0;
    log1p(t + (2.0 * t + t * t).sqrt()) // 2 >= x > 1
}
