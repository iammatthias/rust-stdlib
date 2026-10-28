//! Gamma and log-gamma functions, from FreeBSD's `e_lgamma_r.c` and the Cephes
//! `gamma.c`, as ported by Go's `math/gamma.go` and `math/lgamma.go`
//! (see NOTICE).
#![allow(
    non_upper_case_globals,
    clippy::excessive_precision,
    clippy::approx_constant,
    clippy::many_single_char_names
)]

use super::{inf, is_inf, nan};
use std::f64::consts::PI;

const GAM_P: [f64; 7] = [
    1.60119522476751861407e-04,
    1.19135147006586384913e-03,
    1.04213797561761569935e-02,
    4.76367800457137231464e-02,
    2.07448227648435975150e-01,
    4.94214826801497100753e-01,
    9.99999999999999996796e-01,
];
const GAM_Q: [f64; 8] = [
    -2.31581873324120129819e-05,
    5.39605580493303397842e-04,
    -4.45641913851797240494e-03,
    1.18139785222060435552e-02,
    3.58236398605498653373e-02,
    -2.34591795718243348568e-01,
    7.14304917030273074085e-02,
    1.00000000000000000320e+00,
];
const GAM_S: [f64; 5] = [
    7.87311395793093628397e-04,
    -2.29549961613378126380e-04,
    -2.68132617805781232825e-03,
    3.47222221605458667310e-03,
    8.33333333333482257126e-02,
];
const LGAM_A: [f64; 12] = [
    7.72156649015328655494e-02,
    3.22467033424113591611e-01,
    6.73523010531292681824e-02,
    2.05808084325167332806e-02,
    7.38555086081402883957e-03,
    2.89051383673415629091e-03,
    1.19270763183362067845e-03,
    5.10069792153511336608e-04,
    2.20862790713908385557e-04,
    1.08011567247583939954e-04,
    2.52144565451257326939e-05,
    4.48640949618915160150e-05,
];
const LGAM_R: [f64; 7] = [
    1.0,
    1.39200533467621045958e+00,
    7.21935547567138069525e-01,
    1.71933865632803078993e-01,
    1.86459191715652901344e-02,
    7.77942496381893596434e-04,
    7.32668430744625636189e-06,
];
const LGAM_S: [f64; 7] = [
    -7.72156649015328655494e-02,
    2.14982415960608852501e-01,
    3.25778796408930981787e-01,
    1.46350472652464452805e-01,
    2.66422703033638609560e-02,
    1.84028451407337715652e-03,
    3.19475326584100867617e-05,
];
const LGAM_T: [f64; 15] = [
    4.83836122723810047042e-01,
    -1.47587722994593911752e-01,
    6.46249402391333854778e-02,
    -3.27885410759859649565e-02,
    1.79706750811820387126e-02,
    -1.03142241298341437450e-02,
    6.10053870246291332635e-03,
    -3.68452016781138256760e-03,
    2.25964780900612472250e-03,
    -1.40346469989232843813e-03,
    8.81081882437654011382e-04,
    -5.38595305356740546715e-04,
    3.15632070903625950361e-04,
    -3.12754168375120860518e-04,
    3.35529192635519073543e-04,
];
const LGAM_U: [f64; 6] = [
    -7.72156649015328655494e-02,
    6.32827064025093366517e-01,
    1.45492250137234768737e+00,
    9.77717527963372745603e-01,
    2.28963728064692451092e-01,
    1.33810918536787660377e-02,
];
const LGAM_V: [f64; 6] = [
    1.0,
    2.45597793713041134822e+00,
    2.12848976379893395361e+00,
    7.69285150456672783825e-01,
    1.04222645593369134254e-01,
    3.21709242282423911810e-03,
];
const LGAM_W: [f64; 7] = [
    4.18938533204672725052e-01,
    8.33333333333329678849e-02,
    -2.77777777728775536470e-03,
    7.93650558643019558500e-04,
    -5.95187557450339963135e-04,
    8.36339918996282139126e-04,
    -1.63092934096575273989e-03,
];

/// Gamma function computed by Stirling's formula. The pair of results must be
/// multiplied together to get the actual answer; the multiplication is left to
/// the caller so that it can avoid infinity for 172 <= x <= 180.
fn stirling(x: f64) -> (f64, f64) {
    if x > 200.0 {
        return (inf(1), 1.0);
    }
    const SQRT_TWO_PI: f64 = 2.506628274631000502417;
    const MAX_STIRLING: f64 = 143.01608;
    let mut w = 1.0 / x;
    w = 1.0 + w * ((((GAM_S[0] * w + GAM_S[1]) * w + GAM_S[2]) * w + GAM_S[3]) * w + GAM_S[4]);
    let mut y1 = super::exp(x);
    let mut y2 = 1.0;
    if x > MAX_STIRLING {
        // avoid pow overflow
        let v = super::pow(x, 0.5 * x - 0.25);
        y2 = v / y1;
        y1 = v;
    } else {
        y1 = super::pow(x, x - 0.5) / y1;
    }
    (y1, SQRT_TWO_PI * w * y2)
}

fn is_neg_int(x: f64) -> bool {
    x < 0.0 && x.trunc() == x
}

/// Go's `math.Gamma`: the Gamma function of `x`.
///
/// Special cases: `gamma(+Inf) = +Inf`, `gamma(+0) = +Inf`, `gamma(-0) =
/// -Inf`, `gamma(x) = NaN` for integer `x < 0`, `gamma(-Inf) = NaN`,
/// `gamma(NaN) = NaN`.
pub fn gamma(mut x: f64) -> f64 {
    const EULER: f64 = 0.57721566490153286060651209008240243104215933593992;
    if is_neg_int(x) || is_inf(x, -1) || x.is_nan() {
        return nan();
    }
    if is_inf(x, 1) {
        return inf(1);
    }
    if x == 0.0 {
        return if x.is_sign_negative() {
            inf(-1)
        } else {
            inf(1)
        };
    }
    let mut q = x.abs();
    let mut p = q.floor();
    if q > 33.0 {
        if x >= 0.0 {
            let (y1, y2) = stirling(x);
            return y1 * y2;
        }
        // x is negative but not a negative integer, so it fits an i64.
        let mut signgam = 1;
        if (p as i64) & 1 == 0 {
            signgam = -1;
        }
        let mut z = q - p;
        if z > 0.5 {
            p += 1.0;
            z = q - p;
        }
        z = q * super::sin(PI * z);
        if z == 0.0 {
            return inf(signgam);
        }
        let (sq1, sq2) = stirling(q);
        let absz = z.abs();
        let d = absz * sq1 * sq2;
        if d.is_infinite() {
            z = PI / absz / sq1 / sq2;
        } else {
            z = PI / d;
        }
        return f64::from(signgam) * z;
    }

    // Reduce argument.
    let mut z = 1.0;
    let small = 'reduce: {
        while x >= 3.0 {
            x -= 1.0;
            z *= x;
        }
        while x < 0.0 {
            if x > -1e-09 {
                break 'reduce true;
            }
            z /= x;
            x += 1.0;
        }
        while x < 2.0 {
            if x < 1e-09 {
                break 'reduce true;
            }
            z /= x;
            x += 1.0;
        }
        false
    };
    if small {
        if x == 0.0 {
            return inf(1);
        }
        return z / ((1.0 + EULER * x) * x);
    }
    if x == 2.0 {
        return z;
    }
    x -= 2.0;
    p = (((((x * GAM_P[0] + GAM_P[1]) * x + GAM_P[2]) * x + GAM_P[3]) * x + GAM_P[4]) * x
        + GAM_P[5])
        * x
        + GAM_P[6];
    q = ((((((x * GAM_Q[0] + GAM_Q[1]) * x + GAM_Q[2]) * x + GAM_Q[3]) * x + GAM_Q[4]) * x
        + GAM_Q[5])
        * x
        + GAM_Q[6])
        * x
        + GAM_Q[7];
    z * p / q
}

fn sin_pi(mut x: f64) -> f64 {
    const TWO52: f64 = (1u64 << 52) as f64;
    const TWO53: f64 = (1u64 << 53) as f64;
    if x < 0.25 {
        return -super::sin(PI * x);
    }
    // argument reduction
    let mut z = x.floor();
    let mut n: i64;
    if z != x {
        // inexact
        x %= 2.0;
        n = (x * 4.0) as i64;
    } else if x >= TWO53 {
        // x must be even
        x = 0.0;
        n = 0;
    } else {
        if x < TWO52 {
            z = x + TWO52; // exact
        }
        n = (1 & z.to_bits()) as i64;
        x = n as f64;
        n <<= 2;
    }
    x = match n {
        0 => super::sin(PI * x),
        1 | 2 => super::cos(PI * (0.5 - x)),
        3 | 4 => super::sin(PI * (1.0 - x)),
        5 | 6 => -super::cos(PI * (x - 1.5)),
        _ => super::sin(PI * (x - 2.0)),
    };
    -x
}

/// Go's `math.Lgamma`: the natural logarithm and sign (-1 or +1) of
/// `gamma(x)`.
///
/// Special cases: `lgamma(+Inf) = +Inf`, `lgamma(0) = +Inf`, `lgamma(-integer)
/// = +Inf`, `lgamma(-Inf) = -Inf`, `lgamma(NaN) = NaN`.
pub fn lgamma(mut x: f64) -> (f64, i32) {
    const YMIN: f64 = 1.461632144968362245;
    const TWO52: f64 = (1u64 << 52) as f64;
    const TWO58: f64 = (1u64 << 58) as f64;
    const TINY: f64 = 1.0 / (1u128 << 70) as f64;
    const TC: f64 = 1.46163214496836224576e+00; // 0x3FF762D86356BE3F
    const TF: f64 = -1.21486290535849611461e-01; // 0xBFBF19B9BCC38A42
    const TT: f64 = -3.63867699703950536541e-18; // 0xBC50C7CAA48A971F
    let mut sign = 1;
    if x.is_nan() || x.is_infinite() {
        return (x, sign);
    }
    if x == 0.0 {
        return (inf(1), sign);
    }
    let mut neg = false;
    if x < 0.0 {
        x = -x;
        neg = true;
    }
    if x < TINY {
        // |x| < 2**-70, return -log(|x|)
        if neg {
            sign = -1;
        }
        return (-super::log(x), sign);
    }
    let mut nadj = 0.0;
    if neg {
        if x >= TWO52 {
            // |x| >= 2**52, must be -integer
            return (inf(1), sign);
        }
        let t = sin_pi(x);
        if t == 0.0 {
            return (inf(1), sign); // -integer
        }
        nadj = super::log(PI / (t * x).abs());
        if t < 0.0 {
            sign = -1;
        }
    }

    let mut lgamma;
    if x == 1.0 || x == 2.0 {
        // purge off 1 and 2
        lgamma = 0.0;
    } else if x < 2.0 {
        // use lgamma(x) = lgamma(x+1) - log(x)
        let y;
        let i;
        if x <= 0.9 {
            lgamma = -super::log(x);
            if x >= YMIN - 1.0 + 0.27 {
                // 0.7316 <= x <= 0.9
                y = 1.0 - x;
                i = 0;
            } else if x >= YMIN - 1.0 - 0.27 {
                // 0.2316 <= x < 0.7316
                y = x - (TC - 1.0);
                i = 1;
            } else {
                // 0 < x < 0.2316
                y = x;
                i = 2;
            }
        } else {
            lgamma = 0.0;
            if x >= YMIN + 0.27 {
                // 1.7316 <= x < 2
                y = 2.0 - x;
                i = 0;
            } else if x >= YMIN - 0.27 {
                // 1.2316 <= x < 1.7316
                y = x - TC;
                i = 1;
            } else {
                // 0.9 < x < 1.2316
                y = x - 1.0;
                i = 2;
            }
        }
        match i {
            0 => {
                let z = y * y;
                let p1 = LGAM_A[0]
                    + z * (LGAM_A[2]
                        + z * (LGAM_A[4] + z * (LGAM_A[6] + z * (LGAM_A[8] + z * LGAM_A[10]))));
                let p2 = z
                    * (LGAM_A[1]
                        + z * (LGAM_A[3]
                            + z * (LGAM_A[5]
                                + z * (LGAM_A[7] + z * (LGAM_A[9] + z * LGAM_A[11])))));
                let p = y * p1 + p2;
                lgamma += p - 0.5 * y;
            }
            1 => {
                let z = y * y;
                let w = z * y;
                let p1 = LGAM_T[0]
                    + w * (LGAM_T[3] + w * (LGAM_T[6] + w * (LGAM_T[9] + w * LGAM_T[12])));
                let p2 = LGAM_T[1]
                    + w * (LGAM_T[4] + w * (LGAM_T[7] + w * (LGAM_T[10] + w * LGAM_T[13])));
                let p3 = LGAM_T[2]
                    + w * (LGAM_T[5] + w * (LGAM_T[8] + w * (LGAM_T[11] + w * LGAM_T[14])));
                let p = z * p1 - (TT - w * (p2 + y * p3));
                lgamma += TF + p;
            }
            _ => {
                let p1 = y
                    * (LGAM_U[0]
                        + y * (LGAM_U[1]
                            + y * (LGAM_U[2] + y * (LGAM_U[3] + y * (LGAM_U[4] + y * LGAM_U[5])))));
                let p2 = 1.0
                    + y * (LGAM_V[1]
                        + y * (LGAM_V[2] + y * (LGAM_V[3] + y * (LGAM_V[4] + y * LGAM_V[5]))));
                lgamma += -0.5 * y + p1 / p2;
            }
        }
    } else if x < 8.0 {
        // 2 <= x < 8
        let i = x as i64;
        let y = x - i as f64;
        let p = y
            * (LGAM_S[0]
                + y * (LGAM_S[1]
                    + y * (LGAM_S[2]
                        + y * (LGAM_S[3] + y * (LGAM_S[4] + y * (LGAM_S[5] + y * LGAM_S[6]))))));
        let q = 1.0
            + y * (LGAM_R[1]
                + y * (LGAM_R[2]
                    + y * (LGAM_R[3] + y * (LGAM_R[4] + y * (LGAM_R[5] + y * LGAM_R[6])))));
        lgamma = 0.5 * y + p / q;
        let mut z = 1.0; // lgamma(1+s) = log(s) + lgamma(s)
        if i >= 7 {
            z *= y + 6.0;
        }
        if i >= 6 {
            z *= y + 5.0;
        }
        if i >= 5 {
            z *= y + 4.0;
        }
        if i >= 4 {
            z *= y + 3.0;
        }
        if i >= 3 {
            z *= y + 2.0;
            lgamma += super::log(z);
        }
    } else if x < TWO58 {
        // 8 <= x < 2**58
        let t = super::log(x);
        let z = 1.0 / x;
        let y = z * z;
        let w = LGAM_W[0]
            + z * (LGAM_W[1]
                + y * (LGAM_W[2]
                    + y * (LGAM_W[3] + y * (LGAM_W[4] + y * (LGAM_W[5] + y * LGAM_W[6])))));
        lgamma = (x - 0.5) * (t - 1.0) + w;
    } else {
        // 2**58 <= x <= Inf
        lgamma = x * (super::log(x) - 1.0);
    }
    if neg {
        lgamma = nadj - lgamma;
    }
    (lgamma, sign)
}
