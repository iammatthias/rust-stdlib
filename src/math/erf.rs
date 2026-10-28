//! Error function and its inverse, from FreeBSD's `s_erf.c` and the Wichura
//! AS241 rational approximations, as ported by Go's `math/erf.go` and
//! `math/erfinv.go` (see NOTICE).
#![allow(
    non_upper_case_globals,
    clippy::excessive_precision,
    clippy::approx_constant,
    clippy::many_single_char_names
)]

use super::{inf, is_inf, nan};

const ERX: f64 = 8.45062911510467529297e-01;
const EFX: f64 = 1.28379167095512586316e-01;
const EFX8: f64 = 1.02703333676410069053e+00;
const PP0: f64 = 1.28379167095512558561e-01;
const PP1: f64 = -3.25042107247001499370e-01;
const PP2: f64 = -2.84817495755985104766e-02;
const PP3: f64 = -5.77027029648944159157e-03;
const PP4: f64 = -2.37630166566501626084e-05;
const QQ1: f64 = 3.97917223959155352819e-01;
const QQ2: f64 = 6.50222499887672944485e-02;
const QQ3: f64 = 5.08130628187576562776e-03;
const QQ4: f64 = 1.32494738004321644526e-04;
const QQ5: f64 = -3.96022827877536812320e-06;
const PA0: f64 = -2.36211856075265944077e-03;
const PA1: f64 = 4.14856118683748331666e-01;
const PA2: f64 = -3.72207876035701323847e-01;
const PA3: f64 = 3.18346619901161753674e-01;
const PA4: f64 = -1.10894694282396677476e-01;
const PA5: f64 = 3.54783043256182359371e-02;
const PA6: f64 = -2.16637559486879084300e-03;
const QA1: f64 = 1.06420880400844228286e-01;
const QA2: f64 = 5.40397917702171048937e-01;
const QA3: f64 = 7.18286544141962662868e-02;
const QA4: f64 = 1.26171219808761642112e-01;
const QA5: f64 = 1.36370839120290507362e-02;
const QA6: f64 = 1.19844998467991074170e-02;
const RA0: f64 = -9.86494403484714822705e-03;
const RA1: f64 = -6.93858572707181764372e-01;
const RA2: f64 = -1.05586262253232909814e+01;
const RA3: f64 = -6.23753324503260060396e+01;
const RA4: f64 = -1.62396669462573470355e+02;
const RA5: f64 = -1.84605092906711035994e+02;
const RA6: f64 = -8.12874355063065934246e+01;
const RA7: f64 = -9.81432934416914548592e+00;
const SA1: f64 = 1.96512716674392571292e+01;
const SA2: f64 = 1.37657754143519042600e+02;
const SA3: f64 = 4.34565877475229228821e+02;
const SA4: f64 = 6.45387271733267880336e+02;
const SA5: f64 = 4.29008140027567833386e+02;
const SA6: f64 = 1.08635005541779435134e+02;
const SA7: f64 = 6.57024977031928170135e+00;
const SA8: f64 = -6.04244152148580987438e-02;
const RB0: f64 = -9.86494292470009928597e-03;
const RB1: f64 = -7.99283237680523006574e-01;
const RB2: f64 = -1.77579549177547519889e+01;
const RB3: f64 = -1.60636384855821916062e+02;
const RB4: f64 = -6.37566443368389627722e+02;
const RB5: f64 = -1.02509513161107724954e+03;
const RB6: f64 = -4.83519191608651397019e+02;
const SB1: f64 = 3.03380607434824582924e+01;
const SB2: f64 = 3.25792512996573918826e+02;
const SB3: f64 = 1.53672958608443695994e+03;
const SB4: f64 = 3.19985821950859553908e+03;
const SB5: f64 = 2.55305040643316442583e+03;
const SB6: f64 = 4.74528541206955367215e+02;
const SB7: f64 = -2.24409524465858183362e+01;

/// Go's `math.Erf`: the error function of `x`.
///
/// Special cases: `erf(+Inf) = 1`, `erf(-Inf) = -1`, `erf(NaN) = NaN`.
pub fn erf(mut x: f64) -> f64 {
    const VERY_TINY: f64 = 2.848094538889218e-306; // 0x0080000000000000
    const SMALL: f64 = 1.0 / (1u64 << 28) as f64; // 2**-28
    if x.is_nan() {
        return nan();
    }
    if is_inf(x, 1) {
        return 1.0;
    }
    if is_inf(x, -1) {
        return -1.0;
    }
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    if x < 0.84375 {
        let temp;
        if x < SMALL {
            if x < VERY_TINY {
                temp = 0.125 * (8.0 * x + EFX8 * x);
            } else {
                temp = x + EFX * x;
            }
        } else {
            let z = x * x;
            let r = PP0 + z * (PP1 + z * (PP2 + z * (PP3 + z * PP4)));
            let s = 1.0 + z * (QQ1 + z * (QQ2 + z * (QQ3 + z * (QQ4 + z * QQ5))));
            let y = r / s;
            temp = x + x * y;
        }
        return if sign { -temp } else { temp };
    }
    if x < 1.25 {
        let s = x - 1.0;
        let p = PA0 + s * (PA1 + s * (PA2 + s * (PA3 + s * (PA4 + s * (PA5 + s * PA6)))));
        let q = 1.0 + s * (QA1 + s * (QA2 + s * (QA3 + s * (QA4 + s * (QA5 + s * QA6)))));
        return if sign { -ERX - p / q } else { ERX + p / q };
    }
    if x >= 6.0 {
        return if sign { -1.0 } else { 1.0 };
    }
    let s = 1.0 / (x * x);
    let (r, ss) = tail(x, s);
    let z = f64::from_bits(x.to_bits() & 0xffffffff00000000);
    let r = super::exp(-z * z - 0.5625) * super::exp((z - x) * (z + x) + r / ss);
    if sign {
        r / x - 1.0
    } else {
        1.0 - r / x
    }
}

/// The rational approximations of erfc(x) for x in [1.25, 28).
fn tail(x: f64, s: f64) -> (f64, f64) {
    if x < 1.0 / 0.35 {
        (
            RA0 + s * (RA1 + s * (RA2 + s * (RA3 + s * (RA4 + s * (RA5 + s * (RA6 + s * RA7)))))),
            1.0 + s
                * (SA1
                    + s * (SA2
                        + s * (SA3 + s * (SA4 + s * (SA5 + s * (SA6 + s * (SA7 + s * SA8))))))),
        )
    } else {
        (
            RB0 + s * (RB1 + s * (RB2 + s * (RB3 + s * (RB4 + s * (RB5 + s * RB6))))),
            1.0 + s * (SB1 + s * (SB2 + s * (SB3 + s * (SB4 + s * (SB5 + s * (SB6 + s * SB7)))))),
        )
    }
}

/// Go's `math.Erfc`: the complementary error function of `x`.
///
/// Special cases: `erfc(+Inf) = 0`, `erfc(-Inf) = 2`, `erfc(NaN) = NaN`.
pub fn erfc(mut x: f64) -> f64 {
    const TINY: f64 = 1.0 / (1u64 << 56) as f64; // 2**-56
    if x.is_nan() {
        return nan();
    }
    if is_inf(x, 1) {
        return 0.0;
    }
    if is_inf(x, -1) {
        return 2.0;
    }
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    if x < 0.84375 {
        let temp;
        if x < TINY {
            temp = x;
        } else {
            let z = x * x;
            let r = PP0 + z * (PP1 + z * (PP2 + z * (PP3 + z * PP4)));
            let s = 1.0 + z * (QQ1 + z * (QQ2 + z * (QQ3 + z * (QQ4 + z * QQ5))));
            let y = r / s;
            if x < 0.25 {
                temp = x + x * y;
            } else {
                temp = 0.5 + (x * y + (x - 0.5));
            }
        }
        return if sign { 1.0 + temp } else { 1.0 - temp };
    }
    if x < 1.25 {
        let s = x - 1.0;
        let p = PA0 + s * (PA1 + s * (PA2 + s * (PA3 + s * (PA4 + s * (PA5 + s * PA6)))));
        let q = 1.0 + s * (QA1 + s * (QA2 + s * (QA3 + s * (QA4 + s * (QA5 + s * QA6)))));
        return if sign {
            1.0 + ERX + p / q
        } else {
            1.0 - ERX - p / q
        };
    }
    if x < 28.0 {
        if sign && x > 6.0 && x >= 1.0 / 0.35 {
            return 2.0; // x < -6
        }
        let s = 1.0 / (x * x);
        let (r, ss) = tail(x, s);
        let z = f64::from_bits(x.to_bits() & 0xffffffff00000000);
        let r = super::exp(-z * z - 0.5625) * super::exp((z - x) * (z + x) + r / ss);
        return if sign { 2.0 - r / x } else { r / x };
    }
    if sign {
        2.0
    } else {
        0.0
    }
}

mod inverse {
    pub const A0: f64 = 1.1975323115670912564578e0;
    pub const A1: f64 = 4.7072688112383978012285e1;
    pub const A2: f64 = 6.9706266534389598238465e2;
    pub const A3: f64 = 4.8548868893843886794648e3;
    pub const A4: f64 = 1.6235862515167575384252e4;
    pub const A5: f64 = 2.3782041382114385731252e4;
    pub const A6: f64 = 1.1819493347062294404278e4;
    pub const A7: f64 = 8.8709406962545514830200e2;
    pub const B0: f64 = 1.0000000000000000000e0;
    pub const B1: f64 = 4.2313330701600911252e1;
    pub const B2: f64 = 6.8718700749205790830e2;
    pub const B3: f64 = 5.3941960214247511077e3;
    pub const B4: f64 = 2.1213794301586595867e4;
    pub const B5: f64 = 3.9307895800092710610e4;
    pub const B6: f64 = 2.8729085735721942674e4;
    pub const B7: f64 = 5.2264952788528545610e3;
    pub const C0: f64 = 1.42343711074968357734e0;
    pub const C1: f64 = 4.63033784615654529590e0;
    pub const C2: f64 = 5.76949722146069140550e0;
    pub const C3: f64 = 3.64784832476320460504e0;
    pub const C4: f64 = 1.27045825245236838258e0;
    pub const C5: f64 = 2.41780725177450611770e-1;
    pub const C6: f64 = 2.27238449892691845833e-2;
    pub const C7: f64 = 7.74545014278341407640e-4;
    pub const D0: f64 = 1.4142135623730950488016887e0;
    pub const D1: f64 = 2.9036514445419946173133295e0;
    pub const D2: f64 = 2.3707661626024532365971225e0;
    pub const D3: f64 = 9.7547832001787427186894837e-1;
    pub const D4: f64 = 2.0945065210512749128288442e-1;
    pub const D5: f64 = 2.1494160384252876777097297e-2;
    pub const D6: f64 = 7.7441459065157709165577218e-4;
    pub const D7: f64 = 1.4859850019840355905497876e-9;
    pub const E0: f64 = 6.65790464350110377720e0;
    pub const E1: f64 = 5.46378491116411436990e0;
    pub const E2: f64 = 1.78482653991729133580e0;
    pub const E3: f64 = 2.96560571828504891230e-1;
    pub const E4: f64 = 2.65321895265761230930e-2;
    pub const E5: f64 = 1.24266094738807843860e-3;
    pub const E6: f64 = 2.71155556874348757815e-5;
    pub const E7: f64 = 2.01033439929228813265e-7;
    pub const F0: f64 = 1.414213562373095048801689e0;
    pub const F1: f64 = 8.482908416595164588112026e-1;
    pub const F2: f64 = 1.936480946950659106176712e-1;
    pub const F3: f64 = 2.103693768272068968719679e-2;
    pub const F4: f64 = 1.112800997078859844711555e-3;
    pub const F5: f64 = 2.611088405080593625138020e-5;
    pub const F6: f64 = 2.010321207683943062279931e-7;
    pub const F7: f64 = 2.891024605872965461538222e-15;
}

/// Go's `math.Erfinv`: the inverse error function of `x`.
///
/// Special cases: `erfinv(1) = +Inf`, `erfinv(-1) = -Inf`, `erfinv(x) = NaN`
/// if `x < -1` or `x > 1`, `erfinv(NaN) = NaN`.
pub fn erfinv(mut x: f64) -> f64 {
    use inverse::*;
    if x.is_nan() || x <= -1.0 || x >= 1.0 {
        if x == -1.0 || x == 1.0 {
            return inf(x as i32);
        }
        return nan();
    }
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    let ans;
    if x <= 0.85 {
        let r = 0.180625 - 0.25 * x * x;
        let z1 = ((((((A7 * r + A6) * r + A5) * r + A4) * r + A3) * r + A2) * r + A1) * r + A0;
        let z2 = ((((((B7 * r + B6) * r + B5) * r + B4) * r + B3) * r + B2) * r + B1) * r + B0;
        ans = (x * z1) / z2;
    } else {
        let z1;
        let z2;
        let mut r = (std::f64::consts::LN_2 - super::log(1.0 - x)).sqrt();
        if r <= 5.0 {
            r -= 1.6;
            z1 = ((((((C7 * r + C6) * r + C5) * r + C4) * r + C3) * r + C2) * r + C1) * r + C0;
            z2 = ((((((D7 * r + D6) * r + D5) * r + D4) * r + D3) * r + D2) * r + D1) * r + D0;
        } else {
            r -= 5.0;
            z1 = ((((((E7 * r + E6) * r + E5) * r + E4) * r + E3) * r + E2) * r + E1) * r + E0;
            z2 = ((((((F7 * r + F6) * r + F5) * r + F4) * r + F3) * r + F2) * r + F1) * r + F0;
        }
        ans = z1 / z2;
    }
    if sign {
        -ans
    } else {
        ans
    }
}

/// Go's `math.Erfcinv`: the inverse of [`erfc`], `erfinv(1 - x)`.
pub fn erfcinv(x: f64) -> f64 {
    erfinv(1.0 - x)
}
