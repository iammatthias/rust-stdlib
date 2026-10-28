//! Ported from Go's math/all_test.go, bits_test.go and const_test.go: special
//! cases, exact results and representative values.
use rust_stdlib::math;
use std::cmp::Ordering;

const INF: f64 = f64::INFINITY;
const NINF: f64 = f64::NEG_INFINITY;

fn same(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

fn close(a: f64, b: f64, tol: f64) -> bool {
    same(a, b) || (a - b).abs() <= tol * a.abs().max(b.abs())
}

macro_rules! check {
    ($got:expr, $want:expr) => {{
        let (g, w): (f64, f64) = ($got, $want);
        assert!(
            same(g, w),
            "{} = {g:?} ({:#x}), want {w:?} ({:#x})",
            stringify!($got),
            g.to_bits(),
            w.to_bits()
        );
    }};
}

#[test]
fn nan_and_inf() {
    assert_eq!(math::nan().to_bits(), 0x7FF8000000000001);
    assert!(math::nan().is_nan());
    check!(math::inf(1), INF);
    check!(math::inf(0), INF);
    check!(math::inf(-1), NINF);
    assert!(math::is_inf(INF, 1) && math::is_inf(INF, 0) && !math::is_inf(INF, -1));
    assert!(math::is_inf(NINF, -1) && math::is_inf(NINF, 0) && !math::is_inf(NINF, 1));
    assert!(!math::is_inf(f64::MAX, 0) && !math::is_inf(math::nan(), 0));
}

#[test]
fn constants() {
    assert_eq!(math::MAX_FLOAT32, f64::from(f32::MAX));
    assert_eq!(math::SMALLEST_NONZERO_FLOAT32, f64::from(f32::from_bits(1)));
    assert_eq!(math::SMALLEST_NONZERO_FLOAT64, f64::from_bits(1));
    assert_eq!(math::PHI, (1.0 + 5f64.sqrt()) / 2.0);
    assert!(close(math::SQRT_E, std::f64::consts::E.sqrt(), 1e-15));
    assert!(close(math::SQRT_PI, std::f64::consts::PI.sqrt(), 1e-15));
    assert!(close(math::SQRT_PHI, math::PHI.sqrt(), 1e-15));
}

#[test]
fn max_min_dim() {
    check!(math::max(1.0, math::nan()), math::nan());
    check!(math::max(math::nan(), INF), INF);
    check!(math::max(NINF, NINF), NINF);
    check!(math::max(0.0, -0.0), 0.0);
    check!(math::max(-0.0, 0.0), 0.0);
    check!(math::max(-0.0, -0.0), -0.0);
    check!(math::min(0.0, -0.0), -0.0);
    check!(math::min(-0.0, 0.0), -0.0);
    check!(math::min(0.0, 0.0), 0.0);
    check!(math::min(1.0, math::nan()), math::nan());
    check!(math::min(NINF, math::nan()), NINF);
    check!(math::dim(4.0, 1.0), 3.0);
    check!(math::dim(1.0, 4.0), 0.0);
    check!(math::dim(INF, INF), math::nan());
    check!(math::dim(NINF, NINF), math::nan());
    check!(math::dim(INF, 1.0), INF);
    check!(math::dim(math::nan(), 1.0), math::nan());
}

#[test]
fn frexp_ldexp_modf() {
    check!(math::frexp(0.0).0, 0.0);
    check!(math::frexp(-0.0).0, -0.0);
    assert_eq!(math::frexp(8.0), (0.5, 4));
    assert_eq!(math::frexp(-3.0), (-0.75, 2));
    assert_eq!(math::frexp(5e-324), (0.5, -1073));
    assert_eq!(math::frexp(INF), (INF, 0));
    assert!(math::frexp(math::nan()).0.is_nan());
    check!(math::ldexp(0.5, 4), 8.0);
    check!(math::ldexp(1.0, -1074), 5e-324);
    check!(math::ldexp(1.0, -1075), 0.0);
    check!(math::ldexp(-1.0, -1076), -0.0);
    check!(math::ldexp(1.0, 1024), INF);
    check!(math::ldexp(-1.0, 1024), NINF);
    check!(math::ldexp(1.5, -1074), 1e-323); // ties to even
    check!(math::ldexp(-0.0, 7), -0.0);
    check!(math::ldexp(NINF, 7), NINF);
    let (i, f) = math::modf(-3.25);
    check!(i, -3.0);
    check!(f, -0.25);
    let (i, f) = math::modf(INF);
    check!(i, INF);
    assert!(f.is_nan());
    let (i, f) = math::modf(-0.0);
    check!(i, -0.0);
    check!(f, -0.0);
    let (i, f) = math::modf(-5.0);
    check!(i, -5.0);
    check!(f, -0.0);
}

#[test]
fn logb_ilogb() {
    check!(math::logb(8.0), 3.0);
    check!(math::logb(0.0), NINF);
    check!(math::logb(INF), INF);
    check!(math::logb(5e-324), -1074.0);
    assert_eq!(math::ilogb(1.0), 0);
    assert_eq!(math::ilogb(0.0), i64::from(i32::MIN));
    assert_eq!(math::ilogb(INF), i64::from(i32::MAX));
    assert_eq!(math::ilogb(math::nan()), i64::from(i32::MAX));
    assert_eq!(math::ilogb(0.1), -4);
}

#[test]
fn nextafter() {
    check!(math::nextafter(1.0, 2.0), 1.0 + f64::EPSILON);
    check!(math::nextafter(1.0, 0.0), 1.0 - f64::EPSILON / 2.0);
    check!(math::nextafter(0.0, 1.0), 5e-324);
    check!(math::nextafter(0.0, -1.0), -5e-324);
    check!(math::nextafter(-0.0, 1.0), 5e-324);
    check!(math::nextafter(3.0, 3.0), 3.0);
    check!(math::nextafter(f64::MAX, INF), INF);
    check!(math::nextafter(math::nan(), 1.0), math::nan());
    assert_eq!(math::nextafter32(1.0, 2.0), 1.0 + f32::EPSILON);
    assert_eq!(math::nextafter32(0.0, -1.0), -f32::from_bits(1));
    assert!(math::nextafter32(f32::NAN, 1.0).is_nan());
}

#[test]
fn remainder_mod() {
    check!(math::remainder(5.0, 3.0), -1.0);
    check!(math::remainder(-5.0, 3.0), 1.0);
    check!(math::remainder(4.5, 3.0), -1.5);
    check!(math::remainder(7.5, 3.0), 1.5);
    check!(math::remainder(INF, 3.0), math::nan());
    check!(math::remainder(3.0, 0.0), math::nan());
    check!(math::remainder(3.0, INF), 3.0);
    check!(math::remainder(-6.0, 3.0), -0.0);
    check!(math::remainder(f64::MAX, f64::MIN_POSITIVE), 0.0);
    check!(-7.0 % 3.0, -1.0);
    check!(7.0 % NINF, 7.0);
    check!(INF % 3.0, math::nan());
}

#[test]
fn pow_special_cases() {
    let nan = math::nan();
    check!(math::pow(2.0, 0.0), 1.0);
    check!(math::pow(nan, 0.0), 1.0);
    check!(math::pow(1.0, nan), 1.0);
    check!(math::pow(-1.0, INF), 1.0);
    check!(math::pow(-1.0, NINF), 1.0);
    check!(math::pow(0.0, -1.0), INF);
    check!(math::pow(-0.0, -1.0), NINF);
    check!(math::pow(-0.0, -2.0), INF);
    check!(math::pow(-0.0, 3.0), -0.0);
    check!(math::pow(0.0, 2.0), 0.0);
    check!(math::pow(0.5, INF), 0.0);
    check!(math::pow(2.0, NINF), 0.0);
    check!(math::pow(2.0, INF), INF);
    check!(math::pow(0.5, NINF), INF);
    check!(math::pow(INF, -1.0), 0.0);
    check!(math::pow(NINF, 3.0), NINF);
    check!(math::pow(NINF, 2.0), INF);
    check!(math::pow(NINF, -3.0), -0.0);
    check!(math::pow(-8.0, 1.0 / 3.0), nan);
    check!(math::pow(-2.0, 3.0), -8.0);
    check!(math::pow(2.0, 10.0), 1024.0);
    check!(math::pow(2.0, -1074.0), 5e-324);
    assert!(close(math::pow(10.0, 308.0), 1e308, 1e-15));
    check!(math::pow(4.0, 0.5), 2.0);
    check!(math::pow(4.0, -0.5), 0.5);
    check!(math::pow(-1.0, 9007199254740991.0), -1.0);
    check!(math::pow(1.5, 1e300), INF);
}

#[test]
fn pow10_table() {
    check!(math::pow10(0), 1.0);
    check!(math::pow10(3), 1000.0);
    check!(math::pow10(-3), 0.001);
    check!(math::pow10(308), 1e308);
    check!(math::pow10(309), INF);
    check!(math::pow10(-323), 1e-323);
    check!(math::pow10(-324), 0.0);
    check!(math::pow10(i64::MIN), 0.0);
    check!(math::pow10(i64::MAX), INF);
}

#[test]
fn log_family() {
    check!(math::log(0.0), NINF);
    check!(math::log(-1.0), math::nan());
    check!(math::log(INF), INF);
    check!(math::log(1.0), 0.0);
    check!(math::log2(8.0), 3.0);
    check!(math::log2(0.125), -3.0);
    check!(math::log2(f64::from_bits(1)), -1074.0);
    check!(math::log10(100.0), 2.0);
    check!(math::log10(1e-5), -5.0);
    check!(math::log1p(-1.0), NINF);
    check!(math::log1p(-2.0), math::nan());
    check!(math::log1p(-0.0), -0.0);
    check!(math::log1p(1e-20), 1e-20);
    check!(math::expm1(NINF), -1.0);
    check!(math::expm1(1e-20), 1e-20);
    check!(math::exp(NINF), 0.0);
    check!(math::exp(INF), INF);
    check!(math::exp(0.0), 1.0);
    check!(math::exp(710.0), INF);
    check!(math::exp(-746.0), 0.0);
    check!(math::exp2(10.0), 1024.0);
    check!(math::exp2(-1074.0), 5e-324);
    check!(math::exp2(1024.0), INF);
    check!(math::exp2(-1075.0), 0.0);
}

#[test]
fn trig_special_cases() {
    check!(math::sin(0.0), 0.0);
    check!(math::sin(-0.0), -0.0);
    check!(math::sin(INF), math::nan());
    check!(math::cos(NINF), math::nan());
    check!(math::tan(-0.0), -0.0);
    check!(math::tan(INF), math::nan());
    check!(math::cos(0.0), 1.0);
    // Go's reduction is the reason for these values; they differ from libm.
    assert_eq!(math::sin(std::f64::consts::PI), 1.2246467991473515e-16);
    assert_eq!(math::sincos(0.0), (0.0, 1.0));
    let (s, c) = math::sincos(-0.0);
    check!(s, -0.0);
    check!(c, 1.0);
    assert!(math::sincos(INF).0.is_nan() && math::sincos(INF).1.is_nan());
    assert!(close(math::sin(1e22), -0.8522008497671888, 1e-15));
    assert!(close(math::cos(1e22), 0.5232147853951389, 1e-15));
    check!(math::atan(INF), std::f64::consts::FRAC_PI_2);
    check!(math::atan(-0.0), -0.0);
    check!(math::asin(2.0), math::nan());
    check!(math::asin(-0.0), -0.0);
    check!(math::acos(1.0), 0.0);
    check!(math::acos(2.0), math::nan());
    check!(math::atan2(0.0, 0.0), 0.0);
    check!(math::atan2(-0.0, 0.0), -0.0);
    check!(math::atan2(0.0, -0.0), std::f64::consts::PI);
    check!(math::atan2(-0.0, -0.0), -std::f64::consts::PI);
    check!(math::atan2(1.0, INF), 0.0);
    check!(math::atan2(INF, INF), std::f64::consts::FRAC_PI_4);
    check!(math::atan2(INF, NINF), 3.0 * std::f64::consts::FRAC_PI_4);
    check!(math::atan2(1.0, NINF), std::f64::consts::PI);
    check!(math::atan2(-1.0, NINF), -std::f64::consts::PI);
    check!(math::atan2(INF, 1.0), std::f64::consts::FRAC_PI_2);
    // Go's quirk: a tiny negative y over negative x underflows the quotient.
    check!(math::atan2(-5e-324, -2.0), std::f64::consts::PI);
}

#[test]
fn hyperbolic_and_roots() {
    check!(math::sinh(0.0), 0.0);
    check!(math::sinh(NINF), NINF);
    check!(math::cosh(NINF), INF);
    check!(math::cosh(0.0), 1.0);
    check!(math::tanh(INF), 1.0);
    check!(math::tanh(-1000.0), -1.0);
    check!(math::tanh(-0.0), -0.0);
    check!(math::asinh(NINF), NINF);
    check!(math::acosh(0.5), math::nan());
    check!(math::acosh(1.0), 0.0);
    check!(math::atanh(1.0), INF);
    check!(math::atanh(-1.0), NINF);
    check!(math::atanh(2.0), math::nan());
    check!(math::cbrt(27.0), 3.0);
    check!(math::cbrt(-8.0), -2.0);
    check!(math::cbrt(NINF), NINF);
    check!(math::cbrt(-0.0), -0.0);
    check!(math::hypot(3.0, 4.0), 5.0);
    check!(math::hypot(NINF, math::nan()), INF);
    check!(math::hypot(math::nan(), 1.0), math::nan());
    check!(math::hypot(0.0, 0.0), 0.0);
}

#[test]
fn gamma_erf_bessel() {
    check!(math::gamma(5.0), 24.0);
    check!(math::gamma(1.0), 1.0);
    check!(math::gamma(0.0), INF);
    check!(math::gamma(-0.0), NINF);
    check!(math::gamma(-3.0), math::nan());
    check!(math::gamma(NINF), math::nan());
    check!(math::gamma(INF), INF);
    check!(math::gamma(172.0), INF);
    assert!(close(math::gamma(0.5), std::f64::consts::PI.sqrt(), 1e-15));
    assert!(close(
        math::gamma(-0.5),
        -2.0 * std::f64::consts::PI.sqrt(),
        1e-15
    ));
    let (l, s) = math::lgamma(-0.5);
    assert!(close(l, (2.0 * std::f64::consts::PI.sqrt()).ln(), 1e-15));
    assert_eq!(s, -1);
    assert_eq!(math::lgamma(0.0), (INF, 1));
    assert_eq!(math::lgamma(-2.0), (INF, 1));
    assert_eq!(math::lgamma(NINF), (NINF, 1));
    assert_eq!(math::lgamma(1.0), (0.0, 1));
    assert_eq!(math::lgamma(3.0).1, 1);
    assert!(close(math::lgamma(3.0).0, 2f64.ln(), 1e-15));
    check!(math::erf(0.0), 0.0);
    check!(math::erf(INF), 1.0);
    check!(math::erf(NINF), -1.0);
    check!(math::erf(-0.0), -0.0);
    assert!(close(math::erf(0.5), 0.5204998778130465, 1e-15));
    check!(math::erfc(INF), 0.0);
    check!(math::erfc(NINF), 2.0);
    check!(math::erfc(0.0), 1.0);
    assert!(close(math::erfc(1.0), 0.15729920705028513, 1e-14));
    check!(math::erfinv(1.0), INF);
    check!(math::erfinv(-1.0), NINF);
    check!(math::erfinv(1.5), math::nan());
    check!(math::erfinv(0.0), 0.0);
    assert!(close(math::erfinv(0.5), 0.4769362762044699, 1e-14));
    assert!(close(math::erfcinv(0.5), 0.4769362762044699, 1e-14));
    check!(math::erfcinv(0.0), INF);
    check!(math::erfcinv(2.0), NINF);
    check!(math::j0(0.0), 1.0);
    check!(math::j0(INF), 0.0);
    check!(math::j1(0.0), 0.0);
    check!(math::jn(0, 0.0), 1.0);
    check!(math::jn(3, 0.0), 0.0);
    check!(math::y0(0.0), NINF);
    check!(math::y1(-1.0), math::nan());
    check!(math::yn(2, 0.0), NINF);
    check!(math::yn(-3, 0.0), INF);
    check!(math::yn(-2, 0.0), NINF);
    assert!(close(math::j0(1.0), 0.7651976865579666, 1e-14));
    assert!(close(math::j1(1.0), 0.44005058574493355, 1e-14));
    assert!(close(math::y0(1.0), 0.08825696421567697, 1e-13));
    assert!(close(math::y1(1.0), -0.7812128213002887, 1e-14));
    assert!(close(math::jn(2, 1.0), 0.1149034849319005, 1e-14));
    assert!(close(math::yn(2, 1.0), -1.6506826068162548, 1e-13));
    // Jn recurrence relation: J(n-1)+J(n+1) = 2n/x J(n)
    for n in 1..8 {
        let x = 2.5;
        let lhs = math::jn(n - 1, x) + math::jn(n + 1, x);
        let rhs = 2.0 * n as f64 / x * math::jn(n, x);
        assert!(close(lhs, rhs, 1e-12), "n={n}");
    }
    check!(math::jn(-1, 2.0), -math::j1(2.0));
}

#[test]
fn rounding_and_conversions() {
    check!(2.5f64.round(), 3.0);
    check!((-2.5f64).round(), -3.0);
    check!(2.5f64.round_ties_even(), 2.0);
    check!(3.5f64.round_ties_even(), 4.0);
    check!((-0.4f64).round(), -0.0);
    check!(0.49999999999999994f64.round(), 0.0);
    check!((-0.4f64).ceil(), -0.0);
    check!((-0.0f64).trunc(), -0.0);
    check!(math::nan().floor(), math::nan());
    assert_eq!(1.0f32.to_bits(), 0x3f800000);
    assert_eq!(f64::from_bits(0x3ff0000000000000), 1.0);
    check!(1.0f64.copysign(-0.0), -1.0);
    check!(f64::mul_add(2.0, 3.0, 4.0), 10.0);
    assert!((-0.0f64).is_sign_negative());
    assert_eq!(math::MAX_FLOAT32 as f32, f32::MAX);
}

#[test]
fn integer_limits() {
    assert_eq!(isize::MAX, i64::MAX as isize);
    assert_eq!(u8::MAX, 255);
    assert_eq!(i16::MIN, -32768);
    assert_eq!(usize::BITS, 64);
}

#[test]
fn compare_orders_nan_first() {
    // Go's cmp.Compare: NaN is below everything and equal to itself; -0 == +0.
    assert_eq!(math::compare(&f64::NAN, &1.0), Ordering::Less);
    assert_eq!(math::compare(&1.0, &f64::NAN), Ordering::Greater);
    assert_eq!(math::compare(&f64::NAN, &f64::NAN), Ordering::Equal);
    assert_eq!(math::compare(&-0.0, &0.0), Ordering::Equal);
    assert_eq!(
        math::compare(&f64::NEG_INFINITY, &f64::NAN),
        Ordering::Greater
    );
    assert_eq!(math::compare(&f64::INFINITY, &f64::NAN), Ordering::Greater);
    assert_eq!(math::compare(&f64::NAN, &f64::NEG_INFINITY), Ordering::Less);
    assert!(math::compare(&f64::NAN, &1.0).is_lt() && !math::compare(&f64::NAN, &f64::NAN).is_lt());
    assert_eq!(math::compare(&2, &1), Ordering::Greater);
    assert_eq!(math::compare(&"a", &"b"), Ordering::Less);
    let mut v = [3.0, f64::NAN, -1.0, f64::NEG_INFINITY];
    v.sort_by(math::compare);
    assert!(v[0].is_nan());
    assert_eq!(v[1..], [f64::NEG_INFINITY, -1.0, 3.0]);
    // Go's slices.BinarySearch finds the leftmost match, NaN included.
    let a = [f64::NAN, 1.0];
    let i = a.partition_point(|e| math::compare(e, &f64::NAN).is_lt());
    assert_eq!(i, 0);
}

#[test]
fn minimum_maximum_propagate_nan() {
    assert!(math::maximum(1.0, f64::NAN).is_nan());
    assert!(math::minimum(f64::NAN, 3.0).is_nan());
    assert!(math::minimum(f64::NEG_INFINITY, f64::NAN).is_nan());
    assert!(math::minimum(0.0, -0.0).is_sign_negative());
    assert!(!math::maximum(-0.0, 0.0).is_sign_negative());
    assert_eq!(math::minimum(2.0, 1.0), 1.0);
    assert_eq!(math::maximum(2.0, 1.0), 2.0);
}
