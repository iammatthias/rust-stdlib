//! Ported from Go's math/cmplx tests: values, special cases and branch cuts.
use rust_stdlib::math::cmplx;
use rust_stdlib::strconv::Complex;
use std::f64::consts::{FRAC_PI_2, FRAC_PI_4, PI};

const INF: f64 = f64::INFINITY;

fn c(re: f64, im: f64) -> Complex {
    Complex::new(re, im)
}

fn near(a: Complex, b: Complex) {
    let ok = |x: f64, y: f64| (x - y).abs() <= 1e-14 * (1.0 + x.abs().max(y.abs()));
    assert!(ok(a.re, b.re) && ok(a.im, b.im), "{a:?} != {b:?}");
}

fn same(a: f64, b: f64) -> bool {
    (a.is_nan() && b.is_nan()) || a.to_bits() == b.to_bits()
}

fn exact(a: Complex, re: f64, im: f64) {
    assert!(
        same(a.re, re) && same(a.im, im),
        "{a:?} != ({re:?}, {im:?})"
    );
}

#[test]
fn arithmetic_matches_go() {
    near(c(1.0, 2.0) * c(3.0, 4.0), c(-5.0, 10.0));
    near(c(1.0, 2.0) / c(3.0, 4.0), c(0.44, 0.08));
    exact(c(1.0, 1.0) / c(0.0, 0.0), INF, INF);
    exact(c(1.0, 0.0) / c(INF, 0.0), 0.0, 0.0);
    exact(c(INF, 0.0) / c(1.0, 1.0), INF, -INF);
    assert!((c(f64::NAN, 0.0) / c(1.0, 0.0)).re.is_nan());
    exact(-c(1.0, -0.0), -1.0, 0.0);
}

#[test]
fn basic_functions() {
    assert_eq!(cmplx::abs(c(3.0, 4.0)), 5.0);
    assert_eq!(cmplx::phase(c(-1.0, 0.0)), PI);
    assert_eq!(cmplx::phase(c(-1.0, -0.0)), -PI);
    let (r, t) = cmplx::polar(c(0.0, 2.0));
    assert_eq!((r, t), (2.0, FRAC_PI_2));
    near(cmplx::rect(2.0, FRAC_PI_2), c(0.0, 2.0));
    exact(cmplx::conj(c(1.0, 2.0)), 1.0, -2.0);
    assert!(cmplx::is_inf(c(INF, f64::NAN)));
    assert!(!cmplx::is_nan(c(INF, f64::NAN)));
    assert!(cmplx::is_nan(c(f64::NAN, 1.0)));
    assert!(!cmplx::is_nan(c(1.0, 1.0)));
    exact(cmplx::inf(), INF, INF);
    assert!(cmplx::nan().re.is_nan() && cmplx::nan().im.is_nan());
}

#[test]
fn sqrt_branch_cut() {
    exact(cmplx::sqrt(c(-4.0, 0.0)), 0.0, 2.0);
    exact(cmplx::sqrt(c(-4.0, -0.0)), 0.0, -2.0);
    exact(cmplx::sqrt(c(0.0, 0.0)), 0.0, 0.0);
    exact(cmplx::sqrt(c(0.0, -0.0)), 0.0, -0.0);
    exact(cmplx::sqrt(c(4.0, 0.0)), 2.0, 0.0);
    exact(cmplx::sqrt(c(1.0, INF)), INF, INF);
    near(cmplx::sqrt(c(3.0, 4.0)), c(2.0, 1.0));
    near(cmplx::sqrt(c(3.0, -4.0)), c(2.0, -1.0));
    near(cmplx::sqrt(c(0.0, 2.0)), c(1.0, 1.0));
    near(cmplx::sqrt(c(0.0, -2.0)), c(1.0, -1.0));
    near(cmplx::sqrt(c(-3.0, 4.0)), c(1.0, 2.0));
}

#[test]
fn exp_log_pow() {
    near(cmplx::exp(c(0.0, PI)), c(-1.0, 1.2246467991473532e-16));
    exact(cmplx::exp(c(INF, 0.0)), INF, 0.0);
    exact(cmplx::exp(c(-INF, INF)), 0.0, 0.0);
    exact(cmplx::exp(c(-INF, f64::NAN)), 0.0, 0.0);
    let e = cmplx::exp(c(INF, INF));
    assert!(e.re == INF && e.im.is_nan());
    near(cmplx::log(c(0.0, 1.0)), c(0.0, FRAC_PI_2));
    near(cmplx::log(c(-1.0, 0.0)), c(0.0, PI));
    exact(cmplx::log(c(0.0, 0.0)), -INF, 0.0);
    near(cmplx::log10(c(100.0, 0.0)), c(2.0, 0.0));
    exact(cmplx::pow(c(0.0, 0.0), c(0.0, 0.0)), 1.0, 0.0);
    exact(cmplx::pow(c(0.0, 0.0), c(-1.0, 0.0)), INF, 0.0);
    exact(cmplx::pow(c(0.0, 0.0), c(-1.0, 1.0)), INF, INF);
    exact(cmplx::pow(c(-0.0, 0.0), c(2.0, 1.0)), 0.0, 0.0);
    assert!(cmplx::pow(c(0.0, 0.0), c(f64::NAN, 0.0)).re.is_nan());
    near(cmplx::pow(c(0.0, 1.0), c(2.0, 0.0)), c(-1.0, 0.0));
    near(cmplx::pow(c(2.0, 0.0), c(10.0, 0.0)), c(1024.0, 0.0));
    near(cmplx::pow(c(1.0, 1.0), c(2.0, 0.0)), c(0.0, 2.0));
}

#[test]
fn trigonometric() {
    near(cmplx::sin(c(0.0, 1.0)), c(0.0, 1.1752011936438014));
    near(cmplx::cos(c(0.0, 1.0)), c(1.5430806348152437, -0.0));
    near(cmplx::tan(c(0.0, 1.0)), c(0.0, 0.7615941559557649));
    near(
        cmplx::sin(c(1.0, 2.0)),
        c(3.165778513216168, 1.959601041421606),
    );
    near(
        cmplx::cos(c(1.0, 2.0)),
        c(2.0327230070196656, -3.0518977991518),
    );
    near(
        cmplx::sinh(c(1.0, 2.0)),
        c(-0.4890562590412937, 1.4031192506220405),
    );
    near(
        cmplx::cosh(c(1.0, 2.0)),
        c(-0.64214812471552, 1.0686074213827783),
    );
    near(
        cmplx::tanh(c(1.0, 2.0)),
        c(1.16673625724092, -0.24345820118572523),
    );
    near(
        cmplx::cot(c(1.0, 2.0)),
        c(0.03279775553375259, -0.984329226458191),
    );
    exact(cmplx::sin(c(0.0, INF)), 0.0, INF);
    exact(cmplx::tan(c(1.0, INF)), 0.0f64.copysign(2.0f64.sin()), 1.0);
    exact(cmplx::tanh(c(INF, 1.0)), 1.0, 0.0f64.copysign(2.0f64.sin()));
    assert!(cmplx::sin(c(INF, 0.0)).re.is_nan());
    exact(cmplx::cosh(c(INF, 0.0)), INF, 0.0);
    exact(cmplx::cos(c(0.0, INF)), INF, -0.0);
}

#[test]
fn inverse_branch_cuts() {
    // Asin and Acos: cuts on the real axis outside [-1, 1].
    near(cmplx::asin(c(2.0, 0.0)), c(FRAC_PI_2, 1.3169578969248166));
    near(cmplx::asin(c(2.0, -0.0)), c(FRAC_PI_2, -1.3169578969248166));
    near(cmplx::asin(c(-2.0, 0.0)), c(-FRAC_PI_2, 1.3169578969248166));
    near(cmplx::acos(c(2.0, 0.0)), c(0.0, -1.3169578969248166));
    near(cmplx::acos(c(2.0, -0.0)), c(0.0, 1.3169578969248166));
    near(
        cmplx::asin(c(0.5, 0.0)),
        c(std::f64::consts::FRAC_PI_6, 0.0),
    );
    // Atan: cuts on the imaginary axis outside [-i, i].
    // Go's Pi-reduction maps both zeros to -Pi/2.
    near(cmplx::atan(c(0.0, 2.0)), c(-FRAC_PI_2, 0.5493061443340549));
    near(cmplx::atan(c(-0.0, 2.0)), c(-FRAC_PI_2, 0.5493061443340549));
    near(cmplx::atan(c(1.0, 0.0)), c(FRAC_PI_4, 0.0));
    // Acosh: cut on the real axis below 1.
    let (above, below) = (cmplx::acosh(c(0.5, 0.0)), cmplx::acosh(c(0.5, -0.0)));
    assert!(above.re == 0.0 && below.re == 0.0);
    assert!((above.im.abs() - PI / 3.0).abs() < 1e-14 && (below.im.abs() - PI / 3.0).abs() < 1e-14);
    exact(cmplx::acosh(c(0.0, 0.0)), 0.0, FRAC_PI_2);
    exact(cmplx::acosh(c(0.0, -0.0)), 0.0, -FRAC_PI_2);
    // Asinh: cut on the imaginary axis outside [-i, i].
    near(cmplx::asinh(c(0.0, 2.0)), c(1.3169578969248166, FRAC_PI_2));
    near(
        cmplx::asinh(c(-0.0, 2.0)),
        c(-1.3169578969248166, FRAC_PI_2),
    );
    // Atanh: cut on the real axis outside [-1, 1].
    near(cmplx::atanh(c(2.0, 0.0)), c(0.5493061443340549, FRAC_PI_2));
    let below = cmplx::atanh(c(2.0, -0.0));
    assert!(
        (below.re - 0.5493061443340549).abs() < 1e-14 && (below.im.abs() - FRAC_PI_2).abs() < 1e-14
    );
    exact(cmplx::asin(c(INF, 0.0)), FRAC_PI_2, INF);
    exact(cmplx::asin(c(0.0, f64::NAN)), 0.0, f64::NAN);
}

#[test]
fn large_arguments() {
    // Payne-Hanek reduction in Tan's series fallback and Atan.
    let t = cmplx::tan(c(1e10, 1e-3));
    assert!(t.re.is_finite() && t.im.is_finite());
    let a = cmplx::atan(c(1e300, 1e-300));
    assert!(a.re.is_finite());
    near(cmplx::tan(c(FRAC_PI_4, 0.0)), c(1.0, 0.0));
}
