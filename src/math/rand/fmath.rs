// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/{log,exp,frexp,ldexp,bits}.go (pure-Go
// implementations, themselves derived from FreeBSD's msun) and
// $GOROOT/src/math/exp_arm64.s.
//
// The ziggurat samplers return `log` results directly, so the platform libm
// is not used. Go's results are architecture-dependent: on arm64 the Go
// compiler fuses `a*b+c` into FMA instructions (and `math.Exp` is assembly
// that uses FMA), while on amd64 Go's arithmetic is unfused, as Rust's is
// unless `mul_add` is written. To be bit-identical to Go on the same
// architecture, aarch64 builds use `*_arm64` variants that place `mul_add`
// exactly where Go 1.27's arm64 code generation emits FMADD/FMSUB/FNMSUB;
// every other target uses the unfused portable algorithm (Go's amd64
// behavior). Go's own fusing on riscv64, ppc64le, s390x and loong64 is not
// mirrored.

use super::tables::{
    EXPMULTI_P1, EXPMULTI_P2, EXPMULTI_P3, EXPMULTI_P4, EXPMULTI_P5, EXP_LN2HI, EXP_LN2LO,
    EXP_LOG2E, EXP_NEARZERO, EXP_OVERFLOW, EXP_UNDERFLOW, LOG_L1, LOG_L2, LOG_L3, LOG_L4, LOG_L5,
    LOG_L6, LOG_L7, LOG_LN2HI, LOG_LN2LO, LOG_SQRT2_HALF,
};

const SHIFT: u32 = 52;
const MASK: u64 = 0x7ff;
const BIAS: i64 = 1023;

/// Go's `normalize`: scale subnormals into the normal range.
fn normalize(x: f64) -> (f64, i64) {
    // 2**-1022, Go's SmallestNormal.
    if x.abs() < f64::MIN_POSITIVE {
        return (x * (1u64 << 52) as f64, -52);
    }
    (x, 0)
}

/// Go's `math.Frexp`.
fn frexp(f: f64) -> (f64, i64) {
    if f == 0.0 || f.is_infinite() || f.is_nan() {
        return (f, 0);
    }
    let (f, mut exp) = normalize(f);
    let mut x = f.to_bits();
    exp += ((x >> SHIFT) & MASK) as i64 - BIAS + 1;
    x &= !(MASK << SHIFT);
    x |= ((-1 + BIAS) as u64) << SHIFT;
    (f64::from_bits(x), exp)
}

/// Go's `math.Ldexp`.
fn ldexp(frac: f64, exp: i64) -> f64 {
    if frac == 0.0 || frac.is_infinite() || frac.is_nan() {
        return frac;
    }
    let (frac, e) = normalize(frac);
    let mut exp = exp + e;
    let mut x = frac.to_bits();
    exp += ((x >> SHIFT) & MASK) as i64 - BIAS;
    if exp < -1075 {
        return 0.0f64.copysign(frac);
    }
    if exp > 1023 {
        return if frac < 0.0 {
            f64::NEG_INFINITY
        } else {
            f64::INFINITY
        };
    }
    let mut m = 1.0;
    if exp < -1022 {
        exp += 53;
        m = 1.0 / (1u64 << 53) as f64;
    }
    x &= !(MASK << SHIFT);
    x |= ((exp + BIAS) as u64) << SHIFT;
    m * f64::from_bits(x)
}

/// Whether to reproduce Go's arm64 (fused multiply-add) arithmetic.
pub(crate) const FUSED_MULTIPLY_ADD: bool = cfg!(target_arch = "aarch64");

/// Go's `math.Log` as computed on this architecture.
pub(crate) fn log(x: f64) -> f64 {
    if FUSED_MULTIPLY_ADD {
        log_arm64(x)
    } else {
        log_portable(x)
    }
}

/// Go's `math.Exp` as computed on this architecture.
pub(crate) fn exp(x: f64) -> f64 {
    if FUSED_MULTIPLY_ADD {
        exp_arm64(x)
    } else {
        exp_portable(x)
    }
}

/// Go's `math.Log` reduction: `(f, k)` with `x = (1+f) * 2^k` and `1+f` in
/// `[sqrt(2)/2, sqrt(2))`, or the special-case result.
fn log_reduce(x: f64) -> Result<(f64, f64), f64> {
    if x.is_nan() || x == f64::INFINITY {
        return Err(x);
    }
    if x < 0.0 {
        return Err(f64::NAN);
    }
    if x == 0.0 {
        return Err(f64::NEG_INFINITY);
    }
    let (mut f1, mut ki) = frexp(x);
    if f1 < LOG_SQRT2_HALF {
        f1 *= 2.0;
        ki -= 1;
    }
    Ok((f1 - 1.0, ki as f64))
}

/// Go's pure-Go `math.Log` as compiled for arm64. Each `mul_add` matches one
/// FMADDD/FNMSUBD in the Go 1.27 disassembly of `math.log`; `hfsq` is never
/// rounded on its own because Go fuses both of its uses.
fn log_arm64(x: f64) -> f64 {
    let (f, k) = match log_reduce(x) {
        Ok(reduced) => reduced,
        Err(special) => return special,
    };
    let s = f / (2.0 + f);
    let s2 = s * s;
    let s4 = s2 * s2;
    let p1 = s4.mul_add(s4.mul_add(s4.mul_add(LOG_L7, LOG_L5), LOG_L3), LOG_L1);
    let t2 = s4.mul_add(s4.mul_add(LOG_L6, LOG_L4), LOG_L2) * s4;
    let r = s2.mul_add(p1, t2); // t1 + t2
    let half_f = 0.5 * f;
    let inner = s.mul_add(half_f.mul_add(f, r), k * LOG_LN2LO); // s*(hfsq+R) + k*Ln2Lo
    let d = half_f.mul_add(f, -inner) - f; // (hfsq - inner) - f
    k.mul_add(LOG_LN2HI, -d)
}

/// Go's portable `math.Log` (unfused, as compiled for amd64).
fn log_portable(x: f64) -> f64 {
    let (f, k) = match log_reduce(x) {
        Ok(reduced) => reduced,
        Err(special) => return special,
    };
    let s = f / (2.0 + f);
    let s2 = s * s;
    let s4 = s2 * s2;
    let t1 = s2 * (LOG_L1 + s4 * (LOG_L3 + s4 * (LOG_L5 + s4 * LOG_L7)));
    let t2 = s4 * (LOG_L2 + s4 * (LOG_L4 + s4 * LOG_L6));
    let r = t1 + t2;
    let hfsq = 0.5 * f * f;
    k * LOG_LN2HI - ((hfsq - (s * (hfsq + r) + k * LOG_LN2LO)) - f)
}

/// Go's `exp_arm64.s` (`archExp`), which arm64 uses instead of the pure-Go
/// `exp`: fused argument reduction and polynomial, and an inlined `Ldexp`.
fn exp_arm64(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x > EXP_OVERFLOW {
        return f64::INFINITY;
    }
    if x < EXP_UNDERFLOW {
        return 0.0;
    }
    if x.abs() < EXP_NEARZERO {
        return 1.0 + x;
    }
    let k = if x < 0.0 {
        EXP_LOG2E.mul_add(x, -0.5)
    } else {
        EXP_LOG2E.mul_add(x, 0.5)
    } as i64;
    let kf = k as f64;
    let hi = (-kf).mul_add(EXP_LN2HI, x);
    let lo = kf * EXP_LN2LO;
    let r = hi - lo;
    let t = r * r;
    let poly = t.mul_add(EXPMULTI_P5, EXPMULTI_P4);
    let poly = t.mul_add(poly, EXPMULTI_P3);
    let poly = t.mul_add(poly, EXPMULTI_P2);
    let poly = t.mul_add(poly, EXPMULTI_P1);
    let c = (-t).mul_add(poly, r);
    let y = 1.0 - ((lo - (r * c) / (2.0 - c)) - hi);
    // Inlined Ldexp(y, k) without the generic special cases.
    let bits = y.to_bits();
    let mut exponent = (bits >> 52) as i64 + k;
    let mut m = 1.0;
    if exponent < 1 {
        exponent += 52;
        m = f64::from_bits(0x3cb0000000000000); // 2**-52
    }
    m * f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | ((exponent as u64) << 52))
}

/// Go's portable `math.Exp`.
fn exp_portable(x: f64) -> f64 {
    if x.is_nan() {
        return x;
    }
    if x > EXP_OVERFLOW {
        return f64::INFINITY;
    }
    if x < EXP_UNDERFLOW {
        return 0.0;
    }
    if -EXP_NEARZERO < x && x < EXP_NEARZERO {
        return 1.0 + x;
    }
    let k = if x < 0.0 {
        (EXP_LOG2E * x - 0.5) as i64
    } else if x > 0.0 {
        (EXP_LOG2E * x + 0.5) as i64
    } else {
        0
    };
    let hi = x - k as f64 * EXP_LN2HI;
    let lo = k as f64 * EXP_LN2LO;
    expmulti(hi, lo, k)
}

fn expmulti(hi: f64, lo: f64, k: i64) -> f64 {
    let r = hi - lo;
    let t = r * r;
    let c = r - t
        * (EXPMULTI_P1
            + t * (EXPMULTI_P2 + t * (EXPMULTI_P3 + t * (EXPMULTI_P4 + t * EXPMULTI_P5))));
    let y = 1.0 - ((lo - (r * c) / (2.0 - c)) - hi);
    ldexp(y, k)
}
