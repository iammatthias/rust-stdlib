//! Sine, cosine and tangent with Go's algorithms (Cephes, with a Payne-Hanek
//! reduction above 2**29), ported from Go's `math/sin.go`, `tan.go`,
//! `sincos.go` and `trig_reduce.go` (see NOTICE). Go's results near multiples
//! of Pi differ from the platform libm's by many ULPs, so these are not mapped
//! to `f64::sin` and friends.
#![allow(clippy::excessive_precision, clippy::approx_constant)]

use super::nan;
use std::f64::consts::PI;

const SIN: [f64; 6] = [
    1.58962301576546568060e-10,
    -2.50507477628578072866e-8,
    2.75573136213857245213e-6,
    -1.98412698295895385996e-4,
    8.33333333332211858878e-3,
    -1.66666666666666307295e-1,
];
const COS: [f64; 6] = [
    -1.13585365213876817300e-11,
    2.08757008419747316778e-9,
    -2.75573141792967388112e-7,
    2.48015872888517045348e-5,
    -1.38888888888730564116e-3,
    4.16666666666665929218e-2,
];
const TAN_P: [f64; 3] = [
    -1.30936939181383777646e4,
    1.15351664838587416140e6,
    -1.79565251976484877988e7,
];
const TAN_Q: [f64; 5] = [
    1.00000000000000000000e0,
    1.36812963470692954678e4,
    -1.32089234440210967447e6,
    2.50083801823357915839e7,
    -5.38695755929454629881e7,
];

const PI4A: f64 = 7.85398125648498535156e-1; // 0x3fe921fb40000000, Pi/4 split into three parts
const PI4B: f64 = 3.77489470793079817668e-8; // 0x3e64442d00000000
const PI4C: f64 = 2.69515142907905952645e-15; // 0x3ce8469898cc5170

/// The largest argument reduced with the three-part Cody-Waite scheme.
const REDUCE_THRESHOLD: f64 = (1u64 << 29) as f64;

/// Bits of 4/pi, 64 per digit.
const M_PI4: [u64; 20] = [
    0x0000000000000001,
    0x45f306dc9c882a53,
    0xf84eafa3ea69bb81,
    0xb6c52b3278872083,
    0xfca2c757bd778ac3,
    0x6e48dc74849ba5c0,
    0x0c925dd413a32439,
    0xfc3bd63962534e7d,
    0xd1046bea5d768909,
    0xd338e04d68befc82,
    0x7323ac7306a673e9,
    0x3908bf177bf25076,
    0x3ff12fffbc0b301f,
    0xde5e2316b414da3e,
    0xda6cfd9e4f96136e,
    0x9e8c7ecd3cbfd45a,
    0xea4f758fd7cbe2f6,
    0x7a0e73ef14a525d4,
    0xd7f6bf623f1aba10,
    0xac06608df8f6d757,
];

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

/// Payne-Hanek reduction: the octant `j` and the remainder `z` in
/// [-Pi/4, Pi/4] of `x` modulo Pi/4.
fn trig_reduce(x: f64) -> (u64, f64) {
    const PI4: f64 = PI / 4.0;
    if x < PI4 {
        return (0, x);
    }
    let mut ix = x.to_bits();
    let exp = ((ix >> 52) & 0x7FF) as i64 - 1023 - 52;
    ix &= !(0x7FFu64 << 52);
    ix |= 1 << 52;
    let digit = ((exp + 61) as u64 / 64) as usize;
    let bitshift = ((exp + 61) as u64 % 64) as u32;
    let back = 64 - bitshift;
    let z0 = shl(M_PI4[digit], bitshift) | shr(M_PI4[digit + 1], back);
    let z1 = shl(M_PI4[digit + 1], bitshift) | shr(M_PI4[digit + 2], back);
    let z2 = shl(M_PI4[digit + 2], bitshift) | shr(M_PI4[digit + 3], back);
    let z2hi = ((u128::from(z2) * u128::from(ix)) >> 64) as u64;
    let z1p = u128::from(z1) * u128::from(ix);
    let (z1hi, z1lo) = ((z1p >> 64) as u64, z1p as u64);
    let z0lo = z0.wrapping_mul(ix);
    let (lo, c) = z1lo.overflowing_add(z2hi);
    let mut hi = z0lo.wrapping_add(z1hi).wrapping_add(u64::from(c));
    let mut j = hi >> 61;
    hi = hi << 3 | lo >> 61;
    let lz = hi.leading_zeros();
    let e = 1023u64.wrapping_sub(u64::from(lz) + 1);
    hi = shl(hi, lz + 1) | shr(lo, 64u32.wrapping_sub(lz + 1));
    hi >>= 64 - 52;
    hi |= e << 52;
    let mut z = f64::from_bits(hi);
    if j & 1 == 1 {
        j += 1;
        j &= 7;
        z -= 1.0;
    }
    (j, z * PI4)
}

/// Reduces `x >= 0` to an octant (modulo 8, even-adjusted) and remainder.
fn reduce(x: f64) -> (u64, f64) {
    if x >= REDUCE_THRESHOLD {
        return trig_reduce(x);
    }
    let mut j = (x * (4.0 / PI)) as u64; // integer part of x/(Pi/4)
    let mut y = j as f64;
    if j & 1 == 1 {
        j += 1;
        y += 1.0;
    }
    j &= 7;
    (j, ((x - y * PI4A) - y * PI4B) - y * PI4C)
}

fn sin_poly(z: f64, zz: f64) -> f64 {
    z + z
        * zz
        * ((((((SIN[0] * zz) + SIN[1]) * zz + SIN[2]) * zz + SIN[3]) * zz + SIN[4]) * zz + SIN[5])
}

fn cos_poly(zz: f64) -> f64 {
    1.0 - 0.5 * zz
        + zz * zz
            * ((((((COS[0] * zz) + COS[1]) * zz + COS[2]) * zz + COS[3]) * zz + COS[4]) * zz
                + COS[5])
}

/// Go's `math.Cos`: the cosine of the radian argument `x`.
///
/// Special cases: `cos(±Inf) = NaN`, `cos(NaN) = NaN`.
pub fn cos(x: f64) -> f64 {
    if x.is_nan() || x.is_infinite() {
        return nan();
    }
    let mut sign = false;
    let (mut j, z) = reduce(x.abs());
    if j > 3 {
        j -= 4;
        sign = !sign;
    }
    if j > 1 {
        sign = !sign;
    }
    let zz = z * z;
    let y = if j == 1 || j == 2 {
        sin_poly(z, zz)
    } else {
        cos_poly(zz)
    };
    if sign {
        -y
    } else {
        y
    }
}

/// Go's `math.Sin`: the sine of the radian argument `x`.
///
/// Special cases: `sin(±0) = ±0`, `sin(±Inf) = NaN`, `sin(NaN) = NaN`.
pub fn sin(mut x: f64) -> f64 {
    if x == 0.0 || x.is_nan() {
        return x;
    }
    if x.is_infinite() {
        return nan();
    }
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    let (mut j, z) = reduce(x);
    if j > 3 {
        sign = !sign;
        j -= 4;
    }
    let zz = z * z;
    let y = if j == 1 || j == 2 {
        cos_poly(zz)
    } else {
        sin_poly(z, zz)
    };
    if sign {
        -y
    } else {
        y
    }
}

/// Go's `math.Sincos`: `sin(x), cos(x)`.
///
/// Special cases: `sincos(±0) = ±0, 1`, `sincos(±Inf) = NaN, NaN`,
/// `sincos(NaN) = NaN, NaN`.
pub fn sincos(mut x: f64) -> (f64, f64) {
    if x == 0.0 {
        return (x, 1.0);
    }
    if x.is_nan() || x.is_infinite() {
        return (nan(), nan());
    }
    let (mut sin_sign, mut cos_sign) = (false, false);
    if x < 0.0 {
        x = -x;
        sin_sign = true;
    }
    let (mut j, z) = reduce(x);
    if j > 3 {
        j -= 4;
        sin_sign = !sin_sign;
        cos_sign = !cos_sign;
    }
    if j > 1 {
        cos_sign = !cos_sign;
    }
    let zz = z * z;
    let mut c = cos_poly(zz);
    let mut s = sin_poly(z, zz);
    if j == 1 || j == 2 {
        std::mem::swap(&mut s, &mut c);
    }
    if cos_sign {
        c = -c;
    }
    if sin_sign {
        s = -s;
    }
    (s, c)
}

/// Go's `math.Tan`: the tangent of the radian argument `x`.
///
/// Special cases: `tan(±0) = ±0`, `tan(±Inf) = NaN`, `tan(NaN) = NaN`.
pub fn tan(mut x: f64) -> f64 {
    if x == 0.0 || x.is_nan() {
        return x;
    }
    if x.is_infinite() {
        return nan();
    }
    let mut sign = false;
    if x < 0.0 {
        x = -x;
        sign = true;
    }
    let (j, z);
    if x >= REDUCE_THRESHOLD {
        (j, z) = trig_reduce(x);
    } else {
        let mut jj = (x * (4.0 / PI)) as u64;
        let mut y = jj as f64;
        // map zeros and singularities to origin
        if jj & 1 == 1 {
            jj += 1;
            y += 1.0;
        }
        j = jj;
        z = ((x - y * PI4A) - y * PI4B) - y * PI4C;
    }
    let zz = z * z;
    let mut y = if zz > 1e-14 {
        z + z
            * (zz * (((TAN_P[0] * zz) + TAN_P[1]) * zz + TAN_P[2])
                / ((((zz + TAN_Q[1]) * zz + TAN_Q[2]) * zz + TAN_Q[3]) * zz + TAN_Q[4]))
    } else {
        z
    };
    if j & 2 == 2 {
        y = -1.0 / y;
    }
    if sign {
        -y
    } else {
        y
    }
}
