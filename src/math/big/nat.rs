// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Unsigned magnitudes, after $GOROOT/src/math/big/{arith,nat,natmul,natdiv}.go.

//! Natural numbers as little-endian `u64` limbs.
//!
//! A magnitude is normalized when its most significant limb is non-zero; zero
//! is the empty vector. Every function here takes normalized inputs and returns
//! a normalized result unless documented otherwise. Products and quotients use
//! `u128` intermediates.
//!
//! Complexity: multiplication is schoolbook below [`KARATSUBA_THRESHOLD`] limbs
//! and Karatsuba (O(n^1.585)) above it. Division is Knuth's Algorithm D,
//! O(m·n) limb operations for an (m+n)-limb dividend and n-limb divisor; a
//! 100,000-digit by 50,000-digit division is roughly 7 million limb steps.

use std::cmp::Ordering;

pub(super) type Nat = Vec<u64>;

/// Operand length (in limbs) from which multiplication uses Karatsuba.
pub(super) const KARATSUBA_THRESHOLD: usize = 40;

pub(super) fn norm(z: &mut Nat) {
    while z.last() == Some(&0) {
        z.pop();
    }
}

pub(super) fn normalized(mut z: Nat) -> Nat {
    norm(&mut z);
    z
}

pub(super) fn from_u64(x: u64) -> Nat {
    if x == 0 {
        Vec::new()
    } else {
        vec![x]
    }
}

pub(super) fn low64(x: &[u64]) -> u64 {
    x.first().copied().unwrap_or(0)
}

pub(super) fn is_one(x: &[u64]) -> bool {
    x.len() == 1 && x[0] == 1
}

pub(super) fn cmp(x: &[u64], y: &[u64]) -> Ordering {
    if x.len() != y.len() {
        return x.len().cmp(&y.len());
    }
    for i in (0..x.len()).rev() {
        if x[i] != y[i] {
            return x[i].cmp(&y[i]);
        }
    }
    Ordering::Equal
}

/// z += x (at limb offset 0); z must be long enough to absorb the carry
/// unless the carry is returned.
fn add_into(z: &mut [u64], x: &[u64]) -> u64 {
    let mut carry = 0u64;
    for (i, &xi) in x.iter().enumerate() {
        let (s1, c1) = z[i].overflowing_add(xi);
        let (s2, c2) = s1.overflowing_add(carry);
        z[i] = s2;
        carry = u64::from(c1) + u64::from(c2);
    }
    let mut i = x.len();
    while carry != 0 && i < z.len() {
        let (s, c) = z[i].overflowing_add(carry);
        z[i] = s;
        carry = u64::from(c);
        i += 1;
    }
    carry
}

/// z -= x; returns the borrow out of z.
fn sub_into(z: &mut [u64], x: &[u64]) -> u64 {
    let mut borrow = 0u64;
    for (i, &xi) in x.iter().enumerate() {
        let (d1, b1) = z[i].overflowing_sub(xi);
        let (d2, b2) = d1.overflowing_sub(borrow);
        z[i] = d2;
        borrow = u64::from(b1) + u64::from(b2);
    }
    let mut i = x.len();
    while borrow != 0 && i < z.len() {
        let (d, b) = z[i].overflowing_sub(borrow);
        z[i] = d;
        borrow = u64::from(b);
        i += 1;
    }
    borrow
}

pub(super) fn add(x: &[u64], y: &[u64]) -> Nat {
    let (long, short) = if x.len() >= y.len() { (x, y) } else { (y, x) };
    let mut z = Vec::with_capacity(long.len() + 1);
    z.extend_from_slice(long);
    z.push(0);
    add_into(&mut z, short);
    normalized(z)
}

/// x - y; panics if x < y, like Go's nat.sub.
pub(super) fn sub(x: &[u64], y: &[u64]) -> Nat {
    assert!(cmp(x, y) != Ordering::Less, "underflow");
    let mut z = x.to_vec();
    sub_into(&mut z, y);
    normalized(z)
}

pub(super) fn add_w(x: &[u64], y: u64) -> Nat {
    add(x, &from_u64(y))
}

pub(super) fn sub_w(x: &[u64], y: u64) -> Nat {
    sub(x, &from_u64(y))
}

/// x·y + r.
pub(super) fn mul_add_ww(x: &[u64], y: u64, r: u64) -> Nat {
    let mut z = Vec::with_capacity(x.len() + 1);
    let mut carry = r;
    for &xi in x {
        let t = u128::from(xi) * u128::from(y) + u128::from(carry);
        z.push(t as u64);
        carry = (t >> 64) as u64;
    }
    z.push(carry);
    normalized(z)
}

/// z[i..] += x·y; returns the carry limb.
fn add_mul_vw(z: &mut [u64], x: &[u64], y: u64) -> u64 {
    let mut carry = 0u64;
    for (i, &xi) in x.iter().enumerate() {
        let t = u128::from(xi) * u128::from(y) + u128::from(z[i]) + u128::from(carry);
        z[i] = t as u64;
        carry = (t >> 64) as u64;
    }
    carry
}

fn basic_mul(x: &[u64], y: &[u64]) -> Nat {
    let mut z = vec![0u64; x.len() + y.len()];
    for (i, &yi) in y.iter().enumerate() {
        if yi != 0 {
            let c = add_mul_vw(&mut z[i..i + x.len()], x, yi);
            z[i + x.len()] = c;
        }
    }
    z
}

/// Unnormalized product of two slices (may have high zero limbs).
fn mul_slices(x: &[u64], y: &[u64]) -> Nat {
    let (x, y) = if x.len() >= y.len() { (x, y) } else { (y, x) };
    if y.is_empty() {
        return Vec::new();
    }
    if y.len() < KARATSUBA_THRESHOLD {
        return basic_mul(x, y);
    }
    if x.len() >= 2 * y.len() {
        // Unbalanced: multiply y by y-sized chunks of x.
        let mut z = vec![0u64; x.len() + y.len()];
        let mut i = 0;
        while i < x.len() {
            let end = (i + y.len()).min(x.len());
            let p = mul_slices(&x[i..end], y);
            add_into(&mut z[i..], trim(&p));
            i = end;
        }
        return z;
    }
    karatsuba(x, y)
}

/// Karatsuba product for x.len() >= y.len() > x.len()/2.
fn karatsuba(x: &[u64], y: &[u64]) -> Nat {
    let k = x.len() / 2;
    let (x0, x1) = x.split_at(k);
    let (y0, y1) = y.split_at(k.min(y.len()));
    let z0 = mul_slices(x0, y0);
    let z2 = mul_slices(x1, y1);
    let xs = add(trim(x0), trim(x1));
    let ys = add(trim(y0), trim(y1));
    let mut z1 = mul_slices(&xs, &ys);
    sub_into(&mut z1, trim(&z0));
    sub_into(&mut z1, trim(&z2));
    let mut z = vec![0u64; x.len() + y.len() + 1];
    add_into(&mut z, trim(&z0));
    add_into(&mut z[2 * k..], trim(&z2));
    add_into(&mut z[k..], trim(&z1));
    z
}

fn trim(x: &[u64]) -> &[u64] {
    let mut n = x.len();
    while n > 0 && x[n - 1] == 0 {
        n -= 1;
    }
    &x[..n]
}

pub(super) fn mul(x: &[u64], y: &[u64]) -> Nat {
    if x.is_empty() || y.is_empty() {
        return Vec::new();
    }
    if x.len() == 1 {
        return mul_add_ww(y, x[0], 0);
    }
    if y.len() == 1 {
        return mul_add_ww(x, y[0], 0);
    }
    normalized(mul_slices(x, y))
}

pub(super) fn sqr(x: &[u64]) -> Nat {
    mul(x, x)
}

/// (x / y, x mod y) for a single-limb divisor; panics on y == 0.
pub(super) fn div_w(x: &[u64], y: u64) -> (Nat, u64) {
    assert!(y != 0, "division by zero");
    let mut q = vec![0u64; x.len()];
    let mut r = 0u64;
    let d = u128::from(y);
    for i in (0..x.len()).rev() {
        let t = (u128::from(r) << 64) | u128::from(x[i]);
        q[i] = (t / d) as u64;
        r = (t % d) as u64;
    }
    (normalized(q), r)
}

pub(super) fn mod_w(x: &[u64], y: u64) -> u64 {
    let mut r = 0u64;
    let d = u128::from(y);
    for i in (0..x.len()).rev() {
        let t = (u128::from(r) << 64) | u128::from(x[i]);
        r = (t % d) as u64;
    }
    r
}

/// (u / v, u mod v); panics with "division by zero" when v == 0.
pub(super) fn div(u: &[u64], v: &[u64]) -> (Nat, Nat) {
    assert!(!v.is_empty(), "division by zero");
    if cmp(u, v) == Ordering::Less {
        return (Vec::new(), u.to_vec());
    }
    if v.len() == 1 {
        let (q, r) = div_w(u, v[0]);
        return (q, from_u64(r));
    }
    knuth_div(u, v)
}

pub(super) fn rem(u: &[u64], v: &[u64]) -> Nat {
    div(u, v).1
}

/// Knuth, TAOCP vol. 2, 4.3.1, Algorithm D, for v.len() >= 2 and u >= v.
fn knuth_div(u: &[u64], v: &[u64]) -> (Nat, Nat) {
    let n = v.len();
    let m = u.len() - n;
    let s = v[n - 1].leading_zeros();
    let vn = shl_slice(v, s, false);
    let mut un = shl_slice(u, s, true);
    let mut q = vec![0u64; m + 1];
    let vtop = u128::from(vn[n - 1]);
    let vnext = u128::from(vn[n - 2]);
    for j in (0..=m).rev() {
        let num = (u128::from(un[j + n]) << 64) | u128::from(un[j + n - 1]);
        let mut qhat = num / vtop;
        let mut rhat = num % vtop;
        while qhat > u128::from(u64::MAX)
            || qhat * vnext > ((rhat << 64) | u128::from(un[j + n - 2]))
        {
            qhat -= 1;
            rhat += vtop;
            if rhat > u128::from(u64::MAX) {
                break;
            }
        }
        // Multiply and subtract qhat·vn from un[j..j+n+1].
        let qh = qhat as u64;
        let mut borrow = 0u64;
        let mut carry = 0u64;
        for i in 0..n {
            let p = u128::from(qh) * u128::from(vn[i]) + u128::from(carry);
            carry = (p >> 64) as u64;
            let (d1, b1) = un[i + j].overflowing_sub(p as u64);
            let (d2, b2) = d1.overflowing_sub(borrow);
            un[i + j] = d2;
            borrow = u64::from(b1) + u64::from(b2);
        }
        let (d1, b1) = un[j + n].overflowing_sub(carry);
        let (d2, b2) = d1.overflowing_sub(borrow);
        un[j + n] = d2;
        if b1 || b2 {
            // qhat was one too large: add vn back.
            q[j] = qh.wrapping_sub(1);
            let c = add_into(&mut un[j..j + n], &vn);
            un[j + n] = un[j + n].wrapping_add(c);
        } else {
            q[j] = qh;
        }
    }
    un.truncate(n);
    let r = shr_slice(&un, s);
    (normalized(q), normalized(r))
}

/// x << s for s < 64; with `extend`, one extra limb is always appended.
fn shl_slice(x: &[u64], s: u32, extend: bool) -> Nat {
    let mut z = Vec::with_capacity(x.len() + 1);
    if s == 0 {
        z.extend_from_slice(x);
        if extend {
            z.push(0);
        }
        return z;
    }
    let mut carry = 0u64;
    for &xi in x {
        z.push((xi << s) | carry);
        carry = xi >> (64 - s);
    }
    if extend {
        z.push(carry);
    }
    z
}

/// x >> s for s < 64, unnormalized.
fn shr_slice(x: &[u64], s: u32) -> Nat {
    if s == 0 {
        return x.to_vec();
    }
    let mut z = vec![0u64; x.len()];
    for i in 0..x.len() {
        let hi = if i + 1 < x.len() {
            x[i + 1] << (64 - s)
        } else {
            0
        };
        z[i] = (x[i] >> s) | hi;
    }
    z
}

pub(super) fn shl(x: &[u64], s: usize) -> Nat {
    if x.is_empty() {
        return Vec::new();
    }
    let words = s / 64;
    let bits = (s % 64) as u32;
    let mut z = vec![0u64; words];
    z.extend(shl_slice(x, bits, true));
    normalized(z)
}

pub(super) fn shr(x: &[u64], s: usize) -> Nat {
    let words = s / 64;
    if words >= x.len() {
        return Vec::new();
    }
    normalized(shr_slice(&x[words..], (s % 64) as u32))
}

pub(super) fn bit_len(x: &[u64]) -> usize {
    match x.last() {
        Some(&top) => (x.len() - 1) * 64 + (64 - top.leading_zeros() as usize),
        None => 0,
    }
}

pub(super) fn trailing_zero_bits(x: &[u64]) -> usize {
    for (i, &w) in x.iter().enumerate() {
        if w != 0 {
            return i * 64 + w.trailing_zeros() as usize;
        }
    }
    0
}

pub(super) fn bit(x: &[u64], i: usize) -> u32 {
    let j = i / 64;
    if j >= x.len() {
        return 0;
    }
    ((x[j] >> (i % 64)) & 1) as u32
}

/// 1 if any of the bits below position i are set.
pub(super) fn sticky(x: &[u64], i: usize) -> u32 {
    let j = i / 64;
    if j >= x.len() {
        return u32::from(!x.is_empty());
    }
    if x[..j].iter().any(|&w| w != 0) {
        return 1;
    }
    let s = i % 64;
    u32::from(s != 0 && x[j] << (64 - s) != 0)
}

pub(super) fn set_bit(x: &[u64], i: usize, b: u32) -> Nat {
    let j = i / 64;
    let m = 1u64 << (i % 64);
    let mut z = x.to_vec();
    match b {
        0 => {
            if j < z.len() {
                z[j] &= !m;
            }
            normalized(z)
        }
        1 => {
            if j >= z.len() {
                z.resize(j + 1, 0);
            }
            z[j] |= m;
            z
        }
        _ => panic!("set bit is not 0 or 1"),
    }
}

pub(super) fn and(x: &[u64], y: &[u64]) -> Nat {
    normalized(x.iter().zip(y).map(|(a, b)| a & b).collect())
}

pub(super) fn and_not(x: &[u64], y: &[u64]) -> Nat {
    let mut z = x.to_vec();
    for (zi, &yi) in z.iter_mut().zip(y) {
        *zi &= !yi;
    }
    normalized(z)
}

pub(super) fn or(x: &[u64], y: &[u64]) -> Nat {
    let (long, short) = if x.len() >= y.len() { (x, y) } else { (y, x) };
    let mut z = long.to_vec();
    for (zi, &yi) in z.iter_mut().zip(short) {
        *zi |= yi;
    }
    z
}

pub(super) fn xor(x: &[u64], y: &[u64]) -> Nat {
    let (long, short) = if x.len() >= y.len() { (x, y) } else { (y, x) };
    let mut z = long.to_vec();
    for (zi, &yi) in z.iter_mut().zip(short) {
        *zi ^= yi;
    }
    normalized(z)
}

/// x**y mod m (m empty means no modulus), following Go's special cases.
pub(super) fn exp_nn(x: &[u64], y: &[u64], m: &[u64]) -> Nat {
    if is_one(m) {
        return Vec::new();
    }
    if y.is_empty() {
        return vec![1];
    }
    if x.is_empty() {
        return Vec::new();
    }
    if is_one(x) {
        return vec![1];
    }
    if is_one(y) {
        return if m.is_empty() { x.to_vec() } else { rem(x, m) };
    }
    if m.is_empty() {
        // Plain left-to-right binary exponentiation.
        let mut z = x.to_vec();
        for i in (0..bit_len(y) - 1).rev() {
            z = sqr(&z);
            if bit(y, i) == 1 {
                z = mul(&z, x);
            }
        }
        return z;
    }
    if m[0] & 1 == 1 && m.len() > 1 {
        return exp_montgomery(x, y, m);
    }
    // Fixed 4-bit window with reduction by division.
    let x = if cmp(x, m) != Ordering::Less {
        rem(x, m)
    } else {
        x.to_vec()
    };
    let mut powers: Vec<Nat> = Vec::with_capacity(16);
    powers.push(vec![1]);
    powers.push(x.clone());
    for i in 2..16 {
        let p = mul(&powers[i - 1], &x);
        powers.push(rem(&p, m));
    }
    let mut z: Nat = vec![1];
    let nbits = bit_len(y);
    let top = nbits.div_ceil(4) * 4;
    let mut i = top;
    while i > 0 {
        i -= 4;
        if !z.is_empty() && !is_one(&z) {
            for _ in 0..4 {
                z = rem(&sqr(&z), m);
            }
        }
        let digit = ((bit(y, i + 3) << 3) | (bit(y, i + 2) << 2) | (bit(y, i + 1) << 1) | bit(y, i))
            as usize;
        if digit != 0 {
            z = rem(&mul(&z, &powers[digit]), m);
        }
    }
    rem(&z, m)
}

/// Montgomery product x·y·R⁻¹ mod m for n-limb operands (n == m.len()),
/// returning an n-limb value in [0, 2m).
fn montgomery(x: &[u64], y: &[u64], m: &[u64], k: u64, n: usize) -> Nat {
    let mut z = vec![0u64; 2 * n + 1];
    for i in 0..n {
        let c = add_mul_vw(&mut z[i..i + n], x, y[i]);
        add_into(&mut z[i + n..], &[c]);
        let t = z[i].wrapping_mul(k);
        let c = add_mul_vw(&mut z[i..i + n], m, t);
        add_into(&mut z[i + n..], &[c]);
    }
    let mut r = z[n..2 * n].to_vec();
    if z[2 * n] != 0 {
        sub_into(&mut r, m);
    }
    r
}

/// x**y mod m for odd m with len(m) > 1, using a 4-bit window.
fn exp_montgomery(x: &[u64], y: &[u64], m: &[u64]) -> Nat {
    let n = m.len();
    let mut xr = if x.len() > n { rem(x, m) } else { x.to_vec() };
    xr.resize(n, 0);
    // k0 = -m⁻¹ mod 2**64.
    let mut inv = 1u64;
    for _ in 0..6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
    }
    let k0 = inv.wrapping_neg();
    // RR = R² mod m.
    let mut rr = rem(&shl(&[1], 2 * n * 64), m);
    rr.resize(n, 0);
    let mut one = vec![0u64; n];
    one[0] = 1;
    let mut powers: Vec<Nat> = Vec::with_capacity(16);
    powers.push(montgomery(&one, &rr, m, k0, n));
    powers.push(montgomery(&xr, &rr, m, k0, n));
    for i in 2..16 {
        let p = montgomery(&powers[i - 1], &powers[1], m, k0, n);
        powers.push(p);
    }
    let mut z = powers[0].clone();
    let nbits = bit_len(y);
    let mut i = nbits.div_ceil(4) * 4;
    let mut first = true;
    while i > 0 {
        i -= 4;
        if !first {
            for _ in 0..4 {
                z = montgomery(&z, &z, m, k0, n);
            }
        }
        first = false;
        let digit = ((bit(y, i + 3) << 3) | (bit(y, i + 2) << 2) | (bit(y, i + 1) << 1) | bit(y, i))
            as usize;
        z = montgomery(&z, &powers[digit], m, k0, n);
    }
    let z = normalized(montgomery(&z, &one, m, k0, n));
    if cmp(&z, m) != Ordering::Less {
        return rem(&z, m);
    }
    z
}

/// ⌊√x⌋ by Newton's method from above, as in Go. The starting value comes
/// from the square root of the top half of x (recursively), so only a couple
/// of full-size Newton steps are needed instead of Go's O(log n) from a power
/// of two; the result is the same.
pub(super) fn sqrt(x: &[u64]) -> Nat {
    if cmp(x, &[1]) != Ordering::Greater {
        return x.to_vec();
    }
    let n = bit_len(x);
    let mut z1 = if n <= 256 {
        shl(&[1], n.div_ceil(2))
    } else {
        // √x < (⌊√(x >> 2k)⌋ + 1) << k.
        let k = n / 4;
        let s = sqrt(&shr(x, 2 * k));
        shl(&add_w(&s, 1), k)
    };
    loop {
        let (q, _) = div(x, &z1);
        let z2 = shr(&add(&q, &z1), 1);
        if cmp(&z2, &z1) != Ordering::Less {
            return z1;
        }
        z1 = z2;
    }
}

pub(super) fn set_bytes(buf: &[u8]) -> Nat {
    let mut z = Vec::with_capacity(buf.len().div_ceil(8));
    let mut i = buf.len();
    while i >= 8 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&buf[i - 8..i]);
        z.push(u64::from_be_bytes(w));
        i -= 8;
    }
    if i > 0 {
        let mut d = 0u64;
        for &b in &buf[..i] {
            d = (d << 8) | u64::from(b);
        }
        z.push(d);
    }
    normalized(z)
}

/// Write x big-endian into the tail of buf and return the index of the most
/// significant non-zero byte; panics if buf is too small, as Go does.
pub(super) fn bytes(x: &[u64], buf: &mut [u8]) -> usize {
    let mut i = buf.len();
    for &d in x {
        let mut d = d;
        for _ in 0..8 {
            if i > 0 {
                i -= 1;
                buf[i] = d as u8;
            } else if d as u8 != 0 {
                panic!("math/big: buffer too small to fit value");
            }
            d >>= 8;
        }
    }
    while i < buf.len() && buf[i] == 0 {
        i += 1;
    }
    i
}

/// The product of all integers in [a, b].
pub(super) fn mul_range(a: u64, b: u64) -> Nat {
    if a == 0 {
        return Vec::new();
    }
    if a > b {
        return vec![1];
    }
    if a == b {
        return from_u64(a);
    }
    if a + 1 == b {
        return mul(&from_u64(a), &from_u64(b));
    }
    let m = a + (b - a) / 2;
    mul(&mul_range(a, m), &mul_range(m + 1, b))
}

/// Go's nat.random: uniformly random in [0, limit) drawn from a math/rand
/// v1 generator exactly as Go draws it.
pub(super) fn random<S: crate::math::rand::v1::Source>(
    rand: &mut crate::math::rand::v1::Rand<S>,
    limit: &[u64],
    n: usize,
) -> Nat {
    let mut bits_msw = (n % 64) as u32;
    if bits_msw == 0 {
        bits_msw = 64;
    }
    let mask = if bits_msw == 64 {
        u64::MAX
    } else {
        (1u64 << bits_msw) - 1
    };
    let mut z = vec![0u64; limit.len()];
    loop {
        for w in z.iter_mut() {
            *w = u64::from(rand.uint32()) | (u64::from(rand.uint32()) << 32);
        }
        let last = limit.len() - 1;
        z[last] &= mask;
        if cmp(trim(&z), limit) == Ordering::Less {
            break;
        }
    }
    normalized(z)
}

/// Left-normalize a non-empty mantissa in place; returns the shift applied.
pub(super) fn fnorm(m: &mut [u64]) -> i64 {
    let s = m[m.len() - 1].leading_zeros();
    if s > 0 {
        let mut carry = 0u64;
        for w in m.iter_mut() {
            let next = *w >> (64 - s);
            *w = (*w << s) | carry;
            carry = next;
        }
    }
    i64::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_u128(x: &[u64]) -> u128 {
        let mut v = 0u128;
        for &w in x.iter().rev() {
            v = (v << 64) | u128::from(w);
        }
        v
    }

    #[test]
    fn karatsuba_matches_schoolbook() {
        let mut seed = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for (a, b) in [
            (40, 40),
            (41, 80),
            (100, 57),
            (200, 199),
            (300, 41),
            (81, 80),
            (83, 83),
            (160, 80),
            (205, 50),
        ] {
            let mut x: Nat = (0..a).map(|_| next()).collect();
            let y: Nat = (0..b).map(|_| next()).collect();
            if a == 83 {
                // Sparse operands make the Karatsuba halves short.
                x.iter_mut().take(82).for_each(|w| *w = 0);
            }
            assert_eq!(mul(&x, &y), normalized(basic_mul(&x, &y)));
        }
    }

    #[test]
    fn division_round_trips() {
        let mut seed = 0x0fed_cba9_8765_4321u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for (a, b) in [(2, 2), (5, 2), (10, 3), (64, 31), (100, 99), (7, 1)] {
            let u: Nat = normalized((0..a).map(|_| next()).collect());
            let mut v: Nat = normalized((0..b).map(|_| next() >> (next() % 64)).collect());
            if v.is_empty() {
                v = vec![3];
            }
            let (q, r) = div(&u, &v);
            assert_eq!(cmp(&r, &v), Ordering::Less);
            assert_eq!(add(&mul(&q, &v), &r), u);
        }
        assert_eq!(to_u128(&div(&[0, 1], &[3]).0), (1u128 << 64) / 3);
    }

    #[test]
    fn sqrt_is_floor() {
        for words in [1usize, 2, 3, 5, 9, 40, 90] {
            let x: Nat = normalized(
                (0..words)
                    .map(|i| 0x9e37_79b9_7f4a_7c15u64.rotate_left(i as u32 * 7) | 1)
                    .collect(),
            );
            let s = sqrt(&x);
            assert!(cmp(&sqr(&s), &x) != Ordering::Greater);
            let s1 = add_w(&s, 1);
            assert_eq!(cmp(&sqr(&s1), &x), Ordering::Greater);
        }
    }
}
