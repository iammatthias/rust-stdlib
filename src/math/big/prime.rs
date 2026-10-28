// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/big/prime.go.

use super::int::{jacobi, Int};
use super::nat::{self, Nat};
use crate::math::rand::v1;
use std::cmp::Ordering;

impl Int {
    /// Go's `ProbablyPrime(n)`: n pseudorandom-base Miller-Rabin rounds plus
    /// one with base 2, followed by a Baillie-PSW strong Lucas test. Exact
    /// for x < 2⁶⁴. The bases come from Go's `math/rand` seeded with the
    /// low limb of x, so results are identical to Go's. Panics if n < 0.
    pub fn probably_prime(&self, n: i32) -> bool {
        assert!(n >= 0, "negative n for ProbablyPrime");
        if self.neg || self.abs.is_empty() {
            return false;
        }
        const PRIME_BIT_MASK: u64 = (1 << 2)
            | (1 << 3)
            | (1 << 5)
            | (1 << 7)
            | (1 << 11)
            | (1 << 13)
            | (1 << 17)
            | (1 << 19)
            | (1 << 23)
            | (1 << 29)
            | (1 << 31)
            | (1 << 37)
            | (1 << 41)
            | (1 << 43)
            | (1 << 47)
            | (1 << 53)
            | (1 << 59)
            | (1 << 61);
        let w = self.abs[0];
        if self.abs.len() == 1 && w < 64 {
            return PRIME_BIT_MASK & (1 << w) != 0;
        }
        if w & 1 == 0 {
            return false;
        }
        const PRIMES_A: u64 = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 37;
        const PRIMES_B: u64 = 29 * 31 * 41 * 43 * 47 * 53;
        let r = nat::mod_w(&self.abs, PRIMES_A * PRIMES_B);
        let ra = r % PRIMES_A;
        let rb = r % PRIMES_B;
        if [3, 5, 7, 11, 13, 17, 19, 23, 37]
            .iter()
            .any(|p| ra.is_multiple_of(*p))
            || [29, 31, 41, 43, 47, 53]
                .iter()
                .any(|p| rb.is_multiple_of(*p))
        {
            return false;
        }
        miller_rabin(&self.abs, n as usize + 1, true) && lucas(&self.abs)
    }
}

/// reps Miller-Rabin rounds with Go's pseudorandom bases; with force2 the
/// last round uses base 2.
fn miller_rabin(n: &[u64], reps: usize, force2: bool) -> bool {
    let nm1 = nat::sub_w(n, 1);
    let k = nat::trailing_zero_bits(&nm1);
    let q = nat::shr(&nm1, k);
    let nm3 = nat::sub_w(&nm1, 2);
    let mut rand = v1::Rand::new(v1::RngSource::new(n[0] as i64));
    let nm3_len = nat::bit_len(&nm3);
    'next: for i in 0..reps {
        let x: Nat = if i == reps - 1 && force2 {
            vec![2]
        } else {
            nat::add_w(&nat::random(&mut rand, &nm3, nm3_len), 2)
        };
        let mut y = nat::exp_nn(&x, &q, n);
        if nat::is_one(&y) || y == nm1 {
            continue;
        }
        for _ in 1..k {
            y = nat::rem(&nat::sqr(&y), n);
            if y == nm1 {
                continue 'next;
            }
            if nat::is_one(&y) {
                return false;
            }
        }
        return false;
    }
    true
}

/// Go's probablyPrimeLucas: the extra strong Lucas test with Baillie's
/// parameter selection.
fn lucas(n: &[u64]) -> bool {
    if n.is_empty() || nat::is_one(n) {
        return false;
    }
    if n[0] & 1 == 0 {
        return n == [2];
    }
    let int_n = Int::from_parts(false, n.to_vec());
    let mut p: u64 = 3;
    loop {
        assert!(
            p <= 10000,
            "math/big: internal error: cannot find (D/n) = -1 for {int_n}"
        );
        let d = Int::from_u64(p * p - 4);
        let j = jacobi(&d, &int_n);
        if j == -1 {
            break;
        }
        if j == 0 {
            return n.len() == 1 && n[0] == p + 2;
        }
        if p == 40 {
            let t = nat::sqr(&nat::sqrt(n));
            if t == n {
                return false;
            }
        }
        p += 1;
    }
    let s = nat::add_w(n, 1);
    let r = nat::trailing_zero_bits(&s);
    let s = nat::shr(&s, r);
    let nm2 = nat::sub_w(n, 2);
    let nat_p = nat::from_u64(p);
    let mut vk: Nat = vec![2];
    let mut vk1: Nat = nat::from_u64(p);
    for i in (0..=nat::bit_len(&s)).rev() {
        let t1 = nat::sub(&nat::add(&nat::mul(&vk, &vk1), n), &nat_p);
        if nat::bit(&s, i) != 0 {
            vk = nat::rem(&t1, n);
            vk1 = nat::rem(&nat::add(&nat::sqr(&vk1), &nm2), n);
        } else {
            vk1 = nat::rem(&t1, n);
            vk = nat::rem(&nat::add(&nat::sqr(&vk), &nm2), n);
        }
    }
    if vk == [2] || vk == nm2 {
        let mut t1 = nat::mul(&vk, &nat_p);
        let mut t2 = nat::shl(&vk1, 1);
        if nat::cmp(&t1, &t2) == Ordering::Less {
            std::mem::swap(&mut t1, &mut t2);
        }
        let t1 = nat::sub(&t1, &t2);
        if nat::rem(&t1, n).is_empty() {
            return true;
        }
    }
    for _ in 0..r.saturating_sub(1) {
        if vk.is_empty() {
            return true;
        }
        if vk == [2] {
            return false;
        }
        vk = nat::rem(&nat::sub_w(&nat::sqr(&vk), 2), n);
    }
    false
}
