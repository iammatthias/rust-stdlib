// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/rand/zipf.go; math/rand/v2/zipf.go is identical.
// W. Hormann and G. Derflinger, "Rejection-Inversion to Generate Variates from
// Monotone Discrete Distributions".

use super::fmath::{exp, log, FUSED_MULTIPLY_ADD};

/// The parameters and precomputed constants of Go's `Zipf`, shared by the
/// `math/rand` and `math/rand/v2` generators.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(super) struct Core {
    imax: f64,
    v: f64,
    q: f64,
    s: f64,
    one_minus_q: f64,
    one_minus_q_inv: f64,
    hxm: f64,
    hx0_minus_hxm: f64,
}

impl Core {
    /// Go's `NewZipf` checks and precomputation. `None` where Go returns nil.
    pub(super) fn new(s: f64, v: f64, imax: u64) -> Option<Self> {
        if s <= 1.0 || v < 1.0 {
            return None;
        }
        let mut z = Self {
            imax: imax as f64,
            v,
            q: s,
            s: 0.0,
            one_minus_q: 0.0,
            one_minus_q_inv: 0.0,
            hxm: 0.0,
            hx0_minus_hxm: 0.0,
        };
        z.one_minus_q = 1.0 - z.q;
        z.one_minus_q_inv = 1.0 / z.one_minus_q;
        z.hxm = z.h(z.imax + 0.5);
        z.hx0_minus_hxm = z.h(0.5) - exp(log(z.v) * (-z.q)) - z.hxm;
        z.s = 1.0 - z.hinv(z.h(1.5) - exp(-z.q * log(z.v + 1.0)));
        Some(z)
    }

    fn h(&self, x: f64) -> f64 {
        exp(self.one_minus_q * log(self.v + x)) * self.one_minus_q_inv
    }

    fn hinv(&self, x: f64) -> f64 {
        exp(self.one_minus_q_inv * log(self.one_minus_q * x)) - self.v
    }

    /// Go's `Zipf.Uint64`. `float64` supplies the uniform variates in [0, 1).
    pub(super) fn sample(&self, mut float64: impl FnMut() -> f64) -> u64 {
        let mut k;
        loop {
            let r = float64();
            // Go on arm64 fuses this multiply-add; other targets do not.
            let ur = if FUSED_MULTIPLY_ADD {
                r.mul_add(self.hx0_minus_hxm, self.hxm)
            } else {
                self.hxm + r * self.hx0_minus_hxm
            };
            let x = self.hinv(ur);
            k = (x + 0.5).floor();
            if k - x <= self.s {
                break;
            }
            if ur >= self.h(k + 0.5) - exp(-log(k + self.v) * self.q) {
                break;
            }
        }
        k as u64
    }
}
