// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/rand/v2/pcg.go.

use super::{Source, UnmarshalError};

/// Go's `rand.PCG`: a 128-bit-state permuted congruential generator with the
/// DXSM output function and Go's "cheap multiplier" variant.
///
/// The same seed produces the same sequence as Go's `rand.NewPCG`.
/// It is not suitable for security-sensitive work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Pcg {
    hi: u64,
    lo: u64,
}

const MARSHAL_PREFIX: &[u8] = b"pcg:";

impl Pcg {
    /// Equivalent to Go's `rand.NewPCG(seed1, seed2)`.
    pub const fn new(seed1: u64, seed2: u64) -> Self {
        Self {
            hi: seed1,
            lo: seed2,
        }
    }

    /// Reset the state as if freshly created by `Pcg::new(seed1, seed2)`.
    pub fn seed(&mut self, seed1: u64, seed2: u64) {
        self.hi = seed1;
        self.lo = seed2;
    }

    /// Append Go's binary encoding: `"pcg:"` and the big-endian state.
    pub fn append_binary(&self, mut out: Vec<u8>) -> Vec<u8> {
        out.extend_from_slice(MARSHAL_PREFIX);
        out.extend_from_slice(&self.hi.to_be_bytes());
        out.extend_from_slice(&self.lo.to_be_bytes());
        out
    }

    /// Go's `MarshalBinary`; always 20 bytes.
    pub fn marshal_binary(&self) -> Vec<u8> {
        self.append_binary(Vec::with_capacity(20))
    }

    /// Go's `UnmarshalBinary`. The state is unchanged on error.
    pub fn unmarshal_binary(&mut self, data: &[u8]) -> Result<(), UnmarshalError> {
        if data.len() != 20 || &data[..4] != MARSHAL_PREFIX {
            return Err(UnmarshalError("invalid PCG encoding"));
        }
        self.hi = u64::from_be_bytes(data[4..12].try_into().expect("8-byte slice"));
        self.lo = u64::from_be_bytes(data[12..20].try_into().expect("8-byte slice"));
        Ok(())
    }

    /// Advance the 128-bit LCG: state = state * mul + inc (mod 2^128).
    /// Go spells out the 128-bit multiply with `bits.Mul64`; `u128` wrapping
    /// arithmetic computes the identical low 128 bits.
    fn next(&mut self) -> (u64, u64) {
        const MUL_HI: u64 = 2549297995355413924;
        const MUL_LO: u64 = 4865540595714422341;
        const INC_HI: u64 = 6364136223846793005;
        const INC_LO: u64 = 1442695040888963407;
        let state = (u128::from(self.hi) << 64) | u128::from(self.lo);
        let mul = (u128::from(MUL_HI) << 64) | u128::from(MUL_LO);
        let inc = (u128::from(INC_HI) << 64) | u128::from(INC_LO);
        let state = state.wrapping_mul(mul).wrapping_add(inc);
        self.hi = (state >> 64) as u64;
        self.lo = state as u64;
        (self.hi, self.lo)
    }
}

impl Source for Pcg {
    /// DXSM ("double xorshift multiply") output with Go's cheap multiplier.
    fn uint64(&mut self) -> u64 {
        let (mut hi, lo) = self.next();
        const CHEAP_MUL: u64 = 0xda942042e4dd58b5;
        hi ^= hi >> 32;
        hi = hi.wrapping_mul(CHEAP_MUL);
        hi ^= hi >> 48;
        hi.wrapping_mul(lo | 1)
    }
}
