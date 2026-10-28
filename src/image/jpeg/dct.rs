//! The 8x8 forward and inverse DCT of Go's `image/jpeg` (`dct.go`).
//!
//! Both transforms are Loeffler, Ligtenberg and Moschytz's 11-multiplication
//! factorization in 32-bit fixed point. Go's results depend on its exact
//! intermediate shifts, so the arithmetic is reproduced step by step, with
//! `Wrapping<i32>` standing in for Go's silently wrapping `int32`.
use std::num::Wrapping;

pub(super) const BLOCK_SIZE: usize = 64;

/// An 8x8 block in natural (row-major) order.
pub(super) type Block = [i32; BLOCK_SIZE];

type W = Wrapping<i32>;

const COS1: u64 = 1130768441178740757;
const SIN1: u64 = 224923827593068887;
const COS3: u64 = 958619196450722178;
const SIN3: u64 = 640528868967736374;
const SQRT2: u64 = 1630477228166597777;
const SQRT2_COS6: u64 = 623956622067911264;
const SQRT2_SIN6: u64 = 1506364539328854985;
const SQRT2INV: u64 = 815238614083298888;
const SQRT2INV_COS6: u64 = 311978311033955632;
const SQRT2INV_SIN6: u64 = 753182269664427492;

/// Rounds the 60-bit fixed-point constant `x` to `bits` bits (Go's `c`).
const fn c(x: u64, bits: u32) -> W {
    Wrapping(((x + (1 << (59 - bits))) >> (60 - bits)) as i32)
}

/// A 3-multiply rotation plus scaling (Go's `dctBox`).
fn dct_box(x0: W, x1: W, kcos: W, ksin: W) -> (W, W) {
    let ksum = kcos * (x0 + x1);
    (ksum + (ksin - kcos) * x1, ksum - (kcos + ksin) * x0)
}

/// The forward DCT. Inputs are unsigned 8-bit samples; outputs are Q13.0.
pub(super) fn fdct(b: &mut Block) {
    fdct_cols(b);
    fdct_rows(b);
}

fn fdct_cols(b: &mut Block) {
    for i in 0..8 {
        let mut x0 = Wrapping(b[i]);
        let mut x1 = Wrapping(b[8 + i]);
        let mut x2 = Wrapping(b[2 * 8 + i]);
        let mut x3 = Wrapping(b[3 * 8 + i]);
        let mut x4 = Wrapping(b[4 * 8 + i]);
        let mut x5 = Wrapping(b[5 * 8 + i]);
        let mut x6 = Wrapping(b[6 * 8 + i]);
        let mut x7 = Wrapping(b[7 * 8 + i]);

        (x0, x7) = (x0 + x7, x0 - x7);
        (x1, x6) = (x1 + x6, x1 - x6);
        (x2, x5) = (x2 + x5, x2 - x5);
        (x3, x4) = (x3 + x4, x3 - x4);

        (x4, x7) = dct_box(x4, x7, c(COS3, 18), c(SIN3, 18));
        (x5, x6) = dct_box(x5, x6, c(COS1, 18), c(SIN1, 18));

        (x0, x3) = (x0 + x3, x0 - x3);
        (x1, x2) = (x1 + x2, x1 - x2);

        (x2, x3) = dct_box(x2, x3, c(SQRT2_COS6, 18), c(SQRT2_SIN6, 18));

        (x0, x1) = (x0 + x1, x0 - x1);

        b[i] = ((x0 - Wrapping(128 * 8)) << 18).0;
        b[4 * 8 + i] = (x1 << 18).0;
        b[2 * 8 + i] = x2.0;
        b[6 * 8 + i] = x3.0;

        (x4, x6) = (x4 + x6, x4 - x6);
        (x7, x5) = (x7 + x5, x7 - x5);

        x5 = (x5 >> 12) * c(SQRT2, 12);
        x6 = (x6 >> 12) * c(SQRT2, 12);
        (x7, x4) = (x7 + x4, x7 - x4);

        b[8 + i] = x7.0;
        b[3 * 8 + i] = x5.0;
        b[5 * 8 + i] = x6.0;
        b[7 * 8 + i] = x4.0;
    }
}

fn fdct_rows(b: &mut Block) {
    for i in 0..8 {
        let x = &mut b[8 * i..8 * i + 8];
        let mut x0 = Wrapping(x[0]);
        let mut x1 = Wrapping(x[1]);
        let mut x2 = Wrapping(x[2]);
        let mut x3 = Wrapping(x[3]);
        let mut x4 = Wrapping(x[4]);
        let mut x5 = Wrapping(x[5]);
        let mut x6 = Wrapping(x[6]);
        let mut x7 = Wrapping(x[7]);

        (x0, x7) = (x0 + x7, x0 - x7);
        (x1, x6) = (x1 + x6, x1 - x6);
        (x2, x5) = (x2 + x5, x2 - x5);
        (x3, x4) = (x3 + x4, x3 - x4);

        (x4, x7) = dct_box(x4 >> 14, x7 >> 14, c(COS3, 14), c(SIN3, 14));
        (x5, x6) = dct_box(x5 >> 14, x6 >> 14, c(COS1, 14), c(SIN1, 14));
        (x0, x3) = (x0 + x3, x0 - x3);
        (x1, x2) = (x1 + x2, x1 - x2);

        (x2, x3) = dct_box(x2 >> 14, x3 >> 14, c(SQRT2_COS6, 14), c(SQRT2_SIN6, 14));
        (x0, x1) = (x0 + x1, x0 - x1);
        (x4, x6) = (x4 + x6, x4 - x6);
        (x7, x5) = (x7 + x5, x7 - x5);

        x5 = (x5 >> 14) * c(SQRT2, 14);
        x6 = (x6 >> 14) * c(SQRT2, 14);
        (x7, x4) = (x7 + x4, x7 - x4);

        let half = Wrapping(1 << 17);
        x0 = (x0 + half) >> 18;
        x1 = (x1 + half) >> 18;
        x2 = (x2 + half) >> 18;
        x3 = (x3 + half) >> 18;
        x4 = (x4 + half) >> 18;
        x5 = (x5 + half) >> 18;
        x6 = (x6 + half) >> 18;
        x7 = (x7 + half) >> 18;

        x[0] = x0.0;
        x[1] = x7.0;
        x[2] = x2.0;
        x[3] = x5.0;
        x[4] = x1.0;
        x[5] = x6.0;
        x[6] = x3.0;
        x[7] = x4.0;
    }
}

/// The inverse DCT. The result is the IDCT scaled by 8 (Q10.3).
pub(super) fn idct(b: &mut Block) {
    idct_rows(b);
    idct_cols(b);
}

fn idct_rows(b: &mut Block) {
    for i in 0..8 {
        let x = &mut b[8 * i..8 * i + 8];
        let mut x0 = Wrapping(x[0]);
        let mut x7 = Wrapping(x[1]);
        let mut x2 = Wrapping(x[2]);
        let mut x5 = Wrapping(x[3]);
        let mut x1 = Wrapping(x[4]);
        let mut x6 = Wrapping(x[5]);
        let mut x3 = Wrapping(x[6]);
        let mut x4 = Wrapping(x[7]);

        x0 <<= 17;
        x1 <<= 17;
        (x0, x1) = (x0 + x1, x0 - x1);

        (x2, x3) = dct_box(x2, x3, c(SQRT2INV_COS6, 18), -c(SQRT2INV_SIN6, 18));
        (x1, x2) = (x1 + x2, x1 - x2);
        (x0, x3) = (x0 + x3, x0 - x3);

        x4 <<= 7;
        x7 <<= 7;
        (x7, x4) = (x7 + x4, x7 - x4);

        x6 *= c(SQRT2INV, 8);
        x5 *= c(SQRT2INV, 8);

        (x7, x5) = (x7 + x5, x7 - x5);
        (x4, x6) = (x4 + x6, x4 - x6);

        (x4, x7) = dct_box(x4 >> 2, x7 >> 2, c(COS3, 12), -c(SIN3, 12));
        (x5, x6) = dct_box(x5 >> 2, x6 >> 2, c(COS1, 12), -c(SIN1, 12));

        (x0, x7) = (x0 + x7, x0 - x7);
        (x1, x6) = (x1 + x6, x1 - x6);
        (x2, x5) = (x2 + x5, x2 - x5);
        (x3, x4) = (x3 + x4, x3 - x4);

        x[0] = x0.0;
        x[1] = x1.0;
        x[2] = x2.0;
        x[3] = x3.0;
        x[4] = x4.0;
        x[5] = x5.0;
        x[6] = x6.0;
        x[7] = x7.0;
    }
}

fn idct_cols(b: &mut Block) {
    for i in 0..8 {
        let mut x0 = Wrapping(b[i]);
        let mut x7 = Wrapping(b[8 + i]);
        let mut x2 = Wrapping(b[2 * 8 + i]);
        let mut x5 = Wrapping(b[3 * 8 + i]);
        let mut x1 = Wrapping(b[4 * 8 + i]);
        let mut x6 = Wrapping(b[5 * 8 + i]);
        let mut x3 = Wrapping(b[6 * 8 + i]);
        let mut x4 = Wrapping(b[7 * 8 + i]);

        x0 += Wrapping(1 << 19);

        (x0, x1) = ((x0 + x1) >> 2, (x0 - x1) >> 2);
        (x2, x3) = dct_box(
            x2 >> 13,
            x3 >> 13,
            c(SQRT2INV_COS6, 12),
            -c(SQRT2INV_SIN6, 12),
        );

        (x1, x2) = (x1 + x2, x1 - x2);
        (x0, x3) = (x0 + x3, x0 - x3);

        (x7, x4) = (x7 + x4, x7 - x4);

        x5 = (x5 >> 13) * c(SQRT2INV, 14);
        x6 = (x6 >> 13) * c(SQRT2INV, 14);

        (x7, x5) = (x7 + x5, x7 - x5);
        (x4, x6) = (x4 + x6, x4 - x6);

        (x4, x7) = dct_box(x4 >> 14, x7 >> 14, c(COS3, 12), -c(SIN3, 12));
        (x5, x6) = dct_box(x5 >> 14, x6 >> 14, c(COS1, 12), -c(SIN1, 12));

        (x0, x7) = (x0 + x7, x0 - x7);
        (x1, x6) = (x1 + x6, x1 - x6);
        (x2, x5) = (x2 + x5, x2 - x5);
        (x3, x4) = (x3 + x4, x3 - x4);

        b[i] = (x0 >> 18).0;
        b[8 + i] = (x1 >> 18).0;
        b[2 * 8 + i] = (x2 >> 18).0;
        b[3 * 8 + i] = (x3 >> 18).0;
        b[4 * 8 + i] = (x4 >> 18).0;
        b[5 * 8 + i] = (x5 >> 18).0;
        b[6 * 8 + i] = (x6 >> 18).0;
        b[7 * 8 + i] = (x7 >> 18).0;
    }
}
