//! Constant-time helpers, compatible with Go's `crypto/subtle`.
//!
//! Comparison and selection run on the reviewed `subtle` crate.

use ::subtle::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};

/// Returns 1 if the slices have equal contents and 0 otherwise, in time that
/// depends only on the length. Slices of different lengths compare unequal.
pub fn constant_time_compare(x: &[u8], y: &[u8]) -> i32 {
    i32::from(x.ct_eq(y).unwrap_u8())
}

/// Returns `x` if `v == 1` and `y` if `v == 0`. As in Go, other values of `v`
/// have unspecified results.
pub fn constant_time_select(v: i32, x: i32, y: i32) -> i32 {
    i32::conditional_select(&y, &x, Choice::from((v & 1) as u8))
}

/// Returns 1 if `x == y` and 0 otherwise.
pub fn constant_time_byte_eq(x: u8, y: u8) -> i32 {
    i32::from(x.ct_eq(&y).unwrap_u8())
}

/// Returns 1 if `x == y` and 0 otherwise.
pub fn constant_time_eq(x: i32, y: i32) -> i32 {
    i32::from(x.ct_eq(&y).unwrap_u8())
}

/// Copies `y` into `x` if `v == 1`, and leaves `x` unchanged if `v == 0`. As in
/// Go, other values of `v` have unspecified results.
///
/// # Panics
///
/// Panics with Go's message if the slices have different lengths.
pub fn constant_time_copy(v: i32, x: &mut [u8], y: &[u8]) {
    assert!(x.len() == y.len(), "subtle: slices have different lengths");
    let choice = Choice::from((v & 1) as u8);
    for (dst, src) in x.iter_mut().zip(y) {
        *dst = u8::conditional_select(dst, src, choice);
    }
}

/// Returns 1 if `0 <= x <= y` and 0 otherwise. As in Go, the result is
/// unspecified when `x` or `y` is negative.
pub fn constant_time_less_or_eq(x: i32, y: i32) -> i32 {
    let greater = (x as u32).ct_gt(&(y as u32));
    i32::from((!greater).unwrap_u8())
}

/// Writes `x XOR y` into `dst` for the shorter of the two inputs and returns
/// the number of bytes written.
///
/// # Panics
///
/// Panics with Go's message if `dst` is shorter than that length.
pub fn xor_bytes(dst: &mut [u8], x: &[u8], y: &[u8]) -> usize {
    let n = x.len().min(y.len());
    assert!(dst.len() >= n, "subtle.XORBytes: dst too short");
    for ((out, a), b) in dst.iter_mut().zip(x).zip(y) {
        *out = a ^ b;
    }
    n
}

/// Runs `f`. Go also asks the CPU to disable data-dependent timing for the
/// duration (the ARM64 DIT bit); stable Rust has no safe way to do that, so
/// this only calls `f`. See the deviation recorded in docs/api/crypto_subtle.json.
pub fn with_data_independent_timing<F: FnOnce()>(f: F) {
    f();
}
