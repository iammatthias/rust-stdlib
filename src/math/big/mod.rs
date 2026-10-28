// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the NOTICE file.
//
// Ported from $GOROOT/src/math/big. See NOTICE.

//! Go's `math/big`: arbitrary-precision integers ([`Int`]), rationals
//! ([`Rat`]) and binary floating-point numbers ([`Float`]).
//!
//! Results, text formats, rounding and accuracy reports match Go's on its
//! 64-bit platforms; `tools/big_check.py` compares them with Go
//! differentially.
//!
//! ```
//! use rust_stdlib::math::big::{Float, Int, Rat, RoundingMode};
//! let x: Int = "123456789012345678901234567890".parse()?;
//! let y = Int::new(-987654321);
//! assert_eq!((&x * &y).to_string(), "-121932631124828532112482853211126352690");
//! assert_eq!(x.text(36), "byw97um9s91dlz68tsi");
//!
//! let r = (Rat::new(1, 3) + &Rat::new(1, 6));
//! assert_eq!(r.to_string(), "1/2");
//!
//! let mut f = Float::with_prec(100);
//! f.set_mode(RoundingMode::ToZero);
//! f.quo_into(&Float::from_i64(1), &Float::from_i64(3))?;
//! assert_eq!(f.text(b'g', 20), "0.33333333333333333333");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # API shape
//!
//! [`Int`] and [`Rat`] are values: methods such as [`Int::div_mod`] return a new
//! value instead of storing into a receiver, and Go's `nil` results (for
//! example from `ModInverse`) are `None`. The arithmetic operators are
//! implemented on references (`&a + &b`); `/` and `%` on [`Int`] truncate
//! like Go's `Quo`/`Rem` and Rust's primitive integers, while [`Int::div_euclid`]
//! and [`Int::rem_euclid`] are Go's Euclidean `Div`/`Mod`.
//!
//! [`Float`] keeps Go's receiver style because a receiver's precision and
//! rounding mode select how a result is rounded: `z.add_into(&x, &y)` rounds to
//! `z`'s precision (or the larger operand precision when `z`'s is 0).
//! Operations Go reports by panicking with `ErrNaN` (∞-∞, 0·∞, 0/0, ∞/∞,
//! the square root of a negative number, a NaN `f64`) return
//! `Err(`[`ErrNaN`]`)` from the receiver methods and `Float::checked_*`, and
//! leave the receiver at zero, as Go does before its panic; the `Float`
//! operators (`+`, `-`, `*`, `/`, which round to the larger operand
//! precision) panic like Go. Division of an [`Int`] or [`Rat`] by zero, negative
//! bit indices and invalid bases panic as in Go (and as Rust's integers do).
//!
//! # Performance and resources
//!
//! Limbs are `u64` with `u128` intermediates. Multiplication switches from
//! schoolbook to Karatsuba at 40 limbs; division is Knuth's Algorithm D,
//! O(m·n) for an (m+n)-limb dividend and n-limb divisor. Odd moduli use
//! Montgomery exponentiation. Decimal formatting splits values recursively
//! by powers of the base, and parsing combines digit groups by divide and
//! conquer, so neither is quadratic in the multiplication. Arithmetic has no
//! size limits beyond memory, as in Go: callers that accept untrusted input
//! should bound its length. Go's own guards are kept: `Rat` strings with a
//! decimal exponent beyond 10⁶ or a binary exponent beyond 10⁷ are rejected,
//! and `Float` exponents are limited to `i32`. Note that formatting a
//! `Float` with a huge exponent in `'f'` format produces correspondingly
//! huge strings, as in Go.

mod float;
mod floatconv;
mod ftoa;
mod int;
mod intconv;
mod nat;
mod natconv;
mod prime;
mod rat;
mod ratconv;

pub use float::{Float, MAX_EXP, MAX_PREC, MIN_EXP};
pub use int::jacobi;
pub use int::Int;
pub use natconv::MAX_BASE;
pub use rat::Rat;

use std::fmt;

/// Go's `big.Word`: a single limb of a magnitude ([`Int::bits`] and
/// [`Int::from_bits`]). Always 64 bits, Go's word size on its 64-bit
/// platforms.
pub type Word = u64;

/// Go's `big.RoundingMode`: how a [`Float`] value is rounded. Like Go's
/// `byte` type it holds any value, because `Float::gob_decode` stores the
/// mode bits it reads unvalidated; only the six named modes are meaningful.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct RoundingMode(pub u8);

#[allow(non_upper_case_globals)]
impl RoundingMode {
    /// Round to nearest, ties to even (IEEE 754 roundTiesToEven).
    pub const ToNearestEven: RoundingMode = RoundingMode(0);
    /// Round to nearest, ties away from zero.
    pub const ToNearestAway: RoundingMode = RoundingMode(1);
    /// Round toward zero.
    pub const ToZero: RoundingMode = RoundingMode(2);
    /// Round away from zero.
    pub const AwayFromZero: RoundingMode = RoundingMode(3);
    /// Round toward negative infinity.
    pub const ToNegativeInf: RoundingMode = RoundingMode(4);
    /// Round toward positive infinity.
    pub const ToPositiveInf: RoundingMode = RoundingMode(5);

    /// All six modes in Go's declaration order.
    pub const ALL: [RoundingMode; 6] = [
        RoundingMode::ToNearestEven,
        RoundingMode::ToNearestAway,
        RoundingMode::ToZero,
        RoundingMode::AwayFromZero,
        RoundingMode::ToNegativeInf,
        RoundingMode::ToPositiveInf,
    ];

    /// Go's `big.Trunc`: truncated (T-)division for [`Int::divide`].
    pub const TRUNC: RoundingMode = RoundingMode::ToZero;
    /// Go's `big.Floor`: floored (F-)division.
    pub const FLOOR: RoundingMode = RoundingMode::ToNegativeInf;
    /// Go's `big.Round`: rounded (R-)division.
    pub const ROUND: RoundingMode = RoundingMode::ToNearestEven;
    /// Go's `big.Ceil`: ceiling (C-)division.
    pub const CEIL: RoundingMode = RoundingMode::ToPositiveInf;
}

/// Go's `RoundingMode.String`: the mode name, or `RoundingMode(n)`.
impl fmt::Display for RoundingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            RoundingMode::ToNearestEven => f.write_str("ToNearestEven"),
            RoundingMode::ToNearestAway => f.write_str("ToNearestAway"),
            RoundingMode::ToZero => f.write_str("ToZero"),
            RoundingMode::AwayFromZero => f.write_str("AwayFromZero"),
            RoundingMode::ToNegativeInf => f.write_str("ToNegativeInf"),
            RoundingMode::ToPositiveInf => f.write_str("ToPositiveInf"),
            RoundingMode(n) => write!(f, "RoundingMode({n})"),
        }
    }
}

impl fmt::Debug for RoundingMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Go's `big.Accuracy`: the sign of the rounding error of the most recent
/// [`Float`] operation or conversion. Like Go's `int8` type it holds any
/// value, because `Float::gob_decode` stores the accuracy bits it reads
/// unvalidated; only the three named values are meaningful.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Accuracy(pub i8);

#[allow(non_upper_case_globals)]
impl Accuracy {
    /// The result is smaller than the exact value.
    pub const Below: Accuracy = Accuracy(-1);
    /// The result is exact.
    pub const Exact: Accuracy = Accuracy(0);
    /// The result is larger than the exact value.
    pub const Above: Accuracy = Accuracy(1);

    fn from_above(above: bool) -> Self {
        if above {
            Accuracy::Above
        } else {
            Accuracy::Below
        }
    }
}

/// Go's `Accuracy.String`: `Below`, `Exact`, `Above`, or `Accuracy(n)`.
impl fmt::Display for Accuracy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Accuracy::Below => f.write_str("Below"),
            Accuracy::Exact => f.write_str("Exact"),
            Accuracy::Above => f.write_str("Above"),
            Accuracy(n) => write!(f, "Accuracy({n})"),
        }
    }
}

impl fmt::Debug for Accuracy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Go's `big.ErrNaN`: an operation whose IEEE 754 result would be NaN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrNaN {
    msg: &'static str,
}

impl ErrNaN {
    fn new(msg: &'static str) -> Self {
        Self { msg }
    }
}

impl fmt::Display for ErrNaN {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.msg)
    }
}

impl std::error::Error for ErrNaN {}

/// A failed text, JSON or gob conversion, with Go's message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    msg: String,
}

impl ParseError {
    fn new(msg: impl Into<String>) -> Self {
        Self { msg: msg.into() }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for ParseError {}

/// A parsed Go `fmt` directive (`%+08.3x` and so on) for the Go-compatible
/// `format` methods of [`Int`] and [`Float`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FormatSpec {
    /// The `+` flag.
    pub plus: bool,
    /// The space flag.
    pub space: bool,
    /// The `#` flag.
    pub sharp: bool,
    /// The `-` flag (left-justify).
    pub minus: bool,
    /// The `0` flag (zero padding).
    pub zero: bool,
    /// The field width.
    pub width: Option<usize>,
    /// The precision.
    pub precision: Option<usize>,
}

impl FormatSpec {
    /// Parse a single directive such as `"%+#08.3x"` into flags and verb.
    /// Returns `None` unless the input is exactly one directive.
    pub fn parse(directive: &str) -> Option<(FormatSpec, char)> {
        let rest = directive.strip_prefix('%')?;
        let mut spec = FormatSpec::default();
        let mut chars = rest.char_indices().peekable();
        while let Some(&(_, c)) = chars.peek() {
            match c {
                '+' => spec.plus = true,
                ' ' => spec.space = true,
                '#' => spec.sharp = true,
                '-' => spec.minus = true,
                '0' => spec.zero = true,
                _ => break,
            }
            chars.next();
        }
        let number = |chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>| {
            let mut value: Option<usize> = None;
            while let Some(&(_, c)) = chars.peek() {
                let Some(d) = c.to_digit(10) else { break };
                value = Some(
                    value
                        .unwrap_or(0)
                        .checked_mul(10)?
                        .checked_add(d as usize)?,
                );
                chars.next();
            }
            Some(value)
        };
        spec.width = number(&mut chars)?;
        if let Some(&(_, '.')) = chars.peek() {
            chars.next();
            spec.precision = Some(number(&mut chars)?.unwrap_or(0));
        }
        let (_, verb) = chars.next()?;
        if chars.next().is_some() {
            return None;
        }
        Some((spec, verb))
    }

    /// Flags, width and precision of a Rust formatter.
    fn from_formatter(f: &fmt::Formatter<'_>) -> Self {
        FormatSpec {
            plus: f.sign_plus(),
            space: false,
            sharp: f.alternate(),
            minus: matches!(f.align(), Some(fmt::Alignment::Left)),
            zero: f.sign_aware_zero_pad(),
            width: f.width(),
            precision: f.precision(),
        }
    }
}

fn write_padding(buf: &mut String, c: char, n: usize) {
    buf.extend(std::iter::repeat_n(c, n));
}
