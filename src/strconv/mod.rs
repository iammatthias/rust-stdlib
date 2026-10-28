//! Conversions to and from string representations of basic data types
//! (Go `strconv`).
//!
//! Go strings are byte sequences, so the quoting functions accept anything
//! that is `AsRef<[u8]>` (`&str`, `String`, `&[u8]`, `Vec<u8>`) and
//! [`unquote`] returns bytes. The `Parse*` functions take `&str`.
//!
//! Go's `(value, error)` returns carry a meaningful value alongside
//! [`ERR_RANGE`] (`±Inf`, or the maximum magnitude integer). The parsers
//! return `Result`; the error keeps that value ([`NumError::int_value`],
//! [`NumError::float_value`], ...).
//!
//! For decimal integers and floats that need none of Go's extras (base
//! prefixes, underscores, `Inf`/`NaN` spellings), `str::parse` and
//! `to_string` do the same job.
//!
//! ```
//! use rust_stdlib::strconv;
//! assert_eq!(strconv::parse_int("-0x_1F", 0, 64)?, -31);
//! assert_eq!(strconv::format_float(1.0 / 3.0, b'g', -1, 64), "0.3333333333333333");
//! assert_eq!(strconv::quote("hi\n"), "\"hi\\n\"");
//! assert_eq!(
//!     strconv::parse_int("300", 10, 8).unwrap_err().to_string(),
//!     "strconv.ParseInt: parsing \"300\": value out of range"
//! );
//! # Ok::<(), strconv::NumError>(())
//! ```

use std::fmt;

mod atof;
mod ftoa;
mod quote;

pub use quote::{
    append_quote, append_quote_rune, append_quote_rune_to_ascii, append_quote_rune_to_graphic,
    append_quote_to_ascii, append_quote_to_graphic, can_backquote, is_graphic, is_print, quote,
    quote_rune, quote_rune_to_ascii, quote_rune_to_graphic, quote_to_ascii, quote_to_graphic,
    quoted_prefix, unquote, unquote_char, Rune,
};

/// The size in bits of an `int` or `uint` value (Go `IntSize`).
pub const INT_SIZE: usize = usize::BITS as usize;

/// Why a conversion failed: Go's `ErrRange`, `ErrSyntax` and the dynamic
/// "invalid base" and "invalid bit size" errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The value is out of range for the target type.
    Range,
    /// The value does not have the right syntax for the target type.
    Syntax,
    /// The base passed to `ParseInt`/`ParseUint` is not 0 or 2..=36.
    InvalidBase(i32),
    /// The bit size passed to a parser is not valid.
    InvalidBitSize(i32),
}

/// Indicates that a value is out of range for the target type (Go `ErrRange`).
pub const ERR_RANGE: Error = Error::Range;
/// Indicates that a value does not have the right syntax for the target type
/// (Go `ErrSyntax`).
pub const ERR_SYNTAX: Error = Error::Syntax;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Range => f.write_str("value out of range"),
            Error::Syntax => f.write_str("invalid syntax"),
            Error::InvalidBase(b) => write!(f, "invalid base {b}"),
            Error::InvalidBitSize(b) => write!(f, "invalid bit size {b}"),
        }
    }
}

impl std::error::Error for Error {}

/// A failed conversion (Go `*NumError`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NumError {
    /// The failing function (ParseBool, ParseInt, ParseUint, ParseFloat,
    /// ParseComplex, Atoi).
    pub func: String,
    /// The input.
    pub num: String,
    /// The reason the conversion failed.
    pub err: Error,
    // The value Go returns alongside the error.
    partial: Partial,
}

/// The value a failed parse still produces: zero, or on [`ERR_RANGE`] the
/// maximum magnitude (integers) or infinity (floats).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Partial {
    Zero,
    Int(i64),
    Uint(u64),
    Float(u64),
    Complex(u64, u64),
}

trait IntoPartial {
    fn into_partial(self) -> Partial;
}

impl IntoPartial for bool {
    fn into_partial(self) -> Partial {
        Partial::Zero
    }
}

impl IntoPartial for i64 {
    fn into_partial(self) -> Partial {
        Partial::Int(self)
    }
}

impl IntoPartial for isize {
    fn into_partial(self) -> Partial {
        Partial::Int(self as i64)
    }
}

impl IntoPartial for u64 {
    fn into_partial(self) -> Partial {
        Partial::Uint(self)
    }
}

impl IntoPartial for f64 {
    fn into_partial(self) -> Partial {
        Partial::Float(self.to_bits())
    }
}

impl IntoPartial for Complex {
    fn into_partial(self) -> Partial {
        Partial::Complex(self.re.to_bits(), self.im.to_bits())
    }
}

impl NumError {
    fn new(func: &str, num: &str, err: Error, partial: Partial) -> NumError {
        NumError {
            func: func.to_string(),
            num: num.to_string(),
            err,
            partial,
        }
    }

    /// The value Go's `ParseInt` and `Atoi` return with the error: the
    /// maximum magnitude integer of the bit size and sign on [`ERR_RANGE`],
    /// otherwise 0.
    pub fn int_value(&self) -> i64 {
        match self.partial {
            Partial::Int(v) => v,
            _ => 0,
        }
    }

    /// The value Go's `ParseUint` returns with the error: the maximum for the
    /// bit size on [`ERR_RANGE`], otherwise 0.
    pub fn uint_value(&self) -> u64 {
        match self.partial {
            Partial::Uint(v) => v,
            _ => 0,
        }
    }

    /// The value Go's `ParseFloat` returns with the error: plus or minus
    /// infinity on [`ERR_RANGE`], otherwise 0.
    pub fn float_value(&self) -> f64 {
        match self.partial {
            Partial::Float(bits) => f64::from_bits(bits),
            _ => 0.0,
        }
    }

    /// The value Go's `ParseComplex` returns with the error: the components
    /// are plus or minus infinity on [`ERR_RANGE`], otherwise 0.
    pub fn complex_value(&self) -> Complex {
        match self.partial {
            Partial::Complex(re, im) => Complex {
                re: f64::from_bits(re),
                im: f64::from_bits(im),
            },
            _ => Complex { re: 0.0, im: 0.0 },
        }
    }
}

impl fmt::Display for NumError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "strconv.{}: parsing {}: {}",
            self.func,
            quote(&self.num),
            self.err
        )
    }
}

impl std::error::Error for NumError {
    /// Go's `Unwrap`.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.err)
    }
}

/// A complex number, the Rust counterpart of Go's `complex128`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Complex {
    pub re: f64,
    pub im: f64,
}

fn strict<T: IntoPartial + Copy>(
    func: &str,
    s: &str,
    (v, err): (T, Option<Error>),
) -> Result<T, NumError> {
    match err {
        None => Ok(v),
        Some(e) => Err(NumError::new(func, s, e, v.into_partial())),
    }
}

/// lower(c) is a lower-case letter if and only if c is either that lower-case
/// letter or the equivalent upper-case letter.
pub(crate) fn lower(c: u8) -> u8 {
    c | (b'x' - b'X')
}

// ---------------------------------------------------------------- bool

fn parse_bool_inner(s: &str) -> (bool, Option<Error>) {
    match s {
        "1" | "t" | "T" | "true" | "TRUE" | "True" => (true, None),
        "0" | "f" | "F" | "false" | "FALSE" | "False" => (false, None),
        _ => (false, Some(Error::Syntax)),
    }
}

/// Returns the boolean value represented by the string. It accepts 1, t, T,
/// TRUE, true, True, 0, f, F, FALSE, false, False.
pub fn parse_bool(s: &str) -> Result<bool, NumError> {
    strict("ParseBool", s, parse_bool_inner(s))
}

// ------------------------------------------------------------- integers

/// Reports whether the underscores in s are allowed: only between digits or
/// between a base prefix and a digit.
pub(crate) fn underscore_ok(mut s: &[u8]) -> bool {
    // saw tracks the last character class: ^ beginning, 0 digit or base
    // prefix, _ underscore, ! none of the above.
    let mut saw = b'^';
    let mut i = 0;

    // Optional sign.
    if !s.is_empty() && (s[0] == b'-' || s[0] == b'+') {
        s = &s[1..];
    }

    // Optional base prefix.
    let mut hex = false;
    if s.len() >= 2 && s[0] == b'0' && matches!(lower(s[1]), b'b' | b'o' | b'x') {
        i = 2;
        saw = b'0'; // base prefix counts as a digit for "underscore as digit separator"
        hex = lower(s[1]) == b'x';
    }

    // Number proper.
    while i < s.len() {
        // Digits are always okay.
        if s[i].is_ascii_digit() || hex && (b'a'..=b'f').contains(&lower(s[i])) {
            saw = b'0';
            i += 1;
            continue;
        }
        // Underscore must follow digit.
        if s[i] == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            i += 1;
            continue;
        }
        // Underscore must also be followed by digit.
        if saw == b'_' {
            return false;
        }
        // Saw non-digit, non-underscore.
        saw = b'!';
        i += 1;
    }
    saw != b'_'
}

fn parse_uint_inner(s: &[u8], mut base: i32, mut bit_size: i32) -> (u64, Option<Error>) {
    if s.is_empty() {
        return (0, Some(Error::Syntax));
    }

    let base0 = base == 0;
    let s0 = s;
    let mut s = s;
    if (2..=36).contains(&base) {
        // valid base; nothing to do
    } else if base == 0 {
        // Look for octal, hex prefix.
        base = 10;
        if s[0] == b'0' {
            if s.len() >= 3 && lower(s[1]) == b'b' {
                base = 2;
                s = &s[2..];
            } else if s.len() >= 3 && lower(s[1]) == b'o' {
                base = 8;
                s = &s[2..];
            } else if s.len() >= 3 && lower(s[1]) == b'x' {
                base = 16;
                s = &s[2..];
            } else {
                base = 8;
                s = &s[1..];
            }
        }
    } else {
        return (0, Some(Error::InvalidBase(base)));
    }

    if bit_size == 0 {
        bit_size = INT_SIZE as i32;
    } else if !(0..=64).contains(&bit_size) {
        return (0, Some(Error::InvalidBitSize(bit_size)));
    }

    // Cutoff is the smallest number such that cutoff*base > maxUint64.
    let cutoff = u64::MAX / base as u64 + 1;
    let max_val = if bit_size == 64 {
        u64::MAX
    } else {
        (1u64 << bit_size) - 1
    };

    let mut underscores = false;
    let mut n: u64 = 0;
    for &c in s {
        let d = if c == b'_' && base0 {
            underscores = true;
            continue;
        } else if c.is_ascii_digit() {
            c - b'0'
        } else if lower(c).is_ascii_lowercase() {
            lower(c) - b'a' + 10
        } else {
            return (0, Some(Error::Syntax));
        };

        if d as i32 >= base {
            return (0, Some(Error::Syntax));
        }

        if n >= cutoff {
            // n*base overflows
            return (max_val, Some(Error::Range));
        }
        n *= base as u64;

        let n1 = n.wrapping_add(d as u64);
        if n1 < n || n1 > max_val {
            // n+d overflows
            return (max_val, Some(Error::Range));
        }
        n = n1;
    }

    if underscores && !underscore_ok(s0) {
        return (0, Some(Error::Syntax));
    }

    (n, None)
}

fn parse_int_inner(s: &str, base: i32, mut bit_size: i32) -> (i64, Option<Error>) {
    let mut s = s.as_bytes();
    if s.is_empty() {
        return (0, Some(Error::Syntax));
    }

    // Pick off leading sign.
    let mut neg = false;
    match s[0] {
        b'+' => s = &s[1..],
        b'-' => {
            s = &s[1..];
            neg = true;
        }
        _ => {}
    }

    // Convert unsigned and check range.
    let (un, err) = parse_uint_inner(s, base, bit_size);
    if err.is_some() && err != Some(Error::Range) {
        return (0, err);
    }

    if bit_size == 0 {
        bit_size = INT_SIZE as i32;
    }

    let cutoff = 1u64 << (bit_size - 1) as u32;
    if !neg && un >= cutoff {
        return ((cutoff - 1) as i64, Some(Error::Range));
    }
    if neg && un > cutoff {
        return ((cutoff as i64).wrapping_neg(), Some(Error::Range));
    }
    let n = un as i64;
    (if neg { n.wrapping_neg() } else { n }, None)
}

/// Like [`parse_int`] but for unsigned numbers. A sign prefix is not permitted.
pub fn parse_uint(s: &str, base: i32, bit_size: i32) -> Result<u64, NumError> {
    strict(
        "ParseUint",
        s,
        parse_uint_inner(s.as_bytes(), base, bit_size),
    )
}

/// Interprets a string s in the given base (0, 2 to 36) and bit size (0 to 64)
/// and returns the corresponding value.
///
/// The string may begin with a leading sign: "+" or "-". If base is 0, the
/// true base is implied by the string's prefix following the sign: 2 for "0b",
/// 8 for "0" or "0o", 16 for "0x", and 10 otherwise; for base 0 only,
/// underscores are permitted as in Go integer literals. Bit sizes 0, 8, 16,
/// 32 and 64 correspond to int, int8, int16, int32 and int64.
pub fn parse_int(s: &str, base: i32, bit_size: i32) -> Result<i64, NumError> {
    strict("ParseInt", s, parse_int_inner(s, base, bit_size))
}

fn atoi_inner(s: &str) -> (isize, Option<Error>) {
    let (v, err) = parse_int_inner(s, 10, 0);
    (v as isize, err)
}

/// Equivalent to `parse_int(s, 10, 0)` converted to `isize`; errors report
/// `Atoi` as the function.
pub fn atoi(s: &str) -> Result<isize, NumError> {
    strict("Atoi", s, atoi_inner(s))
}

const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Formats u in the given base. Panics, like Go, if the base is not 2..=36.
fn format_bits(dst: &mut Vec<u8>, mut u: u64, base: i32, neg: bool) {
    if !(2..=36).contains(&base) {
        panic!("strconv: illegal AppendInt/FormatInt base");
    }
    let mut a = [0u8; 65]; // +1 for sign of 64bit value in base 2
    let mut i = a.len();
    if neg {
        u = u.wrapping_neg();
    }
    let b = base as u64;
    while u >= b {
        i -= 1;
        a[i] = DIGITS[(u % b) as usize];
        u /= b;
    }
    i -= 1;
    a[i] = DIGITS[u as usize];
    if neg {
        i -= 1;
        a[i] = b'-';
    }
    dst.extend_from_slice(&a[i..]);
}

fn into_string(v: Vec<u8>) -> String {
    String::from_utf8(v).unwrap_or_default()
}

/// Returns the string representation of i in the given base, for 2 <= base
/// <= 36, using lower-case letters for digit values >= 10.
pub fn format_uint(i: u64, base: i32) -> String {
    let mut v = Vec::new();
    format_bits(&mut v, i, base, false);
    into_string(v)
}

/// Returns the string representation of i in the given base, for 2 <= base
/// <= 36, using lower-case letters for digit values >= 10.
pub fn format_int(i: i64, base: i32) -> String {
    let mut v = Vec::new();
    append_int(&mut v, i, base);
    into_string(v)
}

/// Appends the string form of the integer i, as generated by [`format_int`].
pub fn append_int(dst: &mut Vec<u8>, i: i64, base: i32) {
    format_bits(dst, i as u64, base, i < 0);
}

/// Appends the string form of the unsigned integer i, as generated by
/// [`format_uint`].
pub fn append_uint(dst: &mut Vec<u8>, i: u64, base: i32) {
    format_bits(dst, i, base, false);
}

// --------------------------------------------------------------- floats

fn parse_float_inner(s: &[u8], bit_size: i32) -> (f64, Option<Error>) {
    let (f, n, err) = atof::parse_float_prefix(s, bit_size);
    if n != s.len() {
        return (0.0, Some(Error::Syntax));
    }
    (f, err)
}

/// Converts the string s to a floating-point number with the precision
/// specified by bit_size: 32 for `f32`, or 64 for `f64`. When bit_size is 32,
/// the result is still an `f64` but converts to `f32` without changing its
/// value.
///
/// Accepts decimal and hexadecimal floating-point numbers as defined by the
/// Go syntax for floating-point literals (including underscores), rounds to
/// nearest even, and recognizes "NaN", "Inf" and "Infinity" (signed, case
/// insensitive). If s rounds to infinity the error is [`ERR_RANGE`].
pub fn parse_float(s: &str, bit_size: i32) -> Result<f64, NumError> {
    strict("ParseFloat", s, parse_float_inner(s.as_bytes(), bit_size))
}

/// Converts the floating-point number f to a string according to the format
/// fmt and precision prec, rounding as if f came from a float of bit_size bits
/// (32 or 64; any other value panics, like Go).
///
/// fmt is one of 'b', 'e', 'E', 'f', 'g', 'G', 'x' or 'X'. A negative prec
/// selects the smallest number of digits that round-trips.
pub fn format_float(f: f64, fmt: u8, prec: i32, bit_size: i32) -> String {
    let mut v = Vec::new();
    append_float(&mut v, f, fmt, prec, bit_size);
    into_string(v)
}

/// Appends the string form of f, as generated by [`format_float`], to dst.
pub fn append_float(dst: &mut Vec<u8>, f: f64, fmt: u8, prec: i32, bit_size: i32) {
    match bit_size {
        32 => ftoa::ftoa32(dst, f as f32, fmt, prec),
        64 => ftoa::ftoa64(dst, f, fmt, prec),
        _ => panic!("strconv: illegal AppendFloat/FormatFloat bitSize"),
    }
}

// ------------------------------------------------------------- complex

fn parse_complex_inner(s: &[u8], bit_size: i32) -> (Complex, Option<Error>) {
    let zero = Complex::default();
    let size = if bit_size == 64 { 32 } else { 64 }; // complex64 uses float32 parts

    // Remove parentheses, if any.
    let mut s = s;
    if s.len() >= 2 && s[0] == b'(' && s[s.len() - 1] == b')' {
        s = &s[1..s.len() - 1];
    }

    let mut pending = None; // pending range error

    // Read real part (possibly imaginary part if followed by 'i').
    let (re, n, err) = atof::parse_float_prefix(s, size);
    if let Some(e) = err {
        if e != Error::Range {
            return (zero, Some(e));
        }
        pending = err;
    }
    s = &s[n..];

    // If we have nothing left, we're done.
    if s.is_empty() {
        return (Complex { re, im: 0.0 }, pending);
    }

    // Otherwise, look at the next character.
    match s[0] {
        b'+' => {
            // Consume the '+' to avoid an error if we have "+NaNi", but do
            // this only if we don't have a "++" (don't hide that error).
            if s.len() > 1 && s[1] != b'+' {
                s = &s[1..];
            }
        }
        b'-' => {}
        b'i' => {
            // If 'i' is the last character, we only have an imaginary part.
            if s.len() == 1 {
                return (Complex { re: 0.0, im: re }, pending);
            }
            return (zero, Some(Error::Syntax));
        }
        _ => return (zero, Some(Error::Syntax)),
    }

    // Read imaginary part.
    let (im, n, err) = atof::parse_float_prefix(s, size);
    if let Some(e) = err {
        if e != Error::Range {
            return (zero, Some(e));
        }
        pending = err;
    }
    s = &s[n..];
    if s != b"i" {
        return (zero, Some(Error::Syntax));
    }
    (Complex { re, im }, pending)
}

/// Converts the string s to a complex number with the precision specified by
/// bit_size: 64 for complex64, or 128 for complex128. The form is N, Ni, or
/// N±Ni, where N is a float as recognized by [`parse_float`]; it may be
/// parenthesized and cannot contain spaces.
pub fn parse_complex(s: &str, bit_size: i32) -> Result<Complex, NumError> {
    strict(
        "ParseComplex",
        s,
        parse_complex_inner(s.as_bytes(), bit_size),
    )
}

/// Converts the complex number c to a string of the form (a+bi), with the
/// parts formatted as by [`format_float`]. bit_size must be 64 or 128 (else
/// this panics, like Go).
pub fn format_complex(c: Complex, fmt: u8, prec: i32, bit_size: i32) -> String {
    if bit_size != 64 && bit_size != 128 {
        panic!("invalid bitSize");
    }
    let bit_size = bit_size >> 1; // complex64 uses float32 internally
    let mut dst = vec![b'('];
    append_float(&mut dst, c.re, fmt, prec, bit_size);
    let i = dst.len();
    append_float(&mut dst, c.im, fmt, prec, bit_size);
    // Check if imaginary part has a sign. If not, add one.
    if dst[i] != b'+' && dst[i] != b'-' {
        dst.insert(i, b'+');
    }
    dst.extend_from_slice(b"i)");
    into_string(dst)
}
