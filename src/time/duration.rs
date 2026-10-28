//! Go's `time.Duration`: signed nanosecond spans, `ParseDuration` and
//! `Duration.String`, ported from Go's `src/time/time.go` and `format.go`.
use super::format::quote;
use super::instant::less_than_half;
use std::fmt;
use std::ops::{Add, AddAssign, Div, Mul, Neg, Rem, Sub, SubAssign};

/// A signed nanosecond duration with Go-compatible parsing and formatting.
///
/// This type is separate from `std::time::Duration`, which represents only
/// nonnegative spans. Values use the full signed 64-bit nanosecond range;
/// arithmetic operators wrap like Go's `int64`.
///
/// The constructors are `const`, so a duration can be a constant:
///
/// ```
/// use rust_stdlib::time::Duration;
///
/// const TTL: Duration = Duration::from_mins(5);
/// assert_eq!(TTL, 5 * Duration::MINUTE);
/// assert_eq!(TTL.as_nanos(), 300_000_000_000);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Duration(i64);

/// Go's `time.Nanosecond`.
pub const NANOSECOND: Duration = Duration(1);
/// Go's `time.Microsecond`.
pub const MICROSECOND: Duration = Duration(1000);
/// Go's `time.Millisecond`.
pub const MILLISECOND: Duration = Duration(1_000_000);
/// Go's `time.Second`.
pub const SECOND: Duration = Duration(1_000_000_000);
/// Go's `time.Minute`.
pub const MINUTE: Duration = Duration(60_000_000_000);
/// Go's `time.Hour`.
pub const HOUR: Duration = Duration(3_600_000_000_000);
pub(crate) const MIN_DURATION: Duration = Duration(i64::MIN);
pub(crate) const MAX_DURATION: Duration = Duration(i64::MAX);

impl Duration {
    pub const NANOSECOND: Duration = NANOSECOND;
    pub const MICROSECOND: Duration = MICROSECOND;
    pub const MILLISECOND: Duration = MILLISECOND;
    pub const SECOND: Duration = SECOND;
    pub const MINUTE: Duration = MINUTE;
    pub const HOUR: Duration = HOUR;

    pub(crate) const ZERO: Duration = Duration(0);

    pub(crate) const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// The span as a `std::time::Duration`, with negative durations clamped
    /// to zero (already expired).
    pub(crate) const fn to_std(self) -> std::time::Duration {
        if self.0 > 0 {
            std::time::Duration::from_nanos(self.0 as u64)
        } else {
            std::time::Duration::ZERO
        }
    }

    /// Construct from an exact signed nanosecond count.
    pub const fn from_nanos(nanos: i64) -> Self {
        Self(nanos)
    }

    /// Construct from microseconds. Overflow wraps like Go's
    /// `Duration(n) * Microsecond`.
    pub const fn from_micros(micros: i64) -> Self {
        Self(micros.wrapping_mul(1000))
    }

    /// Construct from milliseconds. Overflow wraps like Go's
    /// `Duration(n) * Millisecond`.
    pub const fn from_millis(millis: i64) -> Self {
        Self(millis.wrapping_mul(1_000_000))
    }

    /// Construct from seconds. Overflow wraps like Go's
    /// `Duration(n) * Second`.
    pub const fn from_secs(secs: i64) -> Self {
        Self(secs.wrapping_mul(1_000_000_000))
    }

    /// Construct from minutes. Overflow wraps like Go's
    /// `Duration(n) * Minute`.
    pub const fn from_mins(mins: i64) -> Self {
        Self(mins.wrapping_mul(60_000_000_000))
    }

    /// Construct from hours. Overflow wraps like Go's
    /// `Duration(n) * Hour`.
    pub const fn from_hours(hours: i64) -> Self {
        Self(hours.wrapping_mul(3_600_000_000_000))
    }

    /// Return the exact signed nanosecond count.
    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    /// Go's `Nanoseconds`.
    pub const fn nanoseconds(self) -> i64 {
        self.0
    }

    /// Go's `Microseconds` (truncated toward zero).
    pub const fn microseconds(self) -> i64 {
        self.0 / 1000
    }

    /// Go's `Milliseconds` (truncated toward zero).
    pub const fn milliseconds(self) -> i64 {
        self.0 / 1_000_000
    }

    /// Go's `Seconds` as a float.
    pub const fn seconds(self) -> f64 {
        let sec = self.0 / SECOND.0;
        let nsec = self.0 % SECOND.0;
        sec as f64 + nsec as f64 / 1e9
    }

    /// Go's `Minutes` as a float.
    pub const fn minutes(self) -> f64 {
        let min = self.0 / MINUTE.0;
        let nsec = self.0 % MINUTE.0;
        min as f64 + nsec as f64 / (60.0 * 1e9)
    }

    /// Go's `Hours` as a float.
    pub const fn hours(self) -> f64 {
        let hour = self.0 / HOUR.0;
        let nsec = self.0 % HOUR.0;
        hour as f64 + nsec as f64 / (60.0 * 60.0 * 1e9)
    }

    /// Go's `Truncate`: round toward zero to a multiple of `m`; `m <= 0`
    /// returns `self` unchanged.
    pub const fn truncate(self, m: Duration) -> Duration {
        if m.0 <= 0 {
            return self;
        }
        Duration(self.0 - self.0 % m.0)
    }

    /// Go's `Round`: round to the nearest multiple of `m`, halfway values
    /// away from zero, saturating on overflow; `m <= 0` returns `self`.
    pub const fn round(self, m: Duration) -> Duration {
        if m.0 <= 0 {
            return self;
        }
        let d = self.0;
        let mut r = d % m.0;
        if d < 0 {
            r = -r;
            if less_than_half(r, m.0) {
                return Duration(d + r);
            }
            let d1 = d.wrapping_sub(m.0).wrapping_add(r);
            if d1 < d {
                return Duration(d1);
            }
            return MIN_DURATION;
        }
        if less_than_half(r, m.0) {
            return Duration(d - r);
        }
        let d1 = d.wrapping_add(m.0).wrapping_sub(r);
        if d1 > d {
            return Duration(d1);
        }
        MAX_DURATION
    }

    /// `d * n` with Go's `int64` wrapping on overflow; the `const` form of
    /// the `*` operator.
    pub const fn mul(self, n: i64) -> Duration {
        Duration(self.0.wrapping_mul(n))
    }

    /// `d * n`, or `None` on overflow.
    pub const fn checked_mul(self, n: i64) -> Option<Duration> {
        match self.0.checked_mul(n) {
            Some(v) => Some(Duration(v)),
            None => None,
        }
    }

    /// `self + rhs`, or `None` on overflow.
    pub const fn checked_add(self, rhs: Duration) -> Option<Duration> {
        match self.0.checked_add(rhs.0) {
            Some(v) => Some(Duration(v)),
            None => None,
        }
    }

    /// `self - rhs`, or `None` on overflow.
    pub const fn checked_sub(self, rhs: Duration) -> Option<Duration> {
        match self.0.checked_sub(rhs.0) {
            Some(v) => Some(Duration(v)),
            None => None,
        }
    }

    /// Go's `Abs`; the minimum duration maps to the maximum.
    pub const fn abs(self) -> Duration {
        if self.0 >= 0 {
            self
        } else if self.0 == i64::MIN {
            MAX_DURATION
        } else {
            Duration(-self.0)
        }
    }
}

impl Add for Duration {
    type Output = Duration;
    fn add(self, rhs: Duration) -> Duration {
        Duration(self.0.wrapping_add(rhs.0))
    }
}
impl AddAssign for Duration {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}
impl Sub for Duration {
    type Output = Duration;
    fn sub(self, rhs: Duration) -> Duration {
        Duration(self.0.wrapping_sub(rhs.0))
    }
}
impl SubAssign for Duration {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}
impl Neg for Duration {
    type Output = Duration;
    fn neg(self) -> Duration {
        Duration(self.0.wrapping_neg())
    }
}
impl Mul<i64> for Duration {
    type Output = Duration;
    fn mul(self, rhs: i64) -> Duration {
        Duration(self.0.wrapping_mul(rhs))
    }
}
impl Mul<Duration> for i64 {
    type Output = Duration;
    fn mul(self, rhs: Duration) -> Duration {
        Duration(self.wrapping_mul(rhs.0))
    }
}
impl Div<i64> for Duration {
    type Output = Duration;
    /// Panics on division by zero, like Go.
    fn div(self, rhs: i64) -> Duration {
        Duration(self.0.wrapping_div(rhs))
    }
}
impl Div for Duration {
    type Output = i64;
    fn div(self, rhs: Duration) -> i64 {
        self.0.wrapping_div(rhs.0)
    }
}
impl Rem for Duration {
    type Output = Duration;
    fn rem(self, rhs: Duration) -> Duration {
        Duration(self.0.wrapping_rem(rhs.0))
    }
}

impl From<std::time::Duration> for Duration {
    /// Saturates at the maximum duration.
    fn from(d: std::time::Duration) -> Self {
        Duration(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX))
    }
}

/// The error from converting a negative [`Duration`] to `std::time::Duration`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegativeDurationError(());

impl fmt::Display for NegativeDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("negative duration cannot be converted to std::time::Duration")
    }
}

impl std::error::Error for NegativeDurationError {}

impl TryFrom<Duration> for std::time::Duration {
    type Error = NegativeDurationError;
    /// Fails for negative durations, which `std::time::Duration` cannot hold.
    fn try_from(d: Duration) -> Result<Self, NegativeDurationError> {
        u64::try_from(d.0)
            .map(std::time::Duration::from_nanos)
            .map_err(|_| NegativeDurationError(()))
    }
}

impl fmt::Display for Duration {
    /// Go's `Duration.String`, e.g. `"72h3m0.5s"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&format_duration(*self))
    }
}

impl std::str::FromStr for Duration {
    type Err = ParseDurationError;

    /// Go's `ParseDuration`: a signed sequence of decimal quantities with
    /// units `ns`, `us`, `µs`, `ms`, `s`, `m` and `h`, e.g. `"-1.5h"`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_duration(input)
    }
}

/// Go's `fmtFrac`: write the low `prec` digits of `v` as a fraction with
/// trailing zeros omitted; return the remaining high digits.
fn fmt_frac(buf: &mut Vec<u8>, mut v: u64, prec: usize) -> u64 {
    let mut print = false;
    for _ in 0..prec {
        let digit = v % 10;
        print = print || digit != 0;
        if print {
            buf.push(digit as u8 + b'0');
        }
        v /= 10;
    }
    if print {
        buf.push(b'.');
    }
    v
}

/// Go's `fmtInt`, in reverse order.
fn fmt_int(buf: &mut Vec<u8>, mut v: u64) {
    if v == 0 {
        buf.push(b'0');
    }
    while v > 0 {
        buf.push((v % 10) as u8 + b'0');
        v /= 10;
    }
}

/// Format a duration using Go's canonical `Duration.String` representation.
fn format_duration(duration: Duration) -> String {
    // Built in reverse, as Go fills its buffer from the end.
    let mut buf = Vec::with_capacity(32);
    let mut u = duration.0.unsigned_abs();
    let neg = duration.0 < 0;
    if u < SECOND.0 as u64 {
        buf.push(b's');
        let prec = match u {
            0 => {
                buf.push(b'0');
                return String::from("0s");
            }
            _ if u < MICROSECOND.0 as u64 => {
                buf.push(b'n');
                0
            }
            _ if u < MILLISECOND.0 as u64 => {
                // "µ" (U+00B5) reversed.
                buf.extend_from_slice(&[0xb5, 0xc2]);
                3
            }
            _ => {
                buf.push(b'm');
                6
            }
        };
        u = fmt_frac(&mut buf, u, prec);
        fmt_int(&mut buf, u);
    } else {
        buf.push(b's');
        u = fmt_frac(&mut buf, u, 9);
        fmt_int(&mut buf, u % 60);
        u /= 60;
        if u > 0 {
            buf.push(b'm');
            fmt_int(&mut buf, u % 60);
            u /= 60;
            if u > 0 {
                buf.push(b'h');
                fmt_int(&mut buf, u);
            }
        }
    }
    if neg {
        buf.push(b'-');
    }
    buf.reverse();
    String::from_utf8(buf).unwrap_or_default()
}

/// Go's `ParseDuration` error: `time: <message> "<input>"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseDurationError {
    message: String,
    value: String,
}

impl ParseDurationError {
    fn new(message: impl Into<String>, value: &str) -> Self {
        Self {
            message: message.into(),
            value: value.into(),
        }
    }
}

impl fmt::Display for ParseDurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "time: {} {}", self.message, quote(self.value.as_bytes()))
    }
}

impl std::error::Error for ParseDurationError {}

/// Go's `leadingInt`: consume leading decimal digits.
pub(crate) fn leading_int(s: &[u8]) -> Option<(u64, &[u8])> {
    let mut x = 0u64;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            break;
        }
        if x > (1 << 63) / 10 {
            return None;
        }
        x = x * 10 + u64::from(c - b'0');
        if x > 1 << 63 {
            return None;
        }
        i += 1;
    }
    Some((x, &s[i..]))
}

/// Go's `leadingFraction`: consume digits, ignoring precision overflow.
fn leading_fraction(s: &[u8]) -> (u64, f64, &[u8]) {
    let mut x = 0u64;
    let mut scale = 1.0f64;
    let mut overflow = false;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            break;
        }
        i += 1;
        if overflow {
            continue;
        }
        if x > (i64::MAX as u64) / 10 {
            overflow = true;
            continue;
        }
        let y = x * 10 + u64::from(c - b'0');
        if y > 1 << 63 {
            overflow = true;
            continue;
        }
        x = y;
        scale *= 10.0;
    }
    (x, scale, &s[i..])
}

/// Parse a duration such as `"-1.5h"` or `"2h45m"` (Go's `ParseDuration`).
///
/// Units are `ns`, `us`, `µs`, `μs`, `ms`, `s`, `m`, and `h`. Fractional
/// quantities are truncated to nanosecond precision exactly as Go does.
fn parse_duration(input: &str) -> Result<Duration, ParseDurationError> {
    let invalid = || ParseDurationError::new("invalid duration", input);
    let mut s = input.as_bytes();
    let mut d = 0u64;
    let mut neg = false;
    if let Some(&c) = s.first() {
        if c == b'-' || c == b'+' {
            neg = c == b'-';
            s = &s[1..];
        }
    }
    if s == b"0" {
        return Ok(Duration(0));
    }
    if s.is_empty() {
        return Err(invalid());
    }
    while !s.is_empty() {
        if !(s[0] == b'.' || s[0].is_ascii_digit()) {
            return Err(invalid());
        }
        let pl = s.len();
        let (mut v, rest) = leading_int(s).ok_or_else(invalid)?;
        s = rest;
        let pre = pl != s.len();
        let mut post = false;
        let (mut f, mut scale) = (0u64, 1.0f64);
        if s.first() == Some(&b'.') {
            s = &s[1..];
            let pl = s.len();
            (f, scale, s) = leading_fraction(s);
            post = pl != s.len();
        }
        if !pre && !post {
            return Err(invalid());
        }
        let i = s
            .iter()
            .position(|&c| c == b'.' || c.is_ascii_digit())
            .unwrap_or(s.len());
        if i == 0 {
            return Err(ParseDurationError::new("missing unit in duration", input));
        }
        let (u, rest) = s.split_at(i);
        s = rest;
        let unit: u64 = match u {
            b"ns" => 1,
            b"us" | b"\xc2\xb5s" | b"\xce\xbcs" => 1000,
            b"ms" => 1_000_000,
            b"s" => 1_000_000_000,
            b"m" => 60_000_000_000,
            b"h" => 3_600_000_000_000,
            _ => {
                return Err(ParseDurationError::new(
                    format!("unknown unit {} in duration", quote(u)),
                    input,
                ))
            }
        };
        if v > (1 << 63) / unit {
            return Err(invalid());
        }
        v *= unit;
        if f > 0 {
            // Go's float64 expression, truncated toward zero.
            v += (f as f64 * (unit as f64 / scale)) as u64;
            if v > 1 << 63 {
                return Err(invalid());
            }
        }
        // Go's uint64 sum wraps (2^63 + 2^63 is 0).
        d = d.wrapping_add(v);
        if d > 1 << 63 {
            return Err(invalid());
        }
    }
    if neg {
        return Ok(Duration((d as i64).wrapping_neg()));
    }
    if d > i64::MAX as u64 {
        return Err(invalid());
    }
    Ok(Duration(d as i64))
}
