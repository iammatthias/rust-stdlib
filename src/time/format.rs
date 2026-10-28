//! Go layout-string formatting and parsing (`Format`, `AppendFormat`,
//! `Parse`, `ParseInLocation`, `ParseError`) and the RFC 3339 fast paths,
//! ported from Go's `src/time/format.go` and `format_rfc3339.go`.
//!
//! Layouts and values are processed as bytes, exactly as Go does. Parsing
//! needs no budget: every step consumes input and the work is linear in the
//! layout and value lengths.
use super::duration::leading_int;
use super::instant::{
    date, days_before, days_in, is_leap, Month, Time, LONG_DAY_NAMES, LONG_MONTH_NAMES,
};
use super::location::{local, Location};
use super::Error;
use std::fmt;

/// Go's reference layout, `time.Layout`.
pub const LAYOUT: &str = "01/02 03:04:05PM '06 -0700";
pub const ANSIC: &str = "Mon Jan _2 15:04:05 2006";
pub const UNIX_DATE: &str = "Mon Jan _2 15:04:05 MST 2006";
pub const RUBY_DATE: &str = "Mon Jan 02 15:04:05 -0700 2006";
pub const RFC822: &str = "02 Jan 06 15:04 MST";
pub const RFC822Z: &str = "02 Jan 06 15:04 -0700";
pub const RFC850: &str = "Monday, 02-Jan-06 15:04:05 MST";
pub const RFC1123: &str = "Mon, 02 Jan 2006 15:04:05 MST";
pub const RFC1123Z: &str = "Mon, 02 Jan 2006 15:04:05 -0700";
pub const RFC3339: &str = "2006-01-02T15:04:05Z07:00";
pub const RFC3339_NANO: &str = "2006-01-02T15:04:05.999999999Z07:00";
pub const KITCHEN: &str = "3:04PM";
pub const STAMP: &str = "Jan _2 15:04:05";
pub const STAMP_MILLI: &str = "Jan _2 15:04:05.000";
pub const STAMP_MICRO: &str = "Jan _2 15:04:05.000000";
pub const STAMP_NANO: &str = "Jan _2 15:04:05.000000000";
/// Go's `time.DateTime` layout (the struct [`super::DateTime`] is unrelated).
pub const DATE_TIME: &str = "2006-01-02 15:04:05";
pub const DATE_ONLY: &str = "2006-01-02";
pub const TIME_ONLY: &str = "15:04:05";

const STD_NEED_DATE: i32 = 1 << 8;
const STD_NEED_YDAY: i32 = 1 << 9;
const STD_NEED_CLOCK: i32 = 1 << 10;
const STD_ARG_SHIFT: i32 = 16;
const STD_SEPARATOR_SHIFT: i32 = 28;
const STD_MASK: i32 = (1 << STD_ARG_SHIFT) - 1;

const STD_LONG_MONTH: i32 = 1 + STD_NEED_DATE;
const STD_MONTH: i32 = 2 + STD_NEED_DATE;
const STD_NUM_MONTH: i32 = 3 + STD_NEED_DATE;
const STD_ZERO_MONTH: i32 = 4 + STD_NEED_DATE;
const STD_LONG_WEEK_DAY: i32 = 5 + STD_NEED_DATE;
const STD_WEEK_DAY: i32 = 6 + STD_NEED_DATE;
const STD_DAY: i32 = 7 + STD_NEED_DATE;
const STD_UNDER_DAY: i32 = 8 + STD_NEED_DATE;
const STD_ZERO_DAY: i32 = 9 + STD_NEED_DATE;
const STD_UNDER_YEAR_DAY: i32 = 10 + STD_NEED_YDAY;
const STD_ZERO_YEAR_DAY: i32 = 11 + STD_NEED_YDAY;
const STD_HOUR: i32 = 12 + STD_NEED_CLOCK;
const STD_HOUR12: i32 = 13 + STD_NEED_CLOCK;
const STD_ZERO_HOUR12: i32 = 14 + STD_NEED_CLOCK;
const STD_MINUTE: i32 = 15 + STD_NEED_CLOCK;
const STD_ZERO_MINUTE: i32 = 16 + STD_NEED_CLOCK;
const STD_SECOND: i32 = 17 + STD_NEED_CLOCK;
const STD_ZERO_SECOND: i32 = 18 + STD_NEED_CLOCK;
const STD_LONG_YEAR: i32 = 19 + STD_NEED_DATE;
const STD_YEAR: i32 = 20 + STD_NEED_DATE;
const STD_PM: i32 = 21 + STD_NEED_CLOCK;
const STD_LOWER_PM: i32 = 22 + STD_NEED_CLOCK;
const STD_TZ: i32 = 23;
const STD_ISO8601_TZ: i32 = 24;
const STD_ISO8601_SECONDS_TZ: i32 = 25;
const STD_ISO8601_SHORT_TZ: i32 = 26;
const STD_ISO8601_COLON_TZ: i32 = 27;
const STD_ISO8601_COLON_SECONDS_TZ: i32 = 28;
const STD_NUM_TZ: i32 = 29;
const STD_NUM_SECONDS_TZ: i32 = 30;
const STD_NUM_SHORT_TZ: i32 = 31;
const STD_NUM_COLON_TZ: i32 = 32;
const STD_NUM_COLON_SECONDS_TZ: i32 = 33;
const STD_FRAC_SECOND0: i32 = 34;
const STD_FRAC_SECOND9: i32 = 35;

const STD0X: [i32; 6] = [
    STD_ZERO_MONTH,
    STD_ZERO_DAY,
    STD_ZERO_HOUR12,
    STD_ZERO_MINUTE,
    STD_ZERO_SECOND,
    STD_YEAR,
];

const SHORT_DAY_NAMES: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const SHORT_MONTH_NAMES: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn starts_with_lower_case(s: &[u8]) -> bool {
    s.first().is_some_and(u8::is_ascii_lowercase)
}

fn at(s: &[u8], i: usize, pat: &[u8]) -> bool {
    s.get(i..i + pat.len()) == Some(pat)
}

fn is_digit(s: &[u8], i: usize) -> bool {
    s.get(i).is_some_and(u8::is_ascii_digit)
}

fn std_frac_second(code: i32, n: usize, c: u8) -> i32 {
    let std = code | (((n & 0xfff) as i32) << STD_ARG_SHIFT);
    if c == b'.' {
        std
    } else {
        std | 1 << STD_SEPARATOR_SHIFT
    }
}

fn digits_len(std: i32) -> usize {
    ((std >> STD_ARG_SHIFT) & 0xfff) as usize
}

fn separator(std: i32) -> u8 {
    if std >> STD_SEPARATOR_SHIFT == 0 {
        b'.'
    } else {
        b','
    }
}

/// Go's `nextStdChunk`: (prefix length, std code, suffix start).
fn next_std_chunk(layout: &[u8]) -> (usize, i32, usize) {
    let n = layout.len();
    for i in 0..n {
        let c = layout[i];
        match c {
            b'J' => {
                if at(layout, i, b"Jan") {
                    if at(layout, i, b"January") {
                        return (i, STD_LONG_MONTH, i + 7);
                    }
                    if !starts_with_lower_case(&layout[i + 3..]) {
                        return (i, STD_MONTH, i + 3);
                    }
                }
            }
            b'M' => {
                if n >= i + 3 {
                    if at(layout, i, b"Mon") {
                        if at(layout, i, b"Monday") {
                            return (i, STD_LONG_WEEK_DAY, i + 6);
                        }
                        if !starts_with_lower_case(&layout[i + 3..]) {
                            return (i, STD_WEEK_DAY, i + 3);
                        }
                    }
                    if at(layout, i, b"MST") {
                        return (i, STD_TZ, i + 3);
                    }
                }
            }
            b'0' => {
                if n >= i + 2 && (b'1'..=b'6').contains(&layout[i + 1]) {
                    return (i, STD0X[usize::from(layout[i + 1] - b'1')], i + 2);
                }
                if at(layout, i + 1, b"02") {
                    return (i, STD_ZERO_YEAR_DAY, i + 3);
                }
            }
            b'1' => {
                if at(layout, i + 1, b"5") {
                    return (i, STD_HOUR, i + 2);
                }
                return (i, STD_NUM_MONTH, i + 1);
            }
            b'2' => {
                if at(layout, i, b"2006") {
                    return (i, STD_LONG_YEAR, i + 4);
                }
                return (i, STD_DAY, i + 1);
            }
            b'_' => {
                if at(layout, i + 1, b"2") {
                    if at(layout, i + 1, b"2006") {
                        return (i + 1, STD_LONG_YEAR, i + 5);
                    }
                    return (i, STD_UNDER_DAY, i + 2);
                }
                if at(layout, i + 1, b"_2") {
                    return (i, STD_UNDER_YEAR_DAY, i + 3);
                }
            }
            b'3' => return (i, STD_HOUR12, i + 1),
            b'4' => return (i, STD_MINUTE, i + 1),
            b'5' => return (i, STD_SECOND, i + 1),
            b'P' => {
                if at(layout, i + 1, b"M") {
                    return (i, STD_PM, i + 2);
                }
            }
            b'p' => {
                if at(layout, i + 1, b"m") {
                    return (i, STD_LOWER_PM, i + 2);
                }
            }
            b'-' => {
                for (pat, std) in [
                    (&b"-070000"[..], STD_NUM_SECONDS_TZ),
                    (b"-07:00:00", STD_NUM_COLON_SECONDS_TZ),
                    (b"-0700", STD_NUM_TZ),
                    (b"-07:00", STD_NUM_COLON_TZ),
                    (b"-07", STD_NUM_SHORT_TZ),
                ] {
                    if at(layout, i, pat) {
                        return (i, std, i + pat.len());
                    }
                }
            }
            b'Z' => {
                for (pat, std) in [
                    (&b"Z070000"[..], STD_ISO8601_SECONDS_TZ),
                    (b"Z07:00:00", STD_ISO8601_COLON_SECONDS_TZ),
                    (b"Z0700", STD_ISO8601_TZ),
                    (b"Z07:00", STD_ISO8601_COLON_TZ),
                    (b"Z07", STD_ISO8601_SHORT_TZ),
                ] {
                    if at(layout, i, pat) {
                        return (i, std, i + pat.len());
                    }
                }
            }
            b'.' | b',' if i + 1 < n && (layout[i + 1] == b'0' || layout[i + 1] == b'9') => {
                let ch = layout[i + 1];
                let mut j = i + 1;
                while j < n && layout[j] == ch {
                    j += 1;
                }
                if !is_digit(layout, j) {
                    let code = if ch == b'9' {
                        STD_FRAC_SECOND9
                    } else {
                        STD_FRAC_SECOND0
                    };
                    return (i, std_frac_second(code, j - (i + 1), c), j);
                }
            }
            _ => {}
        }
    }
    (n, 0, n)
}

/// Go's `appendInt`: sign, zero padding to `width`, decimal digits.
pub(crate) fn append_int(b: &mut Vec<u8>, x: i64, width: usize) {
    if x < 0 {
        b.push(b'-');
    }
    let digits = x.unsigned_abs().to_string();
    for _ in digits.len()..width {
        b.push(b'0');
    }
    b.extend_from_slice(digits.as_bytes());
}

/// Go's `appendNano`.
fn append_nano(b: &mut Vec<u8>, nanosec: i64, std: i32) {
    let trim = std & STD_MASK == STD_FRAC_SECOND9;
    let n = digits_len(std);
    if trim && (n == 0 || nanosec == 0) {
        return;
    }
    let dot = separator(std);
    b.push(dot);
    append_int(b, nanosec, 9);
    if n < 9 {
        b.truncate(b.len() - 9 + n);
    }
    if trim {
        while b.last() == Some(&b'0') {
            b.pop();
        }
        if b.last() == Some(&dot) {
            b.pop();
        }
    }
}

/// Go's `quote`: a double-quoted string with non-ASCII and control bytes
/// written as `\xNN`.
pub(crate) fn quote(s: &[u8]) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !(b' '..0x80).contains(&c) {
            // Width of the UTF-8 sequence (1 for invalid bytes), as Go's
            // range loop decodes it.
            let width = match std::str::from_utf8(&s[i..s.len().min(i + 4)]) {
                Ok(text) => text.chars().next().map_or(1, char::len_utf8),
                Err(e) if e.valid_up_to() > 0 => std::str::from_utf8(&s[i..i + e.valid_up_to()])
                    .ok()
                    .and_then(|t| t.chars().next())
                    .map_or(1, char::len_utf8),
                Err(_) => 1,
            };
            for &byte in &s[i..i + width] {
                out.push_str(&format!("\\x{byte:02x}"));
            }
            i += width;
        } else {
            if c == b'"' || c == b'\\' {
                out.push('\\');
            }
            out.push(char::from(c));
            i += 1;
        }
    }
    out.push('"');
    out
}

impl Time {
    /// Go's `Format`: render the time using a reference-time layout such as
    /// [`RFC1123`] or `"2006-01-02 15:04"`.
    pub fn format(&self, layout: &str) -> String {
        let mut b = Vec::with_capacity(layout.len() + 10);
        self.append_format(&mut b, layout);
        // Output is layout text plus ASCII fields and the UTF-8 zone name.
        String::from_utf8_lossy(&b).into_owned()
    }

    /// Go's `AppendFormat`.
    pub fn append_format(&self, b: &mut Vec<u8>, layout: &str) {
        match layout {
            RFC3339 => self.append_format_rfc3339(b, false),
            RFC3339_NANO => self.append_format_rfc3339(b, true),
            _ => self.append_format_layout(b, layout.as_bytes()),
        }
    }

    fn append_format_layout(&self, b: &mut Vec<u8>, mut layout: &[u8]) {
        let (name, offset, abs) = self.locabs();
        let days = abs.days();
        let mut year = None;
        let mut yday = -1;
        let mut clock = None;
        while !layout.is_empty() {
            let (prefix, std, suffix) = next_std_chunk(layout);
            b.extend_from_slice(&layout[..prefix]);
            if std == 0 {
                break;
            }
            layout = &layout[suffix..];
            if year.is_none() && std & STD_NEED_DATE != 0 {
                year = Some(days.date());
            }
            if yday < 0 && std & STD_NEED_YDAY != 0 {
                yday = days.year_yday().1;
            }
            if clock.is_none() && std & STD_NEED_CLOCK != 0 {
                clock = Some(abs.clock());
            }
            let (year, month, day) = year.unwrap_or((0, 0, 0));
            let (hour, min, sec) = clock.unwrap_or((0, 0, 0));
            match std & STD_MASK {
                STD_YEAR => append_int(b, year.wrapping_abs() % 100, 2),
                STD_LONG_YEAR => append_int(b, year, 4),
                STD_MONTH => b.extend_from_slice(&Month(month).to_string().as_bytes()[..3]),
                STD_LONG_MONTH => b.extend_from_slice(Month(month).to_string().as_bytes()),
                STD_NUM_MONTH => append_int(b, month, 0),
                STD_ZERO_MONTH => append_int(b, month, 2),
                STD_WEEK_DAY => {
                    b.extend_from_slice(&days.weekday().to_string().as_bytes()[..3]);
                }
                STD_LONG_WEEK_DAY => b.extend_from_slice(days.weekday().to_string().as_bytes()),
                STD_DAY => append_int(b, day, 0),
                STD_UNDER_DAY => {
                    if day < 10 {
                        b.push(b' ');
                    }
                    append_int(b, day, 0);
                }
                STD_ZERO_DAY => append_int(b, day, 2),
                STD_UNDER_YEAR_DAY => {
                    if yday < 100 {
                        b.push(b' ');
                        if yday < 10 {
                            b.push(b' ');
                        }
                    }
                    append_int(b, yday, 0);
                }
                STD_ZERO_YEAR_DAY => append_int(b, yday, 3),
                STD_HOUR => append_int(b, hour, 2),
                STD_HOUR12 | STD_ZERO_HOUR12 => {
                    let hr = if hour % 12 == 0 { 12 } else { hour % 12 };
                    append_int(b, hr, if std == STD_HOUR12 { 0 } else { 2 });
                }
                STD_MINUTE => append_int(b, min, 0),
                STD_ZERO_MINUTE => append_int(b, min, 2),
                STD_SECOND => append_int(b, sec, 0),
                STD_ZERO_SECOND => append_int(b, sec, 2),
                STD_PM => b.extend_from_slice(if hour >= 12 { b"PM" } else { b"AM" }),
                STD_LOWER_PM => b.extend_from_slice(if hour >= 12 { b"pm" } else { b"am" }),
                STD_ISO8601_TZ..=STD_NUM_COLON_SECONDS_TZ => {
                    let iso = matches!(
                        std,
                        STD_ISO8601_TZ
                            | STD_ISO8601_COLON_TZ
                            | STD_ISO8601_SECONDS_TZ
                            | STD_ISO8601_SHORT_TZ
                            | STD_ISO8601_COLON_SECONDS_TZ
                    );
                    if offset == 0 && iso {
                        b.push(b'Z');
                        continue;
                    }
                    let mut zone = i64::from(offset / 60);
                    let mut absoffset = i64::from(offset);
                    if zone < 0 {
                        b.push(b'-');
                        zone = -zone;
                        absoffset = -absoffset;
                    } else {
                        b.push(b'+');
                    }
                    append_int(b, zone / 60, 2);
                    if matches!(
                        std,
                        STD_ISO8601_COLON_TZ
                            | STD_NUM_COLON_TZ
                            | STD_ISO8601_COLON_SECONDS_TZ
                            | STD_NUM_COLON_SECONDS_TZ
                    ) {
                        b.push(b':');
                    }
                    if std != STD_NUM_SHORT_TZ && std != STD_ISO8601_SHORT_TZ {
                        append_int(b, zone % 60, 2);
                    }
                    if matches!(
                        std,
                        STD_ISO8601_SECONDS_TZ
                            | STD_NUM_SECONDS_TZ
                            | STD_NUM_COLON_SECONDS_TZ
                            | STD_ISO8601_COLON_SECONDS_TZ
                    ) {
                        if std == STD_NUM_COLON_SECONDS_TZ || std == STD_ISO8601_COLON_SECONDS_TZ {
                            b.push(b':');
                        }
                        append_int(b, absoffset % 60, 2);
                    }
                }
                STD_TZ => {
                    if !name.is_empty() {
                        b.extend_from_slice(name.as_bytes());
                        continue;
                    }
                    let mut zone = i64::from(offset / 60);
                    if zone < 0 {
                        b.push(b'-');
                        zone = -zone;
                    } else {
                        b.push(b'+');
                    }
                    append_int(b, zone / 60, 2);
                    append_int(b, zone % 60, 2);
                }
                STD_FRAC_SECOND0 | STD_FRAC_SECOND9 => append_nano(b, self.nanosecond(), std),
                _ => {}
            }
        }
    }

    /// Go's `appendFormatRFC3339`.
    fn append_format_rfc3339(&self, b: &mut Vec<u8>, nanos: bool) {
        let (_, offset, abs) = self.locabs();
        let (year, month, day) = abs.days().date();
        append_int(b, year, 4);
        b.push(b'-');
        append_int(b, month, 2);
        b.push(b'-');
        append_int(b, day, 2);
        b.push(b'T');
        let (hour, min, sec) = abs.clock();
        append_int(b, hour, 2);
        b.push(b':');
        append_int(b, min, 2);
        b.push(b':');
        append_int(b, sec, 2);
        if nanos {
            append_nano(
                b,
                self.nanosecond(),
                std_frac_second(STD_FRAC_SECOND9, 9, b'.'),
            );
        }
        if offset == 0 {
            b.push(b'Z');
            return;
        }
        let mut zone = i64::from(offset / 60);
        if zone < 0 {
            b.push(b'-');
            zone = -zone;
        } else {
            b.push(b'+');
        }
        append_int(b, zone / 60, 2);
        b.push(b':');
        append_int(b, zone % 60, 2);
    }

    /// Go's `appendStrictRFC3339`.
    fn append_strict_rfc3339(&self, b: &mut Vec<u8>) -> Result<(), &'static str> {
        let n0 = b.len();
        self.append_format_rfc3339(b, true);
        let num2 = |s: &[u8]| 10 * (s[0].wrapping_sub(b'0')) + s[1].wrapping_sub(b'0');
        if b[n0 + 4] != b'-' {
            return Err("year outside of range [0,9999]");
        }
        if b[b.len() - 1] != b'Z' {
            let c = b[b.len() - 6];
            if c.is_ascii_digit() || num2(&b[b.len() - 5..]) >= 24 {
                return Err("timezone hour outside of range [0,23]");
            }
        }
        Ok(())
    }

    /// Go's `MarshalJSON`: a quoted RFC 3339 string with nanoseconds.
    pub fn marshal_json(&self) -> Result<Vec<u8>, Error> {
        let mut b = vec![b'"'];
        let result = self.append_strict_rfc3339(&mut b);
        b.push(b'"');
        match result {
            Ok(()) => Ok(b),
            Err("year outside of range [0,9999]") => {
                Err(Error("Time.MarshalJSON: year outside of range [0,9999]"))
            }
            Err(_) => Err(Error(
                "Time.MarshalJSON: timezone hour outside of range [0,23]",
            )),
        }
    }

    /// Go's `AppendText`.
    pub fn append_text(&self, b: &mut Vec<u8>) -> Result<(), Error> {
        let start = b.len();
        match self.append_strict_rfc3339(b) {
            Ok(()) => Ok(()),
            Err(e) => {
                b.truncate(start);
                Err(Error(if e.starts_with("year") {
                    "Time.AppendText: year outside of range [0,9999]"
                } else {
                    "Time.AppendText: timezone hour outside of range [0,23]"
                }))
            }
        }
    }

    /// Go's `MarshalText`.
    pub fn marshal_text(&self) -> Result<Vec<u8>, Error> {
        let mut b = Vec::with_capacity(RFC3339_NANO.len());
        match self.append_strict_rfc3339(&mut b) {
            Ok(()) => Ok(b),
            Err(e) => Err(Error(if e.starts_with("year") {
                "Time.MarshalText: year outside of range [0,9999]"
            } else {
                "Time.MarshalText: timezone hour outside of range [0,23]"
            })),
        }
    }

    /// Go's `UnmarshalJSON`: `null` leaves the time unchanged.
    pub fn unmarshal_json(&mut self, data: &[u8]) -> Result<(), UnmarshalError> {
        if data == b"null" {
            return Ok(());
        }
        if data.len() < 2 || data[0] != b'"' || data[data.len() - 1] != b'"' {
            return Err(UnmarshalError::Invalid(Error(
                "Time.UnmarshalJSON: input is not a JSON string",
            )));
        }
        *self = parse_strict_rfc3339(&data[1..data.len() - 1])?;
        Ok(())
    }

    /// Go's `UnmarshalText`.
    pub fn unmarshal_text(&mut self, data: &[u8]) -> Result<(), UnmarshalError> {
        *self = parse_strict_rfc3339(data)?;
        Ok(())
    }
}

impl fmt::Display for Time {
    /// Go's `Time.String`: `2006-01-02 15:04:05.999999999 -0700 MST`, plus
    /// ` m=±s.nnnnnnnnn` when the time carries a monotonic reading.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = self.format("2006-01-02 15:04:05.999999999 -0700 MST");
        if let Some(ext) = self.mono() {
            let mut m2 = ext.unsigned_abs();
            let sign = if ext < 0 { '-' } else { '+' };
            let m1 = m2 / 1_000_000_000;
            m2 %= 1_000_000_000;
            let m0 = m1 / 1_000_000_000;
            let m1 = m1 % 1_000_000_000;
            let mut buf = vec![b' ', b'm', b'=', sign as u8];
            let mut wid = 0;
            if m0 != 0 {
                append_int(&mut buf, m0 as i64, 0);
                wid = 9;
            }
            append_int(&mut buf, m1 as i64, wid);
            buf.push(b'.');
            append_int(&mut buf, m2 as i64, 9);
            s.push_str(&String::from_utf8_lossy(&buf));
        }
        f.write_str(&s)
    }
}

/// Go's `ParseError`, with Go's `Error()` text as `Display`.
///
/// Fields are Go strings; a field that would split a multi-byte UTF-8
/// character is decoded lossily.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub layout: String,
    pub value: String,
    pub layout_elem: String,
    pub value_elem: String,
    pub message: String,
}

impl ParseError {
    fn new(
        layout: &[u8],
        value: &[u8],
        layout_elem: &[u8],
        value_elem: &[u8],
        message: String,
    ) -> Self {
        let s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        Self {
            layout: s(layout),
            value: s(value),
            layout_elem: s(layout_elem),
            value_elem: s(value_elem),
            message,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(
                f,
                "parsing time {} as {}: cannot parse {} as {}",
                quote(self.value.as_bytes()),
                quote(self.layout.as_bytes()),
                quote(self.value_elem.as_bytes()),
                quote(self.layout_elem.as_bytes())
            )
        } else {
            write!(
                f,
                "parsing time {}{}",
                quote(self.value.as_bytes()),
                self.message
            )
        }
    }
}

impl std::error::Error for ParseError {}

/// Errors from [`Time::unmarshal_json`] and [`Time::unmarshal_text`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnmarshalError {
    /// The input is not a JSON string.
    Invalid(Error),
    /// The string is not an RFC 3339 time.
    Parse(ParseError),
}

impl fmt::Display for UnmarshalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(e) => e.fmt(f),
            Self::Parse(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for UnmarshalError {}

impl From<ParseError> for UnmarshalError {
    fn from(e: ParseError) -> Self {
        Self::Parse(e)
    }
}

fn match_fold(s1: &[u8], s2: &[u8]) -> bool {
    s1.iter().zip(s2).all(|(&c1, &c2)| {
        if c1 == c2 {
            return true;
        }
        let (l1, l2) = (c1 | 0x20, c2 | 0x20);
        l1 == l2 && l1.is_ascii_lowercase()
    })
}

/// Go's `lookup`: case-insensitive prefix match against a name table.
fn lookup_name<'a>(tab: &[&str], val: &'a [u8]) -> Option<(i64, &'a [u8])> {
    tab.iter().enumerate().find_map(|(i, v)| {
        let v = v.as_bytes();
        (val.len() >= v.len() && match_fold(&val[..v.len()], v))
            .then(|| (i as i64, &val[v.len()..]))
    })
}

/// Go's `getnum`: one or two digits; `fixed` requires two.
fn getnum(s: &[u8], fixed: bool) -> Option<(i64, &[u8])> {
    if !is_digit(s, 0) {
        return None;
    }
    if !is_digit(s, 1) {
        if fixed {
            return None;
        }
        return Some((i64::from(s[0] - b'0'), &s[1..]));
    }
    Some((
        i64::from(s[0] - b'0') * 10 + i64::from(s[1] - b'0'),
        &s[2..],
    ))
}

/// Go's `getnum3`: one to three digits; `fixed` requires three.
fn getnum3(s: &[u8], fixed: bool) -> Option<(i64, &[u8])> {
    let mut n = 0;
    let mut i = 0;
    while i < 3 && is_digit(s, i) {
        n = n * 10 + i64::from(s[i] - b'0');
        i += 1;
    }
    if i == 0 || fixed && i != 3 {
        return None;
    }
    Some((n, &s[i..]))
}

fn cutspace(mut s: &[u8]) -> &[u8] {
    while s.first() == Some(&b' ') {
        s = &s[1..];
    }
    s
}

/// Go's `skip`: match layout literal text, where runs of spaces in the
/// layout match runs (possibly empty) of spaces in the value.
fn skip<'a>(mut value: &'a [u8], mut prefix: &[u8]) -> Result<&'a [u8], &'a [u8]> {
    while !prefix.is_empty() {
        if prefix[0] == b' ' {
            if !value.is_empty() && value[0] != b' ' {
                return Err(value);
            }
            prefix = cutspace(prefix);
            value = cutspace(value);
            continue;
        }
        if value.is_empty() || value[0] != prefix[0] {
            return Err(value);
        }
        prefix = &prefix[1..];
        value = &value[1..];
    }
    Ok(value)
}

/// Go's `atoi`.
fn atoi(s: &[u8]) -> Option<i64> {
    let (neg, s) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let (q, rem) = leading_int(s)?;
    if !rem.is_empty() {
        return None;
    }
    let x = q as i64;
    Some(if neg { x.wrapping_neg() } else { x })
}

fn comma_or_period(b: u8) -> bool {
    b == b'.' || b == b','
}

/// Go's `parseNanoseconds`: (nanoseconds, range error).
fn parse_nanoseconds(value: &[u8], nbytes: usize) -> Result<(i64, &'static str), ()> {
    if !comma_or_period(value[0]) {
        return Err(());
    }
    let nbytes = nbytes.min(10);
    let mut ns = atoi(&value[1..nbytes]).ok_or(())?;
    if ns < 0 {
        return Ok((ns, "fractional second"));
    }
    for _ in 0..10 - nbytes {
        ns *= 10;
    }
    Ok((ns, ""))
}

/// Go's `parseTimeZone`: the length of a zone abbreviation, if any.
fn parse_time_zone(value: &[u8]) -> Option<usize> {
    if value.len() < 3 {
        return None;
    }
    if at(value, 0, b"ChST") || at(value, 0, b"MeST") {
        return Some(4);
    }
    if at(value, 0, b"GMT") {
        return Some(parse_gmt(value));
    }
    if value[0] == b'+' || value[0] == b'-' {
        let n = parse_signed_offset(value);
        return (n > 0).then_some(n);
    }
    let n_upper = value
        .iter()
        .take(6)
        .take_while(|c| c.is_ascii_uppercase())
        .count();
    match n_upper {
        5 if value[4] == b'T' => Some(5),
        4 if value[3] == b'T' || at(value, 0, b"WITA") => Some(4),
        3 => Some(3),
        _ => None,
    }
}

fn parse_gmt(value: &[u8]) -> usize {
    let value = &value[3..];
    if value.is_empty() {
        return 3;
    }
    3 + parse_signed_offset(value)
}

fn parse_signed_offset(value: &[u8]) -> usize {
    let sign = value[0];
    if sign != b'-' && sign != b'+' {
        return 0;
    }
    match leading_int(&value[1..]) {
        Some((x, rem)) if rem.len() != value.len() - 1 && x <= 23 => value.len() - rem.len(),
        _ => 0,
    }
}

impl Time {
    /// Go's `Parse`: parse `value` according to `layout`. Without a zone in
    /// the value the result is UTC; zone offsets and abbreviations are matched
    /// against the [`local`] location.
    pub fn parse(layout: &str, value: &str) -> Result<Time, ParseError> {
        if layout == RFC3339 || layout == RFC3339_NANO {
            if let Some(t) = parse_rfc3339(value.as_bytes(), &local()) {
                return Ok(t);
            }
        }
        parse_with(
            layout.as_bytes(),
            value.as_bytes(),
            Location::utc_ref(),
            &local(),
        )
    }

    /// Go's `ParseInLocation`: like [`Time::parse`], but a value without zone
    /// information is interpreted in `loc`, and zones are matched against it.
    pub fn parse_in_location(
        layout: &str,
        value: &str,
        loc: &Location,
    ) -> Result<Time, ParseError> {
        if layout == RFC3339 || layout == RFC3339_NANO {
            if let Some(t) = parse_rfc3339(value.as_bytes(), loc) {
                return Ok(t);
            }
        }
        parse_with(layout.as_bytes(), value.as_bytes(), loc, loc)
    }
}

impl std::str::FromStr for Time {
    type Err = ParseError;

    /// Parse an RFC 3339 timestamp, as `Time::parse(RFC3339, s)`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Time::parse(RFC3339, s)
    }
}

/// Sign, hours, minutes, seconds and the rest of the value.
type TzParts<'a> = Option<(&'a [u8], &'a [u8], &'a [u8], &'a [u8], &'a [u8])>;

#[derive(Clone, Copy)]
enum ParseFail {
    Bad,
}

/// Go's `parse`.
fn parse_with(
    alayout: &[u8],
    avalue: &[u8],
    default_location: &Location,
    local: &Location,
) -> Result<Time, ParseError> {
    let (mut layout, mut value) = (alayout, avalue);
    let mut range_err = "";
    let (mut am_set, mut pm_set) = (false, false);
    let mut year = 0i64;
    let (mut month, mut day, mut yday) = (-1i64, -1i64, -1i64);
    let (mut hour, mut min, mut sec, mut nsec) = (0i64, 0i64, 0i64, 0i64);
    let mut z: Option<Location> = None;
    let mut zone_offset = -1i64;
    let mut zone_name: &[u8] = b"";
    loop {
        let (prefix_len, std, suffix) = next_std_chunk(layout);
        let prefix = &layout[..prefix_len];
        let stdstr = &layout[prefix_len..suffix];
        value = match skip(value, prefix) {
            Ok(v) => v,
            Err(v) => {
                return Err(ParseError::new(alayout, avalue, prefix, v, String::new()));
            }
        };
        if std == 0 {
            if !value.is_empty() {
                let message = format!(": extra text: {}", quote(value));
                return Err(ParseError::new(alayout, avalue, b"", value, message));
            }
            break;
        }
        layout = &layout[suffix..];
        let hold = value;
        let mut err: Option<ParseFail> = None;
        let bad = Some(ParseFail::Bad);
        match std & STD_MASK {
            STD_YEAR => {
                if value.len() < 2 {
                    err = bad;
                } else {
                    let p = &value[..2];
                    value = &value[2..];
                    match atoi(p) {
                        Some(y) => year = if y >= 69 { y + 1900 } else { y + 2000 },
                        None => err = bad,
                    }
                }
            }
            STD_LONG_YEAR => {
                if value.len() < 4 || !is_digit(value, 0) {
                    err = bad;
                } else {
                    let p = &value[..4];
                    value = &value[4..];
                    match atoi(p) {
                        Some(y) => year = y,
                        None => err = bad,
                    }
                }
            }
            STD_MONTH | STD_LONG_MONTH => {
                let tab: &[&str] = if std == STD_MONTH {
                    &SHORT_MONTH_NAMES
                } else {
                    &LONG_MONTH_NAMES
                };
                match lookup_name(tab, value) {
                    Some((m, rest)) => {
                        month = m + 1;
                        value = rest;
                    }
                    None => {
                        month = 0;
                        err = bad;
                    }
                }
            }
            STD_NUM_MONTH | STD_ZERO_MONTH => match getnum(value, std == STD_ZERO_MONTH) {
                Some((m, rest)) => {
                    month = m;
                    value = rest;
                    if month <= 0 || 12 < month {
                        range_err = "month";
                    }
                }
                None => {
                    month = 0;
                    err = bad;
                }
            },
            STD_WEEK_DAY | STD_LONG_WEEK_DAY => {
                let tab: &[&str] = if std == STD_WEEK_DAY {
                    &SHORT_DAY_NAMES
                } else {
                    &LONG_DAY_NAMES
                };
                match lookup_name(tab, value) {
                    Some((_, rest)) => value = rest,
                    None => err = bad,
                }
            }
            STD_DAY | STD_UNDER_DAY | STD_ZERO_DAY => {
                if std == STD_UNDER_DAY && value.first() == Some(&b' ') {
                    value = &value[1..];
                }
                match getnum(value, std == STD_ZERO_DAY) {
                    Some((d, rest)) => {
                        day = d;
                        value = rest;
                    }
                    None => {
                        day = 0;
                        err = bad;
                    }
                }
            }
            STD_UNDER_YEAR_DAY | STD_ZERO_YEAR_DAY => {
                for _ in 0..2 {
                    if std == STD_UNDER_YEAR_DAY && value.first() == Some(&b' ') {
                        value = &value[1..];
                    }
                }
                match getnum3(value, std == STD_ZERO_YEAR_DAY) {
                    Some((d, rest)) => {
                        yday = d;
                        value = rest;
                    }
                    None => {
                        yday = 0;
                        err = bad;
                    }
                }
            }
            STD_HOUR => match getnum(value, false) {
                Some((h, rest)) => {
                    hour = h;
                    value = rest;
                    if !(0..24).contains(&hour) {
                        range_err = "hour";
                    }
                }
                None => {
                    hour = 0;
                    err = bad;
                }
            },
            STD_HOUR12 | STD_ZERO_HOUR12 => match getnum(value, std == STD_ZERO_HOUR12) {
                Some((h, rest)) => {
                    hour = h;
                    value = rest;
                    if !(0..=12).contains(&hour) {
                        range_err = "hour";
                    }
                }
                None => {
                    hour = 0;
                    err = bad;
                }
            },
            STD_MINUTE | STD_ZERO_MINUTE => match getnum(value, std == STD_ZERO_MINUTE) {
                Some((m, rest)) => {
                    min = m;
                    value = rest;
                    if !(0..60).contains(&min) {
                        range_err = "minute";
                    }
                }
                None => {
                    min = 0;
                    err = bad;
                }
            },
            STD_SECOND | STD_ZERO_SECOND => match getnum(value, std == STD_ZERO_SECOND) {
                None => {
                    sec = 0;
                    err = bad;
                }
                Some((s, rest)) => {
                    sec = s;
                    value = rest;
                    if !(0..60).contains(&sec) {
                        range_err = "second";
                    } else if value.len() >= 2 && comma_or_period(value[0]) && is_digit(value, 1) {
                        // A fractional second in the value with no fraction
                        // in the layout; the next chunk may consume it.
                        let (_, next, _) = next_std_chunk(layout);
                        let next = next & STD_MASK;
                        if next != STD_FRAC_SECOND0 && next != STD_FRAC_SECOND9 {
                            let mut n = 2;
                            while n < value.len() && is_digit(value, n) {
                                n += 1;
                            }
                            match parse_nanoseconds(value, n) {
                                Ok((ns, r)) => {
                                    nsec = ns;
                                    range_err = r;
                                }
                                Err(()) => err = bad,
                            }
                            value = &value[n..];
                        }
                    }
                }
            },
            STD_PM | STD_LOWER_PM => {
                if value.len() < 2 {
                    err = bad;
                } else {
                    let p = &value[..2];
                    value = &value[2..];
                    let (pm, am): (&[u8], &[u8]) = if std == STD_PM {
                        (b"PM", b"AM")
                    } else {
                        (b"pm", b"am")
                    };
                    if p == pm {
                        pm_set = true;
                    } else if p == am {
                        am_set = true;
                    } else {
                        err = bad;
                    }
                }
            }
            STD_ISO8601_TZ..=STD_NUM_COLON_SECONDS_TZ => {
                let iso = matches!(
                    std,
                    STD_ISO8601_TZ
                        | STD_ISO8601_SHORT_TZ
                        | STD_ISO8601_COLON_TZ
                        | STD_ISO8601_SECONDS_TZ
                        | STD_ISO8601_COLON_SECONDS_TZ
                );
                if iso && value.first() == Some(&b'Z') {
                    value = &value[1..];
                    z = Some(Location::utc());
                } else {
                    let parts: TzParts<'_> = if std == STD_ISO8601_COLON_TZ
                        || std == STD_NUM_COLON_TZ
                    {
                        (value.len() >= 6 && value[3] == b':').then(|| {
                            (
                                &value[0..1],
                                &value[1..3],
                                &value[4..6],
                                &b"00"[..],
                                &value[6..],
                            )
                        })
                    } else if std == STD_NUM_SHORT_TZ || std == STD_ISO8601_SHORT_TZ {
                        (value.len() >= 3).then(|| {
                            (
                                &value[0..1],
                                &value[1..3],
                                &b"00"[..],
                                &b"00"[..],
                                &value[3..],
                            )
                        })
                    } else if std == STD_ISO8601_COLON_SECONDS_TZ || std == STD_NUM_COLON_SECONDS_TZ
                    {
                        (value.len() >= 9 && value[3] == b':' && value[6] == b':').then(|| {
                            (
                                &value[0..1],
                                &value[1..3],
                                &value[4..6],
                                &value[7..9],
                                &value[9..],
                            )
                        })
                    } else if std == STD_ISO8601_SECONDS_TZ || std == STD_NUM_SECONDS_TZ {
                        (value.len() >= 7).then(|| {
                            (
                                &value[0..1],
                                &value[1..3],
                                &value[3..5],
                                &value[5..7],
                                &value[7..],
                            )
                        })
                    } else {
                        (value.len() >= 5).then(|| {
                            (
                                &value[0..1],
                                &value[1..3],
                                &value[3..5],
                                &b"00"[..],
                                &value[5..],
                            )
                        })
                    };
                    match parts {
                        None => err = bad,
                        Some((sign, h, m, s, rest)) => {
                            value = rest;
                            let mut hr = 0;
                            let mut mm = 0;
                            let mut ss = 0;
                            match getnum(h, true) {
                                Some((v, _)) => {
                                    hr = v;
                                    match getnum(m, true) {
                                        Some((v, _)) => {
                                            mm = v;
                                            match getnum(s, true) {
                                                Some((v, _)) => ss = v,
                                                None => err = bad,
                                            }
                                        }
                                        None => err = bad,
                                    }
                                }
                                None => err = bad,
                            }
                            if hr > 24 {
                                range_err = "time zone offset hour";
                            }
                            if mm > 60 {
                                range_err = "time zone offset minute";
                            }
                            if ss > 60 {
                                range_err = "time zone offset second";
                            }
                            zone_offset = (hr * 60 + mm) * 60 + ss;
                            match sign[0] {
                                b'+' => {}
                                b'-' => zone_offset = -zone_offset,
                                _ => err = bad,
                            }
                        }
                    }
                }
            }
            STD_TZ => {
                if at(value, 0, b"UTC") {
                    z = Some(Location::utc());
                    value = &value[3..];
                } else {
                    match parse_time_zone(value) {
                        Some(n) => {
                            zone_name = &value[..n];
                            value = &value[n..];
                        }
                        None => err = bad,
                    }
                }
            }
            STD_FRAC_SECOND0 => {
                let ndigit = 1 + digits_len(std);
                if value.len() < ndigit {
                    err = bad;
                } else {
                    match parse_nanoseconds(value, ndigit) {
                        Ok((ns, r)) => {
                            nsec = ns;
                            range_err = r;
                        }
                        Err(()) => err = bad,
                    }
                    value = &value[ndigit..];
                }
            }
            // Without a fraction in the value, `.999` matches nothing.
            STD_FRAC_SECOND9
                if value.len() >= 2 && comma_or_period(value[0]) && value[1].is_ascii_digit() =>
            {
                let mut i = 0;
                while i + 1 < value.len() && value[i + 1].is_ascii_digit() {
                    i += 1;
                }
                match parse_nanoseconds(value, 1 + i) {
                    Ok((ns, r)) => {
                        nsec = ns;
                        range_err = r;
                    }
                    Err(()) => err = bad,
                }
                value = &value[1 + i..];
            }
            _ => {}
        }
        if !range_err.is_empty() {
            let message = format!(": {range_err} out of range");
            return Err(ParseError::new(alayout, avalue, stdstr, value, message));
        }
        if err.is_some() {
            return Err(ParseError::new(
                alayout,
                avalue,
                stdstr,
                hold,
                String::new(),
            ));
        }
    }
    if pm_set && hour < 12 {
        hour += 12;
    } else if am_set && hour == 12 {
        hour = 0;
    }

    let fail = |message: &str| {
        Err(ParseError::new(
            alayout,
            avalue,
            b"",
            value,
            message.to_string(),
        ))
    };
    if yday >= 0 {
        let mut d = 0;
        let mut m = 0;
        if is_leap(year) {
            if yday == 31 + 29 {
                m = 2;
                d = 29;
            } else if yday > 31 + 29 {
                yday -= 1;
            }
        }
        if !(1..=365).contains(&yday) {
            return fail(": day-of-year out of range");
        }
        if m == 0 {
            m = (yday - 1) / 31 + 1;
            if days_before(m + 1) < yday {
                m += 1;
            }
            d = yday - days_before(m);
        }
        if month >= 0 && month != m {
            return fail(": day-of-year does not match month");
        }
        month = m;
        if day >= 0 && day != d {
            return fail(": day-of-year does not match day");
        }
        day = d;
    } else {
        if month < 0 {
            month = 1;
        }
        if day < 0 {
            day = 1;
        }
    }
    if day < 1 || day > days_in(month, year) {
        return fail(": day out of range");
    }

    let utc = Location::utc_ref();
    if let Some(z) = z {
        return Ok(date(year, Month(month), day, hour, min, sec, nsec, &z));
    }
    if zone_offset != -1 {
        let mut t = date(year, Month(month), day, hour, min, sec, nsec, utc);
        t = t.add_seconds_internal(-zone_offset);
        let zone = local.lookup(t.unix());
        let zname = String::from_utf8_lossy(zone_name);
        if i64::from(zone.offset) == zone_offset && (zone_name.is_empty() || zone.name == zname) {
            return Ok(t.in_location(local));
        }
        return Ok(t.in_location(&Location::fixed(&zname, zone_offset as i32)));
    }
    if !zone_name.is_empty() {
        let zname = String::from_utf8_lossy(zone_name).into_owned();
        let t = date(year, Month(month), day, hour, min, sec, nsec, utc);
        if let Some(offset) = local.lookup_name(&zname, t.unix()) {
            let t = t.add_seconds_internal(-i64::from(offset));
            return Ok(t.in_location(local));
        }
        let mut offset = 0;
        if zname.len() > 3 && zname.starts_with("GMT") {
            offset = atoi(&zone_name[3..]).unwrap_or(0) * 3600;
        }
        return Ok(t.in_location(&Location::fixed(&zname, offset as i32)));
    }
    Ok(date(
        year,
        Month(month),
        day,
        hour,
        min,
        sec,
        nsec,
        default_location,
    ))
}

/// Go's `parseRFC3339` fast path.
fn parse_rfc3339(s: &[u8], local: &Location) -> Option<Time> {
    let ok = std::cell::Cell::new(true);
    let parse_uint = |s: &[u8], min: i64, max: i64| -> i64 {
        let mut x = 0i64;
        for &c in s {
            if !c.is_ascii_digit() {
                ok.set(false);
                return min;
            }
            x = x * 10 + i64::from(c - b'0');
        }
        if x < min || max < x {
            ok.set(false);
            return min;
        }
        x
    };
    if s.len() < "2006-01-02T15:04:05".len() {
        return None;
    }
    let year = parse_uint(&s[0..4], 0, 9999);
    let month = parse_uint(&s[5..7], 1, 12);
    let day = parse_uint(&s[8..10], 1, days_in(month, year));
    let hour = parse_uint(&s[11..13], 0, 23);
    let min = parse_uint(&s[14..16], 0, 59);
    let sec = parse_uint(&s[17..19], 0, 59);
    if !ok.get()
        || !(s[4] == b'-' && s[7] == b'-' && s[10] == b'T' && s[13] == b':' && s[16] == b':')
    {
        return None;
    }
    let mut s = &s[19..];
    let mut nsec = 0;
    if s.len() >= 2 && s[0] == b'.' && is_digit(s, 1) {
        let mut n = 2;
        while n < s.len() && is_digit(s, n) {
            n += 1;
        }
        nsec = parse_nanoseconds(s, n).map_or(0, |(ns, _)| ns);
        s = &s[n..];
    }
    let mut t = date(
        year,
        Month(month),
        day,
        hour,
        min,
        sec,
        nsec,
        Location::utc_ref(),
    );
    if s.len() != 1 || s[0] != b'Z' {
        if s.len() != "-07:00".len() {
            return None;
        }
        let hr = parse_uint(&s[1..3], 0, 23);
        let mm = parse_uint(&s[4..6], 0, 59);
        if !ok.get() || !((s[0] == b'-' || s[0] == b'+') && s[3] == b':') {
            return None;
        }
        let mut zone_offset = (hr * 60 + mm) * 60;
        if s[0] == b'-' {
            zone_offset = -zone_offset;
        }
        t = t.add_seconds_internal(-zone_offset);
        if i64::from(local.lookup(t.unix()).offset) == zone_offset {
            t = t.in_location(local);
        } else {
            t = t.in_location(&Location::fixed("", zone_offset as i32));
        }
    }
    Some(t)
}

/// Go's `parseStrictRFC3339`. Go currently disables its extra strictness
/// checks (go.dev/issue/54580), so a generic RFC 3339 parse is accepted.
fn parse_strict_rfc3339(b: &[u8]) -> Result<Time, ParseError> {
    if let Some(t) = parse_rfc3339(b, &local()) {
        return Ok(t);
    }
    parse_with(RFC3339.as_bytes(), b, Location::utc_ref(), &local())
}
