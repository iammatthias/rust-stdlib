//! `encoding/asn1`'s UTCTime and GeneralizedTime parsing, with the messages of
//! Go's `time.Parse`.
//!
//! Go parses these with the layouts `0601021504Z0700`, `060102150405Z0700`
//! and `20060102150405.999999999Z0700`, rejects values that do not format back
//! to the original string, and reports a `*time.ParseError` otherwise. Only
//! the instant is kept here, or Go's error text.

use super::time::Time;

/// One element of the three layouts used.
#[derive(Clone, Copy, PartialEq)]
enum Std {
    Year,
    LongYear,
    Month,
    Day,
    Hour,
    Minute,
    Second,
    FracSecond9,
    Zone,
}

impl Std {
    /// The text of the element in the layout, as `ParseError.LayoutElem`.
    fn text(self) -> &'static str {
        match self {
            Std::Year => "06",
            Std::LongYear => "2006",
            Std::Month => "01",
            Std::Day => "02",
            Std::Hour => "15",
            Std::Minute => "04",
            Std::Second => "05",
            Std::FracSecond9 => ".999999999",
            Std::Zone => "Z0700",
        }
    }
}

const LAYOUT_UTC_SHORT: (&str, &[Std]) = (
    "0601021504Z0700",
    &[
        Std::Year,
        Std::Month,
        Std::Day,
        Std::Hour,
        Std::Minute,
        Std::Zone,
    ],
);
const LAYOUT_UTC: (&str, &[Std]) = (
    "060102150405Z0700",
    &[
        Std::Year,
        Std::Month,
        Std::Day,
        Std::Hour,
        Std::Minute,
        Std::Second,
        Std::Zone,
    ],
);
const LAYOUT_GENERALIZED: (&str, &[Std]) = (
    "20060102150405.999999999Z0700",
    &[
        Std::LongYear,
        Std::Month,
        Std::Day,
        Std::Hour,
        Std::Minute,
        Std::Second,
        Std::FracSecond9,
        Std::Zone,
    ],
);

/// The fields a successful parse produced, enough to format them back.
#[derive(Default)]
struct Fields {
    year: i64,
    month: i64,
    day: i64,
    hour: i64,
    min: i64,
    sec: i64,
    nsec: i64,
    /// `Some(seconds)` for a numeric offset, `None` for `Z`.
    zone_offset: Option<i64>,
}

/// `time.quote`.
fn quote(s: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !(b' '..0x80).contains(&c) {
            // The width Go's `range` gives the rune: a whole valid sequence,
            // or one byte.
            let width = utf8_width(&s[i..]);
            for &b in &s[i..i + width] {
                out.push_str(&format!("\\x{b:02x}"));
            }
            i += width;
        } else {
            if c == b'"' || c == b'\\' {
                out.push('\\');
            }
            out.push(c as char);
            i += 1;
        }
    }
    out.push('"');
    out
}

/// The length of the UTF-8 sequence at the start of `s`, or 1 if it is not
/// valid (Go decodes it as `utf8.RuneError` of width 1).
fn utf8_width(s: &[u8]) -> usize {
    let want = match s[0] {
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return 1,
    };
    match s.get(..want) {
        Some(seq) if std::str::from_utf8(seq).is_ok() => want,
        _ => 1,
    }
}

/// Go's `*time.ParseError.Error()`.
struct ParseError {
    layout: &'static str,
    value: Vec<u8>,
    layout_elem: String,
    value_elem: Vec<u8>,
    message: String,
}

impl ParseError {
    fn text(&self) -> String {
        if self.message.is_empty() {
            format!(
                "parsing time {} as {}: cannot parse {} as {}",
                quote(&self.value),
                quote(self.layout.as_bytes()),
                quote(&self.value_elem),
                quote(self.layout_elem.as_bytes())
            )
        } else {
            format!("parsing time {}{}", quote(&self.value), self.message)
        }
    }
}

fn is_digit(s: &[u8], i: usize) -> bool {
    s.get(i).is_some_and(u8::is_ascii_digit)
}

/// `getnum`: one or two digits (two if `fixed`), or `None` for `errBad`.
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

/// `time.atoi`: an optional sign and digits.
fn atoi(s: &[u8]) -> Option<i64> {
    let (neg, digits) = match s.first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let mut x: i64 = 0;
    for &c in digits {
        if !c.is_ascii_digit() {
            return None;
        }
        x = x.checked_mul(10)?.checked_add(i64::from(c - b'0'))?;
    }
    Some(if neg { -x } else { x })
}

fn comma_or_period(b: u8) -> bool {
    b == b'.' || b == b','
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in(month: i64, year: i64) -> i64 {
    match month {
        2 if is_leap(year) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `parseNanoseconds`: the value in nanoseconds, or `None` for `errBad`.
fn parse_nanoseconds(value: &[u8], nbytes: usize) -> Option<i64> {
    if !comma_or_period(value[0]) {
        return None;
    }
    let nbytes = nbytes.min(10);
    let mut ns = atoi(&value[1..nbytes])?;
    for _ in 0..10 - nbytes {
        ns *= 10;
    }
    Some(ns)
}

/// `time.Parse` for one of the three layouts: the parsed fields or the text
/// of the `*time.ParseError`.
fn parse(layout: (&'static str, &[Std]), avalue: &[u8]) -> Result<Fields, String> {
    let (alayout, elements) = layout;
    let mut value = avalue;
    let mut f = Fields {
        month: -1,
        day: -1,
        ..Fields::default()
    };
    let error = |elem: &str, value_elem: &[u8], message: String| {
        Err(ParseError {
            layout: alayout,
            value: avalue.to_vec(),
            layout_elem: elem.to_string(),
            value_elem: value_elem.to_vec(),
            message,
        }
        .text())
    };
    for (index, &std) in elements.iter().enumerate() {
        let hold = value;
        let mut range_err = "";
        let mut bad = false;
        match std {
            Std::Year => match value.get(..2).map(|p| (p, atoi(p))) {
                Some((_, Some(year))) => {
                    value = &value[2..];
                    f.year = year + if year >= 69 { 1900 } else { 2000 };
                }
                Some(_) => {
                    value = &value[2..];
                    bad = true;
                }
                None => bad = true,
            },
            Std::LongYear => {
                if value.len() < 4 || !is_digit(value, 0) {
                    bad = true;
                } else {
                    let year = atoi(&value[..4]);
                    value = &value[4..];
                    match year {
                        Some(year) => f.year = year,
                        None => bad = true,
                    }
                }
            }
            Std::Month => match getnum(value, true) {
                Some((month, rest)) => {
                    value = rest;
                    f.month = month;
                    if month <= 0 || 12 < month {
                        range_err = "month";
                    }
                }
                None => bad = true,
            },
            Std::Day => match getnum(value, true) {
                Some((day, rest)) => {
                    value = rest;
                    f.day = day;
                }
                None => bad = true,
            },
            Std::Hour => {
                let parsed = getnum(value, false);
                if let Some((hour, rest)) = parsed {
                    value = rest;
                    f.hour = hour;
                } else {
                    bad = true;
                }
                if !(0..24).contains(&f.hour) {
                    range_err = "hour";
                }
            }
            Std::Minute => {
                let parsed = getnum(value, true);
                if let Some((min, rest)) = parsed {
                    value = rest;
                    f.min = min;
                } else {
                    bad = true;
                }
                if !(0..60).contains(&f.min) {
                    range_err = "minute";
                }
            }
            Std::Second => match getnum(value, true) {
                None => bad = true,
                Some((sec, rest)) => {
                    value = rest;
                    f.sec = sec;
                    if !(0..60).contains(&sec) {
                        range_err = "second";
                    } else if value.len() >= 2 && comma_or_period(value[0]) && is_digit(value, 1) {
                        // A fractional second in the input: the layout has
                        // none unless the next element asks for it.
                        if elements.get(index + 1) != Some(&Std::FracSecond9) {
                            let mut n = 2;
                            while n < value.len() && is_digit(value, n) {
                                n += 1;
                            }
                            match parse_nanoseconds(value, n) {
                                Some(ns) => f.nsec = ns,
                                None => bad = true,
                            }
                            value = &value[n..];
                        }
                    }
                }
            },
            Std::FracSecond9 => {
                if value.len() >= 2 && comma_or_period(value[0]) && value[1].is_ascii_digit() {
                    let mut i = 0;
                    while i + 1 < value.len() && value[i + 1].is_ascii_digit() {
                        i += 1;
                    }
                    match parse_nanoseconds(value, 1 + i) {
                        Some(ns) => f.nsec = ns,
                        None => bad = true,
                    }
                    value = &value[1 + i..];
                }
            }
            Std::Zone => {
                if value.first() == Some(&b'Z') {
                    value = &value[1..];
                    f.zone_offset = None;
                } else if value.len() < 5 {
                    bad = true;
                } else {
                    let (sign, hour, min) = (value[0], &value[1..3], &value[3..5]);
                    value = &value[5..];
                    let (mut hr, mut mm) = (0, 0);
                    match getnum(hour, true) {
                        Some((v, _)) => {
                            hr = v;
                            match getnum(min, true) {
                                Some((v, _)) => mm = v,
                                None => bad = true,
                            }
                        }
                        None => bad = true,
                    }
                    if hr > 24 {
                        range_err = "time zone offset hour";
                    }
                    if mm > 60 {
                        range_err = "time zone offset minute";
                    }
                    let offset = (hr * 60 + mm) * 60;
                    match sign {
                        b'+' => f.zone_offset = Some(offset),
                        b'-' => f.zone_offset = Some(-offset),
                        _ => bad = true,
                    }
                }
            }
        }
        if !range_err.is_empty() {
            return error(std.text(), value, format!(": {range_err} out of range"));
        }
        if bad {
            return error(std.text(), hold, String::new());
        }
    }
    if !value.is_empty() {
        return error("", value, format!(": extra text: {}", quote(value)));
    }
    if f.month < 0 {
        f.month = 1;
    }
    if f.day < 0 {
        f.day = 1;
    }
    if f.day < 1 || f.day > days_in(f.month, f.year) {
        return error("", value, ": day out of range".to_string());
    }
    Ok(f)
}

/// `Time.Format` of the parsed value with `layout`.
fn format(layout: (&str, &[Std]), f: &Fields) -> String {
    let mut out = String::new();
    for &std in layout.1 {
        match std {
            Std::Year => out.push_str(&format!("{:02}", f.year.rem_euclid(100))),
            Std::LongYear => out.push_str(&format!("{:04}", f.year)),
            Std::Month => out.push_str(&format!("{:02}", f.month)),
            Std::Day => out.push_str(&format!("{:02}", f.day)),
            Std::Hour => out.push_str(&format!("{:02}", f.hour)),
            Std::Minute => out.push_str(&format!("{:02}", f.min)),
            Std::Second => out.push_str(&format!("{:02}", f.sec)),
            Std::FracSecond9 => {
                if f.nsec != 0 {
                    let digits = format!("{:09}", f.nsec);
                    out.push('.');
                    out.push_str(digits.trim_end_matches('0'));
                }
            }
            Std::Zone => match f.zone_offset {
                None | Some(0) => out.push('Z'),
                Some(offset) => {
                    let magnitude = offset.abs();
                    out.push(if offset < 0 { '-' } else { '+' });
                    out.push_str(&format!(
                        "{:02}{:02}",
                        magnitude / 3600,
                        magnitude % 3600 / 60
                    ));
                }
            },
        }
    }
    out
}

/// Go's `%q` of an ASCII string.
fn go_quote(s: &[u8]) -> String {
    let mut out = String::from("\"");
    for &b in s {
        match b {
            b'"' => out.push_str("\\\""),
            b'\\' => out.push_str("\\\\"),
            0x07 => out.push_str("\\a"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x0b => out.push_str("\\v"),
            b' '..=b'~' => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out.push('"');
    out
}

fn check_round_trip(layout: (&str, &[Std]), fields: &Fields, s: &[u8]) -> Result<(), String> {
    let serialized = format(layout, fields);
    if serialized.as_bytes() != s {
        return Err(format!(
            "asn1: time did not serialize back to the original value and may be invalid: given {}, but serialized as {}",
            go_quote(s),
            go_quote(serialized.as_bytes())
        ));
    }
    Ok(())
}

/// The instant the fields denote.
fn to_time(fields: &Fields) -> Result<Time, String> {
    let date = |f: &Fields| {
        Time::date(
            f.year,
            f.month as u32,
            f.day as u32,
            f.hour as u32,
            f.min as u32,
            f.sec as u32,
        )
    };
    let base = date(fields).ok_or_else(|| "asn1: invalid time".to_string())?;
    let t = base.add_secs(-fields.zone_offset.unwrap_or(0));
    Ok(Time::unix(t.unix_secs(), fields.nsec))
}

/// Go's `parseUTCTime`.
pub(crate) fn parse_utc_time(bytes: &[u8]) -> Result<Time, String> {
    let (layout, fields) = match parse(LAYOUT_UTC_SHORT, bytes) {
        Ok(fields) => (LAYOUT_UTC_SHORT, fields),
        Err(_) => (LAYOUT_UTC, parse(LAYOUT_UTC, bytes)?),
    };
    check_round_trip(layout, &fields, bytes)?;
    let t = to_time(&fields)?;
    // UTCTime only encodes times prior to 2050.
    Ok(if fields.year >= 2050 {
        t.add_years(-100)
    } else {
        t
    })
}

/// Go's `parseGeneralizedTime`.
pub(crate) fn parse_generalized_time(bytes: &[u8]) -> Result<Time, String> {
    let fields = parse(LAYOUT_GENERALIZED, bytes)?;
    check_round_trip(LAYOUT_GENERALIZED, &fields, bytes)?;
    to_time(&fields)
}
