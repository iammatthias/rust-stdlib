//! UTCTime and GeneralizedTime.
//!
//! Go parses with `time.Parse` and then rejects any input that does not format
//! back to exactly the same text, so the accepted language is the canonical
//! form: fixed-width digits, `Z` for a zero offset, `±hhmm` otherwise and (for
//! GeneralizedTime) an optional fraction without trailing zeros. These
//! functions accept exactly that language.
use super::Error;
use crate::time::DateTime;

fn digits(b: &[u8]) -> Option<u32> {
    if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(b.iter().fold(0, |n, c| n * 10 + u32::from(c - b'0')))
}

/// Parses the zone designator: `Z` or a non-zero `±hhmm` with hh <= 24 and
/// mm <= 59 (`+0000`/`-0000` format back as `Z` and are rejected).
fn parse_zone(b: &[u8]) -> Result<i32, Error> {
    match b {
        b"Z" => Ok(0),
        [sign @ (b'+' | b'-'), rest @ ..] if rest.len() == 4 => {
            let h = digits(&rest[..2]).ok_or(Error::time("invalid time zone"))?;
            let m = digits(&rest[2..]).ok_or(Error::time("invalid time zone"))?;
            if h > 24 || m > 59 || (h == 0 && m == 0) {
                return Err(Error::time("time zone offset out of range"));
            }
            let v = (h * 3600 + m * 60) as i32;
            Ok(if *sign == b'-' { -v } else { v })
        }
        _ => Err(Error::time("invalid time zone")),
    }
}

fn days_in(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

struct Fields {
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
    nanosecond: u32,
    offset: i32,
}

fn build(f: Fields) -> Result<DateTime, Error> {
    if !(1..=12).contains(&f.month)
        || f.day == 0
        || f.day > days_in(f.year, f.month)
        || f.hour > 23
        || f.minute > 59
        || f.second > 59
    {
        return Err(Error::time("time field out of range"));
    }
    // Go additionally accepts year 0000 and offsets of ±24h, which
    // `time::DateTime` cannot represent.
    let year = u16::try_from(f.year).map_err(|_| Error::time("year out of range"))?;
    DateTime::new(
        year,
        f.month as u8,
        f.day as u8,
        f.hour as u8,
        f.minute as u8,
        f.second as u8,
        f.nanosecond,
        f.offset,
    )
    .map_err(|_| Error::time("time outside the representable range"))
}

fn two(b: &[u8], at: usize) -> Result<u32, Error> {
    b.get(at..at + 2)
        .and_then(digits)
        .ok_or(Error::time("invalid time digits"))
}

/// `YYMMDDhhmm[ss](Z|±hhmm)`; years 50..99 are 1950..1999, 00..49 are 2000..2049.
pub(crate) fn parse_utc_time(b: &[u8]) -> Result<DateTime, Error> {
    let seconds = b.len() > 12 && b[10].is_ascii_digit();
    let zone_at = if seconds { 12 } else { 10 };
    if b.len() <= zone_at {
        return Err(Error::time("invalid UTCTime"));
    }
    let yy = two(b, 0)?;
    let f = Fields {
        year: if yy >= 50 { 1900 + yy } else { 2000 + yy },
        month: two(b, 2)?,
        day: two(b, 4)?,
        hour: two(b, 6)?,
        minute: two(b, 8)?,
        second: if seconds { two(b, 10)? } else { 0 },
        nanosecond: 0,
        offset: parse_zone(&b[zone_at..])?,
    };
    build(f)
}

/// `YYYYMMDDhhmmss[.fraction](Z|±hhmm)`.
pub(crate) fn parse_generalized_time(b: &[u8]) -> Result<DateTime, Error> {
    if b.len() < 15 {
        return Err(Error::time("invalid GeneralizedTime"));
    }
    let year = b
        .get(..4)
        .and_then(digits)
        .ok_or(Error::time("invalid time digits"))?;
    let mut pos = 14;
    let mut nanosecond = 0;
    if b[pos] == b'.' {
        let start = pos + 1;
        let mut end = start;
        while end < b.len() && b[end].is_ascii_digit() {
            end += 1;
        }
        let n = end - start;
        if n == 0 || n > 9 || b[end - 1] == b'0' {
            return Err(Error::time("invalid fractional seconds"));
        }
        nanosecond = digits(&b[start..end]).ok_or(Error::time("invalid time digits"))?
            * 10u32.pow((9 - n) as u32);
        pos = end;
    }
    let f = Fields {
        year,
        month: two(b, 4)?,
        day: two(b, 6)?,
        hour: two(b, 8)?,
        minute: two(b, 10)?,
        second: two(b, 12)?,
        nanosecond,
        offset: parse_zone(&b[pos..])?,
    };
    build(f)
}

pub(crate) fn outside_utc_range(t: &DateTime) -> bool {
    !(1950..2050).contains(&t.year())
}

fn push_two(out: &mut Vec<u8>, v: u32) {
    out.push(b'0' + (v / 10 % 10) as u8);
    out.push(b'0' + (v % 10) as u8);
}

/// Go's appendTimeCommon: no fraction; `Z` when the offset truncates to zero
/// minutes, otherwise `±hhmm` of the truncated minutes.
fn append_common(out: &mut Vec<u8>, t: &DateTime) {
    push_two(out, u32::from(t.month()));
    push_two(out, u32::from(t.day()));
    push_two(out, u32::from(t.hour()));
    push_two(out, u32::from(t.minute()));
    push_two(out, u32::from(t.second()));
    let offset = t.offset();
    if offset / 60 == 0 {
        out.push(b'Z');
        return;
    }
    out.push(if offset > 0 { b'+' } else { b'-' });
    let minutes = (offset / 60).unsigned_abs();
    push_two(out, minutes / 60);
    push_two(out, minutes % 60);
}

pub(crate) fn append_utc_time(out: &mut Vec<u8>, t: &DateTime) -> Result<(), Error> {
    let year = u32::from(t.year());
    match year {
        1950..=1999 => push_two(out, year - 1900),
        2000..=2049 => push_two(out, year - 2000),
        _ => return Err(Error::structural("cannot represent time as UTCTime")),
    }
    append_common(out, t);
    Ok(())
}

pub(crate) fn append_generalized_time(out: &mut Vec<u8>, t: &DateTime) {
    let year = u32::from(t.year());
    push_two(out, year / 100);
    push_two(out, year % 100);
    append_common(out, t);
}

/// Go's zero `time.Time`: 0001-01-01 00:00:00 UTC.
pub(crate) fn zero_time() -> DateTime {
    DateTime::new(1, 1, 1, 0, 0, 0, 0, 0).expect("0001-01-01 is a valid civil time")
}

pub(crate) fn is_zero_time(t: &DateTime) -> bool {
    *t == zero_time()
}
