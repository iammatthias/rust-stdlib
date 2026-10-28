//! Go's `time` package: instants, durations, calendars, IANA time zones,
//! layout formatting and parsing, plus Gregorian civil timestamps and
//! explicit transition zones.
//!
//! [`Time`], [`Duration`], [`Month`], [`Weekday`], [`Location`] and
//! [`ParseError`] port Go's types with Go's results: see `docs/api/time.json`
//! for the mapping of every exported Go symbol. [`Location`] reads TZif files
//! (versions 1 to 4) with their POSIX TZ footer; [`load_location`] searches
//! `ZONEINFO`, the system zoneinfo directories, and the embedded database when
//! the `tzdata` feature is enabled. Leap seconds are ignored, as in Go.
//! [`Timer`], [`Ticker`], [`after`], [`after_func`], [`tick`] and [`sleep`]
//! run on one background scheduler thread; `Timer::c` and `Ticker::c` are
//! [`Channel`]s wrapping `std::sync::mpsc` receivers, so both are `Sync`.
//!
//! Coming from `chrono`: RFC 3339 parsing follows Go, so a lowercase `t` or
//! `z`, a space separator and second `:60` are rejected, while a comma before
//! the fraction and the offset `+24:00` are accepted. [`RFC3339_NANO`] and
//! JSON output trim trailing zeros from the fraction (`07.25Z`). [`now`] loads
//! the local zone once per process. `Time` compares with `==`, `<` and
//! [`Time::compare`] like Go's `Equal` and `Compare`, using the monotonic
//! reading when both values carry one, so it has no `Ord` or `Hash`: key a
//! sort or map on `(t.unix(), t.nanosecond())` for a total order on the
//! instant. There is no serde support; wrap
//! `marshal_text` and `unmarshal_text` in a `#[serde(with)]` module.
//!
//! [`DateTime`] is a separate validated civil timestamp (years 1..=9999,
//! offsets below 24 hours) with strict RFC 3339 parsing, used by `net::mail`
//! and `encoding::asn1`; [`Zone`] resolves civil times against explicit
//! transitions. Calendar rules: <https://www.rfc-editor.org/rfc/rfc3339.html>.
//!
//! ```
//! use rust_stdlib::time::{self, Location, Time};
//! let cet = Location::fixed("CET", 3600);
//! let t = time::unix(1_700_000_000, 0).in_location(&cet);
//! assert_eq!(t.zone(), ("CET", 3600));
//! assert_eq!(t.to_string(), "2023-11-14 23:13:20 +0100 CET");
//! assert_eq!(t.format(time::RFC1123), "Tue, 14 Nov 2023 23:13:20 CET");
//! let parsed = time::Time::parse(time::RFC3339, "2023-11-14T23:13:20+01:00").unwrap();
//! assert!(parsed.equal(&t));
//! assert_eq!("1h30m".parse::<time::Duration>().unwrap(), 90 * time::MINUTE);
//! ```
//!
//! ```
//! use rust_stdlib::time::DateTime;
//! let date = DateTime::parse_rfc3339("2024-02-29T12:00:00+05:30")?;
//! assert_eq!(date.format_rfc3339()?, "2024-02-29T12:00:00+05:30");
//! let utc = DateTime::from_unix(date.unix_seconds(), date.nanosecond(), 0)?;
//! assert_eq!(utc.format_rfc3339()?, "2024-02-29T06:30:00Z");
//! # Ok::<(), rust_stdlib::time::Error>(())
//! ```
use std::{error, fmt};

mod duration;
mod format;
mod instant;
mod location;
mod timer;
#[cfg(feature = "tzdata")]
pub mod tzdata;
pub use duration::{
    Duration, NegativeDurationError, ParseDurationError, HOUR, MICROSECOND, MILLISECOND, MINUTE,
    NANOSECOND, SECOND,
};
pub use format::{
    ParseError, UnmarshalError, ANSIC, DATE_ONLY, DATE_TIME, KITCHEN, LAYOUT, RFC1123, RFC1123Z,
    RFC3339, RFC3339_NANO, RFC822, RFC822Z, RFC850, RUBY_DATE, STAMP, STAMP_MICRO, STAMP_MILLI,
    STAMP_NANO, TIME_ONLY, UNIX_DATE,
};
pub use instant::{
    date, now, since, unix, unix_micro, unix_milli, until, Month, Time, Weekday, APRIL, AUGUST,
    DECEMBER, FEBRUARY, FRIDAY, JANUARY, JULY, JUNE, MARCH, MAY, MONDAY, NOVEMBER, OCTOBER,
    SATURDAY, SEPTEMBER, SUNDAY, THURSDAY, TUESDAY, WEDNESDAY,
};
pub use location::{
    load_location, load_location_from, load_location_with, local, local_for_tz, tzdata_from_zip,
    validate_location_name, Location, LocationError, ZoneInfo, ALPHA, MAX_TZDATA_LEN, OMEGA,
    PLATFORM_ZONE_SOURCES,
};
pub use timer::{after, after_func, sleep, tick, Channel, Ticker, Timer};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl error::Error for Error {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
    offset: i32,
}
fn leap(y: u16) -> bool {
    y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400))
}
fn month_days(y: u16, m: u8) -> u8 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}
fn days_before_year(y: u16) -> i64 {
    let y = i64::from(y) - 1;
    365 * y + y / 4 - y / 100 + y / 400
}
const EPOCH_DAYS: i64 = 719162;
impl DateTime {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        nanosecond: u32,
        offset: i32,
    ) -> Result<Self, Error> {
        if !(1..=9999).contains(&year)
            || day == 0
            || day > month_days(year, month)
            || hour > 23
            || minute > 59
            || second > 59
            || nanosecond >= 1_000_000_000
            || offset <= -86400
            || offset >= 86400
        {
            return Err(Error("invalid civil timestamp"));
        }
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
            offset,
        })
    }
    pub fn year(&self) -> u16 {
        self.year
    }
    pub fn month(&self) -> u8 {
        self.month
    }
    pub fn day(&self) -> u8 {
        self.day
    }
    pub fn hour(&self) -> u8 {
        self.hour
    }
    pub fn minute(&self) -> u8 {
        self.minute
    }
    pub fn second(&self) -> u8 {
        self.second
    }
    pub fn nanosecond(&self) -> u32 {
        self.nanosecond
    }
    pub fn offset(&self) -> i32 {
        self.offset
    }
    pub fn unix_seconds(&self) -> i64 {
        let days = days_before_year(self.year)
            + (1..self.month)
                .map(|m| i64::from(month_days(self.year, m)))
                .sum::<i64>()
            + i64::from(self.day)
            - 1
            - EPOCH_DAYS;
        days * 86400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second)
            - i64::from(self.offset)
    }
    pub fn from_unix(seconds: i64, nanosecond: u32, offset: i32) -> Result<Self, Error> {
        if offset <= -86400 || offset >= 86400 || nanosecond >= 1_000_000_000 {
            return Err(Error("invalid timestamp offset or fraction"));
        }
        let local = seconds
            .checked_add(i64::from(offset))
            .ok_or(Error("timestamp overflow"))?;
        let days = local
            .div_euclid(86400)
            .checked_add(EPOCH_DAYS)
            .ok_or(Error("timestamp overflow"))?;
        if days < 0 || days >= days_before_year(10000) {
            return Err(Error("timestamp outside civil range"));
        }
        let mut low = 1u16;
        let mut high = 10000u16;
        while low + 1 < high {
            let mid = low + (high - low) / 2;
            if days_before_year(mid) <= days {
                low = mid
            } else {
                high = mid
            }
        }
        let mut rem = days - days_before_year(low);
        let mut month = 1u8;
        while rem >= i64::from(month_days(low, month)) {
            rem -= i64::from(month_days(low, month));
            month += 1;
        }
        let tod = local.rem_euclid(86400);
        Self::new(
            low,
            month,
            (rem + 1) as u8,
            (tod / 3600) as u8,
            ((tod % 3600) / 60) as u8,
            (tod % 60) as u8,
            nanosecond,
            offset,
        )
    }
    pub fn parse_rfc3339(s: &str) -> Result<Self, Error> {
        let b = s.as_bytes();
        if b.len() < 20
            || b.len() > 35
            || !s.is_ascii()
            || b[4] != b'-'
            || b[7] != b'-'
            || !matches!(b[10], b'T' | b't')
            || b[13] != b':'
            || b[16] != b':'
        {
            return Err(Error("invalid RFC3339 syntax"));
        }
        fn num(b: &[u8]) -> Result<u32, Error> {
            if !b.iter().all(u8::is_ascii_digit) {
                return Err(Error("invalid timestamp digit"));
            }
            Ok(b.iter().fold(0, |n, c| n * 10 + u32::from(c - b'0')))
        }
        let mut pos = 19;
        let mut nanos = 0;
        if b[pos] == b'.' {
            pos += 1;
            let start = pos;
            while pos < b.len() && b[pos].is_ascii_digit() {
                pos += 1;
            }
            let n = pos - start;
            if n == 0 || n > 9 {
                return Err(Error("invalid timestamp fraction"));
            }
            nanos = num(&b[start..pos])? * 10u32.pow((9 - n) as u32);
        }
        let offset = if pos + 1 == b.len() && matches!(b[pos], b'Z' | b'z') {
            0
        } else {
            if pos + 6 != b.len() || !matches!(b[pos], b'+' | b'-') || b[pos + 3] != b':' {
                return Err(Error("invalid timestamp offset"));
            }
            let h = num(&b[pos + 1..pos + 3])?;
            let m = num(&b[pos + 4..pos + 6])?;
            if h > 23 || m > 59 {
                return Err(Error("invalid timestamp offset"));
            }
            let v = (h * 3600 + m * 60) as i32;
            if b[pos] == b'-' {
                if v == 0 {
                    return Err(Error("unknown timestamp offset"));
                }
                -v
            } else {
                v
            }
        };
        Self::new(
            num(&b[..4])? as u16,
            num(&b[5..7])? as u8,
            num(&b[8..10])? as u8,
            num(&b[11..13])? as u8,
            num(&b[14..16])? as u8,
            num(&b[17..19])? as u8,
            nanos,
            offset,
        )
    }
    pub fn format_rfc3339(&self) -> Result<String, Error> {
        if self.offset % 60 != 0 {
            return Err(Error("RFC3339 needs minute-aligned offset"));
        }
        let mut s = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        );
        if self.nanosecond != 0 {
            s.push('.');
            s.push_str(format!("{:09}", self.nanosecond).trim_end_matches('0'));
        }
        if self.offset == 0 {
            s.push('Z');
        } else {
            let o = self.offset.abs();
            s.push_str(&format!(
                "{}{:02}:{:02}",
                if self.offset < 0 { '-' } else { '+' },
                o / 3600,
                (o % 3600) / 60
            ));
        }
        Ok(s)
    }
}
#[derive(Debug, Clone, Copy)]
pub struct Transition {
    pub unix_seconds: i64,
    pub offset: i32,
}
#[derive(Debug, Clone)]
pub struct Zone {
    initial_offset: i32,
    transitions: Vec<Transition>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalResult {
    Missing,
    Unique(i64),
    Ambiguous(Vec<i64>),
}
impl Zone {
    pub fn new(initial_offset: i32, transitions: Vec<Transition>) -> Result<Self, Error> {
        if initial_offset <= -86400
            || initial_offset >= 86400
            || transitions.len() > 100000
            || transitions
                .iter()
                .any(|t| t.offset <= -86400 || t.offset >= 86400)
            || transitions
                .windows(2)
                .any(|w| w[0].unix_seconds >= w[1].unix_seconds)
        {
            return Err(Error("invalid zone transitions"));
        }
        Ok(Self {
            initial_offset,
            transitions,
        })
    }
    pub fn offset_at(&self, seconds: i64) -> i32 {
        let i = self
            .transitions
            .partition_point(|t| t.unix_seconds <= seconds);
        if i == 0 {
            self.initial_offset
        } else {
            self.transitions[i - 1].offset
        }
    }
    pub fn at(&self, seconds: i64, nanosecond: u32) -> Result<DateTime, Error> {
        DateTime::from_unix(seconds, nanosecond, self.offset_at(seconds))
    }
    /// Resolve local civil fields; the input's offset is ignored. Gaps and
    /// overlaps are reported explicitly instead of choosing a daylight rule.
    pub fn resolve(&self, local: &DateTime) -> LocalResult {
        let wall = local.unix_seconds() + i64::from(local.offset);
        let mut offsets = std::collections::BTreeSet::new();
        offsets.insert(self.initial_offset);
        offsets.extend(self.transitions.iter().map(|t| t.offset));
        let mut matches: Vec<_> = offsets
            .into_iter()
            .filter_map(|o| {
                let utc = wall - i64::from(o);
                (self.offset_at(utc) == o).then_some(utc)
            })
            .collect();
        matches.sort_unstable();
        match matches.len() {
            0 => LocalResult::Missing,
            1 => LocalResult::Unique(matches[0]),
            _ => LocalResult::Ambiguous(matches),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn epoch_and_calendar_roundtrip() {
        assert_eq!(
            DateTime::parse_rfc3339("1970-01-01T00:00:00Z")
                .unwrap()
                .unix_seconds(),
            0
        );
        for y in [1, 1600, 1900, 1969, 1970, 2000, 2024, 9999] {
            for m in 1..=12 {
                let d = DateTime::new(y, m, month_days(y, m), 23, 59, 59, 123, -19800).unwrap();
                assert_eq!(
                    DateTime::from_unix(d.unix_seconds(), 123, -19800).unwrap(),
                    d
                );
            }
        }
        assert_eq!(
            DateTime::from_unix(-1, 0, 0)
                .unwrap()
                .format_rfc3339()
                .unwrap(),
            "1969-12-31T23:59:59Z"
        );
    }
    #[test]
    fn rfc_syntax_limits() {
        let s = "2024-02-29T12:34:56.123456789+05:30";
        assert_eq!(
            DateTime::parse_rfc3339(s)
                .unwrap()
                .format_rfc3339()
                .unwrap(),
            s
        );
        for s in [
            "1900-02-29T00:00:00Z",
            "2024-01-01T00:00:60Z",
            "2024-01-01T00:00:00-00:00",
            "2024-01-01T00:00:00.Z",
            "2024-01-01T00:00:00.1234567890Z",
            "2024-01-01T00:00:00+24:00",
            "2024-01-01T00:00:00.123",
            "0000-01-01T00:00:00Z",
        ] {
            assert!(DateTime::parse_rfc3339(s).is_err(), "{s}");
        }
        assert!(DateTime::from_unix(i64::MAX, 0, 0).is_err());
    }
    #[test]
    fn transition_gaps_overlaps() {
        let z = Zone::new(
            0,
            vec![
                Transition {
                    unix_seconds: 0,
                    offset: 3600,
                },
                Transition {
                    unix_seconds: 7200,
                    offset: 0,
                },
            ],
        )
        .unwrap();
        assert_eq!(
            z.resolve(&DateTime::from_unix(1800, 0, 0).unwrap()),
            LocalResult::Missing
        );
        assert_eq!(
            z.resolve(&DateTime::from_unix(8000, 0, 0).unwrap()),
            LocalResult::Ambiguous(vec![4400, 8000])
        );
        assert_eq!(z.offset_at(-1), 0);
        assert_eq!(z.offset_at(0), 3600);
        assert!(Zone::new(
            0,
            vec![
                Transition {
                    unix_seconds: 0,
                    offset: 0
                },
                Transition {
                    unix_seconds: 0,
                    offset: 1
                }
            ]
        )
        .is_err());
    }
}
