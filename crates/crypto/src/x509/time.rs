//! The instant type of `crypto/x509`.
//!
//! This crate has no dependency on the root crate's `time` package
//! (docs/adr/0003), so Go's `time.Time` is [`Time`]: seconds and nanoseconds
//! since the Unix epoch. The zero value is Go's zero time (January 1, year 1,
//! UTC), which is not the epoch.

use std::cmp::Ordering;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds from 0001-01-01 to 1970-01-01.
const UNIX_TO_INTERNAL: i64 = 62_135_596_800;

/// Go's `time.Time` as far as `crypto/x509` uses it: an instant with
/// nanosecond precision. Comparison is by instant, like `time.Time.Equal`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Time {
    /// Seconds since 1970-01-01T00:00:00Z.
    secs: i64,
    /// Nanoseconds within the second, `0..1_000_000_000`.
    nanos: u32,
}

impl Default for Time {
    /// The zero time, January 1, year 1, 00:00:00 UTC.
    fn default() -> Time {
        Time::ZERO
    }
}

impl Time {
    /// Go's zero `time.Time{}`.
    pub const ZERO: Time = Time {
        secs: -UNIX_TO_INTERNAL,
        nanos: 0,
    };

    /// `time.Unix(secs, nanos)`.
    pub fn unix(secs: i64, nanos: i64) -> Time {
        let carry = nanos.div_euclid(1_000_000_000);
        let nanos = nanos.rem_euclid(1_000_000_000) as u32;
        Time {
            secs: secs.saturating_add(carry),
            nanos,
        }
    }

    /// `time.Now()`.
    pub fn now() -> Time {
        Time::from(SystemTime::now())
    }

    /// Whether this is the zero time, like `time.Time.IsZero`.
    pub fn is_zero(&self) -> bool {
        *self == Time::ZERO
    }

    /// Seconds since the Unix epoch, like `time.Time.Unix`.
    pub fn unix_secs(&self) -> i64 {
        self.secs
    }

    /// The nanosecond offset within the second, like `time.Time.Nanosecond`.
    pub fn nanosecond(&self) -> u32 {
        self.nanos
    }

    /// Like `time.Time.Before`.
    pub fn before(&self, other: &Time) -> bool {
        self.cmp(other) == Ordering::Less
    }

    /// Like `time.Time.After`.
    pub fn after(&self, other: &Time) -> bool {
        self.cmp(other) == Ordering::Greater
    }

    /// Like `time.Time.Equal`.
    pub fn equal(&self, other: &Time) -> bool {
        self == other
    }

    /// Go's `time.Time.UTC`; instants carry no location here.
    pub fn utc(&self) -> Time {
        *self
    }

    /// The year, like `time.Time.Year` in UTC.
    pub fn year(&self) -> i64 {
        self.civil().0
    }

    /// `(year, month, day, hour, minute, second)` in UTC.
    pub fn civil(&self) -> (i64, u32, u32, u32, u32, u32) {
        let days = self.secs.div_euclid(86_400);
        let rem = self.secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        (
            y,
            m,
            d,
            (rem / 3600) as u32,
            (rem % 3600 / 60) as u32,
            (rem % 60) as u32,
        )
    }

    /// The instant of a calendar date and time in UTC, or `None` if a field
    /// is out of range.
    pub fn date(year: i64, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<Time> {
        if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
            return None;
        }
        if hour > 23 || min > 59 || sec > 59 {
            return None;
        }
        let days = days_from_civil(year, month, day);
        Some(Time {
            secs: days * 86_400 + i64::from(hour * 3600 + min * 60 + sec),
            nanos: 0,
        })
    }

    /// `t.AddDate(years, 0, 0)` for a date that stays valid (the callers only
    /// shift by whole centuries).
    pub fn add_years(&self, years: i64) -> Time {
        let (y, m, d, hh, mm, ss) = self.civil();
        let ny = y + years;
        // Go normalizes February 29 to March 1 in a non-leap year.
        let (m2, d2) = if m == 2 && d == 29 && days_in_month(ny, 2) < 29 {
            (3, 1)
        } else {
            (m, d)
        };
        let days = days_from_civil(ny, m2, d2);
        Time {
            secs: days * 86_400 + i64::from(hh * 3600 + mm * 60 + ss),
            nanos: self.nanos,
        }
    }

    /// `t.Add(d)` with a whole number of seconds.
    pub fn add_secs(&self, secs: i64) -> Time {
        Time {
            secs: self.secs.saturating_add(secs),
            nanos: self.nanos,
        }
    }

    /// The time formatted like `t.UTC().Format(time.RFC3339)`.
    pub fn format_rfc3339(&self) -> String {
        let (y, mo, d, hh, mm, ss) = self.civil();
        if (0..=9999).contains(&y) {
            format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
        } else {
            format!("{y}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
        }
    }

    /// Converts to a [`SystemTime`] if it is representable.
    pub fn to_system_time(&self) -> Option<SystemTime> {
        if self.secs >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(self.secs as u64, self.nanos))
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_secs(self.secs.unsigned_abs()))
                .and_then(|t| t.checked_add(Duration::from_nanos(u64::from(self.nanos))))
        }
    }
}

impl PartialOrd for Time {
    fn partial_cmp(&self, other: &Time) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Time {
    fn cmp(&self, other: &Time) -> Ordering {
        (self.secs, self.nanos).cmp(&(other.secs, other.nanos))
    }
}

impl From<SystemTime> for Time {
    fn from(t: SystemTime) -> Time {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Time::unix(d.as_secs() as i64, i64::from(d.subsec_nanos())),
            Err(e) => {
                let d = e.duration();
                Time::unix(-(d.as_secs() as i64), -i64::from(d.subsec_nanos()))
            }
        }
    }
}

impl fmt::Display for Time {
    /// Go's `Time.String` for a UTC time: `2006-01-02 15:04:05.999999999 +0000 UTC`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, mo, d, hh, mm, ss) = self.civil();
        write!(f, "{y:04}-{mo:02}-{d:02} {hh:02}:{mm:02}:{ss:02}")?;
        if self.nanos != 0 {
            let frac = format!("{:09}", self.nanos);
            write!(f, ".{}", frac.trim_end_matches('0'))?;
        }
        f.write_str(" +0000 UTC")
    }
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_and_epoch() {
        assert!(Time::ZERO.is_zero());
        assert_eq!(Time::ZERO.civil(), (1, 1, 1, 0, 0, 0));
        assert_eq!(Time::unix(0, 0).civil(), (1970, 1, 1, 0, 0, 0));
        assert_eq!(
            Time::date(2024, 2, 29, 12, 0, 0).unwrap().format_rfc3339(),
            "2024-02-29T12:00:00Z"
        );
        assert!(Time::date(2023, 2, 29, 0, 0, 0).is_none());
    }
}
