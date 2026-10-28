//! Go's `time.Time`: instants with an optional monotonic reading, calendar
//! accessors, arithmetic, rounding and binary/JSON/text encodings.
//!
//! The representation and the calendar algorithms port Go's
//! `src/time/time.go` so results match Go bit for bit, including wrapping at
//! the extremes of the representable range.
use super::duration::{Duration, MAX_DURATION, MIN_DURATION, SECOND};
use super::location::{local, Location};
use super::Error;
use std::cmp::Ordering;
use std::fmt;
use std::sync::OnceLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const HAS_MONOTONIC: u64 = 1 << 63;
const NSEC_MASK: u64 = (1 << 30) - 1;
const NSEC_SHIFT: u32 = 30;

pub(crate) const SECONDS_PER_MINUTE: i64 = 60;
pub(crate) const SECONDS_PER_HOUR: i64 = 60 * SECONDS_PER_MINUTE;
pub(crate) const SECONDS_PER_DAY: i64 = 24 * SECONDS_PER_HOUR;
const MARCH_THRU_DECEMBER: u64 = 31 + 30 + 31 + 30 + 31 + 31 + 30 + 31 + 30 + 31;
const ABSOLUTE_YEARS: u64 = 292_277_022_400;
/// `-(absoluteYears*365.2425 + marchThruDecember) * secondsPerDay`.
const ABSOLUTE_TO_INTERNAL: i64 = -9_223_371_966_606_163_200;
const INTERNAL_TO_ABSOLUTE: i64 = -ABSOLUTE_TO_INTERNAL;
pub(crate) const UNIX_TO_INTERNAL: i64 =
    (1969 * 365 + 1969 / 4 - 1969 / 100 + 1969 / 400) * SECONDS_PER_DAY;
const INTERNAL_TO_UNIX: i64 = -UNIX_TO_INTERNAL;
const ABSOLUTE_TO_UNIX: i64 = ABSOLUTE_TO_INTERNAL + INTERNAL_TO_UNIX;
pub(crate) const UNIX_TO_ABSOLUTE: i64 = UNIX_TO_INTERNAL + INTERNAL_TO_ABSOLUTE;
const WALL_TO_INTERNAL: i64 = (1884 * 365 + 1884 / 4 - 1884 / 100 + 1884 / 400) * SECONDS_PER_DAY;
const MIN_WALL: i64 = WALL_TO_INTERNAL;

/// A month of the year, Go's `time.Month` (`January` is 1). Values outside
/// 1..=12 are representable, as in Go, and print as `%!Month(n)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Month(pub i64);

impl Month {
    pub const JANUARY: Month = Month(1);
    pub const FEBRUARY: Month = Month(2);
    pub const MARCH: Month = Month(3);
    pub const APRIL: Month = Month(4);
    pub const MAY: Month = Month(5);
    pub const JUNE: Month = Month(6);
    pub const JULY: Month = Month(7);
    pub const AUGUST: Month = Month(8);
    pub const SEPTEMBER: Month = Month(9);
    pub const OCTOBER: Month = Month(10);
    pub const NOVEMBER: Month = Month(11);
    pub const DECEMBER: Month = Month(12);
}

pub const JANUARY: Month = Month::JANUARY;
pub const FEBRUARY: Month = Month::FEBRUARY;
pub const MARCH: Month = Month::MARCH;
pub const APRIL: Month = Month::APRIL;
pub const MAY: Month = Month::MAY;
pub const JUNE: Month = Month::JUNE;
pub const JULY: Month = Month::JULY;
pub const AUGUST: Month = Month::AUGUST;
pub const SEPTEMBER: Month = Month::SEPTEMBER;
pub const OCTOBER: Month = Month::OCTOBER;
pub const NOVEMBER: Month = Month::NOVEMBER;
pub const DECEMBER: Month = Month::DECEMBER;

pub(crate) const LONG_MONTH_NAMES: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
pub(crate) const LONG_DAY_NAMES: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

impl fmt::Display for Month {
    /// Go's `Month.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if (1..=12).contains(&self.0) {
            f.write_str(LONG_MONTH_NAMES[(self.0 - 1) as usize])
        } else {
            write!(f, "%!Month({})", self.0 as u64)
        }
    }
}

/// A day of the week, Go's `time.Weekday` (`Sunday` is 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Weekday(pub i64);

impl Weekday {
    pub const SUNDAY: Weekday = Weekday(0);
    pub const MONDAY: Weekday = Weekday(1);
    pub const TUESDAY: Weekday = Weekday(2);
    pub const WEDNESDAY: Weekday = Weekday(3);
    pub const THURSDAY: Weekday = Weekday(4);
    pub const FRIDAY: Weekday = Weekday(5);
    pub const SATURDAY: Weekday = Weekday(6);
}

pub const SUNDAY: Weekday = Weekday::SUNDAY;
pub const MONDAY: Weekday = Weekday::MONDAY;
pub const TUESDAY: Weekday = Weekday::TUESDAY;
pub const WEDNESDAY: Weekday = Weekday::WEDNESDAY;
pub const THURSDAY: Weekday = Weekday::THURSDAY;
pub const FRIDAY: Weekday = Weekday::FRIDAY;
pub const SATURDAY: Weekday = Weekday::SATURDAY;

impl fmt::Display for Weekday {
    /// Go's `Weekday.String`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if (0..=6).contains(&self.0) {
            f.write_str(LONG_DAY_NAMES[self.0 as usize])
        } else {
            write!(f, "%!Weekday({})", self.0 as u64)
        }
    }
}

/// Go's `isLeap`.
pub(crate) fn is_leap(year: i64) -> bool {
    let mask = if year % 25 != 0 { 3 } else { 15 };
    year & mask == 0
}

/// Go's `daysBefore`: days before month `m` in a non-leap year.
pub(crate) fn days_before(m: i64) -> i64 {
    let adj = if m >= 3 { -2 } else { 0 };
    (214 * m - 211) / 7 + adj
}

/// Go's `daysIn`.
pub(crate) fn days_in(m: i64, year: i64) -> i64 {
    if m == 2 {
        return if is_leap(year) { 29 } else { 28 };
    }
    30 + ((m + (m >> 3)) & 1)
}

/// Seconds since Go's absolute epoch (March 1, -292277022399).
#[derive(Clone, Copy)]
pub(crate) struct AbsSeconds(u64);
/// Days since Go's absolute epoch.
#[derive(Clone, Copy)]
pub(crate) struct AbsDays(u64);

/// Go's `dateToAbsDays`.
fn date_to_abs_days(year: i64, month: i64, day: i64) -> AbsDays {
    let mut amonth = month as u32;
    let jan_feb = u32::from(amonth < 3);
    amonth = amonth.wrapping_add(12 * jan_feb);
    let y = (year as u64)
        .wrapping_sub(u64::from(jan_feb))
        .wrapping_add(ABSOLUTE_YEARS);
    let ayday = (979u32.wrapping_mul(amonth).wrapping_sub(2919)) >> 5;
    let century = y / 100;
    let cyear = (y % 100) as u32;
    let cday = 1461 * cyear / 4;
    let centurydays = 146_097u64.wrapping_mul(century) / 4;
    let rest = i64::from(cday + ayday).wrapping_add(day).wrapping_sub(1);
    AbsDays(centurydays.wrapping_add(rest as u64))
}

impl AbsSeconds {
    pub(crate) fn from_unix(sec: i64) -> Self {
        AbsSeconds(sec.wrapping_add(UNIX_TO_ABSOLUTE) as u64)
    }
    pub(crate) fn days(self) -> AbsDays {
        AbsDays(self.0 / SECONDS_PER_DAY as u64)
    }
    /// Go's `absSeconds.clock`.
    pub(crate) fn clock(self) -> (i64, i64, i64) {
        let mut sec = (self.0 % SECONDS_PER_DAY as u64) as i64;
        let hour = sec / SECONDS_PER_HOUR;
        sec -= hour * SECONDS_PER_HOUR;
        let min = sec / SECONDS_PER_MINUTE;
        sec -= min * SECONDS_PER_MINUTE;
        (hour, min, sec)
    }
}

impl AbsDays {
    /// Go's `absDays.split`: century, year in century, day in March-based year.
    fn split(self) -> (u64, u32, u32) {
        let d = 4u64.wrapping_mul(self.0).wrapping_add(3);
        let century = d / 146_097;
        let cd = (d % 146_097) as u32 | 3;
        let product = 2_939_745u64 * u64::from(cd);
        let cyear = (product >> 32) as u32;
        let ayday = (product as u32) / 2_939_745 / 4;
        (century, cyear, ayday)
    }
    pub(crate) fn date(self) -> (i64, i64, i64) {
        let (century, cyear, ayday) = self.split();
        let (amonth, day) = ayday_split(ayday);
        let jan_feb = jan_feb(ayday);
        (
            century_year(century, cyear, jan_feb),
            amonth - jan_feb * 12,
            day,
        )
    }
    pub(crate) fn year_yday(self) -> (i64, i64) {
        let (century, cyear, ayday) = self.split();
        let jan_feb = jan_feb(ayday);
        let leap =
            i64::from(cyear % 4 == 0) & (i64::from(cyear != 0) | i64::from(century % 4 == 0));
        let yday = i64::from(ayday) + (1 + 31 + 28) + (leap & !jan_feb) - 365 * jan_feb;
        (century_year(century, cyear, jan_feb), yday)
    }
    pub(crate) fn weekday(self) -> Weekday {
        Weekday((self.0.wrapping_add(3) % 7) as i64)
    }
}

fn ayday_split(ayday: u32) -> (i64, i64) {
    let d = 2141u32.wrapping_mul(ayday).wrapping_add(197_913);
    (i64::from(d >> 16), 1 + i64::from((d & 0xFFFF) / 2141))
}

fn jan_feb(ayday: u32) -> i64 {
    i64::from(u64::from(ayday) >= MARCH_THRU_DECEMBER)
}

fn century_year(century: u64, cyear: u32, jan_feb: i64) -> i64 {
    (century.wrapping_mul(100).wrapping_sub(ABSOLUTE_YEARS) as i64)
        .wrapping_add(i64::from(cyear))
        .wrapping_add(jan_feb)
}

/// Calendar year and 1-based day of year of a Unix instant (UTC), via Go's
/// absolute-date algorithm.
pub(crate) fn unix_year_yday(sec: i64) -> (i64, i64) {
    AbsSeconds::from_unix(sec).days().year_yday()
}

/// Process-start base for monotonic readings (Go's `startNano`).
fn mono_base() -> Instant {
    static BASE: OnceLock<Instant> = OnceLock::new();
    *BASE.get_or_init(Instant::now)
}

/// Monotonic nanoseconds since the process base, at least 1.
fn mono_now() -> i64 {
    let elapsed = mono_base().elapsed().as_nanos();
    i64::try_from(elapsed).unwrap_or(i64::MAX - 1) + 1
}

/// Go's `time.Time`: an instant with nanosecond precision, an optional
/// monotonic clock reading (set by [`now`]) and a [`Location`].
///
/// The zero value ([`Time::default`]) is January 1, year 1, 00:00:00 UTC.
/// `==` compares instants like Go's `Equal`; ordering follows `Compare`.
#[derive(Clone, Debug, Default)]
pub struct Time {
    wall: u64,
    ext: i64,
    /// `None` is UTC, as in Go's `setLoc`.
    loc: Option<Location>,
}

impl PartialEq for Time {
    fn eq(&self, other: &Self) -> bool {
        self.equal(other)
    }
}

impl PartialOrd for Time {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.compare(other).cmp(&0))
    }
}

/// Go's `time.Unix`: the Local time for `sec` seconds and `nsec`
/// nanoseconds since the Unix epoch; `nsec` outside `0..1e9` is normalized.
pub fn unix(mut sec: i64, mut nsec: i64) -> Time {
    if !(0..1_000_000_000).contains(&nsec) {
        let n = nsec / 1_000_000_000;
        sec = sec.wrapping_add(n);
        nsec -= n * 1_000_000_000;
        if nsec < 0 {
            nsec += 1_000_000_000;
            sec = sec.wrapping_sub(1);
        }
    }
    unix_time(sec, nsec as i32)
}

/// Go's `time.UnixMilli`.
pub fn unix_milli(msec: i64) -> Time {
    unix(msec / 1000, (msec % 1000) * 1_000_000)
}

/// Go's `time.UnixMicro`.
pub fn unix_micro(usec: i64) -> Time {
    unix(usec / 1_000_000, (usec % 1_000_000) * 1000)
}

fn unix_time(sec: i64, nsec: i32) -> Time {
    Time {
        wall: nsec as u32 as u64,
        ext: sec.wrapping_add(UNIX_TO_INTERNAL),
        loc: Some(local()),
    }
}

/// Go's `time.Now`: the current Local time with a monotonic reading.
pub fn now() -> Time {
    let (sec, nsec) = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos() as i64),
        Err(e) => {
            let d = e.duration();
            (-(d.as_secs() as i64), -(d.subsec_nanos() as i64))
        }
    };
    let (sec, nsec) = if nsec < 0 {
        (sec - 1, nsec + 1_000_000_000)
    } else {
        (sec, nsec)
    };
    let mono = mono_now();
    let wall_sec = sec.wrapping_add(UNIX_TO_INTERNAL - MIN_WALL);
    if (wall_sec as u64) >> 33 != 0 {
        return Time {
            wall: nsec as u64,
            ext: wall_sec + MIN_WALL,
            loc: Some(local()),
        };
    }
    Time {
        wall: HAS_MONOTONIC | (wall_sec as u64) << NSEC_SHIFT | nsec as u64,
        ext: mono,
        loc: Some(local()),
    }
}

/// Go's `time.Since`.
pub fn since(t: &Time) -> Duration {
    if t.wall & HAS_MONOTONIC != 0 {
        return sub_mono(mono_now(), t.ext);
    }
    now().sub(t)
}

/// Go's `time.Until`.
pub fn until(t: &Time) -> Duration {
    if t.wall & HAS_MONOTONIC != 0 {
        return sub_mono(t.ext, mono_now());
    }
    t.sub(&now())
}

fn sub_mono(t: i64, u: i64) -> Duration {
    let d = t.wrapping_sub(u);
    if d < 0 && t > u {
        return MAX_DURATION;
    }
    if d > 0 && t < u {
        return MIN_DURATION;
    }
    Duration::from_nanos(d)
}

/// Go's `norm`.
fn norm(mut hi: i64, mut lo: i64, base: i64) -> (i64, i64) {
    if lo < 0 {
        let n = (-(lo + 1)) / base + 1;
        hi = hi.wrapping_sub(n);
        lo = lo.wrapping_add(n.wrapping_mul(base));
    }
    if lo >= base {
        let n = lo / base;
        hi = hi.wrapping_add(n);
        lo -= n * base;
    }
    (hi, lo)
}

/// Go's `time.Date`: the instant at the civil time in `loc`.
///
/// Out-of-range fields are normalized (October 32 is November 1). In a
/// gap or overlap the result is correct in one of the two zones involved,
/// chosen exactly as Go chooses.
#[allow(clippy::too_many_arguments)]
pub fn date(
    year: i64,
    month: Month,
    day: i64,
    hour: i64,
    min: i64,
    sec: i64,
    nsec: i64,
    loc: &Location,
) -> Time {
    let (year, m) = norm(year, month.0.wrapping_sub(1), 12);
    let month = m + 1;
    let (sec, nsec) = norm(sec, nsec, 1_000_000_000);
    let (min, sec) = norm(min, sec, 60);
    let (hour, min) = norm(hour, min, 60);
    let (day, hour) = norm(day, hour, 24);
    let mut unix = (date_to_abs_days(year, month, day).0 as i64)
        .wrapping_mul(SECONDS_PER_DAY)
        .wrapping_add(
            hour.wrapping_mul(SECONDS_PER_HOUR)
                .wrapping_add(min.wrapping_mul(SECONDS_PER_MINUTE))
                .wrapping_add(sec),
        )
        .wrapping_add(ABSOLUTE_TO_UNIX);
    let zone = loc.lookup(unix);
    let mut offset = zone.offset;
    if offset != 0 {
        let utc = unix.wrapping_sub(i64::from(offset));
        if utc < zone.start || utc >= zone.end {
            offset = loc.lookup(utc).offset;
        }
        unix = unix.wrapping_sub(i64::from(offset));
    }
    let mut t = unix_time(unix, nsec as i32);
    t.set_loc(loc);
    t
}

/// Go's `lessThanHalf`.
pub(crate) const fn less_than_half(x: i64, y: i64) -> bool {
    (x as u64).wrapping_add(x as u64) < y as u64
}

impl Time {
    fn nsec(&self) -> i32 {
        (self.wall & NSEC_MASK) as i32
    }

    /// Seconds since January 1, year 1 (Go's internal `sec`).
    fn sec(&self) -> i64 {
        if self.wall & HAS_MONOTONIC != 0 {
            return WALL_TO_INTERNAL + ((self.wall << 1) >> (NSEC_SHIFT + 1)) as i64;
        }
        self.ext
    }

    fn unix_sec(&self) -> i64 {
        self.sec().wrapping_add(INTERNAL_TO_UNIX)
    }

    fn add_sec(&mut self, d: i64) {
        if self.wall & HAS_MONOTONIC != 0 {
            let sec = ((self.wall << 1) >> (NSEC_SHIFT + 1)) as i64;
            let dsec = sec.wrapping_add(d);
            if (0..=(1 << 33) - 1).contains(&dsec) {
                self.wall = self.wall & NSEC_MASK | (dsec as u64) << NSEC_SHIFT | HAS_MONOTONIC;
                return;
            }
            self.strip_mono();
        }
        let sum = self.ext.wrapping_add(d);
        if (sum > self.ext) == (d > 0) {
            self.ext = sum;
        } else if d > 0 {
            self.ext = i64::MAX;
        } else {
            self.ext = -i64::MAX;
        }
    }

    fn set_loc(&mut self, loc: &Location) {
        self.strip_mono();
        self.loc = if loc.is_utc() {
            None
        } else {
            Some(loc.clone())
        };
    }

    fn strip_mono(&mut self) {
        if self.wall & HAS_MONOTONIC != 0 {
            self.ext = self.sec();
            self.wall &= NSEC_MASK;
        }
    }

    /// The location used for lookups (UTC when unset).
    fn loc_ref(&self) -> &Location {
        match &self.loc {
            Some(loc) => loc,
            None => Location::utc_ref(),
        }
    }

    /// Go's `IsZero`: January 1, year 1, 00:00:00 UTC.
    pub fn is_zero(&self) -> bool {
        self.wall == 0 && self.ext == 0
    }

    /// Go's `After`.
    pub fn after(&self, u: &Time) -> bool {
        if self.wall & u.wall & HAS_MONOTONIC != 0 {
            return self.ext > u.ext;
        }
        let (ts, us) = (self.sec(), u.sec());
        ts > us || ts == us && self.nsec() > u.nsec()
    }

    /// Go's `Before`.
    pub fn before(&self, u: &Time) -> bool {
        if self.wall & u.wall & HAS_MONOTONIC != 0 {
            return self.ext < u.ext;
        }
        let (ts, us) = (self.sec(), u.sec());
        ts < us || ts == us && self.nsec() < u.nsec()
    }

    /// Go's `Compare`: -1, 0 or +1.
    pub fn compare(&self, u: &Time) -> i32 {
        let (tc, uc) = if self.wall & u.wall & HAS_MONOTONIC != 0 {
            (self.ext, u.ext)
        } else if self.sec() == u.sec() {
            (i64::from(self.nsec()), i64::from(u.nsec()))
        } else {
            (self.sec(), u.sec())
        };
        match tc.cmp(&uc) {
            Ordering::Less => -1,
            Ordering::Greater => 1,
            Ordering::Equal => 0,
        }
    }

    /// Go's `Equal`: the same instant, regardless of location.
    pub fn equal(&self, u: &Time) -> bool {
        if self.wall & u.wall & HAS_MONOTONIC != 0 {
            return self.ext == u.ext;
        }
        self.sec() == u.sec() && self.nsec() == u.nsec()
    }

    /// Absolute seconds of the local clock reading (Go's `absSec`).
    pub(crate) fn abs_sec(&self) -> AbsSeconds {
        let sec = self.unix_sec();
        let offset = self.loc_ref().lookup(sec).offset;
        AbsSeconds::from_unix(sec.wrapping_add(i64::from(offset)))
    }

    /// Go's `locabs`: zone name, offset and absolute local seconds.
    pub(crate) fn locabs(&self) -> (&str, i32, AbsSeconds) {
        let sec = self.unix_sec();
        let (name, offset) = match &self.loc {
            None => ("UTC", 0),
            Some(loc) => {
                let zone = loc.lookup(sec);
                (zone.name, zone.offset)
            }
        };
        (
            name,
            offset,
            AbsSeconds::from_unix(sec.wrapping_add(i64::from(offset))),
        )
    }

    /// Go's `Date`: year, month and day in the time's location.
    pub fn date(&self) -> (i64, Month, i64) {
        let (y, m, d) = self.abs_sec().days().date();
        (y, Month(m), d)
    }

    /// Go's `Year`.
    pub fn year(&self) -> i64 {
        self.date().0
    }

    /// Go's `Month`.
    pub fn month(&self) -> Month {
        self.date().1
    }

    /// Go's `Day`.
    pub fn day(&self) -> i64 {
        self.date().2
    }

    /// Go's `Weekday`.
    pub fn weekday(&self) -> Weekday {
        self.abs_sec().days().weekday()
    }

    /// Go's `ISOWeek`: the ISO 8601 year and week number (1..=53).
    pub fn iso_week(&self) -> (i64, i64) {
        let days = self.abs_sec().days();
        let prev = AbsDays(days.0.wrapping_sub(1)).weekday().0;
        let thu = AbsDays(days.0.wrapping_add((4 - (prev + 1)) as u64));
        let (year, yday) = thu.year_yday();
        (year, (yday - 1) / 7 + 1)
    }

    /// Go's `Clock`: hour, minute and second.
    pub fn clock(&self) -> (i64, i64, i64) {
        self.abs_sec().clock()
    }

    /// Go's `Hour`.
    pub fn hour(&self) -> i64 {
        self.clock().0
    }

    /// Go's `Minute`.
    pub fn minute(&self) -> i64 {
        self.clock().1
    }

    /// Go's `Second`.
    pub fn second(&self) -> i64 {
        self.clock().2
    }

    /// Go's `Nanosecond`: 0..=999,999,999.
    pub fn nanosecond(&self) -> i64 {
        i64::from(self.nsec())
    }

    /// Go's `YearDay`: 1..=365, or 366 in leap years.
    pub fn year_day(&self) -> i64 {
        self.abs_sec().days().year_yday().1
    }

    /// Go's `Add`.
    pub fn add(&self, d: Duration) -> Time {
        let d = d.as_nanos();
        let mut t = self.clone();
        let mut dsec = d / 1_000_000_000;
        let mut nsec = t.nsec() + (d % 1_000_000_000) as i32;
        if nsec >= 1_000_000_000 {
            dsec += 1;
            nsec -= 1_000_000_000;
        } else if nsec < 0 {
            dsec -= 1;
            nsec += 1_000_000_000;
        }
        t.wall = t.wall & !NSEC_MASK | nsec as u64;
        t.add_sec(dsec);
        if t.wall & HAS_MONOTONIC != 0 {
            let te = t.ext.wrapping_add(d);
            if d < 0 && te > t.ext || d > 0 && te < t.ext {
                t.strip_mono();
            } else {
                t.ext = te;
            }
        }
        t
    }

    /// Go's `Sub`: `self - u`, saturating at the Duration range.
    pub fn sub(&self, u: &Time) -> Duration {
        if self.wall & u.wall & HAS_MONOTONIC != 0 {
            return sub_mono(self.ext, u.ext);
        }
        let d = self
            .sec()
            .wrapping_sub(u.sec())
            .wrapping_mul(SECOND.as_nanos())
            .wrapping_add(i64::from(self.nsec() - u.nsec()));
        let d = Duration::from_nanos(d);
        if u.add(d).equal(self) {
            d
        } else if self.before(u) {
            MIN_DURATION
        } else {
            MAX_DURATION
        }
    }

    /// Go's `AddDate`: add years, months and days, normalizing like
    /// [`date`] (October 31 plus one month is December 1).
    pub fn add_date(&self, years: i64, months: i64, days: i64) -> Time {
        let (year, month, day) = self.date();
        let (hour, min, sec) = self.clock();
        date(
            year.wrapping_add(years),
            Month(month.0.wrapping_add(months)),
            day.wrapping_add(days),
            hour,
            min,
            sec,
            i64::from(self.nsec()),
            &self.location(),
        )
    }

    /// Go's `UTC`.
    pub fn utc(&self) -> Time {
        let mut t = self.clone();
        t.set_loc(Location::utc_ref());
        t
    }

    /// Go's `Local`.
    pub fn local(&self) -> Time {
        let mut t = self.clone();
        t.set_loc(&local());
        t
    }

    /// Go's `In`: the same instant displayed in `loc`.
    pub fn in_location(&self, loc: &Location) -> Time {
        let mut t = self.clone();
        t.set_loc(loc);
        t
    }

    /// Go's `Location` (UTC when unset).
    pub fn location(&self) -> Location {
        self.loc_ref().clone()
    }

    /// Go's `Zone`: the abbreviation and offset in effect.
    pub fn zone(&self) -> (&str, i32) {
        let zone = self.loc_ref().lookup(self.unix_sec());
        (zone.name, zone.offset)
    }

    /// Go's `ZoneBounds`: the start and end of the zone period; the zero
    /// Time for the beginning or end of time.
    pub fn zone_bounds(&self) -> (Time, Time) {
        let zone = self.loc_ref().lookup(self.unix_sec());
        let bound = |sec: i64, limit: i64| {
            if sec == limit {
                Time::default()
            } else {
                let mut t = unix_time(sec, 0);
                t.set_loc(self.loc_ref());
                t
            }
        };
        (
            bound(zone.start, super::ALPHA),
            bound(zone.end, super::OMEGA),
        )
    }

    /// Go's `IsDST`.
    pub fn is_dst(&self) -> bool {
        self.loc_ref().lookup(self.unix_sec()).is_dst
    }

    /// Go's `Unix`: seconds since the Unix epoch.
    pub fn unix(&self) -> i64 {
        self.unix_sec()
    }

    /// Go's `UnixMilli` (wrapping outside the i64 range, as in Go).
    pub fn unix_milli(&self) -> i64 {
        self.unix_sec()
            .wrapping_mul(1000)
            .wrapping_add(i64::from(self.nsec()) / 1_000_000)
    }

    /// Go's `UnixMicro`.
    pub fn unix_micro(&self) -> i64 {
        self.unix_sec()
            .wrapping_mul(1_000_000)
            .wrapping_add(i64::from(self.nsec()) / 1000)
    }

    /// Go's `UnixNano`.
    pub fn unix_nano(&self) -> i64 {
        self.unix_sec()
            .wrapping_mul(1_000_000_000)
            .wrapping_add(i64::from(self.nsec()))
    }

    /// Go's `Truncate`: round down to a multiple of `d` since the zero time.
    pub fn truncate(&self, d: Duration) -> Time {
        let mut t = self.clone();
        t.strip_mono();
        if d.as_nanos() <= 0 {
            return t;
        }
        let (_, r) = div(&t, d.as_nanos());
        t.add(Duration::from_nanos(r.wrapping_neg()))
    }

    /// Go's `Round`: round to the nearest multiple of `d`, halves up.
    pub fn round(&self, d: Duration) -> Time {
        let mut t = self.clone();
        t.strip_mono();
        let d = d.as_nanos();
        if d <= 0 {
            return t;
        }
        let (_, r) = div(&t, d);
        if less_than_half(r, d) {
            return t.add(Duration::from_nanos(r.wrapping_neg()));
        }
        t.add(Duration::from_nanos(d.wrapping_sub(r)))
    }

    /// Go's `AppendBinary`.
    pub fn append_binary(&self, b: &mut Vec<u8>) -> Result<(), Error> {
        let mut offset_sec: i8 = 0;
        let mut version = 1u8;
        let offset_min: i16 = if self.loc_ref().is_utc() {
            -1
        } else {
            let (_, offset) = self.zone();
            if offset % 60 != 0 {
                version = 2;
                offset_sec = (offset % 60) as i8;
            }
            let offset = offset / 60;
            if !(-32768..=32767).contains(&offset) || offset == -1 {
                return Err(Error("Time.MarshalBinary: unexpected zone offset"));
            }
            offset as i16
        };
        b.push(version);
        b.extend_from_slice(&self.sec().to_be_bytes());
        b.extend_from_slice(&self.nsec().to_be_bytes());
        b.extend_from_slice(&offset_min.to_be_bytes());
        if version == 2 {
            b.push(offset_sec as u8);
        }
        Ok(())
    }

    /// Go's `MarshalBinary`.
    pub fn marshal_binary(&self) -> Result<Vec<u8>, Error> {
        let mut b = Vec::with_capacity(16);
        self.append_binary(&mut b)?;
        Ok(b)
    }

    /// Go's `UnmarshalBinary`.
    pub fn unmarshal_binary(&mut self, data: &[u8]) -> Result<(), Error> {
        let Some(&version) = data.first() else {
            return Err(Error("Time.UnmarshalBinary: no data"));
        };
        if version != 1 && version != 2 {
            return Err(Error("Time.UnmarshalBinary: unsupported version"));
        }
        let want = if version == 2 { 16 } else { 15 };
        if data.len() != want {
            return Err(Error("Time.UnmarshalBinary: invalid length"));
        }
        let sec = i64::from_be_bytes(data[1..9].try_into().unwrap_or([0; 8]));
        let nsec = i32::from_be_bytes(data[9..13].try_into().unwrap_or([0; 4]));
        let mut offset = i32::from(i16::from_be_bytes([data[13], data[14]])) * 60;
        if version == 2 {
            offset += i32::from(data[15] as i8);
        }
        // Go's uint64(int32) sign-extends: hostile nanosecond fields can set
        // the monotonic and seconds bits of wall, which setLoc then folds in.
        *self = Time {
            wall: i64::from(nsec) as u64,
            ext: sec,
            loc: None,
        };
        if offset == -60 {
            self.set_loc(Location::utc_ref());
        } else {
            let local = local();
            if local.lookup(self.unix_sec()).offset == offset {
                self.set_loc(&local);
            } else {
                self.set_loc(&Location::fixed("", offset));
            }
        }
        Ok(())
    }

    /// Go's `GobEncode` (the binary encoding).
    pub fn gob_encode(&self) -> Result<Vec<u8>, Error> {
        self.marshal_binary()
    }

    /// Go's `GobDecode`.
    pub fn gob_decode(&mut self, data: &[u8]) -> Result<(), Error> {
        self.unmarshal_binary(data)
    }

    /// Go's `GoString`: a Go source literal that rebuilds the time.
    pub fn literal(&self) -> String {
        let abs = self.abs_sec();
        let (year, month, day) = abs.days().date();
        let (hour, minute, second) = abs.clock();
        let mut s = format!("time.Date({year}");
        if (1..=12).contains(&month) {
            s.push_str(", time.");
            s.push_str(LONG_MONTH_NAMES[(month - 1) as usize]);
        } else {
            s.push_str(&month.to_string());
        }
        s.push_str(&format!(
            ", {day}, {hour}, {minute}, {second}, {}, ",
            self.nsec()
        ));
        let loc = self.loc_ref();
        if loc.is_utc() {
            s.push_str("time.UTC");
        } else if loc.is_local() {
            s.push_str("time.Local");
        } else {
            s.push_str("time.Location(");
            s.push_str(&super::format::quote(loc.name().as_bytes()));
            s.push(')');
        }
        s.push(')');
        s
    }

    /// Convert to the crate's validated [`super::DateTime`] with the zone
    /// offset in effect (not a Go API). Fails outside years 1..=9999 or for
    /// offsets of 24 hours or more.
    pub fn to_date_time(&self) -> Result<super::DateTime, Error> {
        super::DateTime::from_unix(self.unix_sec(), self.nsec() as u32, self.zone().1)
    }

    /// Go's unexported `addSec` on a copy (saturating, stripping the
    /// monotonic reading when it no longer fits).
    pub(crate) fn add_seconds_internal(&self, d: i64) -> Time {
        let mut t = self.clone();
        t.add_sec(d);
        t
    }

    /// The monotonic reading in nanoseconds, if any (Go prints it as
    /// ` m=±s.nnnnnnnnn` in `String`).
    pub(crate) fn mono(&self) -> Option<i64> {
        (self.wall & HAS_MONOTONIC != 0).then_some(self.ext)
    }
}

/// Go's `div`: whether `t / d` is odd and the remainder `t % d`, for the
/// time since the zero time.
fn div(t: &Time, d: i64) -> (i64, i64) {
    let mut neg = false;
    let mut nsec = t.nsec();
    let mut sec = t.sec();
    if sec < 0 {
        neg = true;
        sec = sec.wrapping_neg();
        nsec = -nsec;
        if nsec < 0 {
            nsec += 1_000_000_000;
            sec -= 1;
        }
    }
    let second = SECOND.as_nanos();
    let (mut qmod2, mut r) = if d < second && second % (d + d) == 0 {
        (i64::from(nsec / d as i32) & 1, i64::from(nsec % d as i32))
    } else if d % second == 0 {
        let d1 = d / second;
        ((sec / d1) & 1, (sec % d1) * second + i64::from(nsec))
    } else {
        // 128-bit remainder of (sec*1e9 + nsec) / d; same result as Go's
        // shift-and-subtract loop.
        let total = u128::from(sec as u64) * 1_000_000_000 + nsec as u128;
        let q = total / d as u128;
        ((q & 1) as i64, (total % d as u128) as i64)
    };
    if neg && r != 0 {
        qmod2 ^= 1;
        r = d - r;
    }
    (qmod2, r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_go() {
        assert_eq!(UNIX_TO_INTERNAL, 62_135_596_800);
        assert_eq!(WALL_TO_INTERNAL, 59_453_308_800);
        assert_eq!(super::super::HOUR.as_nanos(), 3_600_000_000_000);
        for m in 1..=12 {
            assert_eq!(days_before(m + 1) - days_before(m), days_in(m, 2023), "{m}");
        }
    }

    #[test]
    fn calendar_round_trip() {
        for (y, m, d) in [
            (1, 1, 1),
            (1970, 1, 1),
            (2000, 2, 29),
            (-1, 12, 31),
            (9999, 12, 31),
        ] {
            let t = date(y, Month(m), d, 0, 0, 0, 0, Location::utc_ref());
            assert_eq!(t.date(), (y, Month(m), d));
        }
        assert!(Time::default().is_zero());
        assert_eq!(
            date(1, JANUARY, 1, 0, 0, 0, 0, Location::utc_ref()).unix(),
            -62_135_596_800
        );
    }
}
