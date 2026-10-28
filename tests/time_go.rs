//! Tables ported from Go's src/time/format_test.go and time_test.go.
//!
//! Go's tests force Local to America/Los_Angeles; Local here comes from the
//! process TZ, so those cases use the Los Angeles zone from the checked-in
//! zoneinfo.zip with `in_location`, `date(.., &la)` and `parse_in_location`.
use rust_stdlib::time::{
    self as time, load_location_from, Duration, Location, Month, Time, Weekday, ANSIC, DATE_ONLY,
    DATE_TIME, FEBRUARY, HOUR, JANUARY, KITCHEN, MICROSECOND, MILLISECOND, MINUTE, NANOSECOND,
    RFC1123, RFC1123Z, RFC3339, RFC3339_NANO, RFC822, RFC850, RUBY_DATE, SECOND, STAMP,
    STAMP_MICRO, STAMP_MILLI, STAMP_NANO, THURSDAY, TIME_ONLY, UNIX_DATE,
};

const ZIP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/time/tzdata/zoneinfo.zip");

fn la() -> Location {
    load_location_from(ZIP, "America/Los_Angeles").unwrap()
}

fn utc() -> Location {
    Location::utc()
}

#[allow(clippy::too_many_arguments)]
fn d(y: i64, m: i64, day: i64, h: i64, mi: i64, s: i64, ns: i64, loc: &Location) -> Time {
    time::date(y, Month(m), day, h, mi, s, ns, loc)
}

fn dur(n: i64) -> Duration {
    Duration::from_nanos(n)
}

#[test]
fn rfc3339_conversion() {
    for (t, want) in [
        (d(2008, 9, 17, 20, 4, 26, 0, &utc()), "2008-09-17T20:04:26Z"),
        (
            d(
                1994,
                9,
                17,
                20,
                4,
                26,
                0,
                &time::Location::fixed("EST", -18000),
            ),
            "1994-09-17T20:04:26-05:00",
        ),
        (
            d(
                2000,
                12,
                26,
                1,
                15,
                6,
                0,
                &time::Location::fixed("OTO", 15600),
            ),
            "2000-12-26T01:15:06+04:20",
        ),
    ] {
        assert_eq!(t.format(RFC3339), want);
    }
}

#[test]
fn format_table() {
    // Thu Feb  4 21:00:57.012345600 PST 2009 (Go's Local is Los Angeles).
    let t = time::unix(0, 1233810057012345600).in_location(&la());
    for (name, layout, want) in [
        ("ANSIC", ANSIC, "Wed Feb  4 21:00:57 2009"),
        ("UnixDate", UNIX_DATE, "Wed Feb  4 21:00:57 PST 2009"),
        ("RubyDate", RUBY_DATE, "Wed Feb 04 21:00:57 -0800 2009"),
        ("RFC822", RFC822, "04 Feb 09 21:00 PST"),
        ("RFC850", RFC850, "Wednesday, 04-Feb-09 21:00:57 PST"),
        ("RFC1123", RFC1123, "Wed, 04 Feb 2009 21:00:57 PST"),
        ("RFC1123Z", RFC1123Z, "Wed, 04 Feb 2009 21:00:57 -0800"),
        ("RFC3339", RFC3339, "2009-02-04T21:00:57-08:00"),
        (
            "RFC3339Nano",
            RFC3339_NANO,
            "2009-02-04T21:00:57.0123456-08:00",
        ),
        ("Kitchen", KITCHEN, "9:00PM"),
        ("am/pm", "3pm", "9pm"),
        ("AM/PM", "3PM", "9PM"),
        ("two-digit year", "06 01 02", "09 02 04"),
        (
            "Janet",
            "Hi Janet, the Month is January",
            "Hi Janet, the Month is February",
        ),
        ("Stamp", STAMP, "Feb  4 21:00:57"),
        ("StampMilli", STAMP_MILLI, "Feb  4 21:00:57.012"),
        ("StampMicro", STAMP_MICRO, "Feb  4 21:00:57.012345"),
        ("StampNano", STAMP_NANO, "Feb  4 21:00:57.012345600"),
        ("DateTime", DATE_TIME, "2009-02-04 21:00:57"),
        ("DateOnly", DATE_ONLY, "2009-02-04"),
        ("TimeOnly", TIME_ONLY, "21:00:57"),
        ("YearDay", "Jan  2 002 __2 2", "Feb  4 035  35 4"),
        ("Year", "2006 6 06 _6 __6 ___6", "2009 6 09 _6 __6 ___6"),
        ("Month", "Jan January 1 01 _1", "Feb February 2 02 _2"),
        ("DayOfMonth", "2 02 _2 __2", "4 04  4  35"),
        ("DayOfWeek", "Mon Monday", "Wed Wednesday"),
        ("Hour", "15 3 03 _3", "21 9 09 _9"),
        ("Minute", "4 04 _4", "0 00 _0"),
        ("Second", "5 05 _5", "57 57 _57"),
        ("frac .000", "15:04:05.000", "21:00:57.012"),
        ("frac .999", "15:04:05.999", "21:00:57.012"),
        ("frac ,000", "15:04:05,000", "21:00:57,012"),
        ("frac ,999", "15:04:05,999", "21:00:57,012"),
    ] {
        assert_eq!(t.format(layout), want, "{name}");
    }
}

#[test]
fn go_string_table() {
    let cases = [
        (
            d(2009, 2, 5, 5, 0, 57, 12345600, &utc()),
            "time.Date(2009, time.February, 5, 5, 0, 57, 12345600, time.UTC)",
        ),
        (
            d(2009, 2, 5, 5, 0, 57, 12345600, &time::local()),
            "time.Date(2009, time.February, 5, 5, 0, 57, 12345600, time.Local)",
        ),
        (
            d(
                2009,
                2,
                5,
                5,
                0,
                57,
                12345600,
                &time::Location::fixed("Europe/Berlin", 3 * 60 * 60),
            ),
            r#"time.Date(2009, time.February, 5, 5, 0, 57, 12345600, time.Location("Europe/Berlin"))"#,
        ),
        (
            d(
                2009,
                2,
                5,
                5,
                0,
                57,
                12345600,
                &time::Location::fixed("Non-ASCII character ⏰", 3 * 60 * 60),
            ),
            r#"time.Date(2009, time.February, 5, 5, 0, 57, 12345600, time.Location("Non-ASCII character \xe2\x8f\xb0"))"#,
        ),
    ];
    for (t, want) in cases {
        assert_eq!(t.literal(), want);
    }
}

#[test]
fn format_single_digits_short_years_and_noon() {
    let t = d(2001, 2, 3, 4, 5, 6, 700000000, &utc());
    assert_eq!(t.format("3:4:5"), "4:5:6");
    for y in [
        -100001, -100000, -99999, -10001, -10000, -9999, -1001, -1000, -999, -101, -100, -99, -11,
        -10, -9, -1, 0, 1, 9, 10, 11, 99, 100, 101, 999, 1000, 1001, 9999, 10000, 10001, 99999,
        100000, 100001,
    ] {
        let want = if y < 0 {
            format!("-{:04}.01.01", -y)
        } else {
            format!("{y:04}.01.01")
        };
        assert_eq!(d(y, 1, 1, 0, 0, 0, 0, &utc()).format("2006.01.02"), want);
    }
    let noon = d(0, 1, 1, 12, 0, 0, 0, &utc());
    assert_eq!(noon.format("3:04PM"), "12:00PM");
    assert_eq!(noon.format("03:04PM"), "12:00PM");
    let midnight = d(0, 1, 1, 0, 0, 0, 0, &utc());
    assert_eq!(midnight.format("3:04PM"), "12:00AM");
    assert_eq!(midnight.format("03:04PM"), "12:00AM");
}

/// Go's `checkTime`: Thursday, February 4 2010, 21:00:57 with the given
/// fractional digits, -0800 when the value has a zone.
fn check_time(t: &Time, name: &str, has_tz: bool, has_wd: bool, year_sign: i64, frac: usize) {
    if year_sign >= 0 {
        assert_eq!(year_sign * t.year(), 2010, "{name}: year");
    }
    assert_eq!(t.month(), FEBRUARY, "{name}: month");
    assert_eq!(t.day(), 4, "{name}: day");
    assert_eq!(t.clock(), (21, 0, 57), "{name}: clock");
    let digits = format!("{}{}", &"012345678"[..frac], &"000000000"[..9 - frac]);
    assert_eq!(
        t.nanosecond(),
        digits.parse::<i64>().unwrap(),
        "{name}: nsec"
    );
    if has_tz {
        assert_eq!(t.zone().1, -28800, "{name}: offset");
    }
    if has_wd {
        assert_eq!(t.weekday(), THURSDAY, "{name}: weekday");
    }
}

#[rustfmt::skip]
const PARSE_TESTS: &[(&str, &str, &str, bool, bool, i64, usize)] = &[
    ("ANSIC", ANSIC, "Thu Feb  4 21:00:57 2010", false, true, 1, 0),
    ("UnixDate", UNIX_DATE, "Thu Feb  4 21:00:57 PST 2010", true, true, 1, 0),
    ("RubyDate", RUBY_DATE, "Thu Feb 04 21:00:57 -0800 2010", true, true, 1, 0),
    ("RFC850", RFC850, "Thursday, 04-Feb-10 21:00:57 PST", true, true, 1, 0),
    ("RFC1123", RFC1123, "Thu, 04 Feb 2010 21:00:57 PST", true, true, 1, 0),
    ("RFC1123", RFC1123, "Thu, 04 Feb 2010 22:00:57 PDT", true, true, 1, 0),
    ("RFC1123Z", RFC1123Z, "Thu, 04 Feb 2010 21:00:57 -0800", true, true, 1, 0),
    ("RFC3339", RFC3339, "2010-02-04T21:00:57-08:00", true, false, 1, 0),
    ("custom", "2006-01-02 15:04:05-07", "2010-02-04 21:00:57-08", true, false, 1, 0),
    ("ANSIC", ANSIC, "Thu Feb  4 21:00:57.0 2010", false, true, 1, 1),
    ("UnixDate", UNIX_DATE, "Thu Feb  4 21:00:57.01 PST 2010", true, true, 1, 2),
    ("RubyDate", RUBY_DATE, "Thu Feb 04 21:00:57.012 -0800 2010", true, true, 1, 3),
    ("RFC850", RFC850, "Thursday, 04-Feb-10 21:00:57.0123 PST", true, true, 1, 4),
    ("RFC1123", RFC1123, "Thu, 04 Feb 2010 21:00:57.01234 PST", true, true, 1, 5),
    ("RFC1123Z", RFC1123Z, "Thu, 04 Feb 2010 21:00:57.01234 -0800", true, true, 1, 5),
    ("RFC3339", RFC3339, "2010-02-04T21:00:57.012345678-08:00", true, false, 1, 9),
    ("custom", "2006-01-02 15:04:05", "2010-02-04 21:00:57.0", false, false, 1, 0),
    ("ANSIC", ANSIC, "Thu Feb 4 21:00:57 2010", false, true, 1, 0),
    ("ANSIC", ANSIC, "Thu      Feb     4     21:00:57     2010", false, true, 1, 0),
    ("ANSIC", ANSIC, "THU FEB 4 21:00:57 2010", false, true, 1, 0),
    ("ANSIC", ANSIC, "thu feb 4 21:00:57 2010", false, true, 1, 0),
    ("ms dot", "Mon Jan _2 15:04:05.000 2006", "Thu Feb  4 21:00:57.012 2010", false, true, 1, 3),
    ("us dot", "Mon Jan _2 15:04:05.000000 2006", "Thu Feb  4 21:00:57.012345 2010", false, true, 1, 6),
    ("ns dot", "Mon Jan _2 15:04:05.000000000 2006", "Thu Feb  4 21:00:57.012345678 2010", false, true, 1, 9),
    ("ms comma", "Mon Jan _2 15:04:05,000 2006", "Thu Feb  4 21:00:57.012 2010", false, true, 1, 3),
    ("us comma", "Mon Jan _2 15:04:05,000000 2006", "Thu Feb  4 21:00:57.012345 2010", false, true, 1, 6),
    ("ns comma", "Mon Jan _2 15:04:05,000000000 2006", "Thu Feb  4 21:00:57.012345678 2010", false, true, 1, 9),
    ("zero1", "2006.01.02.15.04.05.0", "2010.02.04.21.00.57.0", false, false, 1, 1),
    ("zero2", "2006.01.02.15.04.05.00", "2010.02.04.21.00.57.01", false, false, 1, 2),
    ("Janet", "Hi Janet, the Month is January: Jan _2 15:04:05 2006", "Hi Janet, the Month is February: Feb  4 21:00:57 2010", false, true, 1, 0),
    ("GMT-8", UNIX_DATE, "Fri Feb  5 05:00:57 GMT-8 2010", true, true, 1, 0),
    ("", "2006-01-02 15:04:05.9999 -0700 MST", "2010-02-04 21:00:57 -0800 PST", true, false, 1, 0),
    ("", "2006-01-02 15:04:05.999999999 -0700 MST", "2010-02-04 21:00:57 -0800 PST", true, false, 1, 0),
    ("", "2006-01-02 15:04:05.9999 -0700 MST", "2010-02-04 21:00:57.0123 -0800 PST", true, false, 1, 4),
    ("", "2006-01-02 15:04:05.999999999 -0700 MST", "2010-02-04 21:00:57.0123 -0800 PST", true, false, 1, 4),
    ("", "2006-01-02 15:04:05.9999 -0700 MST", "2010-02-04 21:00:57.012345678 -0800 PST", true, false, 1, 9),
    ("", "2006-01-02 15:04:05.999999999 -0700 MST", "2010-02-04 21:00:57.012345678 -0800 PST", true, false, 1, 9),
    ("", "2006-01-02 15:04:05,9999 -0700 MST", "2010-02-04 21:00:57 -0800 PST", true, false, 1, 0),
    ("", "2006-01-02 15:04:05,999999999 -0700 MST", "2010-02-04 21:00:57 -0800 PST", true, false, 1, 0),
    ("", "2006-01-02 15:04:05,9999 -0700 MST", "2010-02-04 21:00:57.0123 -0800 PST", true, false, 1, 4),
    ("", "2006-01-02 15:04:05,999999999 -0700 MST", "2010-02-04 21:00:57.0123 -0800 PST", true, false, 1, 4),
    ("", "2006-01-02 15:04:05,9999 -0700 MST", "2010-02-04 21:00:57.012345678 -0800 PST", true, false, 1, 9),
    ("", "2006-01-02 15:04:05,999999999 -0700 MST", "2010-02-04 21:00:57.012345678 -0800 PST", true, false, 1, 9),
    ("", STAMP_NANO, "Feb  4 21:00:57.012345678", false, false, -1, 9),
    ("", "Jan _2 15:04:05.999", "Feb  4 21:00:57.012300000", false, false, -1, 4),
    ("", "Jan _2 15:04:05.999", "Feb  4 21:00:57.012345678", false, false, -1, 9),
    ("", "Jan _2 15:04:05.999999999", "Feb  4 21:00:57.0123", false, false, -1, 4),
    ("", "Jan _2 15:04:05.999999999", "Feb  4 21:00:57.012345678", false, false, -1, 9),
    ("", "2006-01-02 002 15:04:05", "2010-02-04 035 21:00:57", false, false, 1, 0),
    ("", "2006-01 002 15:04:05", "2010-02 035 21:00:57", false, false, 1, 0),
    ("", "2006-002 15:04:05", "2010-035 21:00:57", false, false, 1, 0),
    ("", "200600201 15:04:05", "201003502 21:00:57", false, false, 1, 0),
    ("", "200600204 15:04:05", "201003504 21:00:57", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z07", "2010-02-04T21:00:57Z", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z07", "2010-02-04T21:00:57+08", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z07", "2010-02-04T21:00:57-08", true, false, 1, 0),
    ("", "2006-01-02T15:04:05Z0700", "2010-02-04T21:00:57Z", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z0700", "2010-02-04T21:00:57+0800", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z0700", "2010-02-04T21:00:57-0800", true, false, 1, 0),
    ("", "2006-01-02T15:04:05Z07:00", "2010-02-04T21:00:57Z", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z07:00", "2010-02-04T21:00:57+08:00", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z07:00", "2010-02-04T21:00:57-08:00", true, false, 1, 0),
    ("", "2006-01-02T15:04:05Z070000", "2010-02-04T21:00:57Z", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z070000", "2010-02-04T21:00:57+080000", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z070000", "2010-02-04T21:00:57-080000", true, false, 1, 0),
    ("", "2006-01-02T15:04:05Z07:00:00", "2010-02-04T21:00:57Z", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z07:00:00", "2010-02-04T21:00:57+08:00:00", false, false, 1, 0),
    ("", "2006-01-02T15:04:05Z07:00:00", "2010-02-04T21:00:57-08:00:00", true, false, 1, 0),
    // rubyTests.
    ("RubyDate", RUBY_DATE, "Thu Feb 04 21:00:57 -0000 2010", false, true, 1, 0),
    ("RubyDate", RUBY_DATE, "Thu Feb 04 21:00:57 +0000 2010", false, true, 1, 0),
    ("RubyDate", RUBY_DATE, "Thu Feb 04 21:00:57 +1130 2010", false, true, 1, 0),
];

#[test]
fn parse_table() {
    let la = la();
    for &(name, layout, value, has_tz, has_wd, sign, frac) in PARSE_TESTS {
        // Go's Parse matches zone names against Local (Los Angeles there).
        let t = time::Time::parse_in_location(layout, value, &la)
            .unwrap_or_else(|e| panic!("{name} {value:?}: {e}"));
        check_time(&t, name, has_tz, has_wd, sign, frac);
        // Plain Parse agrees on the instant fields that do not need Local.
        if !has_tz {
            let u = time::Time::parse(layout, value).unwrap();
            assert_eq!(u.clock(), (21, 0, 57), "{name}");
        }
    }
}

#[test]
fn day_and_month_out_of_range() {
    for (value, ok) in [
        ("Thu Jan 99 21:00:57 2010", false),
        ("Thu Jan 31 21:00:57 2010", true),
        ("Thu Jan 32 21:00:57 2010", false),
        ("Thu Feb 28 21:00:57 2012", true),
        ("Thu Feb 29 21:00:57 2012", true),
        ("Thu Feb 29 21:00:57 2010", false),
        ("Thu Mar 31 21:00:57 2010", true),
        ("Thu Mar 32 21:00:57 2010", false),
        ("Thu Apr 30 21:00:57 2010", true),
        ("Thu Apr 31 21:00:57 2010", false),
        ("Thu May 31 21:00:57 2010", true),
        ("Thu May 32 21:00:57 2010", false),
        ("Thu Jun 30 21:00:57 2010", true),
        ("Thu Jun 31 21:00:57 2010", false),
        ("Thu Jul 31 21:00:57 2010", true),
        ("Thu Jul 32 21:00:57 2010", false),
        ("Thu Aug 31 21:00:57 2010", true),
        ("Thu Aug 32 21:00:57 2010", false),
        ("Thu Sep 30 21:00:57 2010", true),
        ("Thu Sep 31 21:00:57 2010", false),
        ("Thu Oct 31 21:00:57 2010", true),
        ("Thu Oct 32 21:00:57 2010", false),
        ("Thu Nov 30 21:00:57 2010", true),
        ("Thu Nov 31 21:00:57 2010", false),
        ("Thu Dec 31 21:00:57 2010", true),
        ("Thu Dec 32 21:00:57 2010", false),
        ("Thu Dec 00 21:00:57 2010", false),
    ] {
        match time::Time::parse(ANSIC, value) {
            Ok(_) => assert!(ok, "{value}"),
            Err(e) => {
                assert!(!ok, "{value}: {e}");
                assert!(e.to_string().contains("day out of range"), "{e}");
            }
        }
    }
    for (value, ok) in [("00-01", false), ("13-01", false), ("01-01", true)] {
        match time::Time::parse("01-02", value) {
            Ok(_) => assert!(ok),
            Err(e) => assert!(!ok && e.to_string().contains("month out of range"), "{e}"),
        }
    }
}

#[test]
fn parse_in_location_ast() {
    let baghdad = load_location_from(ZIP, "Asia/Baghdad").unwrap();
    let t1 = time::Time::parse_in_location("Jan 02 2006 MST", "Feb 01 2013 AST", &baghdad).unwrap();
    let (_, offset) = t1.zone();
    // Modern tzdata uses "+03" for Baghdad, so AST is not recognized there.
    if offset != 0 {
        assert!(t1.equal(&d(2013, 2, 1, 0, 0, 0, 0, &baghdad)));
        assert_eq!(offset, 3 * 3600);
    }
    let blanc = load_location_from(ZIP, "America/Blanc-Sablon").unwrap();
    let t1 = time::Time::parse_in_location("Jan 02 2006 MST", "Feb 01 2013 AST", &blanc).unwrap();
    assert!(t1.equal(&d(2013, 2, 1, 0, 0, 0, 0, &blanc)));
    assert_eq!(t1.zone().1, -4 * 3600);
}

#[rustfmt::skip]
const PARSE_ERROR_TESTS: &[(&str, &str, &str)] = &[
    (ANSIC, "Feb  4 21:00:60 2010", r#"cannot parse "Feb  4 21:00:60 2010" as "Mon""#),
    (ANSIC, "Thu Feb  4 21:00:57 @2010", r#"cannot parse "@2010" as "2006""#),
    (ANSIC, "Thu Feb  4 21:00:60 2010", "second out of range"),
    (ANSIC, "Thu Feb  4 21:61:57 2010", "minute out of range"),
    (ANSIC, "Thu Feb  4 24:00:60 2010", "hour out of range"),
    ("Mon Jan _2 15:04:05.000 2006", "Thu Feb  4 23:00:59x01 2010", r#"cannot parse "x01 2010" as ".000""#),
    ("Mon Jan _2 15:04:05.000 2006", "Thu Feb  4 23:00:59.xxx 2010", r#"cannot parse ".xxx 2010" as ".000""#),
    ("Mon Jan _2 15:04:05.000 2006", "Thu Feb  4 23:00:59.-123 2010", "fractional second out of range"),
    (STAMP_NANO, "Dec  7 11:22:01.000000", r#"cannot parse ".000000" as ".000000000""#),
    (STAMP_NANO, "Dec  7 11:22:01.0000000000", r#"extra text: "0""#),
    (RFC3339, "2006-01-02T15:04:05Z07:00", r#"parsing time "2006-01-02T15:04:05Z07:00": extra text: "07:00""#),
    (RFC3339, "2006-01-02T15:04_abc", r#"parsing time "2006-01-02T15:04_abc" as "2006-01-02T15:04:05Z07:00": cannot parse "_abc" as ":""#),
    (RFC3339, "2006-01-02T15:04:05_abc", r#"parsing time "2006-01-02T15:04:05_abc" as "2006-01-02T15:04:05Z07:00": cannot parse "_abc" as "Z07:00""#),
    (RFC3339, "2006-01-02T15:04:05Z_abc", r#"parsing time "2006-01-02T15:04:05Z_abc": extra text: "_abc""#),
    (RFC3339, "2010-02-04T21:00:67.012345678-08:00", "second out of range"),
    (RFC3339, "0000-01-01T00:00:.0+00:00", r#"parsing time "0000-01-01T00:00:.0+00:00" as "2006-01-02T15:04:05Z07:00": cannot parse ".0+00:00" as "05""#),
    ("_2 Jan 06 15:04 MST", "4 --- 00 00:00 GMT", r#"cannot parse "--- 00 00:00 GMT" as "Jan""#),
    ("_2 January 06 15:04 MST", "4 --- 00 00:00 GMT", r#"cannot parse "--- 00 00:00 GMT" as "January""#),
    ("Jan _2 002 2006", "Feb  4 034 2006", "day-of-year does not match day"),
    ("Jan _2 002 2006", "Feb  4 004 2006", "day-of-year does not match month"),
    (r#""2006-01-02T15:04:05Z07:00""#, "0", r#"parsing time "0" as "\"2006-01-02T15:04:05Z07:00\"": cannot parse "0" as "\"""#),
    (RFC3339, "\"", r#"parsing time "\"" as "2006-01-02T15:04:05Z07:00": cannot parse "\"" as "2006""#),
    (RFC3339, "0000-01-01T00:00:00+00:+0", r#"parsing time "0000-01-01T00:00:00+00:+0" as "2006-01-02T15:04:05Z07:00": cannot parse "+00:+0" as "Z07:00""#),
    (RFC3339, "0000-01-01T00:00:00+-0:00", r#"parsing time "0000-01-01T00:00:00+-0:00" as "2006-01-02T15:04:05Z07:00": cannot parse "+-0:00" as "Z07:00""#),
    ("2006-01-02", "22-10-25", r#"parsing time "22-10-25" as "2006-01-02": cannot parse "22-10-25" as "2006""#),
    ("06-01-02", "a2-10-25", r#"parsing time "a2-10-25" as "06-01-02": cannot parse "a2-10-25" as "06""#),
    ("03:04PM", "12:03pM", r#"parsing time "12:03pM" as "03:04PM": cannot parse "pM" as "PM""#),
    ("03:04pm", "12:03pM", r#"parsing time "12:03pM" as "03:04pm": cannot parse "pM" as "pm""#),
    ("-07", "-25", "time zone offset hour out of range"),
    ("-07:00", "+25:00", "time zone offset hour out of range"),
    ("-07:00", "-23:61", "time zone offset minute out of range"),
    ("-07:00:00", "+23:59:61", "time zone offset second out of range"),
    ("Z07", "-25", "time zone offset hour out of range"),
    ("Z07:00", "+25:00", "time zone offset hour out of range"),
    ("Z07:00", "-23:61", "time zone offset minute out of range"),
    ("Z07:00:00", "+23:59:61", "time zone offset second out of range"),
];

#[test]
fn parse_errors() {
    for &(layout, value, expect) in PARSE_ERROR_TESTS {
        let err = time::Time::parse(layout, value).expect_err(value);
        assert!(
            err.to_string().contains(expect),
            "{layout:?} {value:?}: {err} does not contain {expect}"
        );
    }
    for (layout, value, prefix) in [
        ("01 MST", "0 MST", "0"),
        ("01 MST", "1 MST", "1"),
        (RFC850, "Thursday, 04-Feb-1 21:00:57 PST", "1"),
    ] {
        let err = time::Time::parse(layout, value).unwrap_err();
        assert!(err.to_string().contains("cannot parse") && err.value_elem.starts_with(prefix));
    }
}

#[test]
fn parse_misc() {
    for layout in ["3:04PM", "03:04PM"] {
        assert_eq!(time::Time::parse(layout, "12:00PM").unwrap().hour(), 12);
        assert_eq!(time::Time::parse(layout, "12:00AM").unwrap().hour(), 0);
    }
    let t = time::Time::parse(RUBY_DATE, "Thu Feb 02 16:10:03 -0500 2006").unwrap();
    assert_eq!(t.format(UNIX_DATE), "Thu Feb  2 16:10:03 -0500 2006");
    let t = time::Time::parse(RUBY_DATE, "Mon Jan 02 15:04:05 +0123 2006").unwrap();
    assert_eq!(t.zone().1, (60 + 23) * 60);
    let t = time::Time::parse("15:04_20060102", "14:38_20150618").unwrap();
    assert_eq!(t.date(), (2015, Month(6), 18));
    assert_eq!((t.hour(), t.minute()), (14, 38));
    for i in 1..=365 {
        let t = time::Time::parse("2006-002", &format!("2020-{i:03}")).unwrap();
        assert_eq!((t.year(), t.year_day()), (2020, i));
    }
}

#[test]
fn seconds_in_time_zone() {
    let o = 34 * 60 + 8;
    for (layout, value, offset) in [
        (
            "2006-01-02T15:04:05-070000",
            "1871-01-01T05:33:02-003408",
            -o,
        ),
        (
            "2006-01-02T15:04:05-07:00:00",
            "1871-01-01T05:33:02-00:34:08",
            -o,
        ),
        (
            "2006-01-02T15:04:05-070000",
            "1871-01-01T05:33:02+003408",
            o,
        ),
        (
            "2006-01-02T15:04:05-07:00:00",
            "1871-01-01T05:33:02+00:34:08",
            o,
        ),
        (
            "2006-01-02T15:04:05Z070000",
            "1871-01-01T05:33:02-003408",
            -o,
        ),
        (
            "2006-01-02T15:04:05Z07:00:00",
            "1871-01-01T05:33:02+00:34:08",
            o,
        ),
        ("2006-01-02T15:04:05-07", "1871-01-01T05:33:02+01", 3600),
        ("2006-01-02T15:04:05-07", "1871-01-01T05:33:02-02", -7200),
        ("2006-01-02T15:04:05Z07", "1871-01-01T05:33:02-02", -7200),
    ] {
        assert_eq!(
            time::Time::parse(layout, value).unwrap().zone().1,
            offset,
            "{value}"
        );
        let t = d(
            1871,
            1,
            1,
            5,
            33,
            2,
            0,
            &time::Location::fixed("LMT", offset),
        );
        assert_eq!(t.format(layout), value);
    }
}

#[test]
fn long_fractional_digits() {
    for (value, want) in [
        ("2021-09-29T16:04:33.000000000Z", 0),
        ("2021-09-29T16:04:33.000000001Z", 1),
        ("2021-09-29T16:04:33.100000000Z", 100_000_000),
        ("2021-09-29T16:04:33.100000001Z", 100_000_001),
        ("2021-09-29T16:04:33.999999999Z", 999_999_999),
        ("2021-09-29T16:04:33.012345678Z", 12_345_678),
        ("2021-09-29T16:04:33.0000000000Z", 0),
        ("2021-09-29T16:04:33.0000000001Z", 0),
        ("2021-09-29T16:04:33.1000000000Z", 100_000_000),
        ("2021-09-29T16:04:33.1000000009Z", 100_000_000),
        ("2021-09-29T16:04:33.9999999999Z", 999_999_999),
        ("2021-09-29T16:04:33.0123456789Z", 12_345_678),
        ("2021-09-29T16:04:33.10000000000Z", 100_000_000),
        ("2021-09-29T16:04:33.00123456789Z", 1_234_567),
        ("2021-09-29T16:04:33.000123456789Z", 123_456),
        ("2021-09-29T16:04:33.9999999999999999Z", 999_999_999),
    ] {
        for layout in [RFC3339, RFC3339_NANO] {
            assert_eq!(
                time::Time::parse(layout, value).unwrap().nanosecond(),
                want,
                "{value}"
            );
        }
    }
}

#[test]
fn format_and_parse_round_trip() {
    let layout = format!("Mon MST {RFC3339}");
    let la = la();
    let mut sec = -(1i64 << 40);
    while sec < 1 << 40 {
        let t1 = time::unix(sec / 2, 0).in_location(&la);
        // Go's quick.Check inputs never reach LA local mean time (pre-1883),
        // whose seconds offset RFC3339 cannot carry.
        if (1900..=9999).contains(&t1.year()) {
            let t2 = time::Time::parse_in_location(&layout, &t1.format(&layout), &la).unwrap();
            assert_eq!((t1.unix(), t1.nanosecond()), (t2.unix(), t2.nanosecond()));
        }
        sec += 7_919_993_337;
    }
}

#[test]
fn unix_and_local_tables() {
    let golden = |t: &Time, y, mo, day, h, mi, s, ns, wd: i64, off, zone: &str| {
        assert_eq!(t.date(), (y, Month(mo), day));
        assert_eq!(t.clock(), (h, mi, s));
        assert_eq!(t.nanosecond(), ns);
        assert_eq!(t.weekday(), Weekday(wd));
        assert_eq!(t.zone(), (zone, off));
    };
    for (sec, y, mo, day, h, mi, s, wd) in [
        (0, 1970, 1, 1, 0, 0, 0, 4),
        (1221681866, 2008, 9, 17, 20, 4, 26, 3),
        (-1221681866, 1931, 4, 16, 3, 55, 34, 4),
        (-11644473600, 1601, 1, 1, 0, 0, 0, 1),
        (599529660, 1988, 12, 31, 0, 1, 0, 6),
        (978220860, 2000, 12, 31, 0, 1, 0, 0),
    ] {
        let t = time::unix(sec, 0).utc();
        assert_eq!(t.unix(), sec);
        golden(&t, y, mo, day, h, mi, s, 0, wd, 0, "UTC");
    }
    let t = time::unix(0, 100_000_000).utc();
    golden(&t, 1970, 1, 1, 0, 0, 0, 100_000_000, 4, 0, "UTC");
    let la = la();
    for (sec, y, mo, day, h, mi, s, wd, off, zone) in [
        (0, 1969, 12, 31, 16, 0, 0, 3, -8 * 3600, "PST"),
        (1221681866, 2008, 9, 17, 13, 4, 26, 3, -7 * 3600, "PDT"),
        (2159200800, 2038, 6, 3, 11, 0, 0, 4, -7 * 3600, "PDT"),
        (2152173599, 2038, 3, 14, 1, 59, 59, 0, -8 * 3600, "PST"),
        (2152173600, 2038, 3, 14, 3, 0, 0, 0, -7 * 3600, "PDT"),
        (2152173601, 2038, 3, 14, 3, 0, 1, 0, -7 * 3600, "PDT"),
        (2172733199, 2038, 11, 7, 1, 59, 59, 0, -7 * 3600, "PDT"),
        (2172733200, 2038, 11, 7, 1, 0, 0, 0, -8 * 3600, "PST"),
        (2172733201, 2038, 11, 7, 1, 0, 1, 0, -8 * 3600, "PST"),
    ] {
        let t = time::unix(sec, 0).in_location(&la);
        golden(&t, y, mo, day, h, mi, s, 0, wd, off, zone);
    }
}

#[test]
fn truncate_round_table() {
    let check = |t0: Time, d: i64| {
        let total =
            i128::from(t0.unix() + 62_135_596_800) * 1_000_000_000 + i128::from(t0.nanosecond());
        let r = total.rem_euclid(i128::from(d)) as i64;
        let mut t1 = t0.add(dur(-r));
        assert!(t0.truncate(dur(d)).equal(&t1), "truncate {t0} {d}");
        if r > d / 2 || r + r == d {
            t1 = t1.add(dur(d));
        }
        assert!(t0.round(dur(d)).equal(&t1), "round {t0} {d}");
    };
    for (t, d) in [
        (d(-1, 1, 1, 12, 15, 30, 500_000_000, &utc()), 3),
        (d(-1, 1, 1, 12, 15, 31, 500_000_000, &utc()), 3),
        (
            d(2012, 1, 1, 12, 15, 30, 500_000_000, &utc()),
            SECOND.as_nanos(),
        ),
        (
            d(2012, 1, 1, 12, 15, 31, 500_000_000, &utc()),
            SECOND.as_nanos(),
        ),
        (time::unix(-19012425939, 649146258), 7435029458905025217),
    ] {
        check(t.utc(), d);
    }
    let unix_to_zero = -62_135_596_800;
    for i in 0..100 {
        for j in 1..100 {
            check(time::unix(unix_to_zero, i).utc(), j);
            check(time::unix(unix_to_zero, -i).utc(), j);
        }
    }
}

#[test]
fn iso_week_table() {
    #[rustfmt::skip]
    let table = [
        (1981, 1, 1, 1981, 1), (1982, 1, 1, 1981, 53), (1983, 1, 1, 1982, 52),
        (1984, 1, 1, 1983, 52), (1985, 1, 1, 1985, 1), (1986, 1, 1, 1986, 1),
        (1987, 1, 1, 1987, 1), (1988, 1, 1, 1987, 53), (1989, 1, 1, 1988, 52),
        (1990, 1, 1, 1990, 1), (1991, 1, 1, 1991, 1), (1992, 1, 1, 1992, 1),
        (1993, 1, 1, 1992, 53), (1994, 1, 1, 1993, 52), (1995, 1, 2, 1995, 1),
        (1996, 1, 1, 1996, 1), (1996, 1, 7, 1996, 1), (1996, 1, 8, 1996, 2),
        (1997, 1, 1, 1997, 1), (1998, 1, 1, 1998, 1), (1999, 1, 1, 1998, 53),
        (2000, 1, 1, 1999, 52), (2001, 1, 1, 2001, 1), (2002, 1, 1, 2002, 1),
        (2003, 1, 1, 2003, 1), (2004, 1, 1, 2004, 1), (2005, 1, 1, 2004, 53),
        (2006, 1, 1, 2005, 52), (2007, 1, 1, 2007, 1), (2008, 1, 1, 2008, 1),
        (2009, 1, 1, 2009, 1), (2010, 1, 1, 2009, 53), (2010, 1, 1, 2009, 53),
        (2011, 1, 1, 2010, 52), (2011, 1, 2, 2010, 52), (2011, 1, 3, 2011, 1),
        (2011, 1, 4, 2011, 1), (2011, 1, 5, 2011, 1), (2011, 1, 6, 2011, 1),
        (2011, 1, 7, 2011, 1), (2011, 1, 8, 2011, 1), (2011, 1, 9, 2011, 1),
        (2011, 1, 10, 2011, 2), (2011, 1, 11, 2011, 2), (2011, 6, 12, 2011, 23),
        (2011, 6, 13, 2011, 24), (2011, 12, 25, 2011, 51), (2011, 12, 26, 2011, 52),
        (2011, 12, 27, 2011, 52), (2011, 12, 28, 2011, 52), (2011, 12, 29, 2011, 52),
        (2011, 12, 30, 2011, 52), (2011, 12, 31, 2011, 52), (1995, 1, 1, 1994, 52),
        (2012, 1, 1, 2011, 52), (2012, 1, 2, 2012, 1), (2012, 1, 8, 2012, 1),
        (2012, 1, 9, 2012, 2), (2012, 12, 23, 2012, 51), (2012, 12, 24, 2012, 52),
        (2012, 12, 30, 2012, 52), (2012, 12, 31, 2013, 1), (2013, 1, 1, 2013, 1),
        (2013, 1, 6, 2013, 1), (2013, 1, 7, 2013, 2), (2013, 12, 22, 2013, 51),
        (2013, 12, 23, 2013, 52), (2013, 12, 29, 2013, 52), (2013, 12, 30, 2014, 1),
        (2014, 1, 1, 2014, 1), (2014, 1, 5, 2014, 1), (2014, 1, 6, 2014, 2),
        (2015, 1, 1, 2015, 1), (2016, 1, 1, 2015, 53), (2017, 1, 1, 2016, 52),
        (2018, 1, 1, 2018, 1), (2019, 1, 1, 2019, 1), (2020, 1, 1, 2020, 1),
        (2021, 1, 1, 2020, 53), (2022, 1, 1, 2021, 52), (2023, 1, 1, 2022, 52),
        (2024, 1, 1, 2024, 1), (2025, 1, 1, 2025, 1), (2026, 1, 1, 2026, 1),
        (2027, 1, 1, 2026, 53), (2028, 1, 1, 2027, 52), (2029, 1, 1, 2029, 1),
        (2030, 1, 1, 2030, 1), (2031, 1, 1, 2031, 1), (2032, 1, 1, 2032, 1),
        (2033, 1, 1, 2032, 53), (2034, 1, 1, 2033, 52), (2035, 1, 1, 2035, 1),
        (2036, 1, 1, 2036, 1), (2037, 1, 1, 2037, 1), (2038, 1, 1, 2037, 53),
        (2039, 1, 1, 2038, 52), (2040, 1, 1, 2039, 52),
    ];
    for (y, m, day, yex, wex) in table {
        assert_eq!(
            d(y, m, day, 0, 0, 0, 0, &utc()).iso_week(),
            (yex, wex),
            "{y}-{m}-{day}"
        );
    }
    for year in 1950..2100 {
        assert_eq!(d(year, 1, 4, 0, 0, 0, 0, &utc()).iso_week(), (year, 1));
    }
}

#[test]
fn year_day_table() {
    #[rustfmt::skip]
    let table = [
        (2007, 1, 1, 1), (2007, 1, 15, 15), (2007, 2, 1, 32), (2007, 2, 15, 46),
        (2007, 3, 1, 60), (2007, 3, 15, 74), (2007, 4, 1, 91), (2007, 12, 31, 365),
        (2008, 1, 1, 1), (2008, 1, 15, 15), (2008, 2, 1, 32), (2008, 2, 15, 46),
        (2008, 3, 1, 61), (2008, 3, 15, 75), (2008, 4, 1, 92), (2008, 12, 31, 366),
        (1900, 1, 1, 1), (1900, 1, 15, 15), (1900, 2, 1, 32), (1900, 2, 15, 46),
        (1900, 3, 1, 60), (1900, 3, 15, 74), (1900, 4, 1, 91), (1900, 12, 31, 365),
        (1, 1, 1, 1), (1, 1, 15, 15), (1, 2, 1, 32), (1, 2, 15, 46),
        (1, 3, 1, 60), (1, 3, 15, 74), (1, 4, 1, 91), (1, 12, 31, 365),
        (-1, 1, 1, 1), (-1, 1, 15, 15), (-1, 2, 1, 32), (-1, 2, 15, 46),
        (-1, 3, 1, 60), (-1, 3, 15, 74), (-1, 4, 1, 91), (-1, 12, 31, 365),
        (-400, 1, 1, 1), (-400, 1, 15, 15), (-400, 2, 1, 32), (-400, 2, 15, 46),
        (-400, 3, 1, 61), (-400, 3, 15, 75), (-400, 4, 1, 92), (-400, 12, 31, 366),
        (1582, 10, 4, 277), (1582, 10, 15, 288),
    ];
    let locations = [
        time::Location::fixed("UTC-8", -8 * 3600),
        time::Location::fixed("UTC-4", -4 * 3600),
        utc(),
        time::Location::fixed("UTC+4", 4 * 3600),
        time::Location::fixed("UTC+8", 8 * 3600),
    ];
    for (i, loc) in locations.iter().enumerate() {
        for (y, m, day, yday) in table {
            let t = d(y, m, day, 0, 0, 0, 0, loc);
            assert_eq!(t.year_day(), yday, "{y}-{m}-{day} in {loc}");
            if !(0..=9999).contains(&y) {
                continue;
            }
            let off = (i as i64 - 2) * 4;
            let sign = if off < 0 { '-' } else { '+' };
            let value = format!("{y:04}-{m:02}-{day:02} {yday:03} {sign}{:02}00", off.abs());
            let t1 = time::Time::parse("2006-01-02 002 -0700", &value).unwrap();
            assert!(t1.equal(&t), "{value}");
        }
    }
}

#[test]
fn duration_string_and_methods() {
    for (s, n) in [
        ("0s", 0),
        ("1ns", 1),
        ("1.1µs", 1100),
        ("2.2ms", 2_200_000),
        ("3.3s", 3_300_000_000),
        ("4m5s", (4 * MINUTE + 5 * SECOND).as_nanos()),
        ("4m5.001s", (4 * MINUTE + 5001 * MILLISECOND).as_nanos()),
        (
            "5h6m7.001s",
            (5 * HOUR + 6 * MINUTE + 7001 * MILLISECOND).as_nanos(),
        ),
        ("8m0.000000001s", (8 * MINUTE + NANOSECOND).as_nanos()),
        ("2562047h47m16.854775807s", i64::MAX),
        ("-2562047h47m16.854775808s", i64::MIN),
    ] {
        assert_eq!(dur(n).to_string(), s);
        if n > 0 {
            assert_eq!(dur(-n).to_string(), format!("-{s}"));
        }
    }
    for (n, want) in [(-1000, -1000), (-1, -1), (1, 1), (1000, 1000)] {
        assert_eq!(dur(n).nanoseconds(), want);
    }
    assert_eq!(
        (dur(-1000).microseconds(), dur(1000).microseconds()),
        (-1, 1)
    );
    assert_eq!(
        (
            dur(-1_000_000).milliseconds(),
            dur(1_000_000).milliseconds()
        ),
        (-1, 1)
    );
    assert_eq!(dur(300_000_000).seconds(), 0.3);
    for (n, want) in [
        (-60_000_000_000, -1.0),
        (-1, -1.0 / 60e9),
        (1, 1.0 / 60e9),
        (60_000_000_000, 1.0),
        (3000, 5e-8),
    ] {
        assert_eq!(dur(n).minutes(), want);
    }
    for (n, want) in [
        (-3_600_000_000_000, -1.0),
        (-1, -1.0 / 3600e9),
        (1, 1.0 / 3600e9),
        (3_600_000_000_000, 1.0),
        (36, 1e-11),
    ] {
        assert_eq!(dur(n).hours(), want);
    }
    let (s, m, h) = (SECOND.as_nanos(), MINUTE.as_nanos(), HOUR.as_nanos());
    for (x, by, want) in [
        (0, s, 0),
        (m, -7 * s, m),
        (m, 0, m),
        (m, 1, m),
        (m + 10 * s, 10 * s, m + 10 * s),
        (2 * m + 10 * s, m, 2 * m),
        (10 * m + 10 * s, 3 * m, 9 * m),
        (m + 10 * s, m + 10 * s + 1, 0),
        (m + 10 * s, h, 0),
        (-m, s, -m),
        (-10 * m, 3 * m, -9 * m),
        (-10 * m, h, 0),
    ] {
        assert_eq!(dur(x).truncate(dur(by)).as_nanos(), want);
    }
    for (x, by, want) in [
        (0, s, 0),
        (m, -11 * s, m),
        (m, 0, m),
        (m, 1, m),
        (2 * m, m, 2 * m),
        (2 * m + 10 * s, m, 2 * m),
        (2 * m + 30 * s, m, 3 * m),
        (2 * m + 50 * s, m, 3 * m),
        (-m, 1, -m),
        (-2 * m, m, -2 * m),
        (-2 * m - 10 * s, m, -2 * m),
        (-2 * m - 30 * s, m, -3 * m),
        (-2 * m - 50 * s, m, -3 * m),
        (
            8_000_000_000_000_000_000,
            3_000_000_000_000_000_000,
            9_000_000_000_000_000_000,
        ),
        (
            9_000_000_000_000_000_000,
            5_000_000_000_000_000_000,
            i64::MAX,
        ),
        (
            -8_000_000_000_000_000_000,
            3_000_000_000_000_000_000,
            -9_000_000_000_000_000_000,
        ),
        (
            -9_000_000_000_000_000_000,
            5_000_000_000_000_000_000,
            i64::MIN,
        ),
        ((3 << 61) - 1, 3 << 61, 3 << 61),
    ] {
        assert_eq!(dur(x).round(dur(by)).as_nanos(), want, "{x} {by}");
    }
    for (x, want) in [
        (0, 0),
        (1, 1),
        (-1, 1),
        (m, m),
        (-m, m),
        (i64::MIN, i64::MAX),
        (i64::MIN + 1, i64::MAX),
        (i64::MIN + 2, i64::MAX - 1),
        (i64::MAX, i64::MAX),
        (i64::MAX - 1, i64::MAX - 1),
    ] {
        assert_eq!(dur(x).abs().as_nanos(), want);
    }
}

#[test]
fn date_table() {
    let la = la();
    for (y, mo, day, h, mi, s, ns, unix) in [
        (2011, 11, 6, 1, 0, 0, 0, 1320566400),
        (2011, 11, 6, 1, 59, 59, 0, 1320569999),
        (2011, 11, 6, 2, 0, 0, 0, 1320573600),
        (2011, 3, 13, 1, 0, 0, 0, 1300006800),
        (2011, 3, 13, 1, 59, 59, 0, 1300010399),
        (2011, 3, 13, 3, 0, 0, 0, 1300010400),
        (2011, 3, 13, 2, 30, 0, 0, 1300008600),
        (2012, 12, 24, 0, 0, 0, 0, 1356336000),
        (2011, 11, 18, 7, 56, 35, 0, 1321631795),
        (2011, 11, 19, -17, 56, 35, 0, 1321631795),
        (2011, 11, 17, 31, 56, 35, 0, 1321631795),
        (2011, 11, 18, 6, 116, 35, 0, 1321631795),
        (2011, 10, 49, 7, 56, 35, 0, 1321631795),
        (2011, 11, 18, 7, 55, 95, 0, 1321631795),
        (2011, 11, 18, 7, 56, 34, 1_000_000_000, 1321631795),
        (2011, 12, -12, 7, 56, 35, 0, 1321631795),
        (2012, 1, -43, 7, 56, 35, 0, 1321631795),
        (2012, 1 - 2, 18, 7, 56, 35, 0, 1321631795),
        (2010, 12 + 11, 18, 7, 56, 35, 0, 1321631795),
        (1970, 1, 15297, 7, 56, 35, 0, 1321631795),
        (1970, 1, -25508, 0, 0, 0, 0, -2203948800),
    ] {
        let t = d(y, mo, day, h, mi, s, ns, &la);
        assert!(t.equal(&time::unix(unix, 0)), "{y}-{mo}-{day} {h}:{mi}:{s}");
    }
}

#[test]
fn add_date_table() {
    let t0 = d(2011, 11, 18, 7, 56, 35, 0, &utc());
    let t1 = d(2016, 3, 19, 7, 56, 35, 0, &utc());
    for (y, m, day) in [(4, 4, 1), (3, 16, 1), (3, 15, 30), (5, -6, -18 - 30 - 12)] {
        assert!(t0.add_date(y, m, day).equal(&t1), "{y} {m} {day}");
    }
    let t2 = d(1899, 12, 31, 0, 0, 0, 0, &utc());
    let days = t2.unix() / 86400;
    assert!(time::unix(0, 0).utc().add_date(0, 0, days).equal(&t2));
    let t = time::now();
    let t2 = t.add(SECOND - dur(t.nanosecond()));
    assert_eq!((t2.second(), t2.nanosecond()), ((t.second() + 1) % 60, 0));
}

fn equal_time_and_zone(a: &Time, b: &Time) -> bool {
    a.equal(b) && a.zone() == b.zone()
}

#[test]
fn binary_gob_and_json() {
    for t in [
        d(0, 1, 2, 3, 4, 5, 6, &utc()),
        d(7, 8, 9, 10, 11, 12, 13, &time::Location::fixed("", 0)),
        time::unix(81985467080890095, 0x76543210),
        Time::default(),
        d(1, 2, 3, 4, 5, 6, 7, &time::Location::fixed("", 32767 * 60)),
        d(1, 2, 3, 4, 5, 6, 7, &time::Location::fixed("", -32768 * 60)),
    ] {
        let b = t.gob_encode().unwrap();
        let mut u = Time::default();
        u.gob_decode(&b).unwrap();
        // The decoded zone is Local when the offset matches it; compare
        // instants and offsets, which are independent of Local.
        assert!(u.equal(&t) && u.zone().1 == t.zone().1, "{t}");
        let mut v = Time::default();
        v.unmarshal_binary(&t.marshal_binary().unwrap()).unwrap();
        assert!(v.equal(&t));
    }
    for (bytes, want) in [
        (&b""[..], "Time.UnmarshalBinary: no data"),
        (&[0, 2, 3][..], "Time.UnmarshalBinary: unsupported version"),
        (&[1, 2, 3][..], "Time.UnmarshalBinary: invalid length"),
    ] {
        let mut t = Time::default();
        assert_eq!(t.gob_decode(bytes).unwrap_err().to_string(), want);
        assert_eq!(t.unmarshal_binary(bytes).unwrap_err().to_string(), want);
    }
    for offset in [-60, -32769 * 60, 32768 * 60] {
        let t = d(0, 1, 2, 3, 4, 5, 6, &time::Location::fixed("", offset));
        let want = "Time.MarshalBinary: unexpected zone offset";
        assert_eq!(t.gob_encode().unwrap_err().to_string(), want);
        assert_eq!(t.marshal_binary().unwrap_err().to_string(), want);
    }
    let la = la();
    for (t, json) in [
        (
            d(9999, 4, 12, 23, 20, 50, 520_000_000, &utc()),
            r#""9999-04-12T23:20:50.52Z""#,
        ),
        (
            d(1996, 12, 19, 16, 39, 57, 0, &la),
            r#""1996-12-19T16:39:57-08:00""#,
        ),
        (
            d(0, 1, 1, 0, 0, 0, 1, &time::Location::fixed("", 60)),
            r#""0000-01-01T00:00:00.000000001+00:01""#,
        ),
        (
            d(
                2020,
                1,
                1,
                0,
                0,
                0,
                0,
                &time::Location::fixed("", 23 * 3600 + 59 * 60),
            ),
            r#""2020-01-01T00:00:00+23:59""#,
        ),
    ] {
        let b = t.marshal_json().unwrap();
        assert_eq!(String::from_utf8(b.clone()).unwrap(), json);
        let mut u = Time::default();
        u.unmarshal_json(&b).unwrap();
        assert!(u.equal(&t) && u.zone().1 == t.zone().1);
        if t.location().name() != "America/Los_Angeles" {
            assert!(equal_time_and_zone(&u, &t) || t.zone().0.is_empty());
        }
    }
    for (input, want) in [
        ("{}", Some("Time.UnmarshalJSON: input is not a JSON string")),
        ("[]", Some("Time.UnmarshalJSON: input is not a JSON string")),
        (r#""2000-01-01T1:12:34Z""#, None),
        (r#""2000-01-01T00:00:00,000Z""#, None),
        (r#""2000-01-01T00:00:00+24:00""#, None),
        (r#""2000-01-01T00:00:00+00:60""#, None),
        (
            r#""2000-01-01T00:00:00+123:45""#,
            Some(
                r#"parsing time "2000-01-01T00:00:00+123:45" as "2006-01-02T15:04:05Z07:00": cannot parse "+123:45" as "Z07:00""#,
            ),
        ),
    ] {
        let mut t = Time::default();
        let got = t
            .unmarshal_json(input.as_bytes())
            .err()
            .map(|e| e.to_string());
        assert_eq!(got.as_deref(), want, "{input}");
        if input.starts_with('"') {
            let got = t
                .unmarshal_text(input.trim_matches('"').as_bytes())
                .err()
                .map(|e| e.to_string());
            assert_eq!(got.as_deref(), want, "{input}");
        }
    }
    for (t, want) in [
        (
            d(10000, 1, 1, 0, 0, 0, 0, &utc()),
            "year outside of range [0,9999]",
        ),
        (
            d(-998, 1, 1, 0, 0, 0, 0, &utc()).add(-SECOND),
            "year outside of range [0,9999]",
        ),
        (
            d(0, 1, 1, 0, 0, 0, 0, &utc()).add(-NANOSECOND),
            "year outside of range [0,9999]",
        ),
        (
            d(
                2020,
                1,
                1,
                0,
                0,
                0,
                0,
                &time::Location::fixed("", 24 * 3600),
            ),
            "timezone hour outside of range [0,23]",
        ),
        (
            d(
                2020,
                1,
                1,
                0,
                0,
                0,
                0,
                &time::Location::fixed("", 123 * 3600),
            ),
            "timezone hour outside of range [0,23]",
        ),
    ] {
        assert_eq!(
            t.marshal_json().unwrap_err().to_string(),
            format!("Time.MarshalJSON: {want}")
        );
        assert_eq!(
            t.marshal_text().unwrap_err().to_string(),
            format!("Time.MarshalText: {want}")
        );
        let mut buf = Vec::new();
        assert_eq!(
            t.append_text(&mut buf).unwrap_err().to_string(),
            format!("Time.AppendText: {want}")
        );
    }
    assert_eq!(JANUARY.to_string(), "January");
}

#[test]
fn parse_duration_tables() {
    let (s, m, h, ms, us) = (SECOND, MINUTE, HOUR, MILLISECOND, MICROSECOND);
    for (input, want) in [
        ("0", dur(0)),
        ("5s", 5 * s),
        ("30s", 30 * s),
        ("1478s", 1478 * s),
        ("-5s", -5 * s),
        ("+5s", 5 * s),
        ("-0", dur(0)),
        ("+0", dur(0)),
        ("5.0s", 5 * s),
        ("5.6s", 5 * s + 600 * ms),
        ("5.s", 5 * s),
        (".5s", 500 * ms),
        ("1.0s", s),
        ("1.00s", s),
        ("1.004s", s + 4 * ms),
        ("1.0040s", s + 4 * ms),
        ("100.00100s", 100 * s + ms),
        ("10ns", 10 * NANOSECOND),
        ("11us", 11 * us),
        ("12µs", 12 * us),
        ("12μs", 12 * us),
        ("13ms", 13 * ms),
        ("14s", 14 * s),
        ("15m", 15 * m),
        ("16h", 16 * h),
        ("3h30m", 3 * h + 30 * m),
        ("10.5s4m", 4 * m + 10 * s + 500 * ms),
        ("-2m3.4s", -(2 * m + 3 * s + 400 * ms)),
        (
            "1h2m3s4ms5us6ns",
            h + 2 * m + 3 * s + 4 * ms + 5 * us + 6 * NANOSECOND,
        ),
        ("39h9m14.425s", 39 * h + 9 * m + 14 * s + 425 * ms),
        ("52763797000ns", dur(52763797000)),
        ("0.3333333333333333333h", 20 * m),
        ("9007199254740993ns", dur((1 << 53) + 1)),
        ("9223372036854775807ns", dur(i64::MAX)),
        ("9223372036854775.807us", dur(i64::MAX)),
        ("9223372036s854ms775us807ns", dur(i64::MAX)),
        ("-9223372036854775808ns", dur(i64::MIN)),
        ("-9223372036854775.808us", dur(i64::MIN)),
        ("-9223372036s854ms775us808ns", dur(i64::MIN)),
        ("-2562047h47m16.854775808s", dur(i64::MIN)),
        ("0.100000000000000000000h", 6 * m),
        ("0.830103483285477580700h", 49 * m + 48 * s + dur(372539827)),
    ] {
        assert_eq!(input.parse::<time::Duration>().unwrap(), want, "{input}");
    }
    for (input, expect) in [
        ("", r#""""#),
        ("3", r#""3""#),
        ("-", r#""-""#),
        ("s", r#""s""#),
        (".", r#"".""#),
        ("-.", r#""-.""#),
        (".s", r#"".s""#),
        ("+.s", r#""+.s""#),
        ("1d", r#""1d""#),
        ("\u{FFFD}", r#""\xef\xbf\xbd""#),
        (
            "\u{FFFD} hello \u{FFFD} world",
            r#""\xef\xbf\xbd hello \xef\xbf\xbd world""#,
        ),
        ("9223372036854775810ns", r#""9223372036854775810ns""#),
        ("9223372036854775808ns", r#""9223372036854775808ns""#),
        ("-9223372036854775809ns", r#""-9223372036854775809ns""#),
        ("9223372036854776us", r#""9223372036854776us""#),
        ("3000000h", r#""3000000h""#),
        ("9223372036854775.808us", r#""9223372036854775.808us""#),
        (
            "9223372036854ms775us808ns",
            r#""9223372036854ms775us808ns""#,
        ),
    ] {
        let err = input.parse::<time::Duration>().unwrap_err().to_string();
        assert!(err.contains(expect), "{input:?}: {err}");
    }
    for d in [dur(i64::MAX), dur(i64::MIN), 1234567 * MILLISECOND] {
        assert_eq!(d.to_string().parse::<time::Duration>().unwrap(), d);
    }
}

#[test]
fn sub_table() {
    let zero = Time::default();
    let (min, max) = (dur(i64::MIN), dur(i64::MAX));
    let day = 24 * HOUR;
    for (t, u, want) in [
        (zero.clone(), zero.clone(), dur(0)),
        (
            d(2009, 11, 23, 0, 0, 0, 1, &utc()),
            d(2009, 11, 23, 0, 0, 0, 0, &utc()),
            dur(1),
        ),
        (
            d(2009, 11, 23, 0, 0, 0, 0, &utc()),
            d(2009, 11, 24, 0, 0, 0, 0, &utc()),
            -day,
        ),
        (
            d(2009, 11, 24, 0, 0, 0, 0, &utc()),
            d(2009, 11, 23, 0, 0, 0, 0, &utc()),
            day,
        ),
        (
            d(-2009, 11, 24, 0, 0, 0, 0, &utc()),
            d(-2009, 11, 23, 0, 0, 0, 0, &utc()),
            day,
        ),
        (zero.clone(), d(2109, 11, 23, 0, 0, 0, 0, &utc()), min),
        (d(2109, 11, 23, 0, 0, 0, 0, &utc()), zero.clone(), max),
        (zero.clone(), d(-2109, 11, 23, 0, 0, 0, 0, &utc()), max),
        (d(-2109, 11, 23, 0, 0, 0, 0, &utc()), zero.clone(), min),
        (
            d(2290, 1, 1, 0, 0, 0, 0, &utc()),
            d(2000, 1, 1, 0, 0, 0, 0, &utc()),
            290 * 365 * day + 71 * day,
        ),
        (
            d(2300, 1, 1, 0, 0, 0, 0, &utc()),
            d(2000, 1, 1, 0, 0, 0, 0, &utc()),
            max,
        ),
        (
            d(2000, 1, 1, 0, 0, 0, 0, &utc()),
            d(2290, 1, 1, 0, 0, 0, 0, &utc()),
            -(290 * 365 * day) - 71 * day,
        ),
        (
            d(2000, 1, 1, 0, 0, 0, 0, &utc()),
            d(2300, 1, 1, 0, 0, 0, 0, &utc()),
            min,
        ),
        (
            d(2311, 11, 26, 2, 16, 47, 63535996, &utc()),
            d(2019, 8, 16, 2, 29, 30, 268436582, &utc()),
            dur(9223372036795099414),
        ),
    ] {
        assert_eq!(t.sub(&u), want, "{t} - {u}");
    }
}

#[test]
fn default_location_matches_utc() {
    // Go's defaultLocTests: the zero Time and the zero Time in UTC agree.
    let t1 = Time::default();
    let t2 = Time::default().utc();
    assert_eq!(t1.after(&t2), t2.after(&t1));
    assert_eq!(t1.compare(&t2), t2.compare(&t1));
    assert_eq!(t1.date(), t2.date());
    assert_eq!(t1.iso_week(), t2.iso_week());
    assert_eq!(t1.clock(), t2.clock());
    assert_eq!(t1.year_day(), t2.year_day());
    assert_eq!(t1.sub(&t2), t2.sub(&t1));
    assert!(t1.add_date(1991, 9, 3).equal(&t2.add_date(1991, 9, 3)));
    assert_eq!(t1.marshal_json().unwrap(), t2.marshal_json().unwrap());
    assert_eq!(t1.format(RFC1123), t2.format(RFC1123));
    assert_eq!(
        t1.literal(),
        "time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)"
    );
    assert_eq!(t1.to_string(), "0001-01-01 00:00:00 +0000 UTC");
}

#[test]
fn month_weekday_strings_and_monotonic() {
    assert_eq!(Month(13).to_string(), "%!Month(13)");
    assert_eq!(Month(-1).to_string(), "%!Month(18446744073709551615)");
    assert_eq!(Weekday(7).to_string(), "%!Weekday(7)");
    assert_eq!(time::SATURDAY.to_string(), "Saturday");
    let t = time::now();
    assert!(t.to_string().contains(" m=+"));
    assert!(!t.round(dur(0)).to_string().contains(" m="));
    assert!(!t.utc().to_string().contains(" m="));
    let later = t.add(SECOND);
    assert_eq!(later.sub(&t), SECOND);
    assert!(time::since(&t) >= dur(0));
    assert!(time::until(&later) <= SECOND);
}
