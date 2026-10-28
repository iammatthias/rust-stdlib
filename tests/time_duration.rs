use rust_stdlib::time::Duration;

fn parsed(input: &str, nanos: i64) {
    assert_eq!(
        input.parse::<Duration>().unwrap().as_nanos(),
        nanos,
        "{input}"
    );
}

#[test]
fn parses_units_signs_fractions_and_combinations() {
    for (input, nanos) in [
        ("0", 0),
        ("0ns", 0),
        ("+0", 0),
        ("-0", 0),
        ("+1ns", 1),
        ("-1ns", -1),
        ("1us", 1_000),
        ("1µs", 1_000),
        ("1μs", 1_000),
        ("1ms", 1_000_000),
        ("1s", 1_000_000_000),
        ("1m", 60_000_000_000),
        ("1h", 3_600_000_000_000),
        ("1.25s", 1_250_000_000),
        (".5s", 500_000_000),
        ("1.s", 1_000_000_000),
        ("2h45m", 9_900_000_000_000),
        ("1h2m3.004005006s", 3_723_004_005_006),
        ("1.9ns", 1),
        ("0.9ns", 0),
        ("1.0000000001s", 1_000_000_000),
    ] {
        parsed(input, nanos);
    }
}

#[test]
fn rejects_malformed_and_overflowing_values() {
    for input in [
        "",
        "+",
        "-",
        ".s",
        "1",
        "1.",
        "1..s",
        "1.2.3s",
        "1e3s",
        "1fortnight",
        "9223372036854775808ns",
        "-9223372036854775809ns",
        "9223372036854775807ns1ns",
        "2562048h",
    ] {
        assert!(input.parse::<Duration>().is_err(), "accepted {input:?}");
    }
    parsed("9223372036854775807ns", i64::MAX);
    parsed("-9223372036854775808ns", i64::MIN);
}

#[test]
fn formats_using_go_canonical_units_and_zero_padding() {
    for (nanos, expected) in [
        (0, "0s"),
        (1, "1ns"),
        (999, "999ns"),
        (1_000, "1µs"),
        (1_001, "1.001µs"),
        (1_000_000, "1ms"),
        (1_234_567, "1.234567ms"),
        (999_999_999, "999.999999ms"),
        (1_000_000_000, "1s"),
        (1_000_000_001, "1.000000001s"),
        (60_000_000_000, "1m0s"),
        (3_600_000_000_000, "1h0m0s"),
        (3_723_004_005_006, "1h2m3.004005006s"),
        (-1_000_000_001, "-1.000000001s"),
        (i64::MAX, "2562047h47m16.854775807s"),
        (i64::MIN, "-2562047h47m16.854775808s"),
    ] {
        let duration = Duration::from_nanos(nanos);
        assert_eq!(duration.to_string(), expected, "{nanos}");
    }
}

const TTL: Duration = Duration::from_mins(5);
const HALF_DAY: Duration = Duration::from_hours(12).mul(1);
const ROUNDED: Duration = Duration::from_millis(1500).round(Duration::SECOND);

#[test]
fn const_constructors() {
    assert_eq!(TTL, 5 * Duration::MINUTE);
    assert_eq!(HALF_DAY, 12 * Duration::HOUR);
    assert_eq!(ROUNDED, 2 * Duration::SECOND);
    assert_eq!(Duration::from_secs(-3), -3 * Duration::SECOND);
    assert_eq!(Duration::from_micros(7), 7 * Duration::MICROSECOND);
    assert_eq!(Duration::from_millis(7), 7 * Duration::MILLISECOND);
    // Overflow wraps like Go's `Duration(n) * Hour`.
    assert_eq!(
        Duration::from_hours(i64::MAX).as_nanos(),
        i64::MAX.wrapping_mul(3_600_000_000_000)
    );
    assert_eq!(Duration::from_hours(1).checked_mul(i64::MAX), None);
    assert_eq!(
        Duration::from_secs(2).checked_mul(3),
        Some(Duration::from_secs(6))
    );
    assert_eq!(
        Duration::from_nanos(i64::MAX).checked_add(Duration::NANOSECOND),
        None
    );
    assert_eq!(
        Duration::from_nanos(i64::MIN).checked_sub(Duration::NANOSECOND),
        None
    );
}

#[test]
fn std_duration_conversions() {
    let std_d = std::time::Duration::from_millis(1500);
    assert_eq!(Duration::from(std_d), Duration::from_millis(1500));
    assert_eq!(
        Duration::from(std::time::Duration::MAX),
        Duration::from_nanos(i64::MAX)
    );
    assert_eq!(
        std::time::Duration::try_from(Duration::from_millis(1500)).unwrap(),
        std_d
    );
    let err = std::time::Duration::try_from(Duration::from_nanos(-1)).unwrap_err();
    assert_eq!(
        err.to_string(),
        "negative duration cannot be converted to std::time::Duration"
    );
}
