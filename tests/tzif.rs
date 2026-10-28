//! TZif parsing, POSIX TZ footer rules, zone lookup and location loading.
//! Go-parity across real zones is checked by tools/tzif_check.py.
use rust_stdlib::time::{
    self as time, load_location_from, load_location_with, local_for_tz, tzdata_from_zip,
    validate_location_name, Location, LocationError, Month, ALPHA, MAX_TZDATA_LEN, OMEGA,
};
use std::path::PathBuf;

const ZIP: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/src/time/tzdata/zoneinfo.zip");

/// Unix seconds for a UTC civil time (via the crate's own Date with UTC).
fn utc(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    time::date(y, Month(mo), d, h, mi, s, 0, &Location::utc()).unix()
}

/// Hand-built TZif. `types` are (offset, is_dst, abbreviation index). For
/// version 2 and later the data is written twice, 32-bit then 64-bit, and
/// the footer follows the 64-bit block.
fn build(
    version: u8,
    times: &[i64],
    idx: &[u8],
    types: &[(i32, bool, u8)],
    abbrev: &[u8],
    footer: &[u8],
) -> Vec<u8> {
    let header = |counts: [u32; 6]| {
        let mut h = b"TZif".to_vec();
        h.push(version);
        h.extend_from_slice(&[0; 15]);
        for c in counts {
            h.extend_from_slice(&c.to_be_bytes());
        }
        h
    };
    let block = |wide: bool| {
        let mut b = Vec::new();
        for &t in times {
            if wide {
                b.extend_from_slice(&t.to_be_bytes());
            } else {
                b.extend_from_slice(&(t as i32).to_be_bytes());
            }
        }
        b.extend_from_slice(idx);
        for &(off, dst, ai) in types {
            b.extend_from_slice(&off.to_be_bytes());
            b.push(u8::from(dst));
            b.push(ai);
        }
        b.extend_from_slice(abbrev);
        b
    };
    let n = types.len() as u32;
    let counts = [0, 0, 0, times.len() as u32, n, abbrev.len() as u32];
    let mut out = header(counts);
    out.extend(block(false));
    if version != 0 {
        out.extend(header(counts));
        out.extend(block(true));
    }
    out.extend_from_slice(footer);
    out
}

const PST: (i32, bool, u8) = (-28800, false, 0);
const PDT: (i32, bool, u8) = (-25200, true, 4);
const ABBR: &[u8] = b"PST\0PDT\0";

fn zone(data: &[u8]) -> Location {
    Location::from_tzdata_at("Test/Zone", data, 0).expect("valid TZif")
}

fn at(loc: &Location, sec: i64) -> (String, i32, bool) {
    let z = loc.lookup(sec);
    (z.name.to_string(), z.offset, z.is_dst)
}

fn footer_zone(footer: &str) -> Location {
    let data = build(
        b'2',
        &[],
        &[],
        &[PST],
        ABBR,
        format!("\n{footer}\n").as_bytes(),
    );
    zone(&data)
}

#[test]
fn version_one_uses_32_bit_data() {
    let data = build(0, &[-100, 0, 1000], &[1, 0, 1], &[PST, PDT], ABBR, b"");
    let loc = zone(&data);
    assert_eq!(loc.name(), "Test/Zone");
    assert_eq!(at(&loc, -101), ("PST".into(), -28800, false));
    assert_eq!(at(&loc, -100), ("PDT".into(), -25200, true));
    assert_eq!(at(&loc, 999), ("PST".into(), -28800, false));
    assert_eq!(at(&loc, i64::MAX), ("PDT".into(), -25200, true));
    let z = loc.lookup(500);
    assert_eq!((z.start, z.end), (0, 1000));
    assert_eq!(loc.lookup(-1000).start, ALPHA);
    assert_eq!(loc.lookup(5000).end, OMEGA);
}

#[test]
fn version_two_and_three_use_64_bit_data_and_footer() {
    let far = 4_000_000_000i64; // 2096
    for version in *b"23" {
        let footer = b"\nPST8PDT,M3.2.0,M11.1.0\n";
        let data = build(
            version,
            &[-3_000_000_000, far],
            &[1, 0],
            &[PST, PDT],
            ABBR,
            footer,
        );
        let loc = zone(&data);
        assert_eq!(loc.extend(), "PST8PDT,M3.2.0,M11.1.0");
        // Before the first transition: the first non-DST zone.
        assert_eq!(at(&loc, -3_000_000_001).0, "PST");
        assert_eq!(at(&loc, -3_000_000_000).0, "PDT");
        // After the last transition the footer decides (2128).
        let summer = utc(2128, 7, 1, 0, 0, 0);
        assert_eq!(at(&loc, summer), ("PDT".into(), -25200, true));
        let winter = utc(2128, 12, 1, 0, 0, 0);
        assert_eq!(at(&loc, winter), ("PST".into(), -28800, false));
        // March 14 2128 is the second Sunday; 02:00 PST is 10:00 UTC.
        let change = utc(2128, 3, 14, 10, 0, 0);
        assert_eq!(at(&loc, change - 1).0, "PST");
        assert_eq!(at(&loc, change).0, "PDT");
        assert_eq!(loc.lookup(change).start, change);
    }
}

#[test]
fn version_two_skips_the_32_bit_block() {
    // The 32-bit block of a v2 file is skipped even when it is nonsense.
    let mut data = build(b'2', &[1_000], &[1], &[PST, PDT], ABBR, b"");
    data[44..48].copy_from_slice(&[0xff; 4]);
    assert_eq!(at(&zone(&data), 2_000).0, "PDT");
}

#[test]
fn first_zone_selection_follows_go() {
    // Zone 0 unused by transitions: it applies before the first one.
    let types = [(-25200, true, 0), (-28800, false, 4)];
    let data = build(b'2', &[0], &[1], &types, b"PDT\0PST\0", b"");
    assert_eq!(at(&zone(&data), -1).0, "PDT");
    // First transition to DST: nearest earlier non-DST zone.
    let types = [PST, (-25200, false, 4), PDT];
    let data = build(b'2', &[0, 10], &[2, 0], &types, b"PST\0MST\0PDT\0", b"");
    assert_eq!(at(&zone(&data), -1).0, "MST");
    // All zones DST: the first zone.
    let data = build(b'2', &[0], &[0], &[PDT, PDT], ABBR, b"");
    assert_eq!(at(&zone(&data), -1), ("PDT".into(), -25200, true));
}

#[test]
fn no_transitions_and_unterminated_abbreviations() {
    let data = build(b'2', &[], &[], &[(19800, false, 0)], b"IST", b"");
    let loc = zone(&data);
    assert_eq!(at(&loc, i64::MIN), ("IST".into(), 19800, false));
    assert_eq!(at(&loc, i64::MAX), ("IST".into(), 19800, false));
    // An empty abbreviation (index at a NUL).
    let data = build(b'2', &[], &[], &[(3600, false, 3)], b"ABC\0", b"");
    let t = time::unix(0, 0).in_location(&zone(&data));
    assert_eq!(t.zone(), ("", 3600));
    assert_eq!(t.to_string(), "1970-01-01 01:00:00 +0100 +0100");
}

#[test]
fn invalid_utf8_abbreviations_are_lossy() {
    let data = build(b'2', &[], &[], &[(0, false, 0)], b"A\xffB\0", b"");
    assert_eq!(at(&zone(&data), 0).0, "A\u{fffd}B");
}

#[test]
fn malformed_headers_and_sections() {
    let good = build(b'2', &[0, 100], &[0, 1], &[PST, PDT], ABBR, b"\nPST8PDT\n");
    assert!(Location::from_tzdata("x", &good).is_ok());
    let malformed = |data: &[u8]| {
        matches!(
            Location::from_tzdata("x", data),
            Err(LocationError::Malformed)
        )
    };
    // Bad magic and versions.
    assert!(malformed(b""));
    assert!(malformed(b"TZif"));
    assert!(malformed(b"TZiF2"));
    for v in [b'1', b'4', b'5', b'Z', 0xff] {
        let mut data = good.clone();
        data[4] = v;
        assert!(malformed(&data), "version {v}");
    }
    // Every truncation inside the data is rejected; truncating the footer
    // only drops it.
    let data_end = good.len() - b"\nPST8PDT\n".len();
    for cut in 0..good.len() {
        let result = Location::from_tzdata("x", &good[..cut]);
        assert_eq!(result.is_ok(), cut >= data_end, "cut {cut}");
    }
    // Zero zones.
    assert!(malformed(&build(b'2', &[], &[], &[], b"", b"")));
    assert!(malformed(&build(0, &[], &[], &[], b"", b"")));
    // Transition index out of range.
    assert!(malformed(&build(b'2', &[0], &[2], &[PST, PDT], ABBR, b"")));
    // Abbreviation index out of range (== length).
    assert!(malformed(&build(
        b'2',
        &[],
        &[],
        &[(0, false, 8)],
        ABBR,
        b""
    )));
}

#[test]
fn oversized_counts_fail_without_allocating() {
    let good = build(b'2', &[0], &[0], &[PST], ABBR, b"");
    let second = 44 + 5 + 6 + ABBR.len();
    for base in [20, second + 20] {
        for field in 0..6 {
            for value in [u32::MAX, 0x7fff_ffff, 1 << 28] {
                let mut data = good.clone();
                let at = base + 4 * field;
                data[at..at + 4].copy_from_slice(&value.to_be_bytes());
                assert!(
                    matches!(
                        Location::from_tzdata("x", &data),
                        Err(LocationError::Malformed)
                    ),
                    "field {field} at {at} = {value}"
                );
            }
        }
    }
    // Go caps only the files it reads, not in-memory data: a huge input is
    // judged by its content, and trailing bytes after the TZif data are ignored.
    let huge = vec![0u8; MAX_TZDATA_LEN + 1];
    assert!(matches!(
        Location::from_tzdata("big", &huge),
        Err(LocationError::Malformed)
    ));
    let mut padded = build(0, &[-100, 0, 1000], &[1, 0, 1], &[PST, PDT], ABBR, b"");
    padded.resize(MAX_TZDATA_LEN + 1, 0);
    let loc = zone(&padded);
    assert_eq!(at(&loc, 999), ("PST".into(), -28800, false));
}

#[test]
fn footer_framing_and_invalid_rules() {
    // Footers need a leading and trailing newline and at least one byte.
    for (footer, extend) in [
        (&b"\nEST5\n"[..], "EST5"),
        (b"EST5\n", ""),
        (b"\nEST5", ""),
        (b"\n\n", ""),
        (b"\nA\nB\n", "A\nB"),
    ] {
        let data = build(b'2', &[0], &[0], &[PST], ABBR, footer);
        assert_eq!(zone(&data).extend(), extend);
    }
    // Invalid rules load fine and fall back to the last transition's zone.
    for bad in [
        "AB5",
        "ABC",
        "ABC+",
        "ABC169",
        "ABC5:60",
        "<ABC",
        "ABC5DEF,M3.2.0",
        "ABC5DEF,M13.1.0,M11.1.0",
        "ABC5DEF,M3.6.0,M11.1.0",
        "ABC5DEF,M3.2.7,M11.1.0",
        "ABC5DEF,J0,J365",
        "ABC5DEF,366,0",
        "ABC5DEF,M3.2.0,M11.1.0x",
        "ABC5DEF6x",
        "ABC5DEF,M3.2.0/169,M11.1.0",
    ] {
        let loc = footer_zone(bad);
        assert_eq!(at(&loc, utc(2100, 7, 1, 0, 0, 0)).0, "PST", "{bad}");
    }
    // A footer without DST ignores anything after a comma, as Go does.
    assert_eq!(
        at(&footer_zone("ABC5,garbage"), 0),
        ("ABC".into(), -18000, false)
    );
}

#[test]
fn posix_names_and_offsets() {
    let loc = footer_zone("<+0330>-3:30");
    assert_eq!(at(&loc, 0), ("+0330".into(), 12600, false));
    let loc = footer_zone("<>5");
    assert_eq!(at(&loc, 0), ("".into(), -18000, false));
    let loc = footer_zone("ABC+167:59:59");
    assert_eq!(at(&loc, 0).1, -(167 * 3600 + 59 * 60 + 59));
    // DST defaults to one hour ahead and the US rules.
    let loc = footer_zone("EST5EDT");
    assert_eq!(
        at(&loc, utc(2030, 7, 1, 0, 0, 0)),
        ("EDT".into(), -14400, true)
    );
    // tzcode accepts ';' before the first rule, but as in Go only after an
    // explicit DST offset; otherwise ';' is parsed as an offset and fails.
    let loc = footer_zone("EST5EDT4;M3.2.0,M11.1.0");
    assert_eq!(at(&loc, utc(2030, 7, 1, 0, 0, 0)).0, "EDT");
    let loc = footer_zone("EST5EDT;M3.2.0,M11.1.0");
    assert_eq!(at(&loc, utc(2030, 7, 1, 0, 0, 0)).0, "PST");
}

#[test]
fn julian_and_zero_based_day_rules() {
    // Jn never counts February 29: J60 is March 1 in leap years.
    let loc = footer_zone("AAA0BBB,J60/0,J300/0");
    assert_eq!(at(&loc, utc(2024, 2, 29, 23, 59, 59)).0, "AAA");
    assert_eq!(at(&loc, utc(2024, 3, 1, 0, 0, 0)).0, "BBB");
    assert_eq!(at(&loc, utc(2023, 3, 1, 0, 0, 0)).0, "BBB");
    // n is zero-based and counts February 29: 59 is Feb 29 in 2024.
    let loc = footer_zone("AAA0BBB,59/0,300/0");
    assert_eq!(at(&loc, utc(2024, 2, 29, 0, 0, 0)).0, "BBB");
    assert_eq!(at(&loc, utc(2024, 2, 28, 23, 59, 59)).0, "AAA");
    assert_eq!(at(&loc, utc(2023, 3, 1, 0, 0, 0)).0, "BBB");
    // DST from Jan 1 to Dec 31 25:00 (an over-24h time) is all-year DST.
    let loc = footer_zone("EST5EDT,0/0,J365/25");
    assert_eq!(at(&loc, utc(2030, 1, 1, 5, 0, 0)).0, "EDT");
    assert_eq!(at(&loc, utc(2030, 12, 31, 23, 0, 0)).0, "EDT");
}

#[test]
fn month_week_day_rules() {
    let loc = footer_zone("CET-1CEST,M3.5.0,M10.5.0/3");
    // Week 5 means the last Sunday: 2030-03-31 and 2030-10-27.
    let start = utc(2030, 3, 31, 1, 0, 0);
    assert_eq!(at(&loc, start - 1), ("CET".into(), 3600, false));
    assert_eq!(at(&loc, start), ("CEST".into(), 7200, true));
    let end = utc(2030, 10, 27, 1, 0, 0);
    assert_eq!(at(&loc, end - 1).0, "CEST");
    assert_eq!(at(&loc, end).0, "CET");
    // Negative transition times (version 3): Greenland's -2 and -1.
    let loc = footer_zone("<-02>2<-01>,M3.5.0/-1,M10.5.0/0");
    let start = utc(2030, 3, 31, 1, 0, 0);
    assert_eq!(at(&loc, start - 1).0, "-02");
    assert_eq!(at(&loc, start).0, "-01");
}

#[test]
fn southern_hemisphere_swaps_labels() {
    let loc = footer_zone("AEST-10AEDT,M10.1.0,M4.1.0/3");
    assert_eq!(
        at(&loc, utc(2030, 1, 15, 0, 0, 0)),
        ("AEDT".into(), 39600, true)
    );
    assert_eq!(
        at(&loc, utc(2030, 7, 15, 0, 0, 0)),
        ("AEST".into(), 36000, false)
    );
    // 2030-10-06 02:00 AEST is 2030-10-05 16:00 UTC.
    let start = utc(2030, 10, 5, 16, 0, 0);
    assert_eq!(at(&loc, start - 1).0, "AEST");
    assert_eq!(at(&loc, start).0, "AEDT");
}

#[test]
fn go_load_cache_is_reproduced() {
    // Unsorted transitions: Go caches the last entry valid for "now" and
    // answers every later instant from it.
    let data = build(b'2', &[5, 3, 9, 1], &[0, 1, 0, 1], &[PST, PDT], ABBR, b"");
    let cached = Location::from_tzdata_at("x", &data, 1_000).unwrap();
    let z = cached.lookup(2);
    assert_eq!((z.name, z.start, z.end), ("PDT", 1, OMEGA));
    let uncached = Location::from_tzdata_at("x", &data, -1_000).unwrap();
    assert_eq!(uncached.lookup(2).name, "PST");
}

#[test]
fn time_display_and_date() {
    let la = load_location_from(ZIP, "America/Los_Angeles").unwrap();
    let t = time::unix(1_300_000_000, 5_000_000).in_location(&la);
    assert_eq!(t.to_string(), "2011-03-12 23:06:40.005 -0800 PST");
    assert_eq!(t.zone(), ("PST", -28800));
    assert!(!t.is_dst());
    assert_eq!(t.utc().to_string(), "2011-03-13 07:06:40.005 +0000 UTC");
    let dt = t.to_date_time().unwrap();
    assert_eq!(
        dt.format_rfc3339().unwrap(),
        "2011-03-12T23:06:40.005-08:00"
    );
    // Local mean time before 1883 prints whole minutes, as Go does.
    let old = time::unix(-3_000_000_000, 0).in_location(&la);
    assert_eq!(old.to_string(), "1874-12-07 10:47:02 -0752 LMT");
    // Gap: 02:15 does not exist on 2011-03-13; Go yields 01:15 PST.
    let gap = time::date(2011, Month(3), 13, 2, 15, 0, 0, &la);
    assert_eq!(gap.to_string(), "2011-03-13 01:15:00 -0800 PST");
    // Overlap: 01:15 on 2011-11-06 happens twice; Go picks PDT.
    let overlap = time::date(2011, Month(11), 6, 1, 15, 0, 0, &la);
    assert_eq!(overlap.to_string(), "2011-11-06 01:15:00 -0700 PDT");
    // Normalization: October 32 is November 1.
    let norm = time::date(2011, Month(10), 32, 24, -1, 60, -1, &Location::utc());
    assert_eq!(norm.to_string(), "2011-11-01 23:59:59.999999999 +0000 UTC");
    assert_eq!(time::unix(0, -1).unix(), -1);
    assert_eq!(
        time::unix(-62_198_755_200, 0).utc().to_string(),
        "-0001-01-01 00:00:00 +0000 UTC"
    );
    let bounds = time::unix(1_300_000_000, 0).in_location(&la).zone_bounds();
    // Go's archive ends LA's transitions in 2007; footer periods are exact
    // at transitions but start at the year start (2011-01-01), as in Go.
    assert_eq!(
        (bounds.0.unix(), bounds.1.unix()),
        (1_293_840_000, 1_300_010_400)
    );
    let fixed = time::unix(0, 0).in_location(&Location::fixed("X", 60));
    let (start, end) = fixed.zone_bounds();
    assert!(start.is_zero() && end.is_zero());
}

#[test]
fn fixed_and_utc_locations() {
    let utc = Location::utc();
    assert_eq!(utc.name(), "UTC");
    let z = utc.lookup(123);
    assert_eq!((z.name, z.offset, z.start, z.end), ("UTC", 0, ALPHA, OMEGA));
    let fixed = Location::fixed("", 5 * 3600 + 30 * 60);
    let t = time::unix(0, 0).in_location(&fixed);
    assert_eq!(t.to_string(), "1970-01-01 05:30:00 +0530 +0530");
    assert_eq!(fixed.lookup_name("", 0), Some(19800));
    let la = load_location_from(ZIP, "America/Los_Angeles").unwrap();
    assert_eq!(la.lookup_name("PDT", 1_310_000_000), Some(-25200));
    assert_eq!(la.lookup_name("XYZ", 0), None);
}

#[test]
fn name_validation() {
    for bad in [
        "..",
        "a..b",
        "../etc/passwd",
        "America/../UTC",
        "/etc/localtime",
        "\\UTC",
    ] {
        assert!(matches!(
            validate_location_name(bad),
            Err(LocationError::InvalidName)
        ));
        assert!(matches!(
            load_location_with(bad, ZIP),
            Err(LocationError::InvalidName)
        ));
        assert!(matches!(
            load_location_from(ZIP, bad),
            Err(LocationError::InvalidName)
        ));
    }
    for good in [".", "a.b", "America/New_York", "a\\b", "x/"] {
        assert!(validate_location_name(good).is_ok(), "{good}");
    }
    assert_eq!(load_location_with("", "").unwrap().name(), "UTC");
    assert_eq!(load_location_with("UTC", "").unwrap().name(), "UTC");
    assert_eq!(
        LocationError::InvalidName.to_string(),
        "time: invalid location name"
    );
}

#[test]
fn zoneinfo_zip_source() {
    let ny = load_location_with("America/New_York", ZIP).unwrap();
    assert_eq!(ny.name(), "America/New_York");
    assert_eq!(ny.extend(), "EST5EDT,M3.2.0,M11.1.0");
    assert!(matches!(
        load_location_from(ZIP, "Nowhere/Zone"),
        Err(LocationError::UnknownZone(name)) if name == "Nowhere/Zone"
    ));
    let bytes = std::fs::read(ZIP).unwrap();
    assert!(tzdata_from_zip(&bytes, "Europe/Paris").unwrap().is_some());
    assert!(tzdata_from_zip(&bytes, "Europe/Pari").unwrap().is_none());
    // Corrupt containers are errors, never panics.
    for cut in [0, 10, 22, bytes.len() - 1, bytes.len() / 2] {
        assert!(matches!(
            tzdata_from_zip(&bytes[..cut], "Europe/Paris"),
            Err(LocationError::CorruptZip(_))
        ));
    }
    // Central directory pointing past the end.
    let mut bad = bytes.clone();
    let n = bad.len();
    bad[n - 6..n - 2].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        tzdata_from_zip(&bad, "Europe/Paris"),
        Err(LocationError::CorruptZip(_))
    ));
}

/// A one-member zip with the given method, as Go's walker reads it.
fn tiny_zip(name: &str, method: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&[20, 0, 0, 0]);
    out.extend_from_slice(&method.to_le_bytes());
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(data);
    let dir = out.len();
    out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    out.extend_from_slice(&[20, 0, 20, 0, 0, 0]);
    out.extend_from_slice(&method.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0; 12]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    let size = out.len() - dir;
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&(dir as u32).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rust-stdlib-tzif-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn stored_only_members_and_directories() {
    let blob = build(b'2', &[], &[], &[(3600, false, 0)], b"ONE\0", b"");
    let zip = tiny_zip("Test/One", 0, &blob);
    let found = tzdata_from_zip(&zip, "Test/One").unwrap().unwrap();
    assert_eq!(found, blob);
    let compressed = tiny_zip("Test/One", 8, &blob);
    assert!(matches!(
        tzdata_from_zip(&compressed, "Test/One"),
        Err(LocationError::UnsupportedCompression { .. })
    ));

    let dir = temp_dir("dir");
    std::fs::create_dir_all(dir.join("Test")).unwrap();
    std::fs::write(dir.join("Test/One"), &blob).unwrap();
    std::fs::write(dir.join("Test/Bad"), b"TZif2").unwrap();
    std::fs::write(dir.join("one.zip"), &zip).unwrap();
    let loc = load_location_from(&dir, "Test/One").unwrap();
    assert_eq!(at(&loc, 0), ("ONE".into(), 3600, false));
    assert!(matches!(
        load_location_from(&dir, "Test/Bad"),
        Err(LocationError::Malformed)
    ));
    // A directory is a read error, not "unknown", as in Go.
    assert!(matches!(
        load_location_from(&dir, "Test"),
        Err(LocationError::Io(_))
    ));
    let zip_path = dir.join("one.zip");
    let loc = load_location_with("Test/One", zip_path.to_str().unwrap()).unwrap();
    assert_eq!(loc.name(), "Test/One");
    // ZONEINFO errors other than "not found" are reported when nothing else
    // has the zone.
    let bad = load_location_with("Test/Bad", dir.to_str().unwrap()).unwrap_err();
    assert!(matches!(bad, LocationError::Malformed));

    // Local from an absolute TZ path keeps the path as its name
    // (`local_for_tz` implements Go's zoneinfo_unix.go rules).
    #[cfg(unix)]
    {
        let path = dir.join("Test/One");
        let path = path.to_str().unwrap();
        assert_eq!(local_for_tz(Some(path)).name(), path);
        assert_eq!(local_for_tz(Some(&format!(":{path}"))).name(), path);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn local_falls_back_to_utc() {
    for tz in ["", "UTC", ":", ":/nonexistent/zone", "Nowhere/Zone", "/"] {
        let loc = local_for_tz(Some(tz));
        assert_eq!(loc.name(), "UTC", "{tz:?}");
        assert_eq!(at(&loc, 0), ("UTC".into(), 0, false));
    }
}

#[cfg(feature = "tzdata")]
#[test]
fn embedded_tzdata() {
    use rust_stdlib::time::tzdata;
    assert_eq!(tzdata::IANA_VERSION, "2026c");
    assert_eq!(tzdata::ZONEINFO_ZIP.len(), 408_467);
    assert_eq!(tzdata::ZONEINFO_ZIP, std::fs::read(ZIP).unwrap().as_slice());
    let data = tzdata::lookup("Pacific/Auckland").unwrap().unwrap();
    let loc = Location::from_tzdata("Pacific/Auckland", &data).unwrap();
    assert_eq!(loc.extend(), "NZST-12NZDT,M9.5.0,M4.1.0/3");
    assert!(tzdata::lookup("Nowhere/Zone").unwrap().is_none());
    // With no ZONEINFO, a zone resolves from the system or embedded data.
    assert_eq!(
        load_location_with("Pacific/Auckland", "").unwrap().extend(),
        "NZST-12NZDT,M9.5.0,M4.1.0/3"
    );
    // Local falls back to embedded data for zone names.
    assert_eq!(
        local_for_tz(Some("Pacific/Auckland")).name(),
        "Pacific/Auckland"
    );
}
