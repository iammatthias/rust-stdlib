//! Ports of Go's `uuid` tests (`uuid_test.go`). Go runs the clock tests in
//! `testing/synctest` bubbles with virtual time; these check the wall clock
//! by reading it before and after each call, without sleeping or assuming a
//! particular scheduling.
use rust_stdlib::uuid::{self, UUID};
use std::time::{SystemTime, UNIX_EPOCH};

fn version(u: &UUID) -> u8 {
    u.0[6] >> 4
}

fn variant(u: &UUID) -> u8 {
    u.0[8] >> 6
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[test]
fn new_versions_and_variants() {
    type Generator = fn() -> UUID;
    let cases: [(&str, Generator, u8); 3] = [
        ("New", uuid::new, 4),
        ("NewV4", uuid::new_v4, 4),
        ("NewV7", uuid::new_v7, 7),
    ];
    for (name, newf, want_version) in cases {
        let u = newf();
        assert_eq!(version(&u), want_version, "{name}: version");
        assert_eq!(variant(&u), 0b10, "{name}: variant");
    }
}

#[test]
fn new_v7_millis() {
    // The unix_ts_ms field of a UUIDv7 is the wall-clock millisecond at
    // generation, so it lies between readings taken just before and just
    // after the call. The generator also moves its counter one 1/4096 ms
    // unit ahead whenever UUIDs are issued within the same millisecond. The
    // collision test in this binary issues about 37k UUIDs on another thread,
    // which can leave the counter up to 9 ms ahead of the clock, so the upper
    // bound allows for that drift. Successive UUIDs must still increase.
    const MAX_COUNTER_DRIFT_MS: u64 = 10;
    let mut prev: Option<UUID> = None;
    for _ in 0..4 {
        let before = unix_millis();
        let u = uuid::new_v7();
        let after = unix_millis();
        let got = u64::from_be_bytes(u.0[..8].try_into().unwrap()) >> 16;
        assert!(
            got >= before && got <= after + MAX_COUNTER_DRIFT_MS,
            "NewV7() = {u}; millis = {got}, want within [{before}, {after} + {MAX_COUNTER_DRIFT_MS}]"
        );
        assert_eq!(version(&u), 7, "NewV7() = {u}: version");
        assert_eq!(variant(&u), 0b10, "NewV7() = {u}: variant");
        if let Some(prev) = prev {
            assert_eq!(
                u.compare(prev),
                1,
                "NewV7 returned UUIDs out of order:\nprevious: {prev}\n current: {u}"
            );
        }
        prev = Some(u);
    }
}

#[test]
fn new_v7_collision() {
    // UUIDv7s generated at the same instant do not collide and are
    // monotonically increasing. Enough iterations to overflow the fractional
    // millisecond component several times.
    let mut last = uuid::new_v7();
    for _ in 0..3 {
        for _ in 0..(1 << 12) * 3 {
            let u = uuid::new_v7();
            assert_eq!(
                u.compare(last),
                1,
                "NewV7 returned UUIDs out of order:\nprevious: {last}\n current: {u}"
            );
            last = u;
        }
    }
}

#[test]
fn new_v4_is_random() {
    let a = uuid::new_v4();
    let b = uuid::new_v4();
    assert_ne!(a, b);
}

#[test]
fn encode() {
    let u = UUID([
        0xf8, 0x1d, 0x4f, 0xae, 0x7d, 0xec, 0x11, 0xd0, 0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e, 0x6b,
        0xf6,
    ]);
    let want = "f81d4fae-7dec-11d0-a765-00a0c91e6bf6";
    assert_eq!(u.to_string(), want, "u.String()");
    assert_eq!(u.marshal_text(), want.as_bytes(), "u.MarshalText()");
    let mut appended = b"urn:uuid:".to_vec();
    u.append_text(&mut appended);
    assert_eq!(
        appended,
        format!("urn:uuid:{want}").as_bytes(),
        "u.AppendText"
    );
}

#[test]
fn unmarshal_text() {
    let mut got = UUID::default();
    got.unmarshal_text(b"f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
        .unwrap();
    let want = UUID([
        0xf8, 0x1d, 0x4f, 0xae, 0x7d, 0xec, 0x11, 0xd0, 0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e, 0x6b,
        0xf6,
    ]);
    assert_eq!(got, want);
}

#[test]
fn parse_success() {
    let u1 = UUID([
        0xf8, 0x1d, 0x4f, 0xae, 0x7d, 0xec, 0x11, 0xd0, 0xa7, 0x65, 0x00, 0xa0, 0xc9, 0x1e, 0x6b,
        0xf6,
    ]);
    let cases = [
        ("00000000-0000-0000-0000-000000000000", uuid::nil()),
        ("ffffffff-ffff-ffff-ffff-ffffffffffff", uuid::max()),
        ("f81d4fae-7dec-11d0-a765-00a0c91e6bf6", u1),
        ("F81D4FAE-7DEC-11D0-A765-00A0C91E6BF6", u1),
        ("f81d4fae7dec11d0a76500a0c91e6bf6", u1),
        ("{f81d4fae-7dec-11d0-a765-00a0c91e6bf6}", u1),
        ("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6", u1),
    ];
    for (s, want) in cases {
        match uuid::parse(s) {
            Ok(u) => assert_eq!(u, want, "Parse({s:?})"),
            Err(e) => panic!("Parse({s:?}) = _, {e}; want success"),
        }
    }
}

#[test]
fn parse_errors() {
    let cases = [
        "",
        "0000000000000-0000-0000-000000000000",
        "00000000-000000000-0000-000000000000",
        "00000000-0000-000000000-000000000000",
        "00000000-0000-0000-00000000000000000",
        "00000000-0000-0000-0000-00000000000",
        "x0000000-0000-0000-0000-000000000000",
        "00000000-x000-0000-0000-000000000000",
        "00000000-0000-x000-0000-000000000000",
        "00000000-0000-0000-x000-000000000000",
        "00000000-0000-0000-0000-x00000000000",
        "{x0000000-0000-0000-0000-000000000000}",
        "urn:uuid:x000000-0000-0000-0000-000000000000",
        "x0000000000000000000000000000000",
        // Some parsers permit hyphens in non-standard locations,
        // but we currently do not.
        "0000-0000-0000-0000-0000-0000-0000-0000",
        // Combinations of variant encodings that we could choose to parse,
        // but currently do not.
        "{00000000000000000000000000000000}",
        "{urn:uuid:00000000-0000-0000-0000-000000000000}",
        "urn:uuid:00000000000000000000000000000000",
    ];
    for s in cases {
        let err = uuid::parse(s).expect_err(&format!("Parse({s:?}) should fail"));
        assert_eq!(err.to_string(), "invalid uuid");
    }
}

#[test]
fn unmarshal_text_leaves_value_on_error() {
    let mut u = UUID([7; 16]);
    assert!(u.unmarshal_text(b"not a uuid").is_err());
    assert_eq!(u, UUID([7; 16]));
}

#[test]
fn must_parse_panics_on_invalid_text() {
    assert_eq!(
        uuid::must_parse("f81d4fae-7dec-11d0-a765-00a0c91e6bf6").to_string(),
        "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"
    );
    assert!(std::panic::catch_unwind(|| uuid::must_parse("nope")).is_err());
}

#[test]
fn compare() {
    let uuids = [
        uuid::nil(),
        uuid::must_parse("f81d4fae-7dec-11d0-a765-00a0c91e6bf6"),
        uuid::max(),
    ];
    for (i, u) in uuids.iter().enumerate() {
        assert_eq!(u.compare(*u), 0, "{u}.Compare(itself)");
        if i == 0 {
            continue;
        }
        let prev = uuids[i - 1];
        assert_eq!(u.compare(prev), 1, "{u}.Compare({prev})");
        assert_eq!(prev.compare(*u), -1, "{prev}.Compare({u})");
    }
}

#[test]
fn nil_and_max() {
    assert_eq!(
        uuid::nil().to_string(),
        "00000000-0000-0000-0000-000000000000"
    );
    assert_eq!(
        uuid::max().to_string(),
        "ffffffff-ffff-ffff-ffff-ffffffffffff"
    );
    assert_eq!(UUID::default(), uuid::nil());
}
