//! Go's `uuid` package: UUIDs as specified in RFC 9562.
//!
//! ```
//! use rust_stdlib::uuid::{self, UUID};
//!
//! let id = uuid::parse("urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6")?;
//! assert_eq!(id.to_string(), "f81d4fae-7dec-11d0-a765-00a0c91e6bf6");
//! assert_eq!(uuid::parse(&id.to_string())?, id);
//! assert_eq!(uuid::new_v4().0[6] >> 4, 4);
//! assert_eq!(uuid::max().compare(uuid::nil()), 1);
//! # Ok::<(), uuid::ParseError>(())
//! ```
//!
//! Random components come from `/dev/urandom`, the operating-system generator
//! that the Rust standard library reads for its own randomness. Without a
//! `std`-only operating-system source (on platforms other than Unix) the
//! generators panic, as Go's `crypto/rand` crashes the program when it
//! cannot read; there is no weaker fallback.

use std::fmt;
use std::io::{self, Read};
use std::sync::{Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

/// A Universally Unique Identifier as specified in RFC 9562.
///
/// UUIDs compare with `==`, and their order is the big-endian byte order of
/// RFC 9562 section 6.11 (see [`UUID::compare`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UUID(pub [u8; 16]);

/// The error returned by [`parse`] and [`UUID::unmarshal_text`] for an invalid
/// UUID string (Go's `invalid uuid`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError;

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid uuid")
    }
}

impl std::error::Error for ParseError {}

/// Parses `s` as a UUID. It accepts the forms
///
/// ```text
/// f81d4fae-7dec-11d0-a765-00a0c91e6bf6
/// {f81d4fae-7dec-11d0-a765-00a0c91e6bf6}
/// urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6
/// f81d4fae7dec11d0a76500a0c91e6bf6
/// ```
///
/// Alphabetic characters in the hexadecimal digits may be any case.
pub fn parse(s: &str) -> Result<UUID, ParseError> {
    let mut u = UUID::default();
    u.unmarshal_text(s.as_bytes())?;
    Ok(u)
}

/// Returns the UUID represented by `s`. It panics if `s` is not a valid
/// string representation of a UUID as defined by [`parse`].
pub fn must_parse(s: &str) -> UUID {
    match parse(s) {
        Ok(u) => u,
        Err(err) => panic!("{err}"),
    }
}

/// Returns a new UUID. At this time it is equivalent to [`new_v4`].
pub fn new() -> UUID {
    new_v4()
}

/// Returns the Nil UUID `00000000-0000-0000-0000-000000000000`, defined in
/// RFC 9562 section 5.9. It is not the same as an absent value.
pub fn nil() -> UUID {
    UUID::default()
}

/// Returns the Max UUID `ffffffff-ffff-ffff-ffff-ffffffffffff`, defined in
/// RFC 9562 section 5.10.
pub fn max() -> UUID {
    UUID([0xff; 16])
}

/// Returns a new version 4 UUID: 122 bits of random data.
///
/// # Panics
///
/// Panics if the operating system's random source cannot be read.
pub fn new_v4() -> UUID {
    let mut u = [0u8; 16];
    fill_random(&mut u);
    set_version(&mut u, 4);
    set_variant(&mut u, 0b10);
    UUID(u)
}

/// Last (seconds, timestamp) produced by [`new_v7`]: the Unix seconds of the
/// last UUID and its 60-bit timestamp.
static V7_LAST: Mutex<(u64, u64)> = Mutex::new((0, 0));

/// Returns a new version 7 UUID: a timestamp in the most significant 48 bits
/// and at least 62 bits of random data.
///
/// UUIDs from this function sort in increasing order, except when the system
/// clock moves backwards. The sub-millisecond part of the time is stored in
/// the `rand_a` field, as RFC 9562 permits.
///
/// # Panics
///
/// Panics if the operating system's random source cannot be read.
pub fn new_v7() -> UUID {
    let mut last = V7_LAST.lock().unwrap_or_else(PoisonError::into_inner);

    // Generate our 60-bit timestamp: 48 bits of millisecond-resolution,
    // followed by 12 bits of 1/4096-millisecond resolution.
    let (secs, nanos) = unix_now();
    let msecs = nanos / 1_000_000;
    let frac = nanos - 1_000_000 * msecs;
    let mut timestamp = 1000u64.wrapping_mul(secs).wrapping_add(msecs) << 12; // ms shifted into position
    timestamp = timestamp.wrapping_add(frac * 4096 / 1_000_000); // ns converted to 1/4096-ms units

    let (last_secs, last_timestamp) = &mut *last;
    if *last_secs > secs {
        // Time has gone backwards. This presumably indicates the system clock
        // has changed, so previously generated UUIDs are ignored.
    } else if timestamp <= *last_timestamp {
        // This timestamp is the same as a previously generated UUID. Use one
        // 1/4096 millisecond later to keep the UUIDs in order.
        timestamp = last_timestamp.wrapping_add(1);
    }
    *last_secs = secs;
    *last_timestamp = timestamp;
    drop(last);

    // Insert a gap for the 4 bits of the ver field into the timestamp.
    let hibits = ((timestamp << 4) & 0xffff_ffff_ffff_0000) | (timestamp & 0x0ffff);

    let mut u = [0u8; 16];
    u[0..8].copy_from_slice(&hibits.to_be_bytes());
    fill_random(&mut u[8..]);
    set_version(&mut u, 7);
    set_variant(&mut u, 0b10);
    UUID(u)
}

/// Fills `buf` from the operating system's random source.
fn fill_random(buf: &mut [u8]) {
    let result = os_random().and_then(|mut file| file.read_exact(buf));
    if let Err(err) = result {
        // Go: crypto/rand.Read crashes the program irrecoverably.
        panic!("crypto/rand: failed to read random data (see https://go.dev/issue/66821): {err}");
    }
}

#[cfg(unix)]
fn os_random() -> io::Result<std::fs::File> {
    std::fs::File::open("/dev/urandom")
}

#[cfg(not(unix))]
fn os_random() -> io::Result<std::fs::File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no std-only operating-system random source on this platform",
    ))
}

/// Returns the Unix time as Go's `time.Now()` reports it: whole seconds
/// (negative before 1970) and a nanosecond part in `0..1_000_000_000`.
fn unix_now() -> (u64, u64) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs(), u64::from(d.subsec_nanos())),
        Err(before) => {
            let d = before.duration();
            let (secs, nanos) = (d.as_secs() as i64, d.subsec_nanos());
            if nanos == 0 {
                (secs.wrapping_neg() as u64, 0)
            } else {
                (
                    secs.wrapping_neg().wrapping_sub(1) as u64,
                    u64::from(1_000_000_000 - nanos),
                )
            }
        }
    }
}

fn set_version(u: &mut [u8; 16], version: u8) {
    u[6] = (u[6] & 0b0000_1111) | (version << 4);
}

fn set_variant(u: &mut [u8; 16], variant: u8) {
    u[8] = (u[8] & 0b0011_1111) | (variant << 6);
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decodes `src` (two hex digits per byte of `dst`) into `dst`.
fn decode_hex(src: &[u8], dst: &mut [u8]) -> Result<(), ParseError> {
    for (out, pair) in dst.iter_mut().zip(src.chunks_exact(2)) {
        let hi = hex_digit(pair[0]).ok_or(ParseError)?;
        let lo = hex_digit(pair[1]).ok_or(ParseError)?;
        *out = (hi << 4) | lo;
    }
    Ok(())
}

impl UUID {
    /// Appends the lowercase hyphenated form of `self` to `b`. The encoding is
    /// the same as [`ToString::to_string`] (Go's `AppendText` never fails).
    pub fn append_text(&self, b: &mut Vec<u8>) {
        b.extend_from_slice(self.to_string().as_bytes());
    }

    /// Returns the lowercase hyphenated form of `self` as bytes.
    pub fn marshal_text(&self) -> Vec<u8> {
        self.to_string().into_bytes()
    }

    /// Sets `self` from text in a form accepted by [`parse`]. On error `self`
    /// is unchanged.
    pub fn unmarshal_text(&mut self, b: &[u8]) -> Result<(), ParseError> {
        let mut b = b;
        let mut dst = [0u8; 16];
        match b.len() {
            // urn:uuid:00000000-0000-0000-0000-000000000000
            45 => b = b.strip_prefix(b"urn:uuid:".as_slice()).unwrap_or(b),
            // {00000000-0000-0000-0000-000000000000}
            38 => {
                b = b.strip_prefix(b"{".as_slice()).unwrap_or(b);
                b = b.strip_suffix(b"}".as_slice()).unwrap_or(b);
            }
            // 00000000000000000000000000000000
            32 => {
                decode_hex(b, &mut dst)?;
                self.0 = dst;
                return Ok(());
            }
            _ => {}
        }
        // 00000000-0000-0000-0000-000000000000
        if b.len() != 36 {
            return Err(ParseError);
        }
        if b[8] != b'-' || b[13] != b'-' || b[18] != b'-' || b[23] != b'-' {
            return Err(ParseError);
        }
        decode_hex(&b[0..8], &mut dst[0..4])?;
        decode_hex(&b[9..13], &mut dst[4..6])?;
        decode_hex(&b[14..18], &mut dst[6..8])?;
        decode_hex(&b[19..23], &mut dst[8..10])?;
        decode_hex(&b[24..36], &mut dst[10..16])?;
        self.0 = dst;
        Ok(())
    }

    /// Compares `self` with `v`, using the big-endian byte order of RFC 9562
    /// section 6.11. It returns -1 if `self` is before `v`, +1 if it is after
    /// and 0 if they are the same.
    pub fn compare(&self, v: UUID) -> isize {
        match self.cmp(&v) {
            std::cmp::Ordering::Less => -1,
            std::cmp::Ordering::Equal => 0,
            std::cmp::Ordering::Greater => 1,
        }
    }
}

impl fmt::Display for UUID {
    /// Writes the lowercase hex-and-dash representation defined in RFC 9562.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let u = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]
        )
    }
}
