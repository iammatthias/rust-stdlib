//! IANA time zones: TZif parsing, POSIX TZ footer rules and Go's
//! `LoadLocation` search order.
//!
//! The parser, zone lookup and TZ-string evaluation port Go's
//! `src/time/zoneinfo.go` and `zoneinfo_read.go` so that offsets,
//! abbreviations and daylight-saving flags agree with Go for every instant.
//! See tzfile(5) and RFC 8536 for the file format.
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, OnceLock};

use super::instant::{days_before, days_in, is_leap, unix_year_yday};

/// Largest TZif input accepted, matching Go's `maxFileSize` for zone files.
///
/// Go applies this limit only when reading whole zone files; in-memory data
/// passed to [`Location::from_tzdata`] and zip members are not capped.
pub const MAX_TZDATA_LEN: usize = 10 << 20;

/// The Unix directories Go searches, in order, after `ZONEINFO`.
pub const PLATFORM_ZONE_SOURCES: [&str; 4] = [
    "/usr/share/zoneinfo/",
    "/usr/share/lib/zoneinfo/",
    "/usr/lib/locale/TZ/",
    "/etc/zoneinfo",
];

/// Start of time for zone bounds, Go's `alpha`.
pub const ALPHA: i64 = i64::MIN;
/// End of time for zone bounds, Go's `omega`.
pub const OMEGA: i64 = i64::MAX;

const SECONDS_PER_DAY: i64 = 86400;
const SECONDS_PER_HOUR: i64 = 3600;

/// Errors from loading or parsing time zone information. Display strings
/// match Go's error text.
#[derive(Debug)]
#[non_exhaustive]
pub enum LocationError {
    /// The name contains `..` or starts with `/` or `\`.
    InvalidName,
    /// No source has a zone with this name.
    UnknownZone(String),
    /// The TZif data is malformed (Go's `errBadData`).
    Malformed,
    /// A zone file exceeds [`MAX_TZDATA_LEN`].
    TooLarge(String),
    /// The zip container is malformed.
    CorruptZip(String),
    /// The zip member is compressed; Go only reads stored members.
    UnsupportedCompression { name: String, source: String },
    /// Reading a zone file failed for a reason other than "not found".
    Io(io::Error),
}

impl fmt::Display for LocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName => f.write_str("time: invalid location name"),
            Self::UnknownZone(name) => write!(f, "unknown time zone {name}"),
            Self::Malformed => f.write_str("malformed time zone information"),
            Self::TooLarge(name) => write!(f, "time: file {name} is too large"),
            Self::CorruptZip(source) => write!(f, "corrupt zip file {source}"),
            Self::UnsupportedCompression { name, source } => {
                write!(f, "unsupported compression for {name} in {source}")
            }
            Self::Io(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for LocationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

/// One local time type: abbreviation, offset east of UTC and DST flag.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ZoneType {
    name: String,
    offset: i32,
    is_dst: bool,
}

#[derive(Debug, Clone, Copy)]
struct ZoneTrans {
    when: i64,
    index: u8,
}

/// The zone in effect at an instant, as returned by [`Location::lookup`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZoneInfo<'a> {
    /// Abbreviation such as `"PST"`; may be empty or numeric like `"+0530"`.
    pub name: &'a str,
    /// Seconds east of UTC.
    pub offset: i32,
    /// Whether daylight saving time is in effect.
    pub is_dst: bool,
    /// First second of this zone period, or [`ALPHA`]. As in Go, periods
    /// derived from the TZ footer are exact only near transitions.
    pub start: i64,
    /// First second after this zone period, or [`OMEGA`].
    pub end: i64,
}

/// A parsed POSIX TZ string (the TZif footer, Go's `extend`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PosixTz {
    std_name: String,
    std_offset: i64,
    dst: Option<PosixDst>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PosixDst {
    name: String,
    offset: i64,
    start: Rule,
    end: Rule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuleKind {
    /// `Jn`: day 1..=365, February 29 never counted.
    Julian,
    /// `n`: zero-based day of year 0..=365.
    DayOfYear,
    /// `Mm.w.d`: day d of week w of month m.
    MonthWeekDay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rule {
    kind: RuleKind,
    day: i64,
    week: i64,
    mon: i64,
    time: i64,
}

#[derive(Debug)]
struct Inner {
    name: String,
    zones: Vec<ZoneType>,
    tx: Vec<ZoneTrans>,
    /// The footer text, kept for inspection.
    extend: String,
    /// The footer parsed once; `None` when absent or when Go's `tzset`
    /// would reject it (lookups then use the last transition).
    rule: Option<PosixTz>,
    /// Go's one-entry lookup cache, filled at load time for "now". It is
    /// part of Go's observable behavior: for unsorted transitions, or when
    /// the footer's period for "now" starts before the last transition, a
    /// cached answer differs from the binary search.
    cache: Option<Cache>,
}

#[derive(Debug, Clone)]
struct Cache {
    start: i64,
    end: i64,
    zone: ZoneType,
}

fn unix_now() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => i64::try_from(e.duration().as_secs()).map_or(i64::MIN, |s| -s),
    }
}

/// A named set of zone rules: Go's `time.Location`.
///
/// Cloning is cheap; the zone data is shared.
#[derive(Clone)]
pub struct Location(Arc<Inner>);

impl fmt::Debug for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Location")
            .field("name", &self.0.name)
            .field("zones", &self.0.zones.len())
            .field("transitions", &self.0.tx.len())
            .field("extend", &self.0.extend)
            .finish()
    }
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.name)
    }
}

/// Big-endian reader that records running out of data, as Go's `dataIO`.
struct DataIo<'a> {
    p: &'a [u8],
    error: bool,
}

impl<'a> DataIo<'a> {
    fn read(&mut self, n: usize) -> &'a [u8] {
        if self.p.len() < n {
            self.p = &[];
            self.error = true;
            return &[];
        }
        let (head, tail) = self.p.split_at(n);
        self.p = tail;
        head
    }
    fn big4(&mut self) -> Option<u32> {
        let p = self.read(4);
        if p.len() < 4 {
            self.error = true;
            return None;
        }
        Some(u32::from_be_bytes([p[0], p[1], p[2], p[3]]))
    }
    fn big8(&mut self) -> Option<u64> {
        let hi = self.big4();
        let lo = self.big4();
        match (hi, lo) {
            (Some(hi), Some(lo)) => Some((u64::from(hi) << 32) | u64::from(lo)),
            _ => {
                self.error = true;
                None
            }
        }
    }
    fn byte(&mut self) -> Option<u8> {
        self.read(1).first().copied().or_else(|| {
            self.error = true;
            None
        })
    }
}

/// Bytes up to the first NUL, decoded lossily (Go keeps raw bytes).
fn byte_string(p: &[u8]) -> String {
    let end = p.iter().position(|&b| b == 0).unwrap_or(p.len());
    String::from_utf8_lossy(&p[..end]).into_owned()
}

/// `count * width` bytes of section data, saturating when that cannot be
/// represented so the read fails like Go's short read.
fn section(count: usize, width: usize) -> usize {
    count.saturating_mul(width)
}

impl Location {
    /// Go's `UTC` location: name `"UTC"`, offset 0, no transitions.
    pub fn utc() -> Self {
        Self::utc_ref().clone()
    }

    pub(crate) fn utc_ref() -> &'static Location {
        static UTC: OnceLock<Location> = OnceLock::new();
        UTC.get_or_init(|| Self::empty("UTC"))
    }

    /// Whether this is Go's `UTC` location (identity, not name).
    pub fn is_utc(&self) -> bool {
        Arc::ptr_eq(&self.0, &Self::utc_ref().0)
    }

    /// Whether this is Go's `Local` location (identity, not name).
    pub fn is_local(&self) -> bool {
        LOCAL.get().is_some_and(|l| Arc::ptr_eq(&self.0, &l.0))
    }

    fn empty(name: &str) -> Self {
        Self(Arc::new(Inner {
            name: name.into(),
            zones: Vec::new(),
            tx: Vec::new(),
            extend: String::new(),
            rule: None,
            cache: None,
        }))
    }

    /// Go's `FixedZone`: always `name` at `offset` seconds east of UTC.
    pub fn fixed(name: &str, offset: i32) -> Self {
        Self(Arc::new(Inner {
            name: name.into(),
            zones: vec![ZoneType {
                name: name.into(),
                offset,
                is_dst: false,
            }],
            tx: vec![ZoneTrans {
                when: ALPHA,
                index: 0,
            }],
            extend: String::new(),
            rule: None,
            cache: None,
        }))
    }

    /// Go's `LoadLocationFromTZData`: parse TZif data (versions 1 to 3, as Go).
    ///
    /// For version 2 and later the 32-bit block is skipped and the 64-bit
    /// block is used. A trailing `\n...\n` footer becomes the POSIX TZ rule
    /// for instants after the last transition; as in Go, an invalid footer
    /// is not an error but is ignored at lookup time. Leap-second records
    /// and the standard/wall and UT/local indicators are read and ignored.
    /// Abbreviations that are not UTF-8 are decoded lossily.
    pub fn from_tzdata(name: &str, data: &[u8]) -> Result<Self, LocationError> {
        Self::from_tzdata_at(name, data, unix_now())
    }

    /// [`Location::from_tzdata`] with an explicit load time. Go caches the
    /// zone in effect when a location is loaded and answers later lookups
    /// in that period from the cache; `now` (Unix seconds) fixes that time
    /// for reproducible results.
    pub fn from_tzdata_at(name: &str, data: &[u8], now: i64) -> Result<Self, LocationError> {
        let mut d = DataIo {
            p: data,
            error: false,
        };
        if d.read(4) != b"TZif" {
            return Err(LocationError::Malformed);
        }
        let p = d.read(16);
        if p.len() != 16 {
            return Err(LocationError::Malformed);
        }
        // Go 1.27 accepts versions 1 to 3 only; version 4 is malformed.
        let version = match p[0] {
            0 => 1,
            b'2' => 2,
            b'3' => 3,
            _ => return Err(LocationError::Malformed),
        };
        // Counts: UT/local indicators, standard/wall indicators, leap
        // seconds, transition times, local time types, abbreviation bytes.
        const NUTC_LOCAL: usize = 0;
        const NSTD_WALL: usize = 1;
        const NLEAP: usize = 2;
        const NTIME: usize = 3;
        const NZONE: usize = 4;
        const NCHAR: usize = 5;
        let mut n = [0usize; 6];
        let read_counts = |d: &mut DataIo<'_>, n: &mut [usize; 6]| -> Option<()> {
            for slot in n.iter_mut() {
                *slot = usize::try_from(d.big4()?).ok()?;
            }
            Some(())
        };
        read_counts(&mut d, &mut n).ok_or(LocationError::Malformed)?;
        let mut is64 = false;
        if version > 1 {
            // Skip the 32-bit block and the second header. Go does not
            // re-check that header's magic or version.
            let skip = [
                section(n[NTIME], 4),
                n[NTIME],
                section(n[NZONE], 6),
                n[NCHAR],
                section(n[NLEAP], 8),
                n[NSTD_WALL],
                n[NUTC_LOCAL],
                4 + 16,
            ]
            .iter()
            .try_fold(0usize, |sum, part| sum.checked_add(*part))
            .unwrap_or(usize::MAX);
            d.read(skip);
            is64 = true;
            read_counts(&mut d, &mut n).ok_or(LocationError::Malformed)?;
        }
        let size = if is64 { 8 } else { 4 };
        let mut txtimes = DataIo {
            p: d.read(section(n[NTIME], size)),
            error: false,
        };
        let txzones = d.read(n[NTIME]);
        let mut zonedata = DataIo {
            p: d.read(section(n[NZONE], 6)),
            error: false,
        };
        let abbrev = d.read(n[NCHAR]);
        d.read(section(n[NLEAP], size + 4));
        d.read(n[NSTD_WALL]);
        d.read(n[NUTC_LOCAL]);
        if d.error {
            return Err(LocationError::Malformed);
        }
        let rest = std::mem::take(&mut d.p);
        let extend_bytes = if rest.len() > 2 && rest[0] == b'\n' && rest[rest.len() - 1] == b'\n' {
            &rest[1..rest.len() - 1]
        } else {
            &[][..]
        };

        if n[NZONE] == 0 {
            return Err(LocationError::Malformed);
        }
        // Every count above is backed by bytes already present in `data`,
        // so these allocations are bounded by the input length.
        let mut zones = Vec::with_capacity(n[NZONE]);
        for _ in 0..n[NZONE] {
            let offset = zonedata.big4().ok_or(LocationError::Malformed)? as i32;
            let is_dst = zonedata.byte().ok_or(LocationError::Malformed)? != 0;
            let index = usize::from(zonedata.byte().ok_or(LocationError::Malformed)?);
            if index >= abbrev.len() {
                return Err(LocationError::Malformed);
            }
            zones.push(ZoneType {
                name: byte_string(&abbrev[index..]),
                offset,
                is_dst,
            });
        }
        let mut tx = Vec::with_capacity(n[NTIME].max(1));
        for &index in txzones {
            let when = if is64 {
                txtimes.big8().ok_or(LocationError::Malformed)? as i64
            } else {
                i64::from(txtimes.big4().ok_or(LocationError::Malformed)? as i32)
            };
            if usize::from(index) >= zones.len() {
                return Err(LocationError::Malformed);
            }
            tx.push(ZoneTrans { when, index });
        }
        if tx.is_empty() {
            // A fake transition covering all time, as for "Etc/GMT0".
            tx.push(ZoneTrans {
                when: ALPHA,
                index: 0,
            });
        }
        let rule = parse_tz(extend_bytes);
        let cache = load_cache(&zones, &tx, rule.as_ref(), now);
        Ok(Self(Arc::new(Inner {
            name: name.into(),
            zones,
            tx,
            extend: String::from_utf8_lossy(extend_bytes).into_owned(),
            rule,
            cache,
        })))
    }

    /// The name given when the location was loaded or created.
    pub fn name(&self) -> &str {
        &self.0.name
    }

    /// The POSIX TZ footer (Go's `extend`), empty when absent.
    pub fn extend(&self) -> &str {
        &self.0.extend
    }

    pub(crate) fn renamed(&self, name: &str) -> Self {
        let inner = &*self.0;
        Self(Arc::new(Inner {
            name: name.into(),
            zones: inner.zones.clone(),
            tx: inner.tx.clone(),
            extend: inner.extend.clone(),
            rule: inner.rule.clone(),
            cache: inner.cache.clone(),
        }))
    }

    /// The zone in effect at `sec` seconds since the Unix epoch (Go's
    /// unexported `Location.lookup`).
    pub fn lookup(&self, sec: i64) -> ZoneInfo<'_> {
        let l = &*self.0;
        if l.zones.is_empty() {
            return ZoneInfo {
                name: "UTC",
                offset: 0,
                is_dst: false,
                start: ALPHA,
                end: OMEGA,
            };
        }
        if let Some(cache) = l.cache.as_ref().filter(|c| c.start <= sec && sec < c.end) {
            return ZoneInfo {
                name: &cache.zone.name,
                offset: cache.zone.offset,
                is_dst: cache.zone.is_dst,
                start: cache.start,
                end: cache.end,
            };
        }
        if l.tx.is_empty() || sec < l.tx[0].when {
            let zone = &l.zones[self.lookup_first_zone()];
            return ZoneInfo {
                name: &zone.name,
                offset: zone.offset,
                is_dst: zone.is_dst,
                start: ALPHA,
                end: l.tx.first().map_or(OMEGA, |t| t.when),
            };
        }
        // Go's binary search for the entry with the largest time <= sec.
        // It does not require sorted transitions, and neither does this.
        let tx = &l.tx;
        let mut end = OMEGA;
        let mut lo = 0usize;
        let mut hi = tx.len();
        while hi - lo > 1 {
            let m = (lo + hi) / 2;
            let lim = tx[m].when;
            if sec < lim {
                end = lim;
                hi = m;
            } else {
                lo = m;
            }
        }
        let zone = &l.zones[usize::from(tx[lo].index)];
        let start = tx[lo].when;
        if lo == tx.len() - 1 {
            if let Some(rule) = &l.rule {
                return rule.evaluate(start, sec);
            }
        }
        ZoneInfo {
            name: &zone.name,
            offset: zone.offset,
            is_dst: zone.is_dst,
            start,
            end,
        }
    }

    /// The zone used before the first transition, following tzcode's
    /// `localtime.c` rules as Go does.
    fn lookup_first_zone(&self) -> usize {
        let l = &*self.0;
        if !l.tx.iter().any(|t| t.index == 0) {
            return 0;
        }
        if let Some(first) = l.tx.first() {
            if l.zones[usize::from(first.index)].is_dst {
                for zi in (0..usize::from(first.index)).rev() {
                    if !l.zones[zi].is_dst {
                        return zi;
                    }
                }
            }
        }
        l.zones.iter().position(|z| !z.is_dst).unwrap_or(0)
    }

    /// Go's `lookupName`: the offset of the zone abbreviation `name` near
    /// the pseudo-Unix time `unix` (local clock read as UTC).
    pub fn lookup_name(&self, name: &str, unix: i64) -> Option<i32> {
        let zones = &self.0.zones;
        for zone in zones.iter().filter(|z| z.name == name) {
            let found = self.lookup(unix.wrapping_sub(i64::from(zone.offset)));
            if found.name == zone.name {
                return Some(found.offset);
            }
        }
        zones.iter().find(|z| z.name == name).map(|z| z.offset)
    }
}

/// Go's load-time cache: the first transition `i` with
/// `tx[i] <= now < tx[i+1]` (or the last one), refined by the footer.
fn load_cache(
    zones: &[ZoneType],
    tx: &[ZoneTrans],
    rule: Option<&PosixTz>,
    now: i64,
) -> Option<Cache> {
    let i =
        (0..tx.len()).find(|&i| tx[i].when <= now && tx.get(i + 1).is_none_or(|t| now < t.when))?;
    let mut cache = Cache {
        start: tx[i].when,
        end: tx.get(i + 1).map_or(OMEGA, |t| t.when),
        zone: zones[usize::from(tx[i].index)].clone(),
    };
    if i + 1 == tx.len() {
        if let Some(rule) = rule {
            let zone = rule.evaluate(cache.start, now);
            cache = Cache {
                start: zone.start,
                end: zone.end,
                zone: ZoneType {
                    name: zone.name.into(),
                    offset: zone.offset,
                    is_dst: zone.is_dst,
                },
            };
        }
    }
    Some(cache)
}

impl PosixTz {
    /// Go's `tzset` evaluation for an instant after the last transition.
    fn evaluate(&self, last_tx: i64, sec: i64) -> ZoneInfo<'_> {
        let Some(dst) = &self.dst else {
            return ZoneInfo {
                name: &self.std_name,
                offset: self.std_offset as i32,
                is_dst: false,
                start: last_tx,
                end: OMEGA,
            };
        };
        let (year, yday) = unix_year_yday(sec);
        // Go uses a truncating remainder here, so instants before 1970 are
        // placed relative to a shifted year start; keep that behavior.
        let ysec = (yday - 1)
            .wrapping_mul(SECONDS_PER_DAY)
            .wrapping_add(sec % SECONDS_PER_DAY);
        let ystart = sec.wrapping_sub(ysec);
        let mut start_sec = rule_time(year, dst.start, self.std_offset);
        let mut end_sec = rule_time(year, dst.end, dst.offset);
        let (mut std_name, mut dst_name) = (self.std_name.as_str(), dst.name.as_str());
        let (mut std_offset, mut dst_offset) = (self.std_offset, dst.offset);
        let (mut std_is_dst, mut dst_is_dst) = (false, true);
        // Southern hemisphere: the labels are swapped, as in Go.
        if end_sec < start_sec {
            std::mem::swap(&mut start_sec, &mut end_sec);
            std::mem::swap(&mut std_name, &mut dst_name);
            std::mem::swap(&mut std_offset, &mut dst_offset);
            std::mem::swap(&mut std_is_dst, &mut dst_is_dst);
        }
        let (name, offset, is_dst, start, end) = if ysec < start_sec {
            (
                std_name,
                std_offset,
                std_is_dst,
                ystart,
                start_sec.wrapping_add(ystart),
            )
        } else if ysec >= end_sec {
            (
                std_name,
                std_offset,
                std_is_dst,
                end_sec.wrapping_add(ystart),
                ystart.wrapping_add(365 * SECONDS_PER_DAY),
            )
        } else {
            (
                dst_name,
                dst_offset,
                dst_is_dst,
                start_sec.wrapping_add(ystart),
                end_sec.wrapping_add(ystart),
            )
        };
        ZoneInfo {
            name,
            offset: offset as i32,
            is_dst,
            start,
            end,
        }
    }
}

/// Parse a POSIX TZ string the way Go's `tzset` does. `None` means Go
/// would report failure and fall back to the last transition's zone.
fn parse_tz(s: &[u8]) -> Option<PosixTz> {
    if s.is_empty() {
        return None;
    }
    let (std_name, s) = tz_name(s)?;
    let (std_offset, s) = tz_offset(s)?;
    // TZ offsets are subtracted from local time to get UTC; ours are added.
    let std_offset = -std_offset;
    if s.is_empty() || s[0] == b',' {
        return Some(PosixTz {
            std_name,
            std_offset,
            dst: None,
        });
    }
    let (dst_name, mut s) = tz_name(s)?;
    let dst_offset = if s.is_empty() || s[0] == b',' {
        std_offset + SECONDS_PER_HOUR
    } else {
        let (offset, rest) = tz_offset(s)?;
        s = rest;
        -offset
    };
    // tzcode's default rules when none are given.
    let s: &[u8] = if s.is_empty() { b",M3.2.0,M11.1.0" } else { s };
    // POSIX requires ','; tzcode also accepts ';'.
    if s[0] != b',' && s[0] != b';' {
        return None;
    }
    let (start, s) = tz_rule(&s[1..])?;
    if s.first() != Some(&b',') {
        return None;
    }
    let (end, s) = tz_rule(&s[1..])?;
    if !s.is_empty() {
        return None;
    }
    Some(PosixTz {
        std_name,
        std_offset,
        dst: Some(PosixDst {
            name: dst_name,
            offset: dst_offset,
            start,
            end,
        }),
    })
}

/// Go's `tzsetName`: an unquoted name of at least three bytes ending at a
/// digit, `,`, `-` or `+` (or the end), or a `<...>` quoted name.
fn tz_name(s: &[u8]) -> Option<(String, &[u8])> {
    let first = *s.first()?;
    if first != b'<' {
        // Only ASCII bytes are compared, so a byte scan matches Go's rune
        // scan even for invalid UTF-8.
        match s
            .iter()
            .position(|b| matches!(b, b'0'..=b'9' | b',' | b'-' | b'+'))
        {
            Some(i) if i < 3 => None,
            Some(i) => Some((String::from_utf8_lossy(&s[..i]).into_owned(), &s[i..])),
            None if s.len() < 3 => None,
            None => Some((String::from_utf8_lossy(s).into_owned(), &[][..])),
        }
    } else {
        let i = s.iter().position(|&b| b == b'>')?;
        Some((String::from_utf8_lossy(&s[1..i]).into_owned(), &s[i + 1..]))
    }
}

/// Go's `tzsetOffset`: `[+-]hh[:mm[:ss]]` with hours up to 24*7.
fn tz_offset(s: &[u8]) -> Option<(i64, &[u8])> {
    let (neg, s) = match s.first()? {
        b'+' => (false, &s[1..]),
        b'-' => (true, &s[1..]),
        _ => (false, s),
    };
    let (hours, mut s) = tz_num(s, 0, 24 * 7)?;
    let mut off = hours * SECONDS_PER_HOUR;
    if s.first() == Some(&b':') {
        let (mins, rest) = tz_num(&s[1..], 0, 59)?;
        off += mins * 60;
        s = rest;
        if s.first() == Some(&b':') {
            let (secs, rest) = tz_num(&s[1..], 0, 59)?;
            off += secs;
            s = rest;
        }
    }
    Some((if neg { -off } else { off }, s))
}

/// Go's `tzsetRule`: `Jn`, `n` or `Mm.w.d`, optionally `/time`.
fn tz_rule(s: &[u8]) -> Option<(Rule, &[u8])> {
    let first = *s.first()?;
    let (mut rule, s) = if first == b'J' {
        let (day, s) = tz_num(&s[1..], 1, 365)?;
        (
            Rule {
                kind: RuleKind::Julian,
                day,
                week: 0,
                mon: 0,
                time: 0,
            },
            s,
        )
    } else if first == b'M' {
        let (mon, s) = tz_num(&s[1..], 1, 12)?;
        if s.first() != Some(&b'.') {
            return None;
        }
        let (week, s) = tz_num(&s[1..], 1, 5)?;
        if s.first() != Some(&b'.') {
            return None;
        }
        let (day, s) = tz_num(&s[1..], 0, 6)?;
        (
            Rule {
                kind: RuleKind::MonthWeekDay,
                day,
                week,
                mon,
                time: 0,
            },
            s,
        )
    } else {
        let (day, s) = tz_num(s, 0, 365)?;
        (
            Rule {
                kind: RuleKind::DayOfYear,
                day,
                week: 0,
                mon: 0,
                time: 0,
            },
            s,
        )
    };
    if s.first() != Some(&b'/') {
        rule.time = 2 * SECONDS_PER_HOUR;
        return Some((rule, s));
    }
    // Version 3 allows negative and over-24-hour transition times.
    let (time, s) = tz_offset(&s[1..])?;
    rule.time = time;
    Some((rule, s))
}

/// Go's `tzsetNum`: a decimal number in `min..=max`.
fn tz_num(s: &[u8], min: i64, max: i64) -> Option<(i64, &[u8])> {
    if s.is_empty() {
        return None;
    }
    let mut num = 0i64;
    for (i, &b) in s.iter().enumerate() {
        if !b.is_ascii_digit() {
            if i == 0 || num < min {
                return None;
            }
            return Some((num, &s[i..]));
        }
        num = num * 10 + i64::from(b - b'0');
        if num > max {
            return None;
        }
    }
    if num < min {
        return None;
    }
    Some((num, &[][..]))
}

/// Go's `tzruleTime`: seconds after the start of `year` at which `r` takes
/// effect, for a zone whose offset is `off`.
fn rule_time(year: i64, r: Rule, off: i64) -> i64 {
    let s = match r.kind {
        RuleKind::Julian => {
            let mut s = (r.day - 1) * SECONDS_PER_DAY;
            if is_leap(year) && r.day >= 60 {
                s += SECONDS_PER_DAY;
            }
            s
        }
        RuleKind::DayOfYear => r.day * SECONDS_PER_DAY,
        RuleKind::MonthWeekDay => {
            // Zeller's congruence for the weekday of the month's first day.
            let m1 = (r.mon + 9) % 12 + 1;
            let yy0 = if r.mon <= 2 {
                year.wrapping_sub(1)
            } else {
                year
            };
            let yy1 = yy0 / 100;
            let yy2 = yy0 % 100;
            let mut dow = ((26 * m1 - 2) / 10 + 1)
                .wrapping_add(yy2)
                .wrapping_add(yy2 / 4)
                .wrapping_add(yy1 / 4)
                .wrapping_sub(yy1.wrapping_mul(2))
                % 7;
            if dow < 0 {
                dow += 7
            }
            let mut d = r.day - dow;
            if d < 0 {
                d += 7;
            }
            for _ in 1..r.week {
                if d + 7 >= days_in(r.mon, year) {
                    break;
                }
                d += 7;
            }
            d += days_before(r.mon);
            if is_leap(year) && r.mon > 2 {
                d += 1;
            }
            d * SECONDS_PER_DAY
        }
    };
    s.wrapping_add(r.time).wrapping_sub(off)
}

/// Random-access source for Go's stored-only zip lookup.
trait ReadAt {
    fn size(&mut self) -> io::Result<u64>;
    /// Fill `buf` from `offset`; `false` on a short read.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> bool;
}

impl ReadAt for &[u8] {
    fn size(&mut self) -> io::Result<u64> {
        Ok(self.len() as u64)
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> bool {
        let Ok(start) = usize::try_from(offset) else {
            return false;
        };
        match start
            .checked_add(buf.len())
            .and_then(|end| self.get(start..end))
        {
            Some(src) => {
                buf.copy_from_slice(src);
                true
            }
            None => false,
        }
    }
}

impl ReadAt for File {
    fn size(&mut self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> bool {
        self.seek(SeekFrom::Start(offset)).is_ok() && self.read_exact(buf).is_ok()
    }
}

fn get4(b: &[u8]) -> u64 {
    b.get(..4).map_or(0, |b| {
        u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    })
}

fn get2(b: &[u8]) -> usize {
    b.get(..2)
        .map_or(0, |b| usize::from(u16::from_le_bytes([b[0], b[1]])))
}

/// Outcome of a zip member lookup.
enum ZipLookup {
    Found(Vec<u8>),
    NotFound,
}

/// Port of Go's `loadTzinfoFromZip`: find `name` in an uncompressed zip by
/// walking the central directory. Every read is bounds-checked against the
/// container size before allocating, and corrupt records are errors where
/// Go would panic on an out-of-range slice.
fn zip_lookup(mut src: impl ReadAt, name: &str, label: &str) -> Result<ZipLookup, LocationError> {
    const ZECHEADER: u64 = 0x0605_4b50;
    const ZCHEADER: u64 = 0x0201_4b50;
    const ZHEADER: u64 = 0x0403_4b50;
    const ZTAILSIZE: u64 = 22;
    let corrupt = || LocationError::CorruptZip(label.into());
    let size = src.size().map_err(LocationError::Io)?;
    let mut tail = [0u8; ZTAILSIZE as usize];
    if size < ZTAILSIZE || !src.read_at(size - ZTAILSIZE, &mut tail) || get4(&tail) != ZECHEADER {
        return Err(corrupt());
    }
    let count = get2(&tail[10..]);
    let dir_size = get4(&tail[12..]);
    let dir_off = get4(&tail[16..]);
    if dir_off.checked_add(dir_size).is_none_or(|end| end > size) {
        return Err(corrupt());
    }
    let mut dir = vec![0u8; dir_size as usize];
    if !src.read_at(dir_off, &mut dir) {
        return Err(corrupt());
    }
    let mut buf = &dir[..];
    for _ in 0..count {
        if get4(buf) != ZCHEADER || buf.len() < 46 {
            break;
        }
        let meth = get2(&buf[10..]);
        let member_size = get4(&buf[24..]);
        let namelen = get2(&buf[28..]);
        let xlen = get2(&buf[30..]);
        let fclen = get2(&buf[32..]);
        let off = get4(&buf[42..]);
        let zname = buf.get(46..46 + namelen).ok_or_else(corrupt)?;
        let matched = zname == name.as_bytes();
        buf = buf.get(46 + namelen + xlen + fclen..).ok_or_else(corrupt)?;
        if !matched {
            continue;
        }
        if meth != 0 {
            return Err(LocationError::UnsupportedCompression {
                name: name.into(),
                source: label.into(),
            });
        }
        let mut header = vec![0u8; 30 + namelen];
        if !src.read_at(off, &mut header)
            || get4(&header) != ZHEADER
            || get2(&header[8..]) != meth
            || get2(&header[26..]) != namelen
            || &header[30..] != name.as_bytes()
        {
            return Err(corrupt());
        }
        let data_off = off + 30 + namelen as u64 + get2(&header[28..]) as u64;
        if data_off
            .checked_add(member_size)
            .is_none_or(|end| end > size)
        {
            return Err(corrupt());
        }
        let mut data = vec![0u8; member_size as usize];
        if !src.read_at(data_off, &mut data) {
            return Err(corrupt());
        }
        return Ok(ZipLookup::Found(data));
    }
    Ok(ZipLookup::NotFound)
}

/// Look up `name` in a zoneinfo zip held in memory (stored members only).
/// Returns `Ok(None)` when the archive has no such member.
pub fn tzdata_from_zip(zip: &[u8], name: &str) -> Result<Option<Vec<u8>>, LocationError> {
    match zip_lookup(zip, name, "zoneinfo zip")? {
        ZipLookup::Found(data) => Ok(Some(data)),
        ZipLookup::NotFound => Ok(None),
    }
}

/// Go's `readFile`: a bounded read of a whole zone file.
fn read_file(path: &str) -> Result<Vec<u8>, LocationError> {
    let file = File::open(path).map_err(LocationError::Io)?;
    let mut data = Vec::new();
    file.take(MAX_TZDATA_LEN as u64 + 1)
        .read_to_end(&mut data)
        .map_err(LocationError::Io)?;
    if data.len() > MAX_TZDATA_LEN {
        return Err(LocationError::TooLarge(path.into()));
    }
    Ok(data)
}

fn not_found() -> LocationError {
    LocationError::Io(io::Error::from(io::ErrorKind::NotFound))
}

fn is_not_found(error: &LocationError) -> bool {
    matches!(error, LocationError::Io(e) if e.kind() == io::ErrorKind::NotFound)
}

/// Go's `loadTzinfoFromDirOrZip`: `source` is a directory, an
/// uncompressed `.zip` file, or empty (then `name` is a path).
fn load_tzinfo(source: &str, name: &str) -> Result<Vec<u8>, LocationError> {
    if source.len() > 4 && source.ends_with(".zip") {
        let file = File::open(source).map_err(LocationError::Io)?;
        return match zip_lookup(file, name, source)? {
            ZipLookup::Found(data) => Ok(data),
            ZipLookup::NotFound => Err(not_found()),
        };
    }
    if source.is_empty() {
        read_file(name)
    } else {
        read_file(&format!("{source}/{name}"))
    }
}

#[cfg(feature = "tzdata")]
fn load_embedded(name: &str) -> Result<Vec<u8>, LocationError> {
    match zip_lookup(super::tzdata::ZONEINFO_ZIP, name, "embedded tzdata")? {
        ZipLookup::Found(data) => Ok(data),
        ZipLookup::NotFound => Err(not_found()),
    }
}

#[cfg(not(feature = "tzdata"))]
fn load_embedded(_name: &str) -> Result<Vec<u8>, LocationError> {
    Err(not_found())
}

/// Go's internal `loadLocation`: try each source, then embedded tzdata.
/// The first error other than "not found" is reported.
fn load_from_sources(name: &str, sources: &[&str]) -> Result<Location, LocationError> {
    let mut first_err = None;
    let attempts = sources
        .iter()
        .map(|source| load_tzinfo(source, name))
        .chain(std::iter::once_with(|| load_embedded(name)));
    for attempt in attempts {
        match attempt.and_then(|data| Location::from_tzdata(name, &data)) {
            Ok(location) => return Ok(location),
            Err(error) => {
                if first_err.is_none() && !is_not_found(&error) {
                    first_err = Some(error);
                }
            }
        }
    }
    Err(first_err.unwrap_or_else(|| LocationError::UnknownZone(name.into())))
}

/// Go's name check: reject `..` anywhere and a leading `/` or `\`.
pub fn validate_location_name(name: &str) -> Result<(), LocationError> {
    if name.contains("..") || name.starts_with('/') || name.starts_with('\\') {
        return Err(LocationError::InvalidName);
    }
    Ok(())
}

/// Go's `LoadLocation`.
///
/// `""` and `"UTC"` give [`Location::utc`]; `"Local"` gives [`local`].
/// Other names are validated and searched for in the directory or
/// uncompressed zip named by the `ZONEINFO` environment variable, then in
/// [`PLATFORM_ZONE_SOURCES`], then in the embedded database when the
/// `tzdata` feature is enabled. Unlike Go, `ZONEINFO` is read on every
/// call and `$GOROOT/lib/time/zoneinfo.zip` is not consulted.
pub fn load_location(name: &str) -> Result<Location, LocationError> {
    let zoneinfo = std::env::var_os("ZONEINFO").map(|v| v.to_string_lossy().into_owned());
    load_location_with(name, zoneinfo.as_deref().unwrap_or(""))
}

/// [`load_location`] with an explicit `ZONEINFO` value (empty for none).
pub fn load_location_with(name: &str, zoneinfo: &str) -> Result<Location, LocationError> {
    if name.is_empty() || name == "UTC" {
        return Ok(Location::utc());
    }
    if name == "Local" {
        return Ok(local());
    }
    validate_location_name(name)?;
    let mut first_err = None;
    if !zoneinfo.is_empty() {
        match load_tzinfo(zoneinfo, name) {
            Ok(data) => match Location::from_tzdata(name, &data) {
                Ok(location) => return Ok(location),
                Err(error) => first_err = Some(error),
            },
            Err(error) if !is_not_found(&error) => first_err = Some(error),
            Err(_) => {}
        }
    }
    match load_from_sources(name, &PLATFORM_ZONE_SOURCES) {
        Ok(location) => Ok(location),
        Err(error) => Err(first_err.unwrap_or(error)),
    }
}

/// Load `name` from one directory or uncompressed `.zip` file, after Go's
/// name validation. Embedded data and system directories are not used.
pub fn load_location_from(source: impl AsRef<Path>, name: &str) -> Result<Location, LocationError> {
    validate_location_name(name)?;
    let source = source.as_ref().to_string_lossy();
    let data = load_tzinfo(&source, name).map_err(|error| {
        if is_not_found(&error) {
            LocationError::UnknownZone(name.into())
        } else {
            error
        }
    })?;
    Location::from_tzdata(name, &data)
}

static LOCAL: OnceLock<Location> = OnceLock::new();

/// Go's `Local`, resolved once from the `TZ` environment variable.
pub fn local() -> Location {
    LOCAL
        .get_or_init(|| {
            let tz = std::env::var_os("TZ").map(|v| v.to_string_lossy().into_owned());
            local_for_tz(tz.as_deref())
        })
        .clone()
}

/// Resolve Go's `Local` for a given `TZ` value (Go's `initLocal` on Unix).
///
/// `None` loads `/etc/localtime` and names it `"Local"`. `""` and `"UTC"`
/// give UTC. A leading `:` is ignored. An absolute path loads that file;
/// another value is a zone name searched in the system directories and
/// embedded data. Any failure falls back to UTC, never to an error.
pub fn local_for_tz(tz: Option<&str>) -> Location {
    match tz {
        None => {
            if let Ok(z) = load_from_sources("localtime", &["/etc"]) {
                return z.renamed("Local");
            }
        }
        Some(tz) if !tz.is_empty() => {
            let tz = tz.strip_prefix(':').unwrap_or(tz);
            if tz.starts_with('/') {
                if let Ok(z) = load_from_sources(tz, &[""]) {
                    return z.renamed(if tz == "/etc/localtime" { "Local" } else { tz });
                }
            } else if !tz.is_empty() && tz != "UTC" {
                if let Ok(z) = load_from_sources(tz, &PLATFORM_ZONE_SOURCES) {
                    return z;
                }
            }
        }
        Some(_) => {}
    }
    Location::empty("UTC")
}
