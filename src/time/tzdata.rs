//! Embedded IANA time zone database, Go's `time/tzdata` (feature `tzdata`).
//!
//! When the `tzdata` feature is enabled, [`super::load_location`] falls back
//! to this archive after `ZONEINFO` and the system directories. The archive is
//! Go's `lib/time/zoneinfo.zip`, checked in verbatim; see
//! `src/time/tzdata/PROVENANCE.md`.
use super::location::{tzdata_from_zip, LocationError};

/// IANA Time Zone Database release of the embedded data.
pub const IANA_VERSION: &str = "2026c";

/// Go's uncompressed zoneinfo zip (408,467 bytes, 598 zones).
pub static ZONEINFO_ZIP: &[u8] = include_bytes!("tzdata/zoneinfo.zip");

/// The raw TZif data for `name`, or `Ok(None)` if the zone is not embedded.
pub fn lookup(name: &str) -> Result<Option<Vec<u8>>, LocationError> {
    tzdata_from_zip(ZONEINFO_ZIP, name)
}
