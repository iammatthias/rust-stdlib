# Embedded time zone database provenance

`zoneinfo.zip` is a byte-for-byte copy of `lib/time/zoneinfo.zip` from the Go
1.27.1 distribution (`$(go env GOROOT)/lib/time/zoneinfo.zip`), the same
archive Go embeds in its `time/tzdata` package.

- SHA-256: `b2d18a7c8fa8142097a48c99609fb3c92db5ee98bc740294e57eab8ae9f94779`
- Size: 408,467 bytes, 598 stored (uncompressed) TZif members
- IANA Time Zone Database release: tzdata 2026c, compiled with tzcode 2026c
  (the `CODE`/`DATA` versions pinned in Go's `lib/time/update.bash`, built
  with `PACKRATDATA=backzone PACKRATLIST=zone.tab`)

The IANA asserts that the time zone database is in the public domain; see
<https://www.iana.org/time-zones> and RFC 6557. Go's packaging scripts are
BSD-licensed (see NOTICE); the archive contents are IANA data.

To update, copy `lib/time/zoneinfo.zip` from a newer Go release, update the
hash, size and IANA version here and in `src/time/tzdata.rs`, and rerun
`python3 tools/tzif_check.py`.
