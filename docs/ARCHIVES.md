# Compression and archive contracts

These modules implement first-party safe Rust with no dependencies, FFI or
filesystem extraction. Their public transport interfaces use `std::io::Read`
and `Write`. Bounds apply to entire operations, including concatenated gzip
members and every archive entry.

## Implemented formats and boundaries

| Module | Decode/read | Encode/write | Explicit boundaries |
| --- | --- | --- | --- |
| `compress` raw DEFLATE | Stored, fixed and dynamic Huffman blocks, overlapping LZ77 references, cross-block history | `compress::flate::Writer` (byte-identical to Go's) | Decoding here is the bounded one-shot `decode_deflate` |
| `compress` zlib | Header/window validation, DEFLATE and Adler-32 validation | `compress::zlib::Writer` | Preset dictionaries rejected by `decode_zlib` |
| `compress` gzip | Optional extra/name/comment/header-CRC fields; reserved-flag rejection; concatenated members; per-member CRC-32 and modulo-2^32 size validation | `compress::gzip::Writer` | Header metadata is validated and discarded |
| `archive::tar` (bounded helpers) | POSIX USTAR regular files, directories, symbolic links; header checksum, octal numbers and zero padding | Deterministic USTAR headers and end blocks; long paths split into prefix/name | GNU/PAX extensions, base-256 numbers, hard links and other special file types rejected; UTF-8 metadata required. The Go-shaped `Reader`/`Writer` below lift these limits |
| `archive::zip` (bounded helpers) | Stored and DEFLATE members; central/local metadata consistency, optional signed/unsigned data descriptors, CRC-32 and decoded size checks | Deterministic stored ZIP entries with UTF-8 names | ZIP64, encryption, multiple disks, preambles, unreferenced/gapped member data, other compression methods and CP437 names rejected. The Go-shaped `Reader`/`Writer` below lift these limits |

The rows above describe the bounded one-shot decoders in `compress`; encoding
is done only by the writers. Go's streaming `compress/flate`, `compress/gzip` and `compress/zlib` APIs live in
`compress::flate`, `compress::gzip` and `compress::zlib`: readers follow Go's
inflate byte for byte (error offsets, trailing data, preset dictionaries,
multistream gzip), and writers implement levels -2 to 9 as a port of Go's compressor (byte-identical
output), with preset dictionaries and sync flushes. They take no
`Limits` (memory is bounded by the 32 KiB window and 64 Ki-token blocks); wrap
the reader in `Read::take` to cap output. See `tools/flate_check.py` for the Go
differential and the compression-ratio report.

ZIP CRC/signature ambiguity in unsigned data descriptors is handled by testing
both layouts against the central directory. Entry paths remain opaque metadata;
callers implementing extraction must enforce their own destination policy.

## Go-shaped `archive/tar` and `archive/zip`

`archive::tar::{Reader, Writer, Header, Format, file_info_header}` and
`archive::zip::{Reader, ReadCloser, Writer, File, FileHeader, open_reader}`
implement every exported symbol of Go's `archive/tar` and `archive/zip`
(`python3 tools/api_parity.py` reports both `complete`; mappings are in
`docs/api/archive_tar.json` and `archive_zip.json`). The bounded `read`/`write`
helpers above are unchanged and stay strict. The small `archive::iofs` module
holds the file model these APIs use (`FileMode`, `FileInfo`, `FileInfoNames`,
`DirEntry`, `File`, `SystemTime` helpers). File systems are the crate-wide
`io::fs::FS`: `zip::Reader` implements it and `add_fs` takes it.

tar: USTAR, PAX and GNU headers with Go's format selection (writer output is
byte-identical to Go's), GNU long names/links, PAX records, global headers and
sub-second times, base-256 numbers, `SCHILY.xattr.` records, star access and
change times, and sparse files in the old GNU, PAX 0.0, 0.1 and 1.0 layouts
(holes read as zeros). Go's writer cannot write sparse files, so
`Writer::write_sparse_header` is a Rust extension (PAX 1.0 maps, or old GNU maps
for `TYPE_GNU_SPARSE`). `Writer::add_fs`, `file_info_header` and
`Header::file_info` follow Go.

zip: ZIP64 read and write (records, extra fields, descriptors with 64-bit
sizes), preambles and `set_offset`, data descriptors with and without
signatures, extended timestamp, NTFS and Unix extra fields, the UTF-8 flag,
CP437 names, `create_raw`/`copy`, `open_raw`, `data_offset`, registered
compressors and decompressors (process-wide and per reader/writer), and the
`fs.FS` view of an archive (`FS::open` on `Reader`, directory synthesis, duplicate
detection) including `Writer::add_fs`.

### Boundaries compared with Go

- Header, name and comment strings are Rust `String`s. tar names, link names,
  user/group names and PAX records that are not valid UTF-8 fail with
  `ERR_HEADER` (Go keeps the bytes). ZIP names and comments that are not valid
  UTF-8 are decoded as CP437 (`cp437_decode`) and encoded again when
  `non_utf8` is set and every character has a CP437 byte; `FS::open` on `Reader` then
  accepts those names where Go's `fs.ValidPath` would reject the raw bytes.
- Times are `std::time::SystemTime`; Go's zero time is
  `iofs::time_zero()`. ZIP `modified` is an instant: Go's zone offset is not
  kept, and MS-DOS date/time fields are written in UTC (Go uses the time's own
  zone).
- `file_info_header` fills ids, times and device numbers from
  `std::fs::Metadata` on Unix but, without a user database in `std`, leaves
  `uname`/`gname` empty unless the `FileInfo` implements `FileInfoNames`.
- `ErrInsecurePath` is opt-in, like Go's default: `GODEBUG=tarinsecurepath=0`
  or `Reader::set_reject_insecure_paths` for tar, and
  `GODEBUG=zipinsecurepath=0` or `Reader::with_options` for zip. The error
  carries the header (`InsecurePathError`) or the reader so callers can keep
  using it, as Go's `(value, ErrInsecurePath)` returns allow.
- `Reader::next` returns `Ok(None)` for `io.EOF`. Data that Go returns together
  with a final error may arrive in an earlier read (and Go drops the last
  chunk when a short member ends in `ErrUnexpectedEOF`), so the differential
  compares byte counts only for successful reads.
- `create_header` and `create_raw` copy the header; unlike Go it is not
  updated with the sizes and CRC when the member closes (read them back with
  `Reader`). The DEFLATE compressor streams each member through
  `compress::flate::Writer` at level 5, like Go, and its output is
  byte-identical to Go's.
- `Writer::set_offset` and the duplicate-registration functions panic exactly
  where Go panics.

## Budgets, errors and I/O

Compression `Limits` bounds compressed/raw source bytes and emitted/decoded
bytes. Archive `Limits` independently bounds archive bytes, entry count, each
file, and total decoded payload. Default limits are documented by each
`Default` implementation. Header fields and integer conversions are validated
before allocating member payloads. Expanding back-references check the output
budget before growth.

Buffered compression decoders validate the complete stream and all checksums
before writing output. ZIP returns entries after complete directory validation.
`tar::read` returns entries after complete archive validation. Errors use
`io::Error`; protocol and budget failures use `InvalidData`, while underlying
I/O failures retain their error kind. `Write::write_all` handles partial writes;
read loops retry interrupted reads. Blocking I/O inherits the caller's deadline
and cancellation policy.

Buffered compression decoders collect bounded output through the streaming
decoder and verify completion before writing it. ZIP retains the bounded
archive and decoded entries.

## Incremental APIs

`Decoder::deflate`, `Decoder::zlib` and `Decoder::gzip` implement `Read` with
a 32 KiB history window and an 8 KiB source buffer. Cumulative input/output
budgets include all concatenated gzip members. Output is provisional until
verified EOF or successful `finish()`; `is_verified()` records that state.
Errors latch and subsequent reads fail. Early `into_inner()` discards buffered
read-ahead. Callers requiring transactional results must stage output and
consume/finish the decoder before committing it.

`tar::read_each` visits one validated bounded member at a time, allowing the
caller to release each payload before the next arrives. `tar::write_stream`
buffers a single encoded member rather than the entire archive. It accepts a
slice of entries whose input data remains caller-owned.

Incremental writers can leave partial destination data after an I/O error,
budget violation or malformed later input. Earlier `read_each` visitor side
effects persist if a later member fails. Callers requiring transactional writes
must provide a transactional destination.

## Executed verification

- Rust unit tests cover externally generated Python stored/fixed/dynamic
  DEFLATE, zlib/gzip/USTAR/ZIP fixtures, gzip concatenation and optional header
  fields, malformed trees and reserved flags, truncation sweeps, CRC/Adler known
  vectors, interrupted reads, partial writes and exact budget boundaries.
- `python3 tools/check_archives.py` executed successfully (Rust 1.99.0, Go
  1.27.1): **84 Go/Rust differential cases**. Six payload families exercise all
  five formats in both directions, plus streaming compression (level 0 writers)
  and USTAR encoders decoded by Go. Payloads include empty, all-byte, repetitive, random 70,000-byte
  and multiple-block data. The harness checks useful buffered compression on
  repetitive input.
- A deterministic mutation test executes **10,000** bounded malformed/truncated
  DEFLATE cases. This is regression evidence, not coverage-guided fuzzing or a
  security audit. Longer coverage-guided campaigns remain a release requirement.
- `tools/check_archive_api.py` (run by `tools/check_archives.py`, so by the
  `archive_differential` gate step) compares the Go-shaped tar and zip APIs
  with Go 1.27.1 (Rust 1.99.0) on **2,628 vectors** (about 30 s): every tar and zip fixture of
  Go's `testdata` (GNU, PAX, star, v7, sparse in all layouts, hard links,
  ZIP64 `.zsparse` archives up to 5 GiB, descriptors, preambles, extended
  timestamps, UTF-8 and CP437 names) read by both sides; 80 seeded tar
  manifests and 70 zip manifests written by both sides (identical accept/reject
  decisions and, for tar and the 70,000-entry ZIP64 archive, identical bytes;
  deflated members are compared by decoded content), then read by both; 40
  Rust-written sparse files read by Go; and 2,000 deterministic bit-flip,
  byte-replacement, truncation and block-splice mutations of those archives
  with identical accept/reject results and content. The Go transcripts of the
  checked-in fixtures (`tests/fixtures/archive/*_golden.txt`) back
  `tests/archive_tar.rs` and `tests/archive_zip.rs`, which also port Go's
  reader, writer, strconv, allowed-formats and header tables.
- Rust-produced gzip, zlib, ZIP and tar outputs also decoded successfully through
  Python's independent standard-library implementations.
- ZIP DEFLATE members are read with `compress::Decoder::deflate_prefix`, which
  stops at the final block and ignores trailing bytes like Go's flate reader.

The Python fixtures were generated with `zlib`, `gzip`, `tarfile` in explicit
USTAR mode and `zipfile` (seekable and nonseekable outputs for descriptors).
No third-party codec source was copied.

## Format sources

- [RFC 1951: DEFLATE](https://www.rfc-editor.org/rfc/rfc1951)
- [RFC 1950: zlib](https://www.rfc-editor.org/rfc/rfc1950)
- [RFC 1952: gzip](https://www.rfc-editor.org/rfc/rfc1952)
- [POSIX pax / USTAR interchange](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html)
- [PKWARE ZIP APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)
- [Go archive and compression packages](https://pkg.go.dev/std)
