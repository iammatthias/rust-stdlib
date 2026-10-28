# Changelog

## 0.1.0 — unreleased

Initial release: parity with Go 1.27's standard library.

- Every exported symbol of the 149 in-scope Go packages is implemented and
  checked against Go by a differential suite, or recorded as a documented
  deviation (9,409 mapped, 337 deviations). See docs/COVERAGE.md and the
  per-package notes in docs/api/.
- Crates: `rust-stdlib` (zero dependencies, `forbid(unsafe_code)`),
  `rust-stdlib-crypto` (reviewed RustCrypto crates, ADR 0003),
  `rust-stdlib-tls` (rustls with ring, ADR 0002), `rust-stdlib-sys` (libc FFI,
  ADR 0004) and `rust-stdlib-derive` (first-party derives, including
  `Reflect`).
- Known limits and the path to 1.0 are in docs/ROADMAP.md.

### API

- ADR 0005: the public API is Rust-shaped; Go behaviour, not Go names.
  `tools/api_shape.py` ratchets the remaining Go-shaped items in the gate.
- `encoding::base64` is one `Engine` type (`STANDARD`, `URL_SAFE`,
  `STANDARD_NO_PAD`, `URL_SAFE_NO_PAD`) with Go's decoding rules by default;
  `strict()` opts into canonical-only decoding. The `GO_*` constants, the
  `Encoding` type and the duplicate `encode_*`/`decode_*` forms are gone.
- Go mirrors of Rust std are gone: `strings`, `bytes`, `sort`, `slices`, `maps`,
  `cmp`, `iter`, `errors`, `sync`, `sync/atomic`, `weak`, `math/bits`,
  `unicode/utf16` and `io/ioutil` symbols map to std items. Real gaps survive
  as small Rust items: `text::BytesExt` (Go's byte-string semantics),
  `text::{Buffer, Reader, Replacer}`, `collections` (heap, list, ring),
  `concurrent::WaitGroup`, `error::{Joined, Message}`, `unicode::rune`.
- `fmt` is now `printf`: Rust's `format!`/`Display` cover Go's `Printf` family;
  the runtime Go-verb formatter and scanning stay for dynamic format strings.
- One implementation per concept: the older bounded `net::http` API, `xml::bounded`
  and the strict JSON parser are deleted; `gotransport`, `gocookie`, `gohttp`,
  `goconn` and `goproxy` became `transport`, `cookie`, `httptest`, `persist` and
  `reverseproxy`; `gotls` became `http_tls`.
- Rust constructors and traits throughout: `Type::new`/`with_*`/`from_*`
  instead of `new_*`, `Display` instead of `string()`, `FromStr` for `Url`,
  `Time`, `Duration` and JSON `Value`, std operator traits for `big::Int` and
  `big::Rat`, `Context::background()` with methods for derived contexts.
- `base32` and `hex` follow the `base64` engine design.
- Behaviour is unchanged: every Go differential suite passes. Deviations fell
  from 337 to 281 because API-shape differences are no longer deviations;
  `sync.Once.Do` poisoning is now recorded as one.
- The shape lint baseline is 0. Leftovers the lint cannot see are listed in
  docs/ROADMAP.md.
- The shape lint also catches CamelCase `Go` names, public fields and
  by-value or trait `string()` methods; it is at 0.
- One TLS API: `tls::Config` is the HTTP client and server TLS configuration;
  `http_tls` is gone and the certificate-callback types lost their `Go` prefix.
- `netip` parses with `FromStr`, orders with `Ord` and converts to and from
  `std::net` types; `to_std()` is replaced by `TryFrom`.
- `io::copy`, `read_full` and friends return `Result` with the partial count in
  the error; `SeekFrom` replaces Go's whence constants; `bufio::Scanner` is an
  iterator; `filepath::WalkDir` is an iterator.
- asn1 follows Go's explicit-tag rule by default (`strict_explicit` opts out);
  `big::Float` has operator traits; `sql::Rows::next_row`.
- The gate denies rustdoc warnings in every crate, and two timing-sensitive
  differentials no longer race under load.
- `netip::Addr` wraps `std::net::IpAddr` plus a zone and delegates its
  predicates to std where std's stable behaviour matches Go.
- One positional-read trait (`io::ReadAt`) and one rune-reader trait
  (`io::RuneReader`); the archive and regexp duplicates are gone.
- `sql::Rows::next_row` is the only row-iteration API; `json::Number::new`
  validates, so an invalid number cannot exist.
- asn1's 256 default depth is recorded as a deviation (the recursion runs
  through caller `Unmarshal` impls).
- `database/sql`, from the first application port: boxed sql and driver
  trait objects and the `DB`/`Rows`/`Stmt`/`Tx`/`Conn` handles implement
  `Debug`; `driver::Res` is public; `driver::BufferedRows` lets a driver over a
  borrowing binding (such as rusqlite) stay safe.
- From the farfield port: `ResponseWriter` is `std::io::Write` and has a
  `copy_from` passthrough (Go's `ReadFrom`); multipart parts stream as
  `PartReader: Read`; `Server`/`Transport`/`Dialer` accept struct-update
  syntax; HTTP status codes are `u16`; `Header::get` returns `Option<&str>`;
  `parse_fs` takes any `io::fs::FS` (the template and archive `Fs` traits are
  gone; `zip::Reader` implements `io::fs::FS`); `const fn` `Duration`
  constructors; `os::signal::notify_context` returns a stop guard.
- From the farfield port, second round: one `time::Duration` in public
  signatures (with `From`/`TryFrom` for `std::time::Duration`); JSON `Value`
  objects keep insertion order (`json::Map`), so structs keep declared order
  and maps stay sorted, as in Go; `json::unmarshal_into`/`Decoder::decode_into`
  merge into an existing value with Go's rules; template functions taking
  `any` receive the dynamic value; unshared images index pixels without a
  lock; an owning multipart part (`Reader::into_next_part`); multipart and the
  HTTP transport keep the original error as the source; examples no longer
  include files from `tests/`; signal constants are re-exported from
  `os::signal`; the duplicate strict multipart codec is gone and
  `multipart::Part` is the streaming part; `httptest::Server` accepts
  struct-update syntax; crypto uses the system CSPRNG by default with
  `*_with_rng` variants for a caller-chosen source.
- DEFLATE output is byte-identical to Go 1.27: Go's compressor is ported
  (fast matchers for levels 1-6, lazy hash chains for 7-9, Go's Huffman
  construction and block writer), and PNG and ZIP now use it at Go's levels.
  The legacy one-shot `compress::encode_*` encoders are removed.
- `sql::driver::Arg` and `sql::NamedArg` are `Clone`; `json::Error::custom`
  and `custom_source` (with `downcast_ref` through the source chain) let user
  `Serialize`/`Deserialize` impls report their own errors.
- `rust_stdlib::io` re-exports std's `Read`, `Write`, `Seek`, `BufRead` and
  `SeekFrom`.
- PNG decode errors match Go's text on every truncation and corruption
  vector (48,270 in the differential); tar, zip, `binary` and the hex stream
  decoder no longer leak std's `read_exact` text. `multipart::Writer` has
  `get_ref`/`get_mut`/`into_inner`; `io::ReadAt`/`WriteAt` are implemented for
  `std::io::Cursor`. `time::Timer`/`Ticker` are `Send + Sync`, with a
  `time::Channel` for `C`. The root `net::Dialer`/`ListenConfig` no longer
  carry an ignored `keep_alive` field: TCP keep-alive is set through
  `rust_stdlib_sys::net::Dialer`.
- New crate `rust-stdlib-sysnet` (`backends/sysnet`, ADR 0006): an adapter
  from `rust-stdlib-sys` connections to the root `net::Conn`, a
  `Transport::dial_context` hook over a sys `Dialer`, and `default_transport()`
  / `default_client()` matching Go's `http.DefaultTransport`, including its
  30 s TCP keep-alive (checked against Go by `tools/sysnet_check.py`).
- `rust-stdlib-sysnet` has a default `tls` feature: `default_client()` does
  HTTPS like Go's `http.DefaultClient` (system roots, ALPN h2, 10 s handshake
  timeout). Without the feature it stays third-party-free and http-only.
- Behaviour audit: about 120 differences from Go that `docs/api` recorded
  only in prose. Most are fixed: multipart forms spill large files to disk;
  Go's pdqsort order for unstable sorts; reflect's capacity growth; os/user
  through libc (NSS, Open Directory) in `rust_stdlib_sys::os::user`;
  `fs::read_dir` returns the partial list with its error; Go's base32 stream
  errors; flag recovers a panicking zero-value String; `error::is`/`find`
  consult `ErrorIs`/`ErrorAs` hooks; x509 parsers give Go's encoding/asn1
  error text; ML-DSA reports Go's verify errors; embed files seek and read at
  offsets; `xml::unmarshal` returns a value; `zip::Reader` takes borrowed
  readers and `OpenError` carries the reader. The rest are coded as
  deviations (411), and three gaps stayed `differs` (closed in the next entry). Two Go behaviours are
  kept out on purpose for security: ed25519 signing with a mismatched public
  half, and lax multi-prime RSA key validation.
- No symbol is marked `differs` any more: of the last three gaps, one is
  fixed and two are recoded as deviations. `sql::driver` gains `Decimal` (Go's decimalDecompose/decimalCompose as the
  `Decompose`/`Compose` traits, a `Value::Decimal` variant) and converts
  `uuid::UUID` arguments to strings as Go does; `archive::tar` gains
  `set_name_lookup`, so an application can install the sys crate's libc
  lookups (without it, tar still reads only `/etc`: deviation
  `no-ffi-in-root`), and keeps `FileInfoNames` names as Go does; x509 quotes
  invalid bytes in error text as Go's `%q` does, and RSA keys with an
  oversized private exponent report Go's "input overflows the modulus size".
  Three certificate URL fields that can hold invalid UTF-8 are a
  `go-string-invalid-utf8` deviation. Breaking: `sql::driver::Value` and
  `Arg` gain variants, and a type cannot implement both `Compose` and
  `Scanner`.
- `docs/COVERAGE.md` lists deviations by code, generated; `docs/ROADMAP.md`
  keeps no hand-written counts. `docs/ARCHITECTURE.md` and
  `docs/PARITY_WORKFLOW.md` gain diagrams (sources in `docs/diagrams/`).
- `regexp` runs Go's one-pass and bit-state backtracking matchers, chosen as
  Go's `doExecute` chooses them, and adds offset searches for tokenizers:
  `find_index_at` and `find_submatch_index_at` (Go's internal `find(pos)`,
  with the text before `start` as context for `^`, `\b`, `\B`) and their
  anchored forms `find_anchored_index_at` / `find_anchored_submatch_index_at`.
  The Go differential compares all four at every offset and reruns every
  vector on each matcher.
- `regexp` searches cost less per call: the matcher state is used in place
  under one lock instead of being moved out of and back into a locked pool,
  index searches no longer allocate a result `Vec`, and
  `unicode::rune::decode_rune` returns ASCII without UTF-8 validation. On a
  20-rule tokenizer replaying `find_anchored_index_at` calls
  (`examples/regexp_tokenizer_bench.rs`), a call costs 43 ns instead of 65 ns
  on 2 KB of text and 64 ns instead of 94 ns on 200 KB (median per run,
  base and new runs alternated 8 times). Offset search runs the unanchored
  program, which never takes the one-pass matcher, and texts past the
  backtracker's limit run on the Pike VM, so a call on 200 KB still costs
  more than on 2 KB. `tools/regexp/bench/tokenizer.go` runs the same
  rules in Go 1.27 for comparison.
- `rust-stdlib-crypto` has one Cargo feature per Go crypto package
  (`default = ["full"]` keeps the old build). A consumer that sets
  `default-features = false` compiles only the packages it enables: `sha256`
  alone reaches 9 registry crates, `sha256,hmac` 17, and
  `sha256,hmac,ecdsa,ed25519,rsa` 62, against 88 for the full set. Hash
  availability follows Go's imports, so PSS, OAEP with options and
  deterministic ECDSA need the hash's package feature, and SHA-3 comes with
  `rsa`, `ecdsa`, `hmac`, `hkdf`, `pbkdf2` and `hpke` as Go's `fips140hash`
  import gives it. `PrivateKey::decrypt` with `OAEPOptions` now reports Go's
  "rsa: requested hash function unavailable".
- `rust-stdlib-crypto` pins `crypto-bigint` 0.7.10 (was 0.7.5, which
  crates.io has yanked). A crate depending on `rust-stdlib-crypto` by path
  failed to resolve with "version 0.7.5 is yanked" under any feature that
  enables `rand`. The update also takes RUSTSEC-2026-0387 (`crypto-bigint`)
  and RUSTSEC-2026-0385 (`ctutils`, now 0.4.6), both constant-time fixes.
  `tools/yank_check.py` reports a yanked direct pin in any manifest.
- `rust-stdlib-tls` pins Rustls 0.23.46 (was 0.23.45), and its lock and
  `rust-stdlib-sysnet`'s take rustls-webpki 0.103.16 (was 0.103.15). A TLS
  client no longer lets an unauthenticated ServerHello choose the key share
  it sends to that server later (RUSTSEC-2026-0349), and certificate
  verification rejects the distrusted emSign intermediates
  (RUSTSEC-2026-0382). The update also takes RUSTSEC-2026-0346, -0347 and
  -0348, which need a `Debug`-printing session store, ECH or the `brotli`
  feature, none of which the adapter uses.
- `image::png` decodes a file whose IDAT run continues after the zlib
  stream ends at a chunk boundary, such as a duplicated IDAT chunk from the
  farfield image corpus. Go skips those chunks after decoding, reporting only
  a bad CRC or a truncation in them, and so does the port. A bad CRC on a
  chunk the stream still needs is reported where Go's zlib reader crosses it.
  The one remaining difference, bytes after the stream inside the chunk it
  ends in, is coded as deviation `idat-tail-bytes` and pinned in the
  differential.
- On Linux, `net` and `rust-stdlib-sys` print an unnamed Unix socket
  address as "@", as Go's Linux `anyToSockaddr` does, and
  `ReadMsgUnix` returns the `MSG_CMSG_CLOEXEC` bit the kernel echoes in its
  flags. `rust-stdlib-sys` `Errno` and `Signal` text comes from Go's table
  for the host architecture, so errno 133 on arm64 is "memory page has
  hardware error"; `syscall` keeps the linux/amd64 tables on every host.
- Gate fixes for native Linux runs (the library was right in each case): the
  archive differential reads its test symlink until a relatime mount stops
  bumping its atime, so Go and Rust see the same timestamp.
  The cgo-resolver rows of the dns and sys differentials run Go with
  `GODEBUG=netdns=cgo`, since `rust_stdlib_sys` always asks the C library; the
  `fe80::1%lo0` reverse lookup runs only on macOS, where lo0 is local.
  The fmt differential masks a func value's code address from five hex digits,
  as Go's non-PIE Linux binaries print it.
  The sys socket tests expect Linux's errno where it differs from macOS (SO_RCVBUF
  0 is clamped, an unaddressed datagram is ENOTCONN), and the unixpacket
  deadline test keeps its peer connected.
  The syslog UDP collector asks for a 4 MiB receive buffer, so loopback drops
  no longer fail the log differential.
  The gob `ignore_interface_field` test registers its types itself instead of
  relying on another test to run first.
  A redundant rebinding in `tests/image_subimage.rs` is gone; clippy flagged it
  only on Linux.
- `os::pipe`, and with it the `os::exec` stdin, stdout and stderr pipes, is a
  real `pipe(2)` from `std::io::pipe` instead of a socketpair. A child that
  wrote a few thousand short lines to stderr while the parent read stdout to
  end of file blocked on Linux after about 300 writes; a pipe holds 64 KiB, as
  Go's does. The minimum Rust version is now 1.87.
- `rust_stdlib_sys::os::Process::with_handle` follows Go's handle state
  machine on Linux: a process that had a pidfd reports `ErrProcessDone` after
  `wait` and "already released" after `release`; `ErrNoHandle` stays for a
  process that never had one (macOS, kernels before 5.3). The sys half of
  `tools/exec_check.py` now matches Go on Linux as well as macOS.
- `Process::wait` after `release` fails with the bare `EINVAL` in both crates,
  as Go's does (`rust_stdlib_sys::os::ProcessError::Errno`), and after `wait`
  then `release` keeps reporting the wait syscall's `ECHILD`. The sys crate's
  `Process::signal` reads the pidfd status before the pid, as Go's pidfd path
  does. `tools/exec_check.py` pins Wait, Signal and WithHandle after Wait and
  after Release.
- `base64::Engine::strict` and `with_padding`, and
  `base32::Engine::with_padding`, are `const fn`, so Go's package-level `var
  raw = base64.RawURLEncoding.Strict()` can be a Rust constant (asked for by
  aoer's dogfooding).
- The GitHub Actions workflow is removed. There is no hosted CI: every change
  runs `tools/check.py` locally, and consumers vendor a pinned revision
  (docs/CI.md).
- A `json::v2` `MarshalTo` derive compiles on a struct with a skipped `String`
  field, or any skipped field whose type has several `PartialEq` impls: the
  struct's zero check names the field type. Behaviour is unchanged.
- `encoding::json` keeps the path a custom `Unmarshaler` puts in the
  `UnmarshalTypeError` it returns (`FlagHolder.flag`), as Go 1.27's
  `encoding/json` does; it used to glue the outer field onto it with no
  separator.
- `encoding::json::v2` marshals and unmarshals `time::Time` and
  `time::Duration` (Go's `arshal_time.go`). A `Time` is an RFC 3339 string with
  nanoseconds, `null` sets the zero time and `omitzero` uses `Time::is_zero`,
  also through an `Option<Time>`. A `Duration` has no default representation,
  as in Go 1.27. With `experimental_support_format_tag`, the `format` tag
  option selects Go's layouts and `unix`/`unixmilli`/`unixmicro`/`unixnano`
  for `Time`, and `units`, `sec`, `milli`, `micro`, `nano` and `iso8601` for
  `Duration`. `MarshalTo` gains `has_is_zero_method` and `is_zero_field`.
