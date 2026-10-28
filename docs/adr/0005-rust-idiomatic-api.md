# ADR 0005: a Rust-idiomatic API

Status: **accepted** (maintainer direction, 2026-10-13).

## Context

The crate reached symbol-level parity with Go 1.27 by mirroring Go: Go package
names, Go function names, Go constructors (`new_reader`), `GO_*` constants,
`go_sprintf!`, and whole modules (`strings`, `sort`, `fmt`) that re-implement
what Rust's std already provides. It works, but it reads like Go. The
maintainer's direction: it should not look like Go; it should achieve what Go's
standard library achieves.

## Decision

**Parity means capability and behaviour, not API shape.** Every Go symbol must
still be covered, and formats and protocols must still behave exactly like Go's
(JSON, HTTP, TLS, DER, PNG, tar, regexp, templates, time layouts). Names,
signatures and module structure follow Rust conventions instead.

1. **Go mirrors of Rust std are removed, not restyled.** Where std already
   achieves the capability (`strings`, `bytes`, `sort`, `slices`, `maps`, `cmp`,
   `iter`, `container/*`, `sync`, `sync/atomic`, `errors`, `math`, `math/bits`,
   `unicode/utf8`, `unicode/utf16`, `fmt`, and most of `io`, `os`,
   `path/filepath`), the module is deleted and the symbol map points at std
   (`str::split_whitespace`, `<[T]>::sort_unstable`, `format!`, `std::fs::read`).
   Code survives only for a real gap, as a small extension trait or function in
   the most natural module (for example Go's cutset trims or `EqualFold`).
2. **One API per module.** Older bounded or strict-default APIs that coexist
   with the Go-parity API are deleted; the surviving API takes the plain name.
3. **Go's behaviour is the default.** No `GO_*` variants of a default; a
   stricter or looser mode is an explicit option on the one type.
4. **Rust shape:**
   - `snake_case` functions, `CamelCase` types, `SCREAMING_CASE` constants, and
     no `go`/`GO` in any public identifier.
   - Constructors are `new`, `with_*`, `from_*`, `parse`, or `Default`; options
     with several fields use a builder or a `Default`-able config struct.
     Not Go's `new_reader`/`new_encoding`/`new_client`.
   - Errors are `Result<T, Error>` with a module `Error` type (enum where there
     are several kinds) implementing `std::error::Error`; absence is `Option`.
     Go's panics on misuse become errors.
   - Go interfaces become std traits where one exists (`Read`, `Write`,
     `BufRead`, `Seek`, `Iterator`, `Display`, `FromStr`, `From`, `Hash`) and
     small purpose-named traits otherwise.
   - `impl Display`, not `fn string(&self)`; `FromStr`/`TryFrom`, not
     `parse_x` helpers duplicating them; iterators, not callback walkers, where
     natural.
   - Byte-level APIs take `impl AsRef<[u8]>`; text APIs take `&str`. A Go string
     that may hold invalid UTF-8 is `&[u8]`/`Vec<u8>`, so no lossy conversion is
     needed.
5. **Scoreboard semantics.** A symbol mapped to a std item counts as mapped.
   `deviation` is only for a capability Rust cannot offer (Go runtime
   internals, `unsafe.Pointer` helpers, loading Go plugins). Shape differences
   that used to be deviations (`panic-to-result`, `nil-vs-empty`,
   `any-argument`, `go-string-invalid-utf8`) are the design, not deviations.
6. **Enforcement.** `tools/api_shape.py` (in the gate) fails on Go-shaped public
   identifiers. The Go differential suites stay; only the Rust probes in
   `examples/` change to the new API.

7. **Thin wrappers that carry Go's contract are Rust shape.** Where a Go
   behaviour has to be exact (for example `os` file operations returning Go's
   `PathError` text, `$PWD`-aware `getwd`, Go's `TMPDIR` rule), a function
   that delegates to std and returns `std::io::Error` with Go's payload is the
   design, not a leftover. A parallel API next to std's is not.

## Consequences

- Much less Rust code: whole modules disappear in favour of std.
- Every public API changes. The crate is pre-1.0 and unpublished, so no
  compatibility shims are kept.
- `encoding::base64` is the reference conversion; later conversions follow it.
