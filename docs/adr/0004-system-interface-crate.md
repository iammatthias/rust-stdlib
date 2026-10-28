# ADR 0004: system interface crate

Status: **accepted** (lead decision under the maintainer's delegation, 2026-10-12).
Implemented; `syscall` landed 2026-10-13 as `rust_stdlib_sys::syscall`.

## Context

Some Go packages need operating-system interfaces that Rust's std does not
expose: `syscall`, `os/signal`, network interface enumeration
(`net.Interfaces`), socket options such as `SO_LINGER`, and a few `os`
functions. Go reaches them through its runtime. The maintainer allows no new
third-party dependencies except cryptography, so the `libc` crate is out.

## Decision

Add a first-party crate, `crates/sys` (`rust_stdlib_sys`), that declares the C
functions it needs with hand-written `extern "C"` blocks against the platform's
own C library. This adds no dependency: Rust's std already links the same
library and calls it the same way.

- `#![deny(unsafe_code)]` at the crate root, with `#[allow(unsafe_code)]` only on
  the small modules that wrap foreign calls. Every `unsafe` block carries a
  `// SAFETY:` comment stating the invariants it relies on.
- Bindings cover only what a mapped Go symbol needs. Constants and struct
  layouts are per target behind `cfg`, with Linux and macOS supported; other
  targets return Go's `ENOSYS`-style errors.
- The root crate keeps `#![forbid(unsafe_code)]` and does not depend on this
  crate. Go symbols that need it are mapped to `rust_stdlib_sys::` paths, which
  the API parity scoreboard verifies like the crypto and TLS crates.
- `tools/dependency_policy.py` allows `deny(unsafe_code)` and FFI only in this
  manifest, and the crate must keep an empty dependency graph.

## Consequences and related calls

- `syscall` is implemented last: its surface is mostly linux/amd64 constants,
  generated from Go's `zerrors_linux_amd64.go` and `zsysnum_linux_amd64.go` with
  `go/parser` rather than typed by hand, plus raw `Syscall`/`Syscall6`.
  `tools/gen_syscall.go` also generates the struct layouts and every zsyscall
  wrapper; the Linux numbers are used as is on linux/x86_64 and elsewhere only a
  portable subset runs (the rest fails with `ENOSYS`), so `syscall.Errno` has its
  own Linux tables and never takes a host's numbers.
- `plugin` is a permanent deviation (`go-runtime-plugin`): it loads Go-built
  shared objects into a Go runtime, which has no meaning for Rust.
- `reflect` is implemented with a first-party `#[derive(Reflect)]` that emits
  type information, not through runtime introspection. `MakeFunc` and the
  pointer-header types are deviations.
