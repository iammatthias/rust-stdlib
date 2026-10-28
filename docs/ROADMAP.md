# Roadmap

## Status

Every exported symbol of the 149 in-scope Go 1.27 packages is accounted for.
Each one maps to a Rust item whose behaviour the Go differential suites check,
or it carries a documented deviation. `docs/COVERAGE.md` has the current
counts and the deviations by code; `tools/api_parity.py` generates it, and the
gate fails when it is stale. The 31 compiler, runtime and tooling packages
(`go/*`, `runtime/*`, `debug/*`, `unsafe`, `builtin`, `structs`) are out of
scope.

A deviation is a Go behaviour that Rust cannot express or that the project
deliberately does not copy. The largest groups are TLS options rustls refuses,
Go strings that may hold invalid UTF-8 where a Rust `String` cannot, Go's
`any` arguments, platform-specific float results, and std's `Read` contract.
Two are kept on purpose for security: ed25519 signing rejects a key whose
public half does not match its seed, and multi-prime RSA keys get full
validation.

Decisions are recorded in `docs/adr/`: a zero-dependency root crate (0001),
the rustls/ring TLS adapter (0002), cryptography only through reviewed crates
with no first-party constructions (0003), FFI confined to `crates/sys` (0004),
a Rust-shaped API with Go's behaviour (0005), and the `sysnet` backend that
joins the root crate to the system crate (0006). `docs/ARCHITECTURE.md` draws
the crate graph.

## Known limits

- **Platforms.** The full gate passes natively on macOS arm64 and Linux arm64
  (Ubuntu, rustc 1.99, Go 1.27.1). Linux x86_64 compiles and passes clippy but
  has no native gate run. Windows does not build: `os` is Unix-only, and
  `net::http::cgi` and the backends depend on it, so a Windows port starts
  with `os`.
- **Timing-sensitive checks.** Some differentials depend on scheduling or host
  state (macOS socket buffer autotuning, VM network interfaces, clocks). They
  resample or wait on events, which makes failures rare rather than
  impossible. The `httptrace` races found so far (scripted HTTP/1 idle timeout,
  h2c `Expect: 100-continue` timeout, and response-body `Close` racing the
  peer's `RST_STREAM`, which Go's own client also loses about 1 in 600 runs)
  are fixed by waiting on events, identically in the Go oracle and the Rust
  probe. Two cannot be waited out. Go's HTTP/2 transport reports
  `WroteRequest` as nil or "aborting request body write" depending on whether
  the response or the body writer finishes first, so h2c compares the two as
  one value. A pipelined HTTP/1 server vector that misses the 150ms read
  window under load is rerun on both sides with a 2s window.
- **API shape.** The shape lint finds no Go-shaped public items. `netip::Addr`
  wraps `std::net::IpAddr` plus a zone and delegates to std where std's stable
  behaviour matches Go; IPv6 link-local and unique-local checks stay ours
  until std stabilises them. `os` keeps Go's error contract as thin wrappers
  over std (ADR 0005, item 7).
  The TLS adapter carries its own small X.509 reader and system-root loader
  because its lock graph cannot share `crates/crypto` (`getrandom`/`zeroize`
  versions differ).
- **Dependencies to revisit.** `rsa 0.10` and `p224 0.14` are release
  candidates, and `rsa` carries the unpatched RUSTSEC-2023-0071 timing advisory
  (documented in its module).

## Before 1.0

Run the full gate natively on Linux x86_64 and Windows; remove the
TLS crate's duplicate X.509 reader; replace the release-candidate crypto crates
when stable versions exist; settle semver and MSRV commitments; configure
private vulnerability reporting and assign release ownership. Publishing stays
disabled until then.
