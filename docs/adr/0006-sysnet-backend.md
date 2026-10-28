# ADR 0006: sysnet backend

Status: **accepted** (lead decision under the maintainer's delegation, 2026-10-14).
Amended 2026-10-14: the `tls` feature, on by default (see Amendment).

## Context

Every Go program that uses `http.DefaultTransport` dials with
`net.Dialer{Timeout: 30s, KeepAlive: 30s}`, so its idle connections carry TCP
keep-alive probes. The first real application, farfield, needs that behaviour.
Two crates each hold half of it:

- The root crate (`rust-stdlib`) is `#![forbid(unsafe_code)]`, and `std` has no
  `SO_KEEPALIVE` setter, so its `net::Dialer` and its `DEFAULT_TRANSPORT`
  cannot enable keep-alive.
- `crates/sys` (`rust_stdlib_sys::net::Dialer`) can, with `keep_alive` and
  `keep_alive_config`. By ADR 0004 it must not depend on the root crate, and the
  root crate must not depend on it, so its connection types do not implement the
  root `net::Conn`, which `http::Transport::dial_context` requires.

Until now each user had to write an adapter between the two (the `Transport`
documentation described one), and had to know which fields make up Go's
`DefaultTransport`.

## Decision

Add a first-party crate, `backends/sysnet` (package `rust-stdlib-sysnet`, lib
`rust_stdlib_sysnet`), at the position of `backends/tls`: it depends on the root
crate and on `crates/sys`, both by path, and, behind the `tls` feature (see
Amendment), on `backends/tls`.

- `Conn` wraps `rust_stdlib_sys::net::Conn` (TCP, Unix, UDP, IP) and implements
  `rust_stdlib::net::Conn`: read, write, close, local and remote address,
  deadlines. `net_error` maps a sys `OpError` to the root `NetError` with Go's
  texts (`dial tcp 127.0.0.1:1: connect: connection refused`, `i/o timeout`,
  `use of closed network connection`, DNS errors).
- `dial_context(dialer)` turns a sys `Dialer` into a `Transport::dial_context`
  hook, adapting the root `Context` (deadline and cancellation) to the sys one.
- `transport()`, `default_transport()` and `default_client()` mirror Go's
  `http.DefaultTransport` and `DefaultClient` field by field: `Proxy` from the
  environment, a dialer with `Timeout` 30 s and `KeepAlive` 30 s,
  `ForceAttemptHTTP2`, `MaxIdleConns` 100, `IdleConnTimeout` 90 s,
  `TLSHandshakeTimeout` 10 s and `ExpectContinueTimeout` 1 s. `tools/sysnet_check.py`
  compares them with a Go oracle, including the keep-alive socket options read
  back from a dialed socket (idle 30 s; Go leaves the interval at its 15 s default).
- `#![forbid(unsafe_code)]`. All `unsafe` stays in `crates/sys`.
  `tools/dependency_policy.py` requires the source to forbid unsafe code and
  pins the manifest, its dependencies and its features (see Amendment).

The plain dial, with keep-alive, goes through this crate and the TLS backend
handshakes on the returned `Conn`.

## Amendment: the `tls` feature

The first version left TLS to the caller. That broke Go equivalence:
`http.DefaultClient` does HTTPS, while `default_client()` failed every `https`
request with "https requests need Transport.TLSClientConfig from a TLS
backend". Code ported from Go on the assumption that the default client speaks
HTTPS silently lost it (an AI call, a deploy hook, a CDN purge, revalidation).

`backends/sysnet` now has a cargo feature `tls`, **on by default**, with an
optional path dependency on `rust-stdlib-tls` (`../tls`). With it, `transport()`,
`default_transport()` and `default_client()` set `tls_client_config` to
`rust_stdlib_tls::tls::Config::new()`, which is what a nil `TLSClientConfig`
means in Go: the system roots as `x509.SystemCertPool` loads them (including
`SSL_CERT_FILE` and `SSL_CERT_DIR`), certificate and host name verification, the
default minimum version, and `h2` negotiated through ALPN because
`ForceAttemptHTTP2` is true. `TLSHandshakeTimeout` stays 10 s. The crate adds no
way to skip verification; callers who need other roots replace the config with
one that sets `root_cas`.

With `default-features = false` the crate is again first-party only and
http-only: `tls_client_config` stays `None`, `https` requests return the root
crate's explicit error, and the documentation of `default_client` says so.

Dependency graph. With the feature on, the crate's lock contains the TLS
adapter's graph: the same 25 external packages as `backends/tls` (Rustls 0.23.46
with `ring`, no native code) plus the four first-party packages. It has the
ledger `docs/sysnet-dependencies.json` and is checked like the TLS adapter's:
resolved identities, checksums, edges, features and licenses, and a pinned
feature table (`default = ["tls"]`, `tls = ["dep:rust-stdlib-tls"]`) with the
`rust-stdlib-tls` dependency required to be optional. The reviewed source
of the 25 packages remains the TLS ADR (0002); nothing new is admitted. The root
crate and `crates/sys` still have no third-party graph.

Why default-on. Go equivalence is the point of this crate: a default that cannot
do HTTPS is a silent behaviour difference. Applications that must stay
zero-third-party opt out explicitly.

Gates run the crate with default features and with `--no-default-features`
(clippy, tests, strict rustdoc).

## Alternatives

- **Root crate depends on `crates/sys`:** rejected. It would move the root's
  unsafe surface from "none" to "reachable" and break ADR 0004.
- **`crates/sys` depends on the root crate:** rejected by ADR 0004; sys is the
  leaf that both can be combined with.
- **A new kernel-level setter in `std` or a socket option on the root `Dialer`:**
  impossible without unsafe code.
- **Leave the adapter to each application:** every Go-shaped app would repeat
  it and could drift from `DefaultTransport`'s settings.
- **Put the adapter in `backends/tls`:** it would tie plain HTTP to Rustls and
  its 25-package graph (now only when the `tls` feature is on).
- **Keep TLS opt-in (feature off by default):** rejected; see Amendment.

## Consequences

- One more manifest, lock and gate steps (format, clippy, tests, doctests, strict
  rustdoc, the Go differential), each also without default features; no new
  third-party package beyond the TLS adapter's reviewed graph.
- `docs/sysnet-dependencies.json` and `docs/tls-dependencies.json` list the same
  25 external packages (checked identical by name, version and checksum); bump
  both locks and ledgers together when Rustls moves.
- The root crate's own `DEFAULT_TRANSPORT` stays without keep-alive; its
  documentation points here.
- Keep the field list in step with Go's `net/http/transport.go` at each Go
  upgrade; the differential fails when Go changes `DefaultTransport`.
