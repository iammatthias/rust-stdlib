# rust-stdlib

> This code has not been audited outside of Claude Code. Independent review and PRs are welcome. Use at your own risk.

Go 1.27's standard library for Rust. Every exported symbol of the 149 in-scope Go packages is implemented and checked against Go, or documented as a deviation. See the [scoreboard](docs/COVERAGE.md) and [roadmap](docs/ROADMAP.md).

## Crates

| Crate | Path | |
|---|---|---|
| `rust_stdlib` | `src/` | The standard library. Zero dependencies, no `unsafe`. |
| `rust_stdlib_crypto` | `crates/crypto/` | `crypto/*` over pinned RustCrypto crates. One feature per package (`sha256`, `hmac`, `ecdsa`, `x509`, ...), all on by default; `default-features = false` compiles only the packages you enable. |
| `rust_stdlib_tls` | `backends/tls/` | `crypto/tls` over rustls. |
| `rust_stdlib_sys` | `crates/sys/` | `syscall`, `os/signal` and other OS interfaces via libc. |
| `rust_stdlib_sysnet` | `backends/sysnet/` | `net/http` over `rust_stdlib_sys` sockets: Go's `DefaultTransport` with TCP keep-alive and, with the default `tls` feature, HTTPS via `rust_stdlib_tls`. |
| `rust_stdlib_derive` | `crates/derive/` | JSON, XML and `Reflect` derives. |

## Try it

```sh
cargo run --example http_server -- 127.0.0.1:8080 .
cargo run --example http_client -- http://127.0.0.1:8080/hello/world
```

## Verify

The Go and Python in `tools/` are the test harness: each package is checked by running the real Go standard library on the same inputs and comparing the results. None of it ships with the crates.

Requires Rust 1.87+, Go 1.27, Python 3.11+ and a C compiler.

```sh
cargo fetch --locked --manifest-path backends/tls/Cargo.toml
cargo fetch --locked --manifest-path crates/crypto/Cargo.toml
cargo fetch --locked --manifest-path fuzz/Cargo.toml
python3 tools/check.py
```

## Contributing

PRs are welcome but not guaranteed to be merged. Additional maintainers are welcome too (hey Omarchy Foundation, what's up). See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. Ported Go code and data are BSD-licensed; see [NOTICE](NOTICE).
