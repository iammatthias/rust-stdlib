# Verification

`python3 tools/check.py` is the complete offline gate. It must pass before a
change is committed. Results are written to `target/check-report.json`
(not committed); the report records a source SHA-256 and fails if source
changes during the run.

Prerequisites: stable Rust with rustfmt and clippy (the crates' MSRV is 1.87;
see docs/CI.md), Python 3.11+, Go, and a C compiler for ring. Provision the
pinned optional graphs once:

```sh
cargo fetch --locked --manifest-path backends/tls/Cargo.toml
cargo fetch --locked --manifest-path crates/crypto/Cargo.toml
cargo fetch --locked --manifest-path crates/sys/Cargo.toml   # no dependencies; a no-op
cargo fetch --locked --manifest-path fuzz/Cargo.toml
```

## What the gate checks

| Area | Check |
|---|---|
| Dependency policy | Manifest/lock contracts for the zero-dependency core and the pinned TLS/crypto/fuzz exceptions, plus policy regressions |
| Formatting | Core, TLS, crypto, sys, derive, derive consumer and fuzz packages |
| Cryptography | `crates/crypto` tests, clippy-clean build and examples, and the hash/MAC/KDF and cipher (modes, GCM, RC4) Go differentials in `tools/parity_check.py` |
| System interface | `crates/sys` (ADR 0004): clippy-clean build, tests and examples; the policy requires an empty dependency graph, `deny(unsafe_code)` at the root with `unsafe` only under `src/ffi` and a `// SAFETY:` comment on every block; `tools/sys_check.py` (in `tools/parity_check.py`) runs about 600 scenarios of identity, signals, `Chtimes`/`Link`, interfaces, socket options, message I/O, file deadlines, dialing and listening against Go; `tools/syscall_check.py` checks that the generated `syscall` files are current and diffs 2397 lines (constants, struct layouts, errno and signal text) between a Go linux/amd64 oracle (run in a `linux/amd64` container on other hosts, skipped with a message if there is no Linux runtime) and `examples/syscall_probe`. The raw-IP and `unixpacket` success paths need root or Linux and are exercised only on such hosts; Linux code paths are type-checked here by building a copy with the OS cfgs swapped, and run wherever the gate runs on Linux |
| Rust tests | All targets and doctests with default features, plus `--no-default-features`, plus the library and `tests/tzif.rs` with `--features tzdata` |
| Go differentials | Codecs, CSV/XML/binary, compression/archives, regex and the per-package oracles in `tools/parity_check.py`, each compared against the local Go toolchain |
| Derives | Real consumer tests and compiler diagnostics in `tools/derive-check` |
| HTTP/TLS | Python/Go interoperability, the TLS adapter tests and the complete web application |
| Docs | `cargo doc` |
| API parity | `tools/api_parity.py --check`: generated scoreboard is fresh and every mapped Rust path resolves |

Every crate, the fuzz targets and the derive consumer tests are also
clippy-clean with warnings denied, the root crate with default features, with
none and with `tzdata`. Coverage-guided fuzzing is separate; see
docs/FUZZING.md.

## Status

The full gate passes natively on macOS arm64 and Linux arm64 (Rust 1.99.0,
Go 1.27.1), and every crate builds and passes its tests on Rust 1.87.0. Linux
x86_64 and Windows have not yet run the gate natively; see docs/ROADMAP.md. A
pass describes tested behaviour, not an external security audit.
