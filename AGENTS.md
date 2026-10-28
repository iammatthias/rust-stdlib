# AGENTS.md

Instructions for AI coding agents and contributors working in this repository.

## What this is

`rust-stdlib` gives Rust parity with Go 1.27's standard library. Every exported
symbol of the 149 in-scope Go packages is either implemented and checked
against Go, or recorded as a documented deviation. The scoreboard is
`docs/COVERAGE.md`; the status and known limits are in `docs/ROADMAP.md`.

## Layout

There is no Cargo workspace: each crate has its own manifest, lock file and
`target/`, and is built with `--manifest-path`.

| Path | Crate | Notes |
|---|---|---|
| `src/` | `rust-stdlib` (`rust_stdlib`) | Zero third-party dependencies, `#![forbid(unsafe_code)]` |
| `crates/crypto/` | `rust-stdlib-crypto` | `crypto/*` over pinned, reviewed RustCrypto crates; one Cargo feature per package, `full` by default (ADR 0003) |
| `backends/tls/` | `rust-stdlib-tls` | `crypto/tls` over rustls with ring (ADR 0002) |
| `crates/sys/` | `rust-stdlib-sys` | libc FFI for `syscall`, `os/signal` and socket/process gaps (ADR 0004) |
| `backends/sysnet/` | `rust-stdlib-sysnet` | Runs `net/http` over `crates/sys` sockets: sys-to-`net.Conn` adapter, `DefaultTransport` with TCP keep-alive; HTTPS through optional default-on `tls` feature (`rust-stdlib-tls` graph), first-party only without it (ADR 0006) |
| `crates/derive/` | `rust-stdlib-derive` | First-party derives (JSON, XML, Reflect, embed); no parser dependencies |
| `fuzz/` | fuzz targets | Development only; see `docs/FUZZING.md` |
| `tools/` | Python and Go tooling | The gate, Go oracles, differentials, generators |
| `docs/api/` | per-package symbol maps | Ground truth for the scoreboard |
| `docs/adr/` | decision records | Read before changing dependencies, FFI or crypto |
| `docs/diagrams/` | diagrams | HTML sources and the SVGs the docs embed |

## Rules

- The root crate has no third-party dependencies of any kind. Third-party
  crates are allowed only inside the `crates/crypto` and `backends/tls` graphs,
  with exact pins and an updated ledger (`docs/*-dependencies.json`).
- `unsafe` and FFI live only in `crates/sys` (inside `src/ffi`), with a
  `// SAFETY:` comment on every block.
- No first-party cryptographic primitives or constructions; use the reviewed
  crates. Never disable certificate validation or downgrade HTTPS.
- The API is Rust-shaped, not Go-shaped (ADR 0005): where std already does the
  job, map the Go symbol to std instead of re-implementing it; otherwise follow
  `encoding::base64` as the template. `tools/api_shape.py --verbose` lists the
  remaining Go-shaped items, and the gate fails if their count grows.
- Go's documented behaviour is the default. A behaviour difference must be
  recorded in `docs/api/<package>.json`, as `differs` (fixable, blocks
  `complete`) or `deviation` (Rust cannot express it), never only in prose.
- Resource limits are configurable budgets whose defaults do not change results
  on Go's own tests.
- No `todo!()`/`unimplemented!()` in production code, no async runtime, public
  I/O through `std::io` traits.
- Do not report a test as passing unless it ran and passed.

## Commands

Provision the pinned graphs once (the gate runs offline):

```sh
cargo fetch --locked --manifest-path backends/tls/Cargo.toml
cargo fetch --locked --manifest-path crates/crypto/Cargo.toml
cargo fetch --locked --manifest-path fuzz/Cargo.toml
```

Day to day:

```sh
cargo test --offline --locked --test <name>          # one test file
python3 tools/<name>_check.py                         # one Go differential
python3 tools/api_parity.py                           # regenerate the scoreboard
python3 tools/api_parity.py --check                   # freshness + rustdoc link check
cargo fmt
cargo clippy --all-targets --offline --locked -- -D warnings
cargo clippy --no-default-features --all-targets --offline --locked -- -D warnings
python3 tools/check.py                                # the full gate; must pass before a PR
```

Online, outside the gate: `python3 tools/yank_check.py` fails when a direct
pin is yanked on crates.io (a path-dependent crate resolves without our lock and
cannot select it). Run it when bumping a dependency. After a reviewed
`cargo update` in an exception graph, `python3 tools/dependency_ledger.py
<manifest>` rewrites that ledger's packages and resolved graph from the lock.

Requirements: Rust 1.87+, Go 1.27, Python 3.11+, a C compiler (for ring).
On a busy machine, `export CARGO_BUILD_JOBS=4`. The gate fails if source changes
while it runs, so don't edit files during it. It writes its report to
`target/check-report.json`; never commit logs, reports or build output.

## Making a change

1. Branch from `main`; `main` only changes through squash-merged pull requests.
2. For Go-facing behaviour, follow `docs/PARITY_WORKFLOW.md`: tests in
   `tests/<module>.rs` (port Go's `*_test.go` tables where practical), a Go
   oracle and Rust probe registered in `tools/parity_check.py`, and the symbol
   map in `docs/api/<package>.json`.
3. Bring in `main` with `git merge main`; never reset, squash over, or rebuild a
   branch from a saved tree. Before opening the PR,
   `git diff main --stat --diff-filter=D` must list only files you meant to
   delete.
4. Run the full gate and fill in the PR template.

Changes to dependencies, FFI, crypto or the TLS adapter need an updated ADR in
`docs/adr/` and the matching dependency-policy tests (`tools/policy_tests.py`).
