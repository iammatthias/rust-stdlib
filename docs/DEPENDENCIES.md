# Dependency policy

## Current budget

The core's complete Cargo graph contains exactly the root package. Runtime,
development, build, optional and target-specific core tables remain empty.
The first-party derive crate also has zero external dependencies. Four isolated
exceptions have exact manifest and resolved graph contracts: the optional TLS
adapter, the sysnet adapter (whose default-on `tls` feature pulls in the TLS
adapter's graph; ledger docs/sysnet-dependencies.json, ADR 0006), the
cryptography crate and the development-only fuzz workspace. None
alters the core graph.

Rust's toolchain, standard library and platform runtime are the baseline. Zero third-party Cargo packages does not mean a native executable has no operating-system or toolchain-provided runtime libraries.

`tools/dependency_policy.py` checks every repository manifest and the lockfile, rejects build scripts and source placeholders, and requires the unsafe-code lint. With `--metadata`, it also checks Cargo's resolved all-features graph. The source-pattern checks are an additional guard; compiler lints and code review remain required.

```sh
python3 tools/dependency_policy.py
python3 tools/dependency_policy.py --metadata
cargo tree --offline --locked --all-features
```

The first command is usable without a Rust compiler. It verifies declarations; Cargo graph verification is a separate result.

A lock keeps a yanked version building here, but a crate that depends on one
of ours by path resolves without that lock and cannot select a yanked `=` pin.
`python3 tools/yank_check.py` checks every direct pin against the crates.io
index. It needs the network, so it runs on demand rather than in the offline
gate. `python3 tools/dependency_ledger.py <manifest>` rewrites an exception
ledger's packages and resolved graph from its lock after a reviewed update,
keeping the hand-written keys.

## Exception process

Each proposed exception requires a checked-in decision record covering purpose, public API exposure, alternatives, complete transitive graph, native linkage, license/provenance, security ownership, update policy, reproducible lockfile and feature selection. CI allowlists must name the reviewed package versions. No implicit permission is granted to add a TLS dependency.

The TLS decision is docs/adr/0002-explicit-tls-adapter.md; its ledger is
docs/tls-dependencies.json. The cryptography decision is
docs/adr/0003-vendored-cryptography.md; `crates/crypto` (93 pinned external
packages from the RustCrypto project and platform glue, no native code) has the
ledger docs/crypto-dependencies.json and its own `Cargo.lock`, and the root
never depends on it. Fuzz instrumentation, native build tools and
findings are recorded in docs/FUZZING.md and docs/fuzz-dependencies.json.
Policy checks full resolved identities, checksums, edges/features and licenses.
Unknown manifests, build scripts, overrides, source symlinks, unsafe/FFI and
foreign first-party paths fail. Every first-party crate forbids unsafe code.

## Development infrastructure

Python 3.11+ runs manifest checks and orchestration through its standard library. Go runs comparison and interoperability drivers using its standard library. GitHub Actions provision those toolchains and Rust; CI actions and toolchain installation involve external infrastructure and are outside the application graph. Pin action revisions and toolchain releases according to the eventual release policy.

No downloads occur in the library build/test commands; Cargo runs with `--offline --locked`. Provision toolchains before running the gate.
