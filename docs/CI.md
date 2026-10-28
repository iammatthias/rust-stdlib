# Local builds

There is no hosted CI. Every change runs the complete gate locally before it
merges, and consumers vendor a pinned revision.

Run the complete gate locally before pushing; prerequisites and provisioning
are in VERIFICATION.md. Provision every pinned graph first:

```sh
cargo fetch --locked --manifest-path backends/tls/Cargo.toml
cargo fetch --locked --manifest-path crates/crypto/Cargo.toml
cargo fetch --locked --manifest-path fuzz/Cargo.toml
```

To check the MSRV as well as stable:

```sh
rustup toolchain install 1.87.0 --profile minimal --component rustfmt --component clippy
rustup override set 1.87.0
python3 tools/check.py
rustup override unset
python3 tools/check.py
```

On Windows, use `python` if that is the installed Python command. A pass on
one platform does not establish a cross-platform pass.
