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

The gate runs on stable. To check the MSRV as well, build and test every
crate on 1.87. Clippy and rustfmt run on stable only, because older clippy
releases flag lints that later releases dropped and warn on lint names they
don't know.

```sh
rustup toolchain install 1.87.0 --profile minimal
for m in Cargo.toml crates/sys/Cargo.toml crates/crypto/Cargo.toml \
    crates/derive/Cargo.toml backends/tls/Cargo.toml backends/sysnet/Cargo.toml; do
  cargo +1.87.0 test --offline --locked --all-targets --manifest-path "$m"
done
```

On Windows, use `python` if that is the installed Python command. A pass on
one platform does not establish a cross-platform pass.
