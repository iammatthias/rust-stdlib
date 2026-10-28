# Coverage-guided parser fuzzing

The isolated `fuzz/` Cargo workspace depends on the root crate and exactly
`libfuzzer-sys = 0.4.13`. Production dependencies remain empty. The complete
locked graph, registry checksums, licenses and dependency edges are recorded in
`docs/fuzz-dependencies.json`. External fuzzing code includes C++ libFuzzer,
native compiler tooling and Rust FFI; this development-only exception does not
change the root crate's unsafe, FFI or build-script prohibition. Target source
forbids authored unsafe code.

## Run

Install nightly Rust and the locked fuzz workspace packages, then run:

```sh
python3 tools/fuzz.py --seconds 60
```

The runner performs an offline locked instrumented build and runs three
campaigns concurrently. Nightly is selected through `RUSTUP_TOOLCHAIN`. LLVM
SanitizerCoverage adds inline counters, PC tables and comparison feedback;
libFuzzer mutates seeded inputs according to this feedback. Explicit
`--target` keeps host build scripts uninstrumented. This runner also works
without a cargo-fuzz executable. A C++ compiler is required by libfuzzer-sys.

Each input is limited to 8192 bytes, each input invocation has a five-second
watchdog, and each process has a 512 MiB RSS limit. Decompressed output is
limited to 65536 bytes. Generated corpora, logs, artifacts and machine-readable
reports are written under ignored `fuzz/runs/`. Static seeds live in
`fuzz/corpus/` and are committed. Reproduction of a reported crash uses the
built binary with its saved artifact path as the sole input argument.

## Targets

| Target | Exercised APIs |
| --- | --- |
| text | JSON parser and semantic serialization round trip; CSV record parser; XML token/namespace/tree parsing; typed text and HTML control-flow/pipelines/functions; context-aware HTML templates; JavaScript/CSS string escaping; bounded regex construction/search |
| protocol | HTTP request/response wire parsers; multipart/form-data; MIME parsing/serialization; Cookie and Set-Cookie parsing; cookie jar storage and lookup; incremental multipart reader; URL/query/percent codecs |
| binary | raw DEFLATE, gzip and zlib buffered/streaming decoders; tar and ZIP readers; hex and all four Base64 buffered/streaming codecs with encoder/decoder round trips; signed/unsigned binary varint round trips |

These runs check panics, bounded-operation failures and explicit semantic
invariants. They do not use AddressSanitizer or ThreadSanitizer. Coverage counts
are observed instrumented edges/features, not a percentage of all paths.
Short campaigns are smoke hardening evidence; they do not prove protocol
compliance or replace long-running fuzzing and differential tests.

Reference: https://llvm.org/docs/LibFuzzer.html
