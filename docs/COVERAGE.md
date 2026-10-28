# Go API parity

Surface: every exported symbol of the in-scope Go go1.27.1 packages (linux/amd64), from `docs/api/go-surface.json`. A symbol counts only when its Rust mapping in `docs/api/<package>.json` compiles (`tests/api_surface.rs`) or it has a documented deviation. Behavioural equivalence is checked separately by the Go differential suites.

Regenerate with `python3 tools/api_parity.py`.

**9746 / 9746 symbols accounted for (100.0%)**: 9328 mapped (0 unreviewed bootstrap guesses, 0 with known behaviour differences), 418 documented deviations, 0 missing.

Packages: 149 complete, 0 partial, 0 planned, 31 out-of-scope.

| Go package | Status | Mapped | Unreviewed | Differs | Deviations | Missing | Total |
|---|---|---:|---:|---:|---:|---:|---:|
| `archive/tar` | complete | 55 | 0 | 0 | 4 | 0 | 59 |
| `archive/zip` | complete | 60 | 0 | 0 | 1 | 0 | 61 |
| `bufio` | complete | 47 | 0 | 0 | 12 | 0 | 59 |
| `bytes` | complete | 95 | 0 | 0 | 5 | 0 | 100 |
| `cmp` | complete | 4 | 0 | 0 | 0 | 0 | 4 |
| `compress/bzip2` | complete | 2 | 0 | 0 | 1 | 0 | 3 |
| `compress/flate` | complete | 29 | 0 | 0 | 0 | 0 | 29 |
| `compress/gzip` | complete | 28 | 0 | 0 | 0 | 0 | 28 |
| `compress/lzw` | complete | 13 | 0 | 0 | 0 | 0 | 13 |
| `compress/zlib` | complete | 20 | 0 | 0 | 0 | 0 | 20 |
| `container/heap` | complete | 8 | 0 | 0 | 0 | 0 | 8 |
| `container/list` | complete | 18 | 0 | 0 | 3 | 0 | 21 |
| `container/ring` | complete | 10 | 0 | 0 | 0 | 0 | 10 |
| `context` | complete | 19 | 0 | 0 | 2 | 0 | 21 |
| `crypto` | complete | 47 | 0 | 0 | 0 | 0 | 47 |
| `crypto/aes` | complete | 4 | 0 | 0 | 0 | 0 | 4 |
| `crypto/cipher` | complete | 33 | 0 | 0 | 1 | 0 | 34 |
| `crypto/des` | complete | 5 | 0 | 0 | 0 | 0 | 5 |
| `crypto/dsa` | complete | 18 | 0 | 0 | 2 | 0 | 20 |
| `crypto/ecdh` | complete | 23 | 0 | 0 | 0 | 0 | 23 |
| `crypto/ecdsa` | complete | 17 | 0 | 0 | 5 | 0 | 22 |
| `crypto/ed25519` | complete | 17 | 0 | 0 | 3 | 0 | 20 |
| `crypto/elliptic` | complete | 25 | 0 | 0 | 5 | 0 | 30 |
| `crypto/fips140` | complete | 2 | 0 | 0 | 2 | 0 | 4 |
| `crypto/hkdf` | complete | 3 | 0 | 0 | 0 | 0 | 3 |
| `crypto/hmac` | complete | 1 | 0 | 0 | 1 | 0 | 2 |
| `crypto/hpke` | complete | 38 | 0 | 0 | 13 | 0 | 51 |
| `crypto/md5` | complete | 4 | 0 | 0 | 0 | 0 | 4 |
| `crypto/mldsa` | complete | 32 | 0 | 0 | 0 | 0 | 32 |
| `crypto/mlkem` | complete | 28 | 0 | 0 | 0 | 0 | 28 |
| `crypto/mlkem/mlkemtest` | complete | 2 | 0 | 0 | 0 | 0 | 2 |
| `crypto/pbkdf2` | complete | 1 | 0 | 0 | 0 | 0 | 1 |
| `crypto/rand` | complete | 5 | 0 | 0 | 0 | 0 | 5 |
| `crypto/rc4` | complete | 6 | 0 | 0 | 0 | 0 | 6 |
| `crypto/rsa` | complete | 48 | 0 | 0 | 4 | 0 | 52 |
| `crypto/sha1` | complete | 4 | 0 | 0 | 0 | 0 | 4 |
| `crypto/sha256` | complete | 7 | 0 | 0 | 0 | 0 | 7 |
| `crypto/sha3` | complete | 29 | 0 | 0 | 3 | 0 | 32 |
| `crypto/sha512` | complete | 13 | 0 | 0 | 0 | 0 | 13 |
| `crypto/subtle` | complete | 7 | 0 | 0 | 1 | 0 | 8 |
| `crypto/tls` | complete | 187 | 0 | 0 | 78 | 0 | 265 |
| `crypto/x509` | complete | 252 | 0 | 0 | 9 | 0 | 261 |
| `crypto/x509/pkix` | complete | 49 | 0 | 0 | 0 | 0 | 49 |
| `database/sql` | complete | 152 | 0 | 0 | 6 | 0 | 158 |
| `database/sql/driver` | complete | 98 | 0 | 0 | 3 | 0 | 101 |
| `embed` | complete | 4 | 0 | 0 | 0 | 0 | 4 |
| `encoding` | complete | 12 | 0 | 0 | 0 | 0 | 12 |
| `encoding/ascii85` | complete | 7 | 0 | 0 | 0 | 0 | 7 |
| `encoding/asn1` | complete | 46 | 0 | 0 | 5 | 0 | 51 |
| `encoding/base32` | complete | 18 | 0 | 0 | 1 | 0 | 19 |
| `encoding/base64` | complete | 22 | 0 | 0 | 0 | 0 | 22 |
| `encoding/binary` | complete | 30 | 0 | 0 | 3 | 0 | 33 |
| `encoding/csv` | complete | 32 | 0 | 0 | 0 | 0 | 32 |
| `encoding/gob` | complete | 16 | 0 | 0 | 1 | 0 | 17 |
| `encoding/hex` | complete | 15 | 0 | 0 | 0 | 0 | 15 |
| `encoding/json` | complete | 74 | 0 | 0 | 8 | 0 | 82 |
| `encoding/json/jsontext` | complete | 94 | 0 | 0 | 9 | 0 | 103 |
| `encoding/json/v2` | complete | 31 | 0 | 0 | 14 | 0 | 45 |
| `encoding/pem` | complete | 7 | 0 | 0 | 0 | 0 | 7 |
| `encoding/xml` | complete | 78 | 0 | 0 | 4 | 0 | 82 |
| `errors` | complete | 7 | 0 | 0 | 0 | 0 | 7 |
| `expvar` | complete | 33 | 0 | 0 | 6 | 0 | 39 |
| `flag` | complete | 85 | 0 | 0 | 3 | 0 | 88 |
| `fmt` | complete | 39 | 0 | 0 | 4 | 0 | 43 |
| `hash` | complete | 14 | 0 | 0 | 0 | 0 | 14 |
| `hash/adler32` | complete | 3 | 0 | 0 | 0 | 0 | 3 |
| `hash/crc32` | complete | 12 | 0 | 0 | 0 | 0 | 12 |
| `hash/crc64` | complete | 8 | 0 | 0 | 0 | 0 | 8 |
| `hash/fnv` | complete | 6 | 0 | 0 | 0 | 0 | 6 |
| `hash/maphash` | complete | 24 | 0 | 0 | 0 | 0 | 24 |
| `html` | complete | 2 | 0 | 0 | 0 | 0 | 2 |
| `html/template` | complete | 57 | 0 | 0 | 3 | 0 | 60 |
| `image` | complete | 262 | 0 | 0 | 1 | 0 | 263 |
| `image/color` | complete | 77 | 0 | 0 | 1 | 0 | 78 |
| `image/color/palette` | complete | 2 | 0 | 0 | 0 | 0 | 2 |
| `image/draw` | complete | 16 | 0 | 0 | 0 | 0 | 16 |
| `image/gif` | complete | 16 | 0 | 0 | 3 | 0 | 19 |
| `image/jpeg` | complete | 10 | 0 | 0 | 1 | 0 | 11 |
| `image/png` | complete | 18 | 0 | 0 | 2 | 0 | 20 |
| `index/suffixarray` | complete | 6 | 0 | 0 | 1 | 0 | 7 |
| `io` | complete | 79 | 0 | 0 | 4 | 0 | 83 |
| `io/fs` | complete | 81 | 0 | 0 | 0 | 0 | 81 |
| `io/ioutil` | complete | 8 | 0 | 0 | 0 | 0 | 8 |
| `iter` | complete | 4 | 0 | 0 | 0 | 0 | 4 |
| `log` | complete | 40 | 0 | 0 | 3 | 0 | 43 |
| `log/slog` | complete | 151 | 0 | 0 | 3 | 0 | 154 |
| `log/syslog` | complete | 43 | 0 | 0 | 0 | 0 | 43 |
| `maps` | complete | 10 | 0 | 0 | 0 | 0 | 10 |
| `math` | complete | 90 | 0 | 0 | 7 | 0 | 97 |
| `math/big` | complete | 170 | 0 | 0 | 1 | 0 | 171 |
| `math/bits` | complete | 50 | 0 | 0 | 0 | 0 | 50 |
| `math/cmplx` | complete | 18 | 0 | 0 | 9 | 0 | 27 |
| `math/rand` | complete | 41 | 0 | 0 | 2 | 0 | 43 |
| `math/rand/v2` | complete | 60 | 0 | 0 | 0 | 0 | 60 |
| `mime` | complete | 12 | 0 | 0 | 2 | 0 | 14 |
| `mime/multipart` | complete | 33 | 0 | 0 | 0 | 0 | 33 |
| `mime/quotedprintable` | complete | 8 | 0 | 0 | 0 | 0 | 8 |
| `net` | complete | 357 | 0 | 0 | 11 | 0 | 368 |
| `net/http` | complete | 397 | 0 | 0 | 9 | 0 | 406 |
| `net/http/cgi` | complete | 14 | 0 | 0 | 0 | 0 | 14 |
| `net/http/cookiejar` | complete | 8 | 0 | 0 | 1 | 0 | 9 |
| `net/http/fcgi` | complete | 4 | 0 | 0 | 0 | 0 | 4 |
| `net/http/httptest` | complete | 31 | 0 | 0 | 0 | 0 | 31 |
| `net/http/httptrace` | complete | 32 | 0 | 0 | 0 | 0 | 32 |
| `net/http/httputil` | complete | 44 | 0 | 0 | 0 | 0 | 44 |
| `net/http/pprof` | complete | 1 | 0 | 0 | 5 | 0 | 6 |
| `net/mail` | complete | 17 | 0 | 0 | 3 | 0 | 20 |
| `net/netip` | complete | 75 | 0 | 0 | 5 | 0 | 80 |
| `net/rpc` | complete | 50 | 0 | 0 | 5 | 0 | 55 |
| `net/rpc/jsonrpc` | complete | 5 | 0 | 0 | 0 | 0 | 5 |
| `net/smtp` | complete | 23 | 0 | 0 | 4 | 0 | 27 |
| `net/textproto` | complete | 40 | 0 | 0 | 7 | 0 | 47 |
| `net/url` | complete | 53 | 0 | 0 | 9 | 0 | 62 |
| `os` | complete | 190 | 0 | 0 | 8 | 0 | 198 |
| `os/exec` | complete | 38 | 0 | 0 | 2 | 0 | 40 |
| `os/signal` | complete | 3 | 0 | 0 | 3 | 0 | 6 |
| `os/user` | complete | 23 | 0 | 0 | 0 | 0 | 23 |
| `path` | complete | 8 | 0 | 0 | 1 | 0 | 9 |
| `path/filepath` | complete | 27 | 0 | 0 | 0 | 0 | 27 |
| `plugin` | complete | 0 | 0 | 0 | 4 | 0 | 4 |
| `reflect` | complete | 203 | 0 | 0 | 24 | 0 | 227 |
| `regexp` | complete | 49 | 0 | 0 | 0 | 0 | 49 |
| `regexp/syntax` | complete | 110 | 0 | 0 | 3 | 0 | 113 |
| `slices` | complete | 38 | 0 | 0 | 2 | 0 | 40 |
| `sort` | complete | 40 | 0 | 0 | 0 | 0 | 40 |
| `strconv` | complete | 42 | 0 | 0 | 1 | 0 | 43 |
| `strings` | complete | 83 | 0 | 0 | 0 | 0 | 83 |
| `sync` | complete | 42 | 0 | 0 | 4 | 0 | 46 |
| `sync/atomic` | complete | 94 | 0 | 0 | 0 | 0 | 94 |
| `syscall` | complete | 2561 | 0 | 0 | 8 | 0 | 2569 |
| `testing` | complete | 155 | 0 | 0 | 13 | 0 | 168 |
| `testing/cryptotest` | complete | 0 | 0 | 0 | 1 | 0 | 1 |
| `testing/fstest` | complete | 15 | 0 | 0 | 0 | 0 | 15 |
| `testing/iotest` | complete | 8 | 0 | 0 | 2 | 0 | 10 |
| `testing/quick` | complete | 14 | 0 | 0 | 7 | 0 | 21 |
| `testing/slogtest` | complete | 2 | 0 | 0 | 0 | 0 | 2 |
| `testing/synctest` | complete | 0 | 0 | 0 | 3 | 0 | 3 |
| `text/scanner` | complete | 38 | 0 | 0 | 1 | 0 | 39 |
| `text/tabwriter` | complete | 12 | 0 | 0 | 0 | 0 | 12 |
| `text/template` | complete | 35 | 0 | 0 | 2 | 0 | 37 |
| `text/template/parse` | complete | 192 | 0 | 0 | 0 | 0 | 192 |
| `time` | complete | 140 | 0 | 0 | 5 | 0 | 145 |
| `time/tzdata` | complete | 0 | 0 | 0 | 0 | 0 | 0 |
| `unicode` | complete | 324 | 0 | 0 | 0 | 0 | 324 |
| `unicode/utf16` | complete | 7 | 0 | 0 | 0 | 0 | 7 |
| `unicode/utf8` | complete | 19 | 0 | 0 | 0 | 0 | 19 |
| `unique` | complete | 3 | 0 | 0 | 0 | 0 | 3 |
| `uuid` | complete | 13 | 0 | 0 | 0 | 0 | 13 |
| `weak` | complete | 3 | 0 | 0 | 0 | 0 | 3 |

## Deviations by code

A combined code such as `a+b` counts toward each part. The meaning of each deviation is in the `note` of its entry in `docs/api/<package>.json`.

| Code | Symbols |
|---|---:|
| `rustls-policy` | 75 |
| `go-string-invalid-utf8` | 50 |
| `reflection` | 29 |
| `platform-float` | 17 |
| `io-read-contract` | 12 |
| `dependency-no-pq-hpke` | 11 |
| `interface-assertion` | 11 |
| `dependency-custom-curves` | 10 |
| `default-budget` | 7 |
| `go-runtime-header` | 7 |
| `no-raw-memory` | 7 |
| `call-stack` | 6 |
| `crypto-tls-config` | 6 |
| `deadline-polling` | 6 |
| `instant-no-zone` | 6 |
| `thread-not-goroutine` | 6 |
| `go-runtime-profiles` | 5 |
| `reflect-copy` | 5 |
| `type-name-text` | 5 |
| `wrapper-identity` | 5 |
| `go-runtime-plugin` | 4 |
| `go-unsafe-pointer` | 4 |
| `no-nil-empty` | 4 |
| `no-platform-verifier` | 4 |
| `closed-interface` | 3 |
| `dependency-state-private` | 3 |
| `fake-runtime` | 3 |
| `native-stack-recursion` | 3 |
| `panic-payload-clone` | 3 |
| `runtime-memstats` | 3 |
| `rusage-unavailable` | 3 |
| `tls-config-hook` | 3 |
| `buffering-granularity` | 2 |
| `deadlock-in-do` | 2 |
| `decode-builds-value` | 2 |
| `dependency-dsa-sizes` | 2 |
| `dependency-no-first-party-construction` | 2 |
| `go-runtime-all-threads` | 2 |
| `go-runtime-signal-defaults` | 2 |
| `hash-identifier` | 2 |
| `mismatched-public-half-rejected` | 2 |
| `no-coverage-runtime` | 2 |
| `no-fips-module` | 2 |
| `panic-hook-output` | 2 |
| `read-n-err` | 2 |
| `rust-ownership` | 2 |
| `self-aliasing` | 2 |
| `slice-capacity-view` | 2 |
| `stdout-capture` | 2 |
| `storage-arrays` | 2 |
| `stricter-key-validation` | 2 |
| `syscall-sysprocattr` | 2 |
| `token-lifetime` | 2 |
| `untyped-interface` | 2 |
| `vec-capacity` | 2 |
| `blocked-copier-abandoned` | 1 |
| `borrowed-subtests` | 1 |
| `channel-capacity` | 1 |
| `context-crate-boundary` | 1 |
| `copied-bytes` | 1 |
| `coverage-guided-fuzzing` | 1 |
| `cpu-mode-unavailable` | 1 |
| `crypto-hook` | 1 |
| `crypto-test-guard` | 1 |
| `default-serve-mux` | 1 |
| `dependency-hash-set` | 1 |
| `dependency-hpke-suites` | 1 |
| `dependency-multi-prime-keygen` | 1 |
| `dependency-no-constant-time-session-key` | 1 |
| `dependency-no-ed25519ctx` | 1 |
| `dependency-nonce-sizes` | 1 |
| `dyn-eq` | 1 |
| `element-ownership` | 1 |
| `error-at-construction` | 1 |
| `fmt-pointer-verb` | 1 |
| `folded-interface` | 1 |
| `go-panics` | 1 |
| `go-slow-path-bug` | 1 |
| `godebug-randseednop` | 1 |
| `idat-tail-bytes` | 1 |
| `idna-mapping-tables` | 1 |
| `internal-export` | 1 |
| `invalid-utf8-string` | 1 |
| `local-not-reassignable` | 1 |
| `method-addressability` | 1 |
| `nil-color` | 1 |
| `nil-map` | 1 |
| `no-ffi-in-root` | 1 |
| `no-goroot-fallback` | 1 |
| `no-native-closure` | 1 |
| `no-specialization` | 1 |
| `no-time-codec` | 1 |
| `no-wait-by-pid` | 1 |
| `no-windows-registry` | 1 |
| `panic-poisons` | 1 |
| `panic-stack-trace` | 1 |
| `partial-option` | 1 |
| `per-target-constant` | 1 |
| `raw-syscall-conn` | 1 |
| `read-corrupt-state` | 1 |
| `reentrant-mutation` | 1 |
| `registered-method-sets` | 1 |
| `relative-source-path` | 1 |
| `runtime-function-names` | 1 |
| `seed-stream` | 1 |
| `sizeof-padding` | 1 |
| `v1-error-types` | 1 |
| `value-semantics` | 1 |
| `webpki-distrust` | 1 |
| `zero-write-error` | 1 |

Out of scope (Go compiler, runtime and tooling): `debug/buildinfo`, `debug/dwarf`, `debug/elf`, `debug/gosym`, `debug/macho`, `debug/pe`, `debug/plan9obj`, `go/ast`, `go/build`, `go/build/constraint`, `go/constant`, `go/doc`, `go/doc/comment`, `go/format`, `go/importer`, `go/parser`, `go/printer`, `go/scanner`, `go/token`, `go/types`, `go/version`, `runtime`, `runtime/cgo`, `runtime/coverage`, `runtime/debug`, `runtime/metrics`, `runtime/pprof`, `runtime/race`, `runtime/trace`, `structs`, `unsafe`.
