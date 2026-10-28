# Compatibility and conformance

## Shared baseline

`tools/conformance.py` generates 175 deterministic vectors. Each contains an operation and an expected output. The Go driver uses encoding/base64, encoding/hex, encoding/json and net/url. The Rust driver uses this crate. Go comparison runs with UseNumber and HTML escaping disabled to preserve shared JSON number/string semantics.

```sh
python3 tools/conformance.py --oracle-only
python3 tools/conformance.py
```

The first command verifies Go against the fixed corpus only. The second requires Cargo and compares actual Rust outputs to Go. Neither is a complete standards-conformance suite or a fuzzing campaign.

The current comparison toolchain is recorded in verification and the inventory
(Go 1.27.2 locally), with a deliberate CI pin.

## Documented differences

| Area | This implementation |
|---|---|
| JSON (`encoding::json`) | Go's v1 behaviour (HTML and U+2028/U+2029 escaping, duplicate keys accepted, invalid UTF-8 replaced). `Unmarshal` returns the decoded value instead of filling a destination, so merging, partial results after a type error and nil-versus-empty do not exist; `[u8; N]` always encodes as an array of numbers; `CallMethodsWithLegacySemantics`, `MergeWithLegacySemantics` and `FormatByteArrayAsArray` are recorded only; `ParseTimeWithLooseRFC3339` is not implemented (`docs/api/encoding_json.json`) |
| URL (`net::url`) | Go's generic parser, error texts, `urlstrictcolons` default and 10000-parameter limit; `Values::encode` sorts by key as Go does. Percent-decoded components that are not UTF-8 hold U+FFFD; `raw_path`, `raw_fragment`, `raw_query` and the host/userinfo bytes keep the encoded form so `String` round-trips |
| HTTP (`net::http`) | Go's framing, `ServeMux`, `Client`, `Transport` and HTTP/2, thread per connection. Header values and request/status lines are Rust strings, so non-UTF-8 header bytes are rejected; Go's panics are `Result`s; `Request.WithContext` copies the Header and Form maps Go shares; TLS is a `TlsConfig` hook (`Server.TLSConfig`, `Transport.TLSClientConfig`), see HTTP.md and `docs/api/net_http.json` |
| XML (`xml::`) | Go's `encoding/xml` semantics, tokens, errors and positions; shortest float digits and error type strings follow Rust (ties resolved like Go); recursion bounded by `Decoder::max_unmarshal_stack` (default 1 MiB) as well as Go's depth limit |
| ASN.1 explicit tags | Go ignores the explicit wrapper length (the default); `Options::strict_explicit` requires the wrapper to hold exactly one element. Depth defaults to 256 (Go 10000) to keep Rust's stack safe; year 0000 and ±24h zone offsets rejected |
| Time | Every exported Go `time` symbol is mapped or explained in `docs/api/time.json`. TZif versions 1 to 3 accepted, version 4 is malformed as in Go 1.27; non-UTF-8 zone abbreviations are decoded lossily; in-memory TZif capped at 10 MiB (Go caps only zone files); `ZONEINFO` read per call; no `$GOROOT` zoneinfo fallback; Local follows Go's Unix `TZ` rules on every platform. Timer and ticker channels are `mpsc` receivers served by one scheduler thread; `AfterFunc` runs callbacks on new threads; `Tick` returns `None` for Go's nil channel |
| Archives | Go-shaped `archive/tar` and `archive/zip` (GNU/PAX/sparse, ZIP64, CP437); tar output is byte-identical to Go, and so is ZIP DEFLATE output (`compress::flate` is a port of Go's compressor); `ErrInsecurePath` is opt-in; `write_sparse_header` is an extension; bounded one-shot `read`/`write` helpers also exist, see ARCHIVES.md |
| Regex | Go 1.27 semantics on Go's one-pass, bit-state backtracking and Pike VM matchers, linear time; patterns are `&str`; offset and anchored searches for tokenizers (`docs/api/regexp.json`) |
| Templates | `text::template` and `html::template` are ports of Go's; values come from a typed `Value` model instead of reflection. `template::` is this crate's own bounded interpolation (typed control flow and functions, ambiguous code rejected), not a Go package |
| TLS | Rustls (ring provider) behind Go's `crypto/tls` shape; TLS 1.2 and 1.3, AEAD suites, X25519/P-256/P-384 only; options Rustls refuses (older versions, renegotiation, external ticket keys, ECH, SHA-1 signatures) fail with an explicit error; chains through a root on webpki's distrust list are rejected, where Go has no such list; roots are the caller's pool or the system roots (a nil pool on macOS does not use the platform verifier) (`docs/api/crypto_tls.json`) |

Canonical JSON in the test harness means deterministic key ordering and compact encoding. It is not RFC 8785 JSON canonicalization and should not be used for signature interoperability on that assumption.

## HTTP interoperability

`tools/smoke.py` starts the compiled example on an OS-assigned loopback port. Python's http.client exercises eight application cases. The Go interoperability driver sends fixed-length and chunked requests to Rust, starts a Go httptest server, and invokes the Rust client against fixed-length and chunked responses.

Rust integration tests independently exercise short reads, malformed framing, Unicode errors, limits, HEAD semantics, panic containment, concurrency and cancellation. Adversarial byte loops are deterministic regression tests, not coverage-guided fuzzing.

## Sources

- JSON: https://www.rfc-editor.org/rfc/rfc8259.html
- Base64/hex: https://www.rfc-editor.org/rfc/rfc4648.html
- URI syntax: https://www.rfc-editor.org/rfc/rfc3986.html
- Go standard library: https://pkg.go.dev/std
- Rust std: https://doc.rust-lang.org/std/
