# Explicit TLS adapter

Status: implemented under the user's instruction to execute the roadmap, including its reviewed optional TLS backend. Core dependency policy remains unchanged. This decision records an integration review, not an independent cryptographic audit.

## Boundary

`backends/tls` is an independently selected first-party Cargo package. The root crate has zero runtime/build/development dependencies and its lock contains one package. The adapter depends on the root by path and exactly Rustls 0.23.46 with defaults disabled and `std`, `ring`, `tls12` enabled. No backend is selected implicitly.

Rustls owns TLS and certificate/hostname/validity verification. Ring owns
cryptographic operations and OS entropy. Application source forbids unsafe;
the reviewed external graph includes unsafe and ring's compiled C/assembly.
A C compiler/platform tooling are build requirements. The ledger records 27
resolved packages (two first-party, 25 external), including native build tools
and target-specific packages. Lock checksums and resolved features/edges are
enforced independently from the root's one-package graph.

## Public API and trust

Public HTTP request/response and std::io interfaces are reused. Caller-supplied DER roots are required; empty stores fail. Root installation, revocation policy and trust-store updates belong to the application. No bundled root snapshot or OS root discovery adds further packages. Revocation checking is not currently configured. TLS 1.2 and 1.3 are enabled through Rustls safe defaults. The HTTP-facing API (`Client`, `tls::Config`, `httptest`) exposes no verifier replacement or verification bypass, and HTTPS never redirects or downgrades to HTTP.

### The `crypto/tls` API (`rust_stdlib_tls::tls`)

`tls::Config` is Go's `tls.Config`. Because Go exposes them, it carries `InsecureSkipVerify`, `VerifyPeerCertificate`, `VerifyConnection`, `GetCertificate`, `GetClientCertificate` and `GetConfigForClient`, and the adapter implements them with Rustls' `ServerCertVerifier`/`ClientCertVerifier`/`ResolvesServerCert`/`ResolvesClientCert` hooks around webpki's verifiers. `InsecureSkipVerify` is false by default, is documented as making TLS insecure, and nothing in this crate sets it: the `Client` and `httptest` paths never touch it. Verification itself stays webpki's; the adapter adds Go's callbacks, `VerifiedChains` and Go's `x509:` error texts. Rustls still owns the protocol; options it refuses on purpose (TLS 1.0/1.1, renegotiation, RC4/3DES/CBC and static-RSA suites, P-521 and post-quantum groups, SHA-1 signatures, Encrypted Client Hello, external ticket keys) are rejected with explicit errors and recorded as `rustls-policy` deviations in `docs/api/crypto_tls.json`. A nil `RootCAs`/`ClientCAs` uses the system roots as Go's `x509.SystemCertPool` loads them (`SSL_CERT_FILE`, `SSL_CERT_DIR`, Go's Unix certificate lists, or the exported macOS keychain); the loader is a copy of `crates/crypto`'s because the two lock files cannot be shared. On macOS, Go's default verification through Security.framework cannot be called without FFI, recorded as deviation `no-platform-verifier`.

`*x509.Certificate` and `*x509.CertPool` are the small DER-reading types in `tls::x509`, not `crates/crypto`'s. Making `backends/tls` depend on `crates/crypto` was evaluated and rejected: the two reviewed lock graphs resolve `getrandom` (0.2.17 under ring, 0.4.3 under the crypto crate) and `zeroize` (1.9.1, 1.8.2) at different versions, and the dependency policy's inventory contract forbids duplicate package names. Allowing it would mean reworking the lock-edge identity checks of `tools/dependency_policy.py` and merging two reviewed ledgers, which this change does not justify. The server uses a caller-supplied DER chain and PKCS#8 key, with HTTP/1.1 ALPN.

Every socket read/write and handshake has an aggregate monotonic deadline and cooperative cancellation. std DNS resolution remains blocking; the budget is rechecked afterward. Buffered HTTP limits apply to plaintext bodies, and rustls send buffers are bounded.

## Alternatives

Platform TLS would require owned unsafe/FFI and different trust behavior per platform. A new TLS/cryptographic engine would require a dedicated review and maintenance program. Rustls's default aws-lc provider is recommended upstream for feature breadth; ring is chosen here for a smaller cached, reproducibly resolved graph and established supported APIs. This is an explicit tradeoff, not a universal performance or security claim.

## Update and release duties

The repository maintainer reviews Rustls/ring advisories and every lock change, updates the inventory and runs certificate-negative/interop/platform tests. Releases must retain upstream license notices and provenance. Ring's upstream license requires preserving its LICENSE and notices when redistributing its code/binaries; consumers use Cargo registry distributions. Neither upstream source nor native implementations are vendored here.

The advisory record is the `advisories` key of `docs/tls-dependencies.json`
(and of `docs/sysnet-dependencies.json`, whose lock carries the same graph).
Every crate in each lock is looked up in the RustSec advisory database and its
locked version compared with the advisory's patched and unaffected ranges.

Rustls update (2026-10-27): the RustSec advisory database at commit 99670cf
(2026-10-27) lists five advisories against the locked Rustls 0.23.45 and
rustls-webpki 0.103.15, all published after 2026-10-12. The pin is now
`=0.23.46` and the lock takes rustls-webpki 0.103.16. Both are the newest
releases in their series, declare Rust 1.71, and have the same dependency
requirements as the versions they replace, so no other package or edge
changed in either lock.

- RUSTSEC-2026-0349 (Rustls before 0.23.46): the client stored the key
  exchange group from an unauthenticated ServerHello and sent only that key
  share to the same server name later. The advisory's impact is a downgrade
  from X25519MLKEM768 to a classical group. The ring provider offers no
  post-quantum group, so here an attacker could only steer which classical
  group (X25519, P-256 or P-384, ordered by `CurvePreferences`) is offered
  first. The adapter's `GatedStore` passed the hint through to Rustls'
  memory cache, so the client was affected.
- RUSTSEC-2026-0382 (rustls-webpki before 0.103.16): path building could
  accept the distrusted emSign intermediates when the caller's roots chain to
  them. Every verification in the adapter is webpki's, so the client and
  client-certificate verification were affected for those roots.
- RUSTSEC-2026-0346 (Rustls 0.21.0 to 0.23.45): the derived `Debug` of
  `Tls12ClientSessionValue` and `Tls13ClientSessionValue` printed the master
  secret or resumption PSK. `GatedStore` implements `ClientSessionStore` but
  never formats these values, so no adapter path printed them.
- RUSTSEC-2026-0347 (Rustls 0.23.44 and 0.23.45): buffered data went to the
  outer server after an ECH rejection. The adapter rejects Encrypted Client
  Hello, so it was not exposed.
- RUSTSEC-2026-0348 (Rustls 0.23.9 to 0.23.45): Brotli certificate
  decompression could allocate 1 GiB. The `brotli` feature is not enabled.

Every other advisory dated from 2026-10-01 at that commit was compared with
the `backends/tls`, `backends/sysnet` and `fuzz` locks, and none names a
locked crate.

Sources: https://docs.rs/rustls/0.23.46/rustls/ ; https://docs.rs/rustls/0.23.46/rustls/client/struct.ClientConfig.html ; https://docs.rs/ring/0.17.14/ring/ .
