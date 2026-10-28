# ADR 0003: cryptography through reviewed dependencies

Status: **accepted** (maintainer decision, 2026-10-12). Foundation, hash
family, symmetric ciphers and the asymmetric packages implemented (below); the
proc-macro dependencies listed under "Asymmetric increment" need explicit
maintainer approval before this lands.

## Decision

Cryptography is the one exception to the zero-dependency rule, because this
project cannot validate cryptographic implementations itself. Go's `crypto/*`
packages are provided by a separate first-party crate, `crates/crypto`
(`rust_stdlib_crypto`), that wraps reviewed third-party crates behind Go-shaped
APIs. The root crate keeps zero third-party dependencies, so applications that
do not need cryptography pull in nothing.

No primitive is implemented first-party, and no upstream source is vendored:
dependencies come from crates.io with an exact lockfile, recorded in a ledger
with versions, checksums, features, licences and advisories, in the same form as
docs/tls-dependencies.json.

## Selection rules

- Prefer the RustCrypto project's pure-Rust crates, which expose the raw
  primitives Go exposes (block ciphers and modes, hash and MAC internals,
  curves, signatures, post-quantum KEMs and signatures).
- Reuse `ring`/`rustls` where the TLS adapter already depends on them, rather
  than adding a second implementation of the same thing.
- Each crate's open RustSec advisories are recorded. A primitive with an
  unresolved advisory (for example timing side channels in `rsa` decryption)
  is exposed only with the advisory stated in its docs.
- `crypto/rand` uses the operating system's generator through the chosen
  crates' entropy source.

## Consequences

- The dependency policy tooling must allow the crypto crate's exact graph and
  nothing else.
- The API parity scoreboard must verify mappings into the crypto crate.
- Maintainers must track upstream advisories and update the lockfile.

## Implementation: `crates/crypto`

The first increment is the hash family: `crypto` (the `Hash` identifiers),
`crypto/md5`, `sha1`, `sha256`, `sha512`, `sha3`, `hmac`, `hkdf`, `pbkdf2`,
`subtle` and `rand`. The package is `rust-stdlib-crypto` (library
`rust_stdlib_crypto`), forbids unsafe code, has no build script and depends on
no first-party crate: it needs nothing from the root, and a path dependency
would compile the whole root for every cryptography build. Applications
depend on both crates side by side.

Direct dependencies, each pinned with `=`, `default-features = false` and
resolved by `Cargo.lock` (93 external packages in total after the
asymmetric increment, all MSRV 1.87 or lower, verified with `cargo metadata`
`rust_version` fields and `cargo +1.87.0 check --all-features` on rustc 1.87.0):

| Crate | Version | Used for |
|---|---|---|
| `digest` | 0.11.3 | the hash engine's traits (direct since the Features section, enabled by the hash packages; already resolved through every hash crate) |
| `md-5` | 0.11.0 | MD5 |
| `sha1` | 0.11.0 | SHA-1 |
| `sha2` | 0.11.0 | SHA-224/256/384/512 and 512/224, 512/256 |
| `sha3` | 0.11.0 | SHA3-224..512 (held at 0.11 so the lock has one `sha3`, see below) |
| `cshake` | 0.2.1 | SHAKE128/256 and cSHAKE128/256 |
| `hmac` | 0.13.0 | HMAC (`SimpleHmacReset`, which also works for SHA-3) |
| `hkdf` | 0.13.0 | HKDF (`SimpleHkdf`) |
| `pbkdf2` | 0.13.0, feature `hmac` | PBKDF2 |
| `subtle` | 2.6.1 | constant-time comparison and selection |
| `getrandom` | 0.4.3 | operating-system randomness |
| `aes` | 0.9.2 | AES-128/192/256 (0.9.3 needs Rust 1.89) |
| `des` | 0.9.0 | DES and Triple DES |
| `rc4` | 0.2.0 | RC4 |
| `cbc` | 0.2.1 | CBC mode |
| `cfb-mode` | 0.9.1 | CFB mode (the buffered, multi-call encryptor and decryptor) |
| `ctr` | 0.10.1 | CTR mode (`Ctr128BE` for 16-byte blocks, `Ctr64BE` for DES) |
| `ofb` | 0.7.1 | OFB mode |
| `aes-gcm` | 0.11.1, feature `aes` | GCM (`AesGcm`, generic over the 16-byte block cipher) |
| `ed25519-dalek` | 3.0.0, features `alloc`, `digest`, `pkcs8` | Ed25519, Ed25519ph |
| `x25519-dalek` | 3.0.0, feature `static_secrets` | X25519 |
| `p224` | 0.14.0-rc.15 (release candidate: no stable release exists) | P-224 |
| `p256`, `p384`, `p521` | 0.14.0 | P-256/384/521, ECDH, point arithmetic |
| `ecdsa` | 0.17.0, features `algorithm`, `alloc`, `der` | ECDSA signing/verification, RFC 6979, DER signatures |
| `rsa` | 0.10.0-rc.19 (release candidate: no stable release exists), feature `encoding` | RSA key generation, PKCS #1 v1.5, PSS, OAEP, PKCS #1/#8/PKIX encodings |
| `dsa` | 0.7.0, features `hazmat`, `pkcs8` | DSA (`hazmat` is the crate's gate for the private-key type) |
| `ml-kem` | 0.3.2, feature `alloc` | ML-KEM-768/1024 |
| `ml-dsa` | 0.1.1, features `alloc`, `rand_core` | ML-DSA-44/65/87 |
| `hpke` | 0.14.1 (rozbb/rust-hpke, MIT OR Apache-2.0), features `alloc`, `aes`, `chacha`, `nistp`, `x25519` | HPKE (RFC 9180) |
| `crypto-bigint`, `crypto-primes`, `rand_core` | 0.7.10, 0.7.2, 0.10.1 | `rand.Int`/`rand.Prime` and the RSA key plumbing |

The remaining packages are the RustCrypto support crates (`digest`,
`crypto-common`, `block-buffer`, `hybrid-array`, `typenum`, `keccak`,
`sponge-cursor`, `cmov`, `ctutils`, `cpufeatures`, and for ciphers `cipher`,
`inout`, `aead`, `ghash`, `polyval`, `universal-hash`, `cpubits`) and `cfg-if`,
`libc` and `r-efi` for platform glue. The cipher crates are used through the
`cipher` traits re-exported by `aes`, so `cipher` and `aead` are not direct
dependencies. `sha2` is held at 0.11.0 because 0.11.1 requires Rust 1.88.
`ctutils` was held at 0.4.2 while the MSRV was 1.85; the `crypto-bigint`
update below moved it to 0.4.6 (MSRV 1.87, which the project now requires).
Licences are MIT and/or Apache-2.0 for everything except `subtle`
(BSD-3-Clause) and `r-efi` (MIT OR Apache-2.0 OR LGPL-2.1-or-later, used under
MIT/Apache-2.0). `docs/crypto-dependencies.json` records versions, checksums,
lock edges, resolved features and licences and is enforced by
`tools/dependency_policy.py` exactly like the TLS ledger.

Advisories, checked against the RustSec database on 2026-10-12 (no
`cargo-audit` binary was available, so the per-crate advisory directories were
read directly): `cmov` RUSTSEC-2026-0003 (non-constant-time code on 32-bit ARM)
is patched in 0.4.4 and the lock has 0.5.4; `keccak` RUSTSEC-2026-0012 (opt-in
ARMv8 `asm` feature) is patched and the feature is not enabled; `sha2`
RUSTSEC-2021-0100 affects only 0.9.7. No advisory applies to the locked
versions. Maintainers re-check these on every lock change.

`crypto-bigint` update (2026-10-27): crates.io yanked `crypto-bigint`
0.7.0 through 0.7.8. 0.7.0 through 0.7.5 carry RUSTSEC-2026-0387 (timing
variability in subtraction, zero counting, division, Montgomery multiplication,
`UintRef` equality and `BoxedMontyForm::invert`), patched in 0.7.6. 0.7.6
through 0.7.8 were then yanked because upstream PR #1373 had to make a breaking
fix (the blanket `Mul` impl for `NonZero<T>` now requires `T: Integer`), and
0.7.9 is the first release with it. The lock already built because Cargo keeps
a locked yanked version, but a downstream crate resolving `rust-stdlib-crypto`
without this lock failed on the `=0.7.5` pin under any feature that enables
`rand`. The pin is now `=0.7.10`, which also moves `ctutils` from 0.4.2 to 0.4.6
(RUSTSEC-2026-0385, non-constant-time mask generation and `u128` comparisons,
patched in 0.4.4). Every dependent in the lock accepts it: `rsa` 0.10.0-rc.19,
`crypto-primes` 0.7.2 and `dsa` 0.7.0 require `^0.7`, and `elliptic-curve`
0.14.1, `primefield` 0.14.0 and `rfc6979` 0.6.0 require `^0.7.5`. The graph
compiles against 0.7.10 and the crate's tests pass, so no dependent used the
removed `Mul` impl. No other package or edge changed. `tools/yank_check.py`
now reports a yanked direct pin in any manifest (an online check, outside the
offline gate).

The cipher increment was checked the same way against the RustSec advisory
database at commit 57dcc0f (2026-10-12): `aead`, `aes`, `cbc`, `cfb-mode`,
`cipher`, `cpubits`, `ctr`, `des`, `ghash`, `inout`, `ofb`, `polyval`, `rc4`
and `universal-hash` have no advisories. `aes-gcm` has RUSTSEC-2023-0096
(`decrypt_in_place_detached` left unauthenticated plaintext in the buffer),
patched in 0.10.3; the lock has 0.11.1, which verifies the tag before
decrypting, and `crypto/cipher` additionally decrypts a copy so that a failed
`Open` never writes to the caller's `dst`.

`crypto/cipher`, `crypto/aes`, `crypto/des` and `crypto/rc4` are implemented
over these crates, and the `crypto` package's key, signing, decryption and
encapsulation interfaces are traits (they need no asymmetric key types). The
modes are the dependencies' own; this repository adds only Go's constructors,
messages and buffer rules. A `cipher::Block` defined outside the crate is
adapted to the RustCrypto traits (8- and 16-byte blocks), and this crate's own
AES/DES blocks run on the dependencies directly. Two limits come from the
dependencies: GCM's nonce size is a compile-time parameter of `aes-gcm`, so
`NewGCMWithNonceSize` accepts the sizes in `cipher::GCM_NONCE_SIZES` (Go accepts
any positive size), and `aes-gcm` bounds tags to 4..=16 bytes (Go accepts
12..=16, which is what is exposed).

Primitive internals stay inside the dependencies. Go's binary hash-state
formats are produced by translating the dependencies' public
`SerializableState` bytes (this is serialization, not a reimplementation of any
primitive). Where a dependency exposes no such interface, the state methods are
recorded as deviations: SHAKE/cSHAKE `MarshalBinary`, `AppendBinary` and
`UnmarshalBinary`. `crypto/rand.Int` and `Prime` are implemented with this crate's `bigint::Int` and
`crypto-primes` (see below).

## Constructions (2026-10-12)

No cryptographic construction is written first-party, even over reviewed
primitives (for example GCM over `ghash`, or HMAC over a caller's hash). Where a
reviewed crate cannot express a Go option, that symbol is a documented
deviation: `cipher.NewGCMWithNonceSize` supports the nonce sizes `aes-gcm` can
instantiate, and `hmac.New` accepts this crate's hashes only.

## Asymmetric increment (2026-10-12)

`crypto/ed25519`, `ecdh`, `ecdsa`, `elliptic`, `rsa`, `dsa`, `mlkem`
(`mlkemtest`), `mldsa`, `hpke`, `fips140` and `rand.Int`/`Prime` are
implemented over the crates in the table above, and the `crypto` package's
`Signer`, `Decrypter`, `Encapsulator` and `Decapsulator` interfaces are
implemented by the key types. Every package is `complete` in
`tools/api_parity.py`; Wycheproof (the version Go pins), NIST CAVS, RFC 6979,
RFC 9180 and Go's own test vectors run in `crates/crypto/tests`, and
`tools/crypto_asym_check.py` compares about 12,000 random and mutated cases with
Go (deterministic outputs byte for byte, randomized outputs by cross-verifying).

Decisions recorded here:

- **Big integers.** The crate still depends on no first-party crate (a path
  dependency on the root would compile the whole root for every cryptography
  build and the dependency policy forbids it). Go's `*big.Int` fields are
  `bigint::Int`, a non-negative big-endian magnitude without arithmetic.
- **No first-party constructions.** Where a reviewed crate cannot express a Go
  option the symbol is a documented deviation: Ed25519ctx (context without
  prehash), generic `elliptic.CurveParams` arithmetic and ECDSA on custom
  curves, multi-prime RSA key generation, the constant-time PKCS #1 v1.5
  session-key countermeasure (a functionally equal, non-constant-time version
  is provided), DSA parameter sizes other than FIPS 186-3's, HPKE with the
  post-quantum KEMs and SHAKE KDFs, and FIPS 140-3 mode.
- **Randomness.** Like Go 1.26+ (without `GODEBUG=cryptocustomrand=1`), the
  reader arguments of ECDH/ECDSA/RSA key generation and signing are ignored;
  OAEP encryption, PSS signing, Ed25519 key generation, DSA and
  `rand.Int` consume the caller's reader. `GODEBUG` is read from the
  environment as Go does (`cryptocustomrand`, `rsa1024min`).

Advisories (RustSec database commit 57dcc0f, 2026-10-12, recorded in the
`advisories` key of docs/crypto-dependencies.json):

- **`rsa` RUSTSEC-2023-0071 (Marvin Attack, timing side channel in
  private-key operations) has no patched release.** `crypto/rsa` is exposed
  with the advisory stated in the `rsa` module documentation; do not expose its
  private-key operations to remote callers that can time them. The maintainers'
  decision to accept this is part of this ADR.
- All other advisories for locked crates (`aes-gcm`, `chacha20`, `cmov`,
  `curve25519-dalek`, `ed25519-dalek`, `keccak`, `ml-dsa`, `rand_core`, `sha2`,
  `zeroize_derive`) are patched in the locked versions.

Items that need maintainer approval (AGENTS.md forbids proc-macro parser
dependencies and the build graph has them through the requested crates):

- `curve25519-dalek 5.0.0` depends on the proc-macro crate
  `curve25519-dalek-derive` on x86-64 (unconditional for that target), which
  builds `syn` 2, `quote` and `proc-macro2`; `hpke 0.14.1` enables
  `zeroize_derive` (a proc macro on the same `syn`) unconditionally. The lock
  also lists `serde`/`serde_derive` (a weak optional feature of
  `ed25519-dalek` that no build activates). `zeroize` is held at 1.8.2,
  `zeroize_derive` at 1.4.3 and `serde` at 1.0.219 so that only `syn` 2 is in
  the lock (the newer releases use `syn` 3 and would need a duplicate package,
  which the dependency policy rejects). Build scripts exist in some
  dependencies (`autocfg`, `rustc_version`).
- `rsa` 0.10 and `p224` 0.14 are release candidates; every other new crate is
  a stable release.
- `ml-kem` needs `sha3` 0.11 while `hpke`'s `mlkem`/`shake` features need
  `sha3` 0.12 (through `x-wing`). A lock with both would duplicate the
  package, so those features are off and the HPKE post-quantum KEMs and SHAKE
  KDFs are deviations. Allowing two `sha3` versions in the policy would lift
  that deviation.

## x509 increment (2026-10-13)

`crypto/x509` and `crypto/x509/pkix` are in `crates/crypto` (`src/x509/`). No
crate was added: the dependency ledger, the lock and the policy are unchanged.

- **The DER layer is first-party.** `x509-cert` 0.3 needs the `der_derive`
  proc macro (forbidden by AGENTS.md), and the `der` types do not reproduce
  Go's parser, which follows `cryptobyte` (single-byte tags, minimal lengths
  and integers) in `parser.go` but `encoding/asn1` laxities elsewhere
  (explicit tags, CSR attributes, DER CRLs). `src/x509/asn1.rs` is a reader
  and builder, not a cryptographic construction: every signature, hash and key
  operation goes through the reviewed crates already in the ledger (`rsa`,
  `ecdsa`, `ed25519-dalek`, `sha2`, `sha1`, `md5`).
- **`rustls-webpki` was not used for `Certificate.Verify`.** It validates one
  chain and cannot return every chain, enforce Go's `VerifyOptions` (key usage
  lists, policies, name constraints on the leaf's SANs, the signature-check
  limit) or produce Go's error values. `verify.rs` ports `buildChains`
  instead. Certificate validation is never disabled.
- **Legacy PEM encryption** (`EncryptPEMBlock`, `DecryptPEMBlock`) is not
  ported: its RFC 1423 key derivation (iterated MD5, OpenSSL's
  `EVP_BytesToKey`) is a cryptographic construction this ADR forbids writing
  first-party, so both are deviations
  (`dependency-no-first-party-construction`). `IsEncryptedPEMBlock` and the
  cipher constants are provided.
- **Platform verifier deviation.** Go's `SystemCertPool` uses the platform
  verifier on macOS and Windows. Here it reads Go's Unix certificate files and
  directories (`SSL_CERT_FILE`, `SSL_CERT_DIR`), and on macOS exports
  `SystemRootCertificates.keychain` through `security find-certificate`. Trust
  settings are not consulted.
- **`rsa.rs` change.** Public keys built from certificates use
  `RsaPublicKey::new_with_max_size(.., 1 << 20)`: the `rsa` crate's default
  8192-bit limit rejected a key that Go's tests accept. Go has no limit here.
- Differential testing: `tools/x509_check.py` drives `tools/x509_oracle.go` and
  `crates/crypto/examples/x509_probe.rs` over Go's test certificates, generated
  certificates, `Create*` in both directions, generated PKI hierarchies for
  `Verify`, and random `pkix.Name` strings. `tools/x509_vectors_gen.py`
  extracts Go's test tables into `crates/crypto/tests/fixtures/x509/`.

## Features (2026-10-15)

Every direct dependency of `crates/crypto` is optional, and each Go package is
a Cargo feature of the same name: `md5`, `sha1`, `sha256`, `sha512`, `sha3`,
`subtle`, `rand`, `hmac`, `hkdf`, `pbkdf2`, `cipher`, `aes`, `des`, `rc4`,
`ecdh`, `elliptic`, `ecdsa`, `ed25519`, `rsa`, `dsa`, `mlkem`, `mldsa`, `hpke`
and `x509`. `default = ["full"]` enables all of them, so a consumer that does
not opt out compiles exactly what it compiled before. The `crypto` root (the
`Hash` identifiers and the signer, decrypter and KEM traits), `hash`,
`fips140` and `bigint` have no dependencies and are always compiled.

A feature enables the features of the packages its module uses, and the
dependency crates its module calls. It copies the edges of Go's import graph
that change behaviour: `crypto/rsa`, `crypto/ecdsa`, `crypto/hmac`,
`crypto/hkdf`, `crypto/pbkdf2` and `crypto/hpke` import `crypto/sha3` through
`crypto/internal/fips140hash`, so SHA-3 is available to a Go program that
imports any of them, and the `rsa`, `ecdsa`, `hmac` (with `hkdf` and
`pbkdf2`) and `hpke` features enable `sha3`. It does not copy `crypto/sha256`
importing `crypto/cipher`, which changes no hash result and would compile the
cipher modes into every hash build. One
internal feature has no Go package of its own: `nistec`, the four NIST curves
behind `ecdh`, `elliptic` and `ecdsa`, like Go's
`crypto/internal/fips140/nistec`. The hash packages enable the `digest` crate
for the hash engine, which is compiled only with a hash package.

Features only remove code. No algorithm, check or message depends on the
feature set, with one deliberate exception that follows Go: a hash function is
available (`Hash::new`, `Hash::available`) only when its package feature is
enabled, as a Go program has only the hashes whose packages it imports. The
operations that Go gates on `Hash.Available` are gated the same way:
`sign_message` with a hash, `rsa::sign_pss` and `verify_pss` (and
`PrivateKey::sign` with `PSSOptions`), `rsa::encrypt_oaep_with_options` and
`PrivateKey::decrypt` with `OAEPOptions`, and deterministic (RFC 6979)
`ecdsa::PrivateKey::sign` without a reader. HMAC, HKDF and PBKDF2 dispatch
only over the enabled hash packages; Go takes a hash constructor, which needs
the package. The operations Go does not gate
work with every hash in every feature set: `rsa::sign_pkcs1v15` and
`verify_pkcs1v15` (Go names the hash by its DigestInfo prefix), plain
`encrypt_oaep` and `decrypt_oaep` (Go is handed a `hash.Hash` value), hedged
ECDSA signing and ECDSA verification. That is why `rsa` compiles `md-5` and
`sha1` without their packages; `nistec` signs deterministically with MD5 or
SHA-1 only when their package is enabled, since the hash must be available to
reach it. The library's unit tests pin these rules with Go 1.27's results for
`rsa` alone, `ecdsa` alone and `rsa,ecdsa`, SHA-3 included.

`cipher` and `aes` are one unit: `aes` enables `cipher`, and the `aes` module
is compiled with `cipher` because the cipher engine's fast paths and GCM are
built on the AES block type. The engine's DES fast path is compiled only with
`des`; without it no DES block can exist.

Code that only some packages use is compiled with them (`sysrng`'s
`Source::finish` with `dsa`, `ecdh` and `rsa`, the RSA key checks that only
`x509` runs with `x509`), so clippy denies warnings for every single feature.
One lint allowance remains, scoped to its module and condition: `nistec`
allows dead code without `ecdsa` (each of `ecdh`, `elliptic` and `ecdsa` uses
part of the backend).

Curves are not split: a Go package is the unit, and splitting them would save
`ecdsa` only the three curves it does not use. `ecdsa` enables
`ecdh` as Go's `crypto/ecdsa` imports `crypto/ecdh`, which brings X25519.
`ecdsa` and `hpke` enable `sha512`, and `hpke` `sha256`, as their Go packages
import `crypto/sha512` and `crypto/sha256`. `rand` hashes its testing reader
with the `sha2` crate directly: Go's `crypto/rand` does not make SHA-256
available.

The CHANGELOG records the registry-crate counts measured when the features
landed; `cargo tree --no-default-features --features <set>` gives the current
ones. `tools/dependency_policy.py` pins the feature table like the dependency
table, the ledger's resolved graph is recorded with `--all-features`, and
`tools/check.py` runs clippy on the library with no features, `sha256,hmac`,
`aes`, `hpke` and `x509`, the library's unit tests with `rsa`, `ecdsa` and
`rsa,ecdsa` (each must run at least one hash-availability test, checked by
`tools/crypto_feature_tests.py`), and rustdoc with `sha256,hmac`.
