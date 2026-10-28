# 0022: crypto features

- **Change.** #22 in the history before the public root, merged
  as 25f7f61. It adds one Cargo feature per Go package to
  `rust-stdlib-crypto`.
- **Reviewers.** Two separate runs of pstack's thermo-nuclear review agent,
  both on Claude Opus 5.5. Neither one wrote the change.
  1. A first review of the branch at 11dffda.
  2. A re-review of the changes from 11dffda through 9e62eea, which included
     the fixes from the first review.

## First review (11dffda)

**Scope.** Look for any feature combination that lets an enabled algorithm
accept input it should reject, or fall back to a weaker path. Also check the
ADR's claims, the lint allows, and gate coverage.

**What the reviewer ran.**
- `cargo check` and `clippy -D warnings` with no features and with each of
  the 26 features alone.
- Library tests under eight partial feature sets.
- Rustdoc under four feature sets.
- The dependency policy tests.
- Behaviour probes under `rsa`, `ecdsa`, `x509` and `full`.
- A pass with the crate-wide lint allow removed, to list the warnings it
  hides.

**Verdict.** No fail-open path. Every path that depends on a feature fails
closed with an error.

| Severity | Finding | Resolution |
|---|---|---|
| Medium | The ADR said RSA and ECDSA behave the same in every feature set. In fact PSS, OAEP with options, and deterministic ECDSA depend on `Hash::available()`, which is gated by feature. The failure is closed, never a pass. | Kept Go's rule, under which a hash is available only when its package is imported. Rewrote the ADR to say so. Pinned the rule with `hash_availability_tests` in `rsa.rs` and `ecdsa.rs` (6cfc339). |
| Low | `rand` turned on `sha256`, which made SHA-256 available in every RNG build. | `rand` now depends on `sha2` directly, so the `sha256` package and its availability stay off (6cfc339). |
| Low | The crate-wide `allow(unused_variables, unreachable_code)` could hide a dropped check in a partial build. | Replaced with allows scoped to the modules that need them (6cfc339). |
| Low | The gate built partial feature sets but never ran tests under them. | `check.py` runs library tests under `rsa`, `ecdsa` and `rsa,ecdsa` (6cfc339, 9e62eea). |

## Re-review (11dffda through 9e62eea)

**Scope.** Check four things:
- Whether the `Hmac::new` restructure can return a MAC for a missing hash.
- Whether the scoped allows can hide a check.
- Whether the availability tests run in each gate set.
- Whether every feature combination compiles.

The reviewer checked hash availability, package by package, against Go
1.27.1. It did not review the regexp changes that came in from main
(77d932c).

**Verdict.** No fail-open path, no change to HMAC output, and every
combination builds. For each package imported alone, hash availability
matches Go 1.27.1.

| Severity | Finding | Resolution |
|---|---|---|
| Low | The crate counts in the ADR were stale after the SHA-3 changes. | Counts removed from the ADR (d807daf). The CHANGELOG entry keeps the measured ones. |
| Low | A comment above `hash_availability_tests` contradicted the tests below it. | Comment rewritten (d807daf). |
| Low | The comment on `check.py`'s test sets was stale. | Comment rewritten (d807daf). |
| Low | The ADR left out the `ecdsa` test set. | Added (d807daf). |
| Low | Four `allow(unused_variables)` attributes could never take effect. | Removed (d807daf). |
| Latent | The gate did not check that the availability tests actually ran, so a cfg guard that stopped matching would skip them silently. | Added `tools/crypto_feature_tests.py`, which fails if no `hash_availability` test ran. It was confirmed to fail on `ecdsa,sha256` (d807daf). |

The full `tools/check.py` gate passed on d807daf with 58 checks.
