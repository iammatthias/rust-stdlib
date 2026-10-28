# Public root: advisory pins (crypto-bigint, rustls, rustls-webpki)

- **Change.** Two dependency commits, plus follow-ups. They first land in
  the public root commit, which replaces the old history, so they have no
  PR number of their own.
  - `crypto: pin crypto-bigint 0.7.10 (0.7.5 is yanked)`
  - `tls: pin rustls 0.23.46 and rustls-webpki 0.103.16 (RustSec)`
- **Author.** The `developer-d4` session, which found the yank while
  dogfooding. It ran the full gate on both commits.
- **Reviewer.** pstack's thermo-nuclear review agent on Claude Opus 5.5.
  It did not write the change.

**Scope.**
- Each advisory and yank, checked against RustSec and crates.io.
- The lock files, ledgers and dependency-policy pins.
- The upstream source diffs that contain the fixes.
- The validation paths in `backends/tls`.
- The new `tools/yank_check.py` and `tools/dependency_ledger.py`.
- ADRs 0002, 0003 and 0006, the diagrams, and the CHANGELOG.

**What the reviewer ran.**
- A full advisory-database audit of all 8 lock files, old and new.
- The old locks reproduce exactly the 2 crypto and 5 TLS advisories these
  commits fix.
- The new locks leave only RUSTSEC-2023-0071 (`rsa`) open, which is
  already documented in the `rsa` module and ADR 0003.
- `tools/dependency_policy.py`, with and without `--metadata`.
- Ledger regeneration, which reproduced the committed ledgers byte for
  byte.
- `tools/yank_check.py`, live, against a pin to a yanked version, and with
  an unreachable index. It fails closed in both bad cases.
- The tls tests: 34 passed.
- The crypto tests, `tools/tls_check.py`, and `tools/x509_check.py` (40,812
  cases).
- `cargo +1.87.0 check` on crypto and tls.

**Verdict.** Approved. Every claim checked out:
- The yanks: crypto-bigint 0.7.0 to 0.7.8.
- The advisories: RUSTSEC-2026-0387, 0385, 0346, 0347, 0348, 0349 and 0382.
- The fixes are present in the upstream sources. In 0.23.46, rustls sets
  the key-share hint after the server Finished. webpki rejects the emSign
  SPKIs.
- The lock diffs change only versions and checksums, with no new crates.
- Certificate validation only got stricter.

| Severity | Finding | Resolution |
|---|---|---|
| Low | webpki's new distrust rejection reached callers as a `Debug` string (`x509: Other(...)`). It was not recorded as a deviation from Go, which has no distrust list. | It now reads `x509: certificate chains to a distrusted root`, with a unit test. It is coded as deviation `webpki-distrust` on `CertificateVerificationError` and noted in `docs/COMPATIBILITY.md`. |
| Low | ADR 0003 still said the crypto graph was MSRV 1.85, but crypto-bigint 0.7.10 and ctutils 0.4.6 declare 1.87. | The ADR now says 1.87, as checked with `cargo +1.87.0 check --all-features`. |
| Low | `tools/dependency_ledger.py` keys hand-written ledger fields by crate name only. A bump can carry stale per-version fields forward. | Stands as a follow-up. No lock holds two versions of a crate today, and the regenerated ledgers are identical. |
| Info | 0.7.9 would have been the smallest crypto-bigint fix. 0.7.10 also replaces `ctutils` primitives. | Kept 0.7.10, the newest unyanked release. It is noted here for the next reviewer. |
