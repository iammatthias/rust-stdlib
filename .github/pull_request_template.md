## Summary

<!-- What changes, and which Go packages or symbols it affects. -->

## Parity

<!-- Paste the changed rows from `python3 tools/api_parity.py` (docs/COVERAGE.md). -->

## Checklist

- [ ] `python3 tools/check.py` passes locally (paste the final status line)
- [ ] `cargo clippy --all-targets --offline --locked -- -D warnings`, with and without `--no-default-features`
- [ ] Behaviour differences from Go are recorded as `differs` or `deviation` in `docs/api/`, not only in prose
- [ ] New Go-facing behaviour has a Go differential registered in `tools/parity_check.py`
- [ ] `git diff main --stat --diff-filter=D` lists only files this change means to delete
- [ ] Changes under `crates/crypto` or `backends/tls`, or to certificate or signature validation: the independent review is recorded in `docs/reviews/` (see its README)
