# 0020: close the last differs

- **Change.** #20 in the history before the public root,
  merged as c05467e. Of the last three `differs`, it fixes one and recodes two
  as deviations. In `crates/crypto`, it changes the error text for RSA keys
  whose `d` or `qinv` overflows the modulus, and the quoting of invalid UTF-8
  in X.509 errors.
- **Reviewer.** pstack's thermo-nuclear review agent, Claude Opus 5.5,
  reading the `differs-int` branch. It did not write the change.

**Scope.** The whole branch diff. The crypto checks were:
- whether the new RSA error path rejects exactly the keys it rejected before;
- whether the X.509 string quoting and IA5 checks match Go;
- whether the narrowed acceptance in the X.509 differential could hide a real
  difference.

The reviewer read Go 1.27.1 source from the local GOROOT and did not run
cargo or the gate.

**Verdict.** No serious findings. RSA `set_bytes_error` rejects exactly the
keys the old `d >= n` and `qinv >= p` checks rejected; only the message
changes, now matching Go's `bigmod`. The X.509 quoting matches
`strconv.Quote`. The differential's new acceptance covers one documented
substitution, in three certificate URL fields, and nothing else.

| Severity | Finding | Resolution |
|---|---|---|
| Low | The CHANGELOG overstated the fix and contradicted an earlier line. | Reworded in c05467e. The earlier line was fixed when this record was added. |
| Low | The `ParseCertificate` recode was checked against one random seed only. | Rerun with X509_SEED 1 to 5 when this record was added: all five pass, between 40994 and 42502 cases each. Each seed accepts only the `go-string-invalid-utf8` substitution, 31 or 32 times. |
| Low | The `Compose` destination's type name comes from `std::any::type_name`, which is not stable. | Stands. Coded as deviation `type-name-text` on `ConvertAssign`. |
| Low | `%T`/`%v` differences on `driver.Bool`, `Int32` and `String` were described only in prose. | Coded as deviation `type-name-text` on all three (c05467e). |
| Low | The x509_check docstring and the parity-loop diagram overstated what is compared. | Both corrected (c05467e). |
| Low | The tar tests assumed `/etc/passwd` is owned by uid 0. | The test now checks the owner first (c05467e). |
