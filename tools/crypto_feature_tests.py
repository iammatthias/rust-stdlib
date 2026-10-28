#!/usr/bin/env python3
"""Run rust-stdlib-crypto's library tests under one partial feature set and
require at least one hash-availability test to run.

The availability tests are cfg-gated on which hash packages are enabled; if a
feature edge changes, a guard can stop matching and the tests vanish without a
failure. Usage: crypto_feature_tests.py <features>
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main(features):
    run = subprocess.run(
        ["cargo", "test", "--offline", "--locked", "--lib", "--manifest-path", "crates/crypto/Cargo.toml",
         "--no-default-features", "--features", features],
        cwd=ROOT, capture_output=True, text=True)
    sys.stdout.write(run.stdout)
    sys.stderr.write(run.stderr)
    if run.returncode != 0:
        return run.returncode
    passed = re.findall(r"^test \S*hash_availability_tests::\S+ \.\.\. ok$", run.stdout, re.M)
    if not passed:
        print(f"crypto feature set {features!r}: no hash_availability test ran", file=sys.stderr)
        return 1
    print(f"crypto feature set {features!r}: {len(passed)} hash_availability tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
