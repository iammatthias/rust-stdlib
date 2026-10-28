#!/usr/bin/env python3
"""Differentially compare the crypto hash family against Go's standard library.

Random inputs, keys, salts and lengths are fed to tools/crypto_hash_oracle.go and
crates/crypto/examples/crypto_probe.rs. Every digest, binary hash state, HMAC,
HKDF, PBKDF2, SHAKE/cSHAKE and crypto/subtle result is compared byte for byte,
including error messages. Rust resumes hashing from the state Go marshaled.
"""
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HASHES = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256",
          "sha3_224", "sha3_256", "sha3_384", "sha3_512"]
# Lengths around every block, rate and padding boundary of the hashes above.
BOUNDARIES = sorted({0, 1, 2, 3, 7, 8, 9, 31, 32, 33, 55, 56, 57, 63, 64, 65, 71, 72, 73, 103, 104,
                     105, 111, 112, 113, 119, 120, 121, 127, 128, 129, 135, 136, 137, 143, 144,
                     145, 167, 168, 169, 191, 192, 255, 256, 257})
INTERESTING = [0, 1, 2, 3, 7, 8, 127, 128, 255, 256, 1000, 65535, 65536, 2**31 - 1, -1, -2, -128, -2**31]


def token(name, value):
    return f"{name}={value}"


def corpus():
    rng = random.Random(20261012)

    def blob(size):
        return bytes(rng.randrange(256) for _ in range(size))

    cases = [{"static": "1"}]
    sizes = list(BOUNDARIES) + [rng.randrange(0, 600) for _ in range(300)]
    sizes += [rng.randrange(600, 5000) for _ in range(30)] + [100_000, 262_144]
    for index, size in enumerate(sizes):
        data = blob(size)
        key_len = rng.choice([0, 1, 16, 32, 63, 64, 65, 72, 128, 129, 144, 145, rng.randrange(0, 300)])
        salt_len = rng.choice([0, 0, 8, 16, rng.randrange(0, 70)])
        if index % 37 == 5:
            key_len_out = rng.randrange(8161, 9000)  # over HKDF's 255 * HashLen for most hashes
        else:
            key_len_out = rng.choice([0, 1, 16, 32, 33, 64, rng.randrange(0, 400)])
        iterations = rng.choice([0, 1, 1, 2, 3, 7, rng.randrange(1, 40)])
        if index % 50 == 7:
            iterations = 1000
        cases.append({
            "data": data.hex(), "split": rng.randrange(0, size + 1), "chunk": rng.randrange(1, 200),
            "key": blob(key_len).hex(), "salt": blob(salt_len).hex(), "info": blob(rng.choice([0, 5, rng.randrange(0, 60)])).hex(),
            "klen": key_len_out, "iter": iterations, "slen": rng.choice([0, 1, 31, 32, 100, 168, 169, 400, rng.randrange(0, 700)]),
            "cn": blob(rng.choice([0, 0, 3, 9])).hex(), "cs": blob(rng.choice([0, 0, 4, 20])).hex(),
            "x": rng.choice(INTERESTING + [rng.randrange(-300, 300)]), "y": rng.choice(INTERESTING + [rng.randrange(-300, 300)]),
            "v": rng.randrange(0, 2),
        })
    return cases


def line_of(case, states=None):
    tokens = [token(k, v) for k, v in case.items()]
    for name, state in (states or {}).items():
        tokens.append(token(f"st.{name}", state))
    return " ".join(tokens)


def parse(line):
    fields = {}
    for part in line.split(" "):
        key, _, value = part.partition("=")
        fields[key] = value
    return fields


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=240, encoding="utf-8")
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return [parse(line) for line in result.stdout.splitlines()]


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("crypto hash differential check requires Go and Cargo on PATH")
    cases = corpus()
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go = run(["go", "run", "tools/crypto_hash_oracle.go"], "".join(line_of(c) + "\n" for c in cases), env)
    if len(go) != len(cases):
        raise AssertionError("Go oracle returned the wrong number of records")
    payload = "".join(
        line_of(case, {name: reply[f"state.{name}"] for name in HASHES} if "static" not in case else None) + "\n"
        for case, reply in zip(cases, go))
    rust = run(["cargo", "run", "--offline", "--locked", "--quiet", "--manifest-path",
                "crates/crypto/Cargo.toml", "--example", "crypto_probe"], payload, env)
    if len(rust) != len(cases):
        raise AssertionError("Rust probe returned the wrong number of records")
    compared, errors = 0, 0
    for index, (want, got) in enumerate(zip(go, rust)):
        if want != got:
            diffs = sorted(k for k in set(want) | set(got) if want.get(k) != got.get(k))
            first = diffs[0]
            raise AssertionError(f"case {index}: {len(diffs)} fields differ, first {first}:\n"
                                 f"  go  : {want.get(first)}\n  rust: {got.get(first)}\n  input: {line_of(cases[index])[:300]}")
        compared += len(want)
        errors += sum(1 for v in want.values() if v.startswith("err:"))
    print(json.dumps({"cases": len(cases) - 1, "fields_compared": compared, "agreed_error_results": errors,
                      "go_oracle": "passed", "rust_differential": "passed"}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
