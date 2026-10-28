#!/usr/bin/env python3
"""Differentially compare FNV and CRC-64 against Go's standard library."""
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def corpus():
    rng = random.Random(20261012)
    samples = [bytes(rng.randrange(256) for _ in range(size)) for size in range(65)]
    samples.extend((b"a", b"hello", b"123456789", bytes(range(256))))
    for size in (255, 256, 1024, 4095, 4096, 8192, 8193, 16384):
        samples.append(bytes(rng.randrange(256) for _ in range(size)))
    return samples


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=180)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return [json.loads(line) for line in result.stdout.splitlines()]


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("hash differential check requires Go and Cargo on PATH")
    data = corpus()
    payload = "".join(sample.hex() + "\n" for sample in data)
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go = run(["go", "run", "tools/hash_oracle.go"], payload, env)
    rust = run(["cargo", "run", "--offline", "--locked", "--quiet",
                "--example", "hash_conformance"], payload, env)
    if len(go) != len(data) or len(rust) != len(data):
        raise AssertionError("hash oracle returned the wrong number of records")
    if go != rust:
        diffs = [(i, data[i].hex(), go[i] if i < len(go) else None,
                  rust[i] if i < len(rust) else None)
                 for i in range(max(len(go), len(rust)))
                 if i >= len(go) or i >= len(rust) or go[i] != rust[i]]
        raise AssertionError(f"Go/Rust hash mismatch: {diffs[:5]}")
    print(json.dumps({"vectors": len(data), "go_oracle": "passed",
                      "rust_differential": "passed"}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
