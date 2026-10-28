#!/usr/bin/env python3
"""Differentially compare duration parsing and formatting with Go time."""
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
UNITS = ("ns", "us", "µs", "μs", "ms", "s", "m", "h")


def corpus():
    values = [
        "", "0", "+0", "-0", "0ns", "+1ns", "-1ns", ".s", "1", "1.",
        "1.s", ".5s", "1.9ns", "0.9ns", "1.0000000001s", "2h45m",
        "1h2m3.004005006s", "1µs", "1μs", "2562047h47m16.854775807s",
        "-2562047h47m16.854775808s", "9223372036854775807ns",
        "9223372036854775808ns", "-9223372036854775808ns",
        "-9223372036854775809ns", "9223372036854775807ns1ns",
        "1..s", "1.2.3s", "1e3s", "1fortnight", "1s-2s", "١s",
        "0." + "0" * 400 + "1ns",
    ]
    rng = random.Random(20261012)
    for _ in range(500):
        sign = rng.choice(("", "+", "-"))
        pieces = []
        for _ in range(rng.randint(1, 4)):
            whole = str(rng.randrange(0, 10**rng.randint(1, 19)))
            fraction = ""
            if rng.randrange(2):
                fraction = "." + "".join(
                    str(rng.randrange(10)) for _ in range(rng.randint(0, 24))
                )
            pieces.append(whole + fraction + rng.choice(UNITS))
        values.append(sign + "".join(pieces))
    malformed = ("x", "--1s", "++1s", "1e", "1µ", "1μ", "1 s", "1s.", "1秒")
    values.extend(malformed)
    return list(dict.fromkeys(values))


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=180)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return [json.loads(line) for line in result.stdout.splitlines()]


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("duration differential check requires Go and Cargo on PATH")
    values = corpus()
    payload = "".join(value + "\n" for value in values)
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go = run(["go", "run", "tools/duration_oracle.go"], payload, env)
    rust = run(["cargo", "run", "--offline", "--locked", "--quiet",
                "--example", "duration_probe"], payload, env)
    if len(go) != len(values) or len(rust) != len(values):
        raise AssertionError("duration oracle returned the wrong number of records")
    if go != rust:
        diffs = [(i, values[i], go[i] if i < len(go) else None,
                  rust[i] if i < len(rust) else None)
                 for i in range(max(len(go), len(rust)))
                 if i >= len(go) or i >= len(rust) or go[i] != rust[i]]
        raise AssertionError(f"Go/Rust duration mismatch: {diffs[:12]}")
    print(json.dumps({"vectors": len(values), "go_oracle": "passed",
                      "rust_differential": "passed"}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
