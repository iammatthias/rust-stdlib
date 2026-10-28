#!/usr/bin/env python3
"""Go/Rust shared vectors. Python and Go dependencies are standard-library only."""
import argparse
import base64
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]

def corpus():
    rng = random.Random(20261012)
    cases = []
    for length in [0, 1, 2, 3, 4, 5, 6, 7, 15, 31, 32, 63, 64, 127, 255, 256, 1024]:
        data = bytes(rng.randrange(256) for _ in range(length))
        cases.append(({"op": "hex", "input": data.hex().upper()}, data.hex()))
        for variant in ["standard", "url", "raw-standard", "raw-url"]:
            encoded = (base64.urlsafe_b64encode(data) if "url" in variant else base64.b64encode(data)).decode("ascii")
            if variant.startswith("raw-"):
                encoded = encoded.rstrip("=")
            cases.append(({"op": "base64", "input": data.hex(), "variant": variant}, encoded))
            cases.append(({"op": "base64-decode", "input": encoded, "variant": variant}, data.hex()))
    for text in ["", "hello", "a b+c", "a/b?c=d&e=f", "-._~", "!$&'()*+,;=:@", "日本語", "😀", "\x00\r\n", "<&>"]:
        cases.append(({"op": "query-escape", "input": text}, urllib.parse.quote_plus(text, safe="")))
    for text, canonical in [
        ("null", "null"), ("true", "true"), ("false", "false"),
        (" 42 ", "42"), ("9007199254740993", "9007199254740993"),
        ("1e9999", "1e9999"), ("-0.000e+12", "-0.000e+12"),
        ('{"z":1,"a":2}', '{"a":2,"z":1}'),
        ('[1,"two",null]', '[1,"two",null]'),
        ('"\\uD83D\\uDE00"', '"😀"'), ('"<>&"', '"<>&"'),
        ('{"a":[true,{"b":"日本語"}]}', '{"a":[true,{"b":"日本語"}]}'),
    ]:
        cases.append(({"op": "json", "input": text}, canonical))
    return cases

def execute(command, payload, environment):
    run = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT, env=environment, timeout=180)
    if run.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{run.stderr}")
    return [json.loads(line) for line in run.stdout.splitlines()]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--oracle-only", action="store_true", help="Run Go against fixed expectations; does not verify Rust.")
    args = parser.parse_args()
    if not shutil.which("go"):
        raise RuntimeError("Go is required for the compatibility oracle")
    cases = corpus()
    payload = "".join(json.dumps(case, ensure_ascii=False) + "\n" for case, _ in cases)
    expected = [{"ok": result} for _, result in cases]
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go = execute(["go", "run", "tools/oracle.go"], payload, env)
    if go != expected:
        differences = [(i, cases[i][0], expected[i], go[i] if i < len(go) else None) for i in range(len(expected)) if i >= len(go) or go[i] != expected[i]]
        raise AssertionError(f"Go oracle differs from fixed expectations: {differences[:5]}")
    result = {"vectors": len(cases), "go_oracle": "passed", "rust_differential": "not_run"}
    if not args.oracle_only:
        if not shutil.which("cargo"):
            raise RuntimeError("Cargo is required to run the Rust side; Go-only success does not validate Rust")
        rust = execute(["cargo", "run", "--offline", "--locked", "--quiet", "--example", "conformance"], payload, env)
        if rust != go:
            differences = [(i, cases[i][0], go[i], rust[i] if i < len(rust) else None) for i in range(len(go)) if i >= len(rust) or rust[i] != go[i]]
            raise AssertionError(f"Rust/Go differences: {differences[:5]}")
        result["rust_differential"] = "passed"
    print(json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, AssertionError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
