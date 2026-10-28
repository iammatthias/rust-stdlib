#!/usr/bin/env python3
"""Differentially check text/template, text/template/parse and html/template
against Go: thousands of generated and mutated templates plus the inputs of
Go's own test tables, with identical output or identical error text required.
"""
import json
import pathlib
import random
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import template_gen  # noqa: E402


def encode(requests):
    return "".join(json.dumps(r).encode().hex() + "\n" for r in requests)


def run(cmd, payload):
    res = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if res.returncode:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{res.stderr}")
    return res.stdout.splitlines()


ADDR = re.compile(r"0x[0-9a-f]{6,}")


def normalize(line):
    """Pointer addresses are not reproducible; compare them as 0xADDR."""
    parts = line.split(" ")
    out = [parts[0]]
    for p in parts[1:]:
        text = bytes.fromhex(p).decode("utf-8", "surrogateescape")
        out.append(ADDR.sub("0xADDR", text))
    return out


def show(line):
    parts = line.split(" ")
    return parts[0] + " " + " | ".join(repr(bytes.fromhex(p).decode("utf-8", "replace")) for p in parts[1:])


def fixture_requests():
    reqs = []
    for path in sorted((ROOT / "tests/fixtures/template").glob("*.jsonl")):
        reqs += [json.loads(line)["req"] for line in path.read_text().splitlines()]
    return reqs


def main():
    seed = int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x7E3917A7E
    rng = random.Random(seed)
    requests = fixture_requests() + template_gen.generate(rng)
    payload = encode(requests)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "template_probe"], payload)
    go = run(["go", "run", "tools/template_oracle.go", "tools/template_oracle_data.go", "tools/template_oracle_html.go"], payload)
    if len(rust) != len(requests) or len(go) != len(requests):
        raise AssertionError(f"reply count: rust {len(rust)}, go {len(go)}, requests {len(requests)}")
    bad = [i for i, (a, b) in enumerate(zip(rust, go)) if normalize(a) != normalize(b)]
    if bad:
        for i in bad[:8]:
            print(f"vector {i}: {json.dumps(requests[i])}\n  Rust: {show(rust[i])}\n  Go:   {show(go[i])}")
        raise SystemExit(f"template differential: {len(bad)} of {len(requests)} vectors differ")
    modes = {}
    for r in requests:
        modes[r["mode"]] = modes.get(r["mode"], 0) + 1
    print(f"template differential: {len(requests)} vectors identical ({modes})")


if __name__ == "__main__":
    main()
