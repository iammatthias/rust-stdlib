#!/usr/bin/env python3
"""Differentially check math/cmplx against Go: special values and branch cuts.

Non-finite components and the sign of exact zeros must match exactly. Finite
components may differ by Go-versus-Rust rounding (libm, fused multiply-add on
Go's arm64): they must agree within RELATIVE of the larger component of the
result. Arithmetic (+, -, *, /) and predicates are compared exactly.
"""
import math
import os
import random
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RELATIVE = 1e-6  # transcendental results; fused multiply-add in Go amplifies cancellation

UNARY = ("acos acosh asin asinh atan atanh conj cos cosh cot exp log log10 sin sinh sqrt tan tanh "
         "neg abs phase polar isinf isnan").split()
BINARY = "pow add sub mul div".split()
EXACT = {"conj", "neg", "isinf", "isnan", "add", "sub", "inf", "nan"}


def bits(x):
    return struct.unpack(">Q", struct.pack(">d", x))[0]


def real(b):
    return struct.unpack(">d", struct.pack(">Q", b))[0]


def h(x):
    return "%016x" % bits(x)


INF = math.inf
NAN = math.nan
VALUES = [0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 2.0, -2.0, 0.25, 3.0, -3.0, 10.0, 100.0, 1e-5, 1e5,
          1e300, 1e-300, 5e-324, 1.7976931348623157e308, 4.0, -4.5, 1e10, 0.7, 0.9999, 1.0001,
          math.pi, -math.pi, math.pi / 2, INF, -INF, NAN]


def rand_part(rng):
    k = rng.randrange(5)
    if k == 0:
        return rng.uniform(-1, 1)
    if k == 1:
        return rng.uniform(-10, 10)
    if k == 2:
        return rng.choice([-1, 1]) * 10 ** rng.uniform(-6, 6)
    if k == 3:
        return float(rng.randrange(-8, 9))
    return rng.uniform(-40, 40)


def requests(rng):
    reqs = ["inf 0 0", "nan 0 0"]
    for op in UNARY:
        for re in VALUES:
            for im in VALUES:
                reqs.append(f"{op} {h(re)} {h(im)}")
        for _ in range(500):
            reqs.append(f"{op} {h(rand_part(rng))} {h(rand_part(rng))}")
    for op in BINARY:
        pool = VALUES[:8] + [INF, -INF, NAN]
        for a in pool:
            for b in pool:
                for c in (0.0, 1.0, -2.0, INF, NAN):
                    reqs.append(f"{op} {h(a)} {h(b)} {h(c)} {h(0.5)}")
                    reqs.append(f"{op} {h(a)} {h(c)} {h(b)} {h(-1.5)}")
        for _ in range(500):
            reqs.append(f"{op} {h(rand_part(rng))} {h(rand_part(rng))} {h(rand_part(rng))} {h(rand_part(rng))}")
    for r in VALUES:
        for t in VALUES:
            reqs.append(f"rect {h(r)} {h(t)}")
    for _ in range(300):
        reqs.append(f"rect {h(rand_part(rng))} {h(rand_part(rng))}")
    return reqs


def is_float(tok):
    return tok == "nan" or len(tok) == 16


def close(expect, actual, scale, rel):
    if expect == actual:
        return True
    if expect == "nan" or actual == "nan":
        return False
    e, a = real(int(expect, 16)), real(int(actual, 16))
    if math.isinf(e) or math.isinf(a):
        return False
    if e == 0 and a == 0:
        return False  # opposite signs of zero (equal strings returned above)
    return abs(e - a) <= rel * scale + 1e-320


def main():
    rng = random.Random(0x636D706C)
    reqs = requests(rng)
    payload = "".join(r + "\n" for r in reqs)
    rust = subprocess.run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "cmplx_probe"],
                          input=payload, text=True, capture_output=True, cwd=ROOT)
    if rust.returncode:
        raise RuntimeError(f"Rust cmplx probe failed:\n{rust.stderr}")
    env = dict(os.environ, GOARCH="amd64")  # no fused multiply-add, like Rust
    probe = subprocess.run(["go", "run", str(ROOT / "tools/cmplx_oracle.go")], input="inf 0 0\n", text=True,
                           capture_output=True, cwd=ROOT, env=env)
    if probe.returncode != 0:
        env = None
    else:
        global RELATIVE
        RELATIVE = 1e-12
    go = subprocess.run(["go", "run", str(ROOT / "tools/cmplx_oracle.go")], input=payload, text=True,
                        capture_output=True, cwd=ROOT, env=env)
    if go.returncode:
        raise RuntimeError(f"Go cmplx oracle failed:\n{go.stderr}")
    r_lines, g_lines = rust.stdout.splitlines(), go.stdout.splitlines()
    if len(r_lines) != len(reqs) or len(g_lines) != len(reqs):
        raise AssertionError("cmplx oracle returned the wrong number of records")
    bad = []
    for req, actual, expect in zip(reqs, r_lines, g_lines):
        op = req.split()[0]
        if env is not None and op not in EXACT:
            # Go's amd64 assembly Log mishandles subnormal arguments.
            args = [real(int(t, 16)) for t in req.split()[1:]]
            if any(0 < abs(v) < 2.2250738585072014e-308 for v in args):
                continue
        a, e = actual.split(), expect.split()
        ok = len(a) == len(e)
        if ok and op not in EXACT and all(is_float(t) for t in e):
            finite = [abs(real(int(t, 16))) for t in e if t != "nan" and not math.isinf(real(int(t, 16)))]
            scale = max(finite) if finite else 0.0
            rel = RELATIVE
            if op == "mul":
                p = [abs(real(int(t, 16))) for t in req.split()[1:]]
                scale, rel = (p[0] + p[1]) * (p[2] + p[3]), 4e-16
            elif op == "div":
                rel = 4e-15
            ok = all(close(x, y, scale, rel) for x, y in zip(e, a))
        else:
            ok = ok and a == e
        if not ok:
            bad.append(f"{req}\n  Rust={actual}\n  Go  ={expect}")
    if bad:
        from collections import Counter
        print("mismatches by operation:", dict(Counter(b.split()[0] for b in bad)))
        print(f"{len(bad)} mismatches of {len(reqs)}; first 25:")
        print("\n".join(bad[:25]))
        raise SystemExit(1)
    print(f"Cmplx Go differential: {len(reqs)} special-value, branch-cut and random vectors passed")


if __name__ == "__main__":
    main()
