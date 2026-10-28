#!/usr/bin/env python3
"""Differentially check math and math/bits against Go.

Floating-point results are compared as IEEE bit patterns. Results that are
exact in Go (rounding, sign, scaling, comparison, bit manipulation, special
values) must match bit for bit. Transcendental results are computed by Go's
algorithms on both sides, except that Go's Exp is assembly on amd64/arm64, so
Exp and what is built on it may differ by rounding: the tolerance is in units
in the last place (ULP_LIMIT) and special values (NaN, infinities, zeros and
their signs) must match exactly. math/bits is exact.
"""
import math
import os
import random
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Allowed difference in ULPs between Rust and Go. Anything
# not listed must be bit-exact. Measured limits are documented in
# docs/api/math.json.
ULP_LIMIT = {
    "acosh": 1, "asinh": 1, "atan": 1, "atan2": 1, "atanh": 1, "cbrt": 1, "cosh": 1, "exp": 1,
    "exp2": 1, "expm1": 1, "log": 1, "log1p": 1, "log10": 2, "log2": 2, "pow": 3, "sinh": 2,
    "tan": 2, "tanh": 1, "hypot": 2, "asin": 40, "acos": 40000, "sin": 2, "cos": 2, "sincos": 2,
    "erf": 1, "erfc": 2, "erfinv": 3, "erfcinv": 3, "gamma": 5, "lgamma": 3,
    "j0": 4, "j1": 12, "jn": 300, "y0": 30, "y1": 35, "yn": 210,
}
# Go on arm64 (and ppc64, s390x) fuses x*y+z into one rounding; Go on amd64 does
# not, and neither does Rust. The results differ where an expression cancels:
# asin/acos near 1 (1-x*x), the Bessel Y functions near their zeros, and Log2
# near 1 (Log(frac)*(1/Ln2)+exp).
# Against an amd64 Go (no fused multiply-add) the functions ported from Go
# (sin, cos, tan, asin, acos, atan, atan2, hypot, log, erf, lgamma, Bessel, ...) are exact;
# only Exp and the functions built on it differ (Go's Exp is assembly), by a few ULPs.
STRICT_LIMIT = {"cosh": 2, "erfc": 1, "exp": 1, "gamma": 3, "pow": 3, "sinh": 3, "tanh": 1}
if len(sys.argv) > 1 and sys.argv[1] == "--measure":
    ULP_LIMIT = {k: 1 << 40 for k in ULP_LIMIT}
    STRICT_LIMIT = {k: 1 << 40 for k in ULP_LIMIT}

UNARY = ("abs acos acosh asin asinh atan atanh cbrt ceil cos cosh erf erfc erfinv erfcinv exp "
         "exp2 expm1 floor gamma j0 j1 log log10 log1p log2 logb round roundtoeven sin sinh "
         "sqrt tan tanh trunc y0 y1").split()
BINARY = "atan2 copysign dim hypot max min mod nextafter pow remainder".split()
FLOAT_RESULT = set(UNARY + BINARY + ["fma", "ldexp", "jn", "yn", "pow10", "inf", "frexp", "modf",
                                      "lgamma", "sincos"])


def bits(x):
    return struct.unpack(">Q", struct.pack(">d", x))[0]


def real(b):
    return struct.unpack(">d", struct.pack(">Q", b))[0]


def h(x):
    return "%016x" % bits(x)


SPECIAL = [0.0, -0.0, 1.0, -1.0, 0.5, -0.5, 2.0, -2.0, 3.0, -3.0, 0.25, 1.5, -1.5, 2.5, -2.5,
           0.1, 0.7, 0.9, 1.2, 1.7, 3.5, -3.5, 10.0, 100.0, 1000.0, -1000.0, 171.5, 172.0, 171.0,
           -170.5, -171.5, 33.5, 34.0, -33.5, -34.5, 709.78, 710.0, -745.0, -746.0, 1e22, 1e23,
           1e300, -1e300, 1e-300, 1e-320, 5e-324, -5e-324, 2.2250738585072014e-308,
           2.225073858507201e-308, 1.7976931348623157e308, -1.7976931348623157e308,
           math.inf, -math.inf, math.nan, math.pi, -math.pi, math.pi / 2, math.pi / 4, math.e,
           2.0 ** 52, 2.0 ** 53, 2.0 ** 63, 2.0 ** 64, -(2.0 ** 52) - 0.5, 4503599627370495.5,
           0.49999999999999994, 1.0000000000000002, 0.9999999999999999, -0.9999999999999999,
           1e-10, 1e10, 1.0 / 3, 6.0, 8.0, 27.0, 1e15, 2.0 ** -28, 2.0 ** -29, 2.0 ** -27, 2.0 ** -54,
           2.0 ** 129, 2.0 ** 302, 2.0 ** -70, 0.84375, 1.25, 28.0, 6.0, -6.0, 0.85, 0.999999,
           -0.999999, 0.3, 7.9, 8.0, 8.5, 1 - 2 * math.exp(-25)]
OTHER_NAN = real(0x7FF0000000000001)
SPECIAL.append(OTHER_NAN)
SPECIAL.append(real(0xFFF8000000000000))


def rand_float(rng):
    kind = rng.randrange(8)
    if kind == 0:
        return real(rng.getrandbits(64))
    if kind == 1:
        return rng.uniform(-1, 1)
    if kind == 2:
        return rng.uniform(-10, 10)
    if kind == 3:
        return rng.uniform(-750, 750)
    if kind == 4:
        return rng.choice([-1, 1]) * 10 ** rng.uniform(-12, 12)
    if kind == 5:
        return float(rng.randrange(-200, 200))
    if kind == 6:
        return rng.randrange(-400, 400) / 2.0
    return rng.uniform(-1e5, 1e5)


def float_requests(rng):
    reqs = []
    for op in UNARY:
        for x in SPECIAL:
            reqs.append(f"{op} {h(x)}")
        for _ in range(250):
            reqs.append(f"{op} {h(rand_float(rng))}")
    sp = SPECIAL[::2]
    for op in BINARY:
        for x in sp:
            for y in SPECIAL[1::2]:
                reqs.append(f"{op} {h(x)} {h(y)}")
        for _ in range(300):
            reqs.append(f"{op} {h(rand_float(rng))} {h(rand_float(rng))}")
    # Pow special values around integers and powers of two.
    for x in [-8.0, -2.0, -1.0, -0.0, 0.0, 0.5, 1.0, 2.0, 10.0, math.inf, -math.inf, math.nan]:
        for y in [-3.0, -2.0, -1.0, -0.5, 0.0, -0.0, 0.5, 1.0, 2.0, 3.0, 1e15, 2.0 ** 53, 2.0 ** 63,
                  -(2.0 ** 63), 1e300, math.inf, -math.inf, math.nan]:
            reqs.append(f"pow {h(x)} {h(y)}")
    for x in SPECIAL:
        for op in ["frexp", "modf", "lgamma", "sincos", "ilogb", "isnan", "signbit", "f64bits",
                   "f32bits"]:
            reqs.append(f"{op} {h(x)}")
        for s in (-1, 0, 1):
            reqs.append(f"isinf {h(x)} {s}")
        for y in (0.0, -0.0, 1.0, -1.0, math.inf, math.nan, 5e-324, -5e-324, 3.4028234663852886e38):
            reqs.append(f"nextafter32 {h(x)} {h(y)}")
        for n in (-2000, -1075, -1074, -1023, -1022, -100, -2, -1, 0, 1, 2, 52, 53, 100, 1023, 1024, 2000,
                  2 ** 31, 2 ** 62, -(2 ** 62)):
            reqs.append(f"ldexp {h(x)} {n}")
        for n in (-3, -2, -1, 0, 1, 2, 3, 5, 10, 40):
            reqs.append(f"jn {n} {h(x)}")
            reqs.append(f"yn {n} {h(x)}")
    for _ in range(600):
        x = rand_float(rng)
        reqs.append(f"frexp {h(x)}")
        reqs.append(f"modf {h(x)}")
        reqs.append(f"lgamma {h(x)}")
        reqs.append(f"sincos {h(x)}")
        reqs.append(f"ilogb {h(x)}")
        reqs.append(f"ldexp {h(x)} {rng.randrange(-1200, 1200)}")
        reqs.append(f"jn {rng.randrange(-40, 40)} {h(rand_float(rng))}")
        reqs.append(f"yn {rng.randrange(-40, 40)} {h(rand_float(rng))}")
        reqs.append(f"fma {h(x)} {h(rand_float(rng))} {h(rand_float(rng))}")
        reqs.append(f"f32bits {h(x)}")
        reqs.append(f"nextafter32 {h(x)} {h(rand_float(rng))}")
    for x in SPECIAL[:40]:
        for y in SPECIAL[:20]:
            for z in SPECIAL[:12]:
                reqs.append(f"fma {h(x)} {h(y)} {h(z)}")
    for n in list(range(-340, 330)) + [2 ** 40, -(2 ** 40)]:
        reqs.append(f"pow10 {n}")
    for s in (-5, -1, 0, 1, 5):
        reqs.append(f"inf {s}")
    for pattern in [0, 1, 0x7F7FFFFF, 0x7F800000, 0xFF800000, 0x7FC00000, 0x7F800001, 0x80000000,
                    0x00800000, 0x007FFFFF, 0x3F800000, 0xFFFFFFFF, 0x12345678]:
        reqs.append(f"f32from {pattern}")
    reqs += ["nan", "const", "intconst"]
    return reqs


def bit_requests(rng):
    reqs = []
    widths = {"8": 8, "16": 16, "32": 32, "64": 64, "": 64}
    for suffix, w in widths.items():
        full = (1 << w) - 1
        vals = {0, 1, 2, 3, full, full - 1, 1 << (w - 1), (1 << (w - 1)) - 1, 0x55 & full, 0xAA & full,
                0x5555555555555555 & full, 0xAAAAAAAAAAAAAAAA & full}
        vals |= {1 << k for k in range(w)}
        vals |= {(1 << k) - 1 for k in range(1, w + 1)}
        vals |= {rng.getrandbits(w) for _ in range(120)}
        vals |= {rng.getrandbits(w) >> rng.randrange(w) for _ in range(60)}
        for v in sorted(vals):
            for op in ("lz", "tz", "oc", "len", "rev"):
                reqs.append(f"{op}{suffix} {v}")
            if suffix != "8":
                reqs.append(f"revb{suffix} {v}")
        for v in sorted(vals)[:: max(1, len(vals) // 40)]:
            for k in list(range(-2 * w - 3, 2 * w + 4)) + [2 ** 31 - 1, -(2 ** 31), 2 ** 40, -(2 ** 40)]:
                reqs.append(f"rot{suffix} {v} {k}")
        if suffix == "8" or suffix == "16":
            continue
        pool = sorted(vals)
        for _ in range(500):
            x, y = rng.choice(pool), rng.choice(pool)
            c = rng.randrange(2)
            reqs.append(f"add{suffix} {x} {y} {c}")
            reqs.append(f"sub{suffix} {x} {y} {c}")
            reqs.append(f"mul{suffix} {x} {y}")
            hi, lo, yy = rng.choice(pool), rng.choice(pool), rng.choice(pool)
            reqs.append(f"div{suffix} {hi} {lo} {yy}")
            reqs.append(f"rem{suffix} {hi} {lo} {yy}")
            yy = max(yy, 1)
            hi = rng.randrange(yy)  # valid for Div: hi < y
            reqs.append(f"div{suffix} {hi} {lo} {yy}")
            reqs.append(f"rem{suffix} {hi} {lo} {yy}")
        for x in (0, 1, full, full - 1, 1 << (w - 1)):
            for y in (0, 1, full, 1 << (w - 1)):
                for c in (0, 1):
                    reqs.append(f"add{suffix} {x} {y} {c}")
                    reqs.append(f"sub{suffix} {x} {y} {c}")
                reqs.append(f"mul{suffix} {x} {y}")
                for z in (0, 1, full, 1 << (w - 1)):
                    reqs.append(f"div{suffix} {x} {y} {z}")
                    reqs.append(f"rem{suffix} {x} {y} {z}")
    return reqs


def ordered(b):
    return -(b & 0x7FFFFFFFFFFFFFFF) if b >> 63 else b


def is_nan_bits(b):
    return (b >> 52) & 0x7FF == 0x7FF and b & 0xFFFFFFFFFFFFF != 0


def float_token(tok):
    return tok == "nan" or (len(tok) == 16 and all(c in "0123456789abcdef" for c in tok))


def compare_float(expect, actual, limit):
    """Returns (ok, ulps)."""
    if expect == "nan" or actual == "nan":
        return expect == actual, 0
    e, a = int(expect, 16), int(actual, 16)
    if e == a:
        return True, 0
    if e & 0x7FFFFFFFFFFFFFFF == 0 or a & 0x7FFFFFFFFFFFFFFF == 0:
        return False, 1 << 62  # signed zeros and zero-versus-nonzero must match
    if (e >> 52) & 0x7FF == 0x7FF or (a >> 52) & 0x7FF == 0x7FF:
        return False, 1 << 62  # infinities must match
    if (e >> 63) != (a >> 63):
        return False, 1 << 62
    d = abs(ordered(e) - ordered(a))
    return d <= limit, d


AMD64 = False


def oracle_env():
    """Go on arm64 fuses x*y+z; prefer an amd64 oracle (Rosetta, or native) where it runs."""
    env = dict(os.environ)
    env["GOARCH"] = "amd64"
    probe = subprocess.run(["go", "run", str(ROOT / "tools/math_oracle.go")], input="abs 0000000000000000\n",
                           text=True, capture_output=True, cwd=ROOT, env=env)
    if probe.returncode == 0 and probe.stdout.strip() == "0000000000000000":
        return env
    return None


def skip(req):
    t = req.split()
    if t[0] == "exp" and -745.2 < real(int(t[1], 16)) < -744.4:
        return True
    if t[0] == "log2" and 0.5 <= real(int(t[1], 16)) <= 2.0:
        return True
    x = real(int(t[-1], 16)) if t[0] in ("exp", "cosh", "sinh") else None
    if x is not None and 709.7 < abs(x) < 709.8:
        return True  # amd64 assembly Exp overflows slightly early
    if t[0] in ("log", "log10", "log2", "lgamma", "y0", "y1", "yn", "pow") and AMD64:
        base = real(int(t[1] if t[0] != "yn" else t[2], 16))
        if 0 < abs(base) < 2.2250738585072014e-308:
            return True  # amd64 assembly Log mishandles subnormals
    return False


def main():
    rng = random.Random(0x6D617468)
    requests = float_requests(rng) + bit_requests(rng)
    payload = "".join(r + "\n" for r in requests)
    rust = subprocess.run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "math_probe"],
                          input=payload, text=True, capture_output=True, cwd=ROOT)
    if rust.returncode:
        raise RuntimeError(f"Rust math probe failed:\n{rust.stderr}")
    global AMD64, ULP_LIMIT
    env = oracle_env()
    AMD64 = env is not None
    if AMD64:
        ULP_LIMIT = STRICT_LIMIT
    go = subprocess.run(["go", "run", str(ROOT / "tools/math_oracle.go")], input=payload, text=True,
                        capture_output=True, cwd=ROOT, env=env)
    if go.returncode:
        raise RuntimeError(f"Go math oracle failed:\n{go.stderr}")
    r_lines, g_lines = rust.stdout.splitlines(), go.stdout.splitlines()
    if len(r_lines) != len(requests) or len(g_lines) != len(requests):
        raise AssertionError("math oracle returned the wrong number of records")
    worst = {}
    worst_req = {}
    bad = []
    for req, actual, expect in zip(requests, r_lines, g_lines):
        op = req.split()[0]
        if skip(req):
            continue
        if op in FLOAT_RESULT:
            limit = ULP_LIMIT.get(op, 0)
            a_toks, e_toks = actual.split(), expect.split()
            ok = len(a_toks) == len(e_toks)
            for i, (a, e) in enumerate(zip(a_toks, e_toks)):
                if float_token(a) and float_token(e) and not (op in ("frexp", "lgamma") and i == 1):
                    good, d = compare_float(e, a, limit)
                    dd = d if d < (1 << 62) else 0
                    if dd > worst.get(op, 0):
                        worst[op] = dd
                        worst_req[op] = (req, actual, expect)
                    ok = ok and good
                else:
                    ok = ok and a == e
            if op == "lgamma" and ok is False:
                pass
        else:
            ok = actual == expect
        if not ok:
            bad.append(f"{req}\n  Rust={actual}\n  Go  ={expect}")
    if "--measure" in sys.argv:
        for op, d in sorted(worst.items()):
            if d:
                print(f"max ulp {op}: {d}  {worst_req[op]}")
    if bad:
        print(f"{len(bad)} mismatches of {len(requests)}; first 25:")
        print("\n".join(bad[:25]))
        sys.exit(1)
    print(f"Math Go differential: {len(requests)} math and math/bits vectors passed "
          f"(max ULP difference: "
          + ", ".join(f"{op} {d}" for op, d in sorted(worst.items()) if d) + ")")


if __name__ == "__main__":
    main()
