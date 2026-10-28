#!/usr/bin/env python3
"""Differentially compare math/big (Int, Rat, Float) with Go.

tools/big_oracle.go and examples/big_probe.rs implement the same line
protocol; every reply must be identical. Operands mix zero, +-1, powers of two
+-1 around limb boundaries, dense and sparse random values up to 4000 bits and
both signs. Integer results are compared as exact hex text; Float results as
exact 'p'-format text plus Accuracy, for all six rounding modes and a spread of
precisions; Text output is compared in every format at several precisions.
Expensive operations (modular exponentiation, primality, all-base Text) use
smaller operands and fewer cases to keep the unoptimized probe fast.
"""
import collections
import pathlib
import random
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIMB_BITS = [1, 2, 31, 32, 33, 52, 53, 54, 63, 64, 65, 127, 128, 129, 191, 192, 193,
             255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2559, 2560, 2561, 4000]
PRECS = [1, 2, 3, 4, 7, 8, 23, 24, 25, 52, 53, 54, 63, 64, 65, 100, 127, 128, 129,
         200, 256, 300, 1000]
FMT_INT = ["%d", "%x", "%X", "%o", "%O", "%b", "%s", "%v", "%#x", "%#X", "%#o", "%#b",
           "%+d", "% d", "%10d", "%-10d", "%010d", "%.5d", "%8.3d", "%.0d", "%+#020x",
           "% x", "%-#12o", "%q", "%08.4X", "%.0x"]
FMT_FLOAT = ["%e", "%E", "%f", "%F", "%g", "%G", "%b", "%x", "%v", "%.3e", "%.0f",
             "%.10g", "%+.4f", "% .2e", "%12.4f", "%-12.4e", "%012.3f", "%+012.3g", "%.0e",
             "%.20f", "%8g", "%q", "%X", "%.2x", "% g", "%0+20.10e"]


def rand_bits(rng, n):
    if n <= 0:
        return 0
    kind = rng.random()
    if kind < 0.1:
        return (1 << n) - 1
    if kind < 0.2:
        v = 1 << (n - 1)
        for _ in range(rng.randrange(4)):
            v |= 1 << rng.randrange(n)
        return v
    return rng.getrandbits(n) | (1 << (n - 1))


def bit_size(rng, limit):
    roll = rng.random()
    if roll < 0.3:
        return rng.choice([b for b in LIMB_BITS if b <= limit] or [1])
    if roll < 0.6:
        return rng.randrange(0, min(limit, 300) + 1)
    if roll < 0.85:
        return rng.randrange(0, min(limit, 1200) + 1)
    return rng.randrange(0, limit + 1)


def rand_mag(rng, limit=4000):
    roll = rng.random()
    if roll < 0.05:
        return rng.choice([0, 1, 2, 3])
    if roll < 0.2:
        k = rng.choice([b for b in LIMB_BITS if b <= limit])
        return (1 << k) + rng.choice([-1, 0, 1])
    return rand_bits(rng, bit_size(rng, limit))


def rand_int(rng, limit=4000, signed=True):
    v = rand_mag(rng, limit)
    if signed and rng.random() < 0.45:
        v = -v
    return v


def lit(v, rng=None):
    """A Go base-0 literal for v (hex or decimal)."""
    if rng is not None and rng.random() < 0.5:
        return str(v)
    return ("-" if v < 0 else "") + hex(abs(v))


def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def rand_prime(rng, bits):
    while True:
        p = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if is_prime(p):
            return p


def rat_lit(rng, limit=600):
    a = rand_int(rng, limit)
    b = rand_mag(rng, limit) or 1
    return f"{a}/{b}"


def float_operand(rng, prec=None, mode=None, max_exp=400):
    """'prec,mode,text' with an exact or rounded binary/decimal literal."""
    if prec is None:
        prec = rng.choice(PRECS + [rng.randrange(1, 400)])
    if mode is None:
        mode = rng.randrange(6)
    roll = rng.random()
    if roll < 0.06:
        text = rng.choice(["0", "-0", "+Inf", "-Inf", "1", "-1", "0.5", "3"])
    elif roll < 0.75:
        bits = rng.choice([1, 2, 3, 24, 53, 54, 64, 65, 128, rng.randrange(1, 300)])
        m = rand_bits(rng, bits)
        e = rng.randrange(-max_exp, max_exp + 1)
        text = f"{'-' if rng.random() < 0.45 else ''}{hex(m)}p{e}"
    else:
        digits = str(rand_bits(rng, rng.randrange(1, 200)))
        point = rng.randrange(len(digits) + 1)
        e = rng.randrange(-max_exp // 3, max_exp // 3 + 1)
        text = f"{'-' if rng.random() < 0.45 else ''}{digits[:point]}.{digits[point:]}e{e}"
    return f"{prec},{mode},{text}"


def int_lines(rng, counts):
    lines = []

    def add(kind, line):
        counts[kind] += 1
        lines.append(line)

    for _ in range(5000):
        x, y = rand_int(rng), rand_int(rng)
        op = rng.choice(["i.add", "i.sub", "i.mul", "i.cmp", "i.and", "i.or", "i.xor", "i.andnot"])
        add("int-binary", f"{op} {lit(x, rng)} {lit(y, rng)}")
    for _ in range(4000):
        x, y = rand_int(rng), rand_int(rng)
        if rng.random() < 0.3:
            y = rand_int(rng, max(abs(x).bit_length(), 1))
        if rng.random() < 0.01:
            y = 0
        op = rng.choice(["i.quo", "i.rem", "i.div", "i.mod", "i.quorem", "i.divmod"])
        add("int-division", f"{op} {lit(x)} {lit(y)}")
    for _ in range(600):
        x, y = rand_int(rng, 1000), rand_int(rng, 600) or 7
        add("int-division", f"i.divide {lit(x)} {lit(y)} {rng.choice([0, 2, 4, 5, 5, 0, 1])}")
    # Beyond 4000 bits: Karatsuba (40+ limbs) on balanced and unbalanced
    # operands, long division and recursive decimal conversion.
    for _ in range(250):
        x = rand_int(rng, 20000) if rng.random() < 0.5 else rand_bits(rng, rng.randrange(2560, 20000))
        y = rand_int(rng, rng.choice([2600, 6000, 20000]))
        op = rng.choice(["i.mul", "i.mul", "i.quorem", "i.divmod", "i.gcd"])
        add("int-large", f"{op} {lit(x)} {lit(y or 3)}")
        add("int-large", f"i.misc {lit(x)}")
    for _ in range(2500):
        x = rand_int(rng)
        n = rng.choice([0, 1, 63, 64, 65, 128, rng.randrange(0, 300), rng.randrange(0, 5000)])
        add("int-shift", f"{rng.choice(['i.lsh', 'i.rsh'])} {lit(x)} {n}")
    for _ in range(2000):
        x = rand_int(rng)
        i = rng.choice([0, 1, 63, 64, 65, rng.randrange(0, 4100)])
        add("int-bit", f"i.bit {lit(x)} {i}")
    for _ in range(3000):
        add("int-misc", f"i.misc {lit(rand_int(rng), rng)}")
    for v in [0, 1, -1, (1 << 63) - 1, 1 << 63, -(1 << 63), -(1 << 63) - 1, (1 << 64) - 1, 1 << 64,
              (1 << 53) + 1, (1 << 54) + 2, (1 << 54) + 6, -(1 << 1024), (1 << 1024) - (1 << 970),
              (1 << 1024) - (1 << 971)]:
        add("int-misc", f"i.misc {lit(v)}")
    for _ in range(700):
        m = rng.choice([None, 0, 1, -1] + [rand_int(rng, 1100) for _ in range(8)])
        x = rand_int(rng, 1100)
        y = rand_int(rng, 700) if rng.random() < 0.8 else rand_int(rng, 64)
        if m is None or m == 0:
            y = abs(y) % 300 if rng.random() < 0.9 else -abs(y)
            x = rand_int(rng, 80)
        if rng.random() < 0.08:
            m = 1 << rng.randrange(1, 300)
        add("int-exp", f"i.exp {lit(x)} {lit(y)} {'nil' if m is None else lit(m)}")
    for _ in range(30):
        add("int-exp", f"i.exp {lit(rand_int(rng, 2048))} {lit(rand_mag(rng, 2048))} {lit(rand_bits(rng, 2048) | 1)}")
    for _ in range(1500):
        a, b = rand_int(rng), rand_int(rng)
        if rng.random() < 0.3:
            g = rand_mag(rng, 500)
            a, b = a * g, b * g
        add("int-gcd", f"i.gcd {lit(a)} {lit(b)}")
    for _ in range(800):
        g, n = rand_int(rng, 1500), rand_int(rng, 1500)
        if n == 0:
            n = 97
        add("int-modinv", f"i.modinv {lit(g)} {lit(n)}")
    primes = [rand_prime(rng, rng.choice([2, 3, 5, 8, 16, 32, 61, 64, 65, 100, 127, 200, 256]))
              for _ in range(80)] + [5, 13, 17, 41, 73, 97, 113, 193, 257, 65537, (1 << 61) - 1,
                                     (1 << 127) - 1, 2 ** 255 - 19]
    for _ in range(900):
        p = rng.choice(primes)
        x = rand_int(rng, p.bit_length() + 10)
        if rng.random() < 0.5:
            r = rng.randrange(p)
            x = r * r % p
        add("int-modsqrt", f"i.modsqrt {lit(x)} {lit(p)}")
    for _ in range(600):
        y = rand_int(rng, 600)
        if rng.random() < 0.9:
            y |= 1
        add("int-jacobi", f"i.jacobi {lit(rand_int(rng, 600))} {lit(y)}")
    for _ in range(500):
        n = rng.randrange(0, 12)
        roll = rng.random()
        if roll < 0.35:
            x = rand_prime(rng, rng.randrange(2, 520))
        elif roll < 0.5:
            x = rand_prime(rng, rng.randrange(2, 130)) * rand_prime(rng, rng.randrange(2, 130))
        elif roll < 0.6:
            x = rng.randrange(0, 200)
        else:
            x = rand_int(rng, 520)
        add("int-prime", f"i.prime {lit(x)} {n}")
    for x in [2047, 1373653, 25326001, 3215031751, 2152302898747, 3474749660383, 341550071728321,
              3825123056546413051, 318665857834031151167461, 3317044064679887385961981,
              (1 << 64) + 13, 2 ** 89 - 1, 2 ** 107 - 1, 2 ** 521 - 1, 2 ** 607 - 1]:
        add("int-prime", f"i.prime {x} 0")
        add("int-prime", f"i.prime {x} 10")
    for _ in range(250):
        add("int-text", f"i.text {lit(rand_int(rng, rng.choice([64, 300, 1500, 4000])))}")
    alphabet = "0123456789abcdefxyzABCDEFXYZ_+-.oObBxX "
    for _ in range(4000):
        base = rng.choice([0, 0, 0, 2, 8, 10, 16, 36, 37, 62, rng.randrange(2, 63)])
        roll = rng.random()
        if roll < 0.5:
            v = rand_int(rng, 1500)
            pick = rng.choice([2, 8, 10, 16]) if base == 0 else base
            digits = int_text(abs(v), pick)
            prefix = {2: "0b", 8: rng.choice(["0o", "0O", "0"]), 10: "", 16: rng.choice(["0x", "0X"])}[pick] if base == 0 else ""
            if base == 0 and rng.random() < 0.3:
                digits = "_".join(digits[i:i + 3] for i in range(0, len(digits), 3))
            if base == 0 and prefix and rng.random() < 0.2:
                prefix += "_"
            s = ("-" if v < 0 else rng.choice(["", "+"])) + prefix + digits
            if rng.random() < 0.2 and len(s) > 1:
                i = rng.randrange(len(s))
                s = s[:i] + rng.choice(alphabet) + s[i + 1:]
        else:
            s = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 12)))
        add("int-parse", f"i.parse h{s.encode().hex()} {base}")
    for s in ["", "0", "-0", "+0", "00", "08", "0_7", "0_", "_0", "0x", "0x_", "0x_1", "0b", "0o",
              "0b102", "1__2", "1_", "-", "+", "0xg", "z", "Z", "0B1", "0O7", "0X1F", "\xff", "1\x00"]:
        for base in (0, 10, 16, 36, 62):
            add("int-parse", f"i.parse h{s.encode('latin-1').hex()} {base}")
        add("int-unmarshal", f"i.unmarshal h{s.encode('latin-1').hex()}")
    for _ in range(300):
        add("int-unmarshal", f"i.unmarshal h{lit(rand_int(rng, 300), rng).encode().hex()}")
    for _ in range(2000):
        add("int-format", f"i.fmt h{rng.choice(FMT_INT).encode().hex()} {lit(rand_int(rng, 400))}")
    for v in [0, 1, -1]:
        for f in FMT_INT:
            add("int-format", f"i.fmt h{f.encode().hex()} {v}")
    for _ in range(300):
        a = rng.randrange(-60, 200)
        b = a + rng.randrange(-3, 120)
        add("int-misc", f"i.mulrange {a} {b}")
    add("int-misc", "i.mulrange -1000000000 1000000000")
    add("int-misc", "i.mulrange 1 0")
    for _ in range(300):
        n = rng.randrange(-5, 400)
        add("int-misc", f"i.binomial {n} {rng.randrange(-3, n + 5)}")
    for _ in range(400):
        v = rand_int(rng, 600)
        n = (abs(v).bit_length() + 7) // 8 + rng.choice([-1, 0, 0, 1, 5])
        add("int-bytes", f"i.fill {lit(v)} {max(n, 0)}")
        add("int-bytes", f"i.setbytes {rng.randbytes(rng.randrange(0, 70)).hex() or '00'}")
        add("int-bytes", f"i.gob {lit(v)}")
    junk = ["", "", " ", "x", "z9", ".5", "_1", "/3", "e5", "\t7", "\xc3\xa9", "-"]
    for _ in range(600):
        verb = rng.choice("bodxXsvq")
        v = rand_int(rng, 300)
        body = rng.choice([lit(v, rng), int_text(abs(v), 16), int_text(abs(v), 2), str(v), ""])
        text = rng.choice(["", " ", "  \t"]) + body + rng.choice(junk)
        add("int-scan", f"i.scan {verb} h{text.encode().hex()}")
    for _ in range(400):
        verb = rng.choice("efgEFGvdx")
        text = rng.choice(["", " "]) + rng.choice([rat_lit(rng, 200), str(rand_int(rng, 100)), "1.5e3", "-.25",
                                                   "1/0", "3/x", "0x10", "1e", ""]) + rng.choice(junk)
        add("rat-scan", f"q.scan {verb} h{text.encode().hex()}")
    for _ in range(400):
        text = rng.choice(["", " "]) + float_operand(rng).split(",", 2)[2] + rng.choice(junk)
        add("float-scan", f"f.scan {rng.choice(PRECS + [0])} {rng.randrange(6)} h{text.encode().hex()}")
    for _ in range(300):
        add("int-rand", f"i.rand {rng.randrange(-(1 << 63), 1 << 63)} {lit(rand_int(rng, 700))}")
    return lines


def int_text(v, base):
    digits = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if v == 0:
        return "0"
    out = []
    while v:
        v, r = divmod(v, base)
        out.append(digits[r])
    return "".join(reversed(out))


def rat_lines(rng, counts):
    lines = []

    def add(kind, line):
        counts[kind] += 1
        lines.append(line)

    for _ in range(3000):
        x, y = rat_lit(rng), rat_lit(rng)
        op = rng.choice(["q.add", "q.sub", "q.mul", "q.quo", "q.cmp"])
        add("rat-arith", f"{op} {x} {y}")
    for _ in range(2000):
        x = rat_lit(rng, rng.choice([64, 200, 1200]))
        if rng.random() < 0.2:
            x = f"{rand_int(rng, 1100)}/{1 << rng.randrange(0, 1200)}"
        add("rat-misc", f"q.misc {x}")
    for x in ["0", "1/3", "-1/3", "1/2", "-5/2", "7/2", "2/3", "1/1024", "3/1000",
              f"{(1 << 53) + 1}/1", f"1/{1 << 1074}", f"1/{1 << 1075}", f"3/{1 << 1076}",
              f"{(1 << 1024) - 1}/1", f"{1 << 1024}/1", f"1/{1 << 149}", f"1/{1 << 150}"]:
        add("rat-misc", f"q.misc {x}")
    pieces = ["1", "0", "-", "+", ".", "/", "e", "E", "p", "_", "x", "0x", "0b", "0o", "5", "9",
              "a", "f", "3", "12", "e-", "e+", "p-"]
    for _ in range(3000):
        roll = rng.random()
        if roll < 0.35:
            digits = str(rand_mag(rng, 300))
            point = rng.randrange(len(digits) + 1)
            s = (rng.choice(["", "-", "+"]) + digits[:point] + rng.choice([".", ""]) + digits[point:]
                 + rng.choice(["", f"e{rng.randrange(-400, 400)}", f"E+{rng.randrange(0, 50)}",
                               f"p{rng.randrange(-300, 300)}", "e1_0"]))
        elif roll < 0.5:
            s = f"{lit(rand_int(rng, 400), rng)}/{lit(rand_mag(rng, 400), rng)}"
        elif roll < 0.62:
            s = (rng.choice(["", "-"]) + rng.choice(["0x", "0b", "0o", "0X"]) +
                 int_text(rand_mag(rng, 100), 16)[:20] + rng.choice(["", ".8", ".1p-4", "p3", "e2"]))
        else:
            s = "".join(rng.choice(pieces) for _ in range(rng.randrange(1, 9)))
        add("rat-parse", f"q.parse h{s.encode().hex()}")
    # Accepted values at the exponent caps are tested in tests/big.rs; their
    # million-digit decimal text is too slow for the unoptimized probe.
    for s in ["1e1000001", "1e-1000001", "1p10000001", "1e3000", "1e-3000", "1p-30000",
              "1p-10000001", "0e99999999999", "1e9223372036854775807", "1e-9223372036854775808",
              "1e9223372036854775808", "0x1.8p1", "0b1.1", "0o1.4", "1/0", "0/1", "-0/5", "1/-2",
              "0x10/0x4", "1_000/1_0", ".5", "5.", "-.5e1", "1.5e", "1e+", "1__0", "0.1_0"]:
        add("rat-parse", f"q.parse h{s.encode().hex()}")
    special = [0, 0x8000000000000000, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000001,
               1, 0x000fffffffffffff, 0x0010000000000000, 0x7fefffffffffffff, 0x3ff0000000000000]
    for bits in special + [rng.getrandbits(64) for _ in range(500)]:
        add("rat-setf64", f"q.setf64 {bits:x}")
    return lines


def float_lines(rng, counts):
    lines = []

    def add(kind, line):
        counts[kind] += 1
        lines.append(line)

    for _ in range(9000):
        op = rng.choice(["f.add", "f.sub", "f.mul", "f.quo"])
        zprec = rng.choice(PRECS + [0, 0, rng.randrange(1, 600)])
        x, y = float_operand(rng), float_operand(rng)
        if op in ("f.add", "f.sub") and rng.random() < 0.3:
            # Nearly cancelling operands exercise usub and rounding to zero.
            y = x.split(",", 2)
            y = f"{rng.choice(PRECS)},{rng.randrange(6)},{y[2]}"
        add("float-arith", f"{op} {zprec} {rng.randrange(6)} {x} {y}")
    for _ in range(300):
        big = f"{rng.choice(PRECS)},0,{hex(rand_bits(rng, 60))}p{rng.choice([2147483580, -2147483700, 2147483587, -2147483708])}"
        add("float-arith", f"{rng.choice(['f.mul', 'f.quo'])} {rng.choice(PRECS)} {rng.randrange(6)} {big} {float_operand(rng)}")
    for _ in range(1500):
        zprec = rng.choice(PRECS + [0, rng.randrange(1, 400)])
        x = float_operand(rng)
        if rng.random() < 0.9:
            x = x.replace(",-", ",")
        add("float-sqrt", f"f.sqrt {zprec} {rng.randrange(6)} {x}")
    for _ in range(1000):
        add("float-cmp", f"f.cmp {float_operand(rng)} {float_operand(rng)}")
    for _ in range(4000):
        prec = rng.choice(PRECS + [0, rng.randrange(1, 500)])
        base = rng.choice([0, 0, 0, 10, 10, 2, 8, 16])
        roll = rng.random()
        if roll < 0.55:
            digits = str(rand_mag(rng, rng.choice([20, 64, 200, 600])))
            point = rng.randrange(len(digits) + 1)
            e = rng.choice([rng.randrange(-30, 30), rng.randrange(-400, 400), rng.randrange(-5000, 5000)])
            s = (rng.choice(["", "-", "+"]) + digits[:point] + rng.choice([".", ""]) + digits[point:]
                 + rng.choice(["", f"e{e}", f"E{e}", f"p{e}"]))
            if base not in (0, 10):
                s = s.replace("e", "p").replace("E", "p")
                s = "".join(c for c in s if c in "-+.p0123456789"[: len("-+.p") + (base if base <= 10 else 10)])
        elif roll < 0.75:
            m = int_text(rand_mag(rng, 300), 16)
            point = rng.randrange(len(m) + 1)
            s = rng.choice(["", "-"]) + "0x" + m[:point] + "." + m[point:] + f"p{rng.randrange(-2000, 2000)}"
            if base != 0:
                s = s.replace("0x", "") if base == 16 else s
        else:
            pieces = ["1", "0", "-", "+", ".", "e", "E", "p", "P", "_", "x", "0x", "0b", "Inf", "inf",
                      "9", "a", "f", "5", "e-", "p+"]
            s = "".join(rng.choice(pieces) for _ in range(rng.randrange(1, 8)))
        add("float-parse", f"f.parse {prec} {rng.randrange(6)} {base} h{s.encode().hex()}")
    for s in ["", "Inf", "inf", "+Inf", "-inf", "INF", "NaN", "0", "-0", "+0.0", "1e2147483647",
              "1e-2147483648", "1p2147483647", "1p2147483648", "1p-2147483648", "1p-2147483649",
              "0x1p-2147483649", "1e9223372036854775807", "1e99999999999999999999", "0x_1p0", "0_1",
              "1_000.000_1e1_0", "1.5e", "0x1.8p", "1x", "0b101.1p3", "0o17.4", "0e1000000000",
              "1e-1000", "4.9406564584124654e-324", "2.2250738585072014e-308", "1.7976931348623157e308",
              "0.1", "123456789012345678901234567890e-30", "1e400", "1e-400"]:
        for prec in (0, 24, 53, 64, 200):
            add("float-parse", f"f.parse {prec} {rng.randrange(6)} 0 h{s.encode().hex()}")
    for _ in range(3000):
        x = float_operand(rng, max_exp=1200)
        if rng.random() < 0.15:
            x = f"{rng.choice(PRECS)},{rng.randrange(6)},{hex(rand_bits(rng, 60))}p{rng.choice([-1074, -1075, -1073, -1022, -1021, -149, -150, -126, 1024, 1025, 128, 129, 64, 63, -1100])}"
        add("float-conv", f"f.conv {x}")
    for _ in range(1500):
        add("float-setprec", f"f.setprec {float_operand(rng)} {rng.choice(PRECS + [0, 1, 2])}")
    for _ in range(800):
        add("float-setmantexp", f"f.setmantexp {rng.choice(PRECS + [0])} {rng.randrange(6)} {float_operand(rng)} {rng.randrange(-3000, 3000)}")
    for _ in range(1000):
        add("float-setint", f"f.setint {rng.choice(PRECS + [0, 0])} {rng.randrange(6)} {lit(rand_int(rng, 1500))}")
    for _ in range(1000):
        add("float-setrat", f"f.setrat {rng.choice(PRECS + [0, 0])} {rng.randrange(6)} {rat_lit(rng, 400)}")
    for bits in [0, 0x8000000000000000, 0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000000, 1,
                 0x000fffffffffffff] + [rng.getrandbits(64) for _ in range(600)]:
        add("float-setf64", f"f.setf64 {rng.choice(PRECS + [0, 0])} {rng.randrange(6)} {bits:x}")
    for _ in range(1600):
        add("float-text", f"f.text {float_operand(rng, max_exp=300)}")
    for x in ["53,0,0", "53,0,-0", "53,0,+Inf", "53,0,-Inf", "53,0,1", "10,0,1e100", "200,0,1e-100",
              "53,0,0.1", "24,0,0.1", "53,0,123456", "64,0,9.999999999999999e22", "1,0,7", "2,0,5"]:
        add("float-text", f"f.text {x}")
    for _ in range(1500):
        add("float-format", f"f.fmt h{rng.choice(FMT_FLOAT).encode().hex()} {float_operand(rng, max_exp=200)}")
    for _ in range(400):
        add("float-gob", f"f.gob {float_operand(rng)}")
    gob_raw_lines(rng, add)
    return lines


def gob_raw_lines(rng, add):
    """GobDecode of hand-built and random byte strings: what Go stores unvalidated.

    Int keeps a negative zero; Rat accepts an empty or all-zero denominator (meaning 1),
    keeps unreduced fractions and a negative zero numerator; Float keeps rounding-mode,
    accuracy and form bits outside the named values.
    """
    mags = [b"", b"\x00", b"\x00\x00\x00", b"\x01", b"\x00\x01", b"\xff" * 9, b"\x80" + b"\x00" * 8]
    mags += [rng.randbytes(rng.randrange(1, 20)) for _ in range(20)]
    for version in (0, 1, 2, 3, 4, 255):
        add("int-gobraw", f"i.gobraw {bytes([version]).hex()}")
        for mag in mags:
            add("int-gobraw", f"i.gobraw {(bytes([version]) + mag).hex()}")
    add("int-gobraw", "i.gobraw ")
    for mag in mags:
        for sign in (0, 1):
            add("int-gobraw", f"i.gobraw {(bytes([2 | sign]) + mag).hex()}")

    def rat_bytes(version, sign, num, den, declared=None):
        n = len(num) if declared is None else declared
        return bytes([version << 1 | sign]) + n.to_bytes(4, "big") + num + den

    nums = [b"", b"\x00", b"\x01", b"\x03", b"\x00\x00\x02", b"\x01\x00", rng.randbytes(9)]
    dens = [b"", b"\x00", b"\x00\x00", b"\x01", b"\x02", b"\x00\x04", b"\x06", b"\x01\x00", rng.randbytes(9)]
    for num in nums:
        for den in dens:
            for sign in (0, 1):
                add("rat-gobraw", f"q.gobraw {rat_bytes(1, sign, num, den).hex()}")
    for version in (0, 2, 3):
        add("rat-gobraw", f"q.gobraw {rat_bytes(version, 0, b'1', b'2').hex()}")
    for raw in (b"", b"\x02", b"\x02\x00\x00\x00", b"\x02\x00\x00\x00\x05", b"\x02\x00\x00\x00\x05ab",
                b"\x02\xff\xff\xff\xff", rat_bytes(1, 0, b"\x01", b"\x02", declared=2)):
        add("rat-gobraw", f"q.gobraw {raw.hex()}")
    add("rat-gobraw", "q.gobraw ")
    for _ in range(300):
        num, den = rng.randbytes(rng.randrange(0, 12)), rng.randbytes(rng.randrange(0, 12))
        add("rat-gobraw", f"q.gobraw {rat_bytes(1, rng.randrange(2), num, den).hex()}")

    mant = b"\x80" + b"\x00" * 7
    for prec in (0, 1, 24, 53, 64, 65, 100):
        for b in range(256):
            for tail in (b"", mant, b"\xc0" + b"\x00" * 7 + b"\x01"):
                raw = bytes([1, b]) + prec.to_bytes(4, "big")
                if tail or (b >> 1) & 3 == 1:
                    raw += (1).to_bytes(4, "big", signed=True) + tail
                add("float-gobraw", f"f.gobraw {raw.hex()}")
    for _ in range(300):
        raw = bytes([rng.choice([0, 1, 1, 1, 2]), rng.randrange(256)]) + rng.getrandbits(32).to_bytes(4, "big")
        raw += rng.randbytes(rng.randrange(0, 20))
        add("float-gobraw", f"f.gobraw {raw.hex()}")
    add("float-gobraw", "f.gobraw ")


def run(command, payload):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, timeout=200)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr[-4000:]}")
    return result.stdout.splitlines()


def main():
    start = time.monotonic()
    rng = random.Random(0xB16_2026)
    counts = collections.Counter()
    lines = int_lines(rng, counts) + rat_lines(rng, counts) + float_lines(rng, counts)
    payload = "".join(line + "\n" for line in lines)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "big_probe"], payload)
    go = run(["go", "run", str(ROOT / "tools/big_oracle.go")], payload)
    if len(rust) != len(lines) or len(go) != len(lines):
        raise AssertionError(f"big oracle returned {len(rust)} Rust / {len(go)} Go replies for {len(lines)} requests")
    failures = [(line, r, g) for line, r, g in zip(lines, rust, go) if r != g]
    if failures:
        for line, r, g in failures[:12]:
            print(f"request: {line[:300]}\n  Rust: {r[:600]}\n  Go:   {g[:600]}")
        raise AssertionError(f"{len(failures)} of {len(lines)} math/big replies differ from Go")
    special = sum(1 for g in go if g in ("panic", "nan", "nil", "fail") or g.startswith("err "))
    groups = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"math/big Go differential: {len(lines)} requests passed ({special} panic/NaN/nil/error "
          f"replies) in {time.monotonic() - start:.1f}s [{groups}]")


if __name__ == "__main__":
    main()
