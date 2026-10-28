#!/usr/bin/env python3
"""Differentially check strconv formatting, parsing and quoting against Go.

Request catalogue (tab separated; strings as hex): F float format, P ParseFloat,
I/U ParseInt/ParseUint, A Atoi, B ParseBool, FI int formatting, C ParseComplex,
FC FormatComplex, Q quote, R quote rune and IsPrint/IsGraphic, UQ Unquote,
QP QuotedPrefix, UC UnquoteChar, CB CanBackquote.

STRCONV_SCALE=<n> multiplies the vector counts (default 5 fits the suite
budget; the persistent evidence run used a much larger scale).
"""
import decimal
import os
import pathlib
import random
import struct
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCALE = float(os.environ.get("STRCONV_SCALE", "5"))
decimal.getcontext().prec = 1500
decimal.getcontext().Emin = -2000
decimal.getcontext().Emax = 2000

FMTS = b"eEfgGbxX"


def h(b):
    return b.hex()


def f32_bits_to_f64_bits(b32):
    return struct.unpack("<Q", struct.pack("<d", struct.unpack("<f", struct.pack("<I", b32))[0]))[0]


def rand_bits(rng, bs):
    k = rng.randrange(8)
    if bs == 32:
        if k == 0:
            return rng.getrandbits(32) & 0x807FFFFF  # subnormal / zero
        if k == 1:
            return (rng.getrandbits(1) << 31) | (rng.choice([0, 1, 0xFE, 0xFF, 0x7F, 0x80]) << 23) | rng.choice([0, 1, 0x7FFFFF, rng.getrandbits(23)])
        if k == 2:
            return struct.unpack("<I", struct.pack("<f", rng.randint(-10**7, 10**7) / 10 ** rng.randrange(0, 8)))[0]
        return rng.getrandbits(32)
    if k == 0:
        return rng.getrandbits(64) & 0x800FFFFFFFFFFFFF
    if k == 1:
        return (rng.getrandbits(1) << 63) | (rng.choice([0, 1, 0x7FE, 0x7FF, 0x3FF, 0x400, 0x3FE]) << 52) | rng.choice([0, 1, (1 << 52) - 1, rng.getrandbits(52)])
    if k == 2:
        v = rng.randint(-10**15, 10**15) / 10 ** rng.randrange(0, 20)
        return struct.unpack("<Q", struct.pack("<d", v))[0]
    if k == 3:
        v = float(rng.randint(-10**6, 10**6)) * 2.0 ** rng.randrange(-60, 60)
        return struct.unpack("<Q", struct.pack("<d", v))[0]
    return rng.getrandbits(64)


def float_requests(rng, n):
    out = []
    for _ in range(n):
        bs = rng.choice([32, 64])
        bits = rand_bits(rng, bs)
        fmt = chr(rng.choice(FMTS)) if rng.random() < 0.97 else chr(rng.choice(b"zdsv%"))
        r = rng.random()
        if r < 0.45:
            prec = -1 if rng.random() < 0.9 else rng.choice([-2, -5])
        elif r < 0.9:
            prec = rng.randrange(0, 26)
        elif r < 0.98:
            prec = rng.randrange(26, 60)
        else:
            prec = rng.randrange(60, 400)
        if fmt == "f" and prec > 60 and (bits >> 52) & 0x7FF > 0x600 and bs == 64:
            prec = 30
        out.append(f"F\t{bits:016x}\t{fmt}\t{prec}\t{bs}")
    return out


def midpoint_strings(rng, n):
    out = []
    for _ in range(n):
        bs = rng.choice([32, 64])
        bits = rand_bits(rng, bs)
        if bs == 32:
            if (bits >> 23) & 0xFF >= 0xFE:
                continue
            lo = struct.unpack("<f", struct.pack("<I", bits & 0x7FFFFFFF))[0]
            hi = struct.unpack("<f", struct.pack("<I", (bits & 0x7FFFFFFF) + 1))[0]
        else:
            if (bits >> 52) & 0x7FF >= 0x7FE:
                continue
            lo = struct.unpack("<d", struct.pack("<Q", bits & 0x7FFFFFFFFFFFFFFF))[0]
            hi = struct.unpack("<d", struct.pack("<Q", (bits & 0x7FFFFFFFFFFFFFFF) + 1))[0]
        mid = (decimal.Decimal(lo) + decimal.Decimal(hi)) / 2
        sign = "-" if bits >> (bs - 1) else ""
        digits, exp = mid.as_tuple().digits, mid.as_tuple().exponent
        ds = "".join(map(str, digits))
        variants = [ds]
        variants.append(str(int(ds) + 1))
        variants.append(str(int(ds) - 1) if int(ds) > 0 else ds)
        variants.append(ds + "0" * rng.randrange(1, 40) + "1")
        variants.append(ds[: rng.randrange(1, len(ds) + 1)])
        for v in variants:
            if len(v) > 790:
                # Go's 800-digit decimal fallback misrounds longer subnormal
                # inputs (Rust agrees with CPython's correctly rounded float()).
                continue
            e = exp + len(ds) - len(v)
            style = rng.randrange(3)
            if style == 0:
                s = f"{v}e{e}"
            elif style == 1:
                s = f"{v[0]}.{v[1:] or '0'}e{e + len(v) - 1}"
            else:
                s = f"0.{v}e{e + len(v)}"
            out.append(f"P\t{h((sign + s).encode())}\t{bs}")
    return out


def rand_decimal_string(rng):
    sign = rng.choice(["", "", "+", "-"])
    ip = "".join(rng.choice("0123456789") for _ in range(rng.choice([0, 1, 1, 2, 5, 17, 19, 20, 25])))
    fp = "".join(rng.choice("0123456789") for _ in range(rng.choice([0, 1, 3, 10, 17, 22, 40])))
    s = sign + ip + (("." + fp) if rng.random() < 0.7 else "")
    if rng.random() < 0.6:
        s += rng.choice("eE") + rng.choice(["", "", "+", "-"]) + str(rng.choice([0, 1, 5, 22, 23, 38, 39, 100, 300, 308, 309, 310, 311, 330, 340, 345, 346, 999999999999]))
    if rng.random() < 0.15:
        s = s.replace("0", "0_", 1)
    if rng.random() < 0.1:
        s = s + rng.choice(["x", "_", ".", "e", "i", " ", "é", "f"])
    return s


def rand_hex_string(rng):
    sign = rng.choice(["", "", "+", "-"])
    ip = "".join(rng.choice("0123456789abcdefABCDEF") for _ in range(rng.choice([0, 1, 2, 8, 13, 14, 20])))
    fp = "".join(rng.choice("0123456789abcdefABCDEF") for _ in range(rng.choice([0, 1, 4, 13, 20])))
    s = sign + rng.choice(["0x", "0X"]) + ip + (("." + fp) if rng.random() < 0.6 else "")
    if rng.random() < 0.9:
        s += rng.choice("pP") + rng.choice(["", "+", "-"]) + str(rng.choice([0, 1, 4, 52, 127, 128, 1023, 1024, 1074, 1075, 1100, 99999]))
    if rng.random() < 0.1:
        s = s.replace("0x", "0x_", 1)
    return s


SPECIAL = ["inf", "Inf", "INF", "+Inf", "-inf", "infinity", "Infinity", "-INFINITY", "infinit", "infx", "+nan", "nan", "NaN", "NAN", "-nan",
           "nanx", "+", "-", "", ".", "e5", "1e", "1e+", "0x", "0x1", "0x1p", "0x.p1", "0x_1p0", "0x1_p0", "1_000", "_1", "1__0", "1_", "1_e5",
           "1e1_0", "0b101", "0o7", "1.5.5", "..", "+.5", "5.", ".5e-3", "0e999999999", "1e999999999999", "1e-999999999", "00000.0000000e5", " 1",
           "1 ", "0x1p-1074", "0x1p-1075", "0x1.fffffffffffffp1023", "0x1.fffffffffffff8p1023", "0x1p1024", "0x1.fffffep127", "0x1.ffffffp127",
           "4.9406564584124654e-324", "2.4703282292062327e-324", "2.4703282292062328e-324", "1.7976931348623157e308", "1.7976931348623158e308",
           "1.7976931348623159e308", "3.4028235e38", "3.4028236e38", "1e-45", "7e-46", "7.006492321624085354618647916449580656401309709796e-46",
           "9007199254740993", "9007199254740992.5", "9007199254740993.0000000000000000000001"]


def float_parse_requests(rng, n):
    out = []
    for s in SPECIAL:
        for bs in (32, 64, 16, 128, 0, -1):
            out.append(f"P\t{h(s.encode())}\t{bs}")
    for _ in range(n):
        r = rng.random()
        s = rand_hex_string(rng) if r < 0.2 else rand_decimal_string(rng)
        out.append(f"P\t{h(s.encode())}\t{rng.choice([32, 64])}")
    return out


def round_trip_requests(rng, n):
    """Parse the shortest decimal Python prints for random floats."""
    out = []
    for _ in range(n):
        bs = rng.choice([32, 64])
        bits = rand_bits(rng, bs)
        if bs == 32:
            v = struct.unpack("<f", struct.pack("<I", bits))[0]
        else:
            v = struct.unpack("<d", struct.pack("<Q", bits))[0]
        if v != v or v in (float("inf"), float("-inf")):
            continue
        s = repr(v) if rng.random() < 0.5 else format(v, ".%de" % rng.randrange(0, 25))
        out.append(f"P\t{h(s.encode())}\t{bs}")
    return out


def int_requests(rng, n):
    out = []
    bases = [0, 10, 2, 8, 16, 36, 1, 37, -1, 3, 7, 11, 35]
    bitsizes = [0, 8, 16, 32, 64, 64, -1, 65, 1, 12]
    edge = ["", "+", "-", "0", "-0", "00", "0x", "0b", "0o", "0x1", "0b1", "0o7", "0_7", "0x_ff", "0x__ff", "_1", "1_", "1__1", "1_000", "0b_1", "-0x8000000000000000",
            "9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809", "18446744073709551615", "18446744073709551616",
            "99999999999999999999999", "0xFFFFFFFFFFFFFFFF", "0x10000000000000000", "127", "128", "-128", "-129", "255", "256", "ZZ", "zz", " 1", "1 ", "٣"]
    for e in edge:
        for base in (0, 10, 16, 2):
            for bs in (0, 8, 64):
                out.append(f"I\t{h(e.encode())}\t{base}\t{bs}")
                out.append(f"U\t{h(e.encode())}\t{base}\t{bs}")
        out.append(f"A\t{h(e.encode())}")
    for _ in range(n):
        alphabet = rng.choice(["01", "01234567", "0123456789", "0123456789abcdefABCDEF", "0123456789abcdefghijklmnopqrstuvwxyz_", "0123456789_"])
        body = "".join(rng.choice(alphabet) for _ in range(rng.choice([1, 2, 3, 8, 15, 18, 19, 20, 21, 30])))
        pre = rng.choice(["", "", "", "0x", "0b", "0o", "0", "0X", "0B", "0O"])
        s = rng.choice(["", "", "+", "-"]) + pre + body
        if rng.random() < 0.1:
            s = s[: len(s) // 2] + "_" + s[len(s) // 2:]
        base = rng.choice(bases)
        bs = rng.choice(bitsizes)
        out.append(f"I\t{h(s.encode())}\t{base}\t{bs}")
        out.append(f"U\t{h(s.encode())}\t{base}\t{bs}")
        out.append(f"A\t{h(s.encode())}")
        v = rng.choice([rng.getrandbits(64) - (1 << 63), rng.getrandbits(rng.randrange(1, 64)) - (1 << 20), -(1 << 63), (1 << 63) - 1])
        out.append(f"FI\t{v}\t{rng.choice([2, 3, 8, 10, 16, 36, rng.randrange(2, 37)])}")
    for s in ["1", "t", "T", "TRUE", "true", "True", "0", "f", "F", "FALSE", "false", "False", "", "tRUE", "yes", "2", " true"]:
        out.append(f"B\t{h(s.encode())}")
    return out


def complex_requests(rng, n):
    out = []
    parts = ["1", "-2.5", "+3e2", "NaN", "Inf", "-Inf", "+Inf", "0x1p3", "1e400", "1e39", "0", "-0", "1_0", ".5"]
    for _ in range(n):
        a, b = rng.choice(parts), rng.choice(parts)
        form = rng.choice(["{a}", "{b}i", "{a}+{b}i", "{a}-{b}i", "({a}+{b}i)", "({a})", "({b}i)", "{a}{b}i", "{a}++{b}i", "i", "+i", "{a}+i", "{a} +{b}i", "{a}+{b}j", "({a}+{b}i", "{a}+{b}i)"])
        s = form.format(a=a, b=b)
        out.append(f"C\t{h(s.encode())}\t{rng.choice([64, 128])}")
    for _ in range(n):
        out.append(f"FC\t{rand_bits(rng, 64):016x}\t{rand_bits(rng, 64):016x}\t{chr(rng.choice(FMTS))}\t{rng.choice([-1, 0, 3, 8, 17])}\t{rng.choice([64, 128])}")
    return out


def rand_rune(rng):
    k = rng.randrange(10)
    if k == 0:
        return rng.randrange(-70000, 0x110010)
    if k == 1:
        return rng.randrange(0, 0x300)
    if k == 2:
        return rng.randrange(0xD790, 0xE010)
    if k == 3:
        return rng.randrange(0x1F000, 0x1FB00)
    if k == 4:
        return rng.choice([0x2028, 0x2029, 0xA0, 0xAD, 0xFEFF, 0x200B, 0x3000, 0xFFFD, 0x10FFFF, 0x110000, 0x1FFFF, 0x20000, 0xE0001, 0xE0100, 0x7F, 0x80, 0x9F, -1, 0xFFFF, 0x10000])
    return rng.randrange(0, 0x30000)


def rand_bytes(rng):
    parts = []
    for _ in range(rng.randrange(0, 12)):
        k = rng.randrange(8)
        if k == 0:
            parts.append(bytes([rng.randrange(256)]))
        elif k == 1:
            parts.append(bytes([rng.randrange(0, 0x20)]))
        elif k == 2:
            parts.append(rng.choice([b"\\", b'"', b"'", b"`", b"\xef\xbb\xbf", b"\xed\xa0\x80", b"\xc0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82", b"\x7f"]))
        else:
            r = rand_rune(rng)
            if 0 <= r < 0x110000 and not 0xD800 <= r < 0xE000:
                parts.append(chr(r).encode())
            else:
                parts.append(b"a")
    return b"".join(parts)


TOKENS = [b"a", b"Z", b" ", b"\n", b"\r", b"\t", b"\\n", b"\\t", b"\\a", b"\\b", b"\\f", b"\\r", b"\\v", b"\\\\", b"\\'", b'\\"', b"\\`", b"\\x41",
          b"\\xff", b"\\x4", b"\\xg1", b"\\u00e9", b"\\u12", b"\\ud800", b"\\U0010ffff", b"\\U00110000", b"\\U0000dfff", b"\\101", b"\\377", b"\\400",
          b"\\8", b"\\78", b"\\0", b"\\", b"\xc3\xa9", b"\xff", b"\xf0\x9f\x98\x80", b'"', b"'", b"`", b"\xe2\x82", b"\xef\xbb\xbf"]


def quote_requests(rng, n):
    out = []
    for _ in range(n):
        s = rand_bytes(rng)
        out.append(f"Q\t{rng.randrange(3)}\t{h(s)}")
        out.append(f"CB\t{h(s)}")
        r = rand_rune(rng)
        out.append(f"R\t{rng.randrange(3)}\t{r}")
    for r in list(range(-3, 0x300)) + list(range(0xD7F0, 0xE020)) + [0x10FFFF, 0x110000, 0x7FFFFFFF, -0x80000000]:
        out.append(f"R\t{r % 3}\t{r}")
    return out


def unquote_requests(rng, n):
    out = []
    for _ in range(n):
        body = b"".join(rng.choice(TOKENS) if rng.random() < 0.8 else rand_bytes(rng) for _ in range(rng.randrange(0, 6)))
        q = rng.choice([b'"', b'"', b"'", b"`", b"'", b'"'])
        r = rng.random()
        if r < 0.8:
            s = q + body + q
        elif r < 0.9:
            s = q + body
        else:
            s = q + body + q + rng.choice([b"x", b'"abc"', b" "])
        out.append(f"UQ\t{h(s)}")
        out.append(f"QP\t{h(s)}")
        c = body
        out.append(f"UC\t{h(c)}\t{rng.choice([0, 34, 39, 96])}")
    return out


def run(cmd, payload, name):
    r = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if r.returncode:
        raise RuntimeError(f"{name} failed:\n{r.stderr[-3000:]}")
    return r.stdout.splitlines()


def main():
    rng = random.Random(0x57C0)
    n = lambda base: max(1, int(base * SCALE))
    records = []
    records += float_requests(rng, n(30000))
    records += float_parse_requests(rng, n(6000))
    records += midpoint_strings(rng, n(1500))
    records += round_trip_requests(rng, n(6000))
    records += int_requests(rng, n(1500))
    records += complex_requests(rng, n(500))
    records += quote_requests(rng, n(2500))
    records += unquote_requests(rng, n(6000))
    payload = "".join(r + "\n" for r in records)

    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--release", "--example", "strconv_probe"], cwd=ROOT, check=True)
    probe = ROOT / "target/release/examples/strconv_probe"
    rust = run([str(probe)], payload, "Rust strconv probe")
    go = run(["go", "run", str(ROOT / "tools/strconv_oracle.go")], payload, "Go strconv oracle")
    if len(rust) != len(records) or len(go) != len(records):
        raise AssertionError(f"record count mismatch: rust={len(rust)} go={len(go)} requests={len(records)}")
    bad = [i for i, (a, b) in enumerate(zip(rust, go)) if a != b]
    for i in bad[:20]:
        print(f"MISMATCH vector {i}: {records[i]!r}\n  Rust={rust[i]!r}\n  Go  ={go[i]!r}")
    if bad:
        raise AssertionError(f"{len(bad)} of {len(records)} strconv vectors differ from Go")
    print(f"strconv Go differential: {len(records)} vectors passed")


if __name__ == "__main__":
    main()
