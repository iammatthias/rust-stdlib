#!/usr/bin/env python3
"""Differentially check rust_stdlib::bytes against Go's bytes package.

Requests are tab-separated lines of hex arguments; tools/bytes_oracle.go and
examples/bytes_probe.rs print one result line per request and the lines are
compared exactly. Case mapping, Title and EqualFold are also compared on
every rune.
"""
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

B = bytes.fromhex
VALID = [b"a", b"b", b"c", b"A", b"B", b"ab", b"abc", b"aab", b" ", b"x", b"1", b"_", b"\n", b"\t",
         "é".encode(), "É".encode(), "雪".encode(), "😀".encode(), "�".encode(),
         "\u0085".encode(), " ".encode(), " ".encode(), "　".encode(), " ".encode(),
         "ß".encode(), "ſ".encode(), "K".encode(), "σ".encode(), "ς".encode(), "Σ".encode(),
         "Ω".encode(), "д".encode(), "Д".encode(), "٣".encode(), "²".encode()]
INVALID = [B("80"), B("bf"), B("c0"), B("c1"), B("e381"), B("eda080"), B("f4908080"), B("f5"),
           B("ff"), B("f09f98"), B("ed"), B("e08080"), B("c3"), B("e9"), B("f0")]
ALL = VALID + INVALID
TEXT = [b"a", b"b", b"ab", b"x", b"\n", b" ", b"1"]
SPACES = [b" ", b"\t", b"\n", b"\v", b"\f", b"\r", "\u0085".encode(), " ".encode(), " ".encode(), "　".encode()]
SMALL = [b"a", b"b", b"a", b"b", b"ab", "é".encode(), B("80"), B("c3"), B("ff"), "�".encode()]
# Case-mapping inputs, including runes whose full mapping differs from Go's
# simple mapping and title-case digraphs.
CASE = [b"a", b"z", b"A", b"Z", b"k", b"K", b" ", b"-", b"1", "é".encode(), "É".encode(), "ß".encode(),
        "ſ".encode(), "K".encode(), "σ".encode(), "ς".encode(), "Σ".encode(), "Ω".encode(),
        "ω".encode(), "İ".encode(), "ı".encode(), "ŉ".encode(), "ǅ".encode(), "ǆ".encode(), "Ǆ".encode(),
        "ᾀ".encode(), "ᾳ".encode(), "ﬃ".encode(), "д".encode(), "Д".encode(), "雪".encode(), "😀".encode(), "�".encode(),
        B("80"), B("ff"), B("e381"), "ÿ".encode(), "Ÿ".encode()]


def pieces(rng, alphabet, lo, hi):
    return b"".join(rng.choice(alphabet) for _ in range(rng.randrange(lo, hi + 1)))


def h(b):
    return b.hex()


def requests():
    rng = random.Random(0xB7E5)
    out = []
    add = lambda *fields: out.append("\t".join(fields))

    for _ in range(600):
        s = pieces(rng, SMALL, 0, 14)
        sep = rng.choice([b"", pieces(rng, SMALL, 0, 3), pieces(rng, SMALL, 1, 3),
                          s[rng.randrange(0, len(s) + 1):][:rng.randrange(0, 4)]])
        s_, p_ = h(s), h(sep)
        for op in ("IDX", "LIDX", "CNT", "CONT", "CUT"):
            add(op, s_, p_)
        for n in (-1, 0, 1, 2, 3, 7):
            add("SPL", s_, p_, str(n), str(rng.randrange(0, 2)))
        add("SPL", s_, p_, "-1", "2")
        add("SPL", s_, p_, "-1", "3")
        for n in (-1, 0, 1, 2, 5):
            add("REP", s_, p_, h(pieces(rng, SMALL, 0, 3)), str(n))
        add("TPS", s_, p_)
        add("TVU", s_, h(pieces(rng, SMALL, 0, 2)))
        add("RUNES", s_)
        add("LN", s_ + h(rng.choice([b"\n", b"", b"x\n"])))

    for _ in range(300):
        s = pieces(rng, ALL, 0, 12)
        add("IB", h(s), h(rng.choice([b"a", b"\n", B("80"), B("ff"), b"\xa9"])))
        add("LIB", h(s), h(rng.choice([b"a", b"\n", B("80"), B("ff"), b"\xa9"])))
        for r in (0x61, 0xFFFD, 0xE9, 0x4E2D, 0x1F600, 0x7F, 0x80, 0xFF):
            add("IR", h(s), str(r))
            add("CR", h(s), str(r))
        chars = pieces(rng, ALL, 0, 5)
        add("IA", h(s), h(chars))
        add("LIA", h(s), h(chars))
        add("CA", h(s), h(chars))
        add("TRIM", h(s), h(chars))
        add("TSP", h(pieces(rng, SPACES, 0, 3) + s + pieces(rng, SPACES, 0, 3)))
        add("FLD", h(s + rng.choice(SPACES) + s))
        for p in range(4):
            add("FF", h(s), str(p))
            add("IF", h(s), str(p))
            add("TF", h(s), str(p))
        for m in range(3):
            add("MAP", h(s), str(m))
        add("TVU", h(s), h(rng.choice([b"", b"?", "�".encode(), b"<>"])))

    for _ in range(300):
        s = pieces(rng, CASE, 0, 10)
        t = s if rng.random() < 0.4 else pieces(rng, CASE, 0, 10)
        add("UP", h(s))
        add("LOW", h(s))
        add("TIT", h(s))
        add("TITLE", h(pieces(rng, CASE + [b" ", b"'", b"-"], 0, 12)))
        add("SPC", h(s + b"iI" + "İı".encode()))
        add("EF", h(s), h(t))
        add("EF", h(s), h(s.swapcase() if rng.random() < 0.5 else s.upper()))

    for s in (b"", b"abc", "ΣΑΣ".encode(), "ǅ".encode(), "ǆǅǄ".encode()):
        add("EF", h(s), h(s.lower()))

    # Large inputs: repetitive text stresses the Rabin-Karp fallbacks.
    big = b"a" * (1 << 20)
    rand = bytes(rng.randrange(256) for _ in range(1 << 20))
    para = (b"lorem ipsum dolor sit amet\n" * 40000)
    mixed = ("é雪 ab " * 100000).encode()
    for s in (big, rand, para, mixed):
        for sep in (b"aaab", b"a" * 100 + b"b", rand[1000:1040], b"ipsum", b"sit amet\nlorem", "雪 ab".encode(), b"\n"):
            add("IDX", h(s), h(sep))
            add("LIDX", h(s), h(sep))
            add("CNT", h(s), h(sep))
        add("CNT", h(s), h(b""))
        add("REP", h(s[:300000]), h(b"a"), h(b"bb"), "-1")
        add("REP", h(s[:300000]), h(b""), h(b"-"), "100000")
        add("SPL", h(s), h(b"a"), "-1", "0")
        add("SPL", h(s), h(b"ab"), "-1", "1")
        add("SPL", h(s), h(b""), "50000", "0")
        add("FLD", h(s))
        add("LN", h(s))
        add("TVU", h(s), h(b"?"))
        add("UP", h(s[:200000]))
        add("TRIM", h(s), h(b"ab\n"))
        add("EF", h(s[:200000]), h(s[:200000]))

    for i in range(450):
        out.append(buffer_script(rng, i))
    for i in range(350):
        out.append(reader_script(rng))
    return out


def buffer_script(rng, i):
    valid = i % 2 == 0
    # ReadString/String are lossy in Rust, so those scripts stay ASCII.
    alphabet = TEXT if valid else ALL

    def data(lo=0, hi=8):
        d = pieces(rng, alphabet, lo, hi)
        if rng.random() < 0.08:
            d = d * rng.randrange(20, 200)
        return d

    kind = rng.randrange(3)
    if kind == 0:
        parts = ["NEW"]
    elif kind == 1:
        d = pieces(rng, alphabet, 0, 6)
        parts = [f"NB:{h(d)}:{len(d) + rng.choice([1, 1, 2, 5, 64, 600])}"]
    else:
        parts = [f"NS:{h(pieces(rng, alphabet if valid else VALID, 0, 6))}"]
    delims = [b"\n", b"a", B("80"), b"x"]
    for _ in range(rng.randrange(3, 26)):
        op = rng.choice(["W", "W", "WB", "WR", "R", "R", "RB", "RB", "RR", "RR", "UB", "UB", "UR", "UR",
                         "N", "T", "G", "P", "RBY", "RST", "RF", "WT", "WS", "RS", "STR"])
        if op == "W":
            parts.append(f"W:{h(data())}")
        elif op == "WS":
            parts.append(f"WS:{h(pieces(rng, TEXT if valid else VALID, 0, 8))}")
        elif op == "WB":
            parts.append(f"WB:{h(bytes([rng.randrange(128 if valid else 256)]))}")
        elif op == "WR":
            parts.append(f"WR:{rng.choice([0x61, 0x7F, 0x20] if valid else [0x61, 0xE9, 0x4E2D, 0x1F600, 0xFFFD, 0x7F, 0x80])}")
        elif op in ("R", "N", "T", "G", "P"):
            parts.append(f"{op}:{rng.choice([0, 1, 2, 3, 5, 9, 70, 700]) if op == 'G' else rng.randrange(0, 12)}")
        elif op in ("RB", "RR", "UB", "UR", "RST"):
            parts.append(op)
        elif op == "RBY":
            parts.append(f"RBY:{h(rng.choice(delims))}")
        elif op == "RS":
            if valid:
                parts.append(f"RS:{h(rng.choice([b'\n', b'a', b'x']))}")
        elif op == "STR":
            if valid:
                parts.append("STR")
        elif op == "RF":
            d = pieces(rng, alphabet, 0, 12)
            if rng.random() < 0.3:
                d = bytes(rng.randrange(256) if not valid else 97 + rng.randrange(26)
                          for _ in range(rng.randrange(0, 3000)))
            parts.append(f"RF:{h(d)}:{rng.choice([1, 3, 64, 511, 512, 700])}")
        elif op == "WT":
            parts.append(f"WT:{rng.choice([0, 1, 4, 10000])}")
    return "BUF\t" + "\t".join(parts)


def reader_script(rng):
    d = pieces(rng, ALL, 0, 10)
    parts = [h(d)]
    for _ in range(rng.randrange(3, 22)):
        op = rng.choice(["R", "R", "RB", "RB", "RR", "RR", "UB", "UR", "UR", "RA", "SK", "WT", "RST"])
        if op == "R":
            parts.append(f"R:{rng.randrange(0, 8)}")
        elif op == "RA":
            parts.append(f"RA:{rng.randrange(0, 8)}:{rng.randrange(-2, 14)}")
        elif op == "SK":
            parts.append(f"SK:{rng.randrange(0, 3)}:{rng.randrange(-4, 14)}")
        elif op == "WT":
            parts.append(f"WT:{rng.choice([0, 1, 3, 100])}")
        elif op == "RST":
            parts.append(f"RST:{h(pieces(rng, ALL, 0, 5))}")
        else:
            parts.append(op)
    return "RDR\t" + "\t".join(parts)


def run(cmd, payload):
    result = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if result.returncode:
        raise RuntimeError(f"{cmd[0]} failed:\n{result.stderr[-4000:]}")
    return result.stdout.splitlines()


def rust(payload):
    return run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "bytes_probe"], payload)


def go(payload):
    return run(["go", "run", str(ROOT / "tools/bytes_oracle.go")], payload)


def all_runes():
    return [r for r in range(0x110000) if not 0xD800 <= r < 0xE000]


def case_scan():
    """Compares ToUpper, ToLower, ToTitle and Title (a rune between two letters) on every rune exactly,
    then EqualFold on each rune against its Go upper, lower and title images."""
    reqs = []
    for r in all_runes():
        hx = chr(r).encode().hex()
        reqs += [f"UP\t{hx}", f"LOW\t{hx}", f"TIT\t{hx}", f"TITLE\t61{hx}61"]
    payload = "".join(r + "\n" for r in reqs)
    actual, expected = rust(payload), go(payload)
    bad = [(q, a, e) for q, a, e in zip(reqs, actual, expected) if a != e]
    if len(actual) != len(reqs) or len(expected) != len(reqs) or bad:
        raise AssertionError(f"case mapping differs on {len(bad)} of {len(reqs)} vectors: {bad[:5]}")
    img = {}
    for q, e in zip(reqs, expected):
        op, hx = q.split("\t")
        if op in ("UP", "LOW", "TIT"):
            img.setdefault(hx, {})[op] = e
    pairs = []
    for hx, m in img.items():
        if all(v == hx for v in m.values()):
            continue
        pairs += [f"EF\t{hx}\t{m['UP']}", f"EF\t{hx}\t{m['LOW']}", f"EF\t{hx}\t{m['TIT']}",
                  f"EF\t{m['UP']}\t{m['LOW']}"]
    payload = "".join(r + "\n" for r in pairs)
    actual, expected = rust(payload), go(payload)
    bad = [(q, a, e) for q, a, e in zip(pairs, actual, expected) if a != e]
    if len(actual) != len(pairs) or len(expected) != len(pairs) or bad:
        raise AssertionError(f"EqualFold differs on {len(bad)} of {len(pairs)} vectors: {bad[:5]}")
    return len(reqs) + len(pairs)


def main():
    scanned = case_scan()
    reqs = requests()
    payload = "".join(r + "\n" for r in reqs)
    actual, expected = rust(payload), go(payload)
    if len(actual) != len(reqs) or len(expected) != len(reqs):
        raise AssertionError(f"line counts: requests={len(reqs)} rust={len(actual)} go={len(expected)}")
    bad = [i for i, (a, e) in enumerate(zip(actual, expected)) if a != e]
    for i in bad[:6]:
        print(f"vector {i}: {reqs[i][:300]!r}\n  Rust={actual[i][:600]!r}\n  Go  ={expected[i][:600]!r}")
    if bad:
        raise AssertionError(f"{len(bad)} of {len(reqs)} vectors differ")
    print(f"bytes Go differential: {len(reqs)} vectors passed; {scanned} exact all-rune case vectors passed")


if __name__ == "__main__":
    main()
