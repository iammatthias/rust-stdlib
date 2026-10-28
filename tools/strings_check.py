#!/usr/bin/env python3
"""Differentially check the strings package against Go: non-ASCII text,
invalid UTF-8, empty separators, huge counts, the Replacer and the Reader."""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]

PIECES = [
    b"a", b"b", b"c", b"ab", b"A", b"Z", b"z", b" ", b"\t", b"\n", b"\x0b", b"\x0c", b"\r",
    b",", b"_", b"0", b"9", b"-", b"aa", b"abab",
    "é".encode(), "中".encode(), "𝄞".encode(), "ß".encode(), "σ".encode(), "ς".encode(),
    "Σ".encode(), "İ".encode(), "ı".encode(), "K".encode(), "ſ".encode(), "Δ".encode(),
    "\u0085".encode(), " ".encode(), "　".encode(), "�".encode(),
    "ǅ".encode(), "ǆ".encode(), "ᾀ".encode(), "ǰ".encode(),
    b"\xff", b"\xc0", b"\x80", b"\xe4\xb8", b"\xc0\x80", b"\xed\xa0\x80", b"\xf0\x90\x80",
    b"\xf4\x90\x80\x80",
]
SEPS = [b"", b"a", b",", b"ab", b"aa", b"abab", b" ", "é".encode(), "中".encode(),
        b"\xff", b"\xe4\xb8", "�".encode(), b"\n", b"b", "𝄞".encode()]
COUNTS = [-1, 0, 1, 2, 3, 9223372036854775807]
REPEAT_COUNTS = [-1, 0, 1, 2, 5, 100, 4611686018427387904, 9223372036854775807]


def hx(b):
    return b.hex()


def rand_str(rng, maxn=9):
    return b"".join(rng.choice(PIECES) for _ in range(rng.randrange(maxn + 1)))


def rand_sep(rng):
    if rng.random() < 0.5:
        return rng.choice(SEPS)
    return rand_str(rng, 3)


def runes_chunks(size=2048):
    chars = [chr(c) for c in range(0x110000) if not 0xD800 <= c < 0xE000]
    for i in range(0, len(chars), size):
        yield "".join(chars[i:i + size]).encode()


def requests():
    rng = random.Random(0x57121)
    out = []
    one = ["Fields", "FieldsSeq", "FieldsFunc", "FieldsFuncSeq", "Lines", "ToUpper", "ToLower",
           "ToTitle", "Title", "ToValidUTF8x", "Map", "TrimSpace", "TrimFunc", "TrimLeftFunc",
           "TrimRightFunc", "IndexFunc", "LastIndexFunc", "ContainsFunc"]
    two = ["Index", "LastIndex", "IndexAny", "LastIndexAny", "Contains", "ContainsAny", "Count",
           "HasPrefix", "HasSuffix", "Compare", "Cut", "CutLast", "CutPrefix", "CutSuffix",
           "TrimPrefix", "TrimSuffix", "EqualFold", "Split", "SplitAfter", "SplitSeq",
           "SplitAfterSeq", "ToValidUTF8", "Trim", "TrimLeft", "TrimRight", "Join"]
    for _ in range(120):
        for op in one:
            if op == "ToValidUTF8x":
                continue
            out.append((op, [hx(rand_str(rng, 12))]))
        for op in two:
            s = rand_str(rng, 12)
            sep = rand_sep(rng)
            if op in ("Index", "LastIndex", "Count", "Split", "Cut", "CutLast") and rng.random() < .4 and s:
                a = rng.randrange(len(s))
                sep = s[a:a + rng.randrange(1, 4)]
            out.append((op, [hx(s), hx(sep)]))
        s = rand_str(rng, 12)
        out.append(("SplitN", [hx(s), hx(rand_sep(rng)), str(rng.choice(COUNTS))]))
        out.append(("SplitAfterN", [hx(s), hx(rand_sep(rng)), str(rng.choice(COUNTS))]))
        out.append(("Repeat", [hx(rand_str(rng, 3)), str(rng.choice(REPEAT_COUNTS))]))
        out.append(("Replace", [hx(s), hx(rand_sep(rng)), hx(rand_str(rng, 3)), str(rng.choice(COUNTS))]))
        out.append(("ReplaceAll", [hx(s), hx(rand_sep(rng)), hx(rand_str(rng, 3))]))
        out.append(("ToUpperSpecial", [hx(s), hx(b"T")]))
        out.append(("ToLowerSpecial", [hx(s), hx(b"A")]))
        out.append(("ToTitleSpecial", [hx(s), hx(b"T")]))
        out.append(("IndexByte", [hx(s), str(rng.choice([0x61, 0x2c, 0xff, 0xe4, 0x00]))]))
        out.append(("LastIndexByte", [hx(s), str(rng.choice([0x61, 0x2c, 0xff, 0xb8, 0x00]))]))
        r = rng.choice([0x61, 0xe9, 0x4e2d, 0x1d11e, 0xfffd, 0xd800, 0x110000, 0x394, 0x0])
        out.append(("IndexRune", [hx(s), str(r)]))
        out.append(("ContainsRune", [hx(s), str(r)]))
    # Whole Unicode range in chunks, bit-exact case mapping and classification.
    for chunk in runes_chunks():
        text = chunk.decode()
        swapped = "".join(c.swapcase() for c in text).encode()
        for op in ("ToUpper", "ToLower", "ToTitle", "Title", "Fields", "TrimSpace", "Map",
                   "ToUpperSpecial", "ToLowerSpecial", "ToTitleSpecial"):
            args = [hx(chunk)]
            if op.endswith("Special"):
                args.append(hx(b"T"))
            out.append((op, args))
        out.append(("EqualFold", [hx(chunk), hx(swapped)]))
        out.append(("EqualFold", [hx(chunk), hx(chunk)]))
    for op in ("ToUpper", "ToLower", "EqualFold"):
        for _ in range(30):
            a = b"".join(rng.choice(PIECES) for _ in range(rng.randrange(1, 40)))
            out.append((op, [hx(a)] + ([hx(a.swapcase())] if op == "EqualFold" else [])))
    # Join with arbitrary separators and many elements.
    for _ in range(60):
        out.append(("Join", [hx(b",".join(rand_str(rng, 3) for _ in range(rng.randrange(6)))),
                             hx(rand_sep(rng))]))
    # Large inputs, huge counts.
    big = b"ab," * 20000
    for op, args in [("Count", [hx(big), hx(b"ab")]), ("Split", [hx(big), hx(b",")]),
                     ("SplitN", [hx(big), hx(b","), "9223372036854775807"]),
                     ("Replace", [hx(big), hx(b"ab"), hx(b"x"), "9223372036854775807"]),
                     ("Repeat", [hx(b""), "9223372036854775807"]),
                     ("Repeat", [hx(b"abc"), "3074457345618258603"]),
                     ("Repeat", [hx(b"abc"), "3074457345618258602"]),
                     ("Fields", [hx(b" a  b " * 20000)]),
                     ("Count", [hx(b""), hx(b"")]),
                     ("LastIndex", [hx(big), hx(b"ab,ab")])]:
        out.append((op, args))
    # Reader scripts.
    alphabet = "rbBcCanszSeEwl"
    for _ in range(250):
        s = rand_str(rng, 6)
        script = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 14)))
        out.append(("Reader", [hx(s), hx(script.encode())]))
    out.append(("Reader", [hx("héllo".encode()), hx(b"cccCCbBBrw")]))
    # Replacers: random, plus the cases that pin down priority and empty keys.
    keys = [b"", b"a", b"b", b"ab", b"abc", b"ba", b"<", b">", b"&", "é".encode(),
            "中".encode(), b"\xff", b"aa", b"a,"]
    for _ in range(400):
        pairs = []
        for _ in range(rng.choice([0, 1, 1, 2, 2, 3, 4, 6])):
            pairs += [rng.choice(keys), rand_str(rng, 3) if rng.random() < .8 else rng.choice([b"x", b"yy", "é".encode()])]
        out.append(("Replacer", [hx(rand_str(rng, 10))] + [hx(p) for p in pairs]))
    fixed = [
        (b"ab", [b"a", b"2", b"ab", b"1"]), (b"ab", [b"ab", b"1", b"a", b"2"]),
        (b"abc", [b"", b"X"]), (b"abc", [b"", b"X", b"a", b"Y"]), (b"abc", [b"a", b"Y", b"", b"X"]),
        ("héllo".encode(), [b"", b"-"]), (b"<a href='x'>&", [b"&", b"&amp;", b"<", b"&lt;", b">", b"&gt;", b"'", b"&#39;"]),
        (b"hello", [b"hello", b"x"]), (b"aaaa", [b"aa", b"b"]), (b"abc", [b"a", b"b", b"b", b"c"]),
        (b"abc", [b"a", b"1", b"a", b"2"]), (b"\xff\xfe", [b"", b"X"]), (b"", [b"", b"X"]),
        (b"aaa", [b"a", b"b", b"aa", b"c", b"aaa", b"d"]), (b"banana", [b"an", b"AN", b"a", b""]),
    ]
    for s, pairs in fixed:
        out.append(("Replacer", [hx(s)] + [hx(p) for p in pairs]))
    return out


def main():
    reqs = requests()
    payload = "".join(op + "".join("\t" + a for a in args) + "\n" for op, args in reqs)
    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "strings_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust strings probe failed:\n{rust_run.stderr[-3000:]}")
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/strings_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_run.returncode:
        raise RuntimeError(f"Go strings oracle failed:\n{go_run.stderr[-3000:]}")
    rust, go = rust_run.stdout.splitlines(), go_run.stdout.splitlines()
    if len(rust) != len(reqs) or len(go) != len(reqs):
        raise AssertionError(f"wrong record count: rust={len(rust)} go={len(go)} want={len(reqs)}")
    bad = [i for i in range(len(reqs)) if rust[i] != go[i]]
    for i in bad[:5]:
        op, args = reqs[i]
        print(f"MISMATCH {op} {[a[:80] for a in args]}\n  Rust={rust[i][:200]!r}\n  Go  ={go[i][:200]!r}")
    if bad:
        raise AssertionError(f"{len(bad)} of {len(reqs)} strings vectors differ")
    print(f"Strings Go differential: {len(reqs)} vectors passed")


if __name__ == "__main__":
    main()
