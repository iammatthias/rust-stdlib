#!/usr/bin/env python3
"""Differentially check text/scanner against Go: tokens, positions, errors and reads.

Requests go to tools/text_scanner_oracle.go and examples/text_scanner_probe.rs.
Each request is <op>:<cfg>:<chunk>:<errAt>:<hex source>; the configurations
(mode sets, white space and identifier predicates) are configs() in both files.
"""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONFIGS = 24

# Snippets from Go's scanner_test.go: numbers, errors, comments, literals.
SEEDS = [
    "// line comments\n//\n////\n// /* comment */\n", "/**/ /***/ /* // comment */ /* /* comment */\n",
    "/*\n comment\n*/", "a a0 foobar abc123 LGTM _ _abc123 abc123_ _abc_123_",
    "_äöü _本 äöü 本 a۰۱۸ foo६४ bar９８７６", "0 1 9 42 1234567890 00 01 07 042 01234567",
    "0x0 0x1 0xf 0x42 0x123456789abcDEF 0X0 0XF 0X123456789abcDEF",
    "0. 1. 42. 01234567890. .0 .1 .42 0.0 1e0 0E0 0e+10 1e-10 0E+10 1E-10",
    "' ' 'a' '本' '\\a' '\\b' '\\f' '\\n' '\\r' '\\t' '\\v' '\\'' '\\000' '\\777' '\\x00' '\\xff'",
    "'\\u0000' '\\ufA16' '\\U00000000' '\\U0000ffAB'",
    "\" \" \"a\" \"本\" \"\\a\" \"\\\"\" \"\\000\" \"\\777\" \"\\x00\" \"\\xff\" \"\\U0000ffAB\"",
    "`` `\\` `\n\n/* foobar */\n\n`", "\x01 +/.~(", "\x00", "\x80", "\xff",
    "1.5e 1.5E 1e+ 1e- 1.5z", "/*/", "`abc\n", "\"abc\n", "'aa'", "'\"'", "\"\\'\"",
    "01238 01238123 0x 0xg 1.5e 1.5e+ 1.5e-", "'", "'\n", "\"abc", "a\x00", "ab\x80", "abc\xff",
    "\"a\x00", "\"ab\x80", "`abc\xff", "\uFEFFif a == bcd /* com\uFEFFment */ {\n\ta += c\n}",
    "0b0 0B1110 0b0190 0b01a0 0b. 0b.1 0b1.0 0b1e10 0b1P-1 0b__1000",
    "0o0 0O1234 0o8123 0o1293 0o12a3 0o. 0o.2 0o1E+2 0o1p10 0o60___0",
    "0123 08123 01293 0F. 0123F. 0123456x 1f 1_000 1_000.000_1 0_466 0466_",
    "0x12efp-123 0xABCD.p+0 0x.0189P-0 0x1.ffffp+1023 0x. 0x0. 0x.0 0x1.1 0x1.1e0",
    "0x1.2gp1a 0x0p 0xeP- 0x1234PAB 0x1.2p1a 0x_f00d.0p1_2 0x1.0_p0 0x___0 2.7_e0 0._1 1_.",
    "0p0 1.0P-1 1e+f 0E+ 0e 0x0p0 0x_f00d", "hello \n\nworld\n!\n", "x \"", "x := 0x1f // hex\n",
    "1.2.3 1..2 .. ... 1e5e6 0x1p-2 0b101 1__0 ab.cd 'x' \"y\" `z`",
    "#!/usr/bin/env go\n/* unterminated", "\n\n\n", "   \t\r\n  ", "ab\u00e9\u4e2d\U0001F600",
]

ALPHABET = list("0123456789abcdefABCDEFxXoObBpPeE_+-.'\"`\\/*\n \t#:;") + [
    "\x00", "\x80", "\xff", "é", "本", "\U0001F600", "\uFEFF", "\u0660", "\u00a0", "Ⅻ",
]


def hex_bytes(text):
    if isinstance(text, bytes):
        return text.hex()
    return text.encode("utf-8", "surrogateescape").hex()


def random_source(rng):
    length = rng.randrange(0, 48)
    parts = []
    for _ in range(length):
        if rng.random() < 0.05:
            parts.append(bytes([rng.randrange(256)]))
        else:
            parts.append(rng.choice(ALPHABET).encode("utf-8", "surrogateescape"))
    return b"".join(parts)


def requests(rng):
    out = []
    sources = [s.encode("utf-8", "surrogateescape") for s in SEEDS]
    # Every seed under every configuration, whole-buffer reads.
    for source in sources:
        for cfg in range(CONFIGS):
            out.append(f"S:{cfg}:0:-1:{source.hex()}")
    # Random sources: a few configurations, read sizes, error offsets and both ops.
    for _ in range(1200):
        source = random_source(rng)
        for _ in range(4):
            cfg = rng.randrange(CONFIGS)
            chunk = rng.choice([0, 1, 2, 3, 5, 8])
            err_at = rng.randrange(0, len(source) + 2) if rng.random() < 0.15 else -1
            op = rng.choice("SN")
            out.append(f"{op}:{cfg}:{chunk}:{err_at}:{source.hex()}")
    # Long inputs cross the 1024-byte buffer and the multi-byte split path.
    for n in (1020, 1021, 1022, 1023, 1024, 1025, 2048, 3000):
        filler = ("a" * n + "本" + "\"x" + "\n" + "0x1.2p3" * (n // 7)).encode("utf-8")
        for cfg in (0, 2, 5):
            out.append(f"S:{cfg}:0:-1:{filler.hex()}")
            out.append(f"S:{cfg}:3:-1:{filler.hex()}")
    return out


def main():
    rng = random.Random(0x7E47)
    lines = requests(rng)
    payload = "".join(line + "\n" for line in lines)

    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "text_scanner_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust text/scanner probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/text_scanner_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_run.returncode:
        raise RuntimeError(f"Go text/scanner oracle failed:\n{go_run.stderr}")
    rust = rust_run.stdout.splitlines()
    go = go_run.stdout.splitlines()
    if len(rust) != len(lines) or len(go) != len(lines):
        raise AssertionError(
            f"text/scanner oracle returned {len(go)} and probe {len(rust)} records for {len(lines)} requests")
    for i, (actual, expected) in enumerate(zip(rust, go)):
        if actual != expected:
            raise AssertionError(f"vector {i}, request={lines[i]!r}\nRust={actual!r}\nGo={expected!r}")
    print(f"text/scanner Go differential: {len(lines)} scan, next, read and error vectors passed")


if __name__ == "__main__":
    main()
