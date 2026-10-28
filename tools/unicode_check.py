#!/usr/bin/env python3
"""Differentially check unicode, unicode/utf8 and unicode/utf16 against Go.

The sweep covers every code point 0..0x110000 plus negative and out-of-range
runes for every predicate and case function; table data is compared exactly.
"""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Differences attributable only to Rust's Unicode version versus Go's. The
# first column of a sweep or table line is compared as a whole; a line listed
# here (key -> reason) is tolerated. Rust 1.99 and Go 1.27 both ship Unicode
# 17.0.0, so the list is empty.
ALLOWED_VERSION_DIFFS = {}


def utf8_cases(rng):
    cases = [bytes([b]) for b in range(256)]
    cases += [b"", "héllo, 世界 \U0001F600".encode(), b"\xed\xa0\x80", b"\xf4\x90\x80\x80",
              b"\xc0\x80", b"\xe0\x80\x80", b"\xf0\x80\x80\x80", b"\xe2\x82", b"\xf0\x9f\x98",
              b"a\xe2\x82", b"\x80\x80\x80\x80\x80", b"\xf8\x88\x80\x80\x80", b"\xef\xbf\xbd",
              b"\xf4\x8f\xbf\xbf", b"\xf4\x8f\xbf\xbf\x80", b"\xed\x9f\xbf", b"\xee\x80\x80"]
    seeds = ["a", "é", "世", "\U0001F600", "\U0010FFFF", "퟿", "", "ࠀ", "߿"]
    for _ in range(4000):
        buf = bytearray()
        for _ in range(rng.randrange(0, 6)):
            if rng.random() < 0.6:
                buf += rng.choice(seeds).encode()
            else:
                buf += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 4)))
        for _ in range(rng.randrange(0, 3)):
            if buf:
                buf[rng.randrange(len(buf))] = rng.choice([0x80, 0xBF, 0xC0, 0xC2, 0xE0, 0xED, 0xF0, 0xF4, 0xF5, 0xFF, rng.randrange(256)])
        if buf and rng.random() < 0.4:
            del buf[rng.randrange(len(buf)):]
        cases.append(bytes(buf))
    cases += [bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40))) for _ in range(3000)]
    return cases


def main():
    rng = random.Random(0x0C0DE)
    records = ["sweep", "tables"]
    records += ["U8 " + c.hex() for c in utf8_cases(rng)]
    interesting16 = [0, 0x41, 0xD7FF, 0xD800, 0xDBFF, 0xDC00, 0xDFFF, 0xE000, 0xFFFF]
    for _ in range(4000):
        n = rng.randrange(0, 8)
        units = [rng.choice(interesting16) if rng.random() < 0.8 else rng.randrange(0x10000) for _ in range(n)]
        records.append("U16 " + "".join(f"{u:04x}" for u in units))
    interesting32 = [0, 0x41, 0xD7FF, 0xD800, 0xDFFF, 0xE000, 0xFFFF, 0x10000, 0x10FFFF, 0x110000,
                     0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0xFFFFFFFE]
    for _ in range(4000):
        n = rng.randrange(0, 8)
        runes = [rng.choice(interesting32) if rng.random() < 0.8 else rng.getrandbits(32) for _ in range(n)]
        records.append("R32 " + "".join(f"{r:08x}" for r in runes))
    payload = "".join(r + "\n" for r in records)

    build = subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--release", "--example", "unicode_probe"],
                           capture_output=True, text=True, cwd=ROOT)
    if build.returncode:
        raise RuntimeError(f"Rust unicode probe failed to build:\n{build.stderr}")
    rust_run = subprocess.run([str(ROOT / "target/release/examples/unicode_probe")], input=payload,
                              text=True, capture_output=True, cwd=ROOT)
    if rust_run.returncode:
        raise RuntimeError(f"Rust unicode probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(["go", "run", str(ROOT / "tools/unicode_oracle.go")], input=payload,
                            text=True, capture_output=True, cwd=ROOT)
    if go_run.returncode:
        raise RuntimeError(f"Go unicode oracle failed:\n{go_run.stderr}")
    rust, go = rust_run.stdout.splitlines(), go_run.stdout.splitlines()
    mismatches = []
    for i in range(max(len(rust), len(go))):
        a = rust[i] if i < len(rust) else "<missing>"
        b = go[i] if i < len(go) else "<missing>"
        if a != b and b not in ALLOWED_VERSION_DIFFS:
            mismatches.append((i, a, b))
    if mismatches:
        for i, a, b in mismatches[:10]:
            print(f"line {i}\n  Rust={a!r}\n  Go  ={b!r}")
        raise AssertionError(f"{len(mismatches)} unicode differential mismatches "
                             f"(rust {len(rust)} lines, go {len(go)} lines)")
    print(f"Unicode Go differential: sweep of {6 + 300 + 0x110020 + 5} runes, "
          f"{len(records) - 2} utf8/utf16 vectors, {len(go)} output lines passed")


if __name__ == "__main__":
    main()
