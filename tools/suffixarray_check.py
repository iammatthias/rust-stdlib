#!/usr/bin/env python3
"""Differentially check index/suffixarray against Go.

Serialized bytes (Write), reads of valid and corrupted streams, Lookup and
FindAllIndex with regexps. Requests go to tools/suffixarray_oracle.go and
examples/suffixarray_probe.rs. Lookup order is unspecified, so lookups compare
sorted results. Where Go panics on a corrupt stream (its readSlice slices
past the buffer), the port must report an error instead.
"""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]

PATTERNS = [
    "a", "an", "ab", "ba", "a+", "b*", "a|b", "(an)+", "x", "^ab", "ab$", "a.c", "[ab]+c",
    "an(a|b)", "a*", "", "banana", r"\bab", "(?i)AB", "a{2,3}", "b[^a]", ".", r"\x61", "(a)(b)?",
    "é", "(?s).", "z+|a", "ba|an", "a?b", "abc|abcd", r"\Qab\E", "[", "(", "a**",
]


def hex_of(data):
    return data.hex()


def random_data(rng):
    kind = rng.randrange(4)
    n = rng.randrange(0, 60)
    if kind == 0:
        return bytes(rng.choice(b"ab") for _ in range(n))
    if kind == 1:
        return bytes(rng.choice(b"abc\x00\xff ") for _ in range(n))
    if kind == 2:
        return bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
    return bytes(rng.choice(b"ab") for _ in range(rng.randrange(0, 40)))


def mutants(serialized, rng):
    """Truncations and corruptions of a serialized index."""
    out = []
    for cut in sorted({0, 1, 9, 10, 11, 12, len(serialized) // 2, len(serialized) - 1}):
        if 0 <= cut < len(serialized):
            out.append(serialized[:cut])
    for _ in range(40):
        b = bytearray(serialized)
        pos = rng.randrange(len(b))
        b[pos] = rng.randrange(256)
        out.append(bytes(b))
    for _ in range(10):
        b = bytearray(serialized)
        pos = rng.randrange(len(b))
        del b[pos:pos + rng.randrange(1, 4)]
        out.append(bytes(b))
    return out


def requests(rng):
    out = []
    datas = [b"", b"a", b"aaaaaaaaaa", b"abc", b"barbarabarbarabarbara", b"abababab",
             "Now is the time for all good men to come to the aid of their country.".encode(),
             b"package main\n\nimport(\n    \"rand\"\n    ", "été banana".encode()]
    datas += [random_data(rng) for _ in range(120)]
    # Large inputs cross the 16 KiB write buffer and the multi-byte element path.
    large = [b"ab" * 5000, b"a" * 6000, bytes(rng.randrange(256) for _ in range(20000))]
    datas += large

    for data in datas:
        out.append(f"W:{hex_of(data)}")
    for data in datas:
        if len(data) > 2000:
            continue
        for pattern in PATTERNS:
            for n in (-1, 0, 1, 2, 5):
                out.append(f"F:{hex_of(data)}:{hex_of(pattern.encode())}:{n}")
        for _ in range(6):
            if data and rng.random() < 0.7:
                start = rng.randrange(len(data))
                pattern = data[start:start + rng.randrange(1, 5)]
            else:
                pattern = bytes(rng.choice(b"abz") for _ in range(rng.randrange(0, 4)))
            for n in (-1, 0, 1, 3, 2000000000):
                out.append(f"L:{hex_of(data)}:{hex_of(pattern)}:{n}")
    for data in large:
        for pattern in (b"ab", b"aa", b"a", b"ba"):
            out.append(f"L:{hex_of(data)}:{hex_of(pattern)}:-1")
            out.append(f"L:{hex_of(data)}:{hex_of(pattern)}:3")
        out.append(f"F:{hex_of(data)}:{hex_of(b'ab')}:-1")
    return out


def main():
    rng = random.Random(0x5FA1)
    lines = requests(rng)
    # Serialized forms come from the Go oracle's Write; each becomes an R request.
    write_payload = "".join(line + "\n" for line in lines)
    go_writes = subprocess.run(
        ["go", "run", str(ROOT / "tools/suffixarray_oracle.go")],
        input=write_payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_writes.returncode:
        raise RuntimeError(f"Go suffixarray oracle failed:\n{go_writes.stderr}")
    go_answers = go_writes.stdout.splitlines()
    serialized = []
    for line, answer in zip(lines, go_answers):
        if line.startswith("W:") and answer != "panic" and not answer.startswith("err:"):
            serialized.append(bytes.fromhex(answer))
    read_lines = []
    for ser in serialized:
        read_lines.append("R:" + ser.hex())
        if len(ser) < 4000:
            for mutant in mutants(ser, rng):
                read_lines.append("R:" + mutant.hex())
    lines += read_lines

    payload = "".join(line + "\n" for line in lines)
    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "suffixarray_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust suffixarray probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/suffixarray_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_run.returncode:
        raise RuntimeError(f"Go suffixarray oracle failed:\n{go_run.stderr}")
    rust = rust_run.stdout.splitlines()
    go = go_run.stdout.splitlines()
    if len(rust) != len(lines) or len(go) != len(lines):
        raise AssertionError(
            f"suffixarray oracle returned {len(go)} and probe {len(rust)} records for {len(lines)} requests")
    panics = 0
    for i, (actual, expected) in enumerate(zip(rust, go)):
        request = lines[i]
        op = request[0]
        if op == "L" and actual != "none" and expected != "none":
            # Lookup order is unspecified; compare the sets of offsets.
            same = sorted(map(int, actual.split(","))) == sorted(map(int, expected.split(",")))
        elif expected == "panic":
            # Go slices past its buffer on a corrupt chunk size; the port reports an error.
            panics += 1
            same = actual.startswith("err:")
        else:
            same = actual == expected
        if not same:
            raise AssertionError(f"vector {i}, request={request[:200]!r}\nRust={actual[:300]!r}\nGo={expected[:300]!r}")
    print(f"suffixarray Go differential: {len(lines)} write, read, lookup and FindAllIndex vectors passed"
          f" ({panics} corrupt streams where Go panics and the port reports an error)")


if __name__ == "__main__":
    main()
