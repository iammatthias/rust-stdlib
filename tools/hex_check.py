#!/usr/bin/env python3
"""Differentially check encoding/hex encode, decode, dump and dumper against Go."""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
DIGITS = b"0123456789abcdefABCDEF"
JUNK = b"gGzZ \t\n\x00\x7f\x80\xa0\xad\xe9\xff:"


def random_text(rng, length, junk_rate):
    return bytes(
        rng.choice(JUNK) if rng.random() < junk_rate else rng.choice(DIGITS)
        for _ in range(length)
    )


def main():
    rng = random.Random(0x4E58)
    special = [b"", b"f", b"fg", b"g", b"0g", b"g0", b"0", b"\xe9", b"00\xe9",
               b"\x00", b"AbCdEf", DIGITS, b"0\xad", b"\xa0 ", b"zz\xe9"]
    records = []
    for payload in special:
        records += [b"E" + payload, b"D" + payload, b"A" + payload, b"P" + payload, b"W" + payload]
    for _ in range(1500):
        payload = random_text(rng, rng.randrange(0, 41), rng.choice([0.0, 0.05, 0.3]))
        records.append(b"D" + payload)
        records.append(b"A" + payload)
    for _ in range(500):
        records.append(b"E" + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300))))
    for _ in range(300):
        body = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        records.append(rng.choice([b"P", b"W"]) + body)
    for _ in range(600):
        # Text mode: Rust accepts only valid UTF-8, so generate UTF-8 with junk characters.
        text = bytes(rng.choice(b"0123456789abcdefABCDEFgz \n") for _ in range(rng.randrange(0, 30)))
        if rng.random() < 0.1:
            text += "é".encode()
        records.append(b"S" + text)
    # Odd-length strings and invalid-UTF-8 payloads both exercise the skip path.
    records.append(b"S\xff\xfe")
    payload = "".join(record[:1].decode() + record[1:].hex() + "\n" for record in records)

    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "hex_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust hex probe failed:\n{rust_run.stderr}")
    rust = rust_run.stdout.splitlines()
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/hex_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_run.returncode:
        raise RuntimeError(f"Go hex oracle failed:\n{go_run.stderr}")
    go = go_run.stdout.splitlines()
    if len(rust) != len(records) or len(go) != len(records):
        raise AssertionError(f"hex oracle returned {len(go)} and probe {len(rust)} records for {len(records)} requests")
    for i, (actual, expected) in enumerate(zip(rust, go)):
        if actual != expected:
            raise AssertionError(f"vector {i}, request={records[i]!r}\nRust={actual!r}\nGo={expected!r}")
    print(f"Hex Go differential: {len(records)} encode/decode/dump vectors passed")


if __name__ == "__main__":
    main()
