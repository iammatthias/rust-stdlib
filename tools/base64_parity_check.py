#!/usr/bin/env python3
"""Differentially check Go-compatible base64 behavior against Go's stdlib."""
import base64
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    rng = random.Random(0xBA5E64)
    values = [b""] + [bytes(range(n)) for n in range(1, 130)]
    values += [bytes(rng.randrange(256) for _ in range(n)) for n in range(130, 650)]
    malformed = ["A", "AA", "AAA", "A===", "====", "Zg=", "Zh==", "Zm9=", "Zg==X",
                 "Z=g=", "Z g==", "Zg==\n", "Zg\n==\r", "AA-_", "__//", "+-_/"]
    records = [value.hex() for value in values]
    records += [f"D{index}:{text.encode().hex()}" for index in range(6) for text in malformed]
    # Length queries and Go's partial Decode (bytes decoded before a CorruptInputError).
    records += [f"N{index}:{n}" for index in range(6) for n in range(0, 40)]
    records += [f"N{index}:{n}" for index in range(6) for n in (1000, 4097, 2**20 + 1)]
    mutated = []
    for value in values[:120]:
        encoded = list(base64.b64encode(value).decode())
        if encoded:
            position = rng.randrange(len(encoded))
            encoded[position] = rng.choice("ABCDxyz0123456789+/=-_\n")
        mutated.append("".join(encoded))
    mutated += [text for text in malformed] + ["Zm9vYmFy\n", "Zm9vYg==\n", "Zm9vYmFyZm9v"]
    records += [f"P{index}:{text.encode().hex()}" for index in range(6) for text in mutated]
    # WithPadding bytes: every byte value (Go accepts 0x80-0xff) and some it panics on.
    padding_bytes = list(range(256)) + [0x100, 0x1FF]
    records += [f"Q{pad:x}:{value.hex()}" for pad in padding_bytes for value in values[:12]]
    payload = "".join(record + "\n" for record in records)
    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "base64_parity_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust base64 probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/base64_parity_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_run.returncode:
        raise RuntimeError(f"Go base64 oracle failed:\n{go_run.stderr}")
    rust, go = rust_run.stdout.splitlines(), go_run.stdout.splitlines()
    if len(rust) != len(records) or len(go) != len(records):
        raise AssertionError("base64 oracle returned the wrong number of records")
    for i, (actual, expected) in enumerate(zip(rust, go)):
        if actual != expected:
            raise AssertionError(f"vector {i}, request={records[i]!r}\nRust={actual!r}\nGo={expected!r}")
    print(f"Base64 Go differential: {len(records)} encode/decode vectors passed")


if __name__ == "__main__":
    main()
