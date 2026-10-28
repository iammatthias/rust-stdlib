#!/usr/bin/env python3
"""Compare the Rust Ascii85 API with Go's encoding/ascii85 using a fixed corpus."""
import os
import random
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def corpus():
    rng = random.Random(0xA5C1185)
    requests = []
    for n in range(257):
        data = bytes(rng.randrange(256) for _ in range(n))
        requests.append(f"E\t{data.hex()}")
        requests.append(f"D\t{data.hex()}\t{n % 2}")
        requests.append(f"D\t{encode_reference_input(data)}\t1")
        requests.append(f"S\t{data.hex()}")
        requests.append(f"R\t{data.hex()}")
        requests.append(f"R\t{encode_reference_input(data)}")
    special = [b"", b"z", b"z!", b"!!!!!", b"!!!!!!", b"!!!!!!!!!!",
               b" \t\r\n z\x00!!!!!!!!!", b"!!!!!x", b"v", b"~>",
               b"!!!!!\\", b"!!!!\xff", bytes(range(33, 118))]
    for data in special:
        requests.extend((f"D\t{data.hex()}\t0", f"D\t{data.hex()}\t1"))
        requests.extend((f"R\t{data.hex()}", f"S\t{data.hex()}"))
    # Longer inputs cross Go's 1024-byte decoder buffer, so chunk-carried input,
    # whitespace compaction and chunk-relative error offsets are exercised.
    long_data = bytes(rng.randrange(256) for _ in range(3000))
    long_encoded = bytes.fromhex(encode_reference_input(long_data))
    spaced = b"\n".join(long_encoded[i:i + 100] for i in range(0, len(long_encoded), 100))
    corrupt = bytearray(long_encoded)
    corrupt[2500] = ord("w")
    requests.extend((f"S\t{long_data.hex()}", f"R\t{long_encoded.hex()}",
                     f"R\t{spaced.hex()}", f"R\t{corrupt.hex()}"))
    for n in range(1, 100):
        raw = bytes(rng.choice(b" !\x00\t\n!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstu vwxyz") for _ in range(n))
        requests.extend((f"D\t{raw.hex()}\t0", f"D\t{raw.hex()}\t1"))
        requests.append(f"R\t{raw.hex()}")
    return requests


def encode_reference_input(data):
    # Build valid fragments independently of the Rust implementation; the
    # matching encoding operations are checked against Go in the same corpus.
    out = bytearray()
    for block in (data[i:i + 4] for i in range(0, len(data), 4)):
        value = int.from_bytes(block.ljust(4, b"\0"), "big")
        if len(block) == 4 and value == 0:
            out.extend(b"z")
            continue
        chars = bytearray(5)
        for i in range(4, -1, -1):
            chars[i] = 33 + value % 85
            value //= 85
        out.extend(chars[:len(block) + 1])
    return bytes(out).hex()


def main():
    requests = corpus()
    source = "\n".join(requests) + "\n"
    env = os.environ.copy()
    rust = subprocess.run(
        ["cargo", "run", "--offline", "--locked", "--quiet", "--example", "ascii85_probe"],
        cwd=ROOT, input=source, text=True, capture_output=True, env=env, check=True,
    ).stdout.splitlines()
    go = subprocess.run(
        ["go", "run", "tools/ascii85_oracle.go"],
        cwd=ROOT, input=source, text=True, capture_output=True, env=env, check=True,
    ).stdout.splitlines()
    if len(rust) != len(requests) or len(go) != len(requests):
        raise AssertionError("Ascii85 oracle returned the wrong number of records")
    if rust != go:
        for i, (actual, expected) in enumerate(zip(rust, go)):
            if actual != expected:
                raise SystemExit(f"Ascii85 mismatch at vector {i}: {requests[i]}\nRust: {actual}\nGo:   {expected}")
        raise SystemExit(f"line count mismatch: Rust {len(rust)}, Go {len(go)}")
    print(f"Ascii85 Go/Rust differential: {len(requests)} vectors passed")


if __name__ == "__main__":
    main()
