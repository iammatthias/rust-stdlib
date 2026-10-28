#!/usr/bin/env python3
"""Differentially check base32 against Go: encodings, lengths, decode offsets and partial output."""
import base64
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
STD = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
HEXA = b"0123456789ABCDEFGHIJKLMNOPQRSTUV"
LOWER = b"abcdefghijklmnopqrstuvwxyz234567"
REVERSED = b"ZYXWVUTSRQPONMLKJIHGFEDCBA765432"
HIGH = bytes(range(0x80, 0xA0))
TOP = bytes(range(0xE0, 0x100))
# Same table as configs() in tools/base32_oracle.go and examples/base32_probe.rs.
CONFIGS = [(STD, b"="), (HEXA, b"="), (STD, None), (HEXA, None),
           (LOWER, b"-"), (HIGH, b"\xff"), (TOP, None), (REVERSED, b"=")]


def encode(plain, config):
    """RFC 4648 encoding in a configured alphabet: index-wise translation of the standard output."""
    alphabet, padding = config
    table = bytes.maketrans(STD + b"=", alphabet + (padding or b"="))
    text = base64.b32encode(plain).translate(table)
    return text if padding else text.rstrip(b"=")


def mutants(encoded, padding):
    """Truncations, injected pad/newline/other bytes, replacements and tails of one encoding."""
    pad = padding or b"="
    for k in range(len(encoded) + 1):
        yield encoded[:k]
    for pos in range(len(encoded) + 1):
        for insert in [pad, b"\r", b"\n", b"A", b"\xff", b"9"]:
            yield encoded[:pos] + insert + encoded[pos:]
    for pos in range(len(encoded)):
        for replacement in [pad, b"\n", b"\xff", b"0", b"Z"]:
            yield encoded[:pos] + replacement + encoded[pos + 1:]
    for tail in [b"A", b"=", b"======", b"AAAAAAAA", b"\n", b"MY======"]:
        yield encoded + tail


# (caller buffer size, source bytes per read)
CHUNK_SCHEDULES = [(1, 1), (3, 1), (5, 7), (8, 8), (7, 3), (64, 5), (1, 64), (700, 1000), (4096, 4096)]


def chunk_stable(text, padding):
    """Whether Go's streaming reader gives the same ok/err for any read chunking.

    Go ignores data after padding (or after the byte 0xff, which is byte(NoPadding))
    when it arrives in the same read, and reports it only in a later read.
    """
    data = text.replace(b"\r", b"").replace(b"\n", b"")
    if padding is None:
        return b"\xff" not in data
    index = data.find(padding)
    return index < 0 or data[index:].strip(padding) == b""


def constructor_requests():
    """NewEncoding and WithPadding cases; Go panics where Rust returns an error."""
    alphabets = [STD, LOWER, REVERSED, HIGH, TOP, bytes(range(32)), STD[:31],
                 STD + b"A", STD[:1] + b"A" + STD[2:], STD[:5] + b"\n" + STD[6:],
                 STD[:1] + b"\r" + STD[2:]]
    paddings = [-2, -1, 0, 9, 10, 13, 32, 45, 61, 65, 88, 127, 128, 255, 256, 300]
    return [f"N:{alphabet.hex()}|{padding}" for alphabet in alphabets for padding in paddings]


def main():
    rng = random.Random(0xB4532)
    requests = []
    plains = {}
    for c, config in enumerate(CONFIGS):
        plains[c] = [bytes(rng.randrange(256) for _ in range(n)) for n in range(17) for _ in range(2)]
        plains[c] += [bytes(range(n)) for n in range(0, 20)]
        for plain in plains[c]:
            requests.append(f"E{c}:{plain.hex()}")
        requests += [f"L{c}:{n}" for n in range(0, 130)]
    encoded = []
    for c, config in enumerate(CONFIGS):
        for plain in plains[c]:
            text = encode(plain, config)
            encoded.append((c, text))
            for mutant in mutants(text, config[1]):
                requests.append(f"A{c}:{mutant.hex()}")
                requests.append(f"B{c}:{mutant.hex()}")
                requests.append(f"S{c}:{mutant.hex()}")
    for i, (c, text) in enumerate(encoded):
        requests.append(f"W{c}:{text.hex()}")
        if chunk_stable(text, CONFIGS[c][1]):
            requests.append(f"R{c}:{text.hex()}")
        if i % 5 == 0:
            for mutant in list(mutants(text, CONFIGS[c][1]))[::7]:
                if chunk_stable(mutant, CONFIGS[c][1]):
                    requests.append(f"R{c}:{mutant.hex()}")
        # Chunked-read schedules: output, errors and their position depend on
        # how the source and the caller chunk the stream, and must match Go.
        if i % 3 == 0:
            for mutant in [text] + list(mutants(text, CONFIGS[c][1]))[::11]:
                for read, chunk in CHUNK_SCHEDULES:
                    requests.append(f"C{c}:{read},{chunk}|{mutant.hex()}")
    for plain in plains[0][:12]:
        requests.append(f"W0:{plain.hex()}")
    requests += constructor_requests()
    payload = "".join(request + "\n" for request in requests)

    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "base32_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust base32 probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/base32_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_run.returncode:
        raise RuntimeError(f"Go base32 oracle failed:\n{go_run.stderr}")
    rust = rust_run.stdout.splitlines()
    go = go_run.stdout.splitlines()
    if len(rust) != len(requests) or len(go) != len(requests):
        raise AssertionError("base32 oracle returned the wrong number of records")
    for i, (actual, expected) in enumerate(zip(rust, go)):
        if actual != expected:
            raise AssertionError(f"vector {i}, request={requests[i]!r}\nRust={actual!r}\nGo={expected!r}")
    print(f"Base32 Go differential: {len(requests)} encode, length, decode, stream and constructor vectors passed")


if __name__ == "__main__":
    main()
