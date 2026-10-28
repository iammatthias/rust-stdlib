#!/usr/bin/env python3
"""Differentially check compress/bzip2 decoding against Go.

Inputs come from Python's bz2 module at levels 1-9 (random and structured
payloads, multi-block streams), concatenated streams with trailing data,
hand-edited header/block fields and thousands of seeded mutations. Rust and Go
must agree on accept/reject for every vector, on the exact bytes delivered
before the end or the first error, and on the StructuralError message. Go returns bytes together with an error (zero-bit
decoding of truncated blocks); Rust must deliver the same bytes before its error, and they are tallied.
"""
import bz2
import os
import pathlib
import random
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def invoke(command, vectors):
    payload = "".join(v.hex() + "\n" for v in vectors)
    process = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT, check=True)
    lines = process.stdout.splitlines()
    if len(lines) != len(vectors):
        raise AssertionError(f"{command[0]}: {len(lines)} responses for {len(vectors)} vectors")
    return lines


def payloads(rng):
    text = b"".join(b"line %d: the quick brown fox jumps over the lazy dog\n" % i for i in range(400))
    out = [
        b"",
        b"a",
        b"ab",
        bytes(range(256)),
        b"\x00" * 1000,
        text,
        bytes(rng.randrange(256) for _ in range(3000)),
        bytes(rng.choice(b"ACGT") for _ in range(5000)),
    ]
    # Run lengths around bzip2's initial RLE thresholds (4 + count byte).
    for run in (3, 4, 5, 6, 255, 258, 259, 260, 1000):
        out.append(b"x" * run + b"y" * run + b"x")
    out.append(b"".join(bytes([i % 256]) * (i % 9) for i in range(2000)))
    return out


def text_blob(rng):
    return b"".join(b"%d %s\n" % (i, bytes(rng.choice(b"abcdefghij") for _ in range(30))) for i in range(6000))


def edit_bits(data, bit_offset, width, value):
    """Overwrite `width` bits starting at MSB-first `bit_offset`."""
    data = bytearray(data)
    for i in range(width):
        bit = (value >> (width - 1 - i)) & 1
        index, shift = divmod(bit_offset + i, 8)
        data[index] = (data[index] & ~(0x80 >> shift)) | (bit << (7 - shift))
    return bytes(data)


def mutate(rng, data):
    data = bytearray(data)
    kind = rng.randrange(6)
    if kind == 0 and data:
        for _ in range(rng.randrange(1, 4)):
            i = rng.randrange(len(data) * 8)
            data[i // 8] ^= 0x80 >> (i % 8)
    elif kind == 1 and data:
        data[rng.randrange(len(data))] = rng.randrange(256)
    elif kind == 2:
        del data[rng.randrange(len(data) + 1):]
    elif kind == 3:
        i = rng.randrange(len(data) + 1)
        data[i:i] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 4)))
    elif kind == 4 and data:
        i = rng.randrange(len(data))
        del data[i:i + rng.randrange(1, 4)]
    else:
        # Concentrate on the block header and tables, where structure lives.
        limit = min(len(data), 80)
        if limit > 4:
            i = rng.randrange(4, limit)
            data[i] ^= 1 << rng.randrange(8)
    return bytes(data)


def main():
    started = time.monotonic()
    rng = random.Random(0xB2_1996)
    vectors = []
    seeds = []
    for level in range(1, 10):
        for payload in payloads(rng):
            stream = bz2.compress(payload, level)
            vectors.append(stream)
            if len(stream) < 700:
                seeds.append(stream)
    # Multi-block streams: level 1 blocks hold at most 100 000 bytes.
    big = bytes(rng.choice(b"abcdefgh ") for _ in range(230_000))
    vectors.append(bz2.compress(big, 1))
    vectors.append(bz2.compress(b"z" * 450_000, 1))
    vectors.append(bz2.compress(big, 9))
    structured = len(vectors)

    one = bz2.compress(b"first stream\n", 9)
    two = bz2.compress(b"second stream\n" * 50, 3)
    empty = bz2.compress(b"", 5)
    vectors += [
        b"", b"B", b"BZ", b"BZh", b"BZh9", b"BZh0", b"BZx9", b"XZh9", b"BZh:",
        empty, one + two, one + empty + two, empty + empty, one + two + one,
        one + b"B", one + b"BZ", one + b"BZh", one + b"BZh0", one + b"\x00",
        one + b"BZh9", one + b"XY", one + one[:-1], one + b"\x00" * 16,
    ]
    # Field edits at fixed offsets: block CRC is bytes 10..14; the randomized
    # flag and the 24-bit origPtr follow at bit 112.
    for stream in (one, two, bz2.compress(bytes(range(256)) * 4, 1)):
        vectors.append(edit_bits(stream, 112, 1, 1))
        for orig_ptr in (0, 1, 12, 13, 0xFFFFFF, len(stream)):
            vectors.append(edit_bits(stream, 113, 24, orig_ptr))
        vectors.append(edit_bits(stream, 80, 32, 0))
        tail = bytearray(stream)
        tail[-2] ^= 0x10
        vectors.append(bytes(tail))
        for cut in range(len(stream)):
            vectors.append(stream[:cut])
    # Random bit strings after a valid header and block magic exercise every
    # table-parsing error path.
    prefix = b"BZh9" + bytes.fromhex("314159265359")
    for _ in range(400):
        vectors.append(prefix + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120))))
    # Truncations inside the block data of larger and multi-block streams: Go decodes
    # the missing bits as zeros and returns those bytes together with ErrUnexpectedEOF.
    for stream in (bz2.compress(big, 1), bz2.compress(text_blob(rng), 9), bz2.compress(b"z" * 450_000, 1)):
        for _ in range(60):
            vectors.append(stream[:rng.randrange(1, len(stream))])
    mutations = 0
    for _ in range(3500):
        vectors.append(mutate(rng, rng.choice(seeds)))
        mutations += 1

    subprocess.run(["cargo", "build", "--offline", "--locked", "--example", "bzip2_probe"], cwd=ROOT, check=True)
    probe = ROOT / "target/debug/examples" / ("bzip2_probe.exe" if os.name == "nt" else "bzip2_probe")
    rust = invoke([str(probe)], vectors)
    go = invoke(["go", "run", str(ROOT / "tools/bzip2_oracle.go")], vectors)
    accepted = 0
    go_tail = 0
    partial = 0
    for i, (r, g) in enumerate(zip(rust, go)):
        r_fields, g_fields = r.split(" "), g.split(" ")
        if g_fields[0] == "err" and int(g_fields[2]) > 0:
            go_tail += 1
        if r_fields[:2] != g_fields[:2]:
            raise AssertionError(f"vector {i}: input={vectors[i].hex()[:400]}\nRust={r[:400]}\nGo={g[:400]}")
        if g_fields[0] == "err" and r_fields[3:] != g_fields[3:]:
            raise AssertionError(f"vector {i}: StructuralError mismatch input={vectors[i].hex()[:400]}\n"
                                 f"Rust={r[:400]}\nGo={g[:400]}")
        accepted += r_fields[0] == "ok"
        partial += r_fields[0] == "err" and r_fields[1] != ""
    for i in range(structured):
        if rust[i] != "ok " + bz2.decompress(vectors[i]).hex():
            raise AssertionError(f"structured vector {i} did not round-trip Python bz2")
    print(f"bzip2 Go differential: {len(vectors)} vectors ({structured} Python bz2 streams, "
          f"{mutations} mutations, {accepted} accepted, {partial} rejected after "
          f"identical partial output); Go returned bytes with an error in "
          f"{go_tail} vectors; passed in {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
