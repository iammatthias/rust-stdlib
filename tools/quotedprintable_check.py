#!/usr/bin/env python3
"""Differentially exercise quoted-printable streams against Go's stdlib."""
import os
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    rng = random.Random(271828)
    vectors = []
    dec = [b"", b"plain text", b"a=20b", b"one=\r\ntwo=\nthree", b"a  \t\r\nb", b"=G1", b"=4", b"=", b"=\rX", b"=\xff", b"=\x01", b"foo\x00bar", b"foo\rbar", b"\xff\x80", b"hello\nworld", b"x=" + b"a" * 80]
    vectors.extend(("decode", b) for b in dec)
    for n in [1, 2, 3, 72, 73, 74, 75, 76, 77, 151, 152, 153]:
        vectors.extend(("encode", bytes([c]) * n) for c in [ord("a"), ord(" "), ord("=")])
    vectors.extend(("encode", b) for b in [b"space \r\n", b"tab\t\n", b"a\rb\nc\r\nd", bytes(range(256))])
    vectors.extend(("encode_binary", b) for b in [b"a\rb\nc\r\nd", bytes(range(256))])
    vectors.extend(("decode", b) for b in [
        b"a" * 4095, b"a" * 4096, b"a" * 4097,
        b"a" * 4095 + b"\n", b"a" * 4096 + b"\n",
        b"a" * 4095 + b"=", b"a" * 4094 + b"= \t",
    ])
    alphabet = b"abc XYZ=\r\n\t\x00\x01\x7f\x80\xff"
    for _ in range(600):
        raw = bytes(rng.choice(alphabet) for _ in range(rng.randrange(0, 130)))
        vectors.append(("decode", raw))
        vectors.append((rng.choice(["encode", "encode_binary"]), raw))
    payload = "".join(f"{op} {data.hex() or '-'}\n" for op, data in vectors)
    env = os.environ.copy()
    subprocess.run(["cargo", "build", "--offline", "--locked", "--example", "quotedprintable_probe"], cwd=ROOT, env=env, check=True)
    exe = ROOT / "target" / "debug" / "examples" / ("quotedprintable_probe.exe" if os.name == "nt" else "quotedprintable_probe")
    commands = [[str(exe)], ["go", "run", str(ROOT / "tools" / "quotedprintable_oracle.go")]]
    results = []
    for cmd in commands:
        p = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT, env=env, check=True)
        results.append(p.stdout.splitlines())
    if len(results[0]) != len(vectors) or len(results[1]) != len(vectors):
        raise AssertionError(f"missing result: {len(results[0])}, {len(results[1])}, expected {len(vectors)}")
    for i, (rust, go) in enumerate(zip(*results)):
        if rust != go:
            op, data = vectors[i]
            raise AssertionError(f"vector {i} ({op}, {data!r}) differs\nRust: {rust}\nGo:   {go}")
    print(f"Quoted-printable Go conformance: {len(vectors)} vectors passed")


if __name__ == "__main__":
    main()
