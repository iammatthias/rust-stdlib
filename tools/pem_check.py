#!/usr/bin/env python3
"""Compare PEM encode/decode and malformed resynchronization with Go."""
import base64
import json
import os
import pathlib
import random
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    started = time.monotonic()
    vectors = []
    vectors.extend([
        {"op": "decode", "input": "junk\n-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----\nrest"},
        {"op": "decode", "input": "-----BEGIN EMPTY-----\n-----END EMPTY-----\n"},
        {"op": "decode", "input": "-----BEGIN BAD-----\n%%%\n-----END BAD-----\n-----BEGIN GOOD-----\ndGVzdA==\n-----END GOOD-----\nrest"},
        {"op": "decode", "input": "-----BEGIN X-----\nA: b\n\nY Q==\t\r\n-----END X----- \t\r\ntail"},
        {"op": "decode", "input": "-----BEGIN X-----\r\nT: v\r\n\r\ndGVzdA==\r\n-----END X-----\r\n"},
        {"op": "decode", "input": "-----BEGIN X-----\n\u00a0Key\u00a0: \u00a0value\u00a0\n\nYQ==\n-----END X-----\n"},
        {"op": "decode", "input": "-----BEGIN X-----\nAAAA\n-----END Y-----\n-----BEGIN X-----\nAQID\n-----END X-----\n"},
        {"op": "decode", "input": "prefix\n-----BEGIN X-----\nYWJj\n-----END X----- trailing\n"},
        {"op": "decode", "input": "-----BEGIN X-----\nA: one\nA: two\n\nYQ==\n-----END X-----\n"},
        {"op": "decode", "input": "-----BEGIN FOO-----\ndGVzdA==\n-----END FOO----\n-----BEGIN GOOD-----\ndGVzdA==\n-----END GOOD-----\n"},
        {"op": "decode", "input": "-----BEGIN FOO-----\ndGVzdA==\n-----END FOO------\n-----BEGIN GOOD-----\ndGVzdA==\n-----END GOOD-----\n"},
        {"op": "decode", "input": "-----BEGIN FOO-----\ndGVzdA==\n-----END FOO----- .\n-----BEGIN GOOD-----\ndGVzdA==\n-----END GOOD-----\n"},
        {"op": "decode", "input": "-----BEGIN FOO-----\ndGVzdA==\n-----END BAR-----\n-----BEGIN GOOD-----\ndGVzdA==\n-----END GOOD-----\n"},
        {"op": "decode", "input": "-----BEGIN PUBLIC KEY\ndGVzdA==\n-----END PUBLIC KEY-----\n-----BEGIN GOOD-----\ndGVzdA==\n-----END GOOD-----\n"},
        {"op": "decode", "input": "-----BEGIN TEST BLOCK-----\n-----BEGIN TEST BLOCK-----\n-----BEGIN TEST BLOCK-----\naGVsbG8=\n-----END TEST BLOCK-----"},
        {"op": "decode", "input": "not pem"},
        {"op": "decode", "input": ("\n-----END X-----" * 1000) + "\n-----BEGIN X-----\ndGVzdA==\n-----END X-----\n"},
    ])
    rng = random.Random(0x50454D)
    for i in range(180):
        payload = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 140)))
        headers = {"Z-last": "z", "A-first": "a"}
        if i % 3 == 0:
            headers["Proc-Type"] = "4,ENCRYPTED"
        vectors.append({"op": "encode", "type": rng.choice(["CERTIFICATE", "PRIVATE KEY", "DATA"]), "headers": headers, "bytes": list(payload)})
        text = base64.b64encode(payload).decode("ascii")
        wrapped = "\n".join(text[n:n + 64] for n in range(0, len(text), 64))
        vectors.append({"op": "decode", "input": f"-----BEGIN DATA-----\n{wrapped}\n-----END DATA-----\n"})
    for _ in range(400):
        junk = "".join(rng.choice("abcXYZ0123%=&; \t\r\n-_") for _ in range(rng.randrange(0, 80)))
        vectors.append({"op": "decode", "input": junk})

    # Arbitrary bytes in the type line and headers, which Go accepts (hex-encoded for JSON).
    raw_types = [b"X", b"\xff\xfe", b"A\x80B", "\u00e9".encode(), b"", b" sp ", b"\x00"]
    raw_headers = [b"", b"K: v\n", b"\xff: \xfe\n", b"\xa0K\xa0: \xa0v\xa0\n", b"\xc2\xa0\xffK\xff\xc2\xa0: v\xe2\x80\x83\n",
                   b"A: b\nA: c\n", b"\xe2\x80: \xe2\x80\n", b"K:\n", b"\x85K\x85:\x85v\x85\n", b"\xed\xa0\x80: x\n"]
    for kind in raw_types:
        for hdr in raw_headers:
            for trail in (b"", b"tail\xff\n"):
                block = b"-----BEGIN " + kind + b"-----\n" + hdr + (b"\n" if hdr else b"") + b"YWJj\n-----END " + kind + b"-----\n" + trail
                vectors.append({"op": "decode_raw", "input_hex": (b"junk\xff\n" + block).hex()})
    for _ in range(300):
        kind = bytes(rng.choice(b"AB \x80\xff\xc2\xa0") for _ in range(rng.randrange(0, 6)))
        hdr = bytes(rng.choice(b"Ka: \n\x80\xff\xc2\xa0\xe2\x80\x83") for _ in range(rng.randrange(0, 14)))
        block = b"-----BEGIN " + kind + b"-----\n" + hdr + b"\nYQ==\n-----END " + kind + b"-----\n"
        vectors.append({"op": "decode_raw", "input_hex": block.hex()})
    payload = "".join(json.dumps(v, ensure_ascii=True) + "\n" for v in vectors)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--example", "pem_probe"], cwd=ROOT, check=True)
    probe = ROOT / "target/debug/examples" / ("pem_probe.exe" if os.name == "nt" else "pem_probe")
    outputs = []
    for command in [[str(probe)], ["go", "run", str(ROOT / "tools/pem_oracle.go")]]:
        process = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT, check=True)
        outputs.append([json.loads(line) for line in process.stdout.splitlines()])
    for index, (rust, go) in enumerate(zip(*outputs)):
        if rust != go:
            raise AssertionError(f"vector {index}: {vectors[index]!r}\nRust={rust!r}\nGo={go!r}")
    print(f"PEM Go conformance: {len(vectors)} vectors passed in {time.monotonic() - started:.3f}s")


if __name__ == "__main__":
    main()
