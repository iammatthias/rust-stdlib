#!/usr/bin/env python3
"""Compare LZW bitstreams, reset behavior and malformed decoding with Go."""
import json
import os
import pathlib
import random
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def invoke(command, vectors):
    payload = "".join(json.dumps(v, ensure_ascii=True) + "\n" for v in vectors)
    process = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT, check=True)
    return [json.loads(line) for line in process.stdout.splitlines()]


def main():
    started = time.monotonic()
    rng = random.Random(0x4C5A57)
    encode_vectors = []
    for order in ("LSB", "MSB"):
        for width in range(2, 9):
            alphabet = 1 << width
            samples = [
                b"",
                bytes(range(alphabet)),
                bytes((i % alphabet) for i in range(alphabet * 8)),
                bytes((i * 17 + i // 19) % alphabet for i in range(4096)),
                bytes(rng.randrange(alphabet) for _ in range(6000)),
            ]
            if width == 8:
                samples.append(bytes(rng.randrange(256) for _ in range(48_000)))
            for sample in samples:
                encode_vectors.append({"op": "encode", "order": order, "lit_width": width, "bytes": list(sample)})
    encode_vectors.extend([
        {"op": "encode", "order": "LSB", "lit_width": 0, "bytes": []},
        {"op": "encode", "order": "LSB", "lit_width": 1, "bytes": []},
        {"op": "encode", "order": "LSB", "lit_width": 9, "bytes": []},
        {"op": "encode", "order": "BAD", "lit_width": 8, "bytes": []},
        {"op": "encode", "order": "LSB", "lit_width": 2, "bytes": [0, 1, 4]},
    ])
    # Close, Close-twice, write-after-close and Reset/reuse of Writer, and Reader.Close.
    # Invalid widths too: Go (and Rust) report them on the first Write, Close or Read.
    lifecycle_vectors = []
    for order in ("LSB", "MSB"):
        for width in (0, 1, 9, 200, *range(2, 9)):
            alphabet = 1 << min(width, 8)
            for sample in (b"", bytes(range(alphabet)), bytes(rng.randrange(alphabet) for _ in range(700))):
                for op in ("encode_close", "encode_reset"):
                    lifecycle_vectors.append({"op": op, "order": order, "lit_width": width, "bytes": list(sample)})
                lifecycle_vectors.append({"op": "decode_close", "order": order, "lit_width": width,
                                          "bytes": list(sample)})
    encode_vectors.extend(lifecycle_vectors)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--example", "lzw_probe"], cwd=ROOT, check=True)
    probe = ROOT / "target/debug/examples" / ("lzw_probe.exe" if os.name == "nt" else "lzw_probe")
    rust_encoded = invoke([str(probe)], encode_vectors)
    go_encoded = invoke(["go", "run", str(ROOT / "tools/lzw_oracle.go")], encode_vectors)
    for i, (rust, go) in enumerate(zip(rust_encoded, go_encoded)):
        if rust != go:
            raise AssertionError(f"encode vector {i}: {encode_vectors[i]!r}\nRust={rust!r}\nGo={go!r}")

    decode_vectors = []
    for request, encoded, go in zip(encode_vectors, rust_encoded, go_encoded):
        if request["op"] == "encode" and request["order"] in ("LSB", "MSB") and 2 <= request["lit_width"] <= 8 and go["ok"]:
            decode_vectors.append({"op": "decode", "order": request["order"], "lit_width": request["lit_width"], "bytes": go["bytes"]})
            raw = bytes(go["bytes"])
            for cut in {0, max(0, len(raw) - 1), max(0, len(raw) - 2)}:
                decode_vectors.append({"op": "decode", "order": request["order"], "lit_width": request["lit_width"], "bytes": list(raw[:cut])})
    for order in ("LSB", "MSB"):
        for width in range(2, 9):
            for _ in range(90):
                raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 100)))
                decode_vectors.append({"op": "decode", "order": order, "lit_width": width, "bytes": list(raw)})
    for width in (0, 1, 9, 200):
        decode_vectors.append({"op": "decode", "order": "LSB", "lit_width": width, "bytes": [0]})
        decode_vectors.append({"op": "decode", "order": "MSB", "lit_width": width, "bytes": []})
    decode_vectors.extend([
        {"op": "decode", "order": "LSB", "lit_width": 2, "bytes": [0x3c]},
        {"op": "decode", "order": "MSB", "lit_width": 2, "bytes": [0x9c]},
    ])
    rust_decoded = invoke([str(probe)], decode_vectors)
    go_decoded = invoke(["go", "run", str(ROOT / "tools/lzw_oracle.go")], decode_vectors)
    for i, (rust, go) in enumerate(zip(rust_decoded, go_decoded)):
        if rust != go:
            raise AssertionError(f"decode vector {i}: {decode_vectors[i]!r}\nRust={rust!r}\nGo={go!r}")
    print(f"LZW Go conformance: {len(encode_vectors)} encode + {len(decode_vectors)} decode vectors passed in {time.monotonic() - started:.3f}s")


if __name__ == "__main__":
    main()
