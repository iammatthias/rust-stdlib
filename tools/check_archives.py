#!/usr/bin/env python3
"""Bidirectional Go standard-library compression/archive interoperability.

Exercises independent DEFLATE implementations on empty, binary, repetitive,
random and multi-block payloads. Also validates wrappers and archive framing.
Run after the library is compiled; invokes only local Rust/Go toolchains.
"""
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def command(*args):
    subprocess.run(args, cwd=ROOT, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def main():
    command("cargo", "build", "--offline", "--locked", "--example", "archive_conformance")
    metadata = subprocess.check_output(["cargo", "metadata", "--offline", "--no-deps", "--format-version", "1"], cwd=ROOT)
    target = Path(json.loads(metadata)["target_directory"])
    rust = str(target / "debug" / "examples" / ("archive_conformance.exe" if os.name == "nt" else "archive_conformance"))
    randomizer = random.Random(1951)
    payloads = [b"", b"a", bytes(range(256)), b"repeat this string\n" * 10000,
                randomizer.randbytes(70000), (bytes(range(256)) * 300)]
    count = 0
    with tempfile.TemporaryDirectory(prefix="rust-stdlib-archives-") as directory:
        directory = Path(directory)
        go = str(directory / ("oracle.exe" if os.name == "nt" else "oracle"))
        command("go", "build", "-o", go, "tools/archive_oracle.go")
        for index, data in enumerate(payloads):
            raw, packed, decoded = (directory / name for name in ("raw", "packed", "decoded"))
            raw.write_bytes(data)
            for format in ("deflate", "zlib", "gzip", "tar", "zip"):
                for encoder, decoder in ((rust, go), (go, rust)):
                    command(encoder, "encode", format, str(raw), str(packed))
                    command(decoder, "decode", format, str(packed), str(decoded))
                    assert decoded.read_bytes() == data, (index, format, encoder)
                    count += 1
                if format != "zip":
                    command(rust, "encode-stream", format, str(raw), str(packed))
                    command(go, "decode", format, str(packed), str(decoded))
                    assert decoded.read_bytes() == data, (index, format, "stream")
                    count += 1
                if format == "deflate" and index == 3:
                    command(rust, "encode", format, str(raw), str(packed))
                    assert packed.stat().st_size < len(data) // 8, "LZ77 failed to reduce repeated input"
    print(f"archive conformance: {count} bidirectional Go/Rust cases passed")
    # Go-shaped tar/zip APIs: GNU/PAX/sparse/ZIP64/descriptor archives, writers and mutations.
    subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "check_archive_api.py")], cwd=ROOT, check=True)

if __name__ == "__main__":
    main()
