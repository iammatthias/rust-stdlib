#!/usr/bin/env python3
"""Differentially check image/jpeg encoding, decoding and malformed input against Go.

Both encoders run the same random Encode requests (every image type, six
chroma ratios, odd sizes, non-zero origins, qualities from below 1 to above
100, and the generic color path forced through a type-hiding wrapper) and must
produce identical bytes. Both decoders then decode those encodings, Go's JPEG
test images (baseline, progressive, restart intervals, every subsampling ratio
including the non-standard ones, RGB, CMYK and YCCK) and thousands of
mutations; the complete decoded planes (padding included, hashed) and the
accept/reject decision with Go's error class and message must agree exactly.
DecodeConfig and the image.Decode registry are compared on the same inputs.
"""
import os
import pathlib
import random
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))

BPP = {"Gray": 1, "RGBA": 4, "NRGBA": 4, "RGBA64": 8, "Gray16": 2, "Alpha": 1, "CMYK": 4}


def tdiv(a, b):
    """Go's truncating integer division."""
    q = abs(a) // b
    return q if a >= 0 else -q


def chroma_size(x0, y0, x1, y1, ratio):
    w, h = x1 - x0, y1 - y0
    if ratio == 1:
        return tdiv(x1 + 1, 2) - tdiv(x0, 2), h
    if ratio == 2:
        return tdiv(x1 + 1, 2) - tdiv(x0, 2), tdiv(y1 + 1, 2) - tdiv(y0, 2)
    if ratio == 3:
        return w, tdiv(y1 + 1, 2) - tdiv(y0, 2)
    if ratio == 4:
        return tdiv(x1 + 3, 4) - tdiv(x0, 4), h
    if ratio == 5:
        return tdiv(x1 + 3, 4) - tdiv(x0, 4), tdiv(y1 + 1, 2) - tdiv(y0, 2)
    return w, h


def pixels(rng, n, style):
    if style == "noise":
        return bytes(rng.randrange(256) for _ in range(n))
    if style == "flat":
        return bytes([rng.randrange(256)]) * n
    if style == "ramp":
        base = rng.randrange(256)
        return bytes((base + i // 3) & 255 for i in range(n))
    # Mostly smooth with sparse noise, like a photograph.
    out = bytearray()
    v = rng.randrange(256)
    for _ in range(n):
        v = max(0, min(255, v + rng.choice([-2, -1, 0, 0, 1, 2]) + (rng.randrange(-40, 40) if rng.random() < 0.03 else 0)))
        out.append(v)
    return bytes(out)


def encode_spec(rng, w=None, h=None):
    kind = rng.choice(list(BPP) + ["YCbCr", "YCbCr", "NYCbCrA", "Paletted", "Uniform"])
    if w is None:
        w = rng.choice([0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 33, rng.randrange(1, 70)])
        h = rng.choice([0, 1, 2, 5, 8, 15, 16, 17, 31, 33, rng.randrange(1, 60)])
        if w == 0 or h == 0:
            if rng.random() < 0.8:
                w, h = max(w, 1), max(h, 1)
    x0, y0 = rng.choice([(0, 0), (0, 0), (rng.randrange(-9, 9), rng.randrange(-9, 9))])
    rect = f"{x0},{y0},{x0 + w},{y0 + h}"
    quality = rng.choice(["nil", "0", "1", "2", "10", "25", "49", "50", "51", "75", "90", "99", "100", "101",
                          "-5", str(rng.randrange(1, 101)), str(rng.randrange(1, 101))])
    style = rng.choice(["noise", "flat", "ramp", "photo", "photo", "photo"])
    hide = rng.choice([0, 0, 1])
    extra = "-"
    if kind == "Uniform":
        data = pixels(rng, 4, "noise")
        if rng.random() < 0.7:
            data = data[:3] + b"\xff"
    elif kind in ("YCbCr", "NYCbCrA"):
        ratio = rng.randrange(6)
        extra = str(ratio)
        cw, ch = chroma_size(x0, y0, x0 + w, y0 + h, ratio)
        data = pixels(rng, w * h, style) + pixels(rng, cw * ch, style) + pixels(rng, cw * ch, style)
        if kind == "NYCbCrA":
            data += pixels(rng, w * h, "noise")
    elif kind == "Paletted":
        n = rng.choice([1, 2, 5, 16, 256])
        extra = ",".join(pixels(rng, 4, "noise").hex() for _ in range(n))
        data = bytes(rng.randrange(n) for _ in range(w * h))
    else:
        data = pixels(rng, BPP[kind] * w * h, style)
        if kind in ("RGBA",):
            # RGBA is premultiplied; keep color <= alpha to stay realistic.
            data = bytearray(data)
            for i in range(0, len(data), 4):
                data[i + 3] = max(data[i], data[i + 1], data[i + 2], data[i + 3] if rng.random() < 0.5 else 255)
            data = bytes(data)
    return f"E {kind} {rect} {quality} {hide} {extra} {data.hex() or '-'}"


def fix_empty(spec):
    # An empty hex payload must still be a token; the probes treat "-" as empty.
    return spec


def mutate(rng, data):
    b = bytearray(data)
    kind = rng.randrange(12)
    if not b:
        return bytes(b)
    i = rng.randrange(len(b))
    if kind == 0:
        b[i] ^= 1 << rng.randrange(8)
    elif kind == 1:
        return bytes(b[:i])
    elif kind == 2:
        b.insert(i, rng.randrange(256))
    elif kind == 3:
        del b[i]
    elif kind == 4:
        b[i] = rng.choice([0x00, 0x01, 0xff, 0xc0, 0xc1, 0xc2, 0xc4, 0xd0, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdd, 0xee, 0xfe])
    elif kind == 5:
        j = rng.randrange(i, min(len(b), i + 40) + 1)
        b[j:j] = b[i:j]
    elif kind == 6:
        for _ in range(rng.randrange(2, 6)):
            b[rng.randrange(len(b))] = rng.randrange(256)
    elif kind == 7:
        # Header fields (SOF sampling factors, dimensions, table ids) decide most
        # accept/reject outcomes, so aim at the first 700 bytes.
        k = rng.randrange(min(len(b), 700))
        b[k] = rng.randrange(256)
    elif kind == 8:
        # Rewrite a sampling-factor byte after an SOF marker.
        for m in range(len(b) - 12):
            if b[m] == 0xFF and b[m + 1] in (0xC0, 0xC1, 0xC2):
                nc = b[m + 9]
                if nc in (1, 3, 4):
                    c = rng.randrange(nc)
                    b[m + 11 + 3 * c] = rng.choice([0x11, 0x12, 0x21, 0x22, 0x14, 0x41, 0x42, 0x24, 0x44, 0x31, 0x13, 0x00, 0x51, 0x11, 0x22])
                break
    elif kind >= 10:
        # Adobe APP14 transform (CMYK versus YCCK, RGB versus YCbCr) or its
        # removal, and JFIF/Adobe marker lengths.
        at = bytes(b).find(b"Adobe")
        if at >= 0 and at + 11 < len(b) and kind == 10:
            b[at + 11] = rng.choice([0, 1, 2, 3])
        elif at >= 0 and kind == 11:
            b[at - 4:at + 12] = b"\xff\xfe\x00\x0e" + bytes(12) if at >= 4 else b[at - 4:at + 12]
        else:
            b[min(len(b) - 1, 2 + rng.randrange(40))] ^= 1 << rng.randrange(8)
    else:
        # Stuff or drop a byte in the entropy-coded data.
        k = rng.randrange(len(b))
        b[k:k] = b"\xff\x00" if rng.random() < 0.5 else b"\xff"
    return bytes(b)


def run(command, lines, label):
    payload = "".join(line + "\n" for line in lines)
    process = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT)
    if process.returncode:
        raise RuntimeError(f"{label} failed:\n{process.stderr[-2000:]}")
    out = process.stdout.splitlines()
    if len(out) != len(lines):
        raise AssertionError(f"{label} returned {len(out)} records for {len(lines)} requests")
    return out


def compare(requests, rust, golang, label):
    skipped = 0
    for i, (actual, expected) in enumerate(zip(rust, golang)):
        if expected == "panic":
            skipped += 1
            continue
        if actual != expected:
            raise AssertionError(f"{label} request {i}: {requests[i][:300]}\nRust={actual[:600]}\nGo  ={expected[:600]}")
    return skipped


def main():
    started = time.monotonic()
    rng = random.Random(0x4A504547)
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "jpeg_probe"],
                   cwd=ROOT, check=True)
    probe = [str(TARGET / "debug/examples" / ("jpeg_probe.exe" if os.name == "nt" else "jpeg_probe"))]
    go = ["go", "run", str(ROOT / "tools/jpeg_oracle.go")]

    specs = [encode_spec(rng) for _ in range(1500)]
    # Every type at the interesting sizes and every quality in one block, so
    # the quantization-table scaling is covered completely.
    for q in [-1, 0, 1, 2, 3, 24, 25, 26, 49, 50, 51, 74, 75, 76, 98, 99, 100, 101, 1000]:
        for _ in range(3):
            spec = encode_spec(rng, rng.choice([8, 16, 17, 33]), rng.choice([8, 16, 15, 31]))
            f = spec.split()
            f[4] = str(q)
            specs.append(" ".join(f))
    for _ in range(100):
        specs.append(encode_spec(rng, 1, 1))
    specs.append("E Gray 0,0,65535,1 nil 0 - " + ("00" * 65535))
    specs.append("E Gray 0,0,65536,1 nil 0 - " + ("00" * 65536))
    specs.append("E Uniform 0,0,1,1 nil 0 - 10203040")
    rust_enc = run(probe, specs, "Rust JPEG encoder")
    go_enc = run(go, specs, "Go JPEG encoder")
    panics = compare(specs, rust_enc, go_enc, "encode")
    encoded = [bytes.fromhex(g) for g in go_enc if g not in ("panic",) and not g.startswith("err")]
    if len(encoded) < len(specs) * 0.8:
        raise AssertionError(f"only {len(encoded)} of {len(specs)} encode requests succeeded")

    goroot = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True, check=True).stdout.strip()
    suite = [p.read_bytes() for p in sorted((pathlib.Path(goroot) / "src/image/testdata").glob("*.jpeg"))]
    if len(suite) < 20:
        raise AssertionError("Go JPEG testdata not found")
    # Go's TestPaddedRSTMarker image (golang.org/issue/28717).
    suite.append((ROOT / "tests/fixtures/jpeg/padded_rst.jpeg").read_bytes())
    small = [e for e in encoded if len(e) < 3000]
    corpus = encoded + suite
    mutants = []
    seeds = suite + small
    for _ in range(4000):
        mutants.append(mutate(rng, rng.choice(seeds)))
    for _ in range(500):
        mutants.append(mutate(rng, mutate(rng, rng.choice(seeds))))
    files = corpus + mutants
    # D: decode (hashed planes), C: DecodeConfig, R: image.Decode registry.
    requests = [f"{kind} {data.hex()}" for data in files for kind in ("D", "C", "R")]
    rust = run(probe, requests, "Rust JPEG decoder")
    golang = run(go, requests, "Go JPEG decoder")
    skipped = compare(requests, rust, golang, "decode")
    accepted = sum(line.startswith("ok ") for line in golang[0::3])
    mutated_accepted = sum(line.startswith("ok ") for line in golang[3 * len(corpus)::3])
    classes = {}
    for line in golang[0::3]:
        key = " ".join(line.split()[:2]) if line.startswith("err") else "ok"
        classes[key] = classes.get(key, 0) + 1
    print(f"JPEG Go differential: {len(specs)} encode requests ({len(encoded)} byte-identical JPEGs, "
          f"{panics} Go panics skipped), {len(suite)} Go testdata + {len(encoded)} Go-encoded files, "
          f"{len(mutants)} mutations ({mutated_accepted} accepted); {len(requests)} Decode/DecodeConfig/"
          f"image.Decode vectors ({accepted} files accepted, {skipped} skipped) passed "
          f"in {time.monotonic() - started:.1f}s")
    if os.environ.get("JPEG_CHECK_VERBOSE"):
        print(classes)


if __name__ == "__main__":
    main()
