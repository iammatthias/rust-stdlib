#!/usr/bin/env python3
"""Differentially check image/png encoding, decoding and malformed input against Go.

Both encoders encode the same random images; both decoders decode both
encodings, Python-built PNGs covering every color type, bit depth, filter and
Adam7 interlacing, and structured mutations. Decoded pixels are compared as
exact RGBA64 values, and accept/reject decisions must agree.
"""
import os
import pathlib
import random
import struct
import subprocess
import time
import zlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIGNATURE = b"\x89PNG\r\n\x1a\n"
TYPES = {"RGBA": 4, "NRGBA": 4, "RGBA64": 8, "NRGBA64": 8, "Gray": 1, "Gray16": 2,
         "Alpha": 1, "Alpha16": 2, "Paletted": 1, "Rect": 0}
COLOR_BYTES = {"RGBA": 4, "NRGBA": 4, "RGBA64": 8, "NRGBA64": 8, "Gray": 1, "Gray16": 2,
               "Alpha": 1, "Alpha16": 2}
LEVELS = (0, -1, -2, -3)
# (color type, bit depth) combinations defined by the PNG specification.
COMBOS = [(0, 1), (0, 2), (0, 4), (0, 8), (0, 16), (2, 8), (2, 16), (3, 1), (3, 2), (3, 4),
          (3, 8), (4, 8), (4, 16), (6, 8), (6, 16)]
CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
ADAM7 = [(8, 8, 0, 0), (8, 8, 4, 0), (4, 8, 0, 4), (4, 4, 2, 0), (2, 4, 0, 2), (2, 2, 1, 0), (1, 2, 0, 1)]


def chunk(kind, data):
    body = kind + data
    return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))


def split_chunks(png):
    """Return [(kind, data)] for a well-formed PNG; trailing bytes are dropped."""
    out, at = [], 8
    while at + 12 <= len(png):
        (n,) = struct.unpack(">I", png[at:at + 4])
        out.append((png[at + 4:at + 8], png[at + 8:at + 8 + n]))
        at += 12 + n
    return out


def join(chunks):
    return SIGNATURE + b"".join(chunk(k, d) for k, d in chunks)


def random_color(rng, opaque):
    tag = rng.choice(list(COLOR_BYTES))
    data = bytearray(rng.randrange(256) for _ in range(COLOR_BYTES[tag]))
    if opaque and tag in ("RGBA", "NRGBA"):
        data[3] = 0xFF
    if opaque and tag in ("RGBA64", "NRGBA64"):
        data[6:8] = b"\xff\xff"
    if opaque and tag.startswith("Alpha"):
        data[:] = b"\xff" * len(data)
    return f"{tag}:{data.hex()}"


def random_spec(rng, kind):
    w = rng.choice([1, 1, 2, 3, 5, 7, 8, 9, 13, 16, 17, 31, 33, rng.randrange(1, 70)])
    h = rng.choice([1, 1, 2, 3, 4, 7, 9, 16, rng.randrange(1, 40)])
    if rng.random() < 0.03:
        w, h = rng.choice([(257, 3), (3, 300), (1, 1000), (600, 1)])
    x0, y0 = rng.choice([(0, 0), (0, 0), (rng.randrange(-50, 50), rng.randrange(-50, 50))])
    rect = (x0, y0, x0 + w, y0 + h)
    bpp = TYPES[kind]
    pix = bytearray(rng.randrange(256) for _ in range(bpp * w * h))
    opaque = rng.random() < 0.35
    if opaque and kind in ("RGBA", "NRGBA"):
        pix[3::4] = b"\xff" * (w * h)
    if opaque and kind in ("RGBA64", "NRGBA64"):
        for i in range(w * h):
            pix[8 * i + 6:8 * i + 8] = b"\xff\xff"
    if opaque and kind.startswith("Alpha"):
        pix[:] = b"\xff" * len(pix)
    palette = ""
    if kind == "Paletted":
        n = rng.choice([1, 2, 3, 4, 5, 15, 16, 17, 200, 256, rng.randrange(1, 257)])
        if rng.random() < 0.03:
            n = rng.choice([0, 257, 300])
        palette = ",".join(random_color(rng, opaque) for _ in range(n))
        # Mostly in-range indexes, with some beyond the palette and bit depth.
        limit = max(1, n) if rng.random() < 0.8 else 256
        pix = bytearray(rng.randrange(limit) for _ in range(w * h))
    sub = ""
    if kind != "Rect" and rng.random() < 0.2:
        sx0, sy0 = rng.randrange(x0 - 3, x0 + w), rng.randrange(y0 - 3, y0 + h)
        sub = f"{sx0},{sy0},{sx0 + rng.randrange(0, w + 3)},{sy0 + rng.randrange(0, h + 3)}"
    level = rng.choice(LEVELS)
    return f"{kind};{','.join(map(str, rect))};{level};{pix.hex()};{palette};{sub}"


def structured_specs(rng):
    """Compressible images (QR-like, gradients, flat, noise) at every level, large
    enough for several blocks and several IDAT chunks."""
    specs = []
    for level in LEVELS:
        # QR-like paletted: 29 random modules per side, scaled.
        for scale, n in ((1, 29), (4, 29), (8, 29), (3, 57), (2, 177)):
            mods = [[rng.random() < 0.5 for _ in range(n)] for _ in range(n)]
            size = (n + 4) * scale
            pix = bytearray()
            for y in range(size):
                for x in range(size):
                    mx, my = x // scale - 2, y // scale - 2
                    pix.append(1 if 0 <= mx < n and 0 <= my < n and mods[my][mx] else 0)
            specs.append(f"Paletted;0,0,{size},{size};{level};{pix.hex()};Gray:ff,Gray:00;")
        w, h = 150, 120
        # Smooth gradients exercise the filter heuristic.
        for kind in ("RGBA", "NRGBA", "RGBA64", "NRGBA64", "Gray", "Gray16"):
            bpp = TYPES[kind]
            pix = bytearray()
            for y in range(h):
                for x in range(w):
                    for c in range(bpp):
                        pix.append((x * (c + 1) + y * 2 + (c * 40)) & 255)
            specs.append(f"{kind};0,0,{w},{h};{level};{pix.hex()};;")
        # Flat and noisy RGBA; noisy data spans several IDAT chunks.
        specs.append(f"RGBA;0,0,{w},{h};{level};{(b'RGBA' * (w * h)).hex()};;")
        noise = bytes(rng.randrange(256) for _ in range(4 * 200 * 150))
        specs.append(f"NRGBA;0,0,200,150;{level};{noise.hex()};;")
        words = [b"\x00\x10\x20\xff", b"\xff\x00\x00\xff", b"\x10\x20\x30\x80"]
        mixed = b"".join(rng.choice(words) for _ in range(200 * 150))
        specs.append(f"NRGBA;0,0,200,150;{level};{mixed.hex()};;")
        # Paletted 256 colours with runs.
        runs = bytearray()
        while len(runs) < 160 * 160:
            runs += bytes([rng.randrange(256)]) * rng.randrange(1, 40)
        runs = runs[:160 * 160]
        pal = ",".join(f"RGBA:{i:02x}{(i * 7) & 255:02x}{(i * 13) & 255:02x}ff" for i in range(256))
        specs.append(f"Paletted;0,0,160,160;{level};{runs.hex()};{pal};")
    return specs


def pass_sizes(w, h, interlaced):
    if not interlaced:
        return [(w, h)]
    return [((w - xo + xf - 1) // xf, (h - yo + yf - 1) // yf) for xf, yf, xo, yo in ADAM7]


def synthetic(rng):
    """A PNG built directly from random filtered scanlines."""
    ctype, depth = rng.choice(COMBOS)
    w = rng.choice([1, 2, 3, 5, 7, 8, 9, 15, 17, rng.randrange(1, 40)])
    h = rng.choice([1, 2, 3, 5, 8, 9, rng.randrange(1, 30)])
    interlaced = rng.random() < 0.5
    bits = depth * CHANNELS[ctype]
    raw = bytearray()
    samples = []
    plain = rng.random() < 0.3
    for pw, ph in pass_sizes(w, h, interlaced):
        if pw == 0 or ph == 0:
            continue
        for _ in range(ph):
            row = bytes(rng.randrange(256) for _ in range((bits * pw + 7) // 8))
            samples.append(row)
            raw.append(0 if plain else rng.randrange(5))
            raw += row
    if rng.random() < 0.02:
        raw[rng.randrange(len(raw))] = rng.randrange(5, 256)  # likely a bad filter byte
    chunks = [(b"IHDR", struct.pack(">IIBBBBB", w, h, depth, ctype, 0, 0, int(interlaced)))]
    if rng.random() < 0.3:
        chunks.append((b"tEXt", b"Comment\x00" + bytes(rng.randrange(32, 127) for _ in range(rng.randrange(20)))))
    if ctype == 3:
        n = rng.randrange(1, (1 << depth) + 1)
        chunks.append((b"PLTE", bytes(rng.randrange(256) for _ in range(3 * n))))
        if rng.random() < 0.5:
            chunks.append((b"tRNS", bytes(rng.randrange(256) for _ in range(rng.randrange(0, min(256, n + 4) + 1)))))
    elif ctype in (2, 6) and rng.random() < 0.2:
        chunks.append((b"PLTE", bytes(rng.randrange(256) for _ in range(3 * rng.randrange(1, 257)))))
    if ctype in (0, 2) and rng.random() < 0.5:
        size = 2 if ctype == 0 else 6
        if plain and samples and rng.random() < 0.7:
            # Choose a value that occurs in the image so transparency is exercised.
            row = rng.choice(samples)
            if depth < 8:
                v = (row[0] >> (8 - depth)) & ((1 << depth) - 1)
                value = struct.pack(">H", v)
            elif depth == 8:
                value = b"".join(struct.pack(">H", b) for b in row[:size // 2])
            else:
                value = row[:size]
            trns = value if len(value) == size else bytes(size)
        else:
            trns = bytes(rng.randrange(256) for _ in range(size))
        chunks.append((b"tRNS", trns))
    data = zlib.compress(bytes(raw), rng.choice([0, 1, 6, 9]))
    pieces = []
    while data:
        n = rng.randrange(1, len(data) + 1) if rng.random() < 0.5 else len(data)
        pieces.append(data[:n])
        data = data[n:]
        if rng.random() < 0.1:
            pieces.append(b"")
    chunks += [(b"IDAT", p) for p in pieces]
    if rng.random() < 0.2:
        chunks.append((b"zzZz", b"ancillary after data"))
    chunks.append((b"IEND", b""))
    return join(chunks)


def fix_ihdr(chunks, **fields):
    w, h, depth, ctype, comp, filt, inter = struct.unpack(">IIBBBBB", chunks[0][1])
    values = dict(w=w, h=h, depth=depth, ctype=ctype, comp=comp, filt=filt, inter=inter)
    values.update(fields)
    chunks[0] = (b"IHDR", struct.pack(">IIBBBBB", *(values[k] for k in
                                                     ("w", "h", "depth", "ctype", "comp", "filt", "inter"))))
    return join(chunks)


def mutate(rng, png):
    chunks = split_chunks(png)
    kind = rng.randrange(14)
    if kind == 0:  # raw byte flip; CRCs normally catch it
        b = bytearray(png)
        b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        return bytes(b)
    if kind == 1:  # flip inside one chunk and repair its CRC
        i = rng.randrange(len(chunks))
        k, d = chunks[i]
        if d:
            d = bytearray(d)
            d[rng.randrange(len(d))] ^= 1 << rng.randrange(8)
            chunks[i] = (k, bytes(d))
        return join(chunks)
    if kind == 2:  # truncation at any byte
        return png[:rng.randrange(len(png))]
    if kind == 3:  # truncation at a chunk boundary
        return join(chunks[:rng.randrange(len(chunks))])
    if kind == 4:  # drop a chunk
        del chunks[rng.randrange(len(chunks))]
        return join(chunks)
    if kind == 5:  # duplicate a non-IDAT chunk (IDAT runs are a documented difference)
        i = rng.randrange(len(chunks))
        if chunks[i][0] != b"IDAT":
            chunks.insert(i, chunks[i])
        return join(chunks)
    if kind == 6:  # swap neighbours
        i = rng.randrange(max(1, len(chunks) - 1))
        chunks[i:i + 2] = chunks[i:i + 2][::-1]
        return join(chunks)
    if kind == 7:  # insert an unknown chunk, sometimes with a bad CRC
        name = bytes(rng.choice(b"abcdABCD") for _ in range(4))
        piece = chunk(name, bytes(rng.randrange(256) for _ in range(rng.randrange(10))))
        if rng.random() < 0.3:
            piece = piece[:-1] + bytes([piece[-1] ^ 1])
        i = rng.randrange(len(chunks) + 1)
        return SIGNATURE + b"".join(chunk(k, d) for k, d in chunks[:i]) + piece + \
            b"".join(chunk(k, d) for k, d in chunks[i:])
    if kind == 8:  # bytes after IEND are ignored
        return png + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 20)))
    if kind == 9:  # IHDR field edits
        field = rng.choice(["depth", "ctype", "inter", "comp", "filt", "w", "h"])
        _, _, depth, ctype, *_ = struct.unpack(">IIBBBBB", chunks[0][1])
        value = {
            "depth": rng.choice([0, 1, 2, 3, 4, 8, 16, 32]),
            "ctype": rng.randrange(8),
            "inter": rng.choice([0, 1, 2]),
            "comp": 1,
            "filt": 1,
            "w": rng.choice([0, 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 4097, 1 << 20, rng.randrange(1, 64)]),
            "h": rng.choice([0, 1, 2, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 4097, 1 << 20, rng.randrange(1, 64)]),
        }[field]
        if chunks and chunks[0][0] == b"IHDR":
            return fix_ihdr(chunks, **{field: value})
        return png
    if kind == 10:  # IEND with data
        return join([c for c in chunks if c[0] != b"IEND"] + [(b"IEND", b"x")])
    if kind == 11:  # zero-length IDATs inside the run and an ignored later run
        out = []
        for k, d in chunks:
            if k == b"IDAT" and rng.random() < 0.5:
                out.append((b"IDAT", b""))
            out.append((k, d))
            if k == b"IDAT" and rng.random() < 0.3:
                out.append((b"IDAT", b""))
        if rng.random() < 0.5:
            at = next((i for i, c in enumerate(out) if c[0] == b"IEND"), len(out))
            out[at:at] = [(b"teXt", b"x"), (b"IDAT", b"garbage after the image")]
        return join(out)
    if kind == 12:  # palette and transparency length/class mismatches
        i = rng.randrange(len(chunks) + 1)
        kind_name = rng.choice([b"PLTE", b"tRNS"])
        size = rng.choice([0, 1, 2, 3, 6, 9, 255, 256, 257, 768, 771])
        chunks.insert(min(i, len(chunks)), (kind_name, bytes(rng.randrange(256) for _ in range(size))))
        return join(chunks)
    # zlib framing edits on the concatenated IDAT payload
    data = b"".join(d for k, d in chunks if k == b"IDAT")
    if len(data) < 6:
        return png
    try:
        raw = zlib.decompress(data)
    except zlib.error:
        return png
    choice = rng.randrange(6)
    if choice == 0:
        data = data[:-4] + bytes([data[-4] ^ 1]) + data[-3:]  # bad Adler-32
    elif choice == 1:
        data = bytes([0x78, 0xBB]) + data[2:]  # FDICT set, valid FCHECK
    elif choice == 2:
        data = bytes([0x88, 0x1D]) + data[2:]  # CINFO > 7
    elif choice == 3:
        data = zlib.compress(raw[:-1])  # missing pixel data
    elif choice == 4:
        data = zlib.compress(raw + b"\x00" * rng.randrange(1, 9))  # too much pixel data
    else:
        b = bytearray(raw)
        b[0] = rng.randrange(5, 256)  # bad filter type on the first row
        data = zlib.compress(bytes(b))
    out, done = [], False
    for k, d in chunks:
        if k == b"IDAT":
            if not done:
                out.append((b"IDAT", data))
                done = True
        else:
            out.append((k, d))
    return join(out)


def run(command, lines, label):
    payload = "".join(line + "\n" for line in lines)
    process = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT)
    if process.returncode:
        raise RuntimeError(f"{label} failed:\n{process.stderr}")
    out = process.stdout.splitlines()
    if len(out) != len(lines):
        raise AssertionError(f"{label} returned {len(out)} records for {len(lines)} requests")
    return out


def ihdr_and_palette(png):
    chunks = dict((k, d) for k, d in split_chunks(png) if k in (b"IHDR", b"PLTE", b"tRNS"))
    return chunks.get(b"IHDR", b"")[8:13], chunks.get(b"PLTE"), chunks.get(b"tRNS")


def corruption_requests(pngs):
    """Flip bits at every byte of the compressed data (zlib header, deflate stream and
    Adler-32), repairing the chunk CRC so the error comes from zlib, not from PNG."""
    out = []
    for png in pngs:
        chunks = split_chunks(png)
        idat = [i for i, (k, _) in enumerate(chunks) if k == b"IDAT"]
        if not idat:
            continue
        first = idat[0]
        data = b"".join(chunks[i][1] for i in idat)
        rest = [c for i, c in enumerate(chunks) if i not in idat]
        for at in range(len(data)):
            for mask in (0x01, 0x80, 0xFF):
                bad = bytearray(data)
                bad[at] ^= mask
                body = rest[:first] + [(b"IDAT", bytes(bad))] + rest[first:]
                out.append(f"TD {join(body).hex()}")
        # Compressed data shorter than a zlib header, followed by IEND.
        for n in (0, 1):
            body = rest[:first] + [(b"IDAT", data[:n])] + rest[first:]
            out.append(f"TD {join(body).hex()}")
    return out


def check_truncations(rng, probe, go, encoded, synthetic_pngs, suite):
    """Cut small PNGs at every byte offset; Decode, DecodeConfig, image.Decode and
    image.DecodeConfig must fail with the same error text as Go (io.EOF becomes
    "unexpected EOF", a short pixel stream is a FormatError, and so on)."""
    small = [p for p in encoded if len(p) <= 700][:12]
    small += [p for p in synthetic_pngs if len(p) <= 260][:25]
    small += [p for p in suite if len(p) <= 400][:12]
    if len(small) < 20:
        raise AssertionError("no small PNGs for truncation vectors")
    requests = []
    for png in small:
        for cut in range(len(png)):
            for kind in ("TD", "TC", "TI", "TJ"):
                requests.append(f"{kind} {png[:cut].hex()}")
    requests.append("TJ " + SIGNATURE.hex())
    requests += corruption_requests(small)
    rust = run([probe], requests, "Rust PNG truncations")
    golang = run(go, requests, "Go PNG truncations")
    for request, actual, expected in zip(requests, rust, golang):
        if actual != expected:
            raise AssertionError(f"truncation {request[:2]} at {len(request) // 2 - 1} bytes: "
                                 f"{request[3:300]}\nRust={actual[:200]}\nGo={expected[:200]}")
    return len(requests)


DEVIATION = "err png: invalid format: too much pixel data"
# A 1x1 gray PNG whose only IDAT chunk appears twice (farfield's repro).
DUP_IDAT = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108000000003a7e9b55"
    "0000000f49444154789c000200fdff0280030000860083a567de54"
    "0000000f49444154789c000200fdff0280030000860083a567de54"
    "0000000049454e44ae426082")


def trailing_idat_vectors(rng, pngs):
    """IDAT chunks after the one the zlib stream ends in. Go never reads them while
    decoding and its chunk loop skips them, so they may hold anything; it still reads
    them, so a bad CRC or a truncation there is reported with Go's error. Returns
    (png, deviates): deviates marks the one recorded difference, junk inside the
    stream-ending chunk, which Go accepts when the rest of the chunk fits its 4 KiB
    read-ahead and the port always rejects."""
    out = [(DUP_IDAT, False)]
    for png in pngs:
        chunks = split_chunks(png)
        idat = [i for i, (k, _) in enumerate(chunks) if k == b"IDAT"]
        if not idat:
            continue
        rest = [c for i, c in enumerate(chunks) if i not in idat]
        head, tail = rest[:idat[0]], rest[idat[0]:]
        data = b"".join(chunks[i][1] for i in idat)
        raw = zlib.decompress(data)

        def build(run, end=tail):
            return join(head) + b"".join(run) + b"".join(chunk(k, d) for k, d in end)

        def bad_crc(piece):
            return piece[:-1] + bytes([piece[-1] ^ 1])

        garbage = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 40)))
        at = rng.randrange(1, len(data))
        split = [chunk(b"IDAT", data[:at]), chunk(b"IDAT", data[at:])]
        before_adler = [chunk(b"IDAT", data[:-4]), chunk(b"IDAT", data[-4:])]
        whole, extra, empty = chunk(b"IDAT", data), chunk(b"IDAT", garbage), chunk(b"IDAT", b"")
        too_long = chunk(b"IDAT", zlib.compress(raw + bytes(rng.randrange(1, 9))))
        bad_adler = chunk(b"IDAT", data[:-4] + bytes([data[-4] ^ 1]) + data[-3:])
        accepted = [[whole, whole], [whole, extra], [whole, empty, extra], [whole, empty, empty],
                    split + [extra], [split[0], empty, split[1], extra], before_adler + [extra]]
        rejected = [[whole, bad_crc(extra)], [whole, chunk(b"IDAT", b"ok"), bad_crc(extra)],
                    [too_long, bad_crc(extra)], [bad_adler, bad_crc(extra)],
                    [bad_crc(split[0]), split[1]], [bad_crc(before_adler[0]), before_adler[1]],
                    [bad_crc(whole), extra]]
        out += [(build(run), False) for run in accepted + rejected]
        cut = build([whole, extra], end=[])
        out += [(cut[:-6], False), (cut[:-2], False), (cut, False), (cut[:-len(extra) + 8], False)]
        out.append((build([chunk(b"IDAT", data + bytes(4096))]), False))
        if len(data) + 4 <= 4096:
            out.append((build([chunk(b"IDAT", data + b"junk")]), True))
    return out


def check_trailing_idats(rng, probe, go, pngs):
    vectors = trailing_idat_vectors(rng, pngs)
    requests = [f"{kind} {png.hex()}" for png, _ in vectors for kind in ("TD", "D")]
    rust = run([probe], requests, "Rust PNG trailing IDAT")
    golang = run(go, requests, "Go PNG trailing IDAT")
    for i, (png, deviates) in enumerate(vectors):
        text, pixels = rust[2 * i], rust[2 * i + 1]
        go_text, go_pixels = golang[2 * i], golang[2 * i + 1]
        if deviates:
            if (text, go_text) != (DEVIATION, "ok") or pixels != "err" or not go_pixels.startswith("ok "):
                raise AssertionError(f"junk inside the stream-ending IDAT: {png.hex()[:300]}\n"
                                     f"Rust={text[:200]}\nGo={go_text[:200]}")
        elif text != go_text or pixels != go_pixels:
            raise AssertionError(f"trailing IDAT vector {i}: {png.hex()[:300]}\n"
                                 f"Rust={text[:200]} {pixels[:200]}\nGo={go_text[:200]} {go_pixels[:200]}")
    return len(vectors), sum(deviates for _, deviates in vectors)


def main():
    started = time.monotonic()
    rng = random.Random(0x504E47)
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "png_probe"],
                   cwd=ROOT, check=True)
    probe = str(ROOT / "target/debug/examples" / ("png_probe.exe" if os.name == "nt" else "png_probe"))
    go = ["go", "run", str(ROOT / "tools/png_oracle.go")]

    specs = [random_spec(rng, kind) for kind in TYPES for _ in range(40)] + structured_specs(rng)
    rust_png = run([probe], ["E " + s for s in specs], "Rust PNG encoder")
    go_png = run(go, ["E " + s for s in specs], "Go PNG encoder")
    encoded = []
    partial_writes = 0
    for spec, r, g in zip(specs, rust_png, go_png):
        if (r.startswith("err")) != (g.startswith("err")):
            raise AssertionError(f"encode accept/reject differs for {spec[:200]}\nRust={r[:80]}\nGo={g[:80]}")
        if g.startswith("err"):
            # The bytes written before the failure (Go has written the
            # signature and IHDR when a palette is bad) must be the same.
            if r != g:
                raise AssertionError(f"partial write differs for {spec[:200]}\nRust={r[:120]}\nGo={g[:120]}")
            partial_writes += 1
            continue
        rb, gb = bytes.fromhex(r), bytes.fromhex(g)
        if ihdr_and_palette(rb) != ihdr_and_palette(gb):
            raise AssertionError(f"IHDR/PLTE/tRNS differ for {spec[:200]}:\n{ihdr_and_palette(rb)}\n{ihdr_and_palette(gb)}")
        if rb != gb:
            raise AssertionError(f"PNG bytes differ for {spec[:200]}:\nRust={len(rb)} bytes\nGo={len(gb)} bytes")
        encoded.append((spec, rb, gb))

    synthetic_pngs = [synthetic(rng) for _ in range(400)]
    # Go's own PNG test corpus (PngSuite plus its invalid-* regressions).
    goroot = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True, check=True).stdout.strip()
    testdata = pathlib.Path(goroot) / "src/image/png/testdata"
    suite = [p.read_bytes() for p in sorted(testdata.glob("*.png")) + sorted(testdata.glob("pngsuite/*.png"))
             if p.stat().st_size < 64 * 1024]
    if len(suite) < 30:
        raise AssertionError(f"Go PNG testdata not found under {testdata}")
    synthetic_pngs += suite
    corpus = [g for _, _, g in encoded] + [r for _, r, _ in encoded] + synthetic_pngs
    mutations = [mutate(rng, rng.choice(corpus)) for _ in range(4000)]

    requests = []
    for _, r, g in encoded:
        requests += ["D " + g.hex(), "D " + r.hex()]
    requests += ["D " + p.hex() for p in synthetic_pngs + mutations]
    requests += ["C " + p.hex() for p in [g for _, _, g in encoded] + synthetic_pngs + mutations]
    # image.Decode reports the format name with an error (png, gif or neither).
    others = [b"GIF89a" + bytes(5), b"GIF87a", b"", b"\x89PNG", b"junk", b"\x89PNG\r\n\x1a\n"]
    requests += ["I " + p.hex() for p in [g for _, _, g in encoded][:50] + synthetic_pngs + mutations + others]
    rust = run([probe], requests, "Rust PNG decoder")
    golang = run(go, requests, "Go PNG decoder")
    for i, (actual, expected) in enumerate(zip(rust, golang)):
        if actual != expected:
            raise AssertionError(f"request {i}: {requests[i][:300]}\nRust={actual[:300]}\nGo={expected[:300]}")
    # Rust-encoded files must decode (in Go) to the same pixels as Go-encoded files.
    for i, (spec, _, _) in enumerate(encoded):
        if golang[2 * i] != golang[2 * i + 1]:
            raise AssertionError(f"Go decodes Rust and Go encodings differently for {spec[:200]}")
        if not golang[2 * i].startswith("ok "):
            raise AssertionError(f"Go rejected an encoding of {spec[:200]}")
    decoded = sum(line.startswith("ok ") for line in golang)
    truncated = check_truncations(rng, probe, go, [g for _, _, g in encoded], synthetic_pngs, suite)
    small = [p for p in [g for _, _, g in encoded] + synthetic_pngs if len(p) <= 3000]
    trailing, deviating = check_trailing_idats(rng, probe, go, small[:40])
    print(f"PNG Go differential: {len(specs)} encode specs ({len(encoded)} encodable), "
          f"{len(synthetic_pngs) - len(suite)} synthetic + {len(suite)} Go testdata files, {len(mutations)} mutations, "
          f"{len(requests)} decode/config/image.Decode vectors ({decoded} accepted), "
          f"{truncated} truncation and corruption vectors with identical error text, "
          f"{trailing} trailing-IDAT vectors ({deviating} with the recorded junk-inside-chunk difference), "
          f"{partial_writes} failed encodes with identical partial output, passed "
          f"in {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
