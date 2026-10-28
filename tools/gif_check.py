#!/usr/bin/env python3
"""Differentially check image/gif encoding, decoding and malformed input against Go.

Both encoders run the same random EncodeAll and Encode requests and must
produce identical bytes. Both decoders then decode those encodings, Go's GIF
test images, Python-built GIFs covering every block type, interlacing,
transparency, loop counts, LZW edge cases and sub-block layouts, and thousands
of mutations. DecodeAll, Decode and DecodeConfig results (frame bounds,
palettes, pixel indexes, delays, disposal, loop count, background index and
screen size) and accept/reject decisions must agree exactly.
"""
import os
import pathlib
import random
import struct
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
COLOR_BYTES = {"RGBA": 4, "NRGBA": 4, "RGBA64": 8, "NRGBA64": 8, "Gray": 1, "Gray16": 2,
               "Alpha": 1, "Alpha16": 2}
BPP = {"RGBA": 4, "NRGBA": 4, "RGBA64": 8, "NRGBA64": 8, "Gray": 1, "Gray16": 2,
       "Alpha": 1, "Alpha16": 2, "Paletted": 1}


# ---------------------------------------------------------------- LZW / GIF

def lzw_encode(data, lit, eof=True, clears=0.0, rng=None):
    """Go's compress/lzw LSB writer, optionally without the end code and with
    extra clear codes inserted at random points."""
    out = bytearray()
    state = {"bits": 0, "nbits": 0, "width": lit + 1, "hi": (1 << lit) + 1,
             "overflow": 1 << (lit + 1), "table": {}}
    clear = 1 << lit

    def write(code):
        state["bits"] |= code << state["nbits"]
        state["nbits"] += state["width"]
        while state["nbits"] >= 8:
            out.append(state["bits"] & 0xFF)
            state["bits"] >>= 8
            state["nbits"] -= 8

    def reset():
        state.update(width=lit + 1, hi=clear + 1, overflow=clear << 1, table={})

    def inc_hi():
        state["hi"] += 1
        if state["hi"] == state["overflow"]:
            state["width"] += 1
            state["overflow"] <<= 1
        if state["hi"] == 4095:
            write(clear)
            reset()
            return False
        return True

    if data:
        write(clear)
        code = data[0]
        for b in data[1:]:
            key = (code << 8) | b
            if key in state["table"]:
                code = state["table"][key]
                continue
            write(code)
            code = b
            if rng is not None and rng.random() < clears:
                write(clear)
                reset()
                continue
            if inc_hi():
                state["table"][key] = state["hi"]
        write(code)
        inc_hi()
    else:
        write(clear)
    if eof:
        write(clear + 1)
    if state["nbits"] > 0:
        out.append(state["bits"] & 0xFF)
    return bytes(out)


def sub_blocks(data, rng, sizes="random"):
    out = bytearray()
    while data:
        n = 255 if sizes == "full" else rng.choice([255, 255, rng.randrange(1, 256), rng.randrange(1, 8)])
        piece, data = data[:n], data[n:]
        out.append(len(piece))
        out += piece
    return bytes(out)


def color_table(rng, bits):
    return bytes(rng.randrange(256) for _ in range(3 * (1 << (bits + 1))))


def extension(rng):
    kind = rng.randrange(7)
    if kind == 0:  # comment
        return b"\x21\xfe" + sub_blocks(bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300))), rng) + b"\x00"
    if kind == 1:  # NETSCAPE loop count, sometimes malformed
        block = rng.choice([b"\x03\x01" + struct.pack("<H", rng.choice([0, 1, 5, 65535, rng.randrange(65536)])),
                            b"\x03\x02\x05\x00", b"\x02\x01\x05", b"\x05\x01\x05\x00\x00\x00", b""])
        tail = b"" if rng.random() < 0.8 else b"\x02ab"
        return b"\x21\xff\x0bNETSCAPE2.0" + block + tail + b"\x00"
    if kind == 2:  # other application blocks, including Adobe's 10-byte size
        name = rng.choice([b"XMP DataXMP", b"ADOBE:XMP\x00", b"ANIMEXTS1.0", b""])
        return b"\x21\xff" + bytes([len(name)]) + name + sub_blocks(b"payload" * rng.randrange(3), rng) + b"\x00"
    if kind == 3:  # plain text
        return b"\x21\x01" + bytes(rng.randrange(256) for _ in range(13)) + sub_blocks(b"text", rng) + b"\x00"
    if kind == 4 and rng.random() < 0.2:  # unknown extension
        return b"\x21" + bytes([rng.choice([0x02, 0x10, 0xfa])]) + b"\x00"
    return gce(rng)


def gce(rng, transparent=None):
    flags = (rng.randrange(8) << 2) | (1 if transparent is not None else 0)
    if transparent is None and rng.random() < 0.3:
        flags |= 1
        transparent = rng.randrange(256)
    size, term = 4, 0
    if rng.random() < 0.03:
        size = rng.choice([3, 5])
    if rng.random() < 0.03:
        term = 1
    return bytes([0x21, 0xF9, size, flags]) + struct.pack("<H", rng.choice([0, 0, 5, 100, rng.randrange(65536)])) + \
        bytes([transparent or 0, term])


def synthetic(rng):
    """A GIF assembled from random but mostly valid blocks."""
    w, h = rng.randrange(0, 40), rng.randrange(0, 30)
    if rng.random() < 0.05:
        w, h = 0, 0
    version = rng.choice([b"GIF89a"] * 8 + [b"GIF87a", b"GIF88a"])
    global_bits = rng.randrange(8) if rng.random() < 0.7 else None
    fields = 0 if global_bits is None else 0x80 | (rng.randrange(8) << 4) | global_bits
    out = bytearray(version + struct.pack("<HH", w, h) + bytes([fields, rng.randrange(256), 0]))
    if global_bits is not None:
        out += color_table(rng, global_bits)
    for _ in range(rng.choice([1, 1, 1, 2, 3, 5])):
        while rng.random() < 0.4:
            out += extension(rng)
        fw = rng.randrange(0, w + 1)
        fh = rng.randrange(0, h + 1)
        left, top = rng.randrange(0, w - fw + 1), rng.randrange(0, h - fh + 1)
        if rng.random() < 0.03:
            left += rng.randrange(1, 4)
        local_bits = rng.randrange(8) if (global_bits is None and rng.random() < 0.95) or rng.random() < 0.4 else None
        interlace = rng.random() < 0.3
        dfields = (0x40 if interlace else 0) | (0 if local_bits is None else 0x80 | local_bits)
        bits = local_bits if local_bits is not None else (global_bits or 0)
        colors = 1 << (bits + 1)
        # A transparent index past the table grows the palette; 255 entries
        # is the one size where index 255 is still a bad pixel.
        ti = None
        if rng.random() < 0.08:
            ti = min(255, rng.choice([254, 254, 255, colors - 1, colors, colors + 3]))
            out += gce(rng, transparent=ti)
        elif rng.random() < 0.3:
            out += gce(rng)
        out += b"\x2c" + struct.pack("<HHHH", left, top, fw, fh) + bytes([dfields])
        if local_bits is not None:
            out += color_table(rng, local_bits)
        lit = max(2, bits + 1) if ti is None else 8
        npix = fw * fh
        limit = colors if rng.random() < 0.9 else min(256, 1 << lit)
        if ti is not None:
            limit = min(256, max(colors, ti + 1) + rng.choice([0, 0, 1]))
        pixels = bytes(rng.randrange(limit) for _ in range(npix))
        roll = rng.random()
        if roll < 0.04:
            pixels += bytes(rng.randrange(limit) for _ in range(rng.randrange(1, 5)))
        elif roll < 0.08 and pixels:
            pixels = pixels[:-rng.randrange(1, len(pixels) + 1)]
        header_lit = lit
        if rng.random() < 0.04:
            header_lit = rng.choice([0, 1, 9, 12, lit + 1, max(2, lit - 1)])
        data = lzw_encode(pixels, lit, eof=rng.random() > 0.15, clears=rng.choice([0, 0, 0.01, 0.2]), rng=rng)
        if rng.random() < 0.08:
            data += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 4)))
        out += bytes([header_lit]) + sub_blocks(data, rng)
        roll = rng.random()
        if roll < 0.05:
            out += b"\x01" + bytes([rng.randrange(256)])  # one stray byte (golang.org/issue/16146)
        elif roll < 0.08:
            out += b"\x02" + bytes([rng.randrange(256), rng.randrange(256)])
        out += b"\x00"
    roll = rng.random()
    if roll < 0.9:
        out += b"\x3b"
    if roll < 0.05:
        out += bytes(rng.randrange(256) for _ in range(rng.randrange(1, 10)))
    return bytes(out)


def mutate(rng, data):
    b = bytearray(data)
    kind = rng.randrange(8)
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
        b[i] = rng.choice([0x00, 0x01, 0x02, 0x03, 0x0B, 0x21, 0x2C, 0x3B, 0x80, 0xF9, 0xFE, 0xFF])
    elif kind == 5:
        j = rng.randrange(i, min(len(b), i + 40) + 1)
        b[j:j] = b[i:j]
    elif kind == 6:
        for _ in range(rng.randrange(2, 6)):
            b[rng.randrange(len(b))] = rng.randrange(256)
    else:
        # Screen or frame dimension fields are the most decision-relevant.
        k = rng.choice([6, 7, 8, 9, 10] + list(range(min(len(b), 13), len(b))))
        if k < len(b):
            b[k] = rng.randrange(256)
    return bytes(b)


# ------------------------------------------------------------ encoder specs

def random_color(rng, transparent_ok=True):
    tag = rng.choice(["RGBA"] * 4 + list(COLOR_BYTES))
    data = bytearray(rng.randrange(256) for _ in range(COLOR_BYTES[tag]))
    if tag in ("RGBA", "NRGBA") and rng.random() < 0.8:
        data[3] = 0xFF
    if not transparent_ok and tag in ("RGBA", "NRGBA"):
        data[3] = 0xFF
    return f"{tag}:{data.hex()}"


def random_palette(rng, n=None):
    n = n if n is not None else rng.choice([1, 2, 3, 4, 5, 8, 16, 17, 100, 256, rng.randrange(1, 257)])
    if n == 0:
        return "-", 0
    return ",".join(random_color(rng) for _ in range(n)), n


def encode_all_spec(rng):
    w, h = rng.randrange(1, 24), rng.randrange(1, 20)
    roll = rng.random()
    global_text, gn = "-", 0
    if roll < 0.25:
        config = "zero"
    elif roll < 0.3:
        config = f"{w};{h};model"
    elif roll < 0.4:
        config = f"{w};{h};-"
    else:
        global_text, gn = random_palette(rng)
        if rng.random() < 0.02:
            global_text, gn = random_palette(rng, 257)
        config = f"{w};{h};{global_text}"
    frames = []
    count = rng.choice([1, 1, 2, 3, 4])
    for _ in range(count):
        sw, sh = (w, h) if config != "zero" else (rng.randrange(1, 24), rng.randrange(1, 20))
        fw, fh = rng.randrange(0, sw + 1), rng.randrange(0, sh + 1)
        x0, y0 = rng.randrange(0, sw - fw + 1), rng.randrange(0, sh - fh + 1)
        if rng.random() < 0.04:
            x0 += rng.choice([-1, 1, 30])
        if config == "zero" and not frames:
            x0, y0 = 0, 0
        stride = fw if rng.random() < 0.8 else fw + rng.randrange(1, 4)
        roll = rng.random()
        if gn and roll < 0.25:
            palette, n = "G", gn
        elif gn and roll < 0.35:
            n = rng.randrange(1, gn + 1)
            palette = f"G:{n}"
        elif gn and roll < 0.45:
            # An unshared copy, sometimes with one entry made transparent the
            # way DecodeAll does.
            colors = global_text.split(",")
            if rng.random() < 0.5:
                colors[rng.randrange(len(colors))] = "RGBA:00000000"
            palette, n = ",".join(colors), len(colors)
        else:
            palette, n = random_palette(rng)
            if rng.random() < 0.02:
                palette, n = "-", 0
            if rng.random() < 0.02:
                palette, n = random_palette(rng, 300)
        bits = max(1, (max(n, 1) - 1).bit_length())
        limit = max(1, n) if rng.random() < 0.9 else min(256, 1 << bits) if rng.random() < 0.5 else 256
        limit = min(limit, 256)
        pix = bytes(rng.randrange(limit) for _ in range(stride * fh))
        delay = rng.choice([0, 0, 0, 1, 50, 65535, 65536 + 7, -1])
        frames.append(f"{x0},{y0},{x0 + fw},{y0 + fh};{stride};{delay};{palette};{pix.hex()}")
    roll = rng.random()
    if roll < 0.4:
        disposal = "nil"
    elif roll < 0.95:
        disposal = ",".join(str(rng.choice([0, 0, 1, 2, 3, 7])) for _ in range(count))
    else:
        disposal = rng.choice(["-", ",".join("1" for _ in range(count + 1))])
    loop = rng.choice([-1, 0, 0, 1, 5, 65535, 65536 + 3])
    return f"E {config} {rng.randrange(256)} {loop} {disposal} " + " ".join(frames)


def image_spec(rng):
    kind = rng.choice(list(BPP) + ["Paletted", "Paletted", "Rect", "Uniform"])
    if kind == "Uniform":
        return "Uniform/-/-/" + random_color(rng)
    x0, y0 = rng.choice([(0, 0), (rng.randrange(-5, 5), rng.randrange(-5, 5))])
    w, h = rng.randrange(0, 16), rng.randrange(0, 12)
    if rng.random() < 0.1:
        w, h = rng.randrange(30, 90), rng.randrange(20, 50)
    rect = f"{x0},{y0},{x0 + w},{y0 + h}"
    if kind == "Rect":
        return f"Rect/{rect}/-/-"
    palette = "-"
    if kind == "Paletted":
        palette, n = random_palette(rng)
        pix = bytes(rng.randrange(n) for _ in range(w * h))
    else:
        pix = bytes(rng.randrange(256) for _ in range(BPP[kind] * w * h))
    return f"{kind}/{rect}/{pix.hex()}/{palette}"


def encode_spec(rng):
    return "S {} {} {} {}".format(image_spec(rng), rng.choice([0, 1, 2, 7, 16, 64, 255, 256, 300, -3]),
                                 rng.choice(["nil", "first"]), rng.choice(["nil", "Src", "Over", "FS"]))


# -------------------------------------------------------------------- run

def run(command, lines, label):
    payload = "".join(line + "\n" for line in lines)
    process = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT)
    if process.returncode:
        raise RuntimeError(f"{label} failed:\n{process.stderr}")
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
            raise AssertionError(f"{label} request {i}: {requests[i][:400]}\nRust={actual[:400]}\nGo  ={expected[:400]}")
    return skipped


def main():
    started = time.monotonic()
    rng = random.Random(0x474946)
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "gif_probe"],
                   cwd=ROOT, check=True)
    probe = [str(ROOT / "target/debug/examples" / ("gif_probe.exe" if os.name == "nt" else "gif_probe"))]
    go = ["go", "run", str(ROOT / "tools/gif_oracle.go")]

    encodes = [encode_all_spec(rng) for _ in range(1500)] + [encode_spec(rng) for _ in range(1000)]
    rust_enc = run(probe, encodes, "Rust GIF encoder")
    go_enc = run(go, encodes, "Go GIF encoder")
    panics = compare(encodes, rust_enc, go_enc, "encode")
    encoded = [bytes.fromhex(g) for g in go_enc if g not in ("err", "panic")]
    if len(encoded) < len(encodes) // 2:
        raise AssertionError(f"only {len(encoded)} of {len(encodes)} encode requests succeeded")

    goroot = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True, check=True).stdout.strip()
    suite = [p.read_bytes() for p in sorted((pathlib.Path(goroot) / "src/image/testdata").glob("*.gif"))]
    if len(suite) < 4:
        raise AssertionError("Go GIF testdata not found")
    synthetic_gifs = [synthetic(rng) for _ in range(1500)]
    corpus = encoded + suite + synthetic_gifs
    mutations = [mutate(rng, rng.choice(corpus)) for _ in range(5000)]
    for _ in range(500):
        mutations.append(mutate(rng, mutate(rng, rng.choice(corpus))))

    files = corpus + mutations
    requests = [f"{kind} {data.hex()}" for data in files for kind in ("A", "D", "C")]
    rust = run(probe, requests, "Rust GIF decoder")
    golang = run(go, requests, "Go GIF decoder")
    compare(requests, rust, golang, "decode")
    accepted = sum(line.startswith("ok ") for line in golang[0::3])
    mutated_accepted = sum(line.startswith("ok ") for line in golang[3 * len(corpus)::3])
    frames = sum(int(line.split()[6]) for line in golang[0::3] if line.startswith("ok "))
    print(f"GIF Go differential: {len(encodes)} encode requests ({len(encoded)} byte-identical GIFs, "
          f"{panics} Go panics skipped), {len(suite)} Go testdata + {len(synthetic_gifs)} synthetic GIFs, "
          f"{len(mutations)} mutations ({mutated_accepted} accepted); {len(requests)} DecodeAll/Decode/"
          f"DecodeConfig vectors ({accepted} files accepted, {frames} frames) passed "
          f"in {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
