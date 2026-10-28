#!/usr/bin/env python3
"""Differentially check image/draw against Go with exact destination pixels.

Random destination/source/mask type combinations (every image type, Uniform
and Rectangle sources and masks, a destination drawn onto itself), random
rectangles that need clipping, both operators, and Floyd-Steinberg dithering
into paletted and non-paletted destinations. The destination's raw pixel
bytes must be identical to Go's.
"""
import os
import pathlib
import random
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
BPP = {"RGBA": 4, "NRGBA": 4, "RGBA64": 8, "NRGBA64": 8, "Gray": 1, "Gray16": 2,
       "Alpha": 1, "Alpha16": 2, "Paletted": 1}
COLOR_BYTES = {"RGBA": 4, "NRGBA": 4, "RGBA64": 8, "NRGBA64": 8, "Gray": 1, "Gray16": 2,
               "Alpha": 1, "Alpha16": 2}
DEST = list(BPP)


def random_bytes(rng, n, style):
    if style == "extreme":
        return bytes(rng.choice((0, 0, 0xFF, 0xFF, 1, 0xFE, 0x80)) for _ in range(n))
    return bytes(rng.randrange(256) for _ in range(n))


def premultiply(kind, pix):
    """Clamp color channels to alpha so premultiplied pixels are valid."""
    pix = bytearray(pix)
    if kind == "RGBA":
        for i in range(0, len(pix), 4):
            for k in range(3):
                pix[i + k] = min(pix[i + k], pix[i + 3])
    if kind == "RGBA64":
        for i in range(0, len(pix), 8):
            a = int.from_bytes(pix[i + 6:i + 8], "big")
            for k in range(3):
                v = min(int.from_bytes(pix[i + 2 * k:i + 2 * k + 2], "big"), a)
                pix[i + 2 * k:i + 2 * k + 2] = v.to_bytes(2, "big")
    return bytes(pix)


def random_color(rng, style):
    tag = rng.choice(list(COLOR_BYTES))
    return f"{tag}:{random_bytes(rng, COLOR_BYTES[tag], style).hex()}"


def random_palette(rng, style, allow_empty):
    n = rng.choice([1, 2, 3, 4, 7, 16, rng.randrange(1, 40)])
    if allow_empty and rng.random() < 0.03:
        return 0, "-"
    return n, ",".join(random_color(rng, style) for _ in range(n))


def random_rect(rng):
    x0, y0 = rng.choice([(0, 0), (rng.randrange(-8, 8), rng.randrange(-8, 8))])
    return x0, y0, x0 + rng.randrange(0, 11), y0 + rng.randrange(0, 9)


def image_spec(rng, kind, dst=False, style=None, clamp=None):
    style = style or rng.choice(["random", "extreme"])
    if kind == "Uniform":
        return f"Uniform/-/-/{random_color(rng, style)}"
    if kind == "Rect":
        return "Rect/{},{},{},{}/-/-".format(*random_rect(rng))
    r = random_rect(rng)
    w, h = r[2] - r[0], r[3] - r[1]
    palette = "-"
    if kind == "Paletted":
        n, palette = random_palette(rng, style, allow_empty=dst)
        pix = bytes(rng.randrange(max(n, 1)) for _ in range(w * h))
    else:
        pix = random_bytes(rng, BPP[kind] * w * h, style)
        if clamp if clamp is not None else rng.random() < 0.5:
            pix = premultiply(kind, pix)
    return "{}/{},{},{},{}/{}/{}".format(kind, *r, pix.hex(), palette)


def point(rng):
    return f"{rng.randrange(-10, 12)},{rng.randrange(-10, 12)}"


def draw_request(rng):
    # RGBA destinations have the most Go fast paths; weight them up.
    dst = "RGBA" if rng.random() < 0.3 else rng.choice(DEST)
    roll = rng.random()
    if roll < 0.12:
        src = "SELF"
    elif roll < 0.25:
        src = image_spec(rng, "Uniform")
    elif roll < 0.3:
        src = image_spec(rng, "Rect")
    elif roll < 0.45:
        # Same-type sources hit Go's copy fast paths (lossless for NRGBA).
        src = image_spec(rng, dst, style="extreme", clamp=False)
    else:
        src = image_spec(rng, rng.choice(DEST))
    roll = rng.random()
    if roll < 0.4:
        mask = "nil"
    elif roll < 0.65:
        mask = image_spec(rng, "Alpha")
    elif roll < 0.8:
        mask = image_spec(rng, "Uniform")
    elif roll < 0.85:
        mask = image_spec(rng, "Rect")
    else:
        mask = image_spec(rng, rng.choice(DEST))
    r = "{},{},{},{}".format(*random_rect(rng)) if rng.random() < 0.8 else \
        f"{rng.randrange(-12, 12)},{rng.randrange(-12, 12)},{rng.randrange(-12, 12)},{rng.randrange(-12, 12)}"
    op = rng.choice(["Over", "Src"])
    return f"D {image_spec(rng, dst, dst=True)} {src} {mask} {r} {point(rng)} {point(rng)} {op}"


def focus_request(rng):
    """RGBA-destination compositing with saturated, invalid premultiplied
    values, which reach Go's 32-bit wrap-around in the blend arithmetic."""
    dst = image_spec(rng, "RGBA", dst=True, style="extreme", clamp=False)
    kind = rng.choice(["Uniform", "RGBA", "RGBA64", "NRGBA", "Gray", "Alpha16", "SELF"])
    if kind == "SELF":
        src = "SELF"
    elif kind == "Uniform":
        tag = rng.choice(["RGBA", "RGBA64"])
        src = f"Uniform/-/-/{tag}:{random_bytes(rng, COLOR_BYTES[tag], 'extreme').hex()}"
    else:
        src = image_spec(rng, kind, style="extreme", clamp=False)
    mask = rng.choice(["nil", image_spec(rng, "Alpha", style="extreme"),
                       image_spec(rng, "Alpha16", style="extreme"),
                       f"Uniform/-/-/Alpha:{rng.choice(['ff', 'fe', '80', '01'])}"])
    op = "Over" if rng.random() < 0.8 else "Src"
    return f"D {dst} {src} {mask} -2,-2,12,12 {point(rng)} {point(rng)} {op}"


def op_draw_request(rng):
    """Go's Op.Draw (no mask): the Drawer implementation of Over and Src."""
    dst = image_spec(rng, rng.choice(DEST), dst=True)
    src = image_spec(rng, rng.choice(DEST + ["Uniform", "Rect"]))
    r = "{},{},{},{}".format(*random_rect(rng))
    return f"O {dst} {src} {r} {point(rng)} {rng.choice(['Over', 'Src'])}"


def dither_request(rng):
    dst = "Paletted" if rng.random() < 0.7 else rng.choice(DEST)
    spec = image_spec(rng, dst)
    if dst == "Paletted" and rng.random() < 0.2:
        # A larger palette exercises the nearest-color search and error terms.
        n, palette = random_palette(rng, "random", allow_empty=False)
        n = rng.randrange(40, 120)
        palette = ",".join(random_color(rng, "random") for _ in range(n))
        kind, rect, pix, _ = spec.split("/")
        pix = bytes(b % n for b in bytes.fromhex(pix)).hex()
        spec = f"{kind}/{rect}/{pix}/{palette}"
    src = image_spec(rng, rng.choice(DEST + ["Uniform", "Rect"]))
    r = "{},{},{},{}".format(*random_rect(rng))
    return f"F {spec} {src} {r} {point(rng)}"


def sub_image_request(rng):
    """SubImage shares pixels: a set through the parent shows in the child and
    one through the child shows in the parent, with the child's stride and Pix
    window as Go has them."""
    kind = rng.choice(DEST)
    spec = image_spec(rng, kind)
    x0, y0, x1, y1 = (int(v) for v in spec.split("/")[1].split(","))
    sub = (x0 + rng.randrange(-3, 4), y0 + rng.randrange(-3, 4), x1 + rng.randrange(-3, 4), y1 + rng.randrange(-3, 4))
    inside = lambda: f"{rng.randrange(x0 - 2, x1 + 2)},{rng.randrange(y0 - 2, y1 + 2)}"
    colors = list(COLOR_BYTES)
    color = lambda: (lambda tag: f"{tag}:{random_bytes(rng, COLOR_BYTES[tag], 'random').hex()}")(rng.choice(colors))
    return f"U {spec} {sub[0]},{sub[1]},{sub[2]},{sub[3]} {inside()} {color()} {inside()} {color()}"


def panic_request(rng):
    """Inputs on which Go panics: a paletted source with an index outside its
    palette, and FloydSteinberg onto an empty palette."""
    if rng.random() < 0.5:
        kind, rect, pix, palette = image_spec(rng, "Paletted").split("/")
        n = len(palette.split(",")) if palette != "-" else 1
        pix = bytes(rng.randrange(n, 256) if rng.random() < 0.5 else b for b in bytes.fromhex(pix)).hex()
        src = f"{kind}/{rect}/{pix}/{palette}"
        dst = image_spec(rng, rng.choice(["RGBA", "NRGBA", "Gray", "Paletted"]), dst=True)
        return f"D {dst} {src} nil {'{},{},{},{}'.format(*random_rect(rng))} {point(rng)} {point(rng)} {rng.choice(['Over', 'Src'])}"
    r = random_rect(rng)
    w, h = r[2] - r[0], r[3] - r[1]
    dst = "Paletted/{},{},{},{}/{}/-".format(*r, bytes(w * h).hex())
    src = image_spec(rng, rng.choice(DEST + ["Uniform"]))
    return f"F {dst} {src} {'{},{},{},{}'.format(*r)} {point(rng)}"


def run(command, lines, label):
    payload = "".join(line + "\n" for line in lines)
    process = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT)
    if process.returncode:
        raise RuntimeError(f"{label} failed:\n{process.stderr}")
    out = process.stdout.splitlines()
    if len(out) != len(lines):
        raise AssertionError(f"{label} returned {len(out)} records for {len(lines)} requests")
    return out


def main():
    started = time.monotonic()
    rng = random.Random(0x44524157)
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "draw_probe"],
                   cwd=ROOT, check=True)
    probe = str(ROOT / "target/debug/examples" / ("draw_probe.exe" if os.name == "nt" else "draw_probe"))
    requests = [draw_request(rng) for _ in range(8000)] + [focus_request(rng) for _ in range(2000)] + \
        [dither_request(rng) for _ in range(2000)] + [op_draw_request(rng) for _ in range(2000)]
    subs = [sub_image_request(rng) for _ in range(2000)]
    panics_wanted = [panic_request(rng) for _ in range(400)]
    requests += subs + panics_wanted
    rust = run([probe], requests, "Rust draw probe")
    golang = run(["go", "run", str(ROOT / "tools/draw_oracle.go")], requests, "Go draw oracle")
    panics = 0
    for i, (actual, expected) in enumerate(zip(rust, golang)):
        if expected == "panic":
            panics += 1
        if actual != expected:
            raise AssertionError(f"request {i}: {requests[i][:600]}\nRust={actual[:300]}\nGo  ={expected[:300]}")
    if panics < 20 or panics > 600:
        raise AssertionError(f"unexpected number of Go panics ({panics}); the generator is broken")
    print(f"draw Go differential: {len(requests) - 6400} DrawMask (2000 RGBA wrap-around focused), "
          f"2000 FloydSteinberg, 2000 Op.Draw, 2000 SubImage sharing and 400 panic vectors, "
          f"{len(requests)} compared with exact pixels ({panics} Go panics matched) "
          f"in {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
