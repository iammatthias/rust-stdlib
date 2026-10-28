#!/usr/bin/env python3
"""Compare image/color conversions with Go over every input that matters.

The YCbCr and CMYK conversions are swept exhaustively (2^24 RGB or YCbCr
triples) and the 32-bit CMYK and NYCbCrA spaces by 2^22 xorshift samples. Random
colors of all eleven types feed each model's Convert. Both sides hash their
outputs into one FNV-1a value per request, so each request is a single exact
comparison; examples/color_probe.rs and tools/color_oracle.go share the
generator and hash.
"""
import os
import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODELS = ["rgba", "rgba64", "nrgba", "nrgba64", "gray", "gray16", "alpha", "alpha16",
          "ycbcr", "nycbcra", "cmyk"]
OPS = ["rgb_to_ycbcr", "ycbcr_to_rgb", "rgb_to_cmyk", "cmyk_to_rgb", "ycbcr_rgba",
       "nycbcra_rgba", "cmyk_rgba", "color_rgba"]


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
    requests = [f"{op} -" for op in OPS] + [f"model {m}" for m in MODELS] + ["model nope", "bogus -"]
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "color_probe"],
                   cwd=ROOT, check=True)
    probe = str(ROOT / "target/debug/examples" / ("color_probe.exe" if os.name == "nt" else "color_probe"))
    rust = run([probe], requests, "Rust color probe")
    golang = run(["go", "run", str(ROOT / "tools/color_oracle.go")], requests, "Go color oracle")
    for request, actual, expected in zip(requests, rust, golang):
        if actual != expected:
            raise AssertionError(f"{request}: Rust={actual} Go={expected}")
    print(f"color Go differential: {len(OPS)} exhaustive or sampled sweeps (2^24 RGB/YCbCr triples for "
          f"RGBToYCbCr, YCbCrToRGB, RGBToCMYK and YCbCr.RGBA; 2^22 samples for CMYK, NYCbCrA and "
          f"CMYKToRGB), 2^20 random colors of 11 types through {len(MODELS)} model conversions "
          f"and RGBA(), all matching Go in {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
