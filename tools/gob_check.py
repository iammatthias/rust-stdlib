#!/usr/bin/env python3
"""Differential test of encoding/gob against Go: generated typed values encode
to identical bytes (type ids included, since both probes assign them in the
same order), each side decodes the other's streams to the same values, and
merged, evolved, mismatched and corrupted streams give identical results and
error texts. Types come from tools/gob_spec.py (written out as Go types and as
#[derive(Reflect)] types by tools/gob_gen.py)."""
import os
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import gob_spec as spec  # noqa: E402
import gob_gen  # noqa: E402

RUST = ["cargo", "run", "--quiet", "--offline", "--locked", "--manifest-path",
        "tools/derive-check/Cargo.toml", "--example", "gob_probe"]
GO = ["go", "run", "tools/gob_oracle.go", "tools/gob_types_gen.go"]


def run(cmd, requests, what):
    payload = "".join(r + "\n" for r in requests)
    res = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if res.returncode:
        raise RuntimeError(f"{what} failed:\n{res.stderr[-3000:]}")
    out = res.stdout.split("\n")[:-1]
    if len(out) != len(requests):
        raise AssertionError(f"{what}: {len(out)} answers for {len(requests)} requests")
    return out


def both(requests):
    rust = run(RUST, requests, "Rust gob probe")
    go = run(GO, requests, "Go gob oracle")
    return go, rust


def compare(label, requests, go, rust):
    bad = [i for i in range(len(requests)) if go[i] != rust[i]]
    if bad and os.environ.get("GOB_DUMP"):
        with open(os.environ["GOB_DUMP"], "w") as fh:
            fh.write("".join(requests[i] + "\n" for i in bad))
    for i in bad[:6]:
        print(f"MISMATCH [{label}] {requests[i][:300]}\n  go:   {go[i][:400]}\n  rust: {rust[i][:400]}")
    if bad:
        raise SystemExit(f"{len(bad)} of {len(requests)} {label} vectors differ")


def main():
    gob_gen.main_check()
    structs, twins, ifaces, table = gob_gen.all_keys()
    tops = spec.tops(structs)
    top_keys = [k for k in tops]
    lits = spec.Lits(structs, ifaces, 1)
    rng = random.Random(99)

    def lit_for(key, maxmap):
        lits.maxmap = maxmap
        return lits.lit(tops[key] if key in tops else table[key], 4)

    # ---- phase 1: encoding ----
    enc = []
    for key in top_keys:
        for _ in range(14):
            enc.append(f"ENC {key} {lit_for(key, 1)}")
    for _ in range(900):
        n = rng.choice([2, 2, 3, 4])
        parts = []
        for _ in range(n):
            k = rng.choice(top_keys)
            parts.append(f"{k} {lit_for(k, 1)}")
        enc.append("ENC " + " ".join(parts))
    # The same value repeated: types are sent once.
    for key in rng.sample(top_keys, 60):
        lit = lit_for(key, 1)
        enc.append(f"ENC {key} {lit} {key} {lit} {key} {lit}")
    # Registered-type interface values at the top level and nested.
    for k in ifaces:
        for _ in range(2):
            enc.append(f"ENC []any [{lits.lit(('any',), 4, 0)},{lits.lit(('any',), 4, 0)}]")
    # Lengths around the one-byte/multi-byte boundaries, and large values.
    for n in (126, 127, 128, 129, 255, 256, 300, 5000):
        hexs = "61" * n
        enc.append(f"ENC string {hexs}")
        enc.append(f"ENC []byte {hexs}")
        enc.append(f"ENC []string [{hexs},{hexs[:4]}]")
        enc.append(f"ENC map[string]int m[{hexs}=7]")
    for n in (127, 128, 129, 300, 2000):
        enc.append("ENC []int [%s]" % ",".join(str(i * 7919 - 100) for i in range(n)))
        enc.append("ENC []float64 [%s]" % ",".join(str(spec.f64_bits(i * 0.5)) for i in range(n)))
        enc.append("ENC []bool [%s]" % ",".join("tf"[i % 2] for i in range(n)))
        enc.append("ENC []S0 [%s]" % ",".join(lit_for("S0", 1) for _ in range(min(n, 40))))
    ints = [k for k in spec.BITS]
    edge = {}
    for k in ints:
        bits = spec.BITS[k]
        if k.startswith("uint"):
            edge[k] = [0, 1, 127, 128, 255, 256, 65535, 65536, (1 << 32) - 1, 1 << 32, (1 << bits) - 1]
        else:
            edge[k] = [0, 1, -1, 63, 64, -64, -65, 127, 128, -128, -129, 32767, -32768, 32768,
                       (1 << 31) - 1, -(1 << 31), 1 << 31, (1 << (bits - 1)) - 1, -(1 << (bits - 1))]
        edge[k] = [v for v in edge[k] if (v >= 0 and v < (1 << bits) if k.startswith("uint") else -(1 << (bits - 1)) <= v < (1 << (bits - 1)))]
    for k in ints:
        for v in edge[k]:
            enc.append(f"ENC {k} {v}")
    f32 = [0.0, -0.0, 1.0, 3.4028234663852886e38, 1e39, 1e-45, 1e-50, float("inf"), float("nan")]
    for v in f32:
        enc.append(f"ENC float64 {spec.f64_bits(v)}")
        enc.append(f"ENC float32 {spec.f32_bits(v) if abs(v) < 3.5e38 or v != v or abs(v) == float('inf') else 0}")
    enc.append("ENC any n")
    go, rust = both(enc)
    compare("encode", enc, go, rust)
    nerr = sum(1 for g in go if g.startswith(("ERR", "PANIC")))

    # ---- phase 2: decode the streams ----
    dec = []
    for req, g in zip(enc, go):
        f = req.split()
        keys = f[1::2]
        if g.startswith("OK "):
            stream = g[3:]
            dec.append(f"DEC {stream} " + " ".join(keys))
    base_dec = len(dec)
    # Larger maps: Go's map order is random, so only decoding is compared.
    big = []
    for _ in range(500):
        k = rng.choice(top_keys)
        big.append(f"ENC {k} {lit_for(k, 3)}")
    bigg, bigr = both(big)
    for req, g, r in zip(big, bigg, bigr):
        keys = req.split()[1::2]
        for out in (g, r):
            if out.startswith("OK "):
                dec.append(f"DEC {out[3:]} " + " ".join(keys))
    # Merging into non-zero initial values.
    for req, g in list(zip(enc, go))[: len(enc) // 3]:
        f = req.split()
        keys = f[1::2]
        if g.startswith("OK ") and len(keys) == 1 and keys[0] in tops:
            init = lit_for(keys[0], 2)
            dec.append(f"DEC {g[3:]} {keys[0]}={init}")
    # Schema evolution: a struct stream decoded into its twin.
    twin_names = {t.name[:-1] for t in twins}
    for req, g in zip(enc, go):
        f = req.split()
        keys = f[1::2]
        if g.startswith("OK ") and len(keys) == 1 and keys[0] in twin_names:
            dec.append(f"DEC {g[3:]} {keys[0]}v")
    # Mismatched types.
    for req, g in zip(enc, go):
        f = req.split()
        keys = f[1::2]
        if g.startswith("OK ") and len(keys) == 1 and rng.random() < 0.25:
            dec.append(f"DEC {g[3:]} {rng.choice(top_keys)}")
    # Every integer and float kind into every other (overflow, kind mismatch).
    grid = ints + ["float32", "float64", "string", "bool", "complex128"]
    for req, g in zip(enc, go):
        f = req.split()
        if (g.startswith("OK ") and len(f) == 3 and f[1] in grid and f[1] != "string" and f[1] != "bool"
                and rng.random() < 0.3):
            for k2 in grid:
                if k2 != f[1]:
                    dec.append(f"DEC {g[3:]} {k2}")
    # Corruption: byte flips, truncation, insertion, duplicated tails.
    good = [(req, g[3:]) for req, g in zip(enc, go) if g.startswith("OK ") and g != "OK -"]
    for _ in range(2500):
        req, stream = rng.choice(good)
        raw = bytearray.fromhex(stream)
        for _ in range(rng.choice([1, 1, 2, 3])):
            how = rng.randrange(5)
            if how == 0 and raw:
                raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
            elif how == 1 and raw:
                raw[rng.randrange(len(raw))] = rng.choice([0, 1, 0x7f, 0x80, 0xff, 0xf8, rng.randrange(256)])
            elif how == 2 and raw:
                del raw[rng.randrange(len(raw)):]
            elif how == 3:
                raw.insert(rng.randrange(len(raw) + 1), rng.randrange(256))
            elif raw:
                del raw[rng.randrange(len(raw))]
        keys = req.split()[1::2]
        dec.append(f"DEC {raw.hex() or '-'} " + " ".join(keys))
    godec, rustdec = both(dec)
    compare("decode", dec, godec, rustdec)
    clean = sum(1 for g in godec if "ERR" not in g and "PANIC" not in g)
    print(f"gob: {len(enc) + len(big) + len(dec)} vectors match Go "
          f"({len(enc)} encode incl. {nerr} errors, {len(dec)} decode incl. {len(dec) - clean} errors/panics)")


if __name__ == "__main__":
    main()
