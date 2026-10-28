#!/usr/bin/env python3
"""Differentially compare seeded math/rand and math/rand/v2 streams with Go.

Every seeded generator and Rand method must be bit-identical to Go on the host
architecture (see src/math/rand/fmath.rs for the arm64 fused-multiply-add
mirror). Floats are compared as IEEE-754 bit patterns.
"""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
U64_MAX = (1 << 64) - 1
I64_MAX = (1 << 63) - 1

# Bounds include 1, powers of two (mask path), values just above powers of two
# (worst-case rejection), 2^31-1, 2^63-1 and each type's maximum.
INT64_ARGS = [1, 2, 3, 5, 7, 10, 32, 100, 1000, 1 << 20, (1 << 20) + 1, 10**9, 1 << 30,
              (1 << 31) - 2, (1 << 31) - 1, 1 << 31, (1 << 31) + 1, (1 << 32) - 1, 1 << 32,
              (1 << 32) + 1, 1 << 40, 10**18, 1 << 60, (1 << 62) + 1, 3 << 61,
              I64_MAX - 1, I64_MAX]
UINT64_ARGS = INT64_ARGS + [1 << 63, (1 << 63) + 1, (1 << 63) + (1 << 62), U64_MAX - 1, U64_MAX]
INT32_ARGS = [1, 2, 3, 5, 7, 10, 32, 100, 1000, 1 << 20, (1 << 20) + 1, 10**9, 1 << 30,
              (1 << 30) + 1, 3 << 29, (1 << 31) - 2, (1 << 31) - 1]
UINT32_ARGS = INT32_ARGS + [1 << 31, (1 << 31) + 1, (1 << 32) - 2, (1 << 32) - 1]
SIZES = [0, 1, 2, 3, 5, 16, 100]
READ_SIZES = [0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 33, 100, 255]
# Zipf arguments "s:v:imax:count"; the last two are invalid (s <= 1 or v < 1) and must give nil.
ZIPF_ARGS = ["1.01:1:0", "1.5:1:1", "1.5:1:10", "2:1:100", "1.1:2.7:1000", "3.5:1:1000000",
             "1.0001:1:4294967295", "2:1.5:18446744073709551615", "1.0000001:1:9", "1e1:3:50",
             "1:1:5", "0.5:1:5", "2:0.5:5"]
V2_PLAIN = ["Int64", "Uint32", "Uint64", "Int32", "Int", "Uint", "Float64", "Float32",
            "NormFloat64", "ExpFloat64"]
V1_PLAIN = ["Int63", "Uint32", "Uint64", "Int31", "Int", "Float64", "Float32",
            "NormFloat64", "ExpFloat64"]


def bounded(rng, values, limit):
    """The fixed edge bounds plus random bounds of random bit length."""
    extra = [rng.randrange(1, 1 << rng.randrange(2, limit.bit_length() + 1)) for _ in range(6)]
    return values + [min(value, limit) for value in extra]


def v2_ops(rng):
    ops = [name for name in V2_PLAIN for _ in range(3)]
    for name, args in (("Int64N", INT64_ARGS), ("IntN", INT64_ARGS), ("NInt64", INT64_ARGS),
                       ("NDuration", INT64_ARGS), ("Uint64N", UINT64_ARGS),
                       ("UintN", UINT64_ARGS), ("Int32N", INT32_ARGS),
                       ("Uint32N", UINT32_ARGS)):
        limit = max(args)
        ops += [f"{name}:{arg}" for arg in bounded(rng, args, limit) for _ in range(2)]
    ops += [f"Zipf:{arg}:{rng.randrange(1, 40)}" for arg in ZIPF_ARGS for _ in range(2)]
    ops += [f"NInt8:{rng.randrange(1, 128)}" for _ in range(4)] + ["NInt8:127", "NInt8:1"]
    ops += [f"NUint16:{rng.randrange(1, 65536)}" for _ in range(4)] + ["NUint16:65535"]
    ops += [f"{name}:{size}" for name in ("Perm", "Shuffle") for size in SIZES]
    rng.shuffle(ops)
    return ops


def v1_ops(rng):
    ops = [name for name in V1_PLAIN for _ in range(3)]
    for name, args in (("Int63n", INT64_ARGS), ("Intn", INT64_ARGS), ("Int31n", INT32_ARGS)):
        ops += [f"{name}:{arg}" for arg in bounded(rng, args, max(args)) for _ in range(2)]
    ops += [f"{name}:{size}" for name in ("Perm", "Shuffle") for size in SIZES]
    ops += [f"Read:{size}" for size in READ_SIZES]
    ops += [f"Zipf:{arg}:{rng.randrange(1, 40)}" for arg in ZIPF_ARGS for _ in range(2)]
    rng.shuffle(ops)
    # Seed resets the Read buffer mid-stream.
    ops.insert(len(ops) // 2, f"Seed:{rng.randrange(-(1 << 63), 1 << 63)}")
    return ops


def chacha_stream_ops(rng):
    """Cross several 16-block reseeds with Uint64, odd-sized reads and marshals."""
    ops = []
    for _ in range(rng.randrange(150, 260)):
        roll = rng.random()
        if roll < 0.45:
            ops.append("Uint64")
        elif roll < 0.9:
            ops.append(f"Read:{rng.choice(READ_SIZES + [rng.randrange(1, 300)])}")
        else:
            ops.append("Marshal")
    return ops


def corpus():
    rng = random.Random(0x5EED_2026)
    lines = []
    pcg_seeds = [(0, 0), (1, 2), (U64_MAX, U64_MAX), (0x123456789ABCDEF0, 0xFEDCBA9876543210)]
    pcg_seeds += [(rng.randrange(1 << 64), rng.randrange(1 << 64)) for _ in range(196)]
    for a, b in pcg_seeds:
        lines.append(f"pcg {a} {b} | " + " ".join(v2_ops(rng)))
    for a, b in pcg_seeds[:40]:
        ops = [rng.choice(["Uint64", "Marshal", "IntN:1000", "Float64"]) for _ in range(40)]
        lines.append(f"pcg {a} {b} | " + " ".join(ops))

    chacha_seeds = [bytes(32), b"\xff" * 32, b"ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"]
    chacha_seeds += [bytes(rng.randrange(256) for _ in range(32)) for _ in range(97)]
    for seed in chacha_seeds:
        lines.append(f"chacha {seed.hex()} | " + " ".join(v2_ops(rng)))
        lines.append(f"chacha {seed.hex()} | " + " ".join(chacha_stream_ops(rng)))
    # Long Uint64 runs: 3 full reseed cycles (124 values per 16-block cycle).
    for seed in chacha_seeds[:10]:
        lines.append(f"chacha {seed.hex()} | " + " ".join(["Uint64"] * 400 + ["Read:2976"]))

    v1_seeds = [0, 1, -1, 2, 89482311, (1 << 31) - 1, 1 << 31, -(1 << 31), I64_MAX, -(1 << 63)]
    v1_seeds += [rng.randrange(-(1 << 63), 1 << 63) for _ in range(190)]
    for seed in v1_seeds:
        lines.append(f"v1 {seed} | " + " ".join(v1_ops(rng)))

    # Distribution tails: enough Norm/Exp draws to reach the ziggurat tail and
    # wedge paths, where Go's arithmetic is architecture-dependent.
    heavy = " ".join(["NormFloat64"] * 15000 + ["ExpFloat64"] * 15000)
    for i in range(4):
        lines.append(f"pcg {pcg_seeds[i + 4][0]} {i} | {heavy}")
        lines.append(f"chacha {chacha_seeds[i + 3].hex()} | {heavy}")
        lines.append(f"v1 {v1_seeds[i + 10]} | {heavy}")
    return lines


def run(command, payload):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, timeout=180)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return result.stdout.splitlines()


def main():
    lines = corpus()
    payload = "".join(line + "\n" for line in lines)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked",
                "--example", "rand_probe"], payload)
    go = run(["go", "run", str(ROOT / "tools/rand_oracle.go")], payload)
    if len(rust) != len(lines) or len(go) != len(lines):
        raise AssertionError("rand oracle returned the wrong number of records")
    values = 0
    for i, (actual, expected) in enumerate(zip(rust, go)):
        a, e = actual.split(" "), expected.split(" ")
        if a != e:
            ops = lines[i].split(" | ", 1)[1].split()
            j = next((k for k, (x, y) in enumerate(zip(a, e)) if x != y), min(len(a), len(e)))
            op = ops[j] if j < len(ops) else "<length>"
            raise AssertionError(f"request {i} ({lines[i].split(' | ')[0]}), op {j} {op}\n"
                                 f"Rust={a[j:j + 1]!r}\nGo={e[j:j + 1]!r}")
        values += len(e)
    print(f"math/rand Go differential: {len(lines)} seeded streams, {values} values passed")


if __name__ == "__main__":
    main()
