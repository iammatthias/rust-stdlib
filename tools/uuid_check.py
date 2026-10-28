#!/usr/bin/env python3
"""Differentially check the uuid package against Go.

Parsing (UnmarshalText) of valid and mutated text, MustParse, String,
MarshalText, AppendText and Compare compare exactly. NewV4 and NewV7 are
random, so their output is checked by its properties (version, variant, the
timestamp of NewV7 against the clock, and ordering) on both sides.
Requests go to tools/uuid_oracle.go and examples/uuid_probe.rs.
"""
import pathlib
import random
import subprocess
import time
import uuid as pyuuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
JUNK = "0123456789abcdefABCDEFgGxX-{}:uUrnRN \t\x00\xff"


def canonical(rng, u):
    """One of the four accepted forms, with random hex case."""
    text = str(pyuuid.UUID(bytes=u))
    if rng.random() < 0.5:
        text = "".join(c.upper() if c.isalpha() and rng.random() < 0.5 else c for c in text)
    form = rng.randrange(4)
    if form == 0:
        return text
    if form == 1:
        return "{" + text + "}"
    if form == 2:
        return "urn:uuid:" + text
    return text.replace("-", "")


def mutate(rng, text):
    """Replacements, insertions, deletions, truncations and extensions of text."""
    chars = list(text)
    for _ in range(rng.randrange(1, 4)):
        kind = rng.randrange(5)
        if kind == 0 and chars:
            chars[rng.randrange(len(chars))] = rng.choice(JUNK)
        elif kind == 1:
            chars.insert(rng.randrange(len(chars) + 1), rng.choice(JUNK))
        elif kind == 2 and chars:
            del chars[rng.randrange(len(chars))]
        elif kind == 3 and chars:
            chars = chars[:rng.randrange(len(chars) + 1)]
        else:
            chars += list(rng.choice(["-", "}", "x", "urn:uuid:", "00"]))
    return "".join(chars)


def text_requests(rng):
    out = []
    for _ in range(900):
        u = bytes(rng.randrange(256) for _ in range(16))
        base = canonical(rng, u)
        out.append(base)
        for _ in range(4):
            out.append(mutate(rng, base))
    for _ in range(300):
        out.append("".join(rng.choice(JUNK) for _ in range(rng.randrange(0, 50))))
    # Lengths around the accepted sizes (32, 36, 38 and 45) with arbitrary content.
    for n in (31, 32, 33, 35, 36, 37, 38, 39, 44, 45, 46):
        for _ in range(20):
            out.append("".join(rng.choice("0123456789abcdef-{}") for _ in range(n)))
    return out


def main():
    rng = random.Random(0x0071D)
    texts = text_requests(rng)
    lines = []
    for text in texts:
        raw = text.encode("utf-8", "surrogateescape")
        lines.append("U:" + raw.hex())
        lines.append("P:" + raw.hex())
    for _ in range(300):
        u = bytes(rng.randrange(256) for _ in range(16))
        lines.append("M:" + u.hex())
    for _ in range(300):
        a = bytes(rng.randrange(256) for _ in range(16))
        b = bytearray(a)
        choice = rng.randrange(3)
        if choice == 0:
            b = bytearray(a)
        elif choice == 1:
            b[rng.randrange(16)] ^= 1 << rng.randrange(8)
        else:
            b = bytes(rng.randrange(256) for _ in range(16))
        lines.append(f"C:{a.hex()}:{bytes(b).hex()}")
    generated = {"G4": 1500, "G7": 1500}
    for op, count in generated.items():
        lines.append(f"{op}:{count}")
    payload = "".join(line + "\n" for line in lines)

    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "uuid_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust uuid probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/uuid_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_run.returncode:
        raise RuntimeError(f"Go uuid oracle failed:\n{go_run.stderr}")
    rust = rust_run.stdout.splitlines()
    go = go_run.stdout.splitlines()
    if len(rust) != len(lines) or len(go) != len(lines):
        raise AssertionError(f"uuid oracle returned {len(go)} and probe {len(rust)} records for {len(lines)} requests")

    exact = 0
    for i, (actual, expected) in enumerate(zip(rust, go)):
        if lines[i].startswith(("G4:", "G7:")):
            continue
        if actual != expected:
            raise AssertionError(f"vector {i}, request={lines[i][:120]!r}\nRust={actual!r}\nGo={expected!r}")
        exact += 1

    check_generated(lines, rust, go, generated)
    print(f"uuid Go differential: {exact} parse, format, compare and MustParse vectors passed exactly; "
          f"{sum(generated.values()) * 2} NewV4/NewV7 values checked by property on both sides")


def check_generated(lines, rust, go, generated):
    """NewV4 and NewV7: versions, variants, distinctness, timestamps and ordering."""
    for side_name, side in (("Rust", rust), ("Go", go)):
        for i, line in enumerate(lines):
            if not line.startswith(("G4:", "G7:")):
                continue
            values = [bytes.fromhex(h) for h in side[i].split(",") if h]
            assert len(values) == generated[line[:2]], f"{side_name} {line}: {len(values)} values"
            assert all(len(v) == 16 for v in values), f"{side_name} {line}: bad length"
            if line.startswith("G4:"):
                assert all(v[6] >> 4 == 4 and v[8] >> 6 == 2 for v in values), f"{side_name} NewV4 version/variant"
                assert len(set(values)) == len(values), f"{side_name} NewV4 repeated a value"
            else:
                assert all(v[6] >> 4 == 7 and v[8] >> 6 == 2 for v in values), f"{side_name} NewV7 version/variant"
                now_ms = time.time() * 1000
                for v in values:
                    stamp_ms = int.from_bytes(v[:6], "big")
                    assert abs(stamp_ms - now_ms) < 120_000, f"{side_name} NewV7 timestamp {stamp_ms} vs {now_ms:.0f}"
                assert all(a < b for a, b in zip(values, values[1:])), f"{side_name} NewV7 not increasing"
            assert len(values) > 0


if __name__ == "__main__":
    main()
