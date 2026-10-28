#!/usr/bin/env python3
"""Differentially check expvar against Go.

Seeded scripts create Int, Float, Map, String and Func variables (published
and standalone), update and read them, use Map.Add/AddFloat/Set/Get/Delete/Do,
and Publish/Get, comparing every rendered value and panic exactly with Go.
Requests are documented in tools/expvar_oracle.go; the Rust side is
examples/expvar_probe.rs. Each script has its own name prefix because the
registry is process-wide.
"""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]

INTS = ["0", "1", "-1", "123", "9223372036854775807", "-9223372036854775808",
        "4611686018427387904", "-4611686018427387905"]
FLOATS = ["0", "-0", "1e21", "1e-7", "123456789.125", "0.1", "NaN", "Inf", "-Inf", "1e100",
          "2.5e-300", "3.14159", "1.7976931348623157e308", "5e-324", "-2.5", "100", "1e6"]
STRINGS = ["", "plain", "<>&", "quote\"back\\slash", "tab\tnl\n", "   ",
           "é本\U0001F600", "\x01\x1f\x7f", "x" * 40, "a'b"]
KEYS = ["", "k", "a b", "<k>", "é", " ", "q\"", "back\\", "z", "a", "m\nn"]
FUNCS = [0, 1, 2, 3]


def h(text):
    return text.encode("utf-8").hex()


def script(rng, index):
    prefix = f"x{index}."
    ops = []
    kinds = {}  # local name -> kind: i, f, m, s, c
    published = []  # local names registered with Publish or New*
    serial = 0

    def fresh():
        nonlocal serial
        serial += 1
        return f"v{serial}"

    def pick(kind):
        names = [n for n, k in kinds.items() if k == kind]
        return rng.choice(names) if names else None

    for _ in range(rng.randrange(10, 40)):
        r = rng.random()
        if r < 0.22:
            op = rng.choice(["ni", "nf", "nm", "ns", "si", "sf", "sm", "ss", "fn"])
            name = fresh()
            if op == "fn":
                ops.append(f"fn:{name}:{rng.choice(FUNCS)}")
            else:
                ops.append(f"{op}:{name}")
            if op[0] == "n":
                published.append(name)
            kinds[name] = {"ni": "i", "nf": "f", "nm": "m", "ns": "s", "si": "i", "sf": "f",
                           "sm": "m", "ss": "s", "fn": "c"}[op]
        elif r < 0.27 and kinds:
            name = rng.choice(list(kinds))
            pub = fresh()
            ops.append(f"pub:{name}:{h(pub)}")
            published.append(pub)
        elif r < 0.31:
            if published and rng.random() < 0.7:
                ops.append(f"get:{h(rng.choice(published))}")
            else:
                ops.append(f"get:{h('missing' + str(rng.randrange(3)))}")
        elif r < 0.40:
            name = pick("i")
            if name:
                ops.append(f"add:{name}:{rng.choice(INTS)}")
        elif r < 0.45:
            name = pick("i")
            if name:
                ops.append(f"set:{name}:{rng.choice(INTS)}")
        elif r < 0.50:
            name = pick("f")
            if name:
                ops.append(f"addf:{name}:{rng.choice(FLOATS)}")
        elif r < 0.54:
            name = pick("f")
            if name:
                ops.append(f"set:{name}:{rng.choice(FLOATS)}")
        elif r < 0.57:
            name = pick("s")
            if name:
                ops.append(f"set:{name}:{h(rng.choice(STRINGS))}")
        elif r < 0.66:
            name = pick("m")
            if name:
                key = h(rng.choice(KEYS))
                kind_roll = rng.random()
                if kind_roll < 0.35:
                    ops.append(f"madd:{name}:{key}:{rng.choice(INTS)}")
                elif kind_roll < 0.55:
                    ops.append(f"maddf:{name}:{key}:{rng.choice(FLOATS)}")
                elif kind_roll < 0.75:
                    # Maps are never stored in maps: a cycle recurses without bound in Go too.
                    targets = [n for n, k in kinds.items() if k != "m"]
                    if targets:
                        ops.append(f"mset:{name}:{key}:{rng.choice(targets)}")
                elif kind_roll < 0.85:
                    ops.append(f"mdel:{name}:{key}")
                else:
                    ops.append(f"mget:{name}:{key}")
        elif r < 0.69:
            name = pick("m")
            if name:
                ops.append(f"mdo:{name}")
        elif r < 0.71:
            name = pick("m")
            if name:
                ops.append(f"minit:{name}")
        elif r < 0.85 and kinds:
            name = rng.choice(list(kinds))
            ops.append(f"str:{name}")
        elif kinds:
            name = rng.choice(list(kinds))
            ops.append(f"val:{name}")
    if published and rng.random() < 0.5:
        # Publishing an existing name again panics in both implementations.
        ops.append(f"ni:{published[0]}")
    return prefix, ops


def main():
    rng = random.Random(0xE5A2)
    lines = []
    for index in range(400):
        prefix, ops = script(rng, index)
        lines.append("|".join([prefix] + ops))
    payload = "".join(line + "\n" for line in lines)

    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "expvar_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust expvar probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/expvar_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_run.returncode:
        raise RuntimeError(f"Go expvar oracle failed:\n{go_run.stderr}")
    rust = rust_run.stdout.splitlines()
    go = go_run.stdout.splitlines()
    if len(rust) != len(lines) or len(go) != len(lines):
        raise AssertionError(
            f"expvar oracle returned {len(go)} and probe {len(rust)} scripts for {len(lines)} requests")
    records = 0
    for i, (actual, expected) in enumerate(zip(rust, go)):
        if actual != expected:
            a, e = actual.split(" "), expected.split(" ")
            for j, (x, y) in enumerate(zip(a, e)):
                if x != y:
                    raise AssertionError(
                        f"script {i} op {j}: request={lines[i][:200]!r}\nRust={x!r}\nGo={y!r}")
            raise AssertionError(f"script {i}: record count Rust={len(a)} Go={len(e)}")
        records += len(expected.split(" "))
    print(f"expvar Go differential: {len(lines)} scripts, {records} operation records passed")


if __name__ == "__main__":
    main()
