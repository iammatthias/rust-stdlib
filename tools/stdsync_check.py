#!/usr/bin/env python3
"""Differentially check errors, sync, sync/atomic, hash/maphash, unique and weak against Go.

Each request runs a deterministic, single-goroutine script (no blocking
operations; Go's unlock-of-unlocked fatal errors cannot be recovered, so
those are covered by tests/sync.rs) on both implementations and compares
every result. hash/maphash output values are implementation-defined, so the
requests compare properties (streaming equals one-shot, chunking
independence, Sum layout, seed sensitivity, ...) which must all hold in both.
"""
import random
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RANGES = {
    "i32": (-(2 ** 31), 2 ** 31 - 1), "i64": (-(2 ** 63), 2 ** 63 - 1),
    "u32": (0, 2 ** 32 - 1), "u64": (0, 2 ** 64 - 1), "up": (0, 2 ** 64 - 1),
    "f32": (-(2 ** 31), 2 ** 31 - 1), "f64": (0, 2 ** 64 - 1),
}


def atomic_scripts(rng):
    reqs = []
    for dom, (lo, hi) in RANGES.items():
        def val():
            k = rng.randrange(5)
            return rng.choice([lo, hi, 0, 1, hi - 1, lo + 1 if lo < 0 else 2]) if k == 0 else rng.randrange(lo, hi + 1) if k < 3 else rng.randrange(0, 16)
        for _ in range(250):
            cmds = []
            cur = 0
            for _ in range(rng.randrange(1, 14)):
                op = rng.choice(["load", "store", "swap", "cas", "add", "and", "or", "cas"])
                if op == "load":
                    cmds.append("load")
                elif op in ("store", "swap", "add", "and", "or"):
                    cmds.append(f"{op} {val()}")
                else:
                    # half the time compare against the (unknown) current value guess
                    cmds.append(f"cas {val()} {val()}")
            reqs.append(f"{dom} " + ";".join(cmds))
    for _ in range(100):
        cmds = []
        for _ in range(rng.randrange(1, 10)):
            op = rng.choice(["load", "store", "swap", "cas"])
            cmds.append(op if op == "load" else f"{op} {rng.randrange(2)}" + (f" {rng.randrange(2)}" if op == "cas" else ""))
        reqs.append("bool " + ";".join(cmds))
    for _ in range(150):
        cmds = []
        for _ in range(rng.randrange(1, 10)):
            op = rng.choice(["load", "store", "swap", "cas"])
            if op == "load":
                cmds.append("load")
            elif op == "cas":
                cmds.append(f"cas {rng.choice(['nil', 'a', 'b', 'c'])} {rng.choice(['nil', 'a', 'b', 'c'])}")
            else:
                cmds.append(f"{op} {rng.choice(['nil', 'a', 'b', 'c'])}")
        reqs.append("pointer " + ";".join(cmds))
    for _ in range(200):
        cmds = []
        for _ in range(rng.randrange(1, 10)):
            op = rng.choice(["load", "store", "swap", "cas"])
            kind = rng.choice(["i", "s"])
            v = str(rng.randrange(3)) if kind == "i" else rng.choice(["x", "y"])
            if op == "load":
                cmds.append("load")
            elif op == "cas":
                if rng.randrange(3) == 0:
                    cmds.append(f"cas n - {kind} {v}")
                else:
                    cmds.append(f"cas {kind} {v} {kind} {v}")
            else:
                cmds.append(f"{op} {kind} {v}")
        reqs.append("value " + ";".join(cmds))
    return reqs


def sync_scripts(rng):
    reqs = []
    # Mutex / RWMutex: only emit operations that cannot block or are fatal in Go.
    for _ in range(200):
        cmds = []
        m = False
        w = False
        r = 0
        for _ in range(rng.randrange(1, 14)):
            op = rng.choice(["trylock", "lock", "unlock", "rwtrylock", "rwlock", "rwunlock", "rlock",
                             "tryrlock", "runlock", "rlocker"])
            if op == "lock":
                if m:
                    continue
                m = True
            elif op == "trylock":
                m = m or True if not m else m
            elif op == "unlock":
                if not m:
                    continue
                m = False
            elif op == "rwlock":
                if w or r:
                    continue
                w = True
            elif op == "rwtrylock":
                if not (w or r):
                    w = True
            elif op == "rwunlock":
                if not w:
                    continue
                w = False
            elif op == "rlock":
                if w:
                    continue
                r += 1
            elif op == "tryrlock":
                if not w:
                    r += 1
            elif op == "runlock":
                if r == 0:
                    continue
                r -= 1
            elif op == "rlocker":
                if w:
                    continue
            cmds.append(op)
        if cmds:
            reqs.append("mutex " + ";".join(cmds))
    for _ in range(150):
        cmds = []
        n = 0
        for _ in range(rng.randrange(1, 12)):
            op = rng.choice(["add", "add", "done", "wait", "go"])
            if op == "add":
                d = rng.randrange(-3, 4)
                if n + d >= 0:
                    cmds.append(f"add {d}")
                    n += d
            elif op == "done":
                if n > 0:
                    cmds.append("done")
                    n -= 1
            elif op == "wait":
                cmds.append("wait")
            elif n == 0:
                cmds.append("go")
        reqs.append("wg " + ";".join(cmds))
    reqs.append("wg add -1")
    reqs.append("wg add 2;add -3")
    reqs.append("wg done")
    for _ in range(60):
        reqs.append("once " + ";".join(rng.choice(["do", "dopanic", "count", "do"]) for _ in range(rng.randrange(1, 8))))
    for _ in range(60):
        reqs.append("oncefunc " + ";".join(rng.choice(["f", "v", "vs", "pf", "pv", "calls"]) for _ in range(rng.randrange(1, 14))))
    keys = ["k1", "k2", "k3", "k4"]
    vals = ["v1", "v2", "v3"]
    for _ in range(300):
        cmds = []
        for _ in range(rng.randrange(1, 16)):
            op = rng.choice(["store", "load", "loadorstore", "loadanddelete", "delete", "swap", "cas", "cad",
                             "clear", "range", "rangestop"])
            if op in ("load", "loadanddelete", "delete"):
                cmds.append(f"{op} {rng.choice(keys)}")
            elif op in ("store", "loadorstore", "swap", "cad"):
                cmds.append(f"{op} {rng.choice(keys)} {rng.choice(vals)}")
            elif op == "cas":
                cmds.append(f"cas {rng.choice(keys)} {rng.choice(vals)} {rng.choice(vals)}")
            else:
                cmds.append(op)
        reqs.append("map " + ";".join(cmds))
    for _ in range(40):
        reqs.append("pool put a;get;get;getplain")
        reqs.append("pool get;getplain;put b;getplain;get")
    reqs.append("cond ")
    return reqs


def error_trees(rng):
    reqs = []

    def gen(depth):
        r = rng.randrange(10)
        if depth == 0 or r < 3:
            return rng.choice(["N", f"L{rng.randrange(4)}", f"L{rng.randrange(4)}"])
        if r < 6:
            return f"W({gen(depth - 1)})"
        return "J(" + ",".join(gen(depth - 1) for _ in range(rng.randrange(1, 4))) + ")"

    for t in ["N", "L0", "W(N)", "J(N)", "J(N,N)", "J(L0,N,L1)", "W(J(L0,W(L1)))", "J(W(L0),W(L0))",
              "W(W(W(L2)))", "J(J(L0,L1),J(L2,L3))"]:
        reqs.append("errors " + t)
    for _ in range(400):
        reqs.append("errors " + gen(rng.randrange(1, 5)))
    return reqs


def maphash_scripts(rng):
    reqs = []
    for n in list(range(0, 20)) + [127, 128, 129, 255, 256, 257, 1000]:
        for _ in range(3):
            data = bytes(rng.randrange(128) for _ in range(n))
            chunks = " ".join(str(rng.randrange(0, 70)) for _ in range(rng.randrange(0, 8)))
            reqs.append(f"maphash {data.hex()}:{chunks}")
    return reqs


def misc_scripts(rng):
    reqs = ["weak "]
    for _ in range(40):
        cmds = []
        for _ in range(rng.randrange(1, 9)):
            if rng.randrange(2):
                cmds.append(f"s {rng.choice(['a', 'b', 'c', 'hello', ''])}".rstrip() if False else f"s {rng.choice(['a', 'b', 'c', 'hello'])}")
            else:
                cmds.append(f"i {rng.randrange(4)}")
        reqs.append("unique " + ";".join(cmds))
    return reqs


def main():
    rng = random.Random(0x73796E63)
    reqs = atomic_scripts(rng) + sync_scripts(rng) + error_trees(rng) + maphash_scripts(rng) + misc_scripts(rng)
    payload = "".join(r + "\n" for r in reqs)
    rust = subprocess.run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "stdsync_probe"],
                          input=payload, text=True, capture_output=True, cwd=ROOT)
    if rust.returncode:
        raise RuntimeError(f"Rust stdsync probe failed:\n{rust.stderr}")
    go = subprocess.run(["go", "run", str(ROOT / "tools/stdsync_oracle.go")], input=payload, text=True,
                        capture_output=True, cwd=ROOT)
    if go.returncode:
        raise RuntimeError(f"Go stdsync oracle failed:\n{go.stderr}")
    r_lines, g_lines = rust.stdout.splitlines(), go.stdout.splitlines()
    if len(r_lines) != len(reqs) or len(g_lines) != len(reqs):
        raise AssertionError(f"stdsync oracle returned the wrong number of records "
                             f"({len(r_lines)} rust, {len(g_lines)} go, {len(reqs)} requests)")
    bad = [f"{q}\n  Rust={a}\n  Go  ={e}" for q, a, e in zip(reqs, r_lines, g_lines) if a != e]
    if bad:
        print(f"{len(bad)} mismatches of {len(reqs)}; first 20:")
        print("\n".join(bad[:20]))
        raise SystemExit(1)
    print(f"Errors/sync/atomic/maphash/unique/weak Go differential: {len(reqs)} scripted vectors passed")


if __name__ == "__main__":
    main()
