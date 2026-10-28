#!/usr/bin/env python3
"""Differentially check sort, slices, maps, cmp, iter and container/{heap,list,ring} against Go.

Unstable sorts (sort.Sort, sort.Slice, slices.Sort, slices.SortFunc) are
implementation-defined for equal elements, so for those the oracle output is
the sorted key sequence plus the keys re-ordered by original index, which
proves sortedness and that the multiset of records is preserved. Stable
sorts, heap, list and ring operation scripts are compared exactly.
"""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]

NAN = ["7ff8000000000000", "fff8000000000001", "7ff0000000000001", "ffffffffffffffff"]
FLOATS = NAN + ["0000000000000000", "8000000000000000", "3ff0000000000000", "bff0000000000000",
                "4004000000000000", "7ff0000000000000", "fff0000000000000", "3ff0000000000001"]


def int_arrays(rng):
    sizes = [0, 1, 2, 3, 12, 13, 14, 20, 40, 49, 50, 51, 100, 257, 1000]
    for n in sizes:
        for k in (1, 2, 5, 50, 100000):
            yield [rng.randrange(k) for _ in range(n)]
        base = sorted(rng.randrange(max(n // 3, 1)) for _ in range(n))
        yield base
        yield base[::-1]
        yield [min(i, n - i) for i in range(n)]
        yield [i % 7 for i in range(n)]
        near = list(base)
        for _ in range(min(3, n // 2)):
            i, j = rng.randrange(n), rng.randrange(n)
            near[i], near[j] = near[j], near[i]
        yield near
    # Go's adversary-style input: forces unbalanced partitions.
    for n in (100, 1000):
        yield [n - 1 - i if i % 2 else i for i in range(n)]
        yield [(i * 7919) % n for i in range(n)]


def float_arrays(rng):
    for n in [0, 1, 2, 5, 12, 13, 50, 51, 120, 400]:
        for _ in range(4):
            yield [rng.choice(FLOATS) for _ in range(n)]


def fkey(bits):
    import struct
    v = struct.unpack(">d", bytes.fromhex(bits))[0]
    return (0, 0.0) if v != v else (1, v)


def vectors():
    rng = random.Random(0x50127)
    out = []
    arrays = list(int_arrays(rng))
    algos = ["sort", "rsort", "stable", "rstable", "slice", "slicestable", "sortfunc", "sortstablefunc"]
    for i, a in enumerate(arrays):
        for algo in algos:
            out.append(f"SORT {algo} " + " ".join(map(str, a)))
        if i % 3 == 0:
            for algo in ("sorted", "ints", "intslice", "strings"):
                out.append(f"SORT {algo} " + " ".join(map(str, a)))
    for a in float_arrays(rng):
        out.append("FSORT " + " ".join(a))
        if a:
            out.append("FMM " + " ".join(a))
    for a in float_arrays(rng):
        s = sorted(a, key=fkey)
        for _ in range(3):
            out.append("FSEARCH " + " ".join([rng.choice(FLOATS)] + s))
    for a in int_arrays(rng):
        s = sorted(a)
        for _ in range(2):
            out.append("ISEARCH " + " ".join(map(str, [rng.randrange(-1, 12)] + s)))
    for x in FLOATS:
        for y in FLOATS:
            out.append(f"CMP {x} {y}")
    # slices
    for _ in range(600):
        n = rng.randrange(0, 15)
        a = [rng.randrange(0, 8) for _ in range(n)]
        b = [rng.randrange(0, 8) for _ in range(rng.randrange(0, 6))]
        sa, sb = " ".join(map(str, a)), " ".join(map(str, b))
        i = rng.randrange(0, n + 1)
        j = rng.randrange(i, n + 1)
        out.append(f"SL compact ; {sa}")
        out.append(f"SL compactfunc ; {sa}")
        out.append(f"SL deletefunc ; {sa}")
        out.append(f"SL reverse ; {sa}")
        out.append(f"SL delete {i} {j} ; {sa}")
        out.append(f"SL insert {i} ; {sa} ; {sb}")
        out.append(f"SL replace {i} {j} ; {sa} ; {sb}")
        out.append(f"SL index {rng.randrange(0, 8)} ; {sa}")
        out.append(f"SL repeat {rng.randrange(0, 4)} ; {sa}")
        out.append(f"SL chunk {rng.randrange(1, 5)} ; {sa}")
        out.append(f"SL compare ; {sa} ; {sb}")
        out.append(f"SL compare ; {sa} ; {sa}")
        out.append(f"SL concat ; {sa} ; {sb}")
        out.append(f"SL backward ; {sa} ; {sb}")
        if n:
            out.append(f"SL minmax ; {sa}")
    # maps
    for _ in range(300):
        def m():
            return " ".join(f"{k}:{rng.randrange(10)}" for k in rng.sample(range(16), rng.randrange(0, 10)))
        m1 = m()
        out.append(f"MAP {m1} ; {m()}")
        out.append(f"MAP {m1} ; {m1}")
    # iter.Pull
    for n in range(0, 8):
        for stop in range(0, n + 3):
            out.append("PULL " + " ".join(map(str, [stop] + list(range(10, 10 + n)))))
    # heap
    for _ in range(400):
        ops, size = [], 0
        n0 = rng.randrange(0, 40)
        ops.append("init " + " ".join(str(rng.randrange(0, 12)) for _ in range(n0)))
        size = n0
        for _ in range(rng.randrange(1, 60)):
            c = rng.choice(["push", "push", "pop", "remove", "fix", "init"])
            if c == "push":
                ops.append(f"push {rng.randrange(0, 12)}")
                size += 1
            elif c == "init":
                k = rng.randrange(0, 20)
                ops.append("init " + " ".join(str(rng.randrange(0, 12)) for _ in range(k)))
                size = k
            elif size == 0:
                continue
            elif c == "pop":
                ops.append("pop")
                size -= 1
            elif c == "remove":
                ops.append(f"remove {rng.randrange(size)}")
                size -= 1
            else:
                ops.append(f"fix {rng.randrange(size)} {rng.randrange(0, 12)}")
        out.append("HEAP " + " ; ".join(ops))
    # list
    for _ in range(500):
        ops = []
        handles = []  # [owner, alive]
        usable = lambda: [h for h, (o, a, dead) in enumerate(handles) if not dead]
        for _ in range(rng.randrange(1, 50)):
            L = rng.choice("AB")
            u = usable()
            c = rng.choice(["pb", "pf", "pb", "pf", "ib", "ia", "rm", "mf", "mb", "mbf", "maf",
                            "pbl", "pfl", "sv", "nx", "pv", "init" if rng.random() < 0.15 else "pb"])
            v = rng.randrange(100)
            if c in ("pb", "pf"):
                handles.append([L, True, False])
                ops.append(f"{L} {c} {v}")
            elif c == "pbl" or c == "pfl":
                ops.append(f"{L} {c}")
            elif c == "init":
                for h in handles:
                    if h[0] == L:
                        h[2] = True
                ops.append(f"{L} init")
            elif not u:
                continue
            elif c in ("ib", "ia"):
                m = rng.choice(u)
                ok = handles[m][0] == L and handles[m][1]
                if ok:
                    handles.append([L, True, False])
                ops.append(f"{L} {c} {v} {m}")
            elif c == "rm":
                h = rng.choice(u)
                if handles[h][0] == L:
                    handles[h][1] = False
                ops.append(f"{L} rm {h}")
            elif c in ("mf", "mb"):
                ops.append(f"{L} {c} {rng.choice(u)}")
            elif c in ("mbf", "maf"):
                ops.append(f"{L} {c} {rng.choice(u)} {rng.choice(u)}")
            elif c == "sv":
                ops.append(f"{L} sv {rng.choice(u)} {v}")
            else:
                ops.append(f"{L} {c} {rng.choice(u)}")
        out.append("LIST " + " ; ".join(ops))
    # ring
    for _ in range(500):
        ops = [f"new {i} {rng.randrange(0, 8)}" for i in range(rng.randrange(1, 3))]
        for _ in range(rng.randrange(1, 40)):
            c = rng.choice(["mv", "link", "link", "unlink", "unlink", "nx", "pv", "sv", "new"])
            a, b, d = (rng.randrange(4) for _ in range(3))
            if c == "mv":
                ops.append(f"mv {a} {b} {rng.randrange(-8, 9)}")
            elif c == "link":
                ops.append(f"link {a} {b} {d}")
            elif c == "unlink":
                ops.append(f"unlink {a} {rng.randrange(-1, 8)} {d}")
            elif c == "new":
                ops.append(f"new {a} {rng.randrange(0, 6)}")
            elif c == "sv":
                ops.append(f"sv {a} {rng.randrange(100, 200)}")
            else:
                ops.append(f"{c} {a} {b}")
        out.append("RING " + " ; ".join(ops))
    return out


def run(cmd, payload):
    r = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if r.returncode:
        raise RuntimeError(f"{cmd} failed:\n{r.stderr[-3000:]}")
    return r.stdout.splitlines()


def main():
    reqs = vectors()
    payload = "".join(r + "\n" for r in reqs)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "collections_probe"], payload)
    go = run(["go", "run", str(ROOT / "tools/collections_oracle.go")], payload)
    if len(rust) != len(reqs) or len(go) != len(reqs):
        raise AssertionError(f"wrong record count: rust={len(rust)} go={len(go)} want={len(reqs)}")
    for i, (a, e) in enumerate(zip(rust, go)):
        if a != e:
            raise AssertionError(f"vector {i}: {reqs[i][:300]!r}\nRust={a[:600]!r}\nGo  ={e[:600]!r}")
    print(f"collections Go differential: {len(reqs)} vectors passed")


if __name__ == "__main__":
    main()
