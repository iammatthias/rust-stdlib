#!/usr/bin/env python3
"""Differentially check reflect against Go.

Types are generated at random (nested slices, arrays, pointers, maps, channels,
functions and structs with embedding, shadowing and tags) and built on both
sides from the same spec text with SliceOf, StructOf, ... Compared per type:
String, Kind, Name, PkgPath, Comparable, Size, Align, struct fields with
offsets, VisibleFields, FieldByName, assignability and convertibility. Values
are built from one literal syntax and compared for DeepEqual (NaN, nil versus
empty, pointers, interfaces), Value.Equal, Value.String, IsZero, Slice, Append,
MapIndex and Set through fields. StructTag.Get/Lookup run on thousands of
random and mutated tags, and Convert on the full numeric kind matrix plus
string and slice conversions. Panics are compared by message.

Float to integer conversions that are out of range, negative to unsigned or NaN
are implementation-defined in Go (arm64 saturates, amd64 does not) and are not
generated.
"""
import math
import pathlib
import random
import struct
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUST = ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "reflect_probe"]
GO = ["go", "run", "tools/reflect_oracle.go"]

INTS = ["int", "int8", "int16", "int32", "int64"]
UINTS = ["uint", "uint8", "uint16", "uint32", "uint64", "uintptr"]
FLOATS = ["float32", "float64"]
COMPLEX = ["complex64", "complex128"]
NUMERIC = INTS + UINTS + FLOATS
BITS = {"int": 64, "int8": 8, "int16": 16, "int32": 32, "int64": 64, "uint": 64, "uint8": 8,
        "uint16": 16, "uint32": 32, "uint64": 64, "uintptr": 64}
BASIC = ["bool"] + NUMERIC + COMPLEX + ["string"]
NAMES = ["A", "B", "C", "D", "Ab", "Z", "X1"]
UNEXP = ["a", "b", "c", "x1"]


def hx(s):
    if isinstance(s, str):
        s = s.encode("utf-8", "surrogateescape")
    return s.hex() or "-"


# ---- type trees ----

def gen_type(rng, depth, exported_only=True, allow_chan=True, comparable=False, nonzero=False):
    """Returns a tree: ('basic', name) | ('slice', t) | ('array', n, t) | ('ptr', t) |
    ('map', k, v) | ('chan', dir, t) | ('func', ins, outs, variadic) | ('struct', fields) | ('any',)."""
    if depth <= 0 or rng.random() < 0.25:
        return ("basic", rng.choice(BASIC))
    choices = ["slice", "array", "ptr", "map", "struct", "struct", "any"]
    if allow_chan:
        choices += ["chan", "func"]
    if comparable:
        choices = ["array", "ptr", "struct", "basic"]
    kind = rng.choice(choices)
    sub = lambda: gen_type(rng, depth - 1, exported_only, allow_chan, comparable, nonzero)
    if kind == "basic":
        return ("basic", rng.choice(BASIC))
    if kind == "slice":
        return ("slice", sub())
    if kind == "array":
        return ("array", rng.randrange(1 if nonzero else 0, 4), sub())
    if kind == "ptr":
        return ("ptr", sub())
    if kind == "any":
        return ("any",)
    if kind == "map":
        k = gen_type(rng, 1, exported_only, False, True, nonzero)
        return ("map", k, sub())
    if kind == "chan":
        return ("chan", rng.choice(["chan", "rchan", "schan"]), sub())
    if kind == "func":
        n = rng.randrange(0, 3)
        ins = [sub() for _ in range(n)]
        variadic = n > 0 and rng.random() < 0.3
        if variadic:
            ins[-1] = ("slice", ins[-1])
        return ("func", ins, [sub() for _ in range(rng.randrange(0, 3))], variadic)
    n = rng.randrange(1 if nonzero else 0, 5)
    fields = []
    pool = list(NAMES)
    for _ in range(n):
        name = rng.choice(pool)
        emb = rng.random() < 0.3
        unexp = (not exported_only) and not emb and rng.random() < 0.2
        if unexp:
            name = rng.choice(UNEXP)
        if emb:
            t = gen_type(rng, depth - 1, exported_only, allow_chan, comparable, nonzero)
            if t[0] not in ("struct", "ptr"):
                t = ("struct", [(rng.choice(NAMES), ("basic", "int"), "", False, False)])
            if rng.random() < 0.3 and t[0] == "struct":
                t = ("ptr", t)
        else:
            t = sub()
        tag = rng.choice(["", "", "", 'json:"x"', 'a:"1" b:"2,omitempty"', "bad tag"])
        fields.append((name, t, tag, emb, unexp))
    return ("struct", fields)


def spec(t):
    k = t[0]
    if k == "basic":
        return t[1]
    if k == "any":
        return "any"
    if k == "slice":
        return "[]" + spec(t[1])
    if k == "array":
        return "[%d]%s" % (t[1], spec(t[2]))
    if k == "ptr":
        return "*" + spec(t[1])
    if k == "map":
        return "map[%s]%s" % (spec(t[1]), spec(t[2]))
    if k == "chan":
        return "%s:%s" % (t[1], spec(t[2]))
    if k == "func":
        ins = ",".join(("..." if t[3] and i == len(t[1]) - 1 else "") + spec(x) for i, x in enumerate(t[1]))
        return "func(%s)(%s)" % (ins, ",".join(spec(x) for x in t[2]))
    parts = []
    for name, ft, tag, emb, unexp in t[1]:
        s = ("@" if emb else "") + name + ("^" if unexp else "") + ":" + spec(ft)
        if tag:
            s += "|" + hx(tag)
        parts.append(s)
    return "{" + ";".join(parts) + "}"


# ---- value trees (nested str / list) ----

def fbits(rng, bits):
    if rng.random() < 0.3:
        specials = [0.0, -0.0, 1.0, -1.0, float("inf"), float("-inf"), float("nan"), 0.5, 1e300, 1e-300, 3.5e38, 1.5]
        f = rng.choice(specials)
    else:
        f = rng.choice([rng.uniform(-100, 100), float(rng.randrange(-1000, 1000))])
    if bits == 32:
        try:
            return "%08x" % struct.unpack("<I", struct.pack("<f", f))[0]
        except OverflowError:
            return "%08x" % struct.unpack("<I", struct.pack("<f", math.copysign(float("inf"), f)))[0]
    return "%016x" % struct.unpack("<Q", struct.pack("<d", f))[0]


def gen_int(rng, name):
    bits = BITS[name]
    signed = name in INTS
    lo, hi = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
    r = rng.random()
    if r < 0.3:
        return str(rng.choice([lo, hi, 0, 1, lo + 1, hi - 1] + ([-1] if signed else [])))
    if r < 0.6:
        return str(rng.randrange(-5, 6) if signed else rng.randrange(0, 6))
    return str(rng.randrange(lo, hi + 1))


def gen_string(rng):
    n = rng.randrange(0, 5)
    pool = [b"a", b"b", "é".encode(), b"\xff", b"\xe1\x80", b"\xf0\x9f\x98\x80", b"\x00", b"z"]
    return hx(b"".join(rng.choice(pool) for _ in range(n)))


def gen_val(rng, t, depth=0):
    k = t[0]
    if k == "basic":
        n = t[1]
        if n == "bool":
            return rng.choice(["t", "f"])
        if n in INTS + UINTS:
            return gen_int(rng, n)
        if n == "float32":
            return fbits(rng, 32)
        if n == "float64":
            return fbits(rng, 64)
        if n == "complex64":
            return [fbits(rng, 32), fbits(rng, 32)]
        if n == "complex128":
            return [fbits(rng, 64), fbits(rng, 64)]
        return gen_string(rng)
    if k in ("chan", "func"):
        return "n"
    if k == "any":
        if rng.random() < 0.3:
            return "n"
        inner = gen_type(rng, 1, True, False, False, True)
        return [hx(spec(inner)), gen_val(rng, inner, depth + 1)]
    if k == "ptr":
        return "n" if rng.random() < 0.3 else [gen_val(rng, t[1], depth + 1)]
    if k == "slice":
        if rng.random() < 0.2:
            return "n"
        return [gen_val(rng, t[1], depth + 1) for _ in range(rng.randrange(0, 4))]
    if k == "array":
        return [gen_val(rng, t[2], depth + 1) for _ in range(t[1])]
    if k == "map":
        if rng.random() < 0.2:
            return "n"
        seen, out = set(), []
        for _ in range(rng.randrange(0, 4)):
            kv = gen_val(rng, t[1], depth + 1)
            if has_nan(kv):
                continue
            key = lit(kv)
            if key in seen:
                continue
            seen.add(key)
            out.append([kv, gen_val(rng, t[2], depth + 1)])
        return out
    return [gen_val(rng, f[1], depth + 1) for f in t[1]]


def has_nan(v):
    if isinstance(v, list):
        return any(has_nan(x) for x in v)
    return v in ("7ff8000000000000", "7fc00000", "7ff8000000000001")


def lit(v):
    if isinstance(v, list):
        return "[" + ",".join(lit(x) for x in v) + "]"
    return v


def mutate(rng, t, v):
    """A value close to v: sometimes identical, sometimes one part changed."""
    r = rng.random()
    if r < 0.35:
        return v
    if r < 0.45 or not isinstance(v, list):
        return gen_val(rng, t)
    k = t[0]
    if k == "ptr" and v:
        return [mutate(rng, t[1], v[0])]
    if k == "slice":
        if not v:
            return rng.choice([[], "n", [gen_val(rng, t[1])]])
        i = rng.randrange(len(v))
        return v[:i] + [mutate(rng, t[1], v[i])] + v[i + 1:]
    if k == "array" and v:
        i = rng.randrange(len(v))
        return v[:i] + [mutate(rng, t[2], v[i])] + v[i + 1:]
    if k == "struct" and v:
        i = rng.randrange(len(v))
        return v[:i] + [mutate(rng, t[1][i][1], v[i])] + v[i + 1:]
    if k == "map":
        return gen_val(rng, t)
    if k == "any" and len(v) == 2:
        return [v[0], v[1]]
    return gen_val(rng, t)


# ---- tags ----

def gen_tag(rng):
    keys = ["json", "xml", "a", "b", "k", "key"]
    values = ['x', 'a,b', '', 'q\\"r', 'tab\\t', '\\u00e9', '\\x41', 'caf\\u00e9', 'bad\\q', 'a b']
    parts = []
    for _ in range(rng.randrange(0, 4)):
        parts.append('%s:"%s"' % (rng.choice(keys), rng.choice(values)))
    tag = rng.choice([" ", "  ", " "]).join(parts)
    if rng.random() < 0.5:
        # Mutate: delete, insert or replace a byte with something nasty.
        data = bytearray(tag.encode())
        for _ in range(rng.randrange(1, 3)):
            op = rng.randrange(3)
            junk = rng.choice([b'"', b":", b" ", b"\\", b"\x7f", b"\x01", b"\xc3", b"\xff", b"k", b"\n"])
            if op == 0 and data:
                del data[rng.randrange(len(data))]
            elif op == 1:
                data.insert(rng.randrange(len(data) + 1), junk[0])
            elif data:
                data[rng.randrange(len(data))] = junk[0]
        return bytes(data), rng.choice(keys + ["", "x", "k:"])
    return tag.encode(), rng.choice(keys + ["", "x"])


# ---- conversion matrix ----

def conv_requests(rng):
    reqs = []
    for src in INTS + UINTS:
        for dst in NUMERIC + ["string"]:
            for _ in range(12):
                reqs.append("C %s %s %s" % (src, dst, gen_int(rng, src)))
    for src in FLOATS:
        for dst in INTS + UINTS + FLOATS:
            for _ in range(10):
                if dst in FLOATS:
                    reqs.append("C %s %s %s" % (src, dst, fbits(rng, 32 if src == "float32" else 64)))
                    continue
                bits = BITS[dst]
                signed = dst in INTS
                for _try in range(20):
                    f = rng.choice([0.0, 1.0, 0.5, 1.9, 255.5, 65535.9, 1e9, 4294967295.5, 1e15, 9.2e18, 1.8e19,
                                    rng.uniform(0, 3e9), -0.0]) * (rng.choice([-1, 1]) if signed else 1)
                    if signed and abs(f) >= 2.0 ** 63:
                        continue
                    if not signed and not (0 <= f < 2.0 ** 64):
                        continue
                    if src == "float32":
                        try:
                            b = "%08x" % struct.unpack("<I", struct.pack("<f", f))[0]
                        except OverflowError:
                            continue
                        f32 = struct.unpack("<f", struct.pack("<I", int(b, 16)))[0]
                        if (signed and abs(f32) >= 2.0 ** 63) or (not signed and not (0 <= f32 < 2.0 ** 64)):
                            continue
                        reqs.append("C %s %s %s" % (src, dst, b))
                    else:
                        reqs.append("C %s %s %016x" % (src, dst, struct.unpack("<Q", struct.pack("<d", f))[0]))
                    break
    for src, dst in [("complex64", "complex128"), ("complex128", "complex64"), ("complex128", "complex128")]:
        for _ in range(20):
            bits = 32 if src == "complex64" else 64
            reqs.append("C %s %s [%s,%s]" % (src, dst, fbits(rng, bits), fbits(rng, bits)))
    for _ in range(300):
        s = gen_string(rng)
        for dst in ["[]uint8", "[]int32", "string"]:
            reqs.append("C string %s %s" % (dst, s))
        reqs.append("C []uint8 string [%s]" % ",".join(gen_int(rng, "uint8") for _ in range(rng.randrange(0, 5))))
        reqs.append("C []int32 string [%s]" % ",".join(gen_int(rng, "int32") for _ in range(rng.randrange(0, 5))))
        n = rng.randrange(0, 4)
        elems = ",".join(gen_int(rng, "int") for _ in range(n))
        reqs.append("C []int [3]int [%s]" % elems)
        reqs.append("C []int *[2]int [%s]" % elems)
        reqs.append("C []int []int8 [%s]" % elems)
    reqs.append("C int int8 5")
    reqs.append("C bool int t")
    reqs.append("C string int 61")
    return reqs


def build_requests():
    rng = random.Random(0x7EF1)
    reqs = []
    for _ in range(1500):
        t = gen_type(rng, rng.randrange(1, 4), exported_only=False)
        s = spec(t)
        reqs.append("T " + s)
        if t[0] == "struct":
            reqs.append("V " + s)
            for name in NAMES + UNEXP + ["Q"]:
                reqs.append("N %s %s" % (s, hx(name)))
            for pre in ["A", "B", "a", "Z", "X"]:
                reqs.append("NF %s %s" % (s, hx(pre)))
        u = gen_type(rng, 2, exported_only=False)
        reqs.append("R %s %s" % (s, spec(u)))
    # Shadowing and embedding cases that StructOf allows.
    inner = "{A:int;B:string}"
    for s in ["{A:int;@X:%s}" % inner, "{@X:%s;@Y:%s}" % (inner, inner), "{@X:*%s;B:bool}" % inner,
              "{@X:{@Y:%s};A:int}" % inner, "{@X:{@Y:%s};@Z:%s}" % (inner, inner)]:
        reqs += ["T " + s, "V " + s] + ["N %s %s" % (s, hx(n)) for n in "ABXYZ"]
    for bad in ["{A:int;A:int}", "{a:int}", "{:int}", "{1a:int}", "{A:map[[]int]int}", "[-1]int", "{@A:**int}",
                "{@A:*any}", "func(int)(int)", "func(...int)(int)", "map[string]chan:int"]:
        reqs.append("T " + bad)
    # StructTag.
    for _ in range(4000):
        tag, key = gen_tag(rng)
        reqs.append("G %s %s" % (hx(tag), hx(key)))
    for tag in ['a:"b"', 'a:"b" c:"d"', 'a:"b\\"c"', 'a:"b', 'a:b', ' a:"b"', 'a:"\\u00e9"', '', ' ',
                'a:"1" a:"2"', 'a:"\\q"', 'a\x7f:"b"', 'x:"y"z:"w"', ':"b"', 'a: "b"']:
        for key in ["a", "c", "x", "z", ""]:
            reqs.append("G %s %s" % (hx(tag), hx(key)))
    # Values.
    for _ in range(2500):
        t = gen_type(rng, rng.randrange(1, 4), nonzero=True)
        s = spec(t)
        a = gen_val(rng, t)
        b = mutate(rng, t, a)
        reqs.append("D %s %s %s" % (s, lit(a), lit(b)))
        reqs.append("D %s %s %s" % (s, lit(a), lit(a)))
    for _ in range(800):
        t = gen_type(rng, rng.randrange(1, 4), nonzero=True)
        s = spec(t)
        v = gen_val(rng, t)
        reqs.append("S %s %s" % (s, lit(v)))
        reqs.append("Z " + s)
    for _ in range(400):
        et = gen_type(rng, 2, nonzero=True)
        t = ("slice", et)
        s = spec(t)
        v = gen_val(rng, t)
        n = len(v) if isinstance(v, list) else 0
        i = rng.randrange(-1, n + 2)
        j = rng.randrange(-1, n + 2)
        reqs.append("L %s %s %d %d" % (s, lit(v), i, j))
        reqs.append("L %s %s %d %d %d" % (s, lit(v), i, j, rng.randrange(-1, n + 2)))
        reqs.append("A %s %s %s" % (s, lit(v), " ".join(lit(gen_val(rng, et)) for _ in range(rng.randrange(0, 3)))))
        a = ("array", rng.randrange(0, 4), et)
        reqs.append("L %s %s 0 1" % (spec(a), lit(gen_val(rng, a))))
    for _ in range(300):
        kt = gen_type(rng, 1, True, False, True, True)
        vt = gen_type(rng, 2, nonzero=True)
        t = ("map", kt, vt)
        v = gen_val(rng, t)
        key = v[0][0] if isinstance(v, list) and v else gen_val(rng, kt)
        reqs.append("M %s %s %s" % (spec(t), lit(v), lit(key)))
        reqs.append("M %s %s %s" % (spec(t), lit(v), lit(gen_val(rng, kt))))
    for _ in range(300):
        t = gen_type(rng, 3, nonzero=True)
        if t[0] != "struct":
            continue
        v = gen_val(rng, t)
        i = rng.randrange(len(t[1])) if t[1] else 0
        if not t[1]:
            continue
        ft = t[1][i][1]
        reqs.append("E %s %s %d %s" % (spec(t), lit(v), i, lit(gen_val(rng, ft))))
        reqs.append("E %s %s %d %s" % (spec(t), lit(v), i + 7, "n"))
    # Overflow.
    for name in INTS:
        for x in [0, 1, -1, 127, 128, -128, -129, 32767, 32768, 2 ** 31, -2 ** 31 - 1, 2 ** 63 - 1, -2 ** 63]:
            reqs.append("O %s %d" % (name, x))
    for name in UINTS:
        for x in [0, 1, 255, 256, 65535, 65536, 2 ** 32 - 1, 2 ** 32, 2 ** 64 - 1]:
            reqs.append("O %s %d" % (name, x))
    for name in FLOATS + COMPLEX:
        for f in [0.0, 1.0, 3.4e38, 3.5e38, -3.5e38, 1e300, float("inf"), float("nan")]:
            reqs.append("O %s %016x" % (name, struct.unpack("<Q", struct.pack("<d", f))[0]))
    reqs += conv_requests(rng)
    return reqs


def run(cmd, payload, what):
    res = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if res.returncode:
        raise RuntimeError(f"{what} failed:\n{res.stderr[-3000:]}")
    return res.stdout.split("\n")[:-1]


def main():
    reqs = build_requests()
    payload = "".join(r + "\n" for r in reqs)
    rust = run(RUST, payload, "Rust reflect probe")
    go = run(GO, payload, "Go reflect oracle")
    if len(rust) != len(reqs) or len(go) != len(reqs):
        raise AssertionError(f"record count: rust={len(rust)} go={len(go)} want={len(reqs)}")
    bad = [i for i in range(len(reqs)) if rust[i] != go[i]]
    kinds = {}
    for r in reqs:
        kinds[r.split(" ")[0]] = kinds.get(r.split(" ")[0], 0) + 1
    if bad:
        shown = {}
        for i in bad:
            op = reqs[i].split(" ")[0]
            if shown.get(op, 0) < 4:
                shown[op] = shown.get(op, 0) + 1
                print(f"MISMATCH {reqs[i]}\n  rust: {rust[i]}\n  go:   {go[i]}")
        raise SystemExit(f"{len(bad)} of {len(reqs)} reflect vectors differ")
    panics = sum(1 for x in go if x.startswith("panic:"))
    print(f"reflect: {len(reqs)} vectors match Go ({panics} identical panics; " +
          ", ".join(f"{k}={v}" for k, v in sorted(kinds.items())) + ")")


if __name__ == "__main__":
    main()
