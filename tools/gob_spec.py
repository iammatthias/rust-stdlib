#!/usr/bin/env python3
"""One description of the gob differential's types, from which both the Go
types (tools/gob_types_gen.go) and the Rust #[derive(Reflect)] types
(tools/derive-check/examples/gob_types_gen.rs) are written, and from which the
value literals the two probes parse are drawn.

Literal syntax (parsed type-directed by both probes):
  n                 zero / nil / not set
  t f               bool
  123 -4            ints and uints
  <bits>            floats, as the decimal bit pattern (u64; u32 for float32)
  <re>:<im>         complex128, as float64 bit patterns
  <hex> or -        string / []byte (empty is -)
  [a,b,c]           slice or array ([] is the empty, non-nil slice)
  {a,b,c}           struct, one literal per field in declaration order; _ is
                    an unexported field
  m[k=v;k=v]        map
  &lit              pointer
  @Key:lit          interface holding a registered type
"""
import random

BASIC = ["bool", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16",
         "uint32", "uint64", "float32", "float64", "complex128", "string"]
KEYS = ["bool", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16",
        "uint32", "uint64", "string"]
RUST_BASIC = {
    "bool": "bool", "int": "isize", "int8": "i8", "int16": "i16", "int32": "i32",
    "int64": "i64", "uint": "usize", "uint8": "u8", "uint16": "u16", "uint32": "u32",
    "uint64": "u64", "float32": "f32", "float64": "f64",
    "complex128": "rust_stdlib::strconv::Complex", "string": "String",
}
SPECIAL = ["GE", "BM", "GP"]
BITS = {"int8": 8, "int16": 16, "int32": 32, "int64": 64, "int": 64,
        "uint8": 8, "uint16": 16, "uint32": 32, "uint64": 64, "uint": 64}


def go(t):
    k = t[0]
    if k == "b":
        return t[1]
    if k == "bytes":
        return "[]byte"
    if k == "slice":
        return "[]" + go(t[1])
    if k == "array":
        return "[%d]%s" % (t[1], go(t[2]))
    if k == "map":
        return "map[%s]%s" % (go(t[1]), go(t[2]))
    if k == "ptr":
        return "*" + go(t[1])
    if k == "any":
        return "any"
    return t[1]


def rust(t):
    k = t[0]
    if k == "b":
        return RUST_BASIC[t[1]]
    if k == "bytes":
        return "Vec<u8>"
    if k == "slice":
        return "Vec<%s>" % rust(t[1])
    if k == "array":
        return "[%s; %d]" % (rust(t[2]), t[1])
    if k == "map":
        return "BTreeMap<%s, %s>" % (rust(t[1]), rust(t[2]))
    if k == "ptr":
        inner = rust(t[1])
        return "Option<%s>" % (inner if t[1][0] in ("ptr", "any") else "Box<%s>" % inner)
    if k == "any":
        return "Value"
    return t[1]


def key(t):
    """The name by which the probes know a type."""
    return go(t)


class Struct:
    def __init__(self, name, fields):
        self.name = name
        # fields: (name, type, exported, embedded)
        self.fields = fields


def rand_type(rng, structs, depth, selfname=None):
    """A random field type; `structs` are the struct types it may mention."""
    r = rng.random()
    if depth <= 0 or r < 0.35:
        return ("b", rng.choice(BASIC))
    if r < 0.42:
        return ("bytes",)
    if r < 0.55:
        inner = rand_type(rng, structs, depth - 1, selfname)
        return ("bytes",) if inner == ("b", "uint8") else ("slice", inner)
    if r < 0.62:
        return ("array", rng.randint(0, 4), rand_type(rng, structs, depth - 1, selfname))
    if r < 0.70:
        return ("map", ("b", rng.choice(KEYS)), rand_type(rng, structs, depth - 1, selfname))
    if r < 0.78:
        return ("ptr", rand_type(rng, structs, depth - 1, selfname))
    if r < 0.84:
        return ("any",)
    pool = [s.name for s in structs] + SPECIAL
    return ("s", rng.choice(pool))


def build(seed=20240611, nstructs=14):
    rng = random.Random(seed)
    structs = []
    for i in range(nstructs):
        fields = []
        used_embed = set()
        for j in range(rng.randint(1, 7)):
            if structs and rng.random() < 0.12:
                cand = rng.choice(structs).name
                if cand not in used_embed:
                    used_embed.add(cand)
                    fields.append((cand, ("s", cand), True, True))
                    continue
            exported = rng.random() > 0.15
            name = ("F%d" if exported else "u%d") % j
            fields.append((name, rand_type(rng, structs, 2), exported, False))
        structs.append(Struct("S%d" % i, fields))
    fixed = [
        Struct("R", [("V", ("b", "int"), True, False), ("N", ("ptr", ("s", "R")), True, False),
                     ("K", ("slice", ("s", "R")), True, False),
                     ("M", ("map", ("b", "string"), ("ptr", ("s", "R"))), True, False)]),
        Struct("MA", [("B", ("ptr", ("s", "MB")), True, False), ("V", ("b", "string"), True, False)]),
        Struct("MB", [("A", ("slice", ("s", "MA")), True, False), ("W", ("b", "int"), True, False)]),
        Struct("Empty", []),
        Struct("NoExp", [("a", ("b", "int"), False, False), ("b", ("b", "string"), False, False)]),
        Struct("Unreg", [("A", ("b", "int"), True, False), ("B", ("slice", ("b", "string")), True, False)]),
        Struct("Wrap", [("E", ("s", "Empty"), True, False), ("Z", ("b", "int"), True, False),
                        ("P", ("ptr", ("s", "Empty")), True, False)]),
    ]
    structs += fixed
    # Twins for the schema-evolution vectors: fields dropped, reordered,
    # retyped within a wire kind, renamed, or retyped across kinds.
    twins = []
    for s in structs[:nstructs]:
        fields = [f for f in s.fields if f[2]]
        mode = rng.randrange(5)
        new = []
        for f in fields:
            t = f[1]
            if mode == 0 and rng.random() < 0.4:
                continue  # drop
            if mode == 1 and t[0] == "b" and t[1] in BITS:
                wide = ("b", "int64") if t[1].startswith("int") else ("b", "uint64")
                t = wide
            if mode == 2 and t[0] == "b" and t[1] in BITS and rng.random() < 0.5:
                t = ("b", "string")  # incompatible
            if mode == 3 and not f[3]:
                f = ("X" + f[0], t, True, False)  # renamed: the old field is ignored
                new.append(f)
                continue
            new.append((f[0], t, True, f[3]))
        if mode == 4:
            new.reverse()
        if mode == 0 and rng.random() < 0.5:
            new.append(("Extra", ("b", "int"), True, False))
        twins.append(Struct(s.name + "v", new))
    return structs, twins


def registered(structs, rng_seed=7):
    """The concrete types usable inside interface values, by key."""
    rng = random.Random(rng_seed)
    keys = list(BASIC)
    keys += ["[]string", "[]int", "[]float64", "[]uint8", "[]bool"]
    for s in structs:
        if s.name == "Unreg":
            continue
        keys.append(("*" if rng.random() < 0.4 else "") + s.name)
    keys += ["GE", "BM", "*GP"]
    return keys


def tops(structs):
    """Top-level types the probes can encode, keyed by name."""
    out = {}
    for b in BASIC:
        out[b] = ("b", b)
    out["[]byte"] = ("bytes",)
    out["any"] = ("any",)
    for s in structs:
        out[s.name] = ("s", s.name)
    for n in SPECIAL:
        out[n] = ("s", n)
    for t in [("slice", ("b", "string")), ("slice", ("b", "int")), ("slice", ("b", "float64")),
              ("array", 3, ("b", "int")), ("array", 2, ("s", "S0")), ("array", 0, ("b", "int")),
              ("map", ("b", "string"), ("b", "int")), ("map", ("b", "int"), ("s", "S1")),
              ("map", ("b", "string"), ("slice", ("b", "int8"))),
              ("ptr", ("s", "S2")), ("ptr", ("b", "int")), ("ptr", ("ptr", ("s", "S3"))),
              ("slice", ("ptr", ("s", "S4"))), ("slice", ("any",)), ("map", ("b", "string"), ("any",)),
              ("array", 2, ("any",)), ("slice", ("s", "GE")), ("slice", ("s", "BM")),
              ("map", ("b", "string"), ("s", "GE")), ("slice", ("slice", ("b", "bool"))),
              ("slice", ("map", ("b", "string"), ("b", "int"))), ("ptr", ("s", "GE")),
              ("ptr", ("s", "GP")), ("slice", ("s", "GP")),
              ("slice", ("bytes",)), ("array", 2, ("bytes",)), ("map", ("b", "string"), ("bytes",)),
              ("slice", ("b", "complex128")), ("slice", ("b", "int8")),
              ("slice", ("b", "uint16")), ("slice", ("b", "int16")), ("slice", ("b", "int32")),
              ("slice", ("b", "uint32")), ("slice", ("b", "float32")), ("slice", ("b", "bool"))]:
        out[key(t)] = t
    return out


# ---- literals ----

def f64_bits(x):
    import struct
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def f32_bits(x):
    import struct
    return struct.unpack("<I", struct.pack("<f", x))[0]


def rand_int(rng, name):
    bits = BITS[name]
    if name.startswith("uint"):
        hi = (1 << bits) - 1
        return str(rng.choice([0, 1, 2, 127, 128, 255, hi, hi - 1, rng.randint(0, hi),
                               rng.randint(0, 1000), rng.randint(0, 1 << min(bits, 20))]) & hi)
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    return str(rng.choice([0, 1, -1, 63, 64, -64, -65, 127, -128, lo, hi, rng.randint(lo, hi),
                           rng.randint(-1000, 1000)]))


def rand_float(rng, name):
    pick = rng.random()
    if name == "float32":
        vals = [0.0, -0.0, 1.0, 1.5, -2.25, 3.4028234663852886e38, 1e-45, float("inf"),
                float("-inf"), float("nan"), 0.1, 17.0, 255.0, 65536.0]
        if pick < 0.6:
            return str(f32_bits(rng.choice(vals)))
        return str(rng.getrandbits(32))
    vals = [0.0, -0.0, 1.0, 1.5, -2.25, 1.7976931348623157e308, 5e-324, float("inf"),
            float("-inf"), float("nan"), 0.1, 17.0, 255.0, 3.141592653589793, 1e300, -1e-300]
    if pick < 0.6:
        return str(f64_bits(rng.choice(vals)))
    return str(rng.getrandbits(64))


def rand_str(rng):
    n = rng.choice([0, 0, 1, 2, 3, 5, 8, 20])
    if n == 0:
        return "-"
    if rng.random() < 0.7:
        return "".join(rng.choice(["61", "62", "63", "e282ac", "20", "7a", "c3a9"]) for _ in range(n))
    return "".join("%02x" % rng.randrange(256) for _ in range(n))


class Lits:
    def __init__(self, structs, ifaces, seed):
        self.structs = {s.name: s for s in structs}
        self.ifaces = ifaces
        self.rng = random.Random(seed)
        self.maxmap = 1
        self.special = {"GE": "{%s,%s}", "BM": "{%s,%s}", "GP": "{%s,%s}"}

    def lit(self, t, depth=4, p_nil=0.25):
        rng = self.rng
        k = t[0]
        if k == "b":
            n = t[1]
            if n == "bool":
                return rng.choice("tf")
            if n in BITS:
                return rand_int(rng, n)
            if n in ("float32", "float64"):
                return rand_float(rng, n)
            if n == "complex128":
                return "%s:%s" % (rand_float(rng, "float64"), rand_float(rng, "float64"))
            return rand_str(rng)
        if k == "bytes":
            return "n" if rng.random() < 0.2 else rand_str(rng)
        if k == "slice":
            if rng.random() < p_nil:
                return "n"
            if depth <= 0:
                return "[]"
            return "[" + ",".join(self.lit(t[1], depth - 1, p_nil) for _ in range(rng.choice([0, 1, 1, 2, 3, 4]))) + "]"
        if k == "array":
            return "[" + ",".join(self.lit(t[2], depth - 1, p_nil) for _ in range(t[1])) + "]"
        if k == "map":
            if rng.random() < p_nil:
                return "n"
            if depth <= 0:
                return "m[]"
            keys = set()
            n = rng.randint(0, self.maxmap)
            items = []
            for _ in range(n):
                kk = self.lit(t[1], 0, 0)
                if kk in keys:
                    continue
                keys.add(kk)
                items.append("%s=%s" % (kk, self.lit(t[2], depth - 1, p_nil)))
            return "m[" + ";".join(items) + "]"
        if k == "ptr":
            if depth <= 0 or rng.random() < p_nil:
                return "n"
            return "&" + self.lit(t[1], depth - 1, p_nil)
        if k == "any":
            if depth <= 0 or rng.random() < p_nil:
                return "n"
            kk = "Unreg" if rng.random() < 0.03 else rng.choice(self.ifaces)
            return "@%s:%s" % (kk, self.lit(self.type_of_key(kk), depth - 1, p_nil))
        # struct
        name = t[1]
        if name in SPECIAL:
            if name == "GE":
                return "{%s,%s}" % (rand_int(rng, "int8") if rng.random() < 0.9 else "-3", rand_str(rng))
            if name == "BM":
                return "{%s,%s}" % (rand_int(rng, "uint16"), rand_str(rng))
            return "{%s,%s}" % (rand_int(rng, "int"), rand_str(rng))
        s = self.structs[name]
        parts = []
        for f in s.fields:
            parts.append(self.lit(f[1], depth - 1, p_nil) if f[2] else "_")
        return "{" + ",".join(parts) + "}"

    def type_of_key(self, kk):
        if kk.startswith("*"):
            return ("ptr", self.type_of_key(kk[1:]))
        if kk in BASIC:
            return ("b", kk)
        if kk.startswith("[]"):
            inner = kk[2:]
            return ("bytes",) if inner == "uint8" else ("slice", self.type_of_key(inner))
        return ("s", kk)
