#!/usr/bin/env python3
"""Differentially check fmt (Printf/Sprint/Sprintln/Errorf and the Sscan
family) against Go, byte for byte.

Printf requests cover every verb x flag subset x width x precision x value
kind: integers of every width, floats, complex numbers, strings (including
invalid UTF-8), byte slices, slices, arrays, maps, structs, pointers, nil,
named types with String/Error/GoString/Format methods (including panicking
ones), explicit argument indexes, `*` widths and precisions, and the
malformed-format error forms. Sprint/Sprintln cover operand spacing; Errorf
covers %w; Sscan/Sscanln/Sscanf cover scanning into typed destinations.

The Go oracle (tools/fmt_oracle.go) and the Rust probe (examples/fmt_probe.rs)
read the same token language, see the header of the oracle. Pointer addresses
differ by construction and are masked in both outputs.

FMT_SCALE=<x> multiplies the vector counts (default 0.6, about 70000 vectors, fits the suite budget;
the persistent evidence run used a much larger scale). FMT_SEED=<n> changes
the random stream.
"""
import os
import pathlib
import random
import re
import struct
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCALE = float(os.environ.get("FMT_SCALE", "0.6"))


def h(s):
    if isinstance(s, str):
        s = s.encode()
    return s.hex()


def T(s):
    return h(s)


def enc(text):
    """UTF-8, except that U+00FF stands for the raw byte 0xFF."""
    return b"\xff".join(part.encode() for part in text.split("\xff"))


# ------------------------------------------------------------------ values


def f32(x):
    return "float32:%08x" % struct.unpack(">I", struct.pack(">f", x))[0]


def f64(x):
    return "float64:%016x" % struct.unpack(">Q", struct.pack(">d", x))[0]


def f32b(bits):
    return "float32:%08x" % bits


def f64b(bits):
    return "float64:%016x" % bits


def c64(a, b):
    return "complex64:%s,%s" % (f32(a)[8:], f32(b)[8:])


def c128(a, b):
    return "complex128:%s,%s" % (f64(a)[8:], f64(b)[8:])


def s(b):
    return "string:" + h(b)


def sl(elem, items, nil=False):
    return "slice:%s:%d:%d %s" % (T(elem), len(items), int(nil), " ".join(items))


def arr(elem, items):
    return "array:%s:%d %s" % (T(elem), len(items), " ".join(items))


def mp(kt, vt, entries, nil=False):
    flat = " ".join(k + " " + v for k, v in entries)
    return "map:%s:%s:%d:%d %s" % (T(kt), T(vt), len(entries), int(nil), flat)


def st(fields):
    parts = ["struct:%d" % len(fields)]
    for name, typ, tok in fields:
        parts += [T(name), T(typ), tok]
    return " ".join(parts)


def ptr(elem, tok=None):
    if tok is None:
        return "ptr:%s:0" % T(elem)
    return "ptr:%s:1 %s" % (T(elem), tok)


def raw(typ, nonnil):
    return "raw:%s:%d" % (T(typ), int(nonnil))


def named(name, *payload):
    return "named:" + ":".join([name] + [str(p) for p in payload])


INT_TYPES = ["int", "int8", "int16", "int32", "int64"]
UINT_TYPES = ["uint", "uint8", "uint16", "uint32", "uint64", "uintptr"]
INT_RANGE = {"int": 64, "int8": 8, "int16": 16, "int32": 32, "int64": 64}
UINT_RANGE = {"uint": 64, "uint8": 8, "uint16": 16, "uint32": 32, "uint64": 64, "uintptr": 64}

STRINGS = [b"", b"hi", b"h\xc3\xa9llo", "日本語".encode(), b"a\nb", b"tab\there", b'quote"d',
           b"\xff\xfe", b"\x00\x01", b"back`tick", b"`raw`", b"a b c", b"\x7f", b"\xe2\x80\xa8",
           b"x" * 30, "😀 emoji".encode(), b"\\", b"\xc3", b"it's", b"\xed\xa0\x80", b"\x1b[0m"]

FLOAT_VALUES = [0.0, -0.0, 1.0, -1.0, 0.5, 3.14159, 1e6, 1e21, 1e-7, 123456789.0, 1 / 3, 100.0,
                1e20, 2.5e-5, 1e100, 5e-324, 1.7976931348623157e308, 12345.6789, 0.000123,
                float("inf"), float("-inf"), float("nan"), 255.0, 1e-5, 99999.5, 1234567.0,
                0.1, 1e15, 123456.0, 4.9e-324]
F32_VALUES = [0.0, 1.0, -2.5, 3.14159, 1e10, 1e-10, 16777216.0, 0.1, 3.4028235e38, 1e-45,
              float("inf"), float("nan"), 100.0, 123456.789]

INT_VALUES = [0, 1, -1, 5, 42, -42, 65, 100, 127, 128, 255, 256, 1000, -1000, 65535, 65536,
              0x1F600, 0x10FFFF, 0x110000, 0xD800, 2**31 - 1, -2**31, 2**31, 2**32 - 1, 2**63 - 1,
              -2**63, 2**64 - 1, 7, 8, 9, 10, 15, 16, 31, 99999, 12345678, -128, -32768]


def ints():
    out = []
    for t in INT_TYPES:
        bits = INT_RANGE[t]
        lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
        for v in INT_VALUES:
            if lo <= v <= hi:
                out.append(("%s:%d" % (t, v), set()))
    for t in UINT_TYPES:
        bits = UINT_RANGE[t]
        for v in INT_VALUES:
            if 0 <= v < (1 << bits):
                out.append(("%s:%d" % (t, v), set()))
    return out


def floats():
    out = []
    for v in FLOAT_VALUES:
        out.append((f64(v), set()))
    for v in F32_VALUES:
        out.append((f32(v), set()))
    out.append((f32b(0x7FC00001), set()))
    out.append((f64b(0xFFF8000000000001), set()))
    cvals = [0.0, 1.0, -1.0, 2.5, float("inf"), float("nan"), 1e10, 1 / 3]
    for a in cvals:
        for b in cvals[:6]:
            out.append((c128(a, b), set()))
            out.append((c64(a, b), set()))
    return out


def strings():
    return [(s(b), set()) for b in STRINGS]


def bytes_slices():
    out = []
    for b in [b"", b"hi", b"\x00\xff", "日本".encode(), b"abc\n", bytes(range(20)), b"x" * 20]:
        out.append((sl("uint8", ["uint8:%d" % c for c in b]), set()))
    out.append((sl("uint8", [], nil=True), set()))
    out.append((arr("uint8", ["uint8:%d" % c for c in b"abcd"]), set()))
    out.append((arr("uint8", []), set()))
    out.append((named("MyBytes", "6869"), set()))
    out.append((named("MyBytes", "nil"), set()))
    out.append((named("MyBytes", ""), set()))
    return out


def composites():
    out = []
    add = lambda tok, tags=(): out.append((tok, set(tags)))
    add(sl("int", ["int:%d" % i for i in (1, 2, 3)]))
    add(sl("int", []))
    add(sl("int", [], nil=True))
    add(sl("string", [s(b"a"), s(b"b c"), s(b"")]))
    add(sl("string", [s("é".encode()), s(b"\xff")]))
    add(sl("float64", [f64(1.5), f64(-0.25), f64(1e21)]))
    add(sl("bool", ["bool:1", "bool:0"]))
    add(sl("[]int", [sl("int", ["int:1"]), sl("int", []), sl("int", ["int:2", "int:3"])]))
    add(sl("interface {}", ["int:1", s(b"two"), f64(3.5), "nil", "bool:1", sl("int", ["int:9"])]))
    add(sl("interface {}", [], nil=True))
    add(sl("error", [named("ErrT", 3), "nil"]))
    add(sl("main.SInt", [named("SInt", 1), named("SInt", 2)]))
    add(sl("uint16", ["uint16:1", "uint16:65535"]))
    add(sl("int8", ["int8:-1", "int8:127"]))
    add(sl("complex128", [c128(1, 2), c128(0, -1)]))
    add(sl("main.MyInt", [named("MyInt", 3)]))
    add(sl("main.MyStr", [named("MyStr", h("x y"))]))
    add(arr("int", ["int:1", "int:2", "int:3"]))
    add(arr("string", [s(b"a"), s(b"b")]))
    add(arr("bool", ["bool:1"]))
    add(arr("float32", [f32(1.5), f32(0.1)]))
    add(arr("[2]int", [arr("int", ["int:1", "int:2"]), arr("int", ["int:3", "int:4"])]))
    add(mp("string", "int", [(s(b"b"), "int:2"), (s(b"a"), "int:1"), (s(b"c"), "int:3")]))
    add(mp("string", "int", []))
    add(mp("string", "int", [], nil=True))
    add(mp("int", "string", [("int:3", s(b"c")), ("int:-1", s(b"neg")), ("int:2", s(b"b"))]))
    add(mp("bool", "int", [("bool:1", "int:1"), ("bool:0", "int:0")]))
    add(mp("float64", "string", [(f64(2.5), s(b"x")), (f64(-1.0), s(b"y")), (f64(float("inf")), s(b"z"))]))
    add(mp("uint8", "bool", [("uint8:200", "bool:1"), ("uint8:3", "bool:0")]))
    add(mp("string", "[]int", [(s(b"k"), sl("int", ["int:1", "int:2"]))]))
    add(mp("string", "interface {}", [(s(b"a"), "int:1"), (s(b"b"), "nil"), (s(b"c"), s(b"s"))]))
    add(mp("main.Pt", "string", [(named("Pt", 2, 1), s(b"b")), (named("Pt", 1, 5), s(b"a")), (named("Pt", 1, 2), s(b"c"))]))
    add(mp("[2]int", "int", [(arr("int", ["int:2", "int:1"]), "int:1"), (arr("int", ["int:1", "int:9"]), "int:2")]))
    add(mp("main.SInt", "main.SInt", [(named("SInt", 2), named("SInt", 20)), (named("SInt", 1), named("SInt", 10))]))
    add(mp("complex128", "int", [(c128(1, 2), "int:1"), (c128(1, -2), "int:2")]))
    add(st([("A", "int", "int:1"), ("B", "string", s(b"x"))]))
    add(st([]))
    add(st([("A", "[]int", sl("int", ["int:1", "int:2"])), ("M", "map[string]int", mp("string", "int", [(s(b"k"), "int:1")]))]))
    add(st([("I", "interface {}", "nil"), ("J", "interface {}", s(b"s")), ("E", "error", named("ErrT", 4)), ("F", "float64", f64(2.5))]))
    add(st([("S", "main.SInt", named("SInt", 7)), ("N", "main.MyInt", named("MyInt", 8))]))
    add(st([("B", "[]uint8", sl("uint8", ["uint8:1", "uint8:2"])), ("U", "uint", "uint:5"), ("C", "complex64", c64(1, 2))]))
    add(st([("A", "main.Pt", named("Pt", 1, 2)), ("Z", "bool", "bool:0")]))
    add(ptr("int", "int:5"), ["ptr"])
    add(ptr("int"))
    add(ptr("string"))
    add(ptr("string", s(b"s")), ["ptr"])
    add(ptr("[]int", sl("int", ["int:1", "int:2"])))
    add(ptr("[]int"))
    add(ptr("[2]int", arr("int", ["int:1", "int:2"])))
    add(ptr("map[string]int", mp("string", "int", [(s(b"a"), "int:1")])))
    add(ptr("map[string]int"))
    add(ptr("main.Pt", named("Pt", 1, 2)))
    add(ptr("*int"))
    add(ptr("*int", ptr("int", "int:2")), ["ptr"])
    add(ptr("*main.Pt", ptr("main.Pt", named("Pt", 1, 2))), ["ptr"])
    add(sl("*int", [ptr("int", "int:1"), ptr("int")]), ["ptr"])
    add(st([("P", "*int", ptr("int", "int:1")), ("Q", "*int", ptr("int"))]), ["ptr"])
    add(raw("chan int", False))
    add(raw("chan int", True), ["ptr"])
    add(raw("func()", False))
    add(raw("func()", True), ["ptr"])
    add(raw("unsafe.Pointer", False))
    add(raw("unsafe.Pointer", True), ["ptr"])
    add("nil")
    return out


def named_values():
    out = []
    add = lambda tok, tags=(): out.append((tok, set(tags)))
    for v in (0, 5, -7, 12345):
        add(named("MyInt", v))
        add(named("MyUint", abs(v)))
        add(named("SInt", v))
        add(named("PanicS", v))
        add(named("ErrT", v))
        add(named("GoS", v))
        add(named("Fmt", v))
        add(named("PtrS", v))
        add(named("PtrSP", v))
        add(named("ErrWrap", v))
    for b in (b"", b"x", b"two words", "h\u00e9".encode()):
        add(named("MyStr", h(b)))
        add(named("SStr", h(b)))
        add(named("ErrNew", h(b)))
    add(named("MyStr", h(b"\xff\xfe")))
    for v in (0.0, 2.5, float("inf")):
        add(named("MyFloat", f64(v)[8:]))
    add(named("MyBool", 1))
    add(named("MyBool", 0))
    add(named("MyC", "%s,%s" % (f64(1)[8:], f64(-2)[8:])))
    add(named("PanicE"))
    add(named("NilPS", 0))
    add(named("NilPS", 1, h("x")), ["ptr"])
    add(named("Pt", 1, 2))
    add(named("PtP", 3, 4))
    add(named("Mixed", 1, 2, 3) + " int:4 string:" + h("s"))
    add(named("Mixed", 1, 2, 3) + " nil nil")
    add(named("Mixed", 5, 6, 7) + " " + named("SInt", 8) + " " + named("ErrT", 9))
    add(named("Wrap", 1, 1, 2, 2) + " nil int:7 int:8", ["ptr"])
    add(named("Wrap", 0, 0, 0, 0) + " " + named("SInt", 1))
    add(named("Gen") + " " + named("SInt", 3))
    add(named("Gen") + " nil")
    add(named("Gen") + " " + sl("int", ["int:1"]))
    add(named("Gen") + " " + named("Gen") + " int:1")
    return out


ADDR_RE = re.compile(r"ptr:[0-9a-f]+:1|raw:[0-9a-f]+:1|named:(PtrSP|ErrWrap|ErrNew|PtP)|named:NilPS:1|named:Wrap:1:")


def all_values():
    vals = ints() + floats() + strings() + bytes_slices() + composites() + named_values() + [
        ("bool:1", set()), ("bool:0", set())]
    return [(t, tags | {"addr"} if ADDR_RE.search(t) else tags) for t, tags in vals]


# ---------------------------------------------------------------- requests

VERBS = "vTtbcdoOqxXUeEfFgGspw%zkaiNhBdv"
PTR_BAD = set("bodcqUeEfFgGt")


def flags_str(rng, p=0.35):
    return "".join(c for c in "+-# 0" if rng.random() < p)


def spec(rng, verb, addr=False):
    f = flags_str(rng)
    if addr:
        return "%" + f + verb
    w = rng.choice(["", "", "", "0", "1", "3", "5", "8", "12", "20", "100"])
    pr = rng.choice(["", "", "", ".", ".0", ".1", ".2", ".3", ".5", ".8", ".12", ".30"])
    return "%" + f + w + pr + verb


def pline(fmt, toks):
    return "\t".join(["P", h(fmt)] + toks)


def has_addr(tok):
    """Slices and maps print a heap address under %p unless they are nil."""
    p = tok.split(" ")[0].split(":")
    if p[0] == "named" and p[1] == "MyBytes":
        return p[2] != "nil"
    if p[0] == "slice":
        return p[3] != "1"
    if p[0] == "map":
        return p[4] != "1"
    return False


def printf_requests(rng, scale):
    reqs = []
    values = all_values()
    per = max(1, int(3 * scale))
    for tok, tags in values:
        for verb in VERBS:
            if "ptr" in tags and verb in PTR_BAD:
                continue
            if verb == "p" and has_addr(tok):
                continue
            reqs.append(pline("%" + verb, [tok]))
            for _ in range(per):
                reqs.append(pline(spec(rng, verb, "addr" in tags), [tok]))
    # Every flag subset x width x precision for the scalar kinds on the verbs
    # they format.
    scal = [v for v in values if v[0].split(":")[0] in
            ("int", "int8", "int32", "uint", "uint8", "float64", "float32", "string", "complex128", "bool")
            and not v[1]]
    flagsets = ["".join(c for i, c in enumerate("+-# 0") if m >> i & 1) for m in range(32)]
    for _ in range(int(6000 * scale)):
        tok, _t = rng.choice(scal)
        kind = tok.split(":")[0]
        if kind.startswith(("int", "uint")):
            verb = rng.choice("vdbcoOqxXU")
        elif kind.startswith("float"):
            verb = rng.choice("vbeEfFgGxX")
        elif kind == "complex128":
            verb = rng.choice("vbeEfFgGxX")
        elif kind == "string":
            verb = rng.choice("vsqxX")
        else:
            verb = rng.choice("vt")
        fmt = "%" + rng.choice(flagsets) + rng.choice(["", "0", "1", "4", "9", "16"]) + \
            rng.choice(["", ".", ".0", ".2", ".4", ".9"]) + verb
        reqs.append(pline(fmt, [tok]))
    return reqs


def arg_pool(rng):
    pool = [v[0] for v in all_values() if "ptr" not in v[1]]
    return pool


def index_requests(rng, scale):
    reqs = []
    pool = arg_pool(rng)
    small = [t for t in pool if t.split(":")[0] in ("int", "uint8", "string", "float64", "bool", "int8")]
    fmts = ["%[2]d %[1]d", "%[3]*.[2]*[1]f", "%[0]d", "%[x]d", "%[1]", "%[", "%[1]*d", "%[2]*[1]d",
            "%[1]d %d %d", "%d %[1]d %d", "%[5]d", "%[-1]d", "%[1]d%[1]d", "%[1]*[1]d", "%[1]#v %[1]T",
            "%6.[1]*[2]d", "%[2]6.2f", "%.[1]d", "%[1].2d", "%[1]2d", "%[]d", "%[1]]d", "%[ 1]d",
            "%[1]!", "%[999999999999999999999]d", "%1000001d", "%.1000001d", "%999999999999d", "%*d|", "%[1]%", "%[1]*[2]*[3]d", "%*d", "%.*d", "%*.*f",
            "%[2]*d", "%-*d|", "%0*d", "%*d %*d", "%.[2]*[1]f", "%[3]v %[2]v %[1]v", "%[1]v %v",
            "%v %[2]v %v", "%[1]d %[1]x %[1]o %[1]b"]
    for _ in range(int(4000 * scale)):
        n = rng.randrange(0, 5)
        args = [rng.choice(small) for _ in range(n)]
        if rng.random() < 0.5:
            args = [rng.choice(["int:%d" % rng.choice([-5, 0, 1, 3, 7, 12, 1000001, -1000001]),
                                "int8:%d" % rng.randrange(-8, 9), "uint:%d" % rng.randrange(0, 12),
                                "uint64:%d" % (2**63 + 5), "uint16:%d" % rng.randrange(0, 40)])
                    if rng.random() < 0.6 else rng.choice(small) for _ in range(n)]
        reqs.append(pline(rng.choice(fmts), args))
    return reqs


FRAGS = ["%", "d", "v", "s", "[1]", "[2]", "*", ".", "3", "-", "+", "#", "0", " ", "%%", "abc", "\n", "é",
         "x", "T", "q", "[", "]", "w", "f", "t", "5", ".2", "\xff", "p", "c", "U", "e", "g", "b", "%d",
         "%v", "%s", "%5d", "%-5s", "%.2f", "%x", "%+v", "%#v", "%q", "[3]"]


def no_p(fmt, args):
    """Heap addresses of slices and maps are not comparable: drop %p then."""
    if any(has_addr(a) or ADDR_RE.search(a) for a in args):
        return fmt.replace("p", "q")
    return fmt


def random_format_requests(rng, scale):
    reqs = []
    pool = [v[0] for v in all_values() if "ptr" not in v[1]]
    for _ in range(int(14000 * scale)):
        fmt = "".join(rng.choice(FRAGS) for _ in range(rng.randrange(1, 9)))
        n = rng.randrange(0, 5)
        args = [rng.choice(pool) for _ in range(n)]
        reqs.append(pline(enc(no_p(fmt, args)), args))
    # multi-verb formats with all arguments consumed or not
    for _ in range(int(3000 * scale)):
        n = rng.randrange(1, 5)
        args = [rng.choice(pool) for _ in range(n)]
        fmt = " ".join(spec(rng, rng.choice("vdsqxfgeTtc")) for _ in range(rng.randrange(0, 6)))
        reqs.append(pline(fmt, args))
    return reqs


def print_requests(rng, scale):
    reqs = []
    pool = [v[0] for v in all_values() if "ptr" not in v[1]]
    strs = [t for t in pool if t.startswith(("string:", "named:MyStr", "named:SStr"))]
    for _ in range(int(5000 * scale)):
        n = rng.randrange(0, 7)
        args = [rng.choice(strs if rng.random() < 0.35 else pool) for _ in range(n)]
        reqs.append("\t".join(["S"] + args))
        reqs.append("\t".join(["L"] + args))
    return reqs


def errorf_requests(rng, scale):
    reqs = []
    errs = [named("ErrT", 1), named("ErrT", 2), named("ErrNew", h("plain")), named("ErrWrap", 5), "nil",
            "int:3", s(b"str"), named("PanicE"), named("SInt", 4)]
    fmts = ["%w", "a %w b", "%v", "%w %w", "%w: %w: %w", "%[2]w %[1]w", "%[1]w %[1]w", "%d", "%w", "x",
            "%w%w", "%[2]w", "%+w", "%#w", "%5w", "%-5w|", "%.2w", "%s %w", "%w %s", "%q %w", "%x %w",
            "%[1]w %w", "%!w", "%w %", "%[3]w %w", "%[1]w %[2]w %[1]w", ""]
    for _ in range(int(3000 * scale)):
        n = rng.randrange(0, 4)
        reqs.append("\t".join(["E", h(rng.choice(fmts))] + [rng.choice(errs) for _ in range(n)]))
    return reqs


# ---------------------------------------------------------------- scanning

SCAN_KINDS = ["bool", "int", "int8", "int16", "int32", "int64", "uint", "uint8", "uint16", "uint32",
              "uint64", "uintptr", "float32", "float64", "complex64", "complex128", "string", "bytes",
              "scanner"]

SCAN_WORDS = ["", "0", "1", "-1", "+5", "42", "  42", "\t7", "007", "0x1F", "0b101", "0o17", "1_000", "-0x_ff",
              "128", "255", "256", "-129", "32768", "65536", "4294967296", "18446744073709551615",
              "9223372036854775808", "-9223372036854775809", "99999999999999999999",
              "3.14", "-2.5e3", "1e400", "1e-400", ".5", "5.", "inf", "-Inf", "NaN", "0x1p-2", "1p3",
              "1.5p2", "1_0.5", "true", "false", "T", "F", "TRUE", "tRuE", "tr", "fal", "yes",
              "(1+2i)", "1+2i", "(3-4i)", "2i", "1+2", "hello", "héllo", "\"quoted str\"", "`raw str`",
              "\"bad\\q\"", "\"unterminated", "6869", "68 69", "zz", "U+0041", "U+1F600", "a", "日本語",
              "x" * 40, "%", "abc", "-", "+", "0x", "1e", "e5", "\r", "\xff"]
SEPS = [" ", "  ", "\n", " \n", "\n ", "\t", ",", "\r\n", ""]
VERB_BY_KIND = {
    "int": "dvbxXocUq", "uint": "dvbxXocUq", "float": "vfeEgGb", "string": "svqxX", "bool": "tv",
    "bytes": "svqxX", "complex": "vfeg", "scanner": "vsd",
}


def kind_class(k):
    for c in ("uint", "int", "float", "complex"):
        if k.startswith(c):
            return c
    return k


KIND_TOKENS = {
    "int": ["0", "1", "-1", "+7", "42", "-128", "127", "128", "255", "256", "32767", "32768", "65535",
            "65536", "2147483648", "4294967295", "9223372036854775807", "9223372036854775808",
            "-9223372036854775808", "0x1f", "0X1F", "0b101", "0o17", "017", "1_000", "ff", "FF", "101",
            "777", "U+0041", "U+1F600", "A", "é", "99999999999999999999", "-0", "08", "0x", "1__0", "_1"],
    "float": ["0", "1.5", "-2.5e3", "1e10", "1e400", "0.1", "inf", "-Inf", "nan", "1p3", "0x1p-2",
              "3.4028236e38", "1.17549435e-38", "1e-46", "7e-46", ".5", "5.", "1_0.5", "+1.", "1e+", "0x.8p1",
              "123456789.123456789", "4.9e-324"],
    "bool": ["true", "false", "1", "0", "t", "f", "T", "F", "TRUE", "True", "tRUE", "tr", "fa", "yes", "FALSE"],
    "complex": ["(1+2i)", "1+2i", "(3-4i)", "(1e400+2i)", "1-2.5e3i", "(nan+infi)", "1+2", "2i", "(1+2i",
                "(0x1p1+0x1p2i)", "+1+1i", "1+i"],
    "string": ["hello", "héllo", "日本語", "a", "", "\"quoted str\"", "`raw str`", "\"esc\\n\\t\\u00e9\"",
               "\"bad\\q\"", "\"unterminated", "6869", "68 69", "ZZ", "x" * 40, "a,b", "-", "%d"],
}
KIND_TOKENS["bytes"] = KIND_TOKENS["string"]
KIND_TOKENS["scanner"] = KIND_TOKENS["string"]
KIND_TOKENS["uint"] = KIND_TOKENS["int"]


def scan_requests(rng, scale):
    reqs = []
    for _ in range(int(14000 * scale)):
        n = rng.randrange(0, 5)
        kinds = [rng.choice(SCAN_KINDS) for _ in range(n)]
        mode = rng.choice("fslss")
        sep_in = rng.choice(SEPS)
        sep_fmt = rng.choice([" ", " ", "", ",", "\n", " ,", "-"])
        verbs = [rng.choice(VERB_BY_KIND.get(kind_class(k), "v")) for k in kinds]
        widths = [rng.choice(["", "", "", "", "1", "2", "3", "5"]) for _ in kinds]
        toks = []
        for k in kinds:
            if rng.random() < 0.8:
                toks.append(rng.choice(KIND_TOKENS[kind_class(k) if kind_class(k) in KIND_TOKENS else "int"]))
            else:
                toks.append(rng.choice(SCAN_WORDS))
        if mode == "f":
            sep_in = sep_fmt if rng.random() < 0.7 else sep_in
            text = sep_in.join(toks) + rng.choice(["", "", "", "\n", " ", "x"])
            fmt = sep_fmt.join("%" + w + v for w, v in zip(widths, verbs))
            if rng.random() < 0.15:
                fmt = "".join(rng.choice(["%d", "%s", " ", "\n", "%", "x", "%%", "%c", "%z", ",", "%v"]) for _ in range(4))
            elif rng.random() < 0.2:
                fmt = rng.choice(["", "x", "T:"]) + fmt + rng.choice(["", " ", "\n", "x", " \n "])
        else:
            if rng.random() < 0.6:
                sep_in = rng.choice([" ", "  ", "\n", " \n", "\t"])
            text = sep_in.join(toks) + rng.choice(["", "", "\n", " ", "x", "\n\n", " 1"])
            fmt = ""
        if rng.random() < 0.05:
            text = "".join(rng.choice(SCAN_WORDS) + rng.choice(SEPS) for _ in range(rng.randrange(0, 4)))
        reqs.append("\t".join(["Z", mode, h(enc(text)), h(enc(fmt)), ",".join(kinds)]))
    return reqs


# ------------------------------------------------------------------- main

PTR_RE = re.compile(rb"(?<![0-9a-zA-Z])(?:0[xX])?[0-9a-fA-F]{9,12}(?![0-9a-zA-Z])")
# A func value prints its code address, which in a non-PIE binary (Go on Linux)
# can be as short as five hex digits: text starts at 0x10000 or above.
FUNC_TOKEN = "raw:%s:1" % "func()".encode().hex()
FUNC_ADDR_RE = re.compile(rb"(?<![0-9a-zA-Z])(?:0[xX])?[0-9a-fA-F]{5,12}(?![0-9a-zA-Z])")


def mask(line, ptr_re=PTR_RE):
    """Masks pointer addresses in the decoded fields of one output line."""
    if line.startswith(("GOPANIC", "RUSTPANIC")) or not line:
        return line
    parts = line.split(":")
    out = []
    for p in parts:
        try:
            raw_bytes = bytes.fromhex(p)
        except ValueError:
            out.append(p)
            continue
        out.append(ptr_re.sub(b"ADDR", raw_bytes).hex())
    return ":".join(out)


def run_both(payload):
    env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")
    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "fmt_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT, env=env, encoding="utf-8",
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust fmt probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/fmt_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT, env=env, encoding="utf-8",
    )
    if go_run.returncode:
        raise RuntimeError(f"Go fmt oracle failed:\n{go_run.stderr}")
    return rust_run.stdout.splitlines(), go_run.stdout.splitlines()


def main():
    rng = random.Random(int(os.environ.get("FMT_SEED", "0xF317"), 0))
    sections = [
        ("printf", printf_requests(rng, SCALE)),
        ("index", index_requests(rng, SCALE)),
        ("random-format", random_format_requests(rng, SCALE)),
        ("sprint", print_requests(rng, SCALE)),
        ("errorf", errorf_requests(rng, SCALE)),
        ("scan", scan_requests(rng, SCALE)),
    ]
    records = [r for _, rs in sections for r in rs]
    payload = "".join(r + "\n" for r in records)
    rust, go = run_both(payload)
    if len(rust) != len(records) or len(go) != len(records):
        raise AssertionError(f"fmt oracle returned the wrong number of records: {len(rust)} {len(go)} {len(records)}")
    panics = [records[i] for i, l in enumerate(go) if l.startswith("GOPANIC")]
    if panics:
        raise AssertionError(f"{len(panics)} requests panicked in the Go oracle, e.g. {panics[0]!r}")
    bad = 0
    groups = set()

    def dec(x):
        return " | ".join(
            bytes.fromhex(p).decode("utf-8", "backslashreplace") if re.fullmatch(r"([0-9a-f][0-9a-f])*", p) else p
            for p in x.split(":"))

    for i, (actual, expected) in enumerate(zip(rust, go)):
        # Only a record printing nothing but the func value gets the wider mask.
        ptr_re = FUNC_ADDR_RE if records[i].split("\t")[2:] == [FUNC_TOKEN] else PTR_RE
        if (mask(actual, ptr_re) != mask(expected, ptr_re)) if ADDR_RE.search(records[i]) else (actual != expected):
            bad += 1
            f = records[i].split("\t")
            key = (f[0], f[2][:40] if len(f) > 2 else "")
            if key not in groups and len(groups) < 25:
                groups.add(key)
                print(f"vector {i}: request={records[i]!r}\n  fmt={bytes.fromhex(f[1]).decode('utf-8', 'backslashreplace') if f[0] in 'PE' else ''!r}"
                      f"\n  Rust={dec(actual)!r}\n  Go  ={dec(expected)!r}")
    if bad:
        raise AssertionError(f"{bad} of {len(records)} fmt vectors differ")
    scan_ok = sum(1 for r, g in zip(records, go) if r.startswith("Z") and g.split("|")[1] == "-")
    counts = ", ".join(f"{len(rs)} {name}" for name, rs in sections)
    print(f"fmt Go differential: {len(records)} vectors passed ({counts}; {scan_ok} scans succeeded)")


if __name__ == "__main__":
    main()
