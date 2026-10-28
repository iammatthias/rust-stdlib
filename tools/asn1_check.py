#!/usr/bin/env python3
"""Compare encoding/asn1 marshal/unmarshal and DER strictness with Go.

Requests carry a schema tree that tools/asn1_oracle.go turns into Go types
(reflect.StructOf with asn1 struct tags) and examples/asn1_probe.rs maps onto
the Rust Decode/Marshal API. Phases:

1. marshal: random typed values per primitive and random nested SEQUENCEs
   with explicit/implicit/optional/default/set/string/time options; the DER
   bytes (or failure) must be identical.
2. unmarshal: Go-produced DER, the same bytes decoded with a different schema,
   hand-built content variants per primitive, and mutated DER. Results (value,
   remaining bytes, or failure) must be identical in Rust's Go-compatible
   explicit-tag mode. Rust's default strict mode must agree or reject with an
   explicit-length error. Values Go accepts but time::DateTime cannot hold
   (year 0000, offsets of +/-24h) must be rejected by Rust as time errors.
"""
import json
import os
import pathlib
import random
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
PRIMITIVES = ["bool", "int", "int32", "big", "enum", "flag", "bits", "octets",
              "oid", "string", "time", "raw"]
STRING_TYPES = ["utf8", "ia5", "printable", "numeric"]
PRINTABLE = "abcXYZ019 '()+,-./:=?"
ALPHABETS = [PRINTABLE, PRINTABLE + "*&@", "0123456789 ", "abc\x00\x7f!\"#$%",
             "aé£ÿ", "aΣж中", "a😀\U0001F600", "*"]


def node(kind, params="", fields=None, elem=None):
    n = {"k": kind, "p": params}
    if fields is not None:
        n["f"] = fields
    if elem is not None:
        n["e"] = elem
    return n


# Value generators ---------------------------------------------------------

def twos(n):
    length = 1
    while not -(1 << (8 * length - 1)) <= n < (1 << (8 * length - 1)):
        length += 1
    return (n % (1 << (8 * length))).to_bytes(length, "big").hex()


def gen_int(rng, bits=64):
    lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    r = rng.random()
    if r < 0.3:
        return rng.choice([0, 1, -1, 127, 128, -128, -129, 255, 256, 32767, 32768,
                           -32768, -32769, lo, hi, lo + 1, hi - 1, 1 << 23, -(1 << 31),
                           (1 << 31) - 1])
    if r < 0.6:
        return rng.randint(-300, 300)
    width = rng.randint(1, bits - 1)
    return max(lo, min(hi, rng.randint(-(1 << width), 1 << width)))


def gen_oid(rng):
    r = rng.random()
    if r < 0.05:
        return rng.choice([[], [1], [3, 1], [0, 40], [1, 45, 2]])
    first = rng.randint(0, 2)
    second = rng.randint(0, 39) if first < 2 else rng.choice([0, 5, 39, 40, 47, 100, 999, 1 << 20])
    arcs = [first, second]
    for _ in range(rng.randint(0, 6)):
        arcs.append(rng.choice([rng.randint(0, 127), rng.randint(128, 16383),
                                rng.randint(0, (1 << 31) - 1), 113549, 840]))
    if r > 0.97:
        arcs.append(rng.choice([1 << 31, (1 << 35) + 5]))
    return arcs


def gen_time(rng):
    r = rng.random()
    if r < 0.25:
        year = rng.choice([1949, 1950, 1951, 1999, 2000, 2049, 2050, 2051])
    elif r < 0.3:
        year = rng.choice([1, 2, 999, 1000, 9999])
    else:
        year = rng.randint(1, 9999)
    month = rng.randint(1, 12)
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = [31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1]
    day = rng.choice([1, days, rng.randint(1, days)])
    nanos = rng.randint(0, 999_999_999) if rng.random() < 0.3 else 0
    r = rng.random()
    if r < 0.45:
        offset = 0
    elif r < 0.93:
        offset = rng.choice([1, -1]) * (rng.randint(0, 23) * 3600 + rng.randint(0, 59) * 60)
    else:
        offset = rng.choice([30, -30, -90, 3630, -3630, 86399, -86399])
    if year == 1 and offset > 0:
        offset = -offset
    return [year, month, day, rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59), nanos, offset]


def gen_string(rng, params):
    if "numeric" in params and rng.random() < 0.8:
        alphabet = "0123456789 "
    elif ("printable" in params or "ia5" in params) and rng.random() < 0.7:
        alphabet = PRINTABLE + ("*" if rng.random() < 0.3 else "")
    else:
        alphabet = rng.choice(ALPHABETS)
    length = rng.choice([0, 1, 3, 10, 40]) if rng.random() < 0.97 else rng.randint(120, 300)
    return "".join(rng.choice(alphabet) for _ in range(length))


def gen_bytes(rng, max_len):
    return bytes(rng.randrange(256) for _ in range(rng.randint(0, max_len)))


def gen_value(rng, s):
    k, p = s["k"], s["p"]
    if k in ("bool", "flag"):
        return rng.random() < 0.5
    if k == "int":
        return 0 if rng.random() < 0.1 else gen_int(rng)
    if k == "int32":
        return gen_int(rng, 32)
    if k == "enum":
        return gen_int(rng, 64 if rng.random() < 0.2 else 32)
    if k == "big":
        if "optional" in p and rng.random() < 0.3:
            return None
        bits = rng.choice([1, 7, 8, 9, 63, 64, 65, 128, 300])
        return twos(rng.randint(-(1 << bits), 1 << bits))
    if k == "bits":
        data = bytearray(gen_bytes(rng, 12))
        pad = rng.randint(0, 7) if data else 0
        if data and rng.random() < 0.95:
            data[-1] &= (0xff << pad) & 0xff
        return {"b": data.hex(), "n": len(data) * 8 - pad}
    if k == "octets":
        return gen_bytes(rng, 40 if rng.random() < 0.95 else 300).hex()
    if k == "oid":
        return gen_oid(rng)
    if k == "string":
        return gen_string(rng, p)
    if k == "time":
        return gen_time(rng)
    if k == "raw":
        if rng.random() < 0.5:
            content = gen_bytes(rng, 10)
            return {"c": rng.randint(0, 3), "t": rng.choice([0, 1, 4, 5, 16, 30, 31, 200, rng.randint(0, 1 << 20)]),
                    "x": rng.random() < 0.3, "b": content.hex(), "f": ""}
        content = gen_bytes(rng, 8)
        full = bytes([rng.choice([0x02, 0x04, 0x05, 0x30, 0x80, 0xa0])]) + bytes([len(content)]) + content
        if rng.random() < 0.1:
            full = gen_bytes(rng, 6)
        return {"c": 0, "t": 0, "x": False, "b": "", "f": full.hex()}
    if k == "seq":
        return [gen_value(rng, f) for f in s["f"]]
    if k == "seqof":
        return [gen_value(rng, s["e"]) for _ in range(rng.choice([0, 1, 2, 3, 5]))]
    raise AssertionError(k)


# Schema generators --------------------------------------------------------

def gen_params(rng, kind, top=False):
    parts = []
    if rng.random() < (0.15 if top else 0.35):
        parts.append("optional")
        if kind in ("int", "int32", "enum") and rng.random() < 0.4:
            parts.append(f"default:{rng.choice([0, 1, -1, 5, 127, 128])}")
    r = rng.random()
    if r < 0.25:
        parts += ["explicit", f"tag:{rng.choice([0, 1, 2, 3, 5, 30, 31, 200])}"]
    elif r < 0.5:
        parts.append(f"tag:{rng.choice([0, 1, 2, 3, 5, 30, 31, 200])}")
    if parts and parts[-1].startswith("tag:"):
        r = rng.random()
        if r < 0.1:
            parts.append("application")
        elif r < 0.15:
            parts.append("private")
    if kind == "string" and rng.random() < 0.5:
        parts.append(rng.choice(STRING_TYPES))
    if kind == "time" and rng.random() < 0.5:
        parts.append(rng.choice(["utc", "generalized"]))
    if kind in ("seq", "seqof") and rng.random() < 0.15:
        parts.append("set")
    if kind in ("octets", "oid", "seqof") and rng.random() < 0.2:
        parts.append("omitempty")
    if rng.random() < 0.02:
        parts.append(rng.choice(["set", "utf8", "generalized", "numeric"]))
    rng.shuffle(parts)
    return ",".join(parts)


def gen_schema(rng, depth, params=True, top=False):
    if depth > 0 and rng.random() < 0.35:
        if rng.random() < 0.7:
            fields = [gen_schema(rng, depth - 1) for _ in range(rng.randint(0, 5))]
            return node("seq", gen_params(rng, "seq", top) if params else "", fields=fields)
        elem = gen_schema(rng, depth - 1, params=False)
        return node("seqof", gen_params(rng, "seqof", top) if params else "", elem=elem)
    kind = rng.choice(PRIMITIVES)
    return node(kind, gen_params(rng, kind, top) if params else "")


# DER helpers and mutations -------------------------------------------------

def tlv(tag, content, form="min"):
    n = len(content)
    if form == "min":
        length = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    elif form == "long1":
        length = bytes([0x81, n]) if n < 256 else bytes([0x82]) + n.to_bytes(2, "big")
    elif form == "zero":
        length = bytes([0x82]) + n.to_bytes(2, "big") if n < 256 else bytes([0x83]) + n.to_bytes(3, "big")
    else:  # indefinite
        return bytes([tag]) + b"\x80" + content + b"\x00\x00"
    return bytes([tag]) + length + content


def mutate(rng, der):
    b = bytearray(der)
    op = rng.randrange(9)
    if not b:
        return bytes([rng.randrange(256)])
    i = rng.randrange(len(b))
    if op == 0:
        b[i] ^= 1 << rng.randrange(8)
    elif op == 1:
        b[i] = rng.choice([0x00, 0x7f, 0x80, 0x81, 0xff, 0x1f, 0x30, 0xa0, rng.randrange(256)])
    elif op == 2:
        b.insert(i, rng.randrange(256))
    elif op == 3:
        del b[i]
    elif op == 4:
        del b[rng.randrange(len(b) + 1):]
    elif op == 5:
        b += bytes(rng.randrange(256) for _ in range(rng.randint(1, 3)))
    elif op == 6 and len(b) > 1:
        b[1] = (b[1] + rng.choice([-1, 1])) & 0xff
    elif op == 7 and len(b) > 1 and b[1] < 0x80:
        b[1:2] = bytes([0x81, b[1]])
    else:
        b[i] = (b[i] + rng.choice([-1, 1])) & 0xff
    return bytes(b)


def content_variants(rng, kind):
    """Hand-built (tag, content) pairs that stress each primitive's rules."""
    if kind in ("bool", "flag"):
        return [(1, bytes([rng.choice([0, 0xff, 1, 0x80])] * rng.choice([0, 1, 1, 1, 2])))]
    if kind in ("int", "int32", "big", "enum"):
        n = gen_int(rng, rng.choice([8, 32, 64, 128]))
        c = bytes.fromhex(twos(n))
        r = rng.random()
        if r < 0.3:
            c = rng.choice([b"\x00", b"\xff"]) + c
        elif r < 0.4:
            c = b""
        elif r < 0.6:
            c = gen_bytes(rng, 10)
        return [(rng.choice([2, 2, 10]), c)]
    if kind == "bits":
        return [(3, bytes([rng.choice([0, 1, 7, 8, rng.randrange(256)])]) + gen_bytes(rng, 4))]
    if kind == "octets":
        return [(4, gen_bytes(rng, 6))]
    if kind == "oid":
        c = bytearray()
        for _ in range(rng.randint(0, 5)):
            c += bytes([rng.choice([0x80, 0x81, 0xff, 0x8f]) for _ in range(rng.randint(0, 5))]) + bytes([rng.randrange(128)])
        if rng.random() < 0.2:
            c += b"\x80"
        return [(6, bytes(c))]
    if kind == "string":
        tag = rng.choice([12, 18, 19, 20, 22, 27, 30, 26, 28])
        r = rng.random()
        if r < 0.5:
            c = gen_string(rng, "").encode("utf-8")
        elif r < 0.7:
            c = gen_string(rng, "").encode("utf-16-be", "surrogatepass")
            if rng.random() < 0.3:
                c += b"\x00\x00"
        else:
            c = gen_bytes(rng, 8)
        return [(tag, c)]
    if kind == "time":
        t = gen_time(rng)
        y, mo, d, h, mi, s, ns, off = t
        tag = rng.choice([23, 24])
        zone = "Z" if off == 0 else ("+" if off > 0 else "-") + f"{abs(off) // 3600:02d}{abs(off) % 3600 // 60:02d}"
        text = (f"{y:04d}" if tag == 24 else f"{y % 100:02d}") + f"{mo:02d}{d:02d}{h:02d}{mi:02d}"
        if tag == 24 or rng.random() < 0.8:
            text += f"{s:02d}"
        if tag == 24 and ns and rng.random() < 0.7:
            text += "." + f"{ns:09d}"[: rng.randint(1, 10)]
        text += rng.choice([zone, zone, "Z", "+0000", "-0000", "+2400", "-2400", "+2460", "+0060", "+1", "", "z"])
        b = bytearray(text.encode())
        if rng.random() < 0.3 and b:
            b[rng.randrange(len(b))] = ord(rng.choice("0123456789+-Z.,:a "))
        if rng.random() < 0.05:
            b = bytearray(rng.choice([b"00000101000000Z", b"20000229000000Z", b"19000229000000Z",
                                      b"000229000000Z", b"20000101240000Z", b"20000101000000.0Z"]))
        return [(tag, bytes(b))]
    return [(rng.choice([2, 4, 5, 0x30, 0x80, 0xa1]), gen_bytes(rng, 4))]


# Driver --------------------------------------------------------------------

def run(command, requests):
    payload = "".join(json.dumps(r, ensure_ascii=True) + "\n" for r in requests)
    env = dict(os.environ, TZ="UTC", GOTOOLCHAIN="local")
    process = subprocess.run(command, input=payload, text=True, capture_output=True,
                             cwd=ROOT, check=True, env=env)
    # JSON strings may hold U+0085/U+2028, which str.splitlines() would split on.
    return [json.loads(line) for line in process.stdout.split("\n") if line]


def compare(requests, probe):
    rust = run([str(probe)], requests)
    go = run(["go", "run", str(ROOT / "tools/asn1_oracle.go")], requests)
    assert len(rust) == len(go) == len(requests), (len(rust), len(go), len(requests))
    return rust, go


def main():
    started = time.monotonic()
    rng = random.Random(0x41534E31)
    subprocess.run(["cargo", "build", "--offline", "--locked", "--example", "asn1_probe"], cwd=ROOT, check=True)
    probe = ROOT / "target/debug/examples" / ("asn1_probe.exe" if os.name == "nt" else "asn1_probe")

    # Phase 1: marshal.
    marshal = []
    for kind in PRIMITIVES:
        for i in range(1500):
            params = gen_params(rng, kind, top=True) if i % 3 == 0 else ""
            s = node(kind, params)
            marshal.append({"op": "marshal", "s": s, "v": gen_value(rng, s)})
    for _ in range(4000):
        s = gen_schema(rng, 4, top=True)
        if s["k"] not in ("seq", "seqof"):
            s = node("seq", "", fields=[s, gen_schema(rng, 3)])
        marshal.append({"op": "marshal", "s": s, "v": gen_value(rng, s)})
    rust, go = compare(marshal, probe)
    marshal_ok = 0
    for i, (r, g) in enumerate(zip(rust, go)):
        if r != g:
            raise AssertionError(f"marshal {i}: {marshal[i]!r}\nRust={r!r}\nGo={g!r}")
        marshal_ok += g["ok"]

    # Phase 2: unmarshal.
    unmarshal = []
    labels = []

    def add(label, s, der):
        unmarshal.append({"op": "unmarshal", "s": s, "d": der.hex()})
        labels.append(label)

    produced = [(req["s"], bytes.fromhex(g["der"])) for req, g in zip(marshal, go) if g["ok"]]
    primitive_count = len(PRIMITIVES) * 1500
    for index, (s, der) in enumerate(produced):
        add("go-bytes", s, der)
        is_primitive = s["k"] in PRIMITIVES and index < primitive_count
        for _ in range(2 if is_primitive else 3):
            add("mutated", s, mutate(rng, der))
        if rng.random() < 0.2:
            other = node(rng.choice(PRIMITIVES + ["any"]), rng.choice(["", "", "optional", "explicit,tag:0", "tag:0"]))
            add("cross", other, der)
    for kind in PRIMITIVES + ["any"]:
        for _ in range(1500):
            tag, content = content_variants(rng, rng.choice(PRIMITIVES) if kind == "any" else kind)[0]
            form = rng.choice(["min"] * 12 + ["long1", "zero", "indef"])
            der = tlv(tag, content, form)
            params = rng.choice(["", "", "", "optional", "utf8", "generalized"]) if kind in ("string", "time") else ""
            add(f"content-{kind}", node(kind, params), der)
            if rng.random() < 0.3:
                add(f"content-{kind}", node(kind, "explicit,tag:2"), tlv(0xa2, der, rng.choice(["min", "min", "long1"])))
    rust, go = compare(unmarshal, probe)
    stats = {"accepted": 0, "rejected": 0, "strict_only_rejects": 0, "time_range_deviations": 0}
    for i, (r, g) in enumerate(zip(rust, go)):
        where = f"unmarshal {i} ({labels[i]}): {unmarshal[i]!r}\nRust={r!r}\nGo={g!r}"
        strict = r.pop("strict")
        if g.get("dev"):
            if r["ok"] or r["err"] != "time" or strict["ok"]:
                raise AssertionError("expected a time rejection for " + where)
            stats["time_range_deviations"] += 1
            continue
        r.pop("err", None)
        strict.pop("err_kind", None)
        if r != g:
            raise AssertionError(where)
        stats["accepted" if g["ok"] else "rejected"] += 1
        if strict.get("ok"):
            if not g["ok"] or {k: strict[k] for k in ("ok", "v", "rest")} != g:
                raise AssertionError(f"strict mode disagrees on {where}\nstrict={strict!r}")
        elif g["ok"]:
            if strict["err"] != "explicit_length":
                raise AssertionError(f"strict mode rejected without an explicit-length error: {where}\nstrict={strict!r}")
            stats["strict_only_rejects"] += 1
    by_label = {}
    for label in labels:
        by_label[label] = by_label.get(label, 0) + 1
    print(f"ASN.1 Go conformance: {len(marshal)} marshal vectors ({marshal_ok} encoded), "
          f"{len(unmarshal)} unmarshal vectors {json.dumps(by_label, sort_keys=True)}, "
          f"{json.dumps(stats, sort_keys=True)} passed in {time.monotonic() - started:.3f}s")


if __name__ == "__main__":
    main()
