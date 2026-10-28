#!/usr/bin/env python3
"""Differentially check encoding/json/jsontext against Go: Decoder token and
value streams (with chunked readers, offsets, stack pointers, unread buffers
and error text), Encoder token and value writes under every option, Value
Format/Compact/Indent/Canonicalize, Pointer operations, AppendQuote,
AppendUnquote and AppendFloat."""
import collections
import json
import math
import pathlib
import random
import re
import struct
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import json_gen  # noqa: E402

RUST = ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "jsontext_probe"]
GO = ["go", "run", "tools/jsontext_oracle.go"]


def build_go(tmp):
    """Compiles the Go oracle once instead of once per batch."""
    exe = pathlib.Path(tmp) / "jsontext_oracle"
    subprocess.run(["go", "build", "-o", str(exe), "tools/jsontext_oracle.go"], cwd=ROOT, check=True)
    return [str(exe)]


def hx(b):
    return b.hex() or "-"


def run(cmd, payload, what):
    result = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if result.returncode:
        errs = [l for l in result.stderr.splitlines() if not l.startswith(("warning", " ", "|", "=")) and l.strip()]
        raise RuntimeError(f"{what} failed:\n" + "\n".join(errs[-30:]))
    return result.stdout.split("\n")[:-1]


def show(line):
    def fix(m):
        try:
            return bytes.fromhex(m.group(0)).decode("utf-8", "replace")
        except ValueError:
            return m.group(0)

    return re.sub(r"(?<=E|\|p|:)[0-9a-f]{4,}", fix, line)[:600]


def compare(label, requests, verbose=6):
    payload = "".join(r + "\n" for r in requests)
    got, want = run(RUST, payload, "Rust jsontext probe"), run(GO, payload, "Go jsontext oracle")
    if len(got) != len(requests) or len(want) != len(requests):
        raise AssertionError(f"wrong record count: rust={len(got)} go={len(want)} want={len(requests)}")
    bad = [i for i, (x, y) in enumerate(zip(got, want)) if x != y]
    if bad:
        seen = collections.Counter()
        shown = 0
        for i in bad:
            key = (requests[i].split()[0], requests[i].split()[1][:8], re.sub(r"[0-9a-f]+", "N", got[i])[:40])
            seen[key] += 1
            if seen[key] == 1 and shown < verbose:
                shown += 1
                print(f"MISMATCH [{label}] request: {requests[i][:400]}\n  Rust: {got[i][:900]}\n  Go:   {want[i][:900]}",
                      file=sys.stderr)
        raise AssertionError(f"{label}: {len(bad)} of {len(requests)} vectors differ ({len(seen)} kinds)")
    return len(requests)


TOKEN_RE = re.compile(rb'"(?:[^"\\]|\\.)*"|-?[0-9][0-9.eE+-]*|true|false|null|[\[\]{}]')


def lex(doc):
    """Token ops for a valid document, or None."""
    ops = []
    for m in TOKEN_RE.finditer(doc):
        t = m.group(0)
        c = t[:1]
        if c in b"[]{}":
            ops.append("t" + c.decode())
        elif t == b"true":
            ops.append("tt")
        elif t == b"false":
            ops.append("tf")
        elif t == b"null":
            ops.append("tn")
        elif c == b'"':
            try:
                s = json.loads(t.decode("utf-8", "replace"))
            except ValueError:
                return None
            ops.append("ts" + hx(s.encode("utf-8", "surrogatepass")))
        else:
            text = t.decode()
            try:
                if re.fullmatch(r"-?[0-9]+", text):
                    n = int(text)
                    if -(1 << 63) <= n < (1 << 63):
                        ops.append(f"ti{n}")
                    elif 0 <= n < (1 << 64):
                        ops.append(f"tu{n}")
                    else:
                        ops.append("tF%016x" % struct.unpack(">Q", struct.pack(">d", float(text)))[0])
                else:
                    ops.append("tF%016x" % struct.unpack(">Q", struct.pack(">d", float(text)))[0])
            except (OverflowError, ValueError):
                ops.append("tF7ff0000000000000")
    return ops


SPECIAL_TOKENS = ["tn", "tt", "tf", "t{", "t}", "t[", "t]", "ts", "tsc3a9", "tsff", "tse280a8", "ts3c3e26", "ti0", "ti-1", "tu0",
                  "tu18446744073709551615", "ti-9223372036854775808", "tF0", "tF8000000000000000", "tF7ff8000000000000",
                  "tF7ff0000000000000", "tFfff0000000000000", "tF3ff8000000000000", "tF444b1ae4d6e2ef50", "tG3f800000", "tG7f800000",
                  "tG0", "tG80000000", "tGffc00000", "tx", "tb1", "tb0", "?", "tF0000000000000001", "tF7fefffffffffffff",
                  "tF3eb0c6f7a0b5ed8d", "tF3e7ad7f29abcaf48"]


def mutate_ops(rng, ops):
    ops = list(ops)
    for _ in range(rng.randrange(1, 3)):
        k = rng.randrange(5)
        i = rng.randrange(len(ops) + 1)
        if k == 0 and ops:
            del ops[min(i, len(ops) - 1)]
        elif k == 1:
            ops.insert(i, rng.choice(SPECIAL_TOKENS))
        elif k == 2 and ops:
            ops[min(i, len(ops) - 1)] = rng.choice(SPECIAL_TOKENS)
        elif k == 3 and ops:
            j = min(i, len(ops) - 1)
            ops.insert(j, ops[j])
        elif k == 4:
            ops.insert(i, "v" + hx(json_gen.gen_doc(rng)))
    return ops


ENCODE_OPTS = ["-", "d", "u", "du", "h", "j", "hj", "p", "hp", "jp", "i", "f", "if", "r", "ifr", "m", "mI", "mT", "mP", "mIP",
               ":", ",", ":,", "m:", "m,", "I", "T", "P", "X", "mX", "ifrd", "dm", "uhj", "mc", "m:k", "hjpdu", "mTP:,", "Dc", "UH"]
ENCODE_OPTS = [o for o in ENCODE_OPTS if "H" not in o]
DECODE_OPTS = ["-", "d", "u", "du", "D", "U"]
VALUE_OPS = ["valid", "format", "compact", "indent", "canon", "kind", "string", "clone", "marshal", "appendformat"]
VALUE_OPTS = ENCODE_OPTS


def f64bits(f):
    return "%016x" % struct.unpack(">Q", struct.pack(">d", f))[0]


def f32bits(f):
    return "%08x" % struct.unpack(">I", struct.pack(">f", f))[0]


def token_requests():
    """The token constructors and raw tokens of Go's TestTokenAccessors."""
    reqs = ["tokacc zero -"] + [f"tokacc {c} -" for c in ("null", "false", "true", "bo", "eo", "ba", "ea")]
    reqs += ["tokacc bool 0", "tokacc bool 1", "tokacc string -", "tokacc string " + hx(b"hello, world!"),
             "tokacc string " + hx("é\u2028".encode()), "tokacc string ff"]
    inf, nan = float("inf"), float("nan")
    for f in (0.0, -0.0, nan, inf, -inf, 3.141592653589793, -3.4028234663852886e38, 3.4028234663852886e38, 123.0,
              7.038531e-26, 0.1, 1e20, 16777216.0, 0.5):
        reqs.append(f"tokacc f32 {f32bits(f)}")
    reqs += ["tokacc f32 00000001", "tokacc f32 7f7fffff", "tokacc f32 ff7fffff"]
    for f in (0.0, -0.0, nan, inf, -inf, 3.141592653589793, -1.7976931348623157e308, 1.7976931348623157e308, 123.0,
              7.038531e-26, 0.1, 1e300, 5e-324, 9223372036854775808.0, 18446744073709551616.0, -9223372036854775808.0):
        reqs.append(f"tokacc f64 {f64bits(f)}")
    for n in (-(1 << 63), -(1 << 63) + 1, -1, 0, 1, (1 << 63) - 2, (1 << 63) - 1):
        reqs.append(f"tokacc int {n}")
    for n in (0, 1, (1 << 64) - 2, (1 << 64) - 1, 1 << 63):
        reqs.append(f"tokacc uint {n}")
    for t in ("-0", "1e1000", "-1e1000", "0.1", "0.5", "0.9", "1.0", "1.1", "123", "-0.1", "-0.5", "-0.9", "-1.0", "-1.1",
              "-123", "99999999999999999999", "-99999999999999999999", "3.1415927", "3.141592653589793",
              "-9223372036854775807", "-9223372036854775808", "-9223372036854775809", "9223372036854775806",
              "9223372036854775807", "9223372036854775808", "18446744073709551614", "18446744073709551615",
              "18446744073709551616", "9000000000.0000001", "7.038531e-26", "0", "1E5", "1e-7", "100e-2",
              '"hello, world!"', '"a\\nb"', '"\\u00e9"', '"NaN"', '"Infinity"', '"-Infinity"', '"1"', "true", "null",
              "[", "}", '""'):
        reqs.append(f"tokacc raw {hx(t.encode())}")
    return reqs


def decode_requests(rng):
    docs = json_gen.documents(0x4A534F4E, 1400)
    docs += json_gen.documents(0x4455504C, 300)  # duplicates appear in the fixed set
    # Streams of several values, and trailing garbage.
    for _ in range(300):
        n = rng.randrange(1, 4)
        docs.append(b" ".join(json_gen.gen_doc(rng) for _ in range(n)) + rng.choice([b"", b"\n", b" ,", b"]", b" ", b"}", b":"]))
    # Duplicate names.
    docs += [b'{"a":1,"a":2}', b'{"a":1,"b":{"c":1,"c":2}}', b'{"a\\u0062":1,"ab":2}', b'[{"x":1},{"x":2}]', b'{"a":{"b":1,"b":2},"a":1}',
             b'{"\\ud800":1,"\\ud800":2}', b'{"\xff":1,"\xff":2}']
    reqs = []
    op_sets = ["T", "V", "KT", "S", "TVS", "KV", "TTKS", "K", "TS", "VT"]
    for d in docs:
        h = hx(d)
        for _ in range(5):
            chunk = rng.choice(["b", "0", "1", "3", "7", "64"])
            reqs.append(f"decode {chunk} {rng.choice(DECODE_OPTS)} {rng.choice(op_sets)} {h}")
        reqs.append(f"decode b - T {h}")
        reqs.append(f"decode 1 - V {h}")
    for d in json_gen.deep_documents():
        reqs.append(f"decode b - D {hx(d)}")
        reqs.append(f"decode b - V {hx(d)}")
        reqs.append(f"decode 0 - S {hx(d)}")
        reqs.append(f"decode 1 - D {hx(d)}")
    return reqs


def encode_requests(rng):
    docs = [d for d in json_gen.documents(0x454E43, 1500)]
    reqs = []
    for d in docs:
        ops = lex(d)
        if ops is None:
            continue
        for _ in range(3):
            reqs.append("encode w " + rng.choice(ENCODE_OPTS) + " " + " ".join(ops + ["?"]) if ops else "encode w - ?")
        for _ in range(3):
            reqs.append("encode b " + rng.choice(ENCODE_OPTS) + " " + " ".join(mutate_ops(rng, ops) + ["?"]))
    # Several top-level values, and tokens in odd places.
    for _ in range(400):
        n = rng.randrange(1, 4)
        ops = []
        for _ in range(n):
            ops += lex(json_gen.gen_doc(rng)) or []
        reqs.append("encode w " + rng.choice(ENCODE_OPTS) + " " + " ".join(ops + ["?"]))
    # WriteValue of documents (valid, invalid and mutated), possibly nested in a token context.
    for d in json_gen.documents(0x56414C, 1500):
        ctx = rng.choice([[], ["t["], ["t{", "tsc3a9"], ["t{", "ts61", "tn", "ts61"], ["tn"], ["t[", "ti1"]])
        reqs.append("encode w " + rng.choice(ENCODE_OPTS) + " " + " ".join(ctx + ["v" + hx(d), "?", "v" + hx(d), "?"]))
    return reqs


def value_requests(rng):
    reqs = []
    docs = json_gen.documents(0x56414C55, 1800)
    # Documents with members to reorder.
    docs += [b'{"b":1,"a":2}', b'{"\\u20ac":1,"\\ud83d\\ude00":2,"\\ue000":3}', b'{"a":{"z":1,"y":2},"A":[{"d":1,"c":2}]}',
             b' { "b" : 1 , "a" : { "d" : 1 , "c" : 2 } , "": 0 } ', b'{"1":1,"10":2,"2":3}', b'{"a":1,"a":0}',
             b'[1e0,10000000000000000,123456789012345678,1E400,-0,0.0,1.50,100e-2,12345678901234567890,0.000001,1e-7]',
             b'"\\u00e9\\/\\u001f\\ud800"', b'"a\\u2028<>&"']
    for d in docs:
        h = hx(d)
        for op in VALUE_OPS:
            if op == "string":
                try:
                    d.decode()
                except UnicodeDecodeError:
                    continue  # a Rust String cannot hold invalid UTF-8
            for _ in range(2 if op in ("format", "canon", "indent", "compact") else 1):
                reqs.append(f"value {op} {rng.choice(VALUE_OPTS)} {h}")
    return reqs


def quote_requests(rng):
    reqs = []
    pieces = [b"", b"a", b"<>&", b"\\", b'"', b"\n\t\r\b\f", b"\x00\x1f\x7f", "é".encode(), " ".encode(), " ".encode(), b"\xff",
              b"\xc3", b"\xed\xa0\x80", "😀".encode(), b"\xf4\x90\x80\x80", b"/", b"\\u", b"\\u00e9", b"\\ud83d\\ude00", b"\\ud83d", b"\\ude00",
              b"\\ud83dx", b"\\x", b"\\/", b"\\u00zz", b"\\n", b"\\\"", b"\\\\", b"\\b\\f\\r\\t"]
    for _ in range(2500):
        s = b"".join(rng.choice(pieces) for _ in range(rng.randrange(0, 6)))
        reqs.append(f"quote {hx(s)}")
        q = b'"' + s + rng.choice([b'"', b"", b'"x', b'""', b'"\n'])
        reqs.append(f"unquote {hx(q)}")
        reqs.append(f"unquote {hx(s)}")
    return reqs


def float_requests(rng):
    reqs = []
    specials = [0, 1 << 63, 0x3FF0000000000000, 0xBFF0000000000000, 0x7FEFFFFFFFFFFFFF, 1, 0x7FF0000000000000, 0x7FF8000000000000,
                0x444B1AE4D6E2EF50, 0x444B1AE4D6E2EF4F, 0x3EB0C6F7A0B5ED8D, 0x3EB0C6F7A0B5ED8C, 0x4415AF1D78B58C40, 0x3E45798EE2308C3A,
                0x3F847AE147AE147B, 0x40C3880000000000, 0x4341C37937E08000, 0x7F7FFFFF, 0x00800000, 0x1, 0x358637BD, 0x3F800000]
    for _ in range(1500):
        bits = 64 if rng.random() < 0.6 else 32
        if rng.random() < 0.3:
            n = rng.choice(specials)
        elif bits == 64:
            exp = rng.randrange(-30, 30)
            n = struct.unpack(">Q", struct.pack(">d", rng.random() * 10.0 ** exp))[0]
            if rng.random() < 0.3:
                n = rng.getrandbits(64)
        else:
            n = rng.getrandbits(32)
            if rng.random() < 0.5:
                n = struct.unpack(">I", struct.pack(">f", float(rng.random() * 10.0 ** rng.randrange(-8, 25))))[0]
        reqs.append(f"float {bits} {n:x}")
    return reqs


def pointer_requests(rng):
    reqs = []
    names = ["", "a", "b", "0", "1", "~", "/", "~0", "~1", "~2", "é", "a/b", "a~b", "x y", " ", "😀", "-", "00"]
    for _ in range(2500):
        k = rng.randrange(4)
        p = "".join("/" + rng.choice(names).replace("~", "~0").replace("/", "~1") if rng.random() < 0.8
                    else "/" + rng.choice(names) for _ in range(rng.randrange(0, 5)))
        if k == 0:
            p = rng.choice(["", "/", "//", "a", "~", "/~", "/~0", "/~1/~", "/a~", "/a~2", "~0"]) + (p if rng.random() < 0.5 else "")
        other = p + rng.choice(["", "/x", "/", "x", "/~0", "/a/b"]) if rng.random() < 0.5 else rng.choice(names)
        for op in ("valid", "parent", "last", "tokens"):
            reqs.append(f"pointer {op} {hx(p.encode())} -")
        reqs.append(f"pointer append {hx(p.encode())} {hx(rng.choice(names).encode())}")
        reqs.append(f"pointer contains {hx(p.encode())} {hx(other.encode())}")
    for s in ("", " ", "\t", "  ", "    ", "\t\t", "x", " x", "\n", "é", "\t "):
        reqs.append(f"options indent {hx(s.encode())}")
        reqs.append(f"options prefix {hx(s.encode())}")
    return reqs


def main():
    global GO
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        GO = build_go(tmp)
        run_all()


def run_all():
    rng = random.Random(0x4A545854)
    total = 0
    total += compare("token", token_requests())
    total += compare("decode", decode_requests(rng))
    total += compare("encode", encode_requests(rng))
    total += compare("value", value_requests(rng))
    total += compare("quote", quote_requests(rng))
    total += compare("float", float_requests(rng))
    total += compare("pointer", pointer_requests(rng))
    print(f"jsontext Go differential: {total} vectors passed")


if __name__ == "__main__":
    main()
