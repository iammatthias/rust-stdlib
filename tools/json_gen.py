"""Deterministic generators of valid and mutated JSON documents for json_check.py."""
import random

PIECES = [
    "", "a", "abc", "hello world", "\\u00e9", "é", "日本語", "😀", "\\ud83d\\ude00", "\\ud83d", "\\ude00",
    "\\ud83dx", "\\ud83d\\u0041", "\\n", "\\t\\r\\b\\f", "\\\\", "\\/", "\\\"", "<script>", "&amp;", ">",
    "\u2028", "\u2029", "\\u2028", "\\u0000", "\\u001f", "\\u00FF", "\\uD800\\uDC00", "x" * 40,
    "\x7f", "\u00a0", "\ufeff", "\U0010ffff",
]
NUMBERS = [
    "0", "-0", "1", "-1", "10", "123456789", "-987654321", "1.5", "0.5", "-0.25", "1e5", "1E5", "1e+5", "1e-5",
    "1.5e10", "2.5E-3", "0e0", "0.0", "100", "1e21", "1e20", "123456789012345678901234567890", "1e999", "-1e999",
    "1e-999", "0.000001", "0.0000001", "9007199254740993", "18446744073709551615", "-9223372036854775808",
    "3.141592653589793", "1.7976931348623157e308", "4.9e-324", "5e-324", "0.1", "123.456e-7", "1e0", "12e3",
]
WS = ["", "", "", " ", "\n", "\t", "\r\n", "  ", " \n\t "]


def gen_string(rng, allow_raw=True):
    n = rng.randrange(0, 4)
    s = "".join(rng.choice(PIECES) for _ in range(n))
    return '"' + s + '"'


def gen_value(rng, depth=0):
    r = rng.random()
    if depth >= 5 or r < 0.35:
        k = rng.randrange(6)
        if k == 0:
            return "null"
        if k == 1:
            return rng.choice(["true", "false"])
        if k == 2:
            return gen_string(rng)
        return rng.choice(NUMBERS)
    ws = lambda: rng.choice(WS)
    if r < 0.67:
        items = [gen_value(rng, depth + 1) for _ in range(rng.randrange(0, 5))]
        return "[" + ws() + ("," + ws()).join(ws() + i + ws() for i in items) + ws() + "]"
    members = []
    keys = set()
    for _ in range(rng.randrange(0, 5)):
        k = gen_string(rng)
        if rng.random() < 0.9 and k in keys:
            continue
        keys.add(k)
        members.append(ws() + k + ws() + ":" + ws() + gen_value(rng, depth + 1) + ws())
    return "{" + ws() + ",".join(members) + ws() + "}"


def gen_doc(rng):
    return (rng.choice(WS) + gen_value(rng) + rng.choice(WS)).encode()


MUT_BYTES = list(b'{}[]",:\\/ \t\n\r-+.eE0123456789tfnulsarx') + [0, 1, 0x1f, 0x7f, 0x80, 0xc3, 0xe2, 0xff, 0xa8, 0xa9, 0xed]
SPLICES = [b"\xe2\x80\xa8", b"\xe2\x80\xa9", b"\xff", b"\xc3", b"\xed\xa0\x80", b"\\u", b"\\ud800", b"null", b"[", b"]", b"{", b"}", b'"']


def mutate(rng, data):
    d = bytearray(data)
    for _ in range(rng.randrange(1, 4)):
        k = rng.randrange(7)
        if not d:
            d = bytearray(rng.choice(SPLICES))
            continue
        i = rng.randrange(len(d))
        if k == 0:
            del d[i]
        elif k == 1:
            d.insert(i, rng.choice(MUT_BYTES))
        elif k == 2:
            d[i] = rng.choice(MUT_BYTES)
        elif k == 3:
            d = d[:i]
        elif k == 4:
            d[i:i] = rng.choice(SPLICES)
        elif k == 5:
            j = rng.randrange(len(d))
            a, b = min(i, j), max(i, j)
            d[b:b] = d[a:b]
        else:
            d[i:i + 1] = rng.choice(SPLICES)
    return bytes(d)


def deep_documents():
    """Documents around Go's maximum nesting depth of 10000."""
    docs = [b"[" * 10001, b"[" * 10000 + b"]" * 10000, b"[" * 10001 + b"]" * 10001]
    for n in (9999, 10000, 10001):
        docs.append(b'{"a":' * n + b"0" + b"}" * n)
        docs.append(b"[" * n + b"0" + b"]" * n)
        docs.append(b"[" * n + b"0")
    return docs


def documents(seed, count):
    rng = random.Random(seed)
    docs = []
    fixed = [b"", b" ", b"null", b"nul", b"nulll", b"[", b"]", b"{", b"}", b'"', b'"\\', b'"\\u12', b"-", b"-a", b"01", b"1.",
             b"1e", b"1e+", b"tru", b"truex", b"[1,]", b"[,1]", b"{,}", b'{"a"}', b'{"a":}', b'{"a":1,}', b"[1 2]",
             b"\xff", b'"\xff"', b'"\xc3"', b'"\xe2\x80\xa8"', b"'a'", b"[1]\n\n", b" [ ] ", b"{ }", b"[[],{}]",
             b"\x00", b"1 2", b"{\"a\":1,\"a\":2}", b"\xef\xbb\xbf1", b"[\"\\u00zz\"]", b"\"\\x\"", b"\"\x01\""]
    docs.extend(fixed)
    while len(docs) < count:
        d = gen_doc(rng)
        docs.append(d)
        if rng.random() < 0.7:
            docs.append(mutate(rng, d))
    return docs[:count]
