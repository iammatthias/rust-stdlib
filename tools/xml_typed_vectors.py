"""Request generator for the typed Marshal/Unmarshal suite of tools/xml_check.py.

Struct values travel as JSON (keys are the Go/Rust field names); the Go oracle
decodes them with encoding/json and the Rust probe with a small FromValue layer.
Unmarshal inputs are Go's own Marshal output for random values, then mutated.
"""
import base64
import json
import random
import re
import struct
import subprocess

import xml_check

STRINGS = ["", "a", "hello world", "a<b>c", "x&y", '"q"', "it's", "tab\there", "line\nbreak", "cr\rreturn",
           "日本語", "é", "--", "a--b", "-", "]]>", "x]]>y", "a--->", "�", "\x01ctl", "  pad  ", "&amp;",
           "<![CDATA[", "emoji \U0001f600", "AbC", "fail", "skip", "txt:abc", "A-xyz", "urn:x", "0", "-12", "3.5"]
WORDS = ["alpha", "beta", "gamma", "delta", "eps", "x", "y", "z"]
SPACES = ["", "", "urn:a", "urn:b", "urn:c", "http://x.org/p", "http://www.w3.org/XML/1998/namespace", "xml", "a:b", "/"]


def rs(rng, bias_empty=0.1):
    if rng.random() < bias_empty:
        return ""
    return rng.choice(STRINGS) if rng.random() < 0.7 else "".join(rng.choice("abcxyz <>&\"'\n-]") for _ in range(rng.randrange(1, 12)))


def ri(rng, bits=64, signed=True):
    if signed:
        lo, hi = -(1 << (bits - 1)), (1 << (bits - 1)) - 1
    else:
        lo, hi = 0, (1 << bits) - 1
    r = rng.random()
    if r < 0.2:
        return 0
    if r < 0.35:
        return rng.choice([lo, hi, 1, -1 if signed else 2, 255 if bits > 8 else 7])
    if r < 0.7:
        return rng.randrange(max(lo, -1000), min(hi, 1000) + 1)
    return rng.randrange(lo, hi + 1)


def f32(rng):
    r = rng.random()
    if r < 0.15:
        return 0.0
    if r < 0.2:
        return -0.0
    if r < 0.5:
        return struct.unpack("<f", struct.pack("<f", rng.choice([0.1, 1.5, 100000.0, 1e6, 1e-5, 123456.789, 3.4028235e38, 1e-45, 16777216.0, -2.5])))[0]
    while True:
        v = struct.unpack("<f", struct.pack("<I", rng.getrandbits(32)))[0]
        if v == v and abs(v) != float("inf"):
            return v


def f64(rng):
    r = rng.random()
    if r < 0.15:
        return 0.0
    if r < 0.2:
        return -0.0
    if r < 0.5:
        return rng.choice([0.1, 1.5, 100000.0, 1e6, 1e21, 1e20, 1e-4, 1e-5, 123456789.0, 5e-324, 1.7976931348623157e308, 2.5e-8, -3.75, 0.3])
    while True:
        v = struct.unpack("<d", struct.pack("<Q", rng.getrandbits(64)))[0]
        if v == v and abs(v) != float("inf"):
            return v


def opt(rng, make, p_none=0.3):
    return None if rng.random() < p_none else make()


def lst(rng, make, n=3):
    k = rng.choice([0, 0, 1, 2, n])
    return [make() for _ in range(k)]


def name(rng):
    return {"Space": rng.choice(SPACES), "Local": rng.choice(["a", "b", "item", "x:y", "", "é"])}


def attr(rng):
    return {"Name": name(rng), "Value": rs(rng)}


def b64(rng):
    return base64.b64encode(bytes(rng.randrange(256) if rng.random() < 0.3 else rng.choice(b"abc<&> \n") for _ in range(rng.randrange(0, 8)))).decode()


def incl(rng, d, p=0.85):
    return {k: v for k, v in d.items() if rng.random() < p}


def leaf(rng):
    return incl(rng, {"V": rs(rng), "N": ri(rng, 32)})


def child(rng):
    return incl(rng, {"Name": rs(rng), "Value": rs(rng)})


def base(rng):
    return incl(rng, {"ID": rs(rng), "Title": rs(rng)})


def named(rng):
    return incl(rng, {"V": rs(rng)})


def upper_word(rng):
    return rng.choice(["abc", "ABC", "", "mixed Case 1", "x"])


def customs(rng):
    word = lambda: rng.choice(["abc", "", "fail", "skip", "txt:q", "A-z", "plain"])
    return incl(rng, {
        "U": upper_word(rng), "Us": lst(rng, lambda: upper_word(rng)), "Up": opt(rng, lambda: upper_word(rng)),
        "P": incl(rng, {"A": rs(rng), "B": rs(rng)}), "T": word(), "Ts": lst(rng, word), "TA": word(), "TC": word(),
        "AV": word(), "AVs": lst(rng, word), "AVp": opt(rng, word),
    })


def scalars_value(rng):
    return incl(rng, {
        "B": rng.random() < 0.5, "I": ri(rng), "I8": ri(rng, 8), "I16": ri(rng, 16), "I32": ri(rng, 32), "I64": ri(rng),
        "U": ri(rng, 64, False), "U8": ri(rng, 8, False), "U16": ri(rng, 16, False), "U32": ri(rng, 32, False),
        "U64": ri(rng, 64, False), "F32": f32(rng), "F64": f64(rng), "S": rs(rng)}, 0.9)


GENERATORS = {
    "Scalars": scalars_value,
    "Attrs": lambda r: incl(r, {"S": rs(r), "I": ri(r), "B": r.random() < 0.5, "F": f64(r), "E": rs(r), "N": ri(r, 16),
                                "P": opt(r, lambda: rs(r)), "Q": opt(r, lambda: ri(r, 16)), "Ns": rs(r), "Ns2": rs(r),
                                "Xl": rs(r), "L": lst(r, lambda: rs(r)), "Text": rs(r)}),
    "Paths": lambda r: incl(r, {"A": rs(r), "B": rs(r), "C": rs(r), "D": lst(r, lambda: rs(r)), "E": rs(r), "F": rs(r),
                                "G": opt(r, lambda: rs(r)), "H": lst(r, lambda: ri(r, 16)), "I": rs(r)}),
    "Content": lambda r: incl(r, {"ID": rs(r), "Text": rs(r), "Note": rs(r), "Items": lst(r, lambda: rs(r))}),
    "Cdata": lambda r: incl(r, {"Data": rs(r), "Other": rs(r)}),
    "Inner": lambda r: incl(r, {"Raw": r.choice(["", "<a>x</a>", "text &amp; more", "<b/><c>1</c>", rs(r)]), "Attr": rs(r)}),
    "InnerBytes": lambda r: incl(r, {"Raw": b64(r), "T": rs(r)}),
    "Comments": lambda r: incl(r, {"C1": r.choice(["", "c", " note ", "a--b", "end-", rs(r)]), "E": rs(r), "C2": b64(r)}),
    "Anys": lambda r: incl(r, {"Name": rs(r), "Rest": lst(r, lambda: child(r)), "Extra": lst(r, lambda: attr(r))}),
    "Ptrs": lambda r: incl(r, {"P": opt(r, lambda: rs(r)), "Q": opt(r, lambda: leaf(r)), "R": lst(r, lambda: opt(r, lambda: leaf(r))),
                               "L": lst(r, lambda: ri(r, 16)), "B": b64(r), "A": [ri(r, 16) for _ in range(r.choice([0, 3]))],
                               "O": opt(r, lambda: ri(r, 16))}),
    "Tree": lambda r: tree(r, 0),
    "Derived": lambda r: incl(r, {"Base": base(r), "Title2": rs(r), "Extra": rs(r)}),
    "Shadow": lambda r: incl(r, {"Base": base(r), "Title": rs(r)}),
    "PtrEmbed": lambda r: incl(r, {"Base": opt(r, lambda: base(r)), "Extra": rs(r)}),
    "PtrEmbedEl": lambda r: incl(r, {"BaseEl": opt(r, lambda: incl(r, {"Title": rs(r), "Note": rs(r)})), "Extra": rs(r)}),
    "Conflict": lambda r: incl(r, {"A": rs(r), "B": rs(r)}),
    "ConflictPath": lambda r: incl(r, {"A": rs(r), "B": rs(r)}),
    "BadFlags": lambda r: incl(r, {"A": rs(r)}),
    "BadChain": lambda r: incl(r, {"A": rs(r)}),
    "Trailing": lambda r: incl(r, {"A": rs(r)}),
    "NsNoName": lambda r: incl(r, {"A": rs(r)}),
    "OmitBad": lambda r: incl(r, {"A": rs(r)}),
    "UsesNamed": lambda r: incl(r, {"N": named(r)}),
    "UsesNamedOK": lambda r: incl(r, {"N": named(r), "M": named(r), "L": lst(r, lambda: named(r))}),
    "Nss": lambda r: incl(r, {"A": rs(r), "B": rs(r), "C": rs(r), "D": rs(r),
                              "L": lst(r, lambda: incl(r, {"V": rs(r), "K": rs(r)}))}),
    "NoNs": lambda r: incl(r, {"V": rs(r)}),
    "Omit": lambda r: incl(r, {"S": rs(r), "I": ri(r, 16), "B": r.random() < 0.5, "F": f64(r), "L": lst(r, lambda: rs(r)),
                               "P": opt(r, lambda: rs(r)), "Q": opt(r, lambda: leaf(r)), "St": leaf(r), "By": b64(r),
                               "M": {} if r.random() < 0.8 else {"k": 1}}, 0.5),
    "Maps": lambda r: incl(r, {"M": {} if r.random() < 0.5 else {"k": ri(r, 16)}}),
    "Defaults": lambda r: incl(r, {"Title": rs(r), "Count": ri(r, 16), "Body": rs(r)}),
    "BadComment": lambda r: incl(r, {"C": r.choice(["ok", "a--b", "", "-", "x-", "--", rs(r)])}),
    "BadCommentType": lambda r: incl(r, {"C": ri(r, 8)}),
    "Chars": lambda r: incl(r, {"I": ri(r, 16), "U": ri(r, 16, False), "F": f32(r), "B": r.random() < 0.5, "Y": b64(r),
                                "S": opt(r, lambda: rs(r))}),
    "Customs": customs,
    "LeakyHolder": lambda r: incl(r, {"L": incl(r, {"V": rs(r)})}),
    "OverHolder": lambda r: incl(r, {"O": incl(r, {"V": rs(r)})}),
    "FailHolder": lambda r: incl(r, {"F": incl(r, {"V": rs(r)})}),
    "LazyHolder": lambda r: incl(r, {"L": incl(r, {"V": rs(r)})}),
    "RawHolder": lambda r: incl(r, {"R": incl(r, {"V": rs(r)})}),
    "NameHolder": lambda r: incl(r, {"N": name(r), "A": attr(r)}),
}


def tree(rng, depth):
    d = {"Value": rs(rng)}
    if depth < 3:
        d["Kids"] = [tree(rng, depth + 1) for _ in range(rng.choice([0, 0, 1, 2]))]
    return d


BARE = {
    "int": lambda r: ri(r), "int8": lambda r: ri(r, 8), "uint16": lambda r: ri(r, 16, False), "uint64": lambda r: ri(r, 64, False),
    "float32": f32, "float64": f64, "bool": lambda r: r.random() < 0.5, "string": rs,
    "strings": lambda r: lst(r, lambda: rs(r)), "ints": lambda r: lst(r, lambda: ri(r, 16)), "bytes": b64,
    "bytearr": lambda r: [ri(r, 8, False), ri(r, 8, False)], "optstr": lambda r: opt(r, lambda: rs(r)),
    "map": lambda r: {} if r.random() < 0.5 else {"a": 1}, "nil": lambda r: None, "upper": upper_word,
    "txt": lambda r: r.choice(["abc", "fail", ""]), "name": name,
}


def marshal_requests(rng):
    out = []
    for struct_name, gen in GENERATORS.items():
        for _ in range(55):
            prefix = rng.choice(["", "", "", ">", "# "])
            indent = rng.choice(["", "  ", "  ", "\t", "--"])
            out.append(f"M\t{struct_name}\t{prefix.encode().hex()}\t{indent.encode().hex()}\t{json.dumps(gen(rng))}")
    for struct_name, gen in GENERATORS.items():
        for _ in range(6):
            mode = rng.choice(["el", "el", "elplain", "elbad"])
            prefix = rng.choice(["", ">"])
            indent = rng.choice(["", "  "])
            out.append(f"M\t{mode}:{struct_name}\t{prefix.encode().hex()}\t{indent.encode().hex()}\t{json.dumps(gen(rng))}")
    for kind, gen in BARE.items():
        for _ in range(14):
            prefix = rng.choice(["", ">"])
            indent = rng.choice(["", "  "])
            out.append(f"M\tbare:{kind}\t{prefix.encode().hex()}\t{indent.encode().hex()}\t{json.dumps(gen(rng))}")
    for _ in range(1400):
        out.append(f"M\tbare:f32bits\t\t\t{rng.getrandbits(32)}")
        out.append(f"M\tbare:f64bits\t\t\t{rng.getrandbits(64)}")
    for bits in (0, 1 << 31, 0x7F800000, 0xFF800000, 0x7FC00000, 0x00000001, 0x7F7FFFFF, 0x358637BD, 0x49742400, 0x4B189680):
        out.append(f"M\tbare:f32bits\t\t\t{bits}")
    for bits in (0, 1 << 63, 0x7FF0000000000000, 0xFFF0000000000000, 0x7FF8000000000000, 1, 0x7FEFFFFFFFFFFFFF,
                 0x3EB0C6F7A0B5ED8D, 0x444B1AE4D6E2EF50, 0x4415AF1D78B58C40, 0x412E848000000000):
        out.append(f"M\tbare:f64bits\t\t\t{bits}")
    return out


VALUES = ["x", "", " 12 ", "-1", "256", "99999999999999999999", "1e3", "0x10", "true", "T", "yes", "1.5", "inf", "NaN",
          "+5", "1_0", "٣", "-0", "1e999", "4294967296", "-129", "0", "TRUE", "f", "1.", ".5", " ", "\n7\n"]


def mutate_values(rng, doc: str) -> str:
    segments = list(re.finditer(r">([^<>]*)<|=\"([^\"]*)\"", doc))
    if not segments:
        return doc
    m = rng.choice(segments)
    group = 1 if m.group(1) is not None else 2
    return doc[:m.start(group)] + rng.choice(VALUES) + doc[m.end(group):]


def rename_root(rng, doc: str) -> str:
    return re.sub(r"^<(\w+)", lambda m: "<" + rng.choice(["other", "WRONG", m.group(1) + "x"]), doc, count=1) \
        if rng.random() < 0.5 else re.sub(r"^<(\w+)", lambda m: f'<{m.group(1)} xmlns="urn:zzz"', doc, count=1)


def unmarshal_requests(rng, marshal_reqs):
    # Go's own Marshal output, then mutations.
    payload = "".join(r + "\n" for r in marshal_reqs if r.split("\t")[1] in GENERATORS) + ""
    kept = [r for r in marshal_reqs if r.split("\t")[1] in GENERATORS]
    go = xml_check.run(xml_check.ORACLE, "".join(r + "\n" for r in kept))
    seeds = {}
    for req, line in zip(kept, go):
        first = line.split(" | ")[0]
        if first.startswith("OK "):
            seeds.setdefault(req.split("\t")[1], []).append(bytes.fromhex(first[3:]).decode("utf-8", "replace"))
    out = []
    for struct_name in GENERATORS:
        docs = seeds.get(struct_name) or ["<x/>"]
        for _ in range(40):
            doc = rng.choice(docs)
            r = rng.random()
            if r < 0.3:
                data = doc.encode()
            elif r < 0.5:
                data = mutate_values(rng, doc).encode()
            elif r < 0.6:
                data = rename_root(rng, doc).encode()
            elif r < 0.8:
                data = xml_check.mutate(rng, doc.encode())
            else:
                data = ("<?xml version='1.0'?>" + doc.replace(">", "><!--c-->", 1) + "<!--tail-->").encode()
            out.append(f"U\t{struct_name}\t{data.hex()}")
        out.append(f"U\t{struct_name}\t")
        out.append(f"U\t{struct_name}\t{'<a>'.encode().hex()}")
    bare_docs = {
        "int": ["<int>5</int>", "<x> 42 </x>", "<x/>", "<x>1.5</x>", "<x>-0</x>", "<x>9999999999999999999</x>", "<x>a<b>1</b></x>", "text", "<x>+7</x>"],
        "int8": ["<x>127</x>", "<x>128</x>", "<x>-128</x>", "<x>-129</x>"],
        "uint16": ["<x>65535</x>", "<x>65536</x>", "<x>-1</x>", "<x>+1</x>"],
        "uint64": ["<x>18446744073709551615</x>", "<x>18446744073709551616</x>"],
        "float32": ["<x>1.5</x>", "<x>1e39</x>", "<x> .5 </x>", "<x>NaN</x>", "<x>inf</x>", "<x>0x1p-2</x>", "<x>1_0.5</x>", "<x>x</x>"],
        "float64": ["<x>1e308</x>", "<x>1e309</x>", "<x>-Inf</x>", "<x>+nan</x>", "<x>1e-400</x>", "<x>1.7976931348623157e308</x>"],
        "bool": ["<x>true</x>", "<x> T </x>", "<x>1</x>", "<x>yes</x>", "<x></x>", "<x>FALSE</x>", "<x>False</x>", "<x>tRUE</x>"],
        "string": ["<x>a&amp;b</x>", "<x><![CDATA[<raw>]]></x>", "<x>a<y>skipped</y>b</x>", "<x/>", "<x>1<!--c-->2</x>", "<x>\r\n</x>"],
        "strings": ["<x>a</x>", "<a>1</a>", "<s>x</s>"],
        "ints": ["<x>1</x>", "<x>bad</x>", "<x>3</x>"],
        "bytes": ["<x>abc</x>", "<x/>"],
        "optstr": ["<x>v</x>", "<x/>"],
        "name": ["<n xmlns='urn:q'/>", "<a:b xmlns:a='urn:z'/>", "<x/>"],
        "upper": ["<x>ABC</x>", "<x>MiXed</x>", "<x/>"],
        "txt": ["<x>txt:abc</x>", "<x>fail</x>", "<x>a<b/>c</x>", "<x/>"],
        "bytearr": ["<x>ab</x>"],
    }
    for kind, docs in bare_docs.items():
        for doc in docs:
            out.append(f"U\tbare:{kind}\t{doc.encode().hex()}")
            for _ in range(3):
                out.append(f"U\tbare:{kind}\t{xml_check.mutate(rng, doc.encode()).hex()}")
    return out


def requests(rng):
    m = marshal_requests(rng)
    return m + unmarshal_requests(rng, m)
