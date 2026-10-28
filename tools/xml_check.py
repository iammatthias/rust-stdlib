#!/usr/bin/env python3
"""Differentially check encoding/xml against Go.

Four suites share one Go oracle (tools/xml_oracle.go + tools/xml_typed.go):

* tokens: thousands of generated and mutated documents decoded with Token,
  RawToken and Skip under strict/non-strict, AutoClose, Entity and DefaultSpace
  settings; token stream, error text, line numbers and offsets must match;
* escape: EscapeText/Escape on random byte strings;
* encode-token: Encoder.EncodeToken sequences (valid and invalid) with indent;
* typed: Marshal/MarshalIndent/Unmarshal of generated typed values through the
  derive macros (tools/derive-check/src/bin/xml_typed_probe.rs).
"""
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ORACLE = ["go", "run", str(ROOT / "tools/xml_oracle.go"), str(ROOT / "tools/xml_typed.go")]
EXAMPLE = ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "xml_probe"]
TYPED = ["cargo", "run", "--quiet", "--offline", "--locked", "--manifest-path",
         str(ROOT / "tools/derive-check/Cargo.toml"), "--bin", "xml_typed_probe"]

NAMES = ["a", "b", "item", "p:x", "q:y", "xml:lang", "xmlns:p", "xmlns", "ns:thing", "é", "名前",
         "a.b", "a-b", "_u", "x1", "br", "img", "P", "BR", "html", "body"]
URLS = ["urn:one", "urn:two", "http://example.com/ns", "", "http://www.w3.org/XML/1998/namespace"]
CLEAN_TEXTS = ["hello", "a &amp; b", "&lt;tag&gt;", "&#65;&#x42;", "a\r\nb", "tab\there", "  ", "\n", "日本語",
               "&apos;&quot;", "&#1114111;", "x ] y", "]]", "a > b", "\ufffd", "'\"", "&#x1F600;"]
CLEAN_NAMES = ["a", "b", "item", "p:x", "q:y", "xml:lang", "ns:thing", "é", "名前", "a.b", "a-b", "_u", "x1", "html"]
TEXTS = ["hello", "a &amp; b", "&lt;tag&gt;", "&#65;&#x42;", "&nbsp;&copy;", "&foo;&x;", "&bad;", "&",
         "a\r\nb", "tab\there", "]]", "x]]>y", "&#0;", "&#xD800;", "&#x110000;", "&#;", "&#x;", "&amp",
         "  ", "\n", "日本語", "&e;", "&lt", "a<b", "\ufffd", "\x01", "&#1114111;", "&apos;&quot;"]
DICT = ["<", ">", "&", "&#", "]]>", "--", "<!--", "-->", "<![CDATA[", "<![", "<!", "</", "/>", "<?", "?>",
        "'", '"', "=", "\r", "\r\n", "\n", ":", "::", "\x00", "\xff", "\xc3", "\xe2\x82", " ", "xmlns", "xmlns:",
        "<?xml version='1.0'?>", "<?xml version=\"2.0\"?>", "<?xml encoding='latin1'?>",
        "<!DOCTYPE x [<!ENTITY e 'v'>]>", "<!-- c -->", "&#x", "&amp;", "&nbsp;"]


def attr(rng, clean):
    names = CLEAN_NAMES if clean else NAMES
    name = rng.choice(names)
    texts = CLEAN_TEXTS if clean else TEXTS
    value = rng.choice(texts + ["", "v", URLS[rng.randrange(len(URLS))]])
    q = rng.choice(['"', "'"])
    if name == "xmlns" or name.startswith("xmlns:"):
        value = rng.choice(URLS)
    if not clean and rng.random() < 0.05:
        return f"{name}={value}"
    if not clean and rng.random() < 0.03:
        return name
    return f"{name}={q}{value.replace(q, '')}{q}"


def element(rng, depth, clean):
    names = CLEAN_NAMES if clean else NAMES
    name = rng.choice(names)
    seen = set()
    attrs = ""
    for _ in range(rng.choice([0, 0, 1, 2, 3])):
        a = attr(rng, clean)
        key = a.split("=")[0]
        if clean and key in seen:
            continue
        seen.add(key)
        attrs += " " + a
    if rng.random() < 0.15 or depth > 5:
        return f"<{name}{attrs}/>" if rng.random() < 0.7 else f"<{name}{attrs}></{name}>"
    body = "".join(content(rng, depth + 1, clean) for _ in range(rng.choice([0, 1, 2, 3])))
    end = name if clean or rng.random() > 0.04 else rng.choice(NAMES)
    if not clean and rng.random() < 0.05:
        return f"<{name}{attrs}>{body}"
    return f"<{name}{attrs}>{body}</{end}>"


def content(rng, depth, clean):
    r = rng.random()
    if r < 0.4:
        return element(rng, depth, clean)
    if r < 0.65:
        return rng.choice(CLEAN_TEXTS if clean else TEXTS)
    if r < 0.75:
        return f"<!--{rng.choice(['c', ' x ', '', 'a-b', '-x'] if clean else ['c', ' x ', '', 'a-b', 'a--b', '-'])}-->"
    if r < 0.82:
        return f"<![CDATA[{rng.choice(['raw <&>', '', ']]', 'a]]b', '&amp;', 'a\r\nb'])}]]>"
    if r < 0.9:
        return rng.choice(["<?pi data?>", "<?pi?>", "<?x  y z ?>", "<?a b?c?>"] if clean
                          else ["<?pi data?>", "<?pi?>", "<?x  y z ?>", "<?xml version='1.0'?>", "<?a ?b?>"])
    return rng.choice(["<!DOCTYPE d>", "<!DOCTYPE d [<!ENTITY e \"v>\">]>", "<!ELEMENT a (b)>",
                       "<!DOCTYPE x <!-- c --> y>", "<!ATTLIST a b 'c'>", "<!-- c --><!x>"])


def document(rng, clean):
    parts = []
    if rng.random() < 0.3:
        decl = ["<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "<?xml version='1.0' encoding='utf-8'?>",
                "<?xml encoding='x'?>"]
        if not clean:
            decl += ["<?xml version=\"1.0\" encoding=\"fail\"?>", "<?xml version=\"1.1\"?>",
                     "<?xml version=\"1.0\" encoding=\"latin1\"?>"]
        else:
            decl += ["<?xml version=\"1.0\" encoding=\"latin1\"?>"]
        parts.append(rng.choice(decl) + rng.choice(["", "\n"]))
    for _ in range(rng.choice([1, 1, 1, 2])):
        parts.append(element(rng, 0, clean))
        if rng.random() < 0.3:
            parts.append(rng.choice(["\n", " ", "text", "<!--t-->"]))
    return "".join(parts)


def html_document(rng):
    tags = ["br", "img", "p", "div", "hr", "li", "input", "BR", "Img", "meta", "a"]
    out = []
    for _ in range(rng.randrange(1, 8)):
        t = rng.choice(tags)
        a = rng.choice(["", " src=x.png", " class=\"c\"", " disabled", " href='h'", " a=1 b=2"])
        out.append(f"<{t}{a}>" + rng.choice(["", "text", "&nbsp;&copy;", "&amp;", "x &y z"]))
        if rng.random() < 0.4:
            out.append(f"</{rng.choice(tags)}>")
    return "".join(out)


def mutate(rng, data: bytes) -> bytes:
    data = bytearray(data)
    for _ in range(rng.choice([1, 1, 2, 3])):
        kind = rng.randrange(6)
        pos = rng.randrange(len(data) + 1)
        if kind == 0 and data:
            del data[min(pos, len(data) - 1)]
        elif kind == 1:
            data[pos:pos] = rng.choice(DICT).encode("latin-1", "replace") if rng.random() < 0.5 else rng.choice(DICT).encode()
        elif kind == 2 and data:
            data[min(pos, len(data) - 1)] = rng.randrange(256)
        elif kind == 3:
            del data[pos:]
        elif kind == 4 and data:
            a = rng.randrange(len(data))
            data[pos:pos] = data[a:a + rng.randrange(1, 12)]
        else:
            data[pos:pos] = bytes(rng.choice([0x3c, 0x3e, 0x26, 0x3b, 0x22, 0x27]) for _ in range(rng.randrange(1, 3)))
    return bytes(data)


def token_requests(rng, count):
    requests = []
    seeds = [
        '<?xml version="1.0" encoding="UTF-8"?><root xmlns="urn:one" xmlns:p="urn:two" a="1" p:b="2"><p:c/></root>',
        "<!DOCTYPE html [<!ENTITY e 'v'> <!-- c --> <!ATTLIST a b 'c>d'>]><html><br><p>x</html>",
        "<a>\r\n<b>&amp;&lt;&#65;</b>\r</a>",
        "<a xmlns:xml='http://www.w3.org/XML/1998/namespace' xml:lang='en'><b xmlns=''/></a>",
        "<root><![CDATA[a<b]]>text</root>trailing",
        "<a><b></a>", "<a></b>", "<p:a></q:a>", "</a>", "<a", "<a b", "<a b=", "<a b='", "<!--", "<?x", "<![CDATA[x",
        "", " ", "text", "&", "<a>&", "<a b='&'/>", "<:a/>", "<a:/>", "<a:b:c/>", "<a b:c:d='1'/>",
        "<br>text<br/>more</br>", "<a>]]></a>", "<a b='<'/>", "<a\xff/>", "<\xffa/>", "<a>\xff</a>",
        "<a>\x00</a>", "<a/><b/>", "<?xml version='1.0' encoding='fail'?><a/>",
    ]
    for _ in range(count):
        r = rng.random()
        if r < 0.1:
            base = rng.choice(seeds).encode("latin-1", "replace") if rng.random() < 0.5 else rng.choice(seeds).encode()
        elif r < 0.25:
            base = html_document(rng).encode()
        else:
            clean = rng.random() < 0.55
            base = document(rng, clean).encode()
            if clean and rng.random() < 0.8:
                requests.append(f"T\t{rng.choice(['1', '1', '1', '0'])}{rng.choice('0001')}{rng.choice('0012')}{rng.choice('0001')}{rng.choice('00012')}\t{base.hex()}")
                continue
        if rng.random() < 0.6:
            base = mutate(rng, base)
        flags = "".join([
            rng.choice("11110"),  # strict, mostly on
            rng.choice("0001"),
            rng.choice("0012"),
            rng.choice("0001"),
            rng.choice("00012"),
        ])
        requests.append(f"T\t{flags}\t{base.hex()}")
    for seed in seeds:
        for flags in ("11000", "00110", "01210", "10101", "10002", "11001"):
            requests.append(f"T\t{flags}\t{seed.encode('latin-1', 'replace').hex()}")
    return requests


def escape_requests(rng, count):
    out = []
    pool = [c for c in '"\'&<>\t\n\r\x00\x01\x1f\x7f \ufffd\u2028\ud7ff\ue000\U0001f600abc日本'] + ["\xff", "\xc3", "\xe2\x82"]
    for _ in range(count):
        parts = []
        for _ in range(rng.randrange(0, 12)):
            c = rng.choice(pool)
            parts.append(c.encode("latin-1") if c in ("\xff", "\xc3", "\xe2\x82") else c.encode("utf-8", "surrogatepass"))
        out.append("E\t" + b"".join(parts).hex())
    out.append("E\t")
    return out


def tok(kind, *fields):
    return ":".join([kind] + [f.encode().hex() for f in fields])


def encode_requests(rng, count):
    out = []
    spaces = ["", "", "urn:a", "http://x.org/ns/p", "http://www.w3.org/XML/1998/namespace", "xml", "urn:b/", "/", "a:b"]
    locals_ = ["a", "b", "item", "x:y", "", "é", "1bad", "xml"]
    texts = ["t", "a&b", "<>", '"q"', "a\nb", "\t", "]]>", "--", "a-->b", "x?>y", ""]
    for _ in range(count):
        ops = []
        stack = []
        for _ in range(rng.randrange(1, 10)):
            r = rng.random()
            if r < 0.3 or not stack and r < 0.5:
                name = (rng.choice(spaces), rng.choice(locals_))
                attrs = []
                for _ in range(rng.choice([0, 0, 1, 2])):
                    attrs += [rng.choice(spaces), rng.choice(locals_), rng.choice(texts)]
                ops.append(":".join(["S", name[0].encode().hex(), name[1].encode().hex()]
                                    + [x.encode().hex() for x in attrs]))
                stack.append(name)
            elif r < 0.55 and stack:
                name = stack.pop() if rng.random() < 0.85 else (rng.choice(spaces), rng.choice(locals_))
                ops.append(tok("E", *name))
            elif r < 0.7:
                ops.append(tok("C", rng.choice(texts)))
            elif r < 0.78:
                ops.append(tok("M", rng.choice(texts)))
            elif r < 0.88:
                ops.append(tok("P", rng.choice(["xml", "pi", "", "1x", "a b"]), rng.choice(["version=\"1.0\"", "", "d", "?>"])))
            elif r < 0.96:
                ops.append(tok("D", rng.choice(["DOCTYPE x", "a>b", "<a>", "x<!-- > -->y", "'", "a<b", "<!-- x"])))
            else:
                ops.append("FLUSH")
        while stack and rng.random() < 0.8:
            ops.append(tok("E", *stack.pop()))
        prefix = rng.choice(["", "", ">", "# "])
        indent = rng.choice(["", "", "  ", "\t"])
        out.append(f"K\t{prefix.encode().hex()}\t{indent.encode().hex()}\t{' '.join(ops)}")
    # Buffer boundaries: the xml declaration is only legal while nothing is
    # buffered, which depends on where bufio flushed.
    for n in (1, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 12288):
        for body in ("a", "<", "é"):
            for kind in ("C", "M"):
                ops = [tok(kind, body * n), tok("P", "xml", "version=\"1.0\""), tok("P", "x", "d"), "FLUSH",
                       tok("P", "xml", "version=\"1.0\"")]
                out.append(f"K\t\t\t{' '.join(ops)}")
    return out


def run(command, payload, cwd=ROOT):
    result = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=cwd)
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed:\n{result.stderr[-4000:]}")
    return result.stdout.splitlines()


def describe(request):
    fields = request.split("\t")
    text = []
    for f in fields[1:]:
        try:
            text.append(bytes.fromhex(f).decode("utf-8", "replace") if all(c in "0123456789abcdef" for c in f) and len(f) % 2 == 0 and f else f)
        except ValueError:
            text.append(f)
    return fields[0] + " " + " | ".join(repr(t) for t in text)


def compare(name, requests, rust, go):
    if len(rust) != len(requests) or len(go) != len(requests):
        raise AssertionError(f"{name}: got {len(rust)} Rust and {len(go)} Go responses for {len(requests)} requests")
    bad = 0
    for i, (r, g) in enumerate(zip(rust, go)):
        if r != g:
            bad += 1
            if bad <= 5:
                print(f"{name} vector {i}: {describe(requests[i])}\n  request={requests[i][:300]}\n  Rust={r[:900]}\n  Go  ={g[:900]}")
    if bad:
        raise AssertionError(f"{name}: {bad} of {len(requests)} vectors differ from Go")


def main():
    rng = random.Random(0x584D4C)
    suites = {
        "tokens": (token_requests(rng, 8000), EXAMPLE),
        "escape": (escape_requests(rng, 1500), EXAMPLE),
        "encode-token": (encode_requests(rng, 3000), EXAMPLE),
    }
    only = set(sys.argv[1:])
    if not only or "typed" in only:
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            import xml_typed_vectors
        except ImportError:
            xml_typed_vectors = None
        if xml_typed_vectors:
            suites["typed"] = (xml_typed_vectors.requests(rng), TYPED)
    total = 0
    for name, (requests, command) in suites.items():
        if only and name not in only:
            continue
        payload = "".join(r + "\n" for r in requests)
        rust = run(command, payload)
        go = run(ORACLE, payload)
        compare(name, requests, rust, go)
        total += len(requests)
        print(f"xml {name}: {len(requests)} vectors match Go")
    print(f"XML Go differential: {total} vectors passed")


if __name__ == "__main__":
    main()
