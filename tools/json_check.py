#!/usr/bin/env python3
"""Differentially check encoding/json against Go: Valid, Compact, Indent,
HTMLEscape, Unmarshal into a dynamic value, Decoder token and value streams,
and Marshal of generated values with struct tag options."""
import collections
import json
import pathlib
import random
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import json_gen  # noqa: E402

RUST = ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "json_probe"]
RUST_TYPED = ["cargo", "run", "--quiet", "--offline", "--locked", "--manifest-path",
              "tools/derive-check/Cargo.toml", "--example", "json_typed_probe"]
GO = ["go", "run", "tools/json_oracle.go"]


def hx(b):
    return b.hex() or "-"


def run(cmd, payload, what):
    result = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if result.returncode:
        raise RuntimeError(f"{what} failed:\n{result.stderr}")
    return result.stdout.splitlines()


def run_both(requests, rust=RUST):
    payload = "".join(r + "\n" for r in requests)
    a, b = run(rust, payload, "Rust json probe"), run(GO, payload, "Go json oracle")
    if len(a) != len(requests) or len(b) != len(requests):
        raise AssertionError(f"wrong record count: rust={len(a)} go={len(b)} want={len(requests)}")
    return a, b


def show(line):
    parts = line.split(" ")
    if len(parts) > 1 and parts[0] in ("ok", "err") and parts[1] != "-":
        try:
            return parts[0] + " " + bytes.fromhex(parts[1]).decode("utf-8", "replace") + " " + " ".join(parts[2:])
        except ValueError:
            pass
    return line


def compare(label, requests, rust=RUST, verbose=8):
    got, want = run_both(requests, rust)
    bad = [i for i, (x, y) in enumerate(zip(got, want)) if x != y]
    if bad:
        seen = collections.Counter()
        shown = 0
        for i in bad:
            key = (requests[i].split()[0], re.sub(r"[0-9]+", "N", show(got[i]))[:60], re.sub(r"[0-9]+", "N", show(want[i]))[:60])
            seen[key] += 1
            if seen[key] == 1 and shown < verbose:
                shown += 1
                print(f"MISMATCH [{label}] request: {requests[i][:300]}\n  Rust: {show(got[i])[:400]!r}\n  Go:   {show(want[i])[:400]!r}", file=sys.stderr)
        raise AssertionError(f"{label}: {len(bad)} of {len(requests)} vectors differ ({len(seen)} kinds)")
    return len(requests)


TYPES = ["Basic", "Opts", "Containers", "Embed1", "Embed2", "Embed3", "Embed4", "Embed5",
         "Embed6", "Embed7", "Embed8", "Floats", "Strings", "Customs"]


def marshal_requests(per_type):
    gens = [f"gen {t} {seed} {special}" for t in TYPES for seed in range(per_type) for special in (0, 1)
            if special == 0 or seed % 4 == 0]
    atoms = run(GO, "".join(g + "\n" for g in gens), "Go value generator")
    requests = []
    for g, a in zip(gens, atoms):
        t = g.split()[1]
        for mode in ("h", "n", "i", "oe", "os", "oes", "oby"):
            requests.append(f"marshal {t} {mode} {a}")
    return requests


class Raw:
    """A number kept as its source text."""

    def __init__(self, text):
        self.text = text


def dump(node):
    if isinstance(node, Raw):
        return node.text
    if isinstance(node, list):
        return "[" + ",".join(dump(x) for x in node) + "]"
    if isinstance(node, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + dump(v) for k, v in node.items()) + "}"
    return json.dumps(node, ensure_ascii=False)


REPLACEMENTS = [None, True, False, Raw("0"), Raw("-1"), Raw("1.5"), Raw("1e400"), Raw("300"), Raw("1e2"), Raw("70000"),
                Raw("-129"), Raw("123456789012345678901234567890"), "x", "123", "true", "null", "", [], {}, [Raw("1")],
                {"a": Raw("1")}, [[]], "1.5", "\u00e9", "1e999", " 12", Raw("-0")]


def paths(node, prefix=()):
    yield prefix
    if isinstance(node, list):
        for i, x in enumerate(node):
            yield from paths(x, prefix + (i,))
    elif isinstance(node, dict):
        for k, x in node.items():
            yield from paths(x, prefix + (k,))


def get(node, path):
    for p in path:
        node = node[p]
    return node


def mutate_tree(rng, root):
    root = json.loads(dump(root), parse_int=Raw, parse_float=Raw)
    for _ in range(rng.randrange(1, 3)):
        ps = list(paths(root))
        path = rng.choice(ps)
        kind = rng.randrange(6)
        if kind == 0 and path:  # replace
            parent = get(root, path[:-1])
            parent[path[-1]] = rng.choice(REPLACEMENTS)
        elif kind == 1 and path and isinstance(get(root, path[:-1]), dict):  # delete
            del get(root, path[:-1])[path[-1]]
        elif kind == 2 and path and isinstance(get(root, path[:-1]), dict):  # recase key
            parent = get(root, path[:-1])
            key = path[-1]
            new = rng.choice([key.upper(), key.lower(), key.swapcase(), key.title()])
            if new not in parent:
                items = list(parent.items())
                parent.clear()
                for k, v in items:
                    parent[new if k == key else k] = v
        elif kind == 3 and isinstance(get(root, path), dict):  # unknown member
            get(root, path)[rng.choice(["zzz", "extra", "A", "id2"])] = rng.choice(REPLACEMENTS)
        elif kind == 4 and path:  # numbers <-> strings
            parent = get(root, path[:-1])
            v = parent[path[-1]]
            if isinstance(v, Raw):
                parent[path[-1]] = v.text
            elif isinstance(v, str):
                parent[path[-1]] = Raw(v) if v else v
        elif kind == 5 and isinstance(get(root, path), list):  # change length
            lst = get(root, path)
            if lst and rng.random() < 0.5:
                lst.pop()
            else:
                lst.append(rng.choice(REPLACEMENTS))
    return dump(root).encode()


def unmarshal_requests(per_type):
    rng = random.Random(0x554E4D)
    gens = [f"gen {t} {seed} 0" for t in TYPES for seed in range(per_type)]
    atoms = run(GO, "".join(g + "\n" for g in gens), "Go value generator")
    bases = run(GO, "".join(f"marshal {g.split()[1]} n {a}\n" for g, a in zip(gens, atoms)), "Go marshal")
    reqs = []
    for g, line in zip(gens, bases):
        parts = line.split(" ")
        if parts[0] != "ok" or len(parts) < 2:
            continue
        t = g.split()[1]
        text = bytes.fromhex(parts[1]) if parts[1] != "-" else b""
        reqs.append(f"unmarshaltyped {t} h {hx(text)}")
        reqs.append(f"unmarshaltyped {t} osad {hx(text)}")
        try:
            root = json.loads(text.decode(), parse_int=Raw, parse_float=Raw)
        except ValueError:
            continue
        for _ in range(4):
            reqs.append(f"unmarshaltyped {t} h {hx(mutate_tree(rng, root))}")
            reqs.append(f"unmarshaltyped {t} {rng.choice(['os', 'oa', 'od', 'osad'])} {hx(mutate_tree(rng, root))}")
        if rng.random() < 0.3:
            reqs.append(f"unmarshaltyped {t} h {hx(json_gen.mutate(rng, text))}")
    # ParseBytesWithLooseRFC4648(false) and FormatBytesWithLegacySemantics(false)
    # change how base64 text and arrays decode into a byte slice.
    for body in ['"aGk="', '"aGk=\\n"', '"aGk=\\r"', '"a\\nGk="', '"aG\\r\\nk="', '[1,2,3]', '[]', 'null', '"aGk"',
                 '""', '"aGl="', '"a"', '1', '{}', '[256]', '["a"]', '"\\n"']:
        doc = ('{"Bytes":' + body + '}').encode()
        for mode in ("h", "ob", "oy", "oby", "obysad"):
            reqs.append(f"unmarshaltyped Containers {mode} {hx(doc)}")
    return reqs


def stream_requests():
    rng = random.Random(0x57524541)
    docs = json_gen.documents(0x544F4B, 700)
    for _ in range(500):
        n = rng.randrange(1, 4)
        docs.append(b" ".join(json_gen.gen_doc(rng) for _ in range(n)) + rng.choice([b"", b"\n", b" ,", b"]", b" "]))
    reqs = []
    for d in docs:
        h = hx(d)
        for chunk in (0, 1, 5):
            reqs += [f"tokens {chunk} 0 {h}", f"decodes {chunk} 0 {h}"]
        reqs += [f"tokens 0 1 {h}", f"decodes 0 1 {h}"]
    return reqs


def main():
    total = 0
    docs = json_gen.documents(0x4A534F4E, 2500)
    reqs = []
    for d in docs:
        h = hx(d)
        reqs += [f"valid {h}", f"compact {h}", f"indent - 2020 {h}", f"indent 7072 09 {h}", f"html {h}", f"unmarshal {h}"]
    for d in json_gen.deep_documents():
        reqs += [f"valid {hx(d)}", f"compact {hx(d)}"]
    total += compare("scanner", reqs)
    total += compare("stream", stream_requests())
    total += compare("unmarshal", unmarshal_requests(60), RUST_TYPED)
    total += compare("marshal", marshal_requests(120), RUST_TYPED)
    print(f"JSON Go differential: {total} vectors passed")


if __name__ == "__main__":
    main()
