#!/usr/bin/env python3
"""Differentially check encoding/json/v2 against Go: Marshal and Unmarshal of
generated and mutated typed values under every option, including error text,
byte offsets, JSON Pointers and the state left behind by a failed
Unmarshal."""
import collections
import copy
import json
import pathlib
import random
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import json_check  # noqa: E402
import json_gen  # noqa: E402

RUST = ["cargo", "run", "--quiet", "--offline", "--locked", "--manifest-path", "tools/derive-check/Cargo.toml",
        "--example", "jsonv2_probe"]
GO = ["go", "run", "tools/jsonv2_oracle.go"]

TYPES = ["Inner", "Scalars", "Tags", "Omit", "Containers", "BoolKeys", "Floats", "StrTags", "StrErr", "BoolErr",
         "MapErr", "Names", "Embed1", "Embed2", "Embed3", "Embed4", "Embed5", "Embed6", "Embed7", "Embed8",
         "Embed9", "Embed10", "Conflict", "BadTag1", "BadTag2", "BadTag3", "BadTag4", "BadTag5", "BadTag6",
         "BadTag7", "Fmt", "Empty", "NoFields", "Fall1", "Fall2", "Fall3", "Fall4", "FallBad", "Customs"]
MARSHAL_OPTS = ["-", "-", "n", "o", "h", "j", "hj", "mx", "m", "x", "ck", "hjn", "on", "p", "q", "pq", "F", "Fn", "a", "v",
                "mcxk", "ohj"]
UNMARSHAL_OPTS = ["-", "-", "-", "i", "r", "ir", "n", "a", "v", "G", "Gi", "rn", "o"]


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

    return re.sub(r"(?<=err )[0-9a-f]{4,}|(?<=ok )[0-9a-f]{4,}|(?<=\| )[0-9a-f]{4,}", fix, line)[:500]


def compare(label, requests, rust, go, verbose=8):
    payload = "".join(r + "\n" for r in requests)
    got, want = run(rust, payload, "Rust jsonv2 probe"), run(go, payload, "Go jsonv2 oracle")
    if len(got) != len(requests) or len(want) != len(requests):
        raise AssertionError(f"wrong record count: rust={len(got)} go={len(want)} want={len(requests)}")
    bad = [i for i, (x, y) in enumerate(zip(got, want)) if x != y]
    if bad:
        seen = collections.Counter()
        shown = 0
        for i in bad:
            key = (requests[i].split()[1], re.sub(r"[0-9]+", "N", show(got[i]))[:50], re.sub(r"[0-9]+", "N", show(want[i]))[:50])
            seen[key] += 1
            if seen[key] == 1 and shown < verbose:
                shown += 1
                print(f"MISMATCH [{label}] request: {requests[i][:400]}\n  Rust: {show(got[i])}\n  Go:   {show(want[i])}",
                      file=sys.stderr)
        raise AssertionError(f"{label}: {len(bad)} of {len(requests)} vectors differ ({len(seen)} kinds)")
    return len(requests)


def build_go(tmp):
    exe = pathlib.Path(tmp) / "jsonv2_oracle"
    subprocess.run(["go", "build", "-o", str(exe), "tools/jsonv2_oracle.go"], cwd=ROOT, check=True)
    return [str(exe)]


def build_rust():
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--manifest-path", "tools/derive-check/Cargo.toml",
                    "--example", "jsonv2_probe"], cwd=ROOT, check=True, stderr=subprocess.DEVNULL)
    return [str(ROOT / "tools/derive-check/target/debug/examples/jsonv2_probe")]


def mutate_tree(rng, root):
    """json_check.mutate_tree, copying the replacement values so that a
    mutation cannot make a tree contain itself."""
    saved = json_check.REPLACEMENTS
    json_check.REPLACEMENTS = _CopyingChoices(saved)
    try:
        return json_check.mutate_tree(rng, root)
    finally:
        json_check.REPLACEMENTS = saved


class _CopyingChoices(list):
    """A list whose elements are deep-copied when chosen at random."""

    def __init__(self, items):
        super().__init__(items)

    def __getitem__(self, i):
        return copy.deepcopy(super().__getitem__(i))


def atoms(go, gens):
    return run(go, "".join(g + "\n" for g in gens), "Go value generator")


def marshal_requests(go, rng, per_type):
    gens = [f"gen {t} {seed} {special}" for t in TYPES for seed in range(per_type) for special in (0, 1)
            if special == 0 or seed % 3 == 0]
    out = atoms(go, gens)
    reqs = []
    for g, a in zip(gens, out):
        t = g.split()[1]
        for _ in range(3):
            reqs.append(f"marshal {t} {rng.choice(MARSHAL_OPTS)} {a}".rstrip())
    return reqs


def unmarshal_requests(go, rng, per_type):
    gens = [f"gen {t} {seed} 0" for t in TYPES for seed in range(per_type)]
    out = atoms(go, gens)
    bases = run(go, "".join(f"marshal {g.split()[1]} - {a}\n".rstrip() + "\n" for g, a in zip(gens, out)), "Go marshal")
    other = atoms(go, [f"gen {t} {1000 + seed} 0" for t in TYPES for seed in range(per_type)])
    reqs = []
    for g, line, prefill in zip(gens, bases, other):
        parts = line.split(" ")
        t = g.split()[1]
        if parts[0] != "ok" or len(parts) < 2:
            # Types that always fail to marshal: feed small documents.
            for doc in (b"{}", b'{"a":1,"x":2}', b'{"A":1}', b"[]", b"null", b'{"a":1,"a":2}'):
                reqs.append(f"unmarshal {t} {rng.choice(UNMARSHAL_OPTS)} {hx(doc)}")
            continue
        text = bytes.fromhex(parts[1]) if parts[1] != "-" else b""
        reqs.append(f"unmarshal {t} - {hx(text)}")
        reqs.append(f"unmarshal {t} {rng.choice(UNMARSHAL_OPTS)} {hx(text)} {prefill}".rstrip())
        try:
            root = json.loads(text.decode(), parse_int=json_check.Raw, parse_float=json_check.Raw)
        except ValueError:
            continue
        for _ in range(6):
            mutated = mutate_tree(rng, root)
            pre = f" {prefill}" if rng.random() < 0.4 else ""
            reqs.append(f"unmarshal {t} {rng.choice(UNMARSHAL_OPTS)} {hx(mutated)}{pre}".rstrip())
        if rng.random() < 0.5:
            reqs.append(f"unmarshal {t} {rng.choice(UNMARSHAL_OPTS)} {hx(json_gen.mutate(rng, text))}")
    return reqs


def main():
    rng = random.Random(0x4A534F4E32)
    total = 0
    with tempfile.TemporaryDirectory() as tmp:
        go = build_go(tmp)
        rust = build_rust()
        total += compare("marshal", marshal_requests(go, rng, 70), rust, go)
        total += compare("unmarshal", unmarshal_requests(go, rng, 45), rust, go)
    print(f"jsonv2 Go differential: {total} vectors passed")


if __name__ == "__main__":
    main()
