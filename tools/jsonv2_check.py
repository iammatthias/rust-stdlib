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
         "BadTag7", "Fmt", "Empty", "NoFields", "Fall1", "Fall2", "Fall3", "Fall4", "FallBad", "Customs", "Times",
         "TimeFmts", "TimeBad", "Durs", "DurFmts", "DurBad"]
# Types with `format` tag options, which mostly need option t
# (ExperimentalSupportFormatTag).
FORMAT_TYPES = {"TimeFmts", "TimeBad", "Durs", "DurFmts", "DurBad"}
MARSHAL_OPTS = ["-", "-", "n", "o", "h", "j", "hj", "mx", "m", "x", "ck", "hjn", "on", "p", "q", "pq", "F", "Fn", "a", "v",
                "mcxk", "ohj"]
UNMARSHAL_OPTS = ["-", "-", "-", "i", "r", "ir", "n", "a", "v", "G", "Gi", "rn", "o"]


def with_format(rng, t, opts):
    """Adds option t to most requests for a type with `format` tags."""
    if t not in FORMAT_TYPES or rng.random() < 0.25:
        return opts
    return "t" if opts == "-" else opts + "t"


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
            reqs.append(f"marshal {t} {with_format(rng, t, rng.choice(MARSHAL_OPTS))} {a}".rstrip())
    return reqs


def unmarshal_requests(go, rng, per_type):
    gens = [f"gen {t} {seed} 0" for t in TYPES for seed in range(per_type)]
    out = atoms(go, gens)
    base_opts = ["t" if g.split()[1] in FORMAT_TYPES else "-" for g in gens]
    bases = run(go, "".join(f"marshal {g.split()[1]} {o} {a}".rstrip() + "\n" for g, o, a in zip(gens, base_opts, out)),
                "Go marshal")
    other = atoms(go, [f"gen {t} {1000 + seed} 0" for t in TYPES for seed in range(per_type)])
    reqs = []
    for g, line, prefill in zip(gens, bases, other):
        parts = line.split(" ")
        t = g.split()[1]
        if parts[0] != "ok" or len(parts) < 2:
            # Types that always fail to marshal: feed small documents.
            for doc in (b"{}", b'{"a":1,"x":2}', b'{"A":1}', b"[]", b"null", b'{"a":1,"a":2}'):
                reqs.append(f"unmarshal {t} {with_format(rng, t, rng.choice(UNMARSHAL_OPTS))} {hx(doc)}")
            continue
        text = bytes.fromhex(parts[1]) if parts[1] != "-" else b""
        reqs.append(f"unmarshal {t} - {hx(text)}")
        reqs.append(f"unmarshal {t} {with_format(rng, t, rng.choice(UNMARSHAL_OPTS))} {hx(text)} {prefill}".rstrip())
        try:
            root = json.loads(text.decode(), parse_int=json_check.Raw, parse_float=json_check.Raw)
        except ValueError:
            continue
        for _ in range(6):
            mutated = mutate_tree(rng, root)
            pre = f" {prefill}" if rng.random() < 0.4 else ""
            reqs.append(f"unmarshal {t} {with_format(rng, t, rng.choice(UNMARSHAL_OPTS))} {hx(mutated)}{pre}".rstrip())
        if rng.random() < 0.5:
            reqs.append(f"unmarshal {t} {with_format(rng, t, rng.choice(UNMARSHAL_OPTS))} {hx(json_gen.mutate(rng, text))}")
    return reqs


# Texts for the time fields: RFC 3339 edge cases, the other layouts, the
# unix and duration number tables of Go's arshal_time_test.go, and ISO 8601
# and Go durations.
TIME_TEXTS = [
    "2026-10-27T01:02:03.000000004Z", "2026-10-27T01:02:03Z", "2026-10-27T01:02:03+05:30", "2026-10-27T01:02:03-23:59",
    "2026-10-27T1:02:03Z", "2026-10-27T01:02:03,5Z", "2026-10-27T01:02:03+24:00", "2026-10-27T01:02:03+05:60",
    "2026-10-27t01:02:03z", "2026-10-27 01:02:03Z", "0000-01-01T00:00:00Z", "9999-12-31T23:59:59.999999999Z",
    "10000-01-01T00:00:00Z", "2026-02-30T00:00:00Z", "2026-10-27T01:02:03.Z", "2026-10-27T01:02:03.1234567891Z",
    "2026-10-27", "2026-10-27T01:02:03", "", "x", "Mon Jan  2 15:04:05 2006", "Mon Jan  2 15:04:05 MST 2006",
    "Mon Jan 02 15:04:05 -0700 2006", "02 Jan 06 15:04 MST", "02 Jan 06 15:04 -0700", "Monday, 02-Jan-06 15:04:05 MST",
    "Mon, 02 Jan 2006 15:04:05 MST", "Mon, 02 Jan 2006 15:04:05 -0700", "3:04PM", "13:04PM", "Jan  2 15:04:05.000000000",
    "2006-01-02 15:04:05", "15:04:05", "2006/01/02 15h04.000 -0700", "2006/01/02 15h04.5 -0700",
    "0", "0.", "0.0", "0.00", "00.0", "+0", "-0", "1e0", "1.5", "-1.5", "1234567890123456789012345678901234567890",
    "9223372036854775808000.000000", "9223372036854775807999999.9999", "9223372036854775807999999999.9",
    "9223372036854775807.999999999x", "9223372036854775807000000000", "-9223372036854775808",
    "-9223372036854775808000.000001", "-9223372036854775808000000.0001", "-9223372036854775808000000000.x",
    "-1234567890123456789012345678901234567890", "253402300799", "-62135596800", "1767225600123.456",
    "1h2m3s", "-1.5h", "1", "1.000000001", "0.000000001", "9223372036.854775807", "9223372036.854775808",
    "-9223372036.854775808", "-9223372036.854775809", "18446744073709551616", "1e3", "PT0S", "PT1H", "P1D", "PT1.5M",
    "-PT1S", "+PT1S", "pt1h2m3.5s", "PT", "P", "PT1,5S", "PT1.S", "P1Y2M3W4DT5H6M7.8S", "PT9223372036854775807S",
    "PT2562047H47M16.854775807S", "-PT2562047H47M16.854775808S", "PT2562047H47M16.854775808S", "PT00001H",
    "PT1.5H30M", "PT1.e5H", "PT1.5e3H", "P1.5D", "PT0.000000000001S", "PT1.0000000005S", "xPT1S", "PT1X",
    "300ms", "-1.5µs", "2562047h47m16.854775808s",
]

JSON_NUMBER = re.compile(r"-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?")

TIME_FIELDS = {
    "Times": "abcdef", "TimeFmts": ["u", "um", "uu", "un", "us", "r", "rn", "an", "ud", "rb", "r8", "rz", "r5", "r1",
                                    "ry", "k", "sn", "dt", "do", "to", "cu"],
    "TimeBad": "ab", "Durs": "dp", "DurFmts": ["u", "s", "ss", "m", "mi", "n", "i", "iz"], "DurBad": "ab",
}


def time_requests(go, rng):
    """Unmarshals of every field of the time types from TIME_TEXTS, as JSON
    strings and (where valid) numbers, into zero and pre-filled values."""
    prefills = {t: atoms(go, [f"gen {t} {seed} 0" for seed in range(8)]) for t in TIME_FIELDS}
    reqs = []
    for t, fields in TIME_FIELDS.items():
        for field in fields:
            for text in TIME_TEXTS:
                values = [json.dumps(text, ensure_ascii=False)]
                if JSON_NUMBER.fullmatch(text):
                    values.append(text)
                for v in values:
                    if field == "d":
                        v = f"[{v}]" if t == "Times" else v
                    elif field == "e" and t == "Times":
                        v = f'{{"k":{v}}}'
                    pre = f" {rng.choice(prefills[t])}" if rng.random() < 0.3 else ""
                    doc = f'{{"{field}":{v}}}'.encode()
                    reqs.append(f"unmarshal {t} {with_format(rng, t, rng.choice(UNMARSHAL_OPTS))} {hx(doc)}{pre}".rstrip())
            for v in ("null", "true", "{}", "[]"):
                doc = f'{{"{field}":{v}}}'.encode()
                reqs.append(f"unmarshal {t} {with_format(rng, t, rng.choice(UNMARSHAL_OPTS))} {hx(doc)}")
    return reqs


def main():
    rng = random.Random(0x4A534F4E32)
    total = 0
    with tempfile.TemporaryDirectory() as tmp:
        go = build_go(tmp)
        rust = build_rust()
        total += compare("marshal", marshal_requests(go, rng, 70), rust, go)
        total += compare("unmarshal", unmarshal_requests(go, rng, 45), rust, go)
        total += compare("time", time_requests(go, rng), rust, go)
    print(f"jsonv2 Go differential: {total} vectors passed")


if __name__ == "__main__":
    main()
