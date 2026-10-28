#!/usr/bin/env python3
"""Differentially check net/url (Parse, ParseRequestURI, String, ResolveReference,
JoinPath, escaping, ParseQuery, Hostname/Port) against Go on generated and
mutated inputs. Compares every URL field, every derived string and error text.

Inputs whose percent-decoded components are not valid UTF-8 are answered SKIP
by the oracle: Go strings are bytes, the Rust port stores U+FFFD instead.
"""
import json
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]

SCHEMES = ["http", "https", "HTTP", "ftp", "mailto", "file", "x-y.z+w", "a", "", "1a", "a b", "javascript"]
USERS = ["", "u@", "u:p@", "us%20er:p%40ss@", ":@", "u:@", "a@b@", "u^@", "%zz@", "u:p:q@", "é@"]
HOSTS = ["example.com", "EXAMPLE.com", "a.b", "localhost", "1.2.3.4", "[::1]", "[2001:db8::1]",
         "[fe80::1%25en0]", "[fe80::1%en0]", "[::ffff:1.2.3.4]", "[1.2.3.4]", "[::1", "::1]",
         "[]", "[x]", "a b", "a%41", "a%2e", "%", "héllo", "a_b", "h:1:2", "", "[::1]x", "x[::1]",
         "[1:2:3:4:5:6:7:8]", "[1:2:3:4:5:6:7:8:9]", "[::1::2]", "[:1]", "[1:]", "[0:0:0:0:0:0:0:01234]",
         "[::01.2.3.4]", "[fe80::1%25]", "[fe80::1%2541]", "[fe80::1%25%zz]", "[::%41]"]
PORTS = ["", ":", ":80", ":0", ":65536", ":abc", ":8a", ":%38", ":00080", "::"]
PATHS = ["", "/", "/a", "/a/b/c", "/a%2Fb", "/a b", "/a%20b", "/%zz", "/./a", "/../a", "/a/../b", "/a/./b/..",
         "//a", "///a", "a", "a/b", "../a", "./a", "a:b", "./a:b", "/a:b", "*", "/é", "/%C3%A9", "/a;b,c",
         "/a?b", "/%3F", "/%2f%2F", "/a/", "/a//b", "/~u", "/a+b", "/a%2", "/a%", "/!$&'()*+,;=:@", "/[x]",
         "/a%25b", "/ ", "/\U0001f600", "/%00", "/%41"]
QUERIES = ["", "?", "?a=b", "?a=b&c=d", "?a", "?=b", "?a=b&a=c", "?a=%zz", "?a;b=c", "?a=1;b=2", "?q=x+y",
           "?x=%41&y=%e9", "?&&", "?a=b?c", "?%", "?é=1", "?a=b#"]
FRAGS = ["", "#", "#f", "#a b", "#%41", "#%zz", "#a%20b", "#é", "#f#g", "#!$&'()*+,;=:@/?", "#%2F", "#%"]
FRAGMENTS = ["://", "//", "/", "?", "#", "@", ":", "[", "]", "%", "%2F", "%25", "%zz", "%41", "%3a", "%00",
             " ", "\t", "\x7f", "\x00", ".", "..", "/../", "/./", "é", "\U0001f600", "::1", "[::1]",
             "%25en0", "1.2.3.4", ":80", ":65536", "a", "0", "-", "_", "~", "+", ";", "=", "&", "!", "'", "(", ")",
             "*", ",", "\\", "\"", "<", ">", "^", "`", "{", "}", "|", "http:", "https://h", "mailto:", "%e9", "%c3%a9"]


def structured(rng):
    scheme = rng.choice(SCHEMES)
    out = scheme + ":" if scheme else ""
    if rng.random() < 0.8:
        out += "//" + rng.choice(USERS) + rng.choice(HOSTS) + rng.choice(PORTS)
    out += rng.choice(PATHS) + rng.choice(QUERIES) + rng.choice(FRAGS)
    return out


def mutate(rng, text):
    for _ in range(rng.randint(1, 3)):
        kind = rng.randrange(5)
        pos = rng.randrange(len(text) + 1)
        if kind == 0:
            text = text[:pos] + rng.choice(FRAGMENTS) + text[pos:]
        elif kind == 1 and text:
            end = min(len(text), pos + rng.randint(1, 4))
            text = text[:pos] + text[end:]
        elif kind == 2 and text:
            end = min(len(text), pos + rng.randint(1, 6))
            text = text[:pos] + text[pos:end] + text[pos:]
        elif kind == 3 and text:
            end = min(len(text), pos + 1)
            text = text[:pos] + rng.choice(FRAGMENTS) + text[end:]
        else:
            text = text.replace(rng.choice("/:?#@[]%."), rng.choice(FRAGMENTS), 1)
    return text


def enc(text):
    return "_" if text == "" else text.encode("utf-8", "surrogatepass").hex()


def main():
    rng = random.Random(0x75726C)
    tables = json.loads((ROOT / "tests/fixtures/url_go_tables.json").read_text())
    seeds = [r["in"] for r in tables["parse"]] + [r["url"] for r in tables["parse_request_uri"]]
    seeds += [r["base"] for r in tables["resolve_reference"]] + [r["rel"] for r in tables["resolve_reference"]]
    seeds = [s for s in seeds if s]
    pool = list(seeds)

    def url_input():
        roll = rng.random()
        if roll < 0.35:
            return mutate(rng, rng.choice(seeds))
        if roll < 0.65:
            return structured(rng)
        if roll < 0.85:
            return mutate(rng, structured(rng))
        return rng.choice(seeds)

    records = []
    for s in seeds:
        records.append(("P", [s]))
        records.append(("R", [s]))
    # Raw (non-UTF-8) bytes in the host and user info must survive String().
    for s in ["http://u%e9:p%ff@h%e9.com/x", "http://%c3@h/", "//%ff%fe/p", "http://[::1%25a%ff]:80/",
              "http://h%e9:80/?q=1", "x://u%e9@/p", "http://a%ffb%e9c@h%80%81/"]:
        records.append(("P", [s]))
        records.append(("X", ["http://base/dir/", s]))
    for _ in range(3500):
        records.append(("P", [url_input()]))
    for _ in range(1500):
        records.append(("R", [url_input()]))
    for r in tables["resolve_reference"]:
        records.append(("X", [r["base"], r["rel"]]))
    for _ in range(2600):
        base = url_input() if rng.random() < 0.5 else structured(rng)
        ref = rng.choice([url_input(), structured(rng), rng.choice(PATHS) + rng.choice(QUERIES) + rng.choice(FRAGS),
                          rng.choice(["", "?", "#", "?q", "#f", "//h/p", "../x", "./y", "/z", ".", "..", "g;x=1/../y"])])
        records.append(("X", [base, ref]))
    for _ in range(900):
        base = url_input() if rng.random() < 0.5 else structured(rng)
        elems = [rng.choice(PATHS + ["..", ".", "", "x", "y/", "%2f", "100%", "a b", "é"]) for _ in range(rng.randint(0, 4))]
        records.append(("J", [base] + elems))
    texts = [url_input() for _ in range(300)] + [rng.choice(PATHS + QUERIES + FRAGS + HOSTS) for _ in range(300)]
    texts += ["".join(rng.choice(FRAGMENTS + ["a", "b", "%", "+", " "]) for _ in range(rng.randint(0, 8))) for _ in range(1200)]
    for t in texts:
        records.append(("QE", [t]))
        records.append(("QU", [t]))
        records.append(("PU", [t]))
    for _ in range(1600):
        pairs = rng.randint(0, 5)
        keyvals = []
        for _ in range(pairs):
            k = rng.choice(["a", "b", "a b", "é", "%41", "%zz", "", "k;", "x+y", "%2B", "z"])
            v = rng.choice(["", "1", "x y", "%20", "%zz", "é", "+", "%2b", "a=b", "=", "v;", "%", "%e9"])
            keyvals.append(k + ("=" + v if rng.random() < 0.85 else ""))
        q = "&".join(keyvals)
        if rng.random() < 0.3:
            q = mutate(rng, q)
        records.append(("Q", [q]))
    for _ in range(300):
        host = rng.choice(HOSTS) + rng.choice(PORTS)
        records.append(("H", [host if rng.random() < 0.8 else mutate(rng, host)]))
    big = "&".join(f"p{i}" for i in range(10001))
    records.append(("Q", [big]))
    records.append(("Q", [big[: big.rindex("&")]]))

    payload = "".join(op + " " + " ".join(enc(a) for a in args) + "\n" for op, args in records)

    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "url_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust url probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/url_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_run.returncode:
        raise RuntimeError(f"Go url oracle failed:\n{go_run.stderr}")
    rust, go = rust_run.stdout.splitlines(), go_run.stdout.splitlines()
    if len(rust) != len(records) or len(go) != len(records):
        raise AssertionError(f"url oracle record count: rust={len(rust)} go={len(go)} want={len(records)}")
    compared = skipped = errors = 0
    for i, (actual, expected) in enumerate(zip(rust, go)):
        if expected == "SKIP":
            skipped += 1
            continue
        if actual != expected:
            op, args = records[i]
            raise AssertionError(f"vector {i}: {op} {args!r}\nRust={actual!r}\nGo  ={expected!r}")
        compared += 1
        errors += expected.startswith("E")
    print(f"URL Go differential: {len(records)} vectors, {compared} compared "
          f"({errors} Go errors matched), {skipped} skipped for non-UTF-8 decodings")


if __name__ == "__main__":
    main()
