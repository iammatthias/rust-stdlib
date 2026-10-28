#!/usr/bin/env python3
"""Differentially check regexp and regexp/syntax against Go.

Generates thousands of patterns (random syntax trees over a small alphabet,
Go's own parse_test.go tables, and mutated patterns that mostly fail to parse)
and inputs, sends them to tools/regexp/oracle.go and examples/regexp_probe.rs
and compares the lines exactly. Covered: Parse/String/Simplify/Compile/Prog
dumps and error messages, every Find variant (string, bytes, reader) with the
All forms, submatches, Replace* with $ templates, Expand, Split, literal
prefix, subexpression names, in Perl, POSIX and Longest modes; and the search
from every offset (A vectors: Go's unexported find, reached by linkname) for
find_index_at, find_submatch_index_at and their anchored forms.

The Rust probe also reruns every M and A vector with each matcher forced
(one-pass, backtracker, Pike VM) and fails if any disagrees with Go's choice,
so the Pike VM stays covered although Go picks the backtracker for the short
inputs here. LONG_INPUTS cross the backtracker's input-length limit.
"""
import os
import pathlib
import random
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SEED = 0x5E6E4
SYNTAX_CASES = 2400
MATCH_PATTERNS = 1400
INPUTS_PER_PATTERN = 3

ALPHABET = ["a", "b", "c", "A", "B", "é", "日", "\n", " ", "_", "1", "-"]
LITERALS = ["a", "b", "c", "A", "é", "日", "_", "1", " ", "\\n", "\\t", "\\x41", "\\x{3b1}", "\\101", "\\.", "\\*", "\\(", "\\-", "\\/", "\\_", "ab", "abc", "ſ", "k", "K"]
CLASSES = ["[abc]", "[^abc]", "[a-c]", "[^a-c\\n]", "[a-cA-C]", "[é日]", "[[:alpha:]]", "[[:^digit:]]", "[[:word:]-]", "[\\d\\s]", "[\\D]", "[^\\W]", "[\\pL]", "[^\\p{Greek}a]", "[-a]", "[a-]", "[]a]", "[^]a]", "[\\]]", "[\\x{3b1}-\\x{3c9}]", "[a-zA-Z0-9_]", "[\\p{Lu}\\p{Nd}]", "[\\Q-\\E]", "[k]", "[Aa]", "[δΔ]"]
PERL_CLASSES = ["\\d", "\\D", "\\w", "\\W", "\\s", "\\S", "\\pL", "\\PL", "\\p{Greek}", "\\p{^Lu}", "\\P{^Han}", "\\p{Latin}", "\\pN", "\\p{Any}", "\\p{Assigned}", "\\p{Ascii}", "\\p{Letter}", "\\p{Old_Italic}", "\\p{LC}", "\\p{Zs}"]
ANCHORS = ["^", "$", "\\A", "\\z", "\\b", "\\B", "(?m:^)", "(?m:$)", "(?s:.)", "(?i:k)", "(?-s:.)"]
NAMES = ["name", "x", "n1", "a_b1"]
QUANT = ["*", "+", "?", "*?", "+?", "??", "{2}", "{0}", "{1}", "{2,}", "{0,}", "{1,3}", "{2,4}?", "{0,1}", "{3}"]
FLAGS_GROUPS = ["(?i)", "(?s)", "(?m)", "(?U)", "(?i-s)", "(?-i)", "(?is-m)"]


def atom(rng, depth):
    r = rng.random()
    if r < 0.35:
        return rng.choice(LITERALS)
    if r < 0.43:
        return "."
    if r < 0.55:
        return rng.choice(CLASSES)
    if r < 0.63:
        return rng.choice(PERL_CLASSES)
    if r < 0.70:
        return rng.choice(ANCHORS)
    if r < 0.72:
        return rng.choice(FLAGS_GROUPS)
    if r < 0.73:
        return "\\Q" + rng.choice(["a.b", "(", "*+", "x\\", ""]) + rng.choice(["\\E", ""])
    if depth <= 0:
        return rng.choice(LITERALS)
    inner = expr(rng, depth - 1)
    kind = rng.random()
    if kind < 0.45:
        return "(" + inner + ")"
    if kind < 0.65:
        return "(?:" + inner + ")"
    if kind < 0.80:
        return "(?P<" + rng.choice(NAMES) + ">" + inner + ")"
    if kind < 0.85:
        return "(?<" + rng.choice(NAMES) + ">" + inner + ")"
    return "(?" + rng.choice(["i", "s", "m", "U", "i-s", "-i"]) + ":" + inner + ")"


def piece(rng, depth):
    a = atom(rng, depth)
    if rng.random() < 0.4:
        a += rng.choice(QUANT)
    return a


def branch(rng, depth):
    return "".join(piece(rng, depth) for _ in range(rng.choice([0, 1, 1, 2, 2, 3, 4])))


def expr(rng, depth):
    return "|".join(branch(rng, depth) for _ in range(rng.choice([1, 1, 1, 2, 3])))


MUTATION_CHARS = list("()[]{}|*+?\\^$.-:<>P,") + ["é", "\xff", "\n", "0", "9", "x", "p", "E", "Q"]


def mutate(rng, p):
    for _ in range(rng.choice([1, 1, 2])):
        i = rng.randrange(len(p) + 1)
        c = rng.random()
        if c < 0.4 and p:
            p = p[:i - 1 if i else 0] + p[i:]
        elif c < 0.8:
            p = p[:i] + rng.choice(MUTATION_CHARS) + p[i:]
        elif p:
            j = rng.randrange(len(p))
            p = p[:j] + rng.choice(MUTATION_CHARS) + p[j + 1:]
    return p


def go_tables():
    """Pattern strings from Go's parse_test.go and find_test.go, if GOROOT is present."""
    try:
        root = subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return []
    found = []
    for rel in ("regexp/syntax/parse_test.go", "regexp/syntax/simplify_test.go", "regexp/find_test.go", "regexp/all_test.go"):
        path = pathlib.Path(root) / "src" / rel
        if not path.exists():
            continue
        text = path.read_text()
        for m in re.finditer(r'`([^`\n]*)`|"((?:[^"\\\n]|\\.)*)"', text):
            if m.group(1) is not None:
                found.append(m.group(1))
            else:
                try:
                    found.append(bytes(m.group(2), "utf8").decode("unicode_escape").encode("latin-1").decode("utf8"))
                except (UnicodeError, ValueError):
                    pass
    return sorted({s for s in found if 0 < len(s) < 80})


def raw(s):
    return s if isinstance(s, bytes) else s.encode("utf8", "surrogatepass")


def hexs(s):
    return raw(s).hex()


def random_input(rng):
    n = rng.choice([0, 1, 2, 3, 4, 5, 6, 8, 12])
    s = "".join(rng.choice(ALPHABET) for _ in range(n)).encode("utf8")
    if rng.random() < 0.08:
        i = rng.randrange(len(s) + 1)
        s = s[:i] + rng.choice([b"\xff", b"\xc3", b"\xe6\x97", b"\xed\xa0\x80"]) + s[i:]
    return s


CURATED_INPUTS = [b"", b"a", b"abc", b"aaa", b"ab\nab", b"abab", b"\xff", b"a\xffb", b"xAx\xe6\x97"]

# Patterns of about 10 to 600 instructions (the backtracker takes inputs shorter
# than 262144 / instructions, none above 500) with inputs of 300 to 3000
# bytes, so Go's choice lands on each side of the limit.
LONG_PATTERNS = ["[a-c]{40}", "(?:ab|a|b)*c", "(a|b)*?[0-9]{20}", "\\b\\w{3}\\b", "(?i)[a-z]{30}x|y",
                 "(?m)^ab+$", "[^\\n]{60}", "(\\pL+)\\s(\\pL+)", "(?s)a.{200}b|c{150}", "((((a{2}){2}){2}){2})", "[a-c]{250}", "(?:ab|[a-c]){120}x?"]
LONG_SIZES = [300, 1500, 3000]
# One-pass programs whose literal prefix sits after the start anchor: the
# forced Pike VM and backtracker must not skip ahead to that literal.
ONE_PASS_PREFIX_CASES = [("^ab", "xxab"), ("\\Aab", "xxab"), ("^abc(d|e)", "zzabcd"), ("^a", "b\naxb"),
                         ("^ab", "abxxab"), ("(?m)^ab", "xx\nab"), ("^ab$", "ab")]


def build_requests():
    rng = random.Random(SEED)
    tables = go_tables()
    reqs = []
    perl_flags = 212
    flag_bits = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512]
    for _ in range(SYNTAX_CASES):
        r = rng.random()
        if r < 0.15 and tables:
            p = rng.choice(tables)
        elif r < 0.30:
            p = mutate(rng, expr(rng, 3))
        elif r < 0.35 and tables:
            p = mutate(rng, rng.choice(tables))
        else:
            p = expr(rng, 3)
        c = rng.random()
        if c < 0.55:
            flags = perl_flags
        elif c < 0.7:
            flags = 0
        else:
            flags = sum(b for b in flag_bits if rng.random() < 0.4)
        reqs.append(f"S\t{flags}\t{hexs(p)}")
    # Every table pattern in every common mode, and Go's size/depth limits.
    for p in tables:
        for flags in (perl_flags, 0):
            reqs.append(f"S\t{flags}\t{hexs(p)}")
    limits = ["a{1000}", "a{1001}", "(a{1000}){1000}", "((((a{100}){100}){100}){100})", "(a{2}){500}",
              "((a{10}){10}){10}", "((a{10}){10}){11}", "(((a{10}){10}){10}){2}", "a{1000}{1}", "(((a{2}){2}){2}){2}",
              "(" * 1000 + "a" + ")" * 1000, "(" * 1001 + "a" + ")" * 1001, "(?:" * 999 + "a" + ")" * 999,
              "a" * 300, "[a-z]" * 100, "\\pL{20}", "[\\pL\\pN]{10}", "(\\pL{5}){4}", "a**", "a*+", "a*?*", "a++",
              "\\8", "\\1", "\\0", "\\07", "\\08", "\\x", "\\x{", "\\x{}", "\\x{110000}", "\\x{10ffff}", "\\xg", "\\xaz", "\\C", "\\Z",
              "(?P<n", "(?P<n>", "(?P<>a)", "(?P<n!>a)", "(?<n>a)", "(?<>a)", "(?i", "(?i-", "(?-)", "(?i-i)", "(?)", "(?:", ")", "(", "[", "[]", "[^]", "[a", "[z-a]", "[a-\\d]", "[[:foo:]]", "[[:alpha:]", "\\p", "\\pX", "\\p{", "\\p{Foo}", "\\p{^}", "*", "|*", "+a", "{", "a{", "a{,}", "a{1,2", "a{2,1}", "a{1001}", "a{1000,1001}",
              "x{2}{3}", "(?i)\u212a", "(?i)k", "(?i)\u017f", "(?i)[k]", "(?i)[^k]", "(?i)\\pL", "(?i)\\p{Greek}", "(?i)[[:upper:]]", "(?i)[[:^lower:]]", "\\Qab", "\\Qab\\E+", "\\Q\\E", "\\Q\\E*", "a\\Q\\Eb",
              "(?s).", "(?m)^$", "(?U)a+", "(?U)a+?", "^*", "$*", "\\b+", "(|a)*", "(a|)+", "(a*)*", "(a*)+", "(a+)*", "(?:a*)*b", "(a?)*?", "(a|b)*?c",
              "[\\x{10000}-\\x{10ffff}]", "[^\\x00-\\x{10ffff}]", "[\\x00-\\x{10ffff}]", "[^\\n]", "\\P{Any}", "[^a-z]", "a|b|c|d", "ab|ac|ad", "abc|abd|ab", "a.|a.b|a\\n"]
    for p in limits:
        for flags in (perl_flags, 0):
            reqs.append(f"S\t{flags}\t{hexs(p)}")
    for p in (b"\xff", b"a\xff", b"[\xff]", b"\\p{\xff}", b"(?P<\xff>a)", b"\\x\xff", b"a{\xff", b"\\\xff", b"(?\xff)", b"\\Q\xff\\E", b"\xc3", b"a\xe6\x97"):
        for flags in (perl_flags, 0, 2):
            reqs.append(f"S\t{flags}\t{hexs(p)}")
    for p in ("a", "", "a.b*", "\xe6"):
        reqs.append(f"S\t2\t{hexs(p)}")
        reqs.append(f"S\t3\t{hexs(p)}")
    for r1 in (-1, 10, 32, 97, 95, 0x3b1):
        for r2 in (-1, 10, 32, 97, 95, 0x3b1):
            reqs.append(f"E\t{r1}\t{r2}")

    # Match cases: valid UTF-8 patterns only (regexp.Compile takes &str).
    patterns = []
    while len(patterns) < MATCH_PATTERNS:
        r = rng.random()
        if r < 0.12 and tables:
            p = rng.choice(tables)
        elif r < 0.3:
            p = mutate(rng, expr(rng, 3))
        else:
            p = expr(rng, 3)
        if "\xff" in p or any(0xd800 <= ord(c) < 0xe000 for c in p):
            continue
        patterns.append(p)
    patterns += ["", "a", "a*", "(a)|(b)", "(a*)*", "(a*)+", "a|ab", "ab|a", "(a|ab)(c|bcd)(d*)", "x*", "\\b", "^", "$", "(?m)^", "(?m)$", "\\B",
                 "(|a)+", "(a|)+", "a**", "(?i)straSSe", "(?i)\u017f", "[^a]", ".", "(?s).", "\\pL+", "[[:alpha:]]+", "(?P<name>a+)(?P<x>b*)", "(a?)(b?)", "(a)?(b)?"]
    for i, p in enumerate(patterns):
        mode = "P"
        if i % 7 == 1:
            mode = "X"
        elif i % 5 == 2:
            mode = "L"
        inputs = list(CURATED_INPUTS[i % len(CURATED_INPUTS):][:1]) + [random_input(rng) for _ in range(INPUTS_PER_PATTERN)]
        for s in inputs:
            reqs.append(f"M\t{mode}\t{hexs(p)}\t{hexs(s)}")
            reqs.append(f"A\t{mode}\t{hexs(p)}\t{hexs(s)}")
    for i, p in enumerate(LONG_PATTERNS):
        for n in LONG_SIZES:
            s = "".join(rng.choice(ALPHABET + ["ab", "abc" * 20, "a" * 41]) for _ in range(n))
            s = s.encode("utf8")[:n]
            mode = "PXL"[i % 3] if "\\" not in p and "(?" not in p else "PL"[i % 2]
            reqs.append(f"M\t{mode}\t{hexs(p)}\t{hexs(s)}")
            if n <= 1500:
                reqs.append(f"A\t{mode}\t{hexs(p)}\t{hexs(s)}")
    for p, s in ONE_PASS_PREFIX_CASES:
        reqs.append(f"M\tP\t{hexs(p)}\t{hexs(s)}")
        reqs.append(f"A\tP\t{hexs(p)}\t{hexs(s)}")
    return reqs


def prettify(line):
    def decode(m):
        try:
            return repr(bytes.fromhex(m.group(1)).decode("utf8", "replace"))
        except ValueError:
            return m.group(0)
    return re.sub(r"h:([0-9a-f]*)", decode, line)


def normalize(line):
    """Go keeps raw bytes in Error.Expr; Rust's Expr is lossy UTF-8."""
    if not line.startswith("ERR"):
        return line
    return re.sub(r"h:([0-9a-f]*)", lambda m: "h:" + bytes.fromhex(m.group(1)).decode("utf8", "replace").encode("utf8").hex(), line)


def run(command, payload, what):
    result = subprocess.run(command, input=payload, text=True, capture_output=True, cwd=ROOT)
    if result.returncode:
        raise RuntimeError(f"{what} failed:\n{result.stderr[-4000:]}")
    return result.stdout.splitlines()


def main():
    reqs = build_requests()
    payload = "".join(r + "\n" for r in reqs)
    # Optimized build: the debug build of the Unicode class expansion is ~10x slower.
    subprocess.run(["cargo", "build", "--release", "--quiet", "--offline", "--locked", "--example", "regexp_probe"], cwd=ROOT, check=True)
    probe = ROOT / "target/release/examples/regexp_probe"
    rust = run([str(probe)], payload, "Rust regexp probe")
    go = run(["go", "run", str(ROOT / "tools/regexp/oracle.go")], payload, "Go regexp oracle")
    if len(rust) != len(reqs) or len(go) != len(reqs):
        raise AssertionError(f"line counts differ: requests={len(reqs)} rust={len(rust)} go={len(go)}")
    rust = [normalize(line) for line in rust]
    go = [normalize(line) for line in go]
    bad = [i for i, (a, b) in enumerate(zip(rust, go)) if a != b]
    for i in bad[:5]:
        fields = reqs[i].split("\t")
        shown = [fields[0]] + [fields[1]] + [repr(bytes.fromhex(f)) for f in fields[2:]] if fields[0] != "E" else fields
        print(f"MISMATCH vector {i}: {shown}", file=sys.stderr)
        a, b = prettify(rust[i]).split(" "), prettify(go[i]).split(" ")
        diffs = [(x, y) for x, y in zip(a, b) if x != y] or [(" ".join(a), " ".join(b))]
        for x, y in diffs[:4]:
            print(f"  Rust: {x[:600]}\n  Go:   {y[:600]}", file=sys.stderr)
    if bad:
        raise AssertionError(f"{len(bad)} of {len(reqs)} regexp vectors differ from Go")
    kinds = {k: sum(1 for r in reqs if r.startswith(k + "\t")) for k in "SMAE"}
    errors = sum(1 for line in go if line.startswith("ERR"))
    print(f"Regexp Go differential: {len(reqs)} vectors passed ({kinds['S']} syntax, {kinds['M']} match, {kinds['A']} offset, {kinds['E']} empty-op; {errors} parse errors)")


if __name__ == "__main__":
    main()
