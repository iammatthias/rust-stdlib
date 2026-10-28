#!/usr/bin/env python3
"""Differentially check package flag against Go: generated FlagSets (every flag
kind, Func/BoolFunc/TextVar/custom Value, invalid and duplicate definitions)
parsed with generated and mutated argument vectors. Compares the error text,
final values, flags set, remaining arguments, everything written to the set's
output, PrintDefaults, callback logs, Set outcomes and Getter types.
"""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]

NAMES = ["v", "verbose", "n", "count", "help-me", "name", "a", "b", "c", "x", "y", "é", "a.b",
         "long_flag_name_here", "h", "help", "o", "out", "t", "timeout", "rate", "port", "list", "level", "mode", "d"]
USAGES = ["", "usage text", "the `file` to read", "multi\nline", "back`tick", "a `b` and `c`", "with %s percent",
          "é unicode", "enable verbose output", "a much longer usage message that goes on for a while",
          "``", "`x` y `z` w", "line1\nline2\nline3", "\ttabbed"]
KINDS = ["bool", "int", "int64", "uint", "uint64", "string", "float64", "duration", "list", "count", "text",
         "func", "boolfunc"]
DEFAULTS = {
    "bool": ["false", "true", "x"],
    "int": ["0", "7", "-3", "1000", "x"],
    "int64": ["0", "-9223372036854775808", "42"],
    "uint": ["0", "5", "18446744073709551615"],
    "uint64": ["0", "5", "18446744073709551615"],
    "string": ["", "default", "with space", "quo\"te", "é", "0", "a\nb"],
    "float64": ["0", "1.5", "2.5e3", "-0.25", "100000000", "1e21", "0.000001", "3"],
    "duration": ["0", "1s", "1h30m", "250ms", "-5m", "x"],
    "list": ["", "a", "a,b"],
    "count": ["0", "3"],
    "text": ["", "word", "UP"],
    "func": [""],
    "boolfunc": [""],
}
VALUES = {
    "bool": ["true", "false", "1", "0", "t", "f", "T", "F", "TRUE", "FALSE", "True", "False", "yes", "", "2", "tRUE"],
    "int": ["0", "7", "-3", "0x1f", "0o17", "017", "0b101", "1_000", "9223372036854775807", "9223372036854775808",
            "-9223372036854775809", "abc", "", "1.5", "+4", " 1", "0x", "_1"],
    "int64": ["0", "-1", "9223372036854775807", "99999999999999999999", "0xFF", "x"],
    "uint": ["0", "7", "-1", "18446744073709551615", "18446744073709551616", "0x10", "abc", "+1"],
    "uint64": ["0", "7", "-1", "18446744073709551615", "18446744073709551616", "0x10", "abc"],
    "string": ["", "x", "hello world", "-dash", "--", "=eq", "a=b", "éè", "-"],
    "float64": ["0", "1.5", "-2.5e-3", "NaN", "Inf", "-Inf", "1e400", "0x1p-2", "abc", "", ".5", "1_0.5", "1e"],
    "duration": ["0", "1s", "1h2m3s", "1.5h", "-5m", "100", "5x", "", "1us", "1µs", "9223372036854775807ns",
                 "9223372036854775808ns"],
    "list": ["a", "b", "", "x,y"],
    "count": ["", "1", "x"],
    "text": ["abc", "bad", "", "mixed Case"],
    "func": ["ok", "bad", "", "x=y"],
    "boolfunc": ["ok", "bad", "true", ""],
}
JUNK = ["-", "--", "---x", "-=x", "--=x", "-help", "--help", "-h", "--h", "-undefined", "--undefined=1", "positional",
        "pos two", "-n-", "-é", "-x=", "-=", "--x=1=2", "-0", "-9", "-x\t", "- ", "-é=é"]


def make_set(rng):
    nflags = rng.choice([0, 1, 2, 3, 3, 4, 5, 7])
    names = rng.sample(NAMES, min(nflags, len(NAMES)))
    defs = []
    for name in names:
        kind = rng.choice(KINDS)
        defs.append([kind, name, rng.choice(DEFAULTS[kind]), rng.choice(USAGES)])
    roll = rng.random()
    if defs and roll < 0.04:
        defs.append([rng.choice(KINDS), rng.choice(["-bad", "a=b", "--x"]), "", ""])
    elif defs and roll < 0.07:
        d = rng.choice(defs)
        defs.append([rng.choice(KINDS), d[1], "", "dup"])
    return defs


def make_args(rng, defs):
    out = []
    for _ in range(rng.choice([0, 1, 2, 3, 4, 6, 9])):
        if defs and rng.random() < 0.75:
            kind, name, _, _ = rng.choice(defs)
            dashes = rng.choice(["-", "--", "-", "--", "---"] if rng.random() < 0.05 else ["-", "--"])
            val = rng.choice(VALUES.get(kind, [""]))
            form = rng.randrange(4)
            if form == 0:
                out.append(f"{dashes}{name}")
            elif form == 1:
                out.append(f"{dashes}{name}={val}")
            elif form == 2:
                out += [f"{dashes}{name}", val]
            else:
                out += [f"{dashes}{name}", f"{dashes}{rng.choice(defs)[1]}"]
        else:
            out.append(rng.choice(JUNK))
    return out


def tok(text):
    return "_" if text == "" else text.encode("utf-8").hex()


def main():
    rng = random.Random(0xF1A6)
    records = []
    for _ in range(4200):
        defs = make_set(rng)
        args = make_args(rng, defs)
        if rng.random() < 0.1:
            args.insert(rng.randrange(len(args) + 1), "--")
        sets = []
        for _ in range(rng.choice([0, 0, 1, 2, 3])):
            if defs and rng.random() < 0.7:
                kind, name, _, _ = rng.choice(defs)
                sets.append([name, rng.choice(VALUES.get(kind, [""]))])
            else:
                sets.append([rng.choice(NAMES), rng.choice(["1", "x", ""])])
        record = [rng.choice(["", "prog", "my tool"]), str(rng.choice([0, 0, 0, 1])), str(len(defs))]
        for d in defs:
            record += d
        record += [str(len(args))] + args + [str(len(sets))]
        for s in sets:
            record += s
        records.append(record)
    payload = "".join(" ".join(tok(t) for t in r) + "\n" for r in records)

    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "flag_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if rust_run.returncode:
        raise RuntimeError(f"Rust flag probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(
        ["go", "run", str(ROOT / "tools/flag_oracle.go")],
        input=payload, text=True, capture_output=True, cwd=ROOT,
    )
    if go_run.returncode:
        raise RuntimeError(f"Go flag oracle failed:\n{go_run.stderr}")
    rust, go = rust_run.stdout.splitlines(), go_run.stdout.splitlines()
    if len(rust) != len(records) or len(go) != len(records):
        raise AssertionError(f"flag oracle record count: rust={len(rust)} go={len(go)} want={len(records)}")
    errors = panics = 0
    for i, (actual, expected) in enumerate(zip(rust, go)):
        if actual != expected:
            raise AssertionError(f"vector {i}: {records[i]!r}\nRust={actual!r}\nGo  ={expected!r}")
        errors += expected.startswith("ERR")
        panics += expected.startswith("PANIC")
    print(f"Flag Go differential: {len(records)} FlagSet/argv vectors passed "
          f"({errors} parse errors, {panics} definition panics)")


if __name__ == "__main__":
    main()
