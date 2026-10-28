#!/usr/bin/env python3
"""Run a deterministic Go/Rust differential corpus for slash paths and globbing."""
import os
import random
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def hx(value):
    return value.encode("utf-8").hex()


def corpus():
    rows = []
    path_cases = ["", ".", "..", "./", "a/..", "a//b/../c/", "/../../a", "../../a/../b",
                  "///", "a\\b/../c", "é/../雪", "/é/雪", "a.txt", ".hidden", "a.", "a/b.tar.gz", "a/", "//a"]
    for value in path_cases:
        a = hx(value)
        rows.extend(f"{op}\t{a}" for op in "CSBDEA")
        rows.append(f"J\t{a}\t{hx('')}\t{hx('x/..')}\t{hx('雪')}")

    rng = random.Random(0xFA7A)
    alphabet = ["a", "b", ".", "/", "..", "", "é", "雪", "\\"]
    for _ in range(350):
        value = "".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 12)))
        a = hx(value)
        rows.extend(f"{op}\t{a}" for op in "CSBDEA")
        elements = ["".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 5))) for _ in range(rng.randrange(0, 6))]
        rows.append("J\t" + "\t".join(hx(x) for x in elements))

    patterns = ["", "*", "**", "*.txt", "a?c", "a\\*b", "[a-c]at", "[^a-c]at", "[/]", "?", "??",
                "[α-ω]", "[\\-]", "**/x", "\\", "[", "[]", "[^]", "[-a]", "[a-]", "a[", "x\\",
                # Malformed text after a star or a slash is reported only when matching reaches it.
                "/-ab*[^]b[", "a*[", "*[a-", "x*[\\", "a*b[", "a/*[", "*/[", "a/b[", "*?[]"]
    names = ["", "a", "abc", "a/c", "name.txt", "dir/name.txt", "a*b", "bat", "dat", "zat", "/", "雪", "β", "-", "a/x", "other",
             "x", "b", "cbb雪]/c", "/-abcb]/c", "ab/c", "a/bb[", "xyz", "a/b[x"]
    rows.extend(f"M\t{hx(pattern)}\t{hx(name)}" for pattern in patterns for name in names)
    for _ in range(500):
        pattern = "".join(rng.choice("abc/*?[]^-\\.é") for _ in range(rng.randrange(0, 15)))
        name = "".join(rng.choice(["a", "b", "c", "/", "é", "雪"]) for _ in range(rng.randrange(0, 12)))
        rows.append(f"M\t{hx(pattern)}\t{hx(name)}")
    return rows


def main():
    requests = corpus()
    source = "\n".join(requests) + "\n"
    env = os.environ.copy()
    rust = subprocess.run(
        ["cargo", "run", "--offline", "--locked", "--quiet", "--example", "path_probe"],
        cwd=ROOT, input=source, text=True, capture_output=True, env=env, check=True,
    ).stdout.splitlines()
    go = subprocess.run(
        ["go", "run", "tools/path_oracle.go"], cwd=ROOT, input=source, text=True,
        capture_output=True, env=env, check=True,
    ).stdout.splitlines()
    if rust != go:
        for i, (actual, expected) in enumerate(zip(rust, go)):
            if actual != expected:
                raise SystemExit(f"path mismatch at vector {i}: {requests[i]}\nRust: {actual}\nGo:   {expected}")
        raise SystemExit(f"line count mismatch: Rust {len(rust)}, Go {len(go)}")
    print(f"Go/Rust slash-path differential: {len(requests)} vectors passed")


if __name__ == "__main__":
    main()
