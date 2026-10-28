#!/usr/bin/env python3
"""Extract Go's strconv test tables into tests/fixtures/strconv/*.txt.

Reads $(go env GOROOT)/src/internal/strconv/{atoi,atof,ftoa}_test.go and
writes tab-separated fixtures that tests/strconv.rs replays. Entries whose
fields are not plain literals (math.Inf, helper calls) are skipped.
"""
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
GOROOT = pathlib.Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())
SRC = GOROOT / "src/internal/strconv"
OUT = ROOT / "tests/fixtures/strconv"


def table(text, name):
    start = text.index(f"var {name} = ")
    body = text[text.index("{\n", start):text.index("\n}\n", start)]
    return body


def go_string(lit):
    if lit.startswith("`"):
        return lit[1:-1]
    if not re.fullmatch(r'"(?:[^"\\]|\\.)*"', lit):
        raise ValueError(lit)
    return eval(lit)  # Go interpreted literals use the same escapes for these tables


def go_int(expr):
    expr = re.sub(r"\b0([0-7]+)\b", r"0o\1", expr.strip())
    # Go binds << tighter than +/-; Python does not.
    expr = re.sub(r"(\d+)\s*<<\s*(\d+)", r"(\1<<\2)", expr)
    return eval(expr, {"__builtins__": {}})


def split_fields(inner):
    """Split a Go composite literal body on top-level commas."""
    fields, cur, quote, i = [], "", None, 0
    while i < len(inner):
        c = inner[i]
        if quote:
            cur += c
            if c == "\\" and quote == '"':
                cur += inner[i + 1]
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"`":
            quote = c
            cur += c
        elif c == ",":
            fields.append(cur.strip())
            cur = ""
        else:
            cur += c
        i += 1
    fields.append(cur.strip())
    return fields


def entries(body, arity):
    rows = []
    for line in body.splitlines():
        line = line.strip()
        m = re.match(r"\{(.*)\},?\s*(//.*)?$", line)
        if not m:
            continue
        fields = split_fields(m.group(1))
        if len(fields) == arity:
            rows.append(fields)
    return rows


def safe(fn):
    try:
        return fn()
    except (ValueError, SyntaxError, NameError, TypeError, UnicodeEncodeError):
        return None


def hx(s):
    return s.encode("utf-8").hex()


def main():
    atoi = (SRC / "atoi_test.go").read_text()
    lines = []
    for name, kind, bits in [("parseUint64Tests", "U", 64), ("parseInt64Tests", "I", 64), ("parseUint32Tests", "U", 32), ("parseInt32Tests", "I", 32)]:
        for m in entries(table(atoi, name), 3):
            row = safe(lambda: "\t".join([kind, hx(go_string(m[0])), "10", str(bits), str(go_int(m[1])), m[2]]))
            if row:
                lines.append(row)
    for name, kind in [("parseUint64BaseTests", "U"), ("parseInt64BaseTests", "I")]:
        for m in entries(table(atoi, name), 4):
            row = safe(lambda: "\t".join([kind, hx(go_string(m[0])), str(go_int(m[1])), "64", str(go_int(m[2])), m[3]]))
            if row:
                lines.append(row)
    (OUT / "int_cases.txt").write_text("\n".join(lines) + "\n")

    atof = (SRC / "atof_test.go").read_text()
    lines = []
    for name, bits in [("atoftests", 64), ("atof32tests", 32)]:
        for m in entries(table(atof, name), 3):
            row = safe(lambda: "\t".join([str(bits), hx(go_string(m[0])), hx(go_string(m[1])), m[2]]))
            if row:
                lines.append(row)
    (OUT / "atof_cases.txt").write_text("\n".join(lines) + "\n")

    ftoa = (SRC / "ftoa_test.go").read_text()
    lines = []
    pat = re.compile(r"\{\s*(-?[0-9][0-9.e+\-]*|-?0x[0-9a-fA-F.p+\-]+),\s*'(.)',\s*(-?\d+),\s*\"([^\"]*)\"\s*\}")
    for m in pat.finditer(table(ftoa, "ftoatests")):
        lines.append("\t".join([m[1], m[2], m[3], m[4]]))
    (OUT / "ftoa_cases.txt").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
