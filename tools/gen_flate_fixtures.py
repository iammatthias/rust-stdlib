#!/usr/bin/env python3
"""Extract Go's gunzipTests and zlibTests tables into tab separated hex fixtures.

Reads $(go env GOROOT)/src/compress/{gzip/gunzip_test.go,zlib/reader_test.go}
and writes tests/fixtures/compress/{gunzip_tests,zlib_tests}.tsv, which
tests/flate.rs replays. The Go test data is BSD-licensed (see NOTICE).
"""
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOKEN = re.compile(r'"(?:[^"\\]|\\.)*"|\[\]byte\{[^}]*\}|[A-Za-z_][\w.]*|[{},+]|//[^\n]*', re.S)
ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}


def unquote(lit):
    body = lit[1:-1]
    out = bytearray()
    i = 0
    while i < len(body):
        c = body[i]
        if c != "\\":
            out += c.encode()
            i += 1
        elif body[i + 1] == "x":
            out.append(int(body[i + 2:i + 4], 16))
            i += 4
        elif body[i + 1] == "u":
            out += chr(int(body[i + 2:i + 6], 16)).encode()
            i += 6
        else:
            out += ESCAPES[body[i + 1]].encode()
            i += 2
    return bytes(out)


def entries(text, var):
    start = text.index(f"var {var} = ")
    body = text[text.index("{", start) + 1:]
    tokens = [t for t in TOKEN.findall(body) if not t.startswith("//")]
    depth, current, result = 0, [], []
    for t in tokens:
        if t == "{":
            depth += 1
            if depth == 1:
                current = []
                continue
        elif t == "}":
            depth -= 1
            if depth == 0:
                result.append(current)
                continue
            if depth < 0:
                break
        if depth >= 1:
            current.append(t)
    return result


def fields(entry):
    """Split on top level commas; adjacent string literals are joined by '+'."""
    out, cur = [], []
    for t in entry:
        if t == ",":
            out.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        out.append(cur)
    return out


def value(parts):
    if parts[0].startswith("[]byte{"):
        inner = parts[0][len("[]byte{"):-1]
        items = re.findall(r"0x[0-9a-fA-F]+|\d+|'.'", inner)
        return bytes(ord(n[1]) if n.startswith("'") else int(n, 0) for n in items)
    if parts[0].startswith('"'):
        return b"".join(unquote(p) for p in parts if p.startswith('"'))
    return b"" if parts[0] == "nil" else parts[0].encode()


def err_name(parts):
    return parts[0]


def hexs(b):
    return b.hex() if b else "-"


def main():
    goroot = pathlib.Path(subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True, check=True).stdout.strip())
    fixtures = ROOT / "tests/fixtures/compress"
    gz = (goroot / "src/compress/gzip/gunzip_test.go").read_text()
    rows = []
    for entry in entries(gz, "gunzipTests"):
        f = fields(entry)
        name, desc, raw, data = (value(x) for x in f[:4])
        rows.append("\t".join([hexs(name), desc.decode(), hexs(raw), hexs(data), err_name(f[4])]))
    (fixtures / "gunzip_tests.tsv").write_text("\n".join(rows) + "\n")
    print(f"wrote {len(rows)} gunzip fixtures")
    zl = (goroot / "src/compress/zlib/reader_test.go").read_text()
    rows = []
    for entry in entries(zl, "zlibTests"):
        f = fields(entry)
        desc, raw, data, dictionary = (value(x) for x in f[:4])
        rows.append("\t".join([desc.decode(), hexs(raw), hexs(data), hexs(dictionary), err_name(f[4])]))
    (fixtures / "zlib_tests.tsv").write_text("\n".join(rows) + "\n")
    print(f"wrote {len(rows)} zlib fixtures")
    fl = (goroot / "src/compress/flate/flate_test.go").read_text()
    start = fl.index("}{{", fl.index("func TestStreams"))
    block = "{" + fl[start + 2:fl.index("\n\t}}\n", start) + 4]
    rows = []
    for entry in entries("var streams = " + block, "streams"):
        desc, stream, want = (value(x).decode() for x in fields(entry)[:3])
        rows.append("\t".join([desc, stream, want or "-"]))
    (fixtures / "flate_streams.tsv").write_text("\n".join(rows) + "\n")
    print(f"wrote {len(rows)} flate stream fixtures")


if __name__ == "__main__":
    main()
