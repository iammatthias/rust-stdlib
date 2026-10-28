#!/usr/bin/env python3
"""Differentially check mime/multipart framing, forms and writer output against Go.

The Reader follows Go's own framing, so the corpus includes what Go accepts and
rejects: LF line endings, parts without a Content-Disposition, folded and
duplicate headers, quoted-printable parts (NextPart and NextRawPart), truncated
documents and random byte mutations of all of those.
"""
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
RNG = random.Random(0x6D6F)

BOUNDARIES = ["boundary", "a", "xyz-123", "simple boundary", "a'()+_,-./:=?b", "Q9"]
BAD_BOUNDARIES = ["", "a" * 71, "x y ", "a\"b", "é", "a ", "ok\\"]
NAMES = ["file", "a", "field name", "ü", "x y", "q\"q", "back\\slash", "", "日本", "n=v", "semi;colon"]
FILENAMES = ["a.txt", "dir/b.txt", "C:\\path\\c.txt", "", "../../x", "/abs/y", "trail/", "ü.bin",
             "sp ace.txt", "/", "a//b", "x\"quoted\".txt"]
EXTRA_HEADERS = ["Content-Type: text/plain", "X-Test: v", "Content-Type: application/octet-stream; charset=x",
                 "X-Multi: one", "x-empty:"]
BODY_PIECES = [b"", b"x", b"hello", b"\r\n", b"--", b"\r\n--", b"\r\n\r\n", b"--boundary", b"\r\n--boundary-x",
               b"\r\n--boundary  \r\n", b"\x00", b"\xff\xfe", b"plain text", b"\r", b"\n", b"-" * 5]


def escape(text):
    return text.replace("\\", "\\\\").replace("\"", "\\\"")


def utf8_body():
    return "".join(RNG.choice(["a", "é", "日", " ", "\t", "--", "\r\n"]) for _ in range(RNG.randint(0, 12)))


def body_bytes(file_part):
    if not file_part:
        return utf8_body().encode()
    return b"".join(RNG.choice(BODY_PIECES) for _ in range(RNG.randint(0, 8)))


def part(file_part=None):
    name = RNG.choice(NAMES)
    if file_part is None:
        file_part = RNG.random() < 0.4
    disposition = f'form-data; name="{escape(name)}"'
    if file_part:
        disposition += f'; filename="{escape(RNG.choice(FILENAMES))}"'
    headers = [f"Content-Disposition: {disposition}"]
    headers.extend(RNG.sample(EXTRA_HEADERS, RNG.randint(0, 2)))
    head = ("\r\n".join(headers) + "\r\n\r\n").encode()
    return head + body_bytes(file_part)


def body_document(boundary, parts, preamble=True, epilogue=True):
    """A multipart document; parts are complete header and body blocks."""
    out = b""
    if preamble and RNG.random() < 0.3:
        out += b"preamble text\r\n"
    if not parts:
        return out + f"--{boundary}--".encode()
    for item in parts:
        out += f"--{boundary}\r\n".encode() + item + b"\r\n"
    out = out[:-2] + f"\r\n--{boundary}--".encode()
    if epilogue and RNG.random() < 0.3:
        out += b"\r\nepilogue"
    return out


def build_document(boundary):
    return body_document(boundary, [part() for _ in range(RNG.randint(0, 5))])


def fixed_documents():
    """(boundary, document) pairs with hand-picked framing."""
    docs = []
    for boundary in BOUNDARIES:
        docs.append((boundary, body_document(boundary, [])))
        docs.append((boundary, body_document(boundary, [part(False)])))
        docs.append((boundary, body_document(boundary, [part(True), part(False)])))
    docs.append(("boundary", b"--boundary\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nx"))
    docs.append(("boundary", b"--boundary\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nx\r\n--boundary"))
    docs.append(("boundary", b"--boundary\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nx\r\n--boundary--"))
    docs.append(("boundary", b"--boundary\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nx\r\n--boundary--\r\n"))
    many = [f'Content-Disposition: form-data; name="n{i}"\r\n\r\nv{i}'.encode() + b"" for i in range(1001)]
    docs.append(("boundary", body_document("boundary", many, preamble=False, epilogue=False)))
    return docs


def lenient_documents():
    """Documents that only a lenient parser accepts."""
    docs = []
    for boundary in BOUNDARIES[:3]:
        b = boundary
        cd = 'Content-Disposition: form-data; name="a"'
        docs += [
            (b, f"--{b}\n{cd}\n\nvalue\n--{b}--\n".encode()),
            (b, f"--{b}\n{cd}\n\nva\r\nlue\n--{b}\n{cd}; filename=\"f\"\n\nx\n--{b}--".encode()),
            (b, f"--{b}\r\nX-Only: header\r\n\r\nbody\r\n--{b}--\r\n".encode()),
            (b, f"--{b}\r\n\r\nno headers\r\n--{b}--\r\n".encode()),
            (b, f"--{b}\r\n{cd}\r\n\r\none\r\n--{b}\r\n{cd}\r\n\r\ntwo\r\n--{b}--\r\n".encode()),
            (b, f"--{b}\r\n{cd};\r\n filename=\"folded.txt\"\r\n\r\nx\r\n--{b}--\r\n".encode()),
            (b, f"--{b}\r\n{cd}\r\nContent-Disposition: form-data; name=\"b\"\r\n\r\nx\r\n--{b}--\r\n".encode()),
            (b, f"--{b}\r\n{cd}\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nh=C3=A9llo=\r\n world\r\n--{b}--\r\n".encode()),
            (b, f"--{b}\r\n{cd}\r\nContent-Transfer-Encoding: Quoted-Printable\r\n\r\n=ZZ bad=\r\n--{b}--\r\n".encode()),
            (b, f"--{b}\r\n{cd}\r\nContent-Transfer-Encoding: base64\r\n\r\neA==\r\n--{b}--\r\n".encode()),
            (b, f"--{b}  \t\r\n{cd}\r\n\r\nx\r\n--{b}--  \r\n".encode()),
            (b, f"junk\r\nmore junk\r\n--{b}\r\n{cd}\r\n\r\nx\r\n--{b}--\r\n".encode()),
            (b, f"--{b}\r\n{cd}\r\n\r\nx\r\n\r\n--{b}--".encode()),
            (b, f"--{b}\r\n{cd}\r\n\r\nx\r\nstray\r\n--{b}--".encode()),
            (b, f"--{b}\r\n{cd}\r\n\r\nx".encode()),
            (b, f"--{b}\r\n{cd}".encode()),
            (b, f"--{b}\r\n".encode()),
            (b, f"--{b}".encode()),
            (b, b""),
            (b, f"--{b}\r\n{cd}\r\n\r\n--{b}--".encode()),
            (b, f"--{b}\r\n{cd}\r\n\r\n\r\n--{b}-x\r\n--{b}--".encode()),
            (b, (f"--{b}\r\n" + "X: y\r\n" * 40 + f"{cd}\r\n\r\nbody\r\n--{b}--").encode()),
            (b, (f"{'p' * 5000}\r\n--{b}\r\n{cd}\r\n\r\nx\r\n--{b}--").encode()),
            (b, (f"--{b}\r\n{cd}\r\n\r\n" + "y" * 9000 + f"\r\n--{b}--").encode()),
            (b, f"--{b}\r\n bad first: line\r\n\r\nx\r\n--{b}--".encode()),
            (b, f"--{b}\r\nno colon\r\n\r\nx\r\n--{b}--".encode()),
            (b, f"--{b}\r\nBad Key: v\r\n\r\nx\r\n--{b}--".encode()),
        ]
    return docs


def mutated(doc):
    data = bytearray(doc)
    for _ in range(RNG.randint(1, 4)):
        if not data:
            break
        kind = RNG.randrange(4)
        i = RNG.randrange(len(data))
        if kind == 0:
            data[i] = RNG.choice(b"\r\n -:=\"\x00ab")
        elif kind == 1:
            del data[i:i + RNG.randint(1, 6)]
        elif kind == 2:
            data[i:i] = RNG.choice([b"\r\n", b"\n", b"--", b" ", b"\r", b"=\r\n"])
        else:
            data = data[:i]
    return bytes(data)


def scenario_documents(count):
    return [(boundary, build_document(boundary)) for boundary in (RNG.choice(BOUNDARIES) for _ in range(count))]


def writer_items():
    items = []
    for _ in range(RNG.randint(0, 5)):
        kind = RNG.choice(["F", "C", "H", "P"])
        if kind == "F":
            items.append(f"F\x1f{RNG.choice(NAMES)}\x1f{utf8_body()}".encode())
        elif kind == "C":
            items.append(f"C\x1f{RNG.choice(NAMES)}\x1f{RNG.choice(FILENAMES)}\x1f{utf8_body()}".encode())
        elif kind == "H":
            items.append(f"H\x1f{RNG.choice(NAMES)}\x1f{utf8_body()}".encode())
        else:
            key = RNG.choice(["X-Custom", "content-type", "X-A"])
            items.append(f"P\x1f{key}\x1f{RNG.choice(['text/plain', 'a b', ''])}\x1f{utf8_body()}".encode())
    return items


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=600)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return result.stdout.splitlines()


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("multipart differential check requires Go and Cargo on PATH")
    requests = []
    base = fixed_documents() + lenient_documents()
    documents = base + scenario_documents(500)
    documents += [(b, mutated(d)) for b, d in RNG.choices(base + scenario_documents(100), k=700)]
    for boundary, doc in documents:
        requests.append(("R", boundary.encode() + b"\0" + doc))
    for boundary, doc in base + documents[-300:]:
        requests.append(("W", boundary.encode() + b"\0" + doc))
    form_documents = base + scenario_documents(350) + documents[-300:]
    for boundary, doc in form_documents:
        max_memory = RNG.choice([0, 10, 300, 1 << 20, -1, -(10 << 20), -(10 << 20) - 1, 1 << 40])
        requests.append(("F", boundary.encode() + b"\0" + str(max_memory).encode() + b"\0" + doc))
    # Spilling: file parts around max_memory, in a private TMPDIR per process.
    for boundary, doc in base + scenario_documents(200) + documents[-200:]:
        max_memory = RNG.choice([0, 1, 3, 5, 10, 50, 120, 300, -1, 1 << 20])
        requests.append(("T", boundary.encode() + b"\0" + str(max_memory).encode() + b"\0" + doc))
    for boundary in BOUNDARIES:
        for _ in range(12):
            parts = [part(True) for _ in range(RNG.randint(1, 4))]
            max_memory = RNG.choice([0, 4, 8, 16, 40])
            requests.append(("T", boundary.encode() + b"\0" + str(max_memory).encode() + b"\0"
                             + body_document(boundary, parts)))
    for _ in range(150):
        requests.append(("D", RNG.choice(NAMES).encode() + b"\0" + RNG.choice(FILENAMES).encode()))
    for _ in range(200):
        boundary = RNG.choice(BOUNDARIES + BAD_BOUNDARIES)
        requests.append(("B", boundary.encode() + b"\0" + b"\0".join(writer_items())))
    for boundary in BOUNDARIES + BAD_BOUNDARIES:
        requests.append(("S", boundary.encode()))
        requests.append(("M", boundary.encode()))
    payload = "\n".join(f"{mode}:{data.hex()}" for mode, data in requests) + "\n"
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go_tmp = tempfile.mkdtemp(prefix="multipart-go-")
    rust_tmp = tempfile.mkdtemp(prefix="multipart-rust-")
    try:
        go = run(["go", "run", "tools/multipart_oracle.go"], payload, {**env, "TMPDIR": go_tmp})
        rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "multipart_probe"],
                   payload, {**env, "TMPDIR": rust_tmp})
    finally:
        shutil.rmtree(go_tmp, ignore_errors=True)
        shutil.rmtree(rust_tmp, ignore_errors=True)
    if len(go) != len(requests) or len(rust) != len(requests):
        raise AssertionError("multipart oracle returned the wrong number of records")
    # "skip": a header or form value that is not valid UTF-8 (the Rust port
    # holds those as String and rejects them).
    failures = [(mode, data, g, r) for (mode, data), g, r in zip(requests, go, rust) if g != r and g != "skip"]
    for mode, data, g, r in failures[:6]:
        print(f"mode={mode} input={data[:200]!r}\n  Go  ={g[:300]!r}\n  Rust={r[:300]!r}")
    if failures:
        raise AssertionError(f"{len(failures)} of {len(requests)} multipart records differ from Go")
    counts = {}
    for mode, _ in requests:
        counts[mode] = counts.get(mode, 0) + 1
    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    skipped = sum(1 for g in go if g == "skip")
    toolarge = sum(1 for g in go if g == "toolarge")
    errors = sum(1 for g in go if g == "err")
    print(f"multipart Go differential: {len(requests)} records passed ({detail}); "
          f"{toolarge} ErrMessageTooLarge and {errors} error results matched; "
          f"{skipped} skipped for non-UTF-8 text")


if __name__ == "__main__":
    main()
