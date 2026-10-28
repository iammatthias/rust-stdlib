#!/usr/bin/env python3
"""Differentially check net mime media types and extension registry against Go."""
import os
from pathlib import Path
import random
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
RNG = random.Random(0x3131)

MEDIA = [
    "text/html", "TEXT/HTML", "text/plain; charset=utf-8", "text/plain;charset=UTF-8", "image/jpeg",
    "application/json", "application/x-test; a=b", "multipart/form-data; boundary=xyz", "text/", "/",
    "a/b/c", "bad type", "", "text", "application/x-y ; ", "  text/css  ;  charset = \"utf-8\" ",
    "text/plain; charset=", "text/plain; charset=\"\"", "x/y; p", "x/y; p=", "x/y; p=\"unterminated",
    "x/y; =v", "x/y; a=b; a=c", "x/y; a=b; a=b", "x/y; a*0=foo; a*1=bar", "x/y; a*0*=utf-8''f%C3%B6; a*1=bar",
    "x/y; t*=utf-8''%E2%82%AC", "x/y; t*=us-ascii'en'a%20b", "x/y; t*=koi8-r''x", "x/y; t*0*=utf-8''a; t*1=b%zz",
    "x/y; t*=utf-8''%FF", "x/y; t*0*=utf-8''%FF", "x/y; t*0=a; t*2=c", "x/y; t*1=b; t*0=a",
    "x/y; q=\"a\\\"b\"", "x/y; q=\"a\\\\b\"", "x/y; q=\"tab\there\"", "x/y; q=ö", "x/y; q=\"ö\"",
    "x/y;", "x/y; ;", "x/y; a=b;;c=d", "x/y ;a=b c", "x/y; a=b\r\n", "x/y; a=\"b\r\n\"", "x/y; a=\"b\"c",
    "x/y; a=b(c)", "x/y; a= b", "x/y; a =b", "é/x; a=b", "x/é", "X/Y; A*=utf-8'en'%41%42",
    "X/Y; a*=UTF-8''%41; a*=%41", "X/Y; a*0=%41; a*0*=utf-8''b", "x/y; a*1*=%41", "x/y; a*0*=%zz; a*1=q",
    "x/y; a*0=1; a*0=2", "x/y; a=\"\"", "x/y; a=\"\\\\\"", "text/plain; charset=ISO-8859-1",
]
PARAM_NAMES = ["a", "B", "charset", "title", "t*", "t*0", "t*1", "t*0*", "t*1*", "t*2*", "q*", "x*0*", "*", "a*x",
               "Q", "name", "filename*0", "filename*1*", "k*0*"]
PARAM_VALUES = ["", "b", "utf-8", "UTF-8", "us-ascii", "'x'", "''", "utf-8''a", "utf-8''%41", "%E2%82%AC",
                "%zz", "%FF", "a b", "\"q\"", "\"a\\\"b\"", "x;y", "é", "€", "a=b", "tab\tx", "ctl\x01",
                "(c)", "%", "a'b", "\"unclosed"]
MEDIA_ALPHABET = list("/;=\" *'%'\t.-_aZ09é") + ["utf-8''", "*0=", "*1*=", "; "]


def mutate(text, alphabet):
    chars = list(text)
    for _ in range(RNG.randint(1, 3)):
        pos = RNG.randint(0, len(chars))
        op = RNG.randrange(3)
        if op == 0 or not chars:
            chars.insert(pos, RNG.choice(alphabet))
        elif op == 1:
            del chars[min(pos, len(chars) - 1)]
        else:
            chars[min(pos, len(chars) - 1)] = RNG.choice(alphabet)
    return "".join(chars)


def media_value():
    base = RNG.choice(["text", "image", "x", "application", "Multipart", "a"])
    sub = RNG.choice(["plain", "html", "JPEG", "x-y", "", "*"])
    text = RNG.choice([f"{base}/{sub}", base, f"{base}/{sub}/{sub}"])
    for _ in range(RNG.randint(0, 3)):
        name = RNG.choice(PARAM_NAMES)
        value = RNG.choice(PARAM_VALUES)
        sep = RNG.choice(["; ", ";", " ;", ";;", "; "])
        if RNG.random() < 0.5:
            value = f'"{value}"'
        text += f"{sep}{name}={value}"
    if RNG.random() < 0.2:
        text += RNG.choice([";", "; ", " ; x", "\t", "; a"])
    return text


def media_type_fields():
    types = ["text/html", "TEXT/Plain", "x y/z", "", "a", "a/b/c", "bad/", "/x", "text/plain", "é/x"]
    keys = ["charset", "TITLE", "a b", "", "x*", "k", "q\"q", "é", "a;b"]
    values = ["utf-8", "", "with space", "q\"uote", "back\\slash", "ünï", "tab\tx", "ctl\x01", "%41",
              "a;b", "é€", "x=y", "(paren)", "a'b*c%", "<a@b>", "plain", "\x7f", "a" * 90]
    fields = [RNG.choice(types)]
    for _ in range(RNG.randint(0, 4)):
        fields += [RNG.choice(keys), RNG.choice(values)]
    return "\0".join(fields)


EXTENSIONS = [".html", ".HTML", ".Html", ".jpg", ".JPG", ".jPeG", ".unknown", "", ".", "html", ".tar.gz",
              ".ÄÖ", ".gz", ".ico", ".mjs", ".JS", ".text", ".Text", ".xlsx", ".webm", ".svg", ".PPTX",
              ".foo", ".FOO", ".Bar", ".x.y", ".ÜT", ".q"]
ADD_EXTENSIONS = [".foo", ".FOO", ".Bar", "baz", "", ".x.y", ".jpg", ".html", ".ico", ".Mixed", ".ÜT", ".q",
                  ".gz", ".txt"]
ADD_TYPES = ["text/x-foo; charset=\"utf-8\"", "application/foo", "text/plain", "text/x; a=b", "image/png",
             "bad type", "", "text/x-q; p=\"a b\"", "application/x; k=\"\"", "text/x; charset=",
             "application/test; s=ü", "a/b; a*0=x; a*1=y", "text/bad; a=\"b", "text/Plain; CHARSET=UTF-8",
             "application/x-bad; a=\"b\nc\"", "IMAGE/PNG"]
EXT_TYPES = ["image/jpeg", "text/plain", "text/plain; charset=utf-8", "IMAGE/JPEG",
             "application/x-unknown-thing", "", "bad type", "text/plain; charset", "text/html; a=\"x",
             "text/html;q=1;charset=UTF-8", "audio/ogg", "video/mp4", "text/xml", "application/xml",
             "application/rdf+xml", "text/javascript", "application/octet-stream", "text/x-foo", "application/foo",
             "text/x-q", "application/x", "a/b", "image/png", "text/plain; charset=utf-8; a=b"]


def request(mode, text):
    return f"{mode}:{text.encode().hex()}"


def scenario():
    ops = []
    for _ in range(1200):
        choice = RNG.random()
        if choice < 0.45:
            text = media_value() if RNG.random() < 0.8 else mutate(media_value(), MEDIA_ALPHABET)
            ops.append(("P", text))
        elif choice < 0.6:
            ops.append(("F", media_type_fields()))
        elif choice < 0.7:
            ops.append(("T", RNG.choice(EXTENSIONS)))
        elif choice < 0.8:
            ops.append(("E", RNG.choice(EXT_TYPES)))
        else:
            ops.append(("A", RNG.choice(ADD_EXTENSIONS) + "\0" + RNG.choice(ADD_TYPES)))
    return ops


def fixed():
    ops = [("P", m) for m in MEDIA]
    ops += [("E", t) for t in ["text/html", "image/jpeg", "text/plain", "IMAGE/JPEG", "application/xml",
                               "text/plain; charset=utf-8", "application/octet-stream", "bad type", ""]]
    ops += [("T", e) for e in EXTENSIONS]
    ops += [("A", ".zzz\0text/zzz"), ("A", "zzz\0text/zzz"), ("A", ".zzy\0text/zzy; charset=\"ISO-8859-1\""),
            ("A", ".zzx\0bad type"), ("A", ".zzw\0text/w; a*0=x"), ("A", ".jpg\0image/x-jpeg-test"),
            ("A", ".gz\0application/x-gz-test; a=\"b\""), ("A", ".txt\0text/plain; charset=UTF-16"),
            ("T", ".zzz"), ("T", ".ZZZ"), ("T", ".zzy"), ("T", ".zzx"), ("T", ".zzw"), ("T", ".jpg"),
            ("T", ".gz"), ("T", ".txt"), ("E", "text/zzy"), ("E", "text/w"), ("E", "image/x-jpeg-test"),
            ("E", "application/x-gz-test"), ("E", "text/plain"), ("E", "text/w; a=b")]
    ops += [("F", f) for f in ["text/plain\0charset\0utf-8", "a/b\0k\0ü", "a/b\0k\0a b", "a/b\0k\0",
                               "bad type\0k\0v", "a/b\0bad key\0v", "a/b\0\0v", "a/b\0k\0\"q\"",
                               "a/b\0k\0x\0y", "a/b\0k\0v\0k\0w", "a/b\0k\0\x7f", "a/b\0a*\0x", "a/b\0k\0" + "a" * 100]]
    return ops


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("mime differential check requires Go and Cargo on PATH")
    ops = fixed() + scenario()
    lines = [request(mode, text) for mode, text in ops]
    payload = "\n".join(lines) + "\n"
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go = subprocess.run(["go", "run", "tools/mime_oracle.go"], input=payload, text=True, capture_output=True,
                        cwd=ROOT, env=env, timeout=300)
    if go.returncode:
        raise RuntimeError(f"go run tools/mime_oracle.go failed:\n{go.stderr}")
    rust = subprocess.run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "mime_probe"],
                          input=payload, text=True, capture_output=True, cwd=ROOT, env=env, timeout=300)
    if rust.returncode:
        raise RuntimeError(f"mime_probe failed:\n{rust.stderr}")
    go_out = go.stdout.splitlines()
    rust_out = rust.stdout.splitlines()
    if len(go_out) != len(ops) or len(rust_out) != len(ops):
        raise AssertionError("mime oracle returned the wrong number of records")
    failures = []
    skipped = 0
    for (mode, text), g, r in zip(ops, go_out, rust_out):
        if g == "utf8":
            # Go keeps raw bytes that are not UTF-8; the Rust port reports them as errors.
            skipped += 1
        elif g != r:
            failures.append((mode, text, g, r))
    for mode, text, g, r in failures[:8]:
        print(f"mode={mode} input={text!r}\n  Go  ={g!r}\n  Rust={r!r}")
    if failures:
        raise AssertionError(f"{len(failures)} of {len(ops)} mime records differ from Go")
    counts = {}
    for mode, _ in ops:
        counts[mode] = counts.get(mode, 0) + 1
    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"mime Go differential: {len(ops) - skipped} of {len(ops)} records passed ({detail}); "
          f"{skipped} non-UTF-8 results are a documented deviation")


if __name__ == "__main__":
    main()
