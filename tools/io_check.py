#!/usr/bin/env python3
"""Differentially check rust_stdlib::{io, io::fs, bufio} against Go.

Requests are tab-separated lines (byte strings are hex); tools/io_oracle.go
and examples/io_probe.rs print one result line per request and the lines are
compared exactly. The suites:

  bufio.Reader   scripted Peek/Discard/ReadSlice/ReadLine/ReadBytes/ReadRune/
                 UnreadRune/UnreadByte/Read/WriteTo over a chunked reader
  bufio.Writer   scripted writes into a short-writing, failing writer
  bufio.Scanner  every SplitFunc plus final-token, error and panic cases
  io             ReadAtLeast/ReadFull, Copy/CopyN/CopyBuffer, ReadAll,
                 LimitReader, MultiReader/Writer, TeeReader, SectionReader,
                 OffsetWriter and Pipe (writer thread, CloseWithError)
  io/fs          WalkDir, Glob, ValidPath, ReadDir, Stat, ReadFile, Sub and
                 FileMode formatting over generated trees (fstest.MapFS vs
                 rust_stdlib::io::fs::MapFS)
"""
import collections
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

PIECES = [b"a", b"b", b"x", b"\n", b"\n", b"\r\n", b"\r", b" ", b",", b"$", b"X", b"ab", b"\t",
          "é".encode(), "世".encode(), "😀".encode(), "\u0085".encode(), " ".encode(), "　".encode()]
INVALID = [b"\xff", b"\xc3", b"\xe4\xb8", b"\x80", b"\xf0\x9f"]


def data(rng, lo, hi, invalid=True):
    pool = PIECES + (INVALID if invalid else [])
    return b"".join(rng.choice(pool) for _ in range(rng.randrange(lo, hi + 1)))


def valid_utf8(b):
    try:
        b.decode()
        return True
    except UnicodeDecodeError:
        return False


def chunk_list(rng, hi=9):
    return ",".join(str(rng.randrange(1, hi + 1)) for _ in range(rng.randrange(1, 5)))


def err_at(rng, n):
    return str(rng.randrange(0, n + 2)) if rng.random() < 0.25 else "-1"


def bufio_reader(rng, out):
    for _ in range(1800):
        d = data(rng, 0, 110)
        size = rng.choice([1, 8, 15, 16, 16, 17, 20, 24, 32, 64, 4096])
        eff = max(size, 16)
        ops = []
        for _ in range(rng.randrange(1, 14)):
            k = rng.choice(["peek", "peek", "discard", "rs", "rl", "rl", "rb", "rstr", "rbyte", "rbyte", "ubyte",
                            "rrune", "rrune", "urune", "buffered", "size", "read", "read"])
            if k == "rstr" and (ops or not valid_utf8(d)):
                k = "rb"  # ReadString is compared only on valid UTF-8 from the start
            if k in ("peek", "discard"):
                ops.append(f"{k}:{rng.randrange(0, eff + 3)}")
            elif k in ("rs", "rb", "rstr"):
                ops.append(f"{k}:{rng.choice([b'\n', b'a', b',', b'x', b'\r']).hex()}")
            elif k == "read":
                ops.append(f"read:{rng.randrange(0, eff * 2 + 2)}")
            else:
                ops.append(k)
        if rng.random() < 0.15:
            ops.append("wto:" + "+".join(str(rng.randrange(1, 40)) for _ in range(rng.randrange(1, 4))))
        fail = rng.choice([-1, -1, -1, rng.randrange(0, 60)])
        out.append(("BR", "\t".join(["BR", d.hex(), chunk_list(rng), err_at(rng, len(d)), str(size), ";".join(ops), str(fail)])))
    # Long lines force ErrBufferFull / isPrefix handling, including "\r\n" at the seam.
    for n in range(1, 120):
        body = b"x" * n + rng.choice([b"\r\n", b"\n", b"\r", b""]) + b"tail\n"
        ops = ";".join(["rl"] * 5)
        out.append(("BR", "\t".join(["BR", body.hex(), "5,16,1", "-1", "16", ops, "-1"])))
        out.append(("BR", "\t".join(["BR", body.hex(), "3", "-1", "16", "rs:0a;rs:0a;rb:0a;rb:0a", "-1"])))


def bufio_writer(rng, out):
    for _ in range(1500):
        size = rng.choice([1, 2, 3, 4, 5, 8, 16, 100])
        ops = []
        for _ in range(rng.randrange(1, 14)):
            k = rng.choice(["w", "w", "w", "wb", "wr", "wr", "ws", "flush", "flush", "avail", "buffered", "size", "ab", "rf", "reset"])
            if k == "w":
                ops.append("w:" + data(rng, 0, 12).hex())
            elif k == "wb":
                ops.append("wb:" + bytes([rng.randrange(256)]).hex())
            elif k == "wr":
                ops.append("wr:" + str(rng.choice([0x41, 0x7f, 0x80, 0xe9, 0x7ff, 0x800, 0x4e16, 0xffff, 0x10000, 0x1f600, 0x10ffff, 0, 10])))
            elif k == "ws":
                ops.append("ws:" + data(rng, 0, 10, invalid=False).hex())
            elif k == "ab":
                ops.append("ab:" + data(rng, 0, 6).hex())
            elif k == "rf":
                ops.append("rf:" + data(rng, 0, 20).hex() + "+" + "+".join(str(rng.randrange(1, 9)) for _ in range(rng.randrange(1, 4))))
            else:
                ops.append(k)
        fail = rng.choice([-1, -1, rng.randrange(0, 50)])
        out.append(("BW", "\t".join(["BW", str(size), chunk_list(rng, 20), str(fail), ";".join(ops)])))


SPLITS = ["lines", "lines", "words", "runes", "bytes", "comma", "dollar", "dollarnil", "negadv", "toofar",
          "emptytok", "errsplit", "needmore"]


def bufio_scanner(rng, out):
    for _ in range(1800):
        d = data(rng, 0, 90)
        init = rng.choice([-1, -1, -1, 0, 1, 2, 3, 4, 8, 16, 100])
        mx = rng.choice([1, 2, 3, 4, 8, 16, 64, 1000])
        out.append(("SC", "\t".join(["SC", d.hex(), chunk_list(rng), err_at(rng, len(d)), rng.choice(SPLITS), str(init), str(mx)])))
    for name in ("lines", "needmore", "words", "bytes"):
        for n in (4095, 4096, 4097, 65535, 65536, 65537, 70000):
            body = (b"a" * n + b"\nb\n") if name != "words" else (b"a" * n + b" b ")
            out.append(("SC", "\t".join(["SC", body.hex(), "1000,7,4096", "-1", name, "-1", "0"])))
    for init, mx in ((0, 4), (4, 4), (5, 4), (0, 0), (1, 100000)):
        out.append(("SC", "\t".join(["SC", (b"abc\n" * 50).hex(), "6", "-1", "lines", str(init), str(mx)])))


def io_suite(rng, out):
    for _ in range(700):
        d = data(rng, 0, 14)
        out.append(("RAL", "\t".join(["RAL", d.hex(), chunk_list(rng, 6), err_at(rng, len(d)), str(rng.randrange(0, 13)),
                                      rng.choice(["full", str(rng.randrange(0, 13))])])))
    for _ in range(700):
        d = data(rng, 0, 60)
        mode = rng.choice(["copy", "copyn:" + str(rng.randrange(-1, 70)), "copybuf:" + str(rng.randrange(1, 9))])
        out.append(("CP", "\t".join(["CP", d.hex(), chunk_list(rng, 20), err_at(rng, len(d)), chunk_list(rng, 20),
                                     str(rng.choice([-1, -1, rng.randrange(0, 70)])), mode])))
    for _ in range(200):
        d = data(rng, 0, 600)
        out.append(("RALL", "\t".join(["RALL", d.hex(), chunk_list(rng, 300), err_at(rng, len(d))])))
    sizes = lambda: ",".join(str(rng.randrange(1, 8)) for _ in range(rng.randrange(1, 8)))
    for _ in range(400):
        d = data(rng, 0, 30)
        out.append(("LR", "\t".join(["LR", d.hex(), chunk_list(rng, 6), str(rng.randrange(-1, 35)), sizes()])))
    for _ in range(400):
        rs = ",".join(data(rng, 0, 8).hex() for _ in range(rng.randrange(1, 5)))
        out.append(("MR", "\t".join(["MR", rs, chunk_list(rng, 6), sizes()])))
    for _ in range(400):
        specs = ";".join(chunk_list(rng, 8).replace(",", "+") + "/" + str(rng.choice([-1, -1, rng.randrange(0, 25)]))
                         for _ in range(rng.randrange(1, 4)))
        writes = ",".join(data(rng, 0, 8).hex() for _ in range(rng.randrange(1, 5)))
        out.append(("MW", "\t".join(["MW", specs, writes])))
    for _ in range(400):
        d = data(rng, 0, 30)
        out.append(("TR", "\t".join(["TR", d.hex(), chunk_list(rng, 6), chunk_list(rng, 10),
                                     str(rng.choice([-1, -1, rng.randrange(0, 30)])), sizes()])))
    for _ in range(1000):
        d = data(rng, 0, 24)
        n = len(d)
        ops = []
        for _ in range(rng.randrange(1, 9)):
            k = rng.choice(["read", "read", "readat", "seek", "size", "outer"])
            if k == "read":
                ops.append(f"read:{rng.randrange(0, 8)}")
            elif k == "readat":
                ops.append(f"readat:{rng.randrange(0, 8)}@{rng.randrange(-2, n + 3)}")
            elif k == "seek":
                ops.append(f"seek:{rng.randrange(0, 4)}@{rng.randrange(-4, n + 3)}")
            else:
                ops.append(k)
        off, ln = rng.randrange(0, n + 3), rng.randrange(0, n + 4)
        out.append(("SR", "\t".join(["SR", d.hex(), str(off), str(ln), ";".join(ops)])))
    huge = str(2**63 - 1)
    for off, ln in ((huge, "5"), (str(2**63 - 3), "10"), ("2", huge), ("0", huge), (huge, huge)):
        out.append(("SR", "\t".join(["SR", b"hello world".hex(), off, ln, "read:3;readat:3@0;size;seek:1@2;read:4;seek:2@0;outer"])))
    for _ in range(500):
        ops = []
        for _ in range(rng.randrange(1, 9)):
            k = rng.choice(["write", "write", "writeat", "seek"])
            if k == "write":
                ops.append("write:" + data(rng, 0, 5).hex())
            elif k == "writeat":
                ops.append(f"writeat:{data(rng, 0, 5).hex()}@{rng.randrange(-2, 9)}")
            else:
                ops.append(f"seek:{rng.randrange(0, 4)}@{rng.randrange(-5, 9)}")
        out.append(("OW", "\t".join(["OW", str(rng.randrange(-3, 6)), ";".join(ops)])))
    for _ in range(250):
        writes = ",".join(data(rng, 0, 6).hex() for _ in range(rng.randrange(0, 5)))
        sizes_ = ",".join(str(rng.randrange(1, 6)) for _ in range(rng.randrange(0, 8)))
        out.append(("PIPE", "\t".join(["PIPE", writes, sizes_, rng.choice(["nil", "err"]),
                                       str(rng.choice([-1, -1, rng.randrange(0, 8)])), rng.choice(["nil", "err"])])))


NAMES = ["a", "b", "c", "ab", "d1", ".h", "é", "x-y", "a.b"]


def tree(rng):
    entries = {}
    dirs = set()
    for _ in range(rng.randrange(0, 13)):
        parts = [rng.choice(NAMES) for _ in range(rng.randrange(1, 4))]
        path = "/".join(parts)
        # A file may not also be a directory.
        prefixes = {"/".join(parts[:i]) for i in range(1, len(parts))}
        if path in dirs or any(p in entries for p in prefixes) or any(e.startswith(path + "/") for e in entries):
            continue
        entries[path] = data(rng, 0, 6)
        dirs |= prefixes
    explicit = []
    for _ in range(rng.randrange(0, 3)):
        parts = [rng.choice(NAMES) for _ in range(rng.randrange(1, 3))]
        path = "/".join(parts)
        prefixes = {"/".join(parts[:i]) for i in range(1, len(parts) + 1)}
        if any(p in entries for p in prefixes):
            continue
        explicit.append(path + "/")
        dirs |= prefixes
    enc = [f"{p}={d.hex()}" for p, d in entries.items()] + explicit
    rng.shuffle(enc)
    return ",".join(enc), sorted(entries), sorted(dirs)


def fs_suite(rng, out):
    seg = ["*", "?", "a", "b", "[a-c]", "[^a]", "*b", "a*", "**", "\\a", "[", "[a-", "x", "é", "?b", "[a]*", "d1", ".h", ".", "..", ""]
    for _ in range(900):
        t, files, dirs = tree(rng)
        known = files + dirs + ["."]
        roots = [".", ".", rng.choice(known), "nope", "a//b", ".."]
        rules = []
        for _ in range(rng.randrange(0, 3)):
            p = rng.choice(known)
            rules.append(f"{rng.choice(['skipdir', 'skipdir', 'skipall', 'err'])}:{p}")
        out.append(("WALK", "\t".join(["WALK", t, rng.choice(roots), ";".join(rules)])))
        pat = "/".join(rng.choice(seg) for _ in range(rng.randrange(1, 4)))
        out.append(("GLOB", "\t".join(["GLOB", t, pat])))
        if rng.random() < 0.5:
            out.append(("GLOB", "\t".join(["GLOB", t, rng.choice(known)])))
        d = rng.choice(dirs + ["."] + ["nope", "a/", "/a", ".."])
        out.append(("RDIR", "\t".join(["RDIR", t, d])))
        name = rng.choice(known + ["nope", "", "a/", "/a", "a//b", "../a", "a/."])
        out.append(("STAT", "\t".join(["STAT", t, name])))
        sub = rng.choice(dirs + ["nope", "."] + ["..", "a//b"])
        sops = []
        for _ in range(rng.randrange(1, 5)):
            k = rng.choice(["readfile", "readdir", "stat", "glob", "sub"])
            arg = rng.choice(["."] + [f.split("/", 1)[-1] for f in files + dirs] + ["nope", "../a", "*", "*/*", "[", "?"])
            sops.append(f"{k}:{arg}")
        out.append(("SUBO", "\t".join(["SUBO", t, sub, ";".join(sops)])))
    for _ in range(600):
        s = "".join(rng.choice(["a", "b", ".", "..", "", "/", "/", "é", " ", "\x00"]) for _ in range(rng.randrange(0, 6)))
        out.append(("VALID", "\t".join(["VALID", s.encode().hex()])))
    for v in ["", ".", "..", "a", "a/b", "a/", "/a", "./a", "a/./b", "a/../b", "a//b", "a b", "é/世"]:
        out.append(("VALID", "\t".join(["VALID", v.encode().hex()])))
    modes = [0, 0o644, 0o777, 0o4755, 0o1777]
    for i in range(32):
        modes += [1 << i, (1 << i) | 0o640]
    modes += [rng.randrange(0, 2**32) for _ in range(300)]
    for m in modes:
        out.append(("FMODE", f"FMODE\t{m}"))


def run(cmd, payload, label):
    result = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if result.returncode:
        raise RuntimeError(f"{label} failed:\n{result.stderr[-4000:]}")
    return result.stdout.split("\n")[:-1]


def main():
    rng = random.Random(0x10F5)
    requests = []
    for suite in (bufio_reader, bufio_writer, bufio_scanner, io_suite, fs_suite):
        suite(rng, requests)
    payload = "".join(line + "\n" for _, line in requests)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "io_probe"], payload, "Rust io probe")
    go = run(["go", "run", str(ROOT / "tools/io_oracle.go")], payload, "Go io oracle")
    if len(rust) != len(requests) or len(go) != len(requests):
        raise AssertionError(f"wrong record count: requests={len(requests)} rust={len(rust)} go={len(go)}")
    for i, ((kind, line), a, b) in enumerate(zip(requests, rust, go)):
        if a != b:
            raise AssertionError(f"vector {i} ({kind})\nrequest={line!r}\nRust={a!r}\nGo  ={b!r}")
    counts = collections.Counter(kind for kind, _ in requests)
    summary = ", ".join(f"{k} {v}" for k, v in sorted(counts.items()))
    print(f"io/bufio/fs Go differential: {len(requests)} vectors passed ({summary})")


if __name__ == "__main__":
    sys.exit(main())
