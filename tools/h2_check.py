#!/usr/bin/env python3
"""Differentially check the HTTP/2 codecs (HPACK, frames) against Go.

Go's hpack and internal http2 packages cannot be imported, so their sources are
copied into a scratch module (import paths rewritten) next to tools/h2_oracle.go
and tools/h2_frame_oracle.go. The Rust side is examples/h2_probe. Both read one
request per line and must print identical answers.
"""
import os
import pathlib
import random
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
GOENV = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOFLAGS="-mod=mod")
STATIC_NAMES = [
    ":authority", ":method", ":path", ":scheme", ":status", "accept-charset", "accept-encoding",
    "accept-language", "accept-ranges", "accept", "access-control-allow-origin", "age", "allow",
    "authorization", "cache-control", "content-disposition", "content-encoding", "content-language",
    "content-length", "content-location", "content-range", "content-type", "cookie", "date", "etag",
    "expect", "expires", "from", "host", "if-match", "if-modified-since", "if-none-match", "if-range",
    "if-unmodified-since", "last-modified", "link", "location", "max-forwards", "proxy-authenticate",
    "proxy-authorization", "range", "referer", "refresh", "retry-after", "server", "set-cookie",
    "strict-transport-security", "transfer-encoding", "user-agent", "vary", "via", "www-authenticate",
]
STATIC_VALUES = ["GET", "POST", "/", "/index.html", "http", "https", "200", "204", "206", "304", "400",
                 "404", "500", "gzip, deflate", "", "text/html", "no-cache", "max-age=0"]


def goroot():
    return subprocess.check_output(["go", "env", "GOROOT"], text=True, env=GOENV).strip()


def build_oracle(work):
    """Copy Go's sources into a scratch module and build the oracle binary."""
    src = pathlib.Path(goroot()) / "src"
    mod = pathlib.Path(work) / "mod"
    mod.mkdir()
    (mod / "go.mod").write_text("module h2oracle\n\ngo 1.24\n")

    def copy_pkg(from_dir, to_name, skip=(), rewrites=()):
        dest = mod / to_name
        dest.mkdir(parents=True, exist_ok=True)
        for f in sorted(pathlib.Path(from_dir).glob("*.go")):
            if f.name.endswith("_test.go") or f.name in skip:
                continue
            text = f.read_text()
            for old, new in (
                ("golang.org/x/net/http2/hpack", "h2oracle/hpack"),
                ("net/http/internal/httpsfv", "h2oracle/httpsfv"),
                ("golang.org/x/net/http/httpguts", "h2oracle/httpguts"),
                ("net/http/internal/ascii", "h2oracle/ascii"),
            ) + tuple(rewrites):
                text = text.replace(f'"{old}"', f'"{new}"')
            (dest / f.name).write_text(text)

    copy_pkg(src / "vendor/golang.org/x/net/http2/hpack", "hpack")
    copy_pkg(src / "net/http/internal/httpsfv", "httpsfv")
    copy_pkg(src / "net/http/internal/ascii", "ascii")
    # httpguts without idna: only the token/field validators the framer needs.
    copy_pkg(src / "vendor/golang.org/x/net/http/httpguts", "httpguts", skip=("guts.go",))
    gts = mod / "httpguts" / "httplex.go"
    text = gts.read_text()
    text = text.replace('\t"golang.org/x/net/idna"\n', "").replace('\t"net"\n', "")
    text = re.sub(r"func PunycodeHostPort.*?\n}\n", "", text, flags=re.S)
    gts.write_text(text)
    http2_files = ["frame.go", "errors.go", "http2.go", "gotrack.go"]
    h2dest = mod / "http2"
    h2dest.mkdir()
    for name in http2_files:
        p = src / "net/http/internal/http2" / name
        if p.exists():
            text = p.read_text()
            for old, new in (
                ("golang.org/x/net/http2/hpack", "h2oracle/hpack"),
                ("net/http/internal/httpsfv", "h2oracle/httpsfv"),
                ("golang.org/x/net/http/httpguts", "h2oracle/httpguts"),
                ("net/http/internal/ascii", "h2oracle/ascii"),
            ):
                text = text.replace(f'"{old}"', f'"{new}"')
            (h2dest / name).write_text(text)
    shutil.copy(ROOT / "tools/h2_export_oracle.go.txt", h2dest / "export_oracle.go")
    for name in ("h2_oracle.go", "h2_frame_oracle.go"):
        shutil.copy(ROOT / "tools" / name, mod / name.replace("h2_oracle", "main").replace("h2_frame_oracle", "frames"))
    out = pathlib.Path(work) / "oracle"
    r = subprocess.run(["go", "build", "-o", str(out), "."], cwd=mod, env=GOENV, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError("building the Go oracle failed:\n" + r.stderr)
    return out


def run_lines(cmd, requests, cwd=None):
    payload = "".join(r + "\n" for r in requests)
    r = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=cwd, env=GOENV)
    if r.returncode:
        raise RuntimeError(f"{cmd[0]} failed:\n{r.stderr[-3000:]}")
    lines = r.stdout.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) != len(requests):
        raise AssertionError(f"{cmd[0]}: {len(lines)} answers for {len(requests)} requests")
    return lines


class Harness:
    def __init__(self, work):
        self.oracle = build_oracle(work)
        r = subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "h2_probe"],
                           cwd=ROOT, capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError("building h2_probe failed:\n" + r.stderr[-3000:])
        self.probe = ROOT / "target/debug/examples/h2_probe"
        self.count = 0

    def compare(self, label, requests):
        go = run_lines([str(self.oracle)], requests)
        rust = run_lines([str(self.probe)], requests)
        for i, (g, r) in enumerate(zip(go, rust)):
            if g != r:
                raise AssertionError(f"{label} vector {i}: request={requests[i][:400]!r}\nGo  ={g[:600]!r}\nRust={r[:600]!r}")
        self.count += len(requests)
        if os.environ.get("H2_STATS"):
            for token in ("META", "trunc=1", "E:connection error", "E:stream error", "E:EOF", "E:unexpected EOF",
                          "frame too large", "err:", "SETTINGS", "PU ", "PUSH", "UNKNOWN", "HTTP/1.1 header"):
                n = sum(token in line for line in go)
                if n:
                    print(f"  {label}: {token!r} in {n} answers")
        return go


def hx(b):
    return b.hex()


def rand_bytes(rng, n, high=True):
    return bytes(rng.randrange(256 if high else 128) for _ in range(n))


def rand_name(rng):
    k = rng.random()
    if k < 0.5:
        return rng.choice(STATIC_NAMES).encode()
    if k < 0.8:
        return ("x-h%d" % rng.randrange(12)).encode()
    if k < 0.9:
        return bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz-") for _ in range(rng.randrange(1, 40)))
    return rand_bytes(rng, rng.randrange(0, 12))


def rand_value(rng):
    k = rng.random()
    if k < 0.3:
        return rng.choice(STATIC_VALUES).encode()
    if k < 0.45:
        return ("v%d" % rng.randrange(6)).encode()
    if k < 0.7:
        return bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789=;/.,:- ") for _ in range(rng.randrange(0, 60)))
    if k < 0.8:
        return bytes(rng.choice(b"abcdefghij") for _ in range(rng.randrange(200, 700)))
    return rand_bytes(rng, rng.randrange(0, 40))


def gen_ops(rng):
    blocks = []
    for _ in range(rng.randrange(1, 6)):
        ops = []
        if rng.random() < 0.25:
            ops.append("t%d" % rng.choice([0, 1, 31, 32, 64, 100, 256, 1000, 4096, 4097, 100000]))
            if rng.random() < 0.4:
                ops.append("t%d" % rng.choice([0, 50, 4096, 100]))
        if rng.random() < 0.08:
            ops.append("l%d" % rng.choice([0, 64, 512, 4096, 10000]))
        for _ in range(rng.randrange(0, 12)):
            sens = 1 if rng.random() < 0.12 else 0
            ops.append("f%s/%s/%d" % (hx(rand_name(rng)), hx(rand_value(rng)), sens))
        blocks.append(",".join(ops))
    return ";".join(blocks)


def mutate(rng, b):
    b = bytearray(b)
    k = rng.random()
    if not b:
        return bytes(b)
    if k < 0.3:
        return bytes(b[:rng.randrange(len(b))])
    if k < 0.7:
        for _ in range(rng.randrange(1, 4)):
            b[rng.randrange(len(b))] ^= 1 << rng.randrange(8)
        return bytes(b)
    if k < 0.85:
        i = rng.randrange(len(b))
        b[i:i] = rand_bytes(rng, rng.randrange(1, 5))
        return bytes(b)
    return bytes(b) + rand_bytes(rng, rng.randrange(1, 6))


def hpack(h, rng):
    enc = [("E:" + gen_ops(rng)) for _ in range(2500)]
    enc_out = h.compare("hpack-encode", enc)
    # Decode what Go encoded: whole sequences, sizes that admit and refuse its table updates.
    dec = []
    blocks = []
    for out in enc_out:
        bs = out.split(";")
        blocks.append(bs)
        dec.append("D4096,0:" + out)
        dec.append("D%d,0:%s" % (rng.choice([0, 256, 4096, 65536]), out))
        dec.append("D4096,%d:%s" % (rng.choice([5, 20, 100, 800]), out))
        raw = [bytes.fromhex(x) for x in bs]
        if raw and raw[0]:
            m = [hx(mutate(rng, r)) for r in raw]
            dec.append("D4096,0:" + ";".join(m))
            dec.append("D4096,%d:%s" % (rng.choice([0, 30]), ";".join(m)))
        i = rng.randrange(len(raw))
        for split in (1, rng.randrange(0, len(raw[i]) + 2)):
            dec.append("P4096,0,1:%d:%s" % (split, hx(raw[i])))
            dec.append("P4096,0,0:%d:%s" % (split, hx(raw[i])))
            dec.append("P4096,40,1:%d:%s" % (split, hx(mutate(rng, raw[i]))))
    for _ in range(1500):
        dec.append("D4096,0:" + hx(rand_bytes(rng, rng.randrange(1, 30))))
    h.compare("hpack-decode", dec)
    huff = []
    for _ in range(2000):
        s = rand_value(rng) if rng.random() < 0.7 else rand_bytes(rng, rng.randrange(0, 20))
        huff.append("J:" + hx(s))
    outs = h.compare("huffman-encode", huff)
    hd = []
    for line in outs:
        enc_hex = line.split(" ")[0]
        hd.append("H:" + enc_hex)
        raw = bytes.fromhex(enc_hex)
        for _ in range(2):
            hd.append("H:" + hx(mutate(rng, raw)))
    for _ in range(1500):
        hd.append("H:" + hx(rand_bytes(rng, rng.randrange(0, 12))))
    for n in range(0, 5):
        for pad in range(0, 256):
            hd.append("H:" + hx(bytes([pad] * n)))
    h.compare("huffman-decode", hd)


def main():
    seed = int(os.environ.get("H2_SEED", "0x48325"), 0)
    rng = random.Random(seed)
    with tempfile.TemporaryDirectory(prefix="h2check-") as work:
        h = Harness(work)
        hpack(h, rng)
        from h2_frame_vectors import frames
        frames(h, rng)
        print(f"HTTP/2 Go differential: {h.count} vectors passed")


if __name__ == "__main__":
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    main()
