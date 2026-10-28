#!/usr/bin/env python3
"""Differentially check net/http/pprof against Go.

Cmdline (arguments after the program name), Index (the HTML page, with the
rows and descriptions of Go's runtime profiles removed from Go's output because
Rust has no runtime to profile), Symbol (GET queries and POST bodies, including
unparsable counters and a word that overflows the reader's buffer) and Handler
for names no runtime knows (404 "Unknown profile" and the `seconds` and `debug`
parameter errors Go reports for them) must agree byte for byte. Go's runtime
profiles, CPU profile and trace are the documented deviation and are not
compared (they would also sleep for the sampling duration).
"""
import os
import pathlib
import random
import re
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
RUNTIME = ["allocs", "block", "goroutine", "goroutineleak", "heap", "mutex", "threadcreate"]


def hx(s):
    if isinstance(s, str):
        s = s.encode()
    return s.hex() if s else "-"


class Lines:
    def __init__(self, command):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                        bufsize=1, cwd=ROOT)

    def ask(self, line):
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()
        out = self.process.stdout.readline()
        if not out:
            raise RuntimeError(f"probe died on: {line[:200]}")
        return out.rstrip("\n")

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=10)


def fields(out):
    parts = dict(tok.split("=", 1) for tok in out.split(" "))
    return parts["code"], parts["hdr"], bytes.fromhex(parts.get("body", ""))


def strip_runtime(body):
    text = body.decode()
    for name in RUNTIME:
        text = re.sub(r"<tr><td>\d+</td><td><a href='%s\?debug=1'>%s</a></td></tr>\n" % (name, name), "", text)
        text = re.sub(r"<li><div class=profile-name>%s: </div> [^\n]*</li>\n" % name, "", text)
    return text.encode()


def normalize(kind, out):
    code, hdr, body = fields(out)
    if kind == "index":
        body = strip_runtime(body)
    if kind == "cmdline":
        body = body.split(b"\0", 1)[1] if b"\0" in body else b""
    return code, hdr, body


def request(rng):
    kind = rng.choice(["cmdline", "index", "symbol", "symbol", "handler"])
    if kind == "cmdline":
        return kind, f"P cmdline GET {hx('/debug/pprof/cmdline')} -"
    if kind == "index":
        path = rng.choice(["/debug/pprof/", "/debug/pprof/", "/debug/pprof/foo", "/debug/pprof/cmdline/x", "/debug/pprof", "/other",
                           "/debug/pprof/unknown?debug=1", "/debug/pprof/x%20y", "/debug/pprof/?debug=1", "/debug/pprof/a%00b"])
        return kind, f"P index GET {hx(path)} -"
    if kind == "symbol":
        words = [rng.choice(["0x1234", "1", "0", "abc", "", "0xffffffffffffffff", "99999999999999999999", "0b101", "1_000", "-5", "0x"]) for _ in range(rng.randrange(0, 5))]
        text = "+".join(words)
        if rng.random() < 0.05:
            text = "a" * rng.choice([4095, 4096, 4097, 9000]) + rng.choice(["", "+0x10"])
        if rng.random() < 0.5:
            return kind, f"P symbol GET {hx('/debug/pprof/symbol?' + text)} -"
        return kind, f"P symbol POST {hx('/debug/pprof/symbol')} {hx(text)}"
    name = rng.choice(["nosuch", "custom", "x%20y", "", "Heap", "goroutine2", "profile"])
    query = rng.choice(["", "?debug=1", "?seconds=5", "?seconds=0", "?seconds=x", "?debug=2&seconds=3", "?gc=1"])
    return kind, f"P handler:{name} GET {hx('/debug/pprof/' + name + query)} -"


def main():
    started = time.monotonic()
    rng = random.Random(0x50505246)
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "pprof_probe"], cwd=ROOT, check=True)
    rust_bin = str(TARGET / "debug/examples" / ("pprof_probe.exe" if os.name == "nt" else "pprof_probe"))
    with tempfile.TemporaryDirectory() as tmp:
        go_bin = os.path.join(tmp, "pprof_oracle")
        subprocess.run(["go", "build", "-o", go_bin, str(ROOT / "tools/pprof_oracle.go")], cwd=ROOT, check=True)
        go, rust = Lines([go_bin, "-x", "arg two"]), Lines([rust_bin, "-x", "arg two"])
        count = 0
        try:
            for _ in range(1500):
                kind, line = request(rng)
                g, r = go.ask(line), rust.ask(line)
                if g.startswith("panic"):
                    continue
                if normalize(kind, g) != normalize(kind, r):
                    raise AssertionError(f"{line}\nGo  ={g[:600]}\nRust={r[:600]}")
                count += 1
        finally:
            go.close()
            rust.close()
    print(f"pprof Go differential: {count} Cmdline/Index/Symbol/Handler requests passed in {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
