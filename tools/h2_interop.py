#!/usr/bin/env python3
"""HTTP/2 interoperability between this library and Go's net/http.

Go client against the Rust server and Rust client against the Go server, each
over h2c (prior knowledge) and over TLS with ALPN (the test certificates of
backends/tls). Every scenario (bodies, trailers, concurrent streams, flow
control with large bodies, RST_STREAM, GOAWAY, server push refusal...) must
print `ok`.
"""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "backends/tls/tests/fixtures"
ENV = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")


def build():
    for manifest, examples in ((None, ["h2_interop_server", "h2_interop_client"]),
                               ("backends/tls/Cargo.toml", ["h2_interop_server", "h2_interop_client"])):
        for example in examples:
            cmd = ["cargo", "build", "--quiet", "--offline", "--locked", "--example", example]
            if manifest:
                cmd += ["--manifest-path", manifest]
            subprocess.run(cmd, cwd=ROOT, check=True)
    for tool in ("h2_interop_client", "h2_interop_server"):
        subprocess.run(["go", "build", "-o", str(ROOT / f"target/{tool}_go"), f"tools/{tool}.go"],
                       cwd=ROOT, check=True, env=ENV)


def example(manifest, name):
    base = ROOT / ("backends/tls/target" if manifest else "target")
    return str(base / "debug/examples" / name)


def start_server(cmd):
    proc = subprocess.Popen(cmd, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=ENV)
    line = proc.stdout.readline().strip()
    if not line.startswith("listening "):
        proc.kill()
        raise RuntimeError(f"server {cmd[0]} said {line!r}")
    return proc, line.split(" ", 1)[1]


def stop_server(proc):
    try:
        proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_client(cmd, label):
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=300, env=ENV)
    ok = [l for l in r.stdout.splitlines() if l.startswith("ok ")]
    bad = [l for l in r.stdout.splitlines() if l.startswith("FAIL ")]
    if r.returncode or bad or not ok:
        print(r.stdout)
        print(r.stderr[-3000:])
        raise AssertionError(f"{label}: {len(bad)} scenarios failed")
    print(f"  {label}: {len(ok)} scenarios ok")
    return len(ok)


def main():
    build()
    total = 0
    print("Go client -> Rust server")
    proc, addr = start_server([example(None, "h2_interop_server"), "127.0.0.1:0"])
    try:
        total += run_client([str(ROOT / "target/h2_interop_client_go"), "h2c", addr], "h2c")
    finally:
        stop_server(proc)
    proc, addr = start_server([example("backends/tls/Cargo.toml", "h2_interop_server"), "127.0.0.1:0"])
    try:
        total += run_client([str(ROOT / "target/h2_interop_client_go"), "tls", addr, str(FIXTURES / "ca.hex")], "tls")
    finally:
        stop_server(proc)
    print("Rust client -> Go server")
    proc, addr = start_server([str(ROOT / "target/h2_interop_server_go"), "h2c", "127.0.0.1:0"])
    try:
        total += run_client([example(None, "h2_interop_client"), addr], "h2c")
    finally:
        stop_server(proc)
    proc, addr = start_server([str(ROOT / "target/h2_interop_server_go"), "tls", "127.0.0.1:0",
                               str(FIXTURES / "server.hex"), str(FIXTURES / "server-key.hex")])
    try:
        total += run_client([example("backends/tls/Cargo.toml", "h2_interop_client"), addr,
                             str(FIXTURES / "ca.hex")], "tls")
    finally:
        stop_server(proc)
    print(f"HTTP/2 interop: {total} scenario runs passed")


if __name__ == "__main__":
    main()
