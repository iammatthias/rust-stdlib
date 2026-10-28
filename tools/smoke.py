#!/usr/bin/env python3
"""Exercise compiled examples with Python and Go standard-library HTTP clients."""
import http.client
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

def gohttp():
    """The Go-shaped net/http server and client against Python and Go."""
    extension = ".exe" if os.name == "nt" else ""
    server = ROOT / "target/debug/examples" / ("http_server" + extension)
    client = ROOT / "target/debug/examples" / ("http_client" + extension)
    for executable in [server, client]:
        if not executable.is_file():
            raise RuntimeError(f"Missing built example: {executable}; run cargo build --offline --locked --examples")
    with tempfile.TemporaryDirectory() as docroot:
        Path(docroot, "a.txt").write_text("hello rust files\n")
        process = subprocess.Popen([str(server), "127.0.0.1:0", docroot], cwd=ROOT, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            line = process.stdout.readline()
            assert line.startswith("listening "), line
            address = line.split()[1]
            host, port = address.rsplit(":", 1)

            def request(method, path, body=None, headers=None, version=None):
                conn = http.client.HTTPConnection(host, int(port), timeout=5)
                try:
                    if version == 10:
                        conn._http_vsn, conn._http_vsn_str = 10, "HTTP/1.0"
                    conn.request(method, path, body=body, headers=headers or {})
                    response = conn.getresponse()
                    return response.status, dict(response.getheaders()), response.read()
                finally:
                    conn.close()

            assert request("GET", "/hello/python")[2] == b"Hello, python.\n"
            status, headers, _ = request("POST", "/hello/python")
            assert status == 405 and headers["Allow"] == "GET, HEAD", (status, headers)
            assert request("GET", "/files/a.txt", headers={"Range": "bytes=0-4"})[2] == b"hello"
            assert request("GET", "/files/a.txt", headers={"Range": "bytes=0-4"})[0] == 206
            assert request("HEAD", "/files/a.txt")[2] == b""
            assert request("GET", "/files/a.txt", version=10)[2] == b"hello rust files\n"
            assert request("GET", "/files/index.html")[0] in (301, 404)
            status, headers, body = request("POST", "/echo", "x" * 5000, {"Content-Type": "text/plain"})
            assert status == 200 and body == b"x" * 5000
            print("8 Python/Rust Go-shaped HTTP smoke cases passed")
            environment = os.environ.copy()
            environment.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
            subprocess.run(["go", "run", "tools/gohttp_interop.go", f"http://{address}", str(client)],
                           cwd=ROOT, env=environment, check=True, timeout=120)
        finally:
            if process.poll() is None:
                try:
                    process.stdin.write("\n")
                    process.stdin.flush()
                    process.wait(timeout=10)
                except (OSError, subprocess.TimeoutExpired):
                    process.kill()
                    process.wait(timeout=5)
            for stream in [process.stdin, process.stdout, process.stderr]:
                stream.close()
        if process.returncode != 0:
            raise RuntimeError(f"http_server exit status {process.returncode}")


if __name__ == "__main__":
    try:
        gohttp()
    except Exception as error:
        print(f"HTTP interoperability failed: {error}", file=sys.stderr)
        sys.exit(1)
