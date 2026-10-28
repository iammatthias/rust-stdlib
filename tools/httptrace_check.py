#!/usr/bin/env python3
"""Differentially check net/http/httptrace against Go.

A scripted HTTP/1.1 server answers sequences of client requests (plain and
chunked bodies, Expect: 100-continue with and without a 100 reply, 1xx
informational responses, no-body statuses, Connection: close, resets of the
connection) first for Go's Transport and then for the Rust Transport, each with
a ClientTrace recording every hook. Per request the traced events (grouped as
the connection phase, the write loop and the read loop, which race in Go),
the result and the bytes the server received must be identical.

The h2c scenarios run the same comparison over cleartext HTTP/2 with prior
knowledge (Protocols.UnencryptedHTTP2): both Transports talk to a Go HTTP/2
server (tools/httptrace_h2c_server.go) that answers by the X-Mode header
(plain, empty, 204, 404, 70000 bytes, 1xx informational responses, a reset
stream, a HEAD-style response) and, with X-Read, reads the request body so a
request with Expect: 100-continue gets its "100 Continue". Go's HTTP/2
transport fires WroteHeaders, Wait100Continue, WroteRequest,
GotFirstResponseByte, Got100Continue and Got1xxResponse (and
WroteHeaderField, once per HPACK field with lower-cased names and the
pseudo-headers); the traced events must be identical.
"""
import os
import pathlib
import random
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))


class Server(threading.Thread):
    """Plays one script spec per request, across connections."""

    def __init__(self, specs):
        super().__init__(daemon=True)
        self.specs = list(specs)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.3)
        self.port = self.listener.getsockname()[1]
        self.received = []
        self.stop = False
        self.lock = threading.Lock()
        self.conns = 0

    def next_spec(self):
        with self.lock:
            return self.specs.pop(0) if self.specs else None

    def run(self):
        threads = []
        while not self.stop:
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.conns += 1
            t = threading.Thread(target=self.serve, args=(conn, self.conns), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=2)

    def recv(self, conn):
        """Blocks until data, EOF or shutdown. The server never gives up on an
        idle or slow connection itself: a client stalled by machine load (for
        longer than any fixed timeout) would otherwise find its connection
        closed, and see a reset, on one side only."""
        while True:
            try:
                return conn.recv(65536)
            except socket.timeout:
                if self.stop:
                    raise

    def read_head(self, conn, buf):
        while b"\r\n\r\n" not in buf:
            chunk = self.recv(conn)
            if not chunk:
                return None, buf
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        return head, rest

    def serve(self, conn, number):
        conn.settimeout(0.5)
        buf = b""
        try:
            while True:
                head, buf = self.read_head(conn, buf)
                if head is None:
                    return
                lines = head.split(b"\r\n")
                headers = {}
                for line in lines[1:]:
                    k, _, v = line.partition(b":")
                    headers[k.strip().lower()] = v.strip()
                spec = self.next_spec()
                if spec is None:
                    return
                body = b""
                if headers.get(b"expect", b"").lower() == b"100-continue" and spec.get("cont"):
                    conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                if b"content-length" in headers:
                    n = int(headers[b"content-length"])
                    while len(buf) < n:
                        chunk = self.recv(conn)
                        if not chunk:
                            break
                        buf += chunk
                    body, buf = buf[:n], buf[n:]
                elif headers.get(b"transfer-encoding", b"").lower() == b"chunked":
                    while b"\r\n0\r\n\r\n" not in b"\r\n" + buf and not buf.startswith(b"0\r\n\r\n"):
                        chunk = self.recv(conn)
                        if not chunk:
                            break
                        buf += chunk
                    end = buf.find(b"0\r\n\r\n")
                    body, buf = buf[:end + 5], buf[end + 5:]
                self.received.append((number, head + b"\r\n\r\n" + body))
                for info in spec.get("info", []):
                    conn.sendall(info)
                if spec.get("reset"):
                    conn.close()
                    return
                conn.sendall(spec["final"])
                # The "head" response promises 11 body bytes it never sends
                # (right for HEAD, truncated for anything else). Closing right
                # away is what the client's body read ends on; an idle timeout
                # here would make the outcome depend on the machine's load.
                if spec.get("close") or (spec.get("truncated") and not lines[0].startswith(b"HEAD ")):
                    conn.close()
                    return
        except (socket.timeout, OSError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def response(status, body=b"", headers=(), reason=b"OK"):
    out = b"HTTP/1.1 %d %s\r\n" % (status, reason)
    for h in headers:
        out += h + b"\r\n"
    if not any(h.lower().startswith(b"content-length") or h.lower().startswith(b"transfer-encoding") for h in headers) \
            and status not in (204, 304) and not 100 <= status < 200:
        out += b"Content-Length: %d\r\n" % len(body)
    return out + b"\r\n" + body


INFOS = [
    b"HTTP/1.1 102 Processing\r\n\r\n",
    b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\nX-Hint: a\r\n\r\n",
    b"HTTP/1.1 199 Odd\r\nX-Odd: 1\r\n\r\n",
]


def spec_pool(rng):
    kind = rng.choice(["ok", "ok", "ok", "ok", "empty", "nocontent", "info", "close", "chunked", "notfound", "big", "reset", "head", "cont"])
    s = {"final": response(200, b"hello world", [b"Content-Type: text/plain"])}
    if kind == "empty":
        s["final"] = response(200, b"")
    elif kind == "nocontent":
        s["final"] = response(204, b"", reason=b"No Content")
    elif kind == "info":
        s["info"] = rng.sample(INFOS, rng.randrange(1, 3))
    elif kind == "close":
        s["final"] = response(200, b"bye", [b"Connection: close"])
        s["close"] = True
    elif kind == "chunked":
        s["final"] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
    elif kind == "notfound":
        s["final"] = response(404, b"nope", reason=b"Not Found")
    elif kind == "big":
        s["final"] = response(200, b"x" * 70000)
    elif kind == "reset":
        s["reset"] = True
    elif kind == "head":
        s["final"] = b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n"
        s["truncated"] = True
    elif kind == "cont":
        s["cont"] = True
        s["info"] = [b"HTTP/1.1 102 Processing\r\n\r\n"]
    if rng.random() < 0.3:
        s["cont"] = True
    return s


def hx(s):
    return s.encode().hex() if s else "-"


def request_spec(rng):
    method = rng.choice(["GET", "GET", "POST", "PUT", "HEAD", "DELETE"])
    path = rng.choice(["/", "/a", "/search?q=1&r=%20x", "/long/path/segment"])
    body = ""
    flags = []
    if method in ("POST", "PUT") and rng.random() < 0.8:
        body = rng.choice(["payload", "x" * 1500, "a=b&c=d", "ébody"])
        if rng.random() < 0.4:
            flags.append("chunked")
        if rng.random() < 0.4:
            flags.append("expect")
    if rng.random() < 0.15:
        flags.append("noread")
    headers = []
    for _ in range(rng.choice([0, 0, 1, 2, 3])):
        headers.append(hx(rng.choice(["X-Test:one", "Accept:text/html", "x-lower:  padded  ", "X-Multi:a", "Cookie:a=b", "X-Bad: has\nnewline"])))
    return ",".join([method, path, hx(body), "|".join(headers) or "-", "+".join(flags) or "-"])


class Probe:
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


def play(probe, specs, config, requests):
    server = Server(specs)
    server.start()
    result = probe.ask(f"T {server.port} {config} {requests}")
    # Every request was answered before the probe replied, so what the server
    # received is complete; its threads wind down on their own.
    server.stop = True
    # The two clients use different ports; the server-side transcript keeps
    # the order, connection numbers and bytes.
    import re
    result = re.sub(r"(127\.0\.0\.1|localhost|\[::1\]):\d+", "ADDR", result)
    return result, [(n, re.sub(rb"(127\.0\.0\.1|localhost):\d+", b"ADDR", raw)) for n, raw in server.received]


H2_HOOKS = ("WroteHeaderField", "WroteHeaders", "Wait100Continue", "WroteRequest", "GotFirstResponseByte",
            "Got100Continue", "Got1xxResponse")
H2C_MODES = ["ok", "ok", "ok", "ok", "empty", "nocontent", "notfound", "big", "info", "info", "reset", "head"]


def h2c_request(rng):
    f = request_spec(rng).split(",")
    flags = f[4]
    mode = rng.choice(H2C_MODES)
    if mode == "head":
        f[0] = "HEAD"
    hdrs = [] if f[3] == "-" else f[3].split("|")
    hdrs.append(hx("X-Mode:" + mode))
    # Reading the body is what makes Go's server answer Expect: 100-continue.
    if rng.random() < 0.7:
        hdrs.append(hx("X-Read:1"))
    f[3] = "|".join(hdrs)
    return ",".join(f)


def sort_header_fields(result):
    """Go ranges over the request's header map, so the order of the regular
    header fields differs from run to run; the pseudo-header fields come first
    and content-length, accept-encoding and user-agent last, in that order."""
    def fix(m):
        events = m.group(1).split("; ")
        fields = [e for e in events if e.startswith("WroteHeaderField ")]
        rest = [e for e in events if not e.startswith("WroteHeaderField ")]
        pseudo = [e for e in fields if e.startswith("WroteHeaderField :")]
        fields = [e for e in fields if e not in pseudo]
        tail = []
        while fields and fields[-1].split("=")[0].split(" ")[1] in ("content-length", "accept-encoding", "user-agent"):
            tail.insert(0, fields.pop())
        return "write[" + "; ".join(pseudo + sorted(fields) + tail + rest) + "]"
    return re.sub(r"write\[([^\]]*)\]", fix, result)


# An Expect: 100-continue request with X-Read gets its "100 Continue" from the
# server, which races ExpectContinueTimeout: a loaded machine can let the 300ms
# default fire first and drop Got100Continue on one side only. Without X-Read
# the server never replies, so the timeout fires whatever its length. A long
# timeout (set identically on both clients) therefore removes the race and
# only costs time for the never-answered requests.
H2C_CONFIG = "h2c,ect=3000"


def play_h2c(probe, server_bin, requests):
    server = subprocess.Popen([server_bin], stdout=subprocess.PIPE, text=True, cwd=ROOT)
    lines = []
    try:
        first = server.stdout.readline()
        assert first.startswith("PORT "), first
        port = first.split()[1]
        reader = threading.Thread(target=lambda: lines.extend(server.stdout), daemon=True)
        reader.start()
        result = probe.ask(f"T {port} {H2C_CONFIG} {requests}")
        time.sleep(0.15)
    finally:
        server.kill()
        server.wait()
    reader.join(timeout=2)
    result = re.sub(r"(127\.0\.0\.1|localhost|\[::1\]):\d+", "ADDR", result)
    return sort_header_fields(result), [l.rstrip("\n") for l in lines]


# Go's HTTP/2 transport aborts the request body write when the response ends
# the stream before the body-writer goroutine has returned, even if every byte
# was sent, so WroteRequest reports "http2: aborting request body write" or nil
# depending on scheduling. Both clients show both outcomes under load, whatever
# the server waits for, so the two are compared as one value. Every other hook,
# result and server-side byte is still compared exactly.
BODY_WRITE_RACE = re.compile(r"WroteRequest (?:nil|http2: aborting request body write)\]")


def body_write_race(result):
    return BODY_WRITE_RACE.sub("WroteRequest nil-or-aborted]", result)


def check_h2c(rng, go, rust, server_bin):
    count = int(os.environ.get("HTTPTRACE_H2C_SCENARIOS", "60"))
    done = events = 0
    seen = set()
    for n in range(count):
        requests = ";".join(h2c_request(rng) for _ in range(rng.choice([1, 2, 2, 3, 4])))
        go_result, go_recv = play_h2c(go, server_bin, requests)
        rust_result, rust_recv = play_h2c(rust, server_bin, requests)
        if go_result.startswith("panic"):
            continue
        go_result, rust_result = body_write_race(go_result), body_write_race(rust_result)
        if (go_result, go_recv) != (rust_result, rust_recv):
            raise AssertionError(f"h2c scenario {n}: {requests}\nGo   ={go_result}\nRust ={rust_result}\n"
                                 f"Go   recv={go_recv}\nRust recv={rust_recv}")
        done += 1
        events += go_result.count(";") + go_result.count("main[")
        seen.update(h for h in H2_HOOKS if h in go_result)
    # The scenarios must exercise every stream-level hook Go's HTTP/2 transport fires.
    assert count < 20 or seen == set(H2_HOOKS), f"h2c scenarios never fired: {sorted(set(H2_HOOKS) - seen)}"
    return done, events


def main():
    started = time.monotonic()
    rng = random.Random(0x48545450)
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "httptrace_probe"],
                   cwd=ROOT, check=True)
    rust = Probe([str(TARGET / "debug/examples" / ("httptrace_probe.exe" if os.name == "nt" else "httptrace_probe"))])
    go = Probe(["go", "run", str(ROOT / "tools/httptrace_oracle.go")])
    count = int(os.environ.get("HTTPTRACE_SCENARIOS", "100"))
    done = events = 0
    tmp = tempfile.mkdtemp(prefix="httptrace_h2c")
    server_bin = os.path.join(tmp, "h2c_server")
    subprocess.run(["go", "build", "-o", server_bin, str(ROOT / "tools/httptrace_h2c_server.go")], cwd=ROOT, check=True)
    try:
        for n in range(count):
            config = ["x"]
            roll = rng.random()
            if roll < 0.15:
                config.append("nokeepalive")
            elif roll < 0.3:
                config.append("maxidle=-1")
            elif roll < 0.4:
                config.append("maxidleconns=1")
            if rng.random() < 0.1:
                config.append("host=localhost")
            requests = [request_spec(rng) for _ in range(rng.choice([1, 2, 2, 3, 4]))]
            specs = [spec_pool(rng) for _ in range(len(requests) + 3)]
            go_result, go_recv = play(go, specs, ",".join(config), ";".join(requests))
            rust_result, rust_recv = play(rust, specs, ",".join(config), ";".join(requests))
            if go_result.startswith("panic"):
                continue
            if (go_result, go_recv) != (rust_result, rust_recv):
                raise AssertionError(
                    f"scenario {n}: {config} {requests}\nGo   ={go_result}\nRust ={rust_result}\n"
                    f"Go   recv={go_recv}\nRust recv={rust_recv}")
            done += 1
            events += go_result.count(";") + go_result.count("main[")
        h2c_done, h2c_events = check_h2c(rng, go, rust, server_bin)
    finally:
        rust.close()
        go.close()
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"httptrace Go differential: {done} scripted-server scenarios ({events} traced events, identical "
          f"hook sequences, results and server-side bytes) plus {h2c_done} h2c scenarios ({h2c_events} traced events) "
          f"passed in {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
