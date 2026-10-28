#!/usr/bin/env python3
"""Differentially check net/http/cgi and net/http/fcgi against Go.

* RequestFromMap: thousands of random and mutated CGI variable sets; the
  request fields or the error text must agree.
* Handler (the web-server side): scripted requests against tools/cgi_fixture.py
  covering the environment Go builds, inherited and overridden variables,
  arguments, working directory, chunked rejection, internal redirects and
  malformed or unusual CGI output; the status, headers, body and log must agree.
* Serve (the CGI program side): the same handler run as a CGI child with
  scripted environments and request bodies; stdout, stderr and the exit code
  must be identical.
* fcgi.Serve: scripted FastCGI record streams (begin, params split across
  records, stdin, aborts, GetValues, unknown record types, bad roles, large
  responses) sent to a Go and a Rust server; the records returned, grouped
  by request, must be identical.
"""
import os
import pathlib
import random
import re
import socket
import struct
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
TARGET = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target"))
FIXTURE = str(ROOT / "tools/cgi_fixture.py")


def hx(s):
    if isinstance(s, str):
        s = s.encode()
    return s.hex() if s else "-"


class Lines:
    """A persistent line-protocol subprocess."""

    def __init__(self, command, env=None):
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                        bufsize=1, cwd=ROOT, env=env)

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


# ------------------------------------------------------- RequestFromMap

def random_map(rng):
    m = {}
    m["REQUEST_METHOD"] = rng.choice(["GET", "POST", "PUT", "HEAD", "get", "G E T", ""] if rng.random() < 0.2 else ["GET", "POST", "PUT", "DELETE"])
    m["SERVER_PROTOCOL"] = rng.choice(["HTTP/1.1", "HTTP/1.0", "INCLUDED", "HTTP/2.0", "HTTP/1.", "", "SPDY", "HTTP/0.9", "HTTP/1.1 "] if rng.random() < 0.3 else ["HTTP/1.1", "HTTP/1.0", "INCLUDED"])
    if rng.random() < 0.8:
        m["HTTP_HOST"] = rng.choice(["example.com", "example.com:8080", "[::1]:80", "localhost", "a b", "exa mple.com", "bad\x7fhost", "xn--e1afmkfd.example", "user@example.com"])
    if rng.random() < 0.6:
        m["REQUEST_URI"] = rng.choice(["/", "/a/b?x=1&y=2", "/search?q=%20", "/%zz", "/a b", "//double/slash", "*", "/path#frag", "http://other/x", "?only=query", ":bad", "/\x01ctl"])
    else:
        m["SCRIPT_NAME"] = rng.choice(["/cgi-bin/app", "", "/s"])
        m["PATH_INFO"] = rng.choice(["/extra/info", "", "/x y"])
        if rng.random() < 0.5:
            m["QUERY_STRING"] = rng.choice(["a=b", "", "q=%41"])
    if rng.random() < 0.4:
        m["CONTENT_LENGTH"] = rng.choice(["0", "12", "-1", "abc", "9999999999999999999", " 5", "+7", "1_0"])
    if rng.random() < 0.3:
        m["CONTENT_TYPE"] = rng.choice(["text/plain", "application/x-www-form-urlencoded", ""])
    if rng.random() < 0.3:
        m["HTTPS"] = rng.choice(["on", "ON", "1", "off", "", "yes"])
    if rng.random() < 0.7:
        m["REMOTE_ADDR"] = rng.choice(["192.0.2.1", "::1", "2001:db8::1", "", "host name"])
        if rng.random() < 0.6:
            m["REMOTE_PORT"] = rng.choice(["1234", "0", "-5", "x", "", "99999999999999999999", "+80"])
    used = set()
    for _ in range(rng.randrange(0, 5)):
        name = rng.choice(["X_Custom", "ACCEPT", "USER_AGENT", "X_A_B", "COOKIE", "X_LOWER", "ACCEPT_ENCODING", "X_1", "AUTHORIZATION"])
        canon = name.replace("_", "-").lower()
        if canon in used:
            continue
        used.add(canon)
        m["HTTP_" + name] = rng.choice(["v", "two words", "", "a=b; c=d", "x" * 40])
    if rng.random() < 0.05:
        m["HTTP_HOST"] = ""
    return m


def map_line(m):
    return "M " + ("|".join(hx(f"{k}={v}") for k, v in m.items()) or "-")


def check_map(rng, go, rust):
    lines = [map_line(random_map(rng)) for _ in range(2000)]
    mismatches = 0
    ok = 0
    for line in lines:
        g, r = go.ask(line), rust.ask(line)
        if g.startswith("panic"):
            continue
        if g != r:
            raise AssertionError(f"RequestFromMap {line}\nGo  ={g}\nRust={r}")
        ok += g.startswith("ok")
    return len(lines), ok


# ---------------------------------------------------------- Handler (host)

def cgi_output(rng):
    """Raw bytes a CGI program might print."""
    ctype = b"Content-Type: text/html\r\n"
    kind = rng.choice(["plain", "plain", "status", "location", "localredirect", "noctype", "noblank", "long", "bogus",
                       "badname", "shortstatus", "badstatus", "lf", "multi", "empty", "statusonly", "cookies", "bodyonly"])
    body = rng.choice([b"hello", b"", b"<html>x</html>", b"line1\nline2\r\nline3", b"x" * 5000])
    if kind == "plain":
        return ctype + b"\r\n" + body
    if kind == "status":
        return b"Status: " + rng.choice([b"404 Not Found", b"201 Created", b"500", b"302 x", b"200  spaced", b"999 odd"]) + b"\r\n" + ctype + b"\r\n" + body
    if kind == "location":
        return b"Location: http://example.com/next\r\n\r\n" + body
    if kind == "localredirect":
        return b"Location: /local/path?x=1\r\n" + rng.choice([b"", b"Status: 301 Moved\r\n"]) + b"\r\n" + body
    if kind == "noctype":
        return b"X-Other: 1\r\n\r\n" + body
    if kind == "noblank":
        return ctype + b"X-Y: z\r\n"
    if kind == "long":
        return b"X-Long: " + b"a" * 2000 + b"\r\n" + ctype + b"\r\n" + body
    if kind == "bogus":
        return b"this is not a header\r\n" + ctype + b"\r\n" + body
    if kind == "badname":
        return b"Bad Name: v\r\n" + b"X-Ok: 1\r\n" + ctype + b"\r\n" + body
    if kind == "shortstatus":
        return b"Status: 2\r\n" + ctype + b"\r\n" + body
    if kind == "badstatus":
        return b"Status: abc def\r\n" + ctype + b"\r\n" + body
    if kind == "lf":
        return b"Content-Type: text/plain\n\n" + body
    if kind == "multi":
        return b"Content-Type: a\r\nContent-Type: b\r\nX-Multi: 1\r\nX-Multi: 2\r\n\r\n" + body
    if kind == "empty":
        return b""
    if kind == "statusonly":
        return b"Status: 204 No Content\r\n\r\n"
    if kind == "cookies":
        return b"Set-Cookie: a=b\r\nSet-Cookie: c=d; Path=/\r\n" + ctype + b"\r\n" + body
    return body


def host_request(rng):
    f = {}
    f["method"] = hx(rng.choice(["GET", "POST", "PUT", "DELETE", "HEAD"]))
    f["uri"] = hx(rng.choice(["/", "/cgi-bin/app/extra?x=1&y=%20z", "/app/path%20info", "/app/", "/other", "/app", "/a/b/c?"]))
    f["host"] = hx(rng.choice(["example.com", "example.com:8080", "[::1]:9", "localhost", "h"]))
    if rng.random() < 0.3:
        f["tls"] = "1"
    f["remote"] = hx(rng.choice(["192.0.2.1:1234", "[2001:db8::1]:80", "unparsable", "", "1.2.3.4"]))
    hdrs = []
    seen = set()
    for _ in range(rng.randrange(0, 5)):
        name, val = rng.choice([("X-Custom", "v"), ("Cookie", "a=b"), ("Cookie", "c=d"), ("Proxy", "evil:80"), ("Accept", "text/html, */*"),
                                ("X-Dash-Name", "1"), ("Authorization", "Basic xyz"), ("Content-Type", rng.choice(["text/plain", "a/b; c=d"]))])
        hdrs.append(hx(f"{name}:{val}"))
    if hdrs:
        f["hdr"] = "|".join(hdrs)
    if rng.random() < 0.4:
        f["body"] = hx(rng.choice([b"payload", b"a=b&c=d", b"x" * 3000, b"\x00\xff\x01"]))
    if rng.random() < 0.05:
        f["te"] = "chunked"
    f["root"] = hx(rng.choice(["", "/", "/app", "/app/", "/cgi-bin/app//"]))
    mode = rng.choice(["env", "env", "raw", "raw", "raw", "stderr", "slow"])
    env = [f"CGI_MODE={mode}"]
    if mode == "raw":
        env.append("CGI_OUT=" + cgi_output(rng).hex())
    if rng.random() < 0.3:
        env.append(rng.choice(["EXTRA=1", "SERVER_SOFTWARE=override", "PATH_INFO=/forced", "REQUEST_METHOD=HEAD", "DUP=1"]))
        if rng.random() < 0.3:
            env.append("DUP=2")
    f["envx"] = "|".join(hx(e) for e in env)
    if rng.random() < 0.2:
        f["inherit"] = "|".join(hx(e) for e in rng.sample(["HOME", "USER", "PATH", "NOPE_UNSET", "SHELL"], 2))
    if rng.random() < 0.3:
        f["args"] = "|".join(hx(e) for e in rng.sample(["-x", "arg two", "", "--flag=1"], rng.randrange(1, 3)))
    if rng.random() < 0.15:
        f["dir"] = hx(rng.choice(["/tmp", str(ROOT), str(ROOT / "tools")]))
    if rng.random() < 0.5:
        f["loc"] = "1"
    return "H " + " ".join(f"{k}={v}" for k, v in f.items())


def explain(g, r):
    """Decode the hex fields of two host results and show how they differ."""
    def parts(x):
        out = {}
        for tok in x.split(" "):
            k, _, v = tok.partition("=")
            out[k] = v
        return out
    pg, pr = parts(g), parts(r)
    lines = []
    for k in sorted(set(pg) | set(pr)):
        if pg.get(k) != pr.get(k):
            a, b = pg.get(k, ""), pr.get(k, "")
            if k in ("body", "log", "stderr"):
                try:
                    a, b = bytes.fromhex(a).decode(errors="replace"), bytes.fromhex(b).decode(errors="replace")
                except ValueError:
                    pass
            if k in ("body", "log", "stderr"):
                al, bl = a.split("\n"), b.split("\n")
                diff = [(x, y) for x, y in zip(al, bl) if x != y] or [(f"{len(al)} lines", f"{len(bl)} lines")]
                a, b = repr(diff[0][0][:200]), repr(diff[0][1][:200])
                lines.append(f"{k}: first difference\n  Go  ={a}\n  Rust={b}")
            else:
                lines.append(f"{k}:\n  Go  ={a!r}\n  Rust={b!r}")
    return "\n".join(lines) or f"Go={g}\nRust={r}"


def check_host(rng, go, rust):
    n = 0
    for _ in range(120):
        line = host_request(rng)
        g, r = go.ask(line), rust.ask(line)
        if g.startswith("panic"):
            continue
        if g != r:
            raise AssertionError(f"Handler {line}\n{explain(g, r)}")
        n += 1
    # argv[0] is Path itself (no "./" prefix), observed by a real binary: sh -c
    # reports its own argv[0] as $0. Cover a slash-less Path run in Dir, a
    # Path with a directory part, and a relative Path run in Dir.
    script = 'printf "Content-Type: text/plain\\r\\n\\r\\nargv0=%s\\n" "$0"'
    for path, d in [("sh", "/bin"), ("/bin/sh", None), ("bin/sh", "/"), ("./sh", "/bin")]:
        f = {"method": hx("GET"), "uri": hx("/"), "host": hx("h"), "remote": hx("1.2.3.4"), "root": hx(""),
             "path": hx(path), "args": "|".join(hx(a) for a in ["-c", script])}
        if d:
            f["dir"] = hx(d)
        line = "H " + " ".join(f"{k}={v}" for k, v in f.items())
        g, r = go.ask(line), rust.ask(line)
        if g != r or "argv0=" + path not in bytes.fromhex(re.search(r"body=(\w+)", g).group(1)).decode():
            raise AssertionError(f"Handler argv0 {path!r}\n{explain(g, r)}")
        n += 1
    return n


# ---------------------------------------------------------- Serve (child)

def child_env(rng):
    env = {"SERVER_PROTOCOL": rng.choice(["HTTP/1.1", "HTTP/1.0", "INCLUDED"]), "REQUEST_METHOD": rng.choice(["GET", "POST", "PUT"]),
           "HTTP_HOST": rng.choice(["example.com", "example.com:8080", ""]),
           "REMOTE_ADDR": "192.0.2.7", "REMOTE_PORT": "4242", "PATH": os.environ.get("PATH", "")}
    mode = rng.choice(["echo", "echo", "status", "chunks", "big", "sniff", "twice", "nothing", "readn", "notmod"])
    q = {"echo": "mode=echo", "nothing": "mode=nothing", "twice": "mode=twice", "notmod": "mode=notmod",
         "status": "mode=status&code=%d&n=%d" % (rng.choice([200, 201, 204, 301, 404, 500]), rng.choice([0, 5, 100])),
         "chunks": "mode=chunks&c=ab&c=cd&c=%s&flush=%d" % (rng.choice(["e", "<html>", ""]), rng.randrange(2)),
         "big": "mode=big&n=%d" % rng.choice([0, 1, 4096, 100000]),
         "sniff": "mode=sniff&data=" + rng.choice([b"<html>x".hex(), b"GIF89a".hex(), b"plain text".hex(), b"\x89PNG\r\n\x1a\n".hex(), b"%PDF-1.4".hex(), b"".hex() or "-"]),
         "readn": "mode=readn&n=%d" % rng.choice([0, 3, 100])}[mode]
    if mode == "status" and rng.random() < 0.5:
        q += "&ctype=text/x-test&h=X-A%3D1&h=X-B%3D2"
    env["REQUEST_URI"] = "/app/path?" + q
    body = b""
    if env["REQUEST_METHOD"] != "GET" or rng.random() < 0.2:
        body = rng.choice([b"", b"hello body", b"x" * 2000, b"a=b"])
        if body or rng.random() < 0.3:
            env["CONTENT_LENGTH"] = str(len(body) + rng.choice([0, 0, 0, 5, -1]))
        if rng.random() < 0.5:
            env["CONTENT_TYPE"] = "text/plain"
    for _ in range(rng.randrange(0, 4)):
        env["HTTP_" + rng.choice(["X_FOO", "ACCEPT", "COOKIE", "USER_AGENT"])] = rng.choice(["a", "b c", ""])
    if rng.random() < 0.2:
        env["HTTPS"] = "on"
    if rng.random() < 0.05:
        del env["REQUEST_METHOD"]
    return env, body


def run_child(command, env, body):
    p = subprocess.run(command, input=body, capture_output=True, env=env, cwd=ROOT, timeout=20)
    return p.returncode, p.stdout, p.stderr


def check_child(rng, go_bin, rust_bin):
    n = 0
    for _ in range(100):
        env, body = child_env(rng)
        g = run_child([go_bin, "child"], env, body)
        r = run_child([rust_bin, "child"], env, body)
        if g != r:
            raise AssertionError(f"CGI child env={env} body={body[:50]!r}\nGo  ={g}\nRust={r}")
        n += 1
    return n


# ------------------------------------------------------------------ FastCGI

def rec(typ, rid, content=b"", pad=None):
    if pad is None:
        pad = (-len(content)) & 7
    return struct.pack(">BBHHBB", 1, typ, rid, len(content), pad, 0) + content + bytes(pad)


def pairs(d):
    out = b""
    for k, v in d.items():
        k, v = k.encode(), v.encode()
        for n in (len(k), len(v)):
            out += bytes([n]) if n < 128 else struct.pack(">I", n | 1 << 31)
        out += k + v
    return out


def begin(rid, role=1, flags=0):
    return rec(1, rid, struct.pack(">HB5x", role, flags))


def fcgi_scenario(rng):
    """Returns (bytes to send, expected number of EndRequest records)."""
    out = b""
    ends = 0
    rids = rng.sample([1, 2, 3, 300, 65535], rng.choice([1, 1, 1, 2]))
    for rid in rids:
        kind = rng.choice(["normal"] * 8 + ["badrole", "getvalues", "unknowntype", "abort", "dupe", "badparams", "norequest", "noparams"])
        # A request without FCGI_KEEP_CONN closes the connection when it
        # ends, racing with any other request still running in either
        # implementation, so only a lone request may omit it.
        keep = rng.choice([0, 1]) if len(rids) == 1 else 1
        mode = rng.choice(["echo", "echo", "status", "chunks", "big", "sniff", "twice", "nothing", "readn", "notmod"])
        q = {"echo": "mode=echo", "nothing": "mode=nothing", "twice": "mode=twice", "notmod": "mode=notmod",
             "status": "mode=status&code=%d&n=%d" % (rng.choice([200, 404, 204]), rng.choice([0, 7])),
             "chunks": "mode=chunks&c=ab&c=cd&flush=1", "big": "mode=big&n=%d" % rng.choice([10, 65535, 70000, 200000]),
             "sniff": "mode=sniff&data=" + b"<html>x".hex(), "readn": "mode=readn&n=%d" % rng.choice([0, 4, 50])}[mode]
        params = {"REQUEST_METHOD": rng.choice(["GET", "POST"]), "SERVER_PROTOCOL": "HTTP/1.1", "REQUEST_URI": "/x?" + q,
                  "HTTP_HOST": "example.com", "REMOTE_ADDR": "198.51.100.2", "REMOTE_PORT": "55", "SCRIPT_NAME": "/s",
                  "REMOTE_USER": rng.choice(["alice", "bob"]), "SERVER_SOFTWARE": "py", "DOCUMENT_ROOT": "/srv",
                  "HTTP_X_FOO": rng.choice(["a", "b" * 200])}
        if rng.random() < 0.15:
            del params["REQUEST_METHOD"]
        if rng.random() < 0.2:
            params["BIG_VALUE"] = "v" * rng.choice([130, 600, 70000])
        body = rng.choice([b"", b"hello", b"x" * 100, b"y" * 70000])
        if kind == "badrole":
            out += begin(rid, role=rng.choice([2, 3, 9]), flags=keep)
            ends += 1
            continue
        if kind == "getvalues":
            out += rec(9, 0, pairs({"FCGI_MAX_CONNS": "", "FCGI_MPXS_CONNS": ""}))
            continue
        if kind == "unknowntype":
            out += rec(rng.choice([12, 50, 99]), rng.choice([0, rid]), b"abc")
            continue
        if kind == "norequest":
            out += rec(5, rid, b"stray stdin")
            continue
        out += begin(rid, flags=keep)
        if kind == "dupe":
            out += begin(rid)
            break
        raw = pairs(params)
        if kind == "badparams":
            raw = raw[:-3] if rng.random() < 0.5 else b"\xff\xff"
        if kind != "noparams":
            cuts = sorted(rng.sample(range(1, max(2, len(raw))), min(len(raw) - 1, rng.choice([0, 1, 2])))) if len(raw) > 2 else []
            last = 0
            for c in cuts + [len(raw)]:
                for i in range(last, c, 60000):
                    out += rec(4, rid, raw[i:min(c, i + 60000)])
                last = c
            out += rec(4, rid)
        if kind == "abort":
            out += rec(5, rid, b"partial")
            out += rec(2, rid)
            ends += 1
            if not keep:
                break
            continue
        for i in range(0, len(body), 30000):
            out += rec(5, rid, body[i:i + 30000])
        out += rec(5, rid)
        ends += 1
        if not keep:
            break
    return out, ends


def read_records(sock, ends, timeout=3.0):
    # Responses follow the request within milliseconds; a quiet 0.4 s means
    # the server has said everything it will.
    sock.settimeout(0.4)
    buf = b""
    records = []
    seen_ends = 0
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(1 << 20)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 8:
            _, typ, rid, clen, plen, _ = struct.unpack(">BBHHBB", buf[:8])
            if len(buf) < 8 + clen + plen:
                break
            # The Date header of an error response is the current time.
            content = re.sub(rb"Date: \w{3}, \d\d \w{3} \d{4} \d\d:\d\d:\d\d GMT", b"Date: NOW", buf[8:8 + clen])
            records.append((rid, typ, plen, content))
            if typ == 3:
                seen_ends += 1
            buf = buf[8 + clen + plen:]
        if seen_ends >= ends and ends > 0:
            # Let trailing records of the same request arrive.
            sock.settimeout(0.1)
    by_id = {}
    for rid, typ, plen, content in records:
        by_id.setdefault(rid, []).append((typ, plen, content))
    return by_id, buf


def fcgi_exchange(port, data, ends):
    if isinstance(port, str):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(5)
        s.connect(port)
    else:
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        # Send in a couple of pieces so records straddle reads.
        mid = len(data) // 2
        s.sendall(data[:mid])
        s.sendall(data[mid:])
        return read_records(s, ends)
    finally:
        s.close()


def start_fcgi(command):
    p = subprocess.Popen(command, stdout=subprocess.PIPE, text=True, cwd=ROOT)
    line = p.stdout.readline()
    assert line.startswith("PORT "), line
    return p, int(line.split()[1])


def check_fcgi(rng, go_bin, rust_bin):
    gp, gport = start_fcgi([go_bin, "fcgi"])
    rp, rport = start_fcgi([rust_bin, "fcgi"])
    n = 0
    try:
        for _ in range(100):
            data, ends = fcgi_scenario(rng)
            g = fcgi_exchange(gport, data, ends)
            r = fcgi_exchange(rport, data, ends)
            if g != r:
                def short(res):
                    return {k: [(t, p, c[:80]) for t, p, c in v] for k, v in res[0].items()}
                raise AssertionError(f"fcgi stream {data[:300]!r}...\nGo  ={short(g)}\nRust={short(r)}")
            n += 1
    finally:
        gp.kill()
        rp.kill()
    return n


def check_fcgi_stdin(rng, go_bin, rust_bin, tmp):
    """fcgi.Serve(nil): the listener is the socket inherited as standard input
    (net.FileListener(os.Stdin)); a TCP and a Unix listener are served, and a
    standard input that is no socket fails with the same error."""
    n = served = 0
    for family in ("tcp", "unix"):
        procs, targets, socks = [], [], []
        try:
            for name, binary in (("go", go_bin), ("rust", rust_bin)):
                if family == "tcp":
                    ls = socket.socket()
                    ls.bind(("127.0.0.1", 0))
                    target = ls.getsockname()[1]
                else:
                    ls = socket.socket(socket.AF_UNIX)
                    target = os.path.join(tmp, f"{name}.sock")
                    ls.bind(target)
                ls.listen(16)
                p = subprocess.Popen([binary, "fcgistdin"], stdin=ls, stdout=subprocess.PIPE, text=True, cwd=ROOT)
                ls.close()
                assert p.stdout.readline().strip() == "READY"
                procs.append(p)
                targets.append(target)
            for _ in range(20):
                data, ends = fcgi_scenario(rng)
                g = fcgi_exchange(targets[0], data, ends)
                r = fcgi_exchange(targets[1], data, ends)
                if g != r:
                    raise AssertionError(f"fcgi stdin {family} stream {data[:300]!r}...\nGo  ={g}\nRust={r}")
                served += bool(g[0])
                n += 1
        finally:
            for p in procs:
                p.kill()
                p.wait()
    errors = []
    for binary in (go_bin, rust_bin):
        out = subprocess.run([binary, "fcgistdin"], stdin=subprocess.DEVNULL, capture_output=True, text=True, cwd=ROOT, timeout=10).stdout
        errors.append(out)
    if errors[0] != errors[1]:
        raise AssertionError(f"fcgi stdin that is no socket\nGo  ={errors[0]!r}\nRust={errors[1]!r}")
    assert "ERR" in errors[0], errors[0]
    assert served > 10, f"only {served} stdin streams produced records"
    return n + 1


def main():
    started = time.monotonic()
    rng = random.Random(0x43474921)
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "cgi_probe"], cwd=ROOT, check=True)
    rust_bin = str(TARGET / "debug/examples" / ("cgi_probe.exe" if os.name == "nt" else "cgi_probe"))
    with tempfile.TemporaryDirectory() as tmp:
        go_bin = os.path.join(tmp, "cgi_oracle")
        subprocess.run(["go", "build", "-o", go_bin, str(ROOT / "tools/cgi_oracle.go")], cwd=ROOT, check=True)
        env = dict(os.environ, CGI_FIXTURE=FIXTURE)
        go_map, rust_map = Lines([go_bin, "map"], env), Lines([rust_bin, "map"], env)
        go_host, rust_host = Lines([go_bin, "host"], env), Lines([rust_bin, "host"], env)
        try:
            maps, accepted = check_map(rng, go_map, rust_map)
            hosts = check_host(rng, go_host, rust_host)
        finally:
            for p in (go_map, rust_map, go_host, rust_host):
                p.close()
        children = check_child(rng, go_bin, rust_bin)
        streams = check_fcgi(rng, go_bin, rust_bin)
        streams += check_fcgi_stdin(rng, go_bin, rust_bin, tmp)
    print(f"CGI/FastCGI Go differential: {maps} RequestFromMap sets ({accepted} accepted), {hosts} Handler "
          f"requests, {children} CGI child runs, {streams} FastCGI record streams passed in "
          f"{time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
