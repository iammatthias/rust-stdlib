#!/usr/bin/env python3
"""Differentially check net/http/httputil dumps, chunked codec, reverse-proxy
header logic and content sniffing against Go with generated inputs."""
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RNG = random.Random(0x4771)

METHODS = ["GET", "POST", "PUT", "PATCH", "HEAD", "DELETE", "OPTIONS", "", "PROPFIND", "get"]
NAMES = ["Accept", "accept-encoding", "X-MULTI", "x_under", "content-type", "Cookie", "user-agent",
         "Range", "Connection", "Trailer", "Date", "a", "X-1-2", "www-authenticate", "te", "x-Dup",
         "ETag", "content-length", "Cache-Control", "x-forwarded-for"]
VALUES = ["text/plain", "", "gzip, deflate", "a=b; c=d", "  padded  ", "tab\tinside", "x" * 70,
          "close", "keep-alive", "bytes=0-10", "Go-http-client/1.1", "curl/8.0", "1", "0",
          "\"quoted\"", "trailers", "<id@host>", "*/*", "with:colon"]
HOSTS = ["example.com", "h:8080", "[::1]:80", "127.0.0.1", "UPPER.example", None]
TARGETS = ["/", "/a/b?c=d", "/p%20q", "//double", "/a?", "/a??", "/k?b=2&a=1&a=0", "/~u/x.y",
           "/x;y=z", "/q?x=%41"]
SERVER_TARGETS = TARGETS + ["*", "http://example.org/abs?x", "https://h/p"]
STATUSES = [200, 201, 204, 206, 301, 304, 404, 418, 500, 599, 100, 103, 299, 999, 7, 1000, 65535]
PROTOS = ["1.1", "1.1", "1.1", "1.0", "2.0"]


def hexf(data):
    if isinstance(data, str):
        data = data.encode()
    return data.hex()


def header_blob(fields):
    return b"\x01".join(n.encode() + b"\x00" + v.encode() for n, v in fields)


def body():
    roll = RNG.random()
    if roll < 0.3:
        return b""
    if roll < 0.6:
        return RNG.choice([b"hello", b"{\"ok\":true}", b"line\r\nline\n", b"0\r\n\r\n"])
    return bytes(RNG.randrange(256) for _ in range(RNG.randint(1, 300)))


def random_headers(names=NAMES, count=6):
    fields = []
    for _ in range(RNG.randint(0, count)):
        name = RNG.choice(names)
        if RNG.random() < 0.3:
            name = "".join(c.upper() if RNG.random() < 0.5 else c.lower() for c in name)
        fields.append((name, RNG.choice(VALUES)))
    if fields and RNG.random() < 0.3:
        fields.append(RNG.choice(fields))  # multi-value
    return fields


def with_host(fields, hosts=HOSTS):
    host = RNG.choice(hosts)
    if host is not None:
        fields.insert(RNG.randint(0, len(fields)), ("Host", host))
        if RNG.random() < 0.05:
            fields.append(("host", "second.example"))
    return fields


def te_fields(choices):
    return [("Transfer-Encoding", v) for v in RNG.choice(choices)]


def request_records(mode, count):
    records = []
    targets = SERVER_TARGETS if mode == "Q" else TARGETS
    te_choices = [[], [], ["chunked"], ["identity"], ["gzip", "chunked"]] if mode == "Q" else [[], [], ["chunked"]]
    for _ in range(count):
        fields = with_host(random_headers())
        fields += te_fields(te_choices)
        RNG.shuffle(fields)
        flag = "1" if RNG.random() < 0.6 else "0"
        record = [hexf(RNG.choice(METHODS)), hexf(RNG.choice(targets)),
                  hexf(header_blob(fields)), hexf(body()), hexf(flag)]
        if mode == "Q":
            record.append(hexf(RNG.choice(PROTOS)))
        elif mode in "XY":
            record = record[:4]
        records.append((mode, record))
    return records


def response_records(count):
    records = []
    for _ in range(count):
        data = body()
        fields = random_headers([n for n in NAMES if n != "content-length"])
        roll = RNG.random()
        if roll < 0.25:
            fields.append(("Content-Length", str(len(data))))
        elif roll < 0.35:
            fields.append(("Content-Length", RNG.choice(["0", "3", "abc", "-1", "99999", "18446744073709551615"])))
        elif roll < 0.4:
            fields += [("Content-Length", str(len(data))), ("content-length", "7")]
        fields += te_fields([[], [], [], ["chunked"], ["identity"], ["gzip", "chunked"], ["gzip"]])
        if RNG.random() < 0.1:
            fields.append(("Connection", RNG.choice(["close", "Close, keep-alive", "x-close", "keep-alive"])))
        RNG.shuffle(fields)
        flag = "1" if RNG.random() < 0.6 else "0"
        records.append(("R", [hexf(str(RNG.choice(STATUSES))), hexf(header_blob(fields)),
                              hexf(data), hexf(flag), hexf(RNG.choice(PROTOS))]))
    return records


def wire_request(final):
    """One valid request for the crate's strict parser, with framing."""
    method = RNG.choice(["GET", "POST", "PUT", "HEAD", "DELETE"])
    version = RNG.choice(["HTTP/1.1", "HTTP/1.1", "HTTP/1.0"])
    lines = [f"{method} {RNG.choice(TARGETS)} {version}", f"Host: {RNG.choice(['a.example', 'h:81'])}"]
    for name, value in random_headers([n for n in NAMES if n not in
                                       ("content-length", "Connection", "Trailer", "te")], 3):
        lines.append(f"{name}: {value}")
    if RNG.random() < 0.25 or final:
        lines.append(f"Connection: {RNG.choice(['close', 'keep-alive', 'Keep-Alive, x'])}")
    data = RNG.choice([b"", b"payload", bytes(range(40))])
    if data and version == "HTTP/1.1" and RNG.random() < 0.4:
        lines.append("Transfer-Encoding: chunked")
        framed = b"%x\r\n%s\r\n0\r\n\r\n" % (len(data), data)
    elif data or method in ("POST", "PUT"):
        lines.append(f"Content-Length: {len(data)}")
        framed = data
    else:
        framed = b""
    return "\r\n".join(lines).encode() + b"\r\n\r\n" + framed


def server_conn_records(count):
    records = []
    for _ in range(count):
        n = RNG.randint(1, 3)
        stream = b"".join(wire_request(i == n - 1 and RNG.random() < 0.3) for i in range(n))
        if RNG.random() < 0.15:
            tail = wire_request(False)
            stream += tail[:RNG.randint(1, tail.index(b"\r\n\r\n"))]
        records.append(("Z", [hexf(stream)]))
    return records


def wire_response(method):
    version = RNG.choice(["HTTP/1.1", "HTTP/1.1", "HTTP/1.0"])
    status = RNG.choice([200, 201, 204, 304, 404, 500])
    lines = [f"{version} {status} {RNG.choice(['OK', 'Whatever', 'Not Found'])}"]
    for name, value in random_headers([n for n in NAMES if n not in
                                       ("content-length", "Connection", "Trailer", "te")], 3):
        lines.append(f"{name}: {value}")
    if RNG.random() < 0.2:
        lines.append(f"Connection: {RNG.choice(['close', 'keep-alive'])}")
    data = RNG.choice([b"", b"hello", bytes(range(30))])
    bodyless = status in (204, 304) or method == "HEAD"
    if status in (204, 304):
        return "\r\n".join(lines).encode() + b"\r\n\r\n", False
    if version == "HTTP/1.1" and data and RNG.random() < 0.3:
        lines.append("Transfer-Encoding: chunked")
        framed = b"" if bodyless else b"%x\r\n%s\r\n0\r\n\r\n" % (len(data), data)
    else:
        lines.append(f"Content-Length: {len(data)}")
        framed = b"" if bodyless else data
    return "\r\n".join(lines).encode() + b"\r\n\r\n" + framed, False


def client_conn_records(count):
    records = []
    for _ in range(count):
        fields = []
        stream = b""
        for _ in range(RNG.randint(1, 3)):
            method = RNG.choice(["GET", "POST", "HEAD", "PUT"])
            headers = with_host(random_headers([n for n in NAMES if n not in
                                                ("content-length", "Trailer", "Connection")], 3),
                                ["a.example", "h:81"])
            if RNG.random() < 0.1:
                headers.append(("Connection", "close"))
            fields += [hexf(method), hexf(RNG.choice(TARGETS)), hexf(header_blob(headers)), hexf(body())]
            response, _ = wire_response(method)
            stream += response
        records.append(("K", fields + [hexf(stream)]))
    return records


INTERESTING = [b"\r", b"\n", b"\r\n", b"0", b";", b" ", b"\t", b"f", b"g", b"\x00", b"x", b"F"]


def mutate(data):
    data = bytearray(data)
    for _ in range(RNG.randint(1, 3)):
        pos = RNG.randint(0, len(data))
        op = RNG.randrange(3)
        if op == 0 or not data:
            data[pos:pos] = RNG.choice(INTERESTING)
        elif op == 1:
            del data[min(pos, len(data) - 1)]
        else:
            data[min(pos, len(data) - 1)] = RNG.choice(INTERESTING)[0]
    return bytes(data)


def chunk_stream():
    out = bytearray()
    for _ in range(RNG.randint(0, 5)):
        payload = bytes(RNG.randrange(256) for _ in range(RNG.randint(1, 40)))
        size = format(len(payload), RNG.choice(["x", "X", "04x"]))
        ext = RNG.choice(["", "", ";a=b", "; x", ";;;", ";\"bad", " ", "\t;q=\"v\""])
        out += size.encode() + ext.encode() + b"\r\n" + payload + b"\r\n"
    out += RNG.choice([b"0\r\n\r\n", b"0\r\nX-T: v\r\n\r\n", b"000;e\r\n", b"0\r\n"])
    if RNG.random() < 0.2:
        out += b"after"
    return bytes(out)


def chunk_records():
    streams = [chunk_stream() for _ in range(1200)]
    streams += [mutate(RNG.choice(streams)) for _ in range(1200)]
    streams += [s[:RNG.randint(0, len(s))] for s in RNG.sample(streams, 200)]
    streams += [b"", b"0\r\n", b"\r\n", b"5\n", b"5\r\r\n", b"ffffffffffffffff\r\n", b"10000000000000000\r\n",
                b"8000000000000000\r\nabc", b"7fffffffffffffff\r\n" + b"x" * 30, b"g\r\n", b";ext\r\n",
                b"5 \t\r\nhello\r\n0\r\n", b"5\r\nhelloXY0\r\n", b"5\r\nhello\r\n"]
    for length in (4092, 4093, 4094, 4095, 4096, 4097, 5000):
        streams.append(b"1;" + b"e" * (length - 2) + b"\r\na\r\n0\r\n\r\n")
    for ext in (10, 40, 60):
        streams.append((b"1;" + b"e" * ext + b"\r\nz\r\n") * 700 + b"0\r\n\r\n")
    return [("C", [hexf(s)]) for s in streams]


SNIFF_SEEDS = [b"<!DOCTYPE HTML>", b"<html>", b"  \n<HEAD ", b"<script", b"<iframe>", b"<h1>", b"<div ",
               b"<font>", b"<table>", b"<a ", b"<style>", b"<title>", b"<b>", b"<body>", b"<br>", b"<p>",
               b"<!-- c -->", b"<?xml version", b"%PDF-1.4", b"%!PS-Adobe-3", b"\xfe\xff\x00\x00",
               b"\xff\xfe\x00\x00", b"\xef\xbb\xbfabc", b"\x00\x00\x01\x00", b"BMxx", b"GIF87a",
               b"GIF89a", b"RIFF\x00\x00\x00\x00WEBPVP8", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff",
               b"FORM\x00\x00\x00\x00AIFF", b"ID3", b"OggS\x00", b"MThd\x00\x00\x00\x06",
               b"RIFF\x00\x00\x00\x00AVI ", b"RIFF\x00\x00\x00\x00WAVE",
               b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp41isom", b"\x1a\x45\xdf\xa3",
               b"\x00" * 34 + b"LP", b"\x00\x01\x00\x00", b"OTTO", b"ttcf", b"wOFF", b"wOF2",
               b"\x1f\x8b\x08", b"PK\x03\x04", b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00",
               b"\x00asm", b"plain text", b"bin\x01ary", b"", b" \t\r\n", b"<htmlx", b"<HTML",
               b"\x00\x00\x00\x0cftypmp4", b"\x00\x00\x00\x10ftypisommp4\x00"]


def sniff_records():
    records = [("S", [hexf(s)]) for s in SNIFF_SEEDS]
    for _ in range(600):
        seed = RNG.choice(SNIFF_SEEDS)
        data = RNG.choice([b"", b" ", b"\n\t"]) + seed if RNG.random() < 0.3 else seed
        data = mutate(data) if RNG.random() < 0.5 else data
        if RNG.random() < 0.2:
            data += bytes(RNG.randrange(256) for _ in range(RNG.randint(0, 600)))
        records.append(("S", [hexf(data)]))
    return records


PROXY_NAMES = ["Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate",
               "Te", "Trailer", "Transfer-Encoding", "Upgrade", "X-Forwarded-For", "X-Forwarded-Host",
               "X-Forwarded-Proto", "Forwarded", "X-Custom", "X-A", "X-B", "Accept", "User-Agent",
               "Content-Length", "Cookie", "Content-Type"]
PROXY_VALUES = {
    "Connection": ["close", "keep-alive, X-Custom", "Upgrade", "x-a, x-b", " , X-B ,", "te", "content-length",
                   "upgrade, keep-alive", "Host"],
    "Te": ["trailers", "gzip, trailers", "deflate", "TRAILERS;q=1", " trailers "],
    "Upgrade": ["websocket", "h2c", "web\tsocket", ""],
    "X-Forwarded-For": ["10.0.0.1", "10.0.0.1, 10.0.0.2", ""],
    "Transfer-Encoding": ["chunked"],
}
REMOTES = ["192.0.2.1:1234", "[2001:db8::1]:443", "10.0.0.1", "", "bad:addr:1", "[::1]", "host:80",
           "[::1]:80:9", "[a]b:1"]
BACKENDS = ["http://backend:8080", "http://backend:8080/base", "http://backend/base/", "http://backend/base?x=1",
            "http://10.0.0.2:9000/a/b/", "http://[::1]:8081/v1?k=v&k=w"]
PROXY_TARGETS = ["/", "/path", "/a/b?x=1&y=2", "/q?a=1;b=2", "/q?bad=%zz&ok=1", "/p%20q", "/%7Euser", "/x?",
                 "/x??", "/k?b=2&a=1&a=0", "//double", "/s?a+b=c%20d&%FF=1", "/t?z=%2", "/u?&&a=&=b"]
RESP_NAMES = ["Connection", "Keep-Alive", "Transfer-Encoding", "Trailer", "Upgrade", "X-Resp", "Content-Type",
              "Set-Cookie", "Content-Length", "Proxy-Authenticate", "Te"]


def proxy_headers(names):
    fields = []
    for _ in range(RNG.randint(0, 7)):
        name = RNG.choice(names)
        value = RNG.choice(PROXY_VALUES.get(name, ["v1", "v2", "", "a, b"]))
        if name == "Connection" and names is RESP_NAMES:
            value = RNG.choice(["X-Resp", "close", "Set-Cookie, keep-alive"])
        fields.append((name.lower() if RNG.random() < 0.3 else name, value))
    return fields


def proxy_records(count):
    records = []
    for _ in range(count):
        mode = RNG.choice(["director", "rewrite", "rewrite", "rewrite-host", "rewrite-append"])
        method = RNG.choice(["GET", "POST", "PUT", "DELETE"])
        target = RNG.choice(PROXY_TARGETS)
        fields = with_host(proxy_headers(PROXY_NAMES), ["front.example", "front:8443", None])
        if RNG.random() < 0.05:
            method, target = "OPTIONS", "*"
        records.append(("P", [hexf(mode), hexf(method), hexf(target), hexf(header_blob(fields)),
                              hexf(RNG.choice(REMOTES)), hexf(RNG.choice(BACKENDS)),
                              hexf(header_blob(proxy_headers(RESP_NAMES)))]))
    return records


def writer_records():
    records = []
    for _ in range(100):
        chunks = [bytes(RNG.randrange(256) for _ in range(RNG.choice([0, 1, 15, 16, 255, 4096])))
                  for _ in range(RNG.randint(1, 5))]
        records.append(("W", [hexf(c) for c in chunks]))
    return records


def corpus():
    return (request_records("Q", 1500) + request_records("O", 1500) + response_records(1500)
            + request_records("X", 600) + request_records("Y", 600)
            + server_conn_records(600) + client_conn_records(600)
            + chunk_records() + writer_records() + sniff_records() + proxy_records(2500))


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=200)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr}")
    return result.stdout.splitlines()


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("httputil differential check requires Go and Cargo on PATH")
    records = corpus()
    payload = "".join(f"{mode}:{','.join(fields)}\n" for mode, fields in records)
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go = run(["go", "run", "tools/httputil_oracle.go"], payload, env)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "httputil_probe"],
               payload, env)
    if len(go) != len(records) or len(rust) != len(records):
        raise AssertionError("httputil oracle returned the wrong number of records")
    failures = [(mode, fields, g, r) for (mode, fields), g, r in zip(records, go, rust) if g != r]
    for mode, fields, g, r in failures[:10]:
        decoded = [bytes.fromhex(f)[:120] for f in fields]
        show = lambda s: bytes.fromhex(s) if s not in ("ERR",) and all(c in "0123456789abcdef," for c in s) and "," not in s else s
        print(f"mode={mode} fields={decoded!r}\n  Go  ={show(g)!r}\n  Rust={show(r)!r}")
    if failures:
        raise AssertionError(f"{len(failures)} of {len(records)} httputil vectors differ from Go")
    counts = {}
    errors = {}
    for (mode, _), g in zip(records, go):
        counts[mode] = counts.get(mode, 0) + 1
        if g == "ERR" or (mode == "C" and not g.endswith(",")):
            errors[mode] = errors.get(mode, 0) + 1
    detail = ", ".join(f"{k}={v} ({errors.get(k, 0)} rejected)" for k, v in sorted(counts.items()))
    print(f"httputil Go differential: {len(records)} vectors passed ({detail})")
    # The Go-shaped ReverseProxy (Y) and ServerConn/ClientConn (Z) share this
    # package; tools/http_check.py compares them against Go as well.
    shaped = dict(env, HTTP_CHECK_MODES="Y,Z")
    subprocess.run([sys.executable, str(ROOT / "tools/http_check.py")], cwd=ROOT, env=shaped, check=True, timeout=300)


if __name__ == "__main__":
    main()
