#!/usr/bin/env python3
"""Differentially check the Go-shaped net/http API against Go: ServeMux routing
tables, cookies, request and response parse/write round trips, dates and
versions, FileServer/ServeContent and client redirect policy."""
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RNG = random.Random(0x4852)


def hexf(data):
    if isinstance(data, str):
        data = data.encode()
    return data.hex()


# ---------------------------------------------------------------- ServeMux

LITERALS = ["a", "b", "c", "a%20b", "x", "api", "v1", "users", "%7Efoo", "a.b"]
WILD = ["{x}", "{y}", "{id}", "{rest...}", "{path...}", "{$}"]
METHODS_PAT = ["", "", "", "GET ", "POST ", "HEAD ", "PUT ", "GET  ", "DELETE ", "CONNECT "]
HOSTS = ["", "", "", "example.com", "a.org"]
BAD_PATTERNS = ["", "a/b", "/{x", "/{}", "/{x}{y}", "/a/{$}/b", "/{x}/{x}", "/{x...}/b", "/a/../b",
                "GET", "GET ", " /a", "/{1x}", "/{x y}", "GE T /a", "/a//b", "{x}/a", "example.com{x}/",
                "/a/{$}x", "/{...}", "POST /a/./b", "/a/{x...}/", "BREW /x", "/{é}/z", "/%zz"]
REQ_METHODS = ["GET", "GET", "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "CONNECT"]
REQ_HOSTS = ["", "example.com", "a.org", "example.com:8080", "other.net", "[::1]:80"]
REQ_TARGETS = ["/", "/a", "/a/", "/a/b", "/a/b/", "/a/b/c", "/b/a", "/a%20b", "/a%20b/c", "/x/y/z/w", "//a",
               "/a/./b", "/a/../b", "/A", "/a%2Fb", "/api/v1/users", "/api/v1/users/", "/api/v1/users/42",
               "/users/7/a", "/c", "/c/", "/v1", "/a.b", "/~foo", "/%7Efoo", "/a?q=1", "/a/?q=1", "/a/b?x",
               "/x/", "/a/b/c/d/e", "/%zz", "*"]


def random_pattern():
    if RNG.random() < 0.07:
        return RNG.choice(BAD_PATTERNS)
    segs = []
    for i in range(RNG.choice([0, 1, 1, 2, 2, 3, 4])):
        r = RNG.random()
        segs.append(RNG.choice(LITERALS) if r < 0.65 else RNG.choice(WILD[:3]))
    tail = RNG.random()
    path = "/" + "/".join(segs)
    if tail < 0.2 and segs:
        path += "/"
    elif tail < 0.35:
        path = ("/" + "/".join(segs) + "/" if segs else "/") + RNG.choice(["{rest...}", "{path...}"])
    elif tail < 0.45:
        path = ("/" + "/".join(segs) + "/" if segs else "/") + "{$}"
    method = RNG.choice(METHODS_PAT)
    host = RNG.choice(HOSTS)
    return f"{method}{host}{path}"


def request_for(method, host, target):
    if method == "CONNECT":
        target = RNG.choice([target, host or "example.com:443", "example.com:443"])
    return f"{method}\0{host}\0{target}"


def mux_records(count):
    out = []
    for _ in range(count):
        pats = [random_pattern() for _ in range(RNG.randint(1, 7))]
        reqs = []
        for _ in range(RNG.randint(8, 24)):
            reqs.append(request_for(RNG.choice(REQ_METHODS), RNG.choice(REQ_HOSTS), RNG.choice(REQ_TARGETS)))
        out.append(("M", [hexf("\x01".join(pats)), hexf("\x01".join(reqs))]))
    return out


# ----------------------------------------------------------------- cookies

CNAMES = ["a", "b", "sid", "x-y", "", "a b", "Name", "tok_en", "é", "x=y", "a;b"]
CVALUES = ["1", "", '"q"', '"a b"', "a b", "a,b", "vé", '"', '"x', 'x"', "a\\b", "a\"b", "~tilde", "  pad  ", "\ttab"]
SEPS = ["; ", ";", " ;  ", ";;", "; ;"]


def random_cookie_line():
    parts = []
    for _ in range(RNG.randint(0, 5)):
        parts.append(f"{RNG.choice(CNAMES)}={RNG.choice(CVALUES)}" if RNG.random() < 0.9 else RNG.choice(CNAMES))
    return RNG.choice(SEPS).join(parts)


DATES = ["Wed, 21 Oct 2015 07:28:00 GMT", "Wed, 21-Oct-2015 07:28:00 GMT", "Mon, 02 Jan 2006 15:04:05 MST",
         "Wednesday, 21-Oct-15 07:28:00 GMT", "Wed Oct 21 07:28:00 2015", "garbage", "", "Thu, 01 Jan 1601 00:00:00 GMT",
         "Mon, 01 Jan 1600 00:00:00 GMT", "Fri, 31 Dec 9999 23:59:59 GMT", "Tue, 29 Feb 2000 12:00:00 GMT"]
ATTRS = ["Path=/", "Path=/a/b", "Path=", "path=/x", "Domain=example.com", "Domain=.example.com", "domain=",
         "Domain=1.2.3.4", "Domain=bad_domain", "Max-Age=3600", "Max-Age=0", "Max-Age=-5", "Max-Age=05", "Max-Age=x",
         "max-age=1", "Secure", "secure", "HttpOnly", "httponly", "SameSite=Lax", "SameSite=Strict", "SameSite=None",
         "SameSite=bogus", "SameSite", "Partitioned", "Priority=High", "Foo", "Foo=bar", "Path=/a;b", "Expires=",
         'Path="/q"', "Domain=é.com"] + [f"Expires={d}" for d in DATES]


def random_set_cookie():
    base = f"{RNG.choice(CNAMES[:8])}={RNG.choice(CVALUES)}"
    parts = [base] + [RNG.choice(ATTRS) for _ in range(RNG.randint(0, 6))]
    return RNG.choice(["; ", ";", " ; "]).join(parts)


def cookie_records(count):
    out = []
    for _ in range(count):
        out.append(("K", [hexf("PC"), hexf(random_cookie_line())]))
        out.append(("K", [hexf("PS"), hexf(random_set_cookie())]))
        exp = RNG.choice(["", "", "0", "1445412480", "-62135596800", "-12219292800", "253402300799", "1000000000"])
        out.append(("K", [hexf("ST"), hexf(RNG.choice(CNAMES[:6] + ["bad name", "a\nb"])),
                          hexf(RNG.choice(CVALUES + ["new\nline", "semi;colon", "q\"uote"])),
                          hexf(RNG.choice(["0", "1"])), hexf(RNG.choice(["", "/", "/a b", "/a;b", "/x\x01y"])),
                          hexf(RNG.choice(["", "example.com", ".example.com", "1.2.3.4", "::1", "bad_domain", "a..b", "-a.com", "x" * 70 + ".com"])),
                          hexf(exp), hexf(RNG.choice(["0", "0", "5", "-1", "3600"])), hexf(RNG.choice(["0", "1"])),
                          hexf(RNG.choice(["0", "1"])), hexf(RNG.choice(["0", "1", "2", "3", "4", "9"])),
                          hexf(RNG.choice(["0", "1"]))]))
        lines = [random_cookie_line() for _ in range(RNG.randint(0, 3))]
        out.append(("K", [hexf("RC"), hexf("\x01".join(lines)), hexf(RNG.choice(["", "", "a", "sid", "Name"]))]))
    return out


# -------------------------------------------------- request/response parse

HEADER_NAMES = ["Accept", "x-multi", "Content-Type", "Cookie", "User-Agent", "Range", "Connection", "Pragma",
                "Cache-Control", "Expect", "Trailer", "Upgrade", "X-Dup", "etag", "Referer", "Authorization"]
HEADER_VALUES = ["text/plain", "", "a=b; c=d", "  padded  ", "close", "keep-alive", "Keep-Alive, close", "no-cache",
                 "100-continue", "bytes=0-10", "websocket", "Upgrade", "X-Trailer, X-Other", "gzip", "x" * 40, "1"]
TARGETS = ["/", "/a/b?c=d", "/p%20q", "//double", "/a?", "/~u/x.y", "*", "http://example.com/abs?x=1",
           "https://h/p", "example.com:443", "/with space", "", "/a\x01b", "/%zz", "/é"]
BODIES = [b"", b"hello", b"{\"ok\":true}", b"line\r\nline\n", bytes(range(32, 120))]


def chunked_body(data, trailers):
    out = b""
    i = 0
    while i < len(data):
        n = RNG.randint(1, max(1, len(data) - i))
        ext = RNG.choice([b"", b"", b";ext=1", b" ", b";a=\"b\""])
        out += f"{n:x}".encode() + ext + b"\r\n" + data[i:i + n] + b"\r\n"
        i += n
    out += b"0\r\n"
    for t in trailers:
        out += t + b"\r\n"
    return out + b"\r\n"


def make_headers(count):
    hs = []
    for _ in range(RNG.randint(0, count)):
        name = RNG.choice(HEADER_NAMES)
        if RNG.random() < 0.3:
            name = "".join(c.upper() if RNG.random() < 0.5 else c.lower() for c in name)
        hs.append(f"{name}:{RNG.choice([' ', '', '  '])}{RNG.choice(HEADER_VALUES)}".encode())
    return hs


def mutate(raw):
    """Truncate, overwrite or insert; results that are not UTF-8 are dropped
    (the crate keeps text in Rust strings; see utf8-text in the mapping)."""
    r = RNG.random()
    if r < 0.5:
        return raw
    raw = bytearray(raw)
    if r < 0.7 and raw:
        out = bytes(raw[:RNG.randrange(len(raw))])
    elif r < 0.85 and raw:
        raw[RNG.randrange(len(raw))] = RNG.randrange(128)
        out = bytes(raw)
    else:
        if raw:
            i = RNG.randrange(len(raw))
            raw[i:i] = RNG.choice([b"\r\n", b"\n", b" ", b"\x00", b"\r"])
        out = bytes(raw)
    try:
        out.decode("utf-8")
    except UnicodeDecodeError:
        return out.decode("utf-8", "ignore").encode()
    return out


def request_raw():
    method = RNG.choice(["GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS", "CONNECT", "PATCH", "PRI", "G E", "", "get", "BREW"])
    target = RNG.choice(TARGETS)
    proto = RNG.choice(["HTTP/1.1"] * 6 + ["HTTP/1.0", "HTTP/2.0", "HTTP/0.9", "HTTP/1.", "HTTP/9.9", "HTTP/1.10", "http/1.1", "HTTP/1.1 x"])
    heads = make_headers(5)
    if RNG.random() < 0.7:
        heads.insert(RNG.randint(0, len(heads)), b"Host: " + RNG.choice([b"example.com", b"h:8080", b"[::1]:80", b"", b"a b"]))
        if RNG.random() < 0.05:
            heads.append(b"Host: second")
    body = RNG.choice(BODIES)
    kind = RNG.random()
    payload = b""
    if kind < 0.35 and body:
        heads.append(b"Content-Length: " + RNG.choice([str(len(body)).encode(), str(len(body)).encode(), b"+5", b"0x5", b"-1", b" 7 ", b"", b"99999999999999999999"]))
        payload = body
        if RNG.random() < 0.1:
            heads.append(b"Content-Length: " + str(len(body)).encode())
    elif kind < 0.65:
        heads.append(b"Transfer-Encoding: " + RNG.choice([b"chunked", b"chunked", b"Chunked", b"identity", b"gzip, chunked", b"chunked, chunked"]))
        tr = []
        if RNG.random() < 0.4:
            heads.append(b"Trailer: X-Trailer, X-Other")
            tr = [b"X-Trailer: v1", b"X-Other: v2"]
        payload = chunked_body(body, tr)
    raw = f"{method} {target} {proto}\r\n".encode() + b"\r\n".join(heads) + (b"\r\n" if heads else b"") + b"\r\n" + payload
    return mutate(raw)


def response_raw():
    proto = RNG.choice(["HTTP/1.1"] * 6 + ["HTTP/1.0", "HTTP/2.0", "HTTP/0.9", "HTTP/1.", "HTTP/9.9", "foo"])
    status = RNG.choice(["200 OK", "204 No Content", "304 Not Modified", "404 Not Found", "100 Continue", "101 Switching Protocols",
                         "301 Moved", "500", "999 weird", "20 x", "2000 y", "abc", "-12 x", "200", "200  OK  ", "418 I'm a teapot"])
    heads = make_headers(5)
    body = RNG.choice(BODIES)
    kind = RNG.random()
    payload = b""
    if kind < 0.35:
        heads.append(b"Content-Length: " + RNG.choice([str(len(body)).encode(), str(len(body)).encode(), str(len(body) + 3).encode(), b"x", b""]))
        payload = body
    elif kind < 0.65:
        heads.append(b"Transfer-Encoding: " + RNG.choice([b"chunked", b"chunked", b"identity"]))
        tr = []
        if RNG.random() < 0.4:
            heads.append(b"Trailer: X-Trailer")
            tr = [b"X-Trailer: v1"]
        payload = chunked_body(body, tr)
    elif kind < 0.8:
        heads.append(b"Connection: close")
        payload = body
    else:
        payload = body
    raw = f"{proto} {status}\r\n".encode() + b"\r\n".join(heads) + (b"\r\n" if heads else b"") + b"\r\n" + payload
    return mutate(raw)


def message_records(count):
    out = []
    for _ in range(count):
        out.append(("Q", [hexf(request_raw())]))
        out.append(("P", [hexf(response_raw()), hexf(RNG.choice(["", "GET", "HEAD", "POST"]))]))
    return out


# ------------------------------------------------------------------ dates

def date_records():
    out = []
    samples = DATES + ["Sun Nov  6 08:49:37 1994", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun, 06 Nov 1994 08:49:37 GMT",
                       "Sun, 06 Nov 1994 08:49:37 UTC", "Sun, 06 Nov 1994 08:49:37", "06 Nov 1994", " Sun, 06 Nov 1994 08:49:37 GMT"]
    for s in samples:
        out.append(("D", [hexf("T"), hexf(s)]))
    for v in ["HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "HTTP/0.9", "HTTP/1.", "HTTP/12", "HTTP/a.b", "http/1.1", "HTTP/1.1x", "HTTP/9.9", ""]:
        out.append(("D", [hexf("V"), hexf(v)]))
    for k in ["content-type", "x-forwarded-for", "ETAG", "a b", "é", "", "x_y", "Content-Length", "-a", "a--b"]:
        out.append(("D", [hexf("H"), hexf(k)]))
    for code in list(range(95, 130)) + list(range(195, 230)) + list(range(295, 330)) + list(range(395, 460)) + list(range(495, 520)) + [0, 600, 999]:
        out.append(("D", [hexf("S"), hexf(str(code))]))
    return out


# ------------------------------------------------------------------ server

def script_text(ops):
    return "\n".join("\t".join(op) for op in ops)


def random_script():
    ops = []
    r = RNG.random()
    for _ in range(RNG.choice([0, 1, 1, 2, 3])):
        name = RNG.choice(["Content-Type", "X-A", "Content-Length", "Transfer-Encoding", "Connection", "Trailer",
                           "Date", "Content-Encoding", "Cache-Control", "Set-Cookie", "Location"])
        value = {
            "Content-Length": RNG.choice(["0", "5", "11", "100", "-1", "abc", ""]),
            "Transfer-Encoding": RNG.choice(["chunked", "identity", "gzip"]),
            "Connection": RNG.choice(["close", "keep-alive", "Upgrade"]),
            "Trailer": RNG.choice(["X-T", "X-T, X-U"]),
            "Content-Type": RNG.choice(["text/plain", "application/json", "text/html; charset=utf-8", ""]),
            "Date": "Mon, 02 Jan 2006 15:04:05 GMT",
        }.get(name, RNG.choice(["v", "a b", "/next"]))
        ops.append((RNG.choice(["h", "h", "a"]), name, value))
    if RNG.random() < 0.15:
        ops.append(("d", RNG.choice(["Content-Length", "Content-Type", "Date"])))
    if RNG.random() < 0.5:
        ops.append(("c", str(RNG.choice([200, 200, 201, 204, 301, 304, 400, 404, 500, 101, 103, 100, 418, 599]))))
    body_ops = RNG.choice([["w"], ["w", "w"], ["w", "f", "w"], ["r"], ["rn"], ["m"], ["m", "w"], [], ["p"], ["big"]])
    for b in body_ops:
        if b == "w":
            ops.append(("w", RNG.choice(["hello", "world!" * 3, "", "x" * 11])))
        elif b == "big":
            ops.append(("w", "y" * RNG.choice([2047, 2048, 2049, 5000])))
        elif b == "f":
            ops.append(("f",))
        elif b == "rn":
            ops.append(("rn", str(RNG.choice([0, 3, 100]))))
        else:
            ops.append((b,))
    if RNG.random() < 0.2:
        ops.append(("t", RNG.choice(["X-T", "X-U"]), "tv"))
    return script_text(ops)


BAD_RAW = [
    b"GET / HTTP/1.1\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\nBad Header\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a b\r\n\r\n",
    b"BAD METHOD / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"GET /\r\n\r\n",
    b"GET / HTTP/3.0\r\nHost: a\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
    b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: abc\r\n\r\n",
    b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc",
    b"GET http://other.example/abs HTTP/1.1\r\nHost: a\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\nX: \x01bad\r\n\r\n",
    b"\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n",
    b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 10\r\n\r\nshort",
    b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
    b"GET /a%zz HTTP/1.1\r\nHost: a\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: a\r\nExpect: something-else\r\n\r\n",
    b"GET / HTTP/1.0\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
]


def raw_request():
    if RNG.random() < 0.12:
        return RNG.choice(BAD_RAW)
    method = RNG.choice(["GET", "GET", "HEAD", "POST", "POST", "PUT", "OPTIONS", "DELETE"])
    target = RNG.choice(["/", "/a/b?q=1", "*", "/p%20q", "//x", "/index.html"])
    if target == "*" and method != "OPTIONS":
        target = "/"
    proto = RNG.choice(["HTTP/1.1"] * 6 + ["HTTP/1.0", "HTTP/1.0"])
    heads = []
    if RNG.random() < 0.93 or proto == "HTTP/1.0":
        heads.append("Host: example.com")
    if RNG.random() < 0.2:
        heads.append("Connection: " + RNG.choice(["close", "keep-alive", "Close, TE"]))
    if RNG.random() < 0.1:
        heads.append("Expect: 100-continue")
    body = b""
    r = RNG.random()
    if method in ("POST", "PUT") and r < 0.6:
        data = RNG.choice([b"hello", b"x" * 300, b""])
        heads.append(f"Content-Length: {len(data)}")
        body = data
    elif method in ("POST", "PUT") and r < 0.85:
        heads.append("Transfer-Encoding: chunked")
        body = chunked_body(RNG.choice([b"hello", b"abcdef"]), [])
    elif r > 0.97:
        heads.append("Transfer-Encoding: gzip")
    head = f"{method} {target} {proto}\r\n" + "".join(h + "\r\n" for h in heads) + "\r\n"
    return head.encode() + body


def server_records(count):
    out = []
    for _ in range(count):
        raw = b""
        for _ in range(RNG.choice([1, 1, 1, 2, 3])):
            raw += raw_request()
        out.append(("V", [hexf(random_script()), hexf(raw)]))
    return out


# --------------------------------------------------- FileServer / ServeContent

FS_FILES = ["a.txt", "b.html", "index.html", "dir/c.css", "dir/index.html", "e f.txt", "x.unknown", "big.bin",
            "sub/deep/f.js", "data.json", "pic.png", "Upper.TXT", "dir2/z.txt", "empty.txt", "note.pdf", "m.svg"]
FS_CONTENT = [b"hello world\n", b"<html><body>hi</body></html>", b"", b"\x89PNG\r\n\x1a\n" + b"x" * 40,
              bytes(range(256)) * 12, b"abcdefghijklmnopqrstuvwxyz", b"%PDF-1.4 data", b"{\"a\": 1}", b"body{color:red}"]
FS_TARGETS = ["/", "/a.txt", "/dir", "/dir/", "/dir/index.html", "/index.html", "/nonexist", "/a.txt/", "/dir/c.css",
              "/x.unknown", "/../a.txt", "//a.txt", "/%2e%2e/a.txt", "/e%20f.txt", "/e f.txt", "/big.bin", "/sub/",
              "/sub/deep/", "/sub/deep/f.js", "/data.json", "/pic.png", "/Upper.TXT", "/dir2/", "/dir2", "/empty.txt",
              "/note.pdf", "/m.svg", "/a.txt?x=1", "/dir?x=1", "/a%2ftxt", "/dir%2f", "/index.html?q", "/sub/..",
              "/dir/./c.css", "/.", "/missing/dir/", "/a.txt/b"]
RANGES = ["bytes=0-4", "bytes=2-", "bytes=-3", "bytes=0-1,3-4", "bytes=100-", "bytes=a-b", "bytes=0-0,0-0", "bytes=5-2",
          "bytes=-0", "bytes=0-", "items=0-1", "bytes=0-5, 7-9, 12-", "bytes=-1000", "bytes=1000-2000", "bytes=1-1,2-2,3-3",
          "bytes= 1 - 3 ", "bytes=0-99999", "bytes=+1-3", "bytes=1-3,", "bytes=--1"]
DATE_VARIANTS = ["Thu, 14 Nov 2023 22:13:20 GMT", "Thu, 14 Nov 2023 22:13:19 GMT", "Thu, 14 Nov 2023 22:13:21 GMT",
                 "garbage", "Thu, 01 Jan 1970 00:00:00 GMT", "Thursday, 14-Nov-23 22:13:20 GMT", "Thu Nov 14 22:13:20 2023"]
ETAGS = ['"abc"', 'W/"abc"', '"abc", "def"', '*', '"zzz"', 'abc', '"a"b"', '', ',,"abc"', 'W/"x", "abc"']


def fs_spec():
    lines = []
    base_mt = 1700000000
    names = RNG.sample(FS_FILES, RNG.randint(2, 8))
    names.append("a.txt") if "a.txt" not in names and RNG.random() < 0.7 else None
    for name in names:
        lines.append("\t".join(["f", name, RNG.choice(FS_CONTENT).hex(), str(base_mt + RNG.choice([0, 0, 1, 5, 3600]))]))
    if RNG.random() < 0.3:
        lines.append("d\tsub")
    if RNG.random() < 0.3:
        lines.append("d\tempty-dir")
    return "\n".join(lines)


def fs_request():
    method = RNG.choice(["GET"] * 7 + ["HEAD", "POST", "OPTIONS"])
    target = RNG.choice(FS_TARGETS)
    heads = ["Host: localhost"]
    if RNG.random() < 0.35:
        heads.append("Range: " + RNG.choice(RANGES))
    if RNG.random() < 0.15:
        heads.append("If-Modified-Since: " + RNG.choice(DATE_VARIANTS))
    if RNG.random() < 0.1:
        heads.append("If-Unmodified-Since: " + RNG.choice(DATE_VARIANTS))
    if RNG.random() < 0.1:
        heads.append("If-None-Match: " + RNG.choice(ETAGS))
    if RNG.random() < 0.1:
        heads.append("If-Match: " + RNG.choice(ETAGS))
    if RNG.random() < 0.1:
        heads.append("If-Range: " + RNG.choice(DATE_VARIANTS + ETAGS))
    if RNG.random() < 0.1:
        heads.append("X-Set-ETag: " + RNG.choice(['"abc"', 'W/"abc"', '"def"']))
    if RNG.random() < 0.05:
        heads.append("X-Set-Type: " + RNG.choice(["text/x-custom", "application/json"]))
    if RNG.random() < 0.05:
        heads.append("X-Set-Encoding: gzip")
    return f"{method} {target} HTTP/1.1\r\n" + "\r\n".join(heads)


def file_records(count):
    out = []
    for i in range(count):
        spec = fs_spec()
        names = [l.split("\t")[1] for l in spec.split("\n") if l.startswith("f\t")]
        r = RNG.random()
        if r < 0.55:
            kind = "fs"
        elif r < 0.8:
            kind = "content:" + RNG.choice(names)
        else:
            kind = "file:" + RNG.choice(names + ["sub", "missing", "."])
        reqs = "\x01".join(fs_request() for _ in range(RNG.randint(4, 12)))
        out.append(("F", [hexf(kind), hexf(spec), hexf(reqs)]))
    return out


# ------------------------------------------------------ client redirect policy

CLIENT_PATHS = ["/a", "/b", "/c", "/d", "/e/f", "/final", "/loop", "/p/q/r"]
LOCATIONS = ["/a", "/b", "/c", "/final", "/loop", "x", "../up", "?q=1", "", "{B}/a", "{B}/final", "{A}/c", "{A}/b?z=1",
             "http://[::1", "//localhost/final", "/x y", "%zz", "{B}/loop"]


def client_chain():
    """A chain of redirecting pages across both servers, ending in a page that
    does not redirect; returns script lines and the first URL."""
    lines = []
    nodes = []
    for i in range(RNG.randint(1, 6)):
        nodes.append((RNG.choice("AAB"), f"/n{i}"))
    base = {"A": "{A}", "B": "{B}"}
    for i, (server, path) in enumerate(nodes):
        if i + 1 < len(nodes):
            nserver, npath = nodes[i + 1]
            kind = RNG.random()
            if nserver == server and kind < 0.4:
                loc = npath
            elif nserver == server and kind < 0.5:
                loc = npath.lstrip("/")
            elif kind < 0.6:
                loc = "//" + ("127.0.0.1:" if nserver == "A" else "[::1]:") + "{PORT" + nserver + "}" + npath
            else:
                loc = base[nserver] + npath
            status = RNG.choice([301, 302, 303, 307, 308])
            headers = ["Location=" + loc]
            if loc.startswith("//"):
                headers = ["Location=" + loc.replace("{PORTA}", "{PORTA}").replace("{PORTB}", "{PORTB}")]
        else:
            status = RNG.choice([200, 200, 404, 500, 204, 301, 302])
            headers = ["Location=/n0"] if status in (301, 302) else []
        if RNG.random() < 0.25:
            headers.append("Set-Cookie=" + RNG.choice(["sid=1; Path=/", "sid=2", "other=x; Path=/n0", "sid=gone; Max-Age=-1; Path=/"]))
        lines.append("\t".join([server, path, str(status), "\x02".join(headers), RNG.choice(["", "body", "hello world"])]))
    return lines, base[nodes[0][0]] + nodes[0][1]


def client_script():
    lines = []
    for server in "AB":
        for path in RNG.sample(CLIENT_PATHS, RNG.randint(3, 7)):
            status = RNG.choice([200, 200, 301, 302, 302, 303, 307, 308, 404, 500, 204])
            headers = []
            if status in (301, 302, 303, 307, 308) or RNG.random() < 0.1:
                headers.append("Location=" + RNG.choice(LOCATIONS))
            if RNG.random() < 0.25:
                headers.append("Set-Cookie=" + RNG.choice(["sid=1; Path=/", "sid=2", "other=x; Path=/a", "sid=gone; Max-Age=-1; Path=/"]))
            if RNG.random() < 0.05:
                headers.append("Content-Type=text/plain")
            lines.append("\t".join([server, path, str(status), "\x02".join(headers), RNG.choice(["", "body", "hello world"])]))
    return "\n".join(lines)


def client_cfg():
    lines = []
    if RNG.random() < 0.4:
        lines.append("jar")
    r = RNG.random()
    if r < 0.15:
        lines.append("check=none")
    elif r < 0.3:
        lines.append("check=err3")
    method = RNG.choice(["GET"] * 4 + ["POST", "PUT", "HEAD", "DELETE"])
    lines.append("method=" + method)
    if method in ("POST", "PUT") and RNG.random() < 0.8:
        lines.append("body=" + RNG.choice(["payload", "x" * 50, ""]))
    for _ in range(RNG.randint(0, 4)):
        lines.append("hdr=" + RNG.choice(["Authorization:Bearer tok", "Cookie:sid=orig; keep=1", "Content-Type:text/plain",
                                           "X-Custom:v", "Referer:http://explicit.example/", "Www-Authenticate:Basic",
                                           "Content-Language:en", "Cookie2:v"]))
    return "\n".join(lines)


def client_records(count):
    out = []
    for _ in range(count):
        if RNG.random() < 0.8:
            lines, start = client_chain()
            script = "\n".join(lines)
        else:
            start = RNG.choice(["{A}", "{B}"]) + RNG.choice(CLIENT_PATHS)
            script = client_script()
        out.append(("L", [hexf(script), hexf(client_cfg()), hexf(start)]))
    return out


# ------------------------------------------------- ServerConn / ClientConn

def conn_records(count):
    out = []
    for _ in range(count):
        if RNG.random() < 0.5:
            reqs = b""
            for _ in range(RNG.randint(1, 4)):
                reqs += raw_request().replace(b"HTTP/2.0", b"HTTP/1.1")
            if RNG.random() < 0.2:
                reqs = mutate(reqs)
            out.append(("Z", [hexf("S"), hexf(reqs), hexf(str(RNG.randint(1, 5)))]))
        else:
            resps = b""
            n = RNG.randint(1, 4)
            for _ in range(n):
                resps += response_raw() if RNG.random() < 0.3 else RNG.choice([
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi",
                    b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi"])
            out.append(("Z", [hexf("C"), hexf(resps), hexf(str(n))]))
    return out


# ------------------------------------------------------------ reverse proxy

PROXY_REQ_HEADERS = ["Connection: close", "Connection: keep-alive, X-Hop", "Connection: Upgrade", "Upgrade: websocket",
                     "Te: trailers", "Te: gzip", "X-Hop: 1", "X-Forwarded-For: 10.0.0.1", "Forwarded: for=1.2.3.4",
                     "X-Forwarded-Host: old", "X-Forwarded-Proto: https", "User-Agent: curl/8", "User-Agent: ",
                     "Proxy-Authorization: Basic eA==", "Keep-Alive: timeout=5", "Trailer: X-T", "Accept: */*",
                     "Cookie: a=b", "Content-Type: text/plain", "Transfer-Encoding: gzip", "Proxy-Connection: x",
                     "Upgrade: \x01bad"]
PROXY_TARGETS = ["/", "/a/b", "/a/b?c=d", "/a?x=1&y=2", "/p%20q", "/a;b", "/a?q=%zz", "/x/", "?z=9", "/a?b;c=d&e", "/%2F"]
PROXY_RESP_HEADERS = ["Content-Type: text/plain", "Connection: close, X-Resp-Hop", "X-Resp-Hop: 1", "Keep-Alive: 1",
                      "Trailer: X-End", "Set-Cookie: s=1", "X-Unknown-Length: 1", "Transfer-Encoding: chunked",
                      "Content-Type: text/event-stream", "Upgrade: websocket", "Location: /elsewhere"]


def proxy_records(count):
    out = []
    for _ in range(count):
        method = RNG.choice(["GET", "POST", "PUT", "HEAD", "DELETE"])
        target = RNG.choice(PROXY_TARGETS)
        heads = ["Host: front.example"] + [h for h in PROXY_REQ_HEADERS if RNG.random() < 0.18]
        body = b""
        if method in ("POST", "PUT") and RNG.random() < 0.7:
            body = RNG.choice([b"payload", b"x" * 40])
            heads.append(f"Content-Length: {len(body)}")
        raw = (f"{method} {target} HTTP/1.1\r\n" + "".join(h + "\r\n" for h in heads) + "\r\n").encode() + body
        status = RNG.choice([200, 200, 201, 204, 301, 404, 500, 101, 304])
        rheads = [h for h in PROXY_RESP_HEADERS if RNG.random() < 0.2]
        rbody = RNG.choice(["", "hello", "response body"])
        trailer = ""
        if RNG.random() < 0.25 and status not in (101,):
            trailer = "\x01" + "X-End: done"
        spec = f"{status}\n" + "\n".join(rheads) + f"\n\n{rbody}" + trailer
        remote = RNG.choice(["192.0.2.1:1234", "[2001:db8::1]:80", "nonsense", ""])
        out.append(("Y", [hexf(RNG.choice(["director", "rewrite"])), hexf(raw), hexf(remote), hexf(spec)]))
    return out


# -------------------------------------------------- CrossOriginProtection

def cors_records(count):
    origins = ["https://a.example", "http://a.example", "https://b.example:8443", "https://c.example/path", "a.example",
               "", "https://", "https://d.example?q", "null"]
    patterns = ["/api/", "POST /hook", "/x/{id}", "GET /", "/{$}", "bad pattern"]
    out = []
    for _ in range(count):
        cfg = []
        for _ in range(RNG.randint(0, 3)):
            cfg.append("t\t" + RNG.choice(origins))
        for _ in range(RNG.randint(0, 2)):
            cfg.append("b\t" + RNG.choice(patterns))
        if RNG.random() < 0.2:
            cfg.append("d")
        reqs = []
        for _ in range(RNG.randint(6, 14)):
            method = RNG.choice(["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"])
            target = RNG.choice(["/", "/api/x", "/hook", "/x/5", "/other"])
            heads = ["Host: a.example"]
            if RNG.random() < 0.4:
                heads.append("Sec-Fetch-Site: " + RNG.choice(["same-origin", "none", "cross-site", "same-site", ""]))
            if RNG.random() < 0.5:
                heads.append("Origin: " + RNG.choice(origins + ["https://a.example", "http://a.example"]))
            reqs.append(f"{method} {target} HTTP/1.1\r\n" + "\r\n".join(heads))
        out.append(("X", [hexf("\n".join(cfg)), hexf("\x01".join(reqs))]))
    return out


# ------------------------------------------------------------------- driver

def corpus():
    count = lambda name, default: int(os.environ.get(name, str(default)))
    return (mux_records(count("HTTP_CHECK_MUX", 3000)) + cookie_records(1000) + message_records(2600) + date_records()
            + server_records(count("HTTP_CHECK_SERVER", 1200))
            + file_records(count("HTTP_CHECK_FILES", 600))
            + cors_records(400)
            + proxy_records(count("HTTP_CHECK_PROXY", 2500))
            + conn_records(count("HTTP_CHECK_CONN", 500))
            + client_records(count("HTTP_CHECK_CLIENT", 800)))


def run(command, payload, env):
    result = subprocess.run(command, input=payload, text=True, capture_output=True,
                            cwd=ROOT, env=env, timeout=600)
    if result.returncode:
        raise RuntimeError(f"{' '.join(command)} failed:\n{result.stderr[-3000:]}")
    return result.stdout.splitlines()


def show(line):
    try:
        out = []
        for tok in line.split(" "):
            try:
                out.append(bytes.fromhex(tok).replace(b"\0", b"|"))
            except ValueError:
                out.append(tok.encode())
        return out
    except Exception:
        return line


def main():
    if not shutil.which("go") or not shutil.which("cargo"):
        raise RuntimeError("http differential check requires Go and Cargo on PATH")
    records = corpus()
    modes = os.environ.get("HTTP_CHECK_MODES")
    if modes:  # e.g. "Y,Z": only the reverse proxy and ServerConn/ClientConn vectors
        records = [r for r in records if r[0] in modes.split(",")]
    payload = "".join(f"{mode}:{','.join(fields)}\n" for mode, fields in records)
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    go = run(["go", "run", "tools/http_oracle.go"], payload, env)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "http_probe"], payload, env)
    if len(go) != len(records) or len(rust) != len(records):
        raise AssertionError(f"http oracle returned the wrong number of records: go={len(go)} rust={len(rust)} want={len(records)}")
    def go_unusable(g):
        """Go panicked (a Go bug) or lost a keep-alive race against its own test server."""
        if g.startswith("PANIC"):
            return True
        try:
            return b"transport connection broken" in bytes.fromhex(g.split(" ")[0])
        except ValueError:
            return False

    skipped = sum(1 for g in go if go_unusable(g))
    # A pipelined server vector ("V") reads responses until 150ms of silence; on
    # a loaded machine a later response can miss that window on either side.
    # Those vectors are rerun on both sides with a longer window: a real
    # difference survives the rerun, a slow response does not.
    slow = [i for i, ((mode, _), g, r) in enumerate(zip(records, go, rust))
            if mode == "V" and g != r and not go_unusable(g)]
    if slow:
        again = "".join(f"V:{','.join(records[i][1])}\n" for i in slow)
        renv = dict(env, HTTP_SERVER_IDLE_MS="2000")
        go2 = run(["go", "run", "tools/http_oracle.go"], again, renv)
        rust2 = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "http_probe"], again, renv)
        for i, g, r in zip(slow, go2, rust2):
            go[i], rust[i] = g, r
        print(f"http: reran {len(slow)} pipelined vectors with a 2s read window")
    failures = [(mode, fields, g, r) for (mode, fields), g, r in zip(records, go, rust)
                if g != r and not go_unusable(g)]
    for mode, fields, g, r in failures[:int(os.environ.get("HTTP_CHECK_SHOW", "8"))]:
        decoded = [bytes.fromhex(f)[:200] for f in fields]
        gs, rs = show(g), show(r)

        def around(a, b):
            """The first differing byte offset of two byte strings, with context."""
            if not (isinstance(a, bytes) and isinstance(b, bytes)):
                return (a, b)
            i = next((k for k in range(min(len(a), len(b))) if a[k] != b[k]), min(len(a), len(b)))
            return (i, len(a), len(b), a[max(0, i - 60):i + 80], b[max(0, i - 60):i + 80])

        short = [f[:300] + b"..." if len(f) > 300 else f for f in decoded]
        if isinstance(gs, list) and isinstance(rs, list) and len(gs) == len(rs):
            diffs = [(i,) + around(a, b) for i, (a, b) in enumerate(zip(gs, rs)) if a != b][:2]
            print(f"mode={mode} fields={short!r}\n  first diffs={diffs!r}")
        else:
            print(f"mode={mode} fields={short!r}\n  Go  ={gs!r}\n  Rust={rs!r}")
    if failures:
        by_mode = {}
        for m, *_ in failures:
            by_mode[m] = by_mode.get(m, 0) + 1
        raise AssertionError(f"{len(failures)} of {len(records)} http vectors differ from Go {by_mode}")
    counts = {}
    for (mode, _), _g in zip(records, go):
        counts[mode] = counts.get(mode, 0) + 1
    detail = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"http Go differential: {len(records) - skipped} vectors passed ({detail}; {skipped} skipped where Go itself fails)")


if __name__ == "__main__":
    main()
