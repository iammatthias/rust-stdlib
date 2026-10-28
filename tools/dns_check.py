#!/usr/bin/env python3
"""Differentially check the pure DNS resolver against Go's (Resolver{PreferGo: true}).

A local fake DNS server (UDP and TCP, in this script) answers both implementations.
Every lookup kind is compared on its results and error fields, and the fake server's
log of received queries (transport and exact bytes except the random ID) must be
identical for the two clients: same questions, same EDNS0 OPT record, same retries
over TCP and across servers/attempts.

Names use the ".test." zone with trailing dots so neither /etc/hosts nor the
resolv.conf search list takes part. Randomised orders (MX preference ties, SRV weight
shuffles) are compared after sorting.
"""
import pathlib
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]

QR, AA, TC, RD, RA = 0x8000, 0x0400, 0x0200, 0x0100, 0x0080
A, NS, CNAME, PTR, MX, TXT, AAAA, SRV, OPT = 1, 2, 5, 12, 15, 16, 28, 33, 41


def wire_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("latin-1")
    return out + b"\0"


def rr(owner, typ, rdata, ttl=60, cls=1):
    owner = owner if isinstance(owner, bytes) else wire_name(owner)
    return owner + struct.pack(">HHIH", typ, cls, ttl, len(rdata)) + rdata


def a_rdata(ip):
    return socket.inet_pton(socket.AF_INET, ip)


def aaaa_rdata(ip):
    return socket.inet_pton(socket.AF_INET6, ip)


def txt_rdata(*strings):
    return b"".join(bytes([len(s)]) + s for s in strings)


def mx_rdata(pref, host):
    return struct.pack(">H", pref) + wire_name(host)


def srv_rdata(prio, weight, port, host):
    return struct.pack(">HHH", prio, weight, port) + wire_name(host)


class Query:
    def __init__(self, data, transport):
        self.data = data
        self.transport = transport
        self.id, self.flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        off = 12
        labels = []
        while data[off]:
            n = data[off]
            labels.append(data[off + 1:off + 1 + n].decode("latin-1"))
            off += n + 1
        off += 1
        self.qname = ".".join(labels) + "."
        self.qtype, self.qclass = struct.unpack(">HH", data[off:off + 4])
        self.question = data[12:off + 4]
        self.qd, self.ar = qd, ar

    @property
    def label(self):
        return self.qname.split(".")[0].lower()


def reply(q, rcode=0, flags=RA, answers=(), auth=(), add=(), question=None, id=None, extra=0):
    hdr = struct.pack(">HHHHHH", q.id if id is None else id, QR | RD | flags | rcode | extra, 1,
                      len(answers), len(auth), len(add))
    return hdr + (question or q.question) + b"".join(answers) + b"".join(auth) + b"".join(add)


def opt_rr(ext_rcode=0):
    return rr(b"\0", OPT, b"", ttl=ext_rcode << 24, cls=1232)


# --- scenarios: label -> (lookup script lines, handler(q) -> list of packets) ---

SCENARIOS = {}


def scenario(label, lines, strict=False):
    def deco(fn):
        SCENARIOS[label] = (lines, fn)
        return fn
    return deco


def nm(label):
    return f"{label}.test."


@scenario("ok2", [f"host {nm('ok2')}", f"ip ip {nm('ok2')}", f"ip ip4 {nm('ok2')}", f"ip ip6 {nm('ok2')}", f"netip ip {nm('ok2')}",
                  f"ipaddr {nm('ok2')}", f"cname {nm('ok2')}"])
def _(q):
    o = q.qname
    if q.qtype == A:
        return [reply(q, answers=[rr(o, A, a_rdata("192.0.2.1")), rr(o, A, a_rdata("192.0.2.2"))])]
    if q.qtype == AAAA:
        return [reply(q, answers=[rr(o, AAAA, aaaa_rdata("2001:db8::1"))])]
    return [reply(q)]


@scenario("v4only", [f"host {nm('v4only')}", f"ip ip {nm('v4only')}"])
def _(q):
    if q.qtype == A:
        return [reply(q, answers=[rr(q.qname, A, a_rdata("127.0.0.1"))])]
    return [reply(q)]


@scenario("loop", [f"host {nm('loop')}", f"ip ip6 {nm('loop')}"])
def _(q):
    if q.qtype == AAAA:
        return [reply(q, answers=[rr(q.qname, AAAA, aaaa_rdata("::1")), rr(q.qname, AAAA, aaaa_rdata("2001:db8::7"))])]
    return [reply(q, answers=[rr(q.qname, A, a_rdata("127.0.0.1")), rr(q.qname, A, a_rdata("198.51.100.9"))])]


@scenario("nx", [f"host {nm('nx')}", f"ip ip {nm('nx')}", f"cname {nm('nx')}", f"mx {nm('nx')}", f"txt {nm('nx')}",
                 f"ns {nm('nx')}", f"srv - - {nm('nx')}"])
def _(q):
    return [reply(q, rcode=3)]


@scenario("servfail", [f"host {nm('servfail')}", f"host {nm('servfail')} strict", f"mx {nm('servfail')}", f"txt {nm('servfail')}"])
def _(q):
    return [reply(q, rcode=2)]


@scenario("refused", [f"host {nm('refused')}", f"mx {nm('refused')}"])
def _(q):
    return [reply(q, rcode=5)]


@scenario("formerr", [f"host {nm('formerr')}"])
def _(q):
    return [reply(q, rcode=1)]


@scenario("lame", [f"host {nm('lame')}", f"txt {nm('lame')}"])
def _(q):
    return [reply(q, flags=0)]


@scenario("authempty", [f"host {nm('authempty')}", f"txt {nm('authempty')}"])
def _(q):
    return [reply(q, flags=AA)]


@scenario("additional", [f"host {nm('additional')}", f"txt {nm('additional')}"])
def _(q):
    return [reply(q, flags=0, add=[rr("x.test.", A, a_rdata("1.1.1.1"))])]


@scenario("wrongtype", [f"host {nm('wrongtype')}", f"mx {nm('wrongtype')}"])
def _(q):
    return [reply(q, answers=[rr(q.qname, TXT, txt_rdata(b"hello"))])]


@scenario("cname1", [f"cname {nm('cname1')}", f"host {nm('cname1')}"])
def _(q):
    # One hop: the CNAME target is also the A record's owner, so every lane agrees on the name.
    t = "target.test."
    ans = [rr(q.qname, CNAME, wire_name(t))]
    if q.qtype == A:
        ans.append(rr(t, A, a_rdata("192.0.2.45")))
    return [reply(q, answers=ans)]


@scenario("cnamechain", [f"host {nm('cnamechain')}", f"ip ip4 {nm('cnamechain')}"])
def _(q):
    t1, t2 = "mid.test.", "final.test."
    ans = [rr(q.qname, CNAME, wire_name(t1)), rr(t1, CNAME, wire_name(t2))]
    if q.qtype == A:
        ans.append(rr(t2, A, a_rdata("192.0.2.44")))
    elif q.qtype == CNAME:
        return [reply(q, answers=ans[:1])]
    return [reply(q, answers=ans)]


@scenario("cnameonly", [f"cname {nm('cnameonly')}", f"host {nm('cnameonly')}"])
def _(q):
    return [reply(q, answers=[rr(q.qname, CNAME, wire_name("elsewhere.test."))])]


@scenario("trunc", [f"host {nm('trunc')}", f"txt {nm('trunc')}"])
def _(q):
    if q.transport == "udp":
        return [reply(q, extra=TC, answers=[rr(q.qname, A, a_rdata("10.9.9.9"))] if q.qtype == A else [])]
    if q.qtype == A:
        return [reply(q, answers=[rr(q.qname, A, a_rdata("192.0.2.%d" % i)) for i in range(1, 5)])]
    if q.qtype == TXT:
        return [reply(q, answers=[rr(q.qname, TXT, txt_rdata(b"via tcp"))])]
    return [reply(q)]


@scenario("tctcp", [f"host {nm('tctcp')}"])
def _(q):
    if q.qtype == A:
        return [reply(q, extra=TC, answers=[rr(q.qname, A, a_rdata("203.0.113.5"))])]
    return [reply(q, extra=TC)]


@scenario("bogus", [f"host {nm('bogus')}", f"txt {nm('bogus')}"])
def _(q):
    ok = reply(q, answers=[rr(q.qname, A, a_rdata("192.0.2.77"))] if q.qtype == A else
               ([rr(q.qname, TXT, txt_rdata(b"real"))] if q.qtype == TXT else []))
    if q.transport != "udp":
        return [ok]
    wrong_id = reply(q, id=(q.id + 1) & 0xFFFF, answers=[rr(q.qname, A, a_rdata("6.6.6.6"))])
    wrong_q = reply(q, question=wire_name("other.test.") + struct.pack(">HH", q.qtype, 1),
                    answers=[rr(q.qname, A, a_rdata("6.6.6.7"))])
    return [b"\x00\x01garbage", wrong_id, wrong_q, ok]


@scenario("notresp", [f"host {nm('notresp')}"])
def _(q):
    pkt = bytearray(reply(q, answers=[rr(q.qname, A, a_rdata("6.6.6.6"))]))
    pkt[2] &= 0x7F  # QR cleared: a query, not a response
    good = reply(q, answers=[rr(q.qname, A, a_rdata("192.0.2.8"))]) if q.qtype == A else reply(q)
    return [bytes(pkt), good] if q.transport == "udp" else [good]


@scenario("upper", [f"host {nm('upper')}", f"txt {nm('upper')}"])
def _(q):
    up = wire_name(q.qname.upper()) + struct.pack(">HH", q.qtype, q.qclass)
    ans = [rr(q.qname, A, a_rdata("192.0.2.9"))] if q.qtype == A else ([rr(q.qname, TXT, txt_rdata(b"Up"))] if q.qtype == TXT else [])
    return [reply(q, question=up, answers=ans)]


@scenario("extrcode", [f"host {nm('extrcode')}", f"txt {nm('extrcode')}"])
def _(q):
    return [reply(q, add=[opt_rr(1)])]


@scenario("optok", [f"host {nm('optok')}", f"txt {nm('optok')}"])
def _(q):
    ans = [rr(q.qname, A, a_rdata("192.0.2.12"))] if q.qtype == A else ([rr(q.qname, TXT, txt_rdata(b"opt"))] if q.qtype == TXT else [])
    return [reply(q, answers=ans, add=[opt_rr(0)])]


@scenario("compress", [f"host {nm('compress')}", f"mx {nm('compress')}", f"ns {nm('compress')}", f"srv - - {nm('compress')}",
                       f"cname {nm('compress')}", f"txt {nm('compress')}"])
def _(q):
    # Owner and rdata names as pointers: the owner points at the question name (offset 12),
    # rdata names point into earlier labels.
    owner = b"\xc0\x0c"
    if q.qtype == A:
        return [reply(q, answers=[rr(b"\x05alias\xc0\x0c", A, a_rdata("192.0.2.31"))])]
    if q.qtype == MX:
        return [reply(q, answers=[rr(owner, MX, struct.pack(">H", 5) + b"\x04mail\xc0\x0c"),
                                  rr(owner, MX, struct.pack(">H", 5) + b"\x05mail2\xc0\x0c")])]
    if q.qtype == NS:
        return [reply(q, answers=[rr(owner, NS, b"\x03ns1\xc0\x0c")])]
    if q.qtype == SRV:
        return [reply(q, answers=[rr(owner, SRV, struct.pack(">HHH", 1, 2, 80) + b"\x03srv\xc0\x0c")])]
    if q.qtype == CNAME:
        return [reply(q, answers=[rr(owner, CNAME, b"\x05alias\xc0\x0c")])]
    if q.qtype == TXT:
        return [reply(q, answers=[rr(owner, TXT, txt_rdata(b"a", b"", b"bc"))])]
    return [reply(q)]


@scenario("ptrloop", [f"host {nm('ptrloop')}", f"mx {nm('ptrloop')}"])
def _(q):
    # An MX target that is a name pointer pointing at itself.
    start = 12 + len(q.question) + 2 + 10
    if q.qtype != MX:
        return [reply(q)]
    loop = rr(b"\xc0\x0c", MX, struct.pack(">H", 1) + bytes([0xC0, start + 2]))
    return [reply(q, answers=[loop])]


@scenario("badrdata", [f"host {nm('badrdata')}", f"mx {nm('badrdata')}", f"txt {nm('badrdata')}", f"ns {nm('badrdata')}"])
def _(q):
    if q.qtype == A:
        return [reply(q, answers=[rr(q.qname, A, b"\x01\x02\x03")])]
    if q.qtype == MX:
        return [reply(q, answers=[rr(q.qname, MX, b"\x00")])]
    if q.qtype == TXT:
        return [reply(q, answers=[rr(q.qname, TXT, b"\x05ab")])]
    if q.qtype == NS:
        return [reply(q, answers=[rr(q.qname, NS, b"\x7fabc")])]
    return [reply(q)]


@scenario("count", [f"host {nm('count')}", f"txt {nm('count')}"])
def _(q):
    pkt = bytearray(reply(q, answers=[rr(q.qname, A, a_rdata("192.0.2.2"))] if q.qtype == A else []))
    pkt[6:8] = struct.pack(">H", 3)  # claims three answers, carries at most one
    return [bytes(pkt)]


@scenario("twoq", [f"host {nm('twoq')}"])
def _(q):
    pkt = bytearray(reply(q, answers=[rr(q.qname, A, a_rdata("192.0.2.2"))]))
    pkt[4:6] = struct.pack(">H", 2)
    return [bytes(pkt)]


@scenario("mixed", [f"host {nm('mixed')}", f"ip ip {nm('mixed')}"])
def _(q):
    if q.qtype == A:
        return [reply(q, answers=[rr(q.qname, A, a_rdata(ip)) for ip in ["10.0.0.1", "8.8.8.8", "127.0.0.1", "169.254.1.1", "192.0.2.3"]])]
    if q.qtype == AAAA:
        return [reply(q, answers=[rr(q.qname, AAAA, aaaa_rdata(ip)) for ip in
                                  ["2001:db8::1", "::1", "fe80::1", "fc00::5", "2002:c000:204::1", "3ffe::1"]])]
    return [reply(q)]


@scenario("mapped", [f"ip ip6 {nm('mapped')}", f"netip ip6 {nm('mapped')}", f"ip ip4 {nm('mapped')}"])
def _(q):
    if q.qtype == AAAA:
        return [reply(q, answers=[rr(q.qname, AAAA, aaaa_rdata("::ffff:1.2.3.4")), rr(q.qname, AAAA, aaaa_rdata("2001:db8::9"))])]
    return [reply(q)]


@scenario("mx", [f"mx {nm('mx')}"])
def _(q):
    return [reply(q, answers=[rr(q.qname, MX, mx_rdata(30, "c.test.")), rr(q.qname, MX, mx_rdata(10, "a.test.")),
                              rr(q.qname, MX, mx_rdata(20, "b.test.")), rr(q.qname, MX, mx_rdata(20, "b2.test.")),
                              rr(q.qname, MX, mx_rdata(5, "1.2.3.4.")), rr(q.qname, TXT, txt_rdata(b"skip me"))])]


@scenario("mxbad", [f"mx {nm('mxbad')}", f"ns {nm('mxbad')}", f"srv - - {nm('mxbad')}", f"srv sip tcp {nm('mxbad')}"])
def _(q):
    if q.qtype == MX:
        return [reply(q, answers=[rr(q.qname, MX, mx_rdata(1, "good.test.")), rr(q.qname, MX, mx_rdata(2, "bad host.test.")),
                                  rr(q.qname, MX, mx_rdata(3, "fe80::1%x.")), rr(q.qname, MX, mx_rdata(4, "::1."))])]
    if q.qtype == NS:
        return [reply(q, answers=[rr(q.qname, NS, wire_name("ns1.test.")), rr(q.qname, NS, wire_name("ns 2.test.")),
                                  rr(q.qname, NS, wire_name("-bad.test."))])]
    if q.qtype == SRV:
        return [reply(q, answers=[rr(q.qname, SRV, srv_rdata(1, 1, 80, "ok.test.")), rr(q.qname, SRV, srv_rdata(2, 1, 80, "no way.test."))])]
    return [reply(q)]


@scenario("ns", [f"ns {nm('ns')}"])
def _(q):
    return [reply(q, answers=[rr(q.qname, NS, wire_name("ns2.test.")), rr(q.qname, NS, wire_name("ns1.test.")),
                              rr(q.qname, A, a_rdata("9.9.9.9"))])]


@scenario("txt", [f"txt {nm('txt')}"])
def _(q):
    return [reply(q, answers=[rr(q.qname, TXT, txt_rdata(b"v=spf1 -all")), rr(q.qname, TXT, txt_rdata(b"part1", b"part2", b"")),
                              rr(q.qname, TXT, txt_rdata(b"x" * 255, b"y" * 3)), rr(q.qname, TXT, txt_rdata(b"")),
                              rr(q.qname, TXT, b""), rr(q.qname, TXT, txt_rdata("é\"\\".encode("utf-8")))])]


@scenario("srv", [f"srv - - {nm('srv')}", f"srv sip tcp {nm('srv')}", f"srv xmpp udp {nm('srv')}"])
def _(q):
    owner = q.qname
    return [reply(q, answers=[rr(owner, SRV, srv_rdata(30, 5, 5060, "c.test.")), rr(owner, SRV, srv_rdata(10, 60, 5060, "a.test.")),
                              rr(owner, SRV, srv_rdata(10, 60, 5061, "b.test.")), rr(owner, SRV, srv_rdata(20, 0, 1, "d.test.")),
                              rr(owner, SRV, srv_rdata(20, 0, 2, "e.test."))])]


@scenario("srvcname", [f"srv - - {nm('srvcname')}"])
def _(q):
    return [reply(q, answers=[rr("alias.test.", SRV, srv_rdata(1, 1, 9, "t.test."))])]


@scenario("ptr", [f"addr 192.0.2.17", f"addr 2001:db8::5", f"addr 10.255.0.1", f"addr bad", f"addr 192.0.2.18", f"addr ::ffff:192.0.2.17",
                  f"addr fe80::1%x"])
def _(q):
    if q.qtype != PTR:
        return [reply(q)]
    n = q.qname.lower()
    if n == "17.2.0.192.in-addr.arpa.":
        return [reply(q, answers=[rr(q.qname, PTR, wire_name("host17.test.")), rr(q.qname, PTR, wire_name("alias17.test."))])]
    if n.endswith("ip6.arpa.") and n.startswith("5.0.0.0.0."):
        return [reply(q, answers=[rr(q.qname, PTR, wire_name("v6host.test."))])]
    if n == "1.0.255.10.in-addr.arpa.":
        return [reply(q, answers=[rr(q.qname, PTR, wire_name("ok.test.")), rr(q.qname, PTR, wire_name("bad name.test."))])]
    return [reply(q, rcode=3)]


SCRIPT_EXTRA = [
    "host localhost", "ip ip4 localhost", "cname localhost", "addr 127.0.0.1", "addr ::1", "host 1.2.3.4", "host ::1", "host fe80::1%en0",
    "ip ip bad..name.", "host a..b.test.", "host -x.test.", "host " + "a" * 64 + ".test.", "host " + ("a" * 60 + ".") * 5,
    "ip ip4 1.2.3.4", "ip ip6 1.2.3.4", "ip ip6 ::1", "ip tcp x.test.", "ip foo x.test.", "ip ip:1 x.test.",
    "host x.onion.", "host y.ONION.", "txt x.onion.", "ipaddr 1.2.3.4", "ipaddr ::", "netip ip4 1.2.3.4", "netip ip ::1",
]


class Server:
    def __init__(self):
        self.log = []
        self.lock = threading.Lock()
        self.seen = {}
        outer = self

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                q = Query(data, "udp")
                outer.record(q)
                for pkt in outer.answer(q):
                    sock.sendto(pkt, self.client_address)

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                c = self.request
                c.settimeout(5)
                try:
                    while True:
                        hdr = c.recv(2, socket.MSG_WAITALL)
                        if len(hdr) < 2:
                            return
                        n = struct.unpack(">H", hdr)[0]
                        data = c.recv(n, socket.MSG_WAITALL)
                        q = Query(data, "tcp")
                        outer.record(q)
                        for pkt in outer.answer(q):
                            c.sendall(struct.pack(">H", len(pkt)) + pkt)
                except OSError:
                    return

        socketserver.ThreadingTCPServer.allow_reuse_address = True
        for attempt in range(10):
            # The same port number serves UDP and TCP; retry if another process took the TCP side.
            self.udp = socketserver.ThreadingUDPServer(("127.0.0.1", 0), UDP)
            port = self.udp.server_address[1]
            try:
                self.tcp = socketserver.ThreadingTCPServer(("127.0.0.1", port), TCP)
                break
            except OSError:
                self.udp.server_close()
                if attempt == 9:
                    raise
        self.tcp.daemon_threads = self.udp.daemon_threads = True
        self.port = port
        for s in (self.udp, self.tcp):
            threading.Thread(target=s.serve_forever, daemon=True).start()

    def record(self, q):
        with self.lock:
            self.log.append((q.transport, struct.pack(">H", 0) + q.data[2:]))

    def answer(self, q):
        entry = SCENARIOS.get(q.label)
        if entry is None:
            return [reply(q, rcode=3)]
        return entry[1](q)

    def close(self):
        for s in (self.udp, self.tcp):
            s.shutdown()
            s.server_close()


def run(cmd, lines):
    server = Server()
    try:
        p = subprocess.run(cmd + [f"127.0.0.1:{server.port}"], input="\n".join(lines) + "\n", text=True,
                           capture_output=True, cwd=ROOT, timeout=600)
        if p.returncode:
            raise RuntimeError(f"{cmd} failed:\n{p.stderr}")
        return p.stdout.splitlines(), sorted(server.log)
    finally:
        server.close()


CGO_ADDR_ROWS = ["127.0.0.1", "::1", "::ffff:127.0.0.1", "bogus", "", "1.2.3", "1.2.3.4.5", "::1%", "[::1]",
                 "127.0.0.1 ", "01.2.3.4", "::ffff:1.2.3.4x", "1.2.3.4%eth0", "fe80::1%", "::1%0"]
# lo0 is the loopback interface only on macOS. Elsewhere the zone is not a local
# interface and getnameinfo asks the network's DNS server, which is not hermetic.
if sys.platform == "darwin":
    CGO_ADDR_ROWS.append("fe80::1%lo0")
CGO_CNAME_ROWS = ["bad name", "a..b", "x y.z", "..", "a" * 70 + ".test", "-x.test"]
# (GODEBUG, extra environment): the resolver choice must follow Go's conf.go.
CGO_ENVS = [("netdns=2", {}), ("netdns=go+2", {}), ("netdns=cgo+2", {}), ("netdns=2+go", {}),
            ("netdns=2", {"LOCALDOMAIN": ""}), ("netdns=2", {"RES_OPTIONS": "ndots:2"}),
            ("netdns=2", {"HOSTALIASES": "/nonexistent"}), ("netdns=bogus+2", {}), ("netdns=2,other=1", {})]


def cgo_checks():
    """LookupAddr/LookupCNAME through the C library (rust_stdlib_sys::net) against Go's cgo resolver,
    and the choice between the C library and Go's resolver under PreferGo, GODEBUG and the
    environment. Only hermetic names: loopback addresses and strings that are not domain names."""
    p = subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--manifest-path", "crates/sys/Cargo.toml",
                        "--example", "lookup_probe"], cwd=ROOT, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"build failed:\n{p.stderr}")
    import json
    import os
    import tempfile
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                                               "--no-deps", "--manifest-path", "crates/sys/Cargo.toml"], cwd=ROOT, text=True))
    probe = pathlib.Path(meta["target_directory"]) / "debug" / "examples" / "lookup_probe"
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="lookupdiff"))
    oracle = tmp / "oracle"
    subprocess.run(["go", "build", "-o", str(oracle), str(ROOT / "tools/lookup_oracle.go")], cwd=ROOT, check=True)
    rows = [f"addr\t{a}" for a in CGO_ADDR_ROWS] + [f"cname\t{c}" for c in CGO_CNAME_ROWS]
    order_rows = []
    for pg in "01":
        for a in ["127.0.0.1", "::1"]:
            order_rows.append(f"order\t{pg}\taddr\t{a}")
        for h in ["my%host", "my\\host", "bad name"]:
            order_rows.append(f"order\t{pg}\thost\t{h}")
    total = 0

    def run(exe, payload, env):
        e = dict(os.environ)
        for k in ("GODEBUG", "LOCALDOMAIN", "RES_OPTIONS", "HOSTALIASES"):
            e.pop(k, None)
        e.update(env)
        return subprocess.run([str(exe)], input=payload, text=True, capture_output=True, env=e, timeout=300)

    data = "\n".join(rows) + "\n"
    # The probe always asks the C library, so compare with Go's cgo resolver.
    # Without this Go on Linux picks its own resolver, whose answers and errors differ.
    r, g = run(probe, data, {}), run(oracle, data, {"GODEBUG": "netdns=cgo"})
    if r.returncode or g.returncode:
        raise RuntimeError(f"cgo lookup probe failed: {r.stderr[-500:]} {g.stderr[-500:]}")
    bad = [(row, a, b) for row, a, b in zip(rows, r.stdout.splitlines(), g.stdout.splitlines()) if a != b]
    if bad or len(r.stdout.splitlines()) != len(rows) or len(g.stdout.splitlines()) != len(rows):
        raise AssertionError("cgo lookups differ:\n" + "\n".join(f"{row!r}\n Rust: {a}\n Go:   {b}" for row, a, b in bad[:10]))
    total += len(rows)
    data = "\n".join(order_rows) + "\n"
    for godebug, extra in CGO_ENVS:
        env = dict(extra, GODEBUG=godebug)
        r, g = run(probe, data, env), run(oracle, data, env)
        if r.returncode or g.returncode:
            raise RuntimeError(f"cgo order probe failed: {r.stderr[-500:]} {g.stderr[-500:]}")
        rust = [line.split("|", 1)[1] for line in r.stdout.splitlines()]
        go = []
        for line in g.stderr.splitlines():
            if "LookupOrder(" in line:
                go.append("cgo" if line.rstrip().endswith("= cgo") else "go")
        if rust != go or len(rust) != len(order_rows):
            raise AssertionError(f"resolver choice differs under GODEBUG={godebug} {extra}:\nrows {order_rows}\nRust {rust}\nGo   {go}")
        total += len(order_rows)
    shutil.rmtree(tmp, ignore_errors=True)
    return total


def main():
    lines = []
    for label, (script, _) in SCENARIOS.items():
        lines += script
    lines += SCRIPT_EXTRA
    rust_out, rust_log = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "dns_probe", "--"], lines)
    go_out, go_log = run(["go", "run", str(ROOT / "tools/dns_oracle.go")], lines)
    if len(rust_out) != len(lines) or len(go_out) != len(lines):
        raise AssertionError(f"wrong number of records: {len(rust_out)} {len(go_out)} {len(lines)}")
    bad = [f"lookup {i} {lines[i]!r}\nRust: {a}\nGo:   {b}" for i, (a, b) in enumerate(zip(rust_out, go_out)) if a != b]
    if bad:
        raise AssertionError("\n\n".join(bad))
    if rust_log != go_log:
        only_rust = [x for x in rust_log if x not in go_log]
        only_go = [x for x in go_log if x not in rust_log]
        raise AssertionError(f"query logs differ: {len(rust_log)} vs {len(go_log)} queries\nonly Rust: {only_rust[:5]}\nonly Go: {only_go[:5]}")
    cgo = cgo_checks()
    print(f"DNS Go differential: {len(lines)} lookups and {len(go_log)} identical wire queries passed; "
          f"rust_stdlib_sys cgo resolver: {cgo} lookups/choices passed")


if __name__ == "__main__":
    main()
