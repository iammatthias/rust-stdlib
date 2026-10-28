#!/usr/bin/env python3
"""crypto/tls differential: Go's crypto/tls against backends/tls (Rustls).

Live loopback interop in both directions (Go client -> Rust server, Rust client
-> Go server) over TLS 1.2 and 1.3, every cipher suite both sides implement,
ALPN, SNI / GetCertificate selection, client authentication modes, session
resumption, ExportKeyingMaterial equality, key exchange groups and
HelloRetryRequest, plus verification failures whose error text must equal Go's
(expired, not yet valid, wrong host, unknown authority, client certificate
failures). The String/name tables and SessionState encoding are compared on
generated vectors.

Run with TZ=UTC semantics: the clients use a fixed Config.Time.
"""
import json
import os
import pathlib
import queue
import random
import re
import subprocess
import sys
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENV = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", TZ="UTC")
NOW = "2026-01-01T00:00:00Z"
GO = ROOT / "target/gotls_oracle"
RUST = ROOT / "backends/tls/target/debug/examples/gotls_probe"

# Fields that must agree between the two ends of one connection.
PAIR = ["version", "cipher", "curve", "alpn", "sni", "resumed", "hrr", "ekm", "ekm_ctx", "ekm_empty"]

STATS = {"cells": 0, "connections": 0, "text_checks": 0, "vectors": 0}


def build():
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--manifest-path",
                    "backends/tls/Cargo.toml", "--example", "gotls_probe"], cwd=ROOT, check=True, env=ENV)
    (ROOT / "target").mkdir(exist_ok=True)
    subprocess.run(["go", "build", "-o", str(GO), "tools/gotls_oracle.go"], cwd=ROOT, check=True, env=ENV)


class Server:
    def __init__(self, impl, pki, opts, env=ENV):
        exe = str(GO if impl == "go" else RUST)
        self.proc = subprocess.Popen([exe, "server", str(pki)] + [f"{k}={v}" for k, v in opts.items()],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True, env=env)
        self.lines = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        first = self.lines.get(timeout=20)
        if not first.startswith("listening "):
            raise RuntimeError(f"{impl} server said {first!r}: {self.proc.stderr.read()}")
        self.addr = first.split(" ", 1)[1]

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.put(line.strip())

    def events(self, n):
        out = []
        for _ in range(n):
            try:
                out.append(json.loads(self.lines.get(timeout=20)))
            except queue.Empty:
                out.append({"error": "<server produced no event>"})
        return out

    def stop(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.proc.stdout.close()
        self.proc.stderr.close()


def client(impl, pki, addr, opts, env=ENV):
    exe = str(GO if impl == "go" else RUST)
    r = subprocess.run([exe, "client", str(pki), addr] + [f"{k}={v}" for k, v in opts.items()],
                       capture_output=True, text=True, env=env, timeout=60)
    if r.returncode:
        raise RuntimeError(f"{impl} client crashed: {r.stderr[-2000:]}")
    if os.environ.get("GOTLS_DEBUG") and r.stderr:
        print(f"[{impl} client stderr] {r.stderr}", file=sys.stderr)
    return [json.loads(l) for l in r.stdout.splitlines() if l.startswith("{")]


def split_opts(opts):
    """Options for the server and client side. Prefix s: / c: restricts a key."""
    s, c = {}, {}
    for k, v in opts.items():
        if k.startswith("s:"):
            s[k[2:]] = v
        elif k.startswith("c:"):
            c[k[2:]] = v
        else:
            s[k] = v
            c[k] = v
    return s, c


def run_pair(pki, srv_impl, cli_impl, opts, conns):
    # e:NAME keys set an environment variable for both ends.
    env = dict(ENV, **{k[2:]: v for k, v in opts.items() if k.startswith("e:")})
    opts = {k: v for k, v in opts.items() if not k.startswith("e:")}
    sopts, copts = split_opts(opts)
    copts.setdefault("now", NOW)
    copts["conns"] = str(conns)
    # Go ignores the Rust-only TLS 1.3 suite knob; it is harmless to pass.
    srv = Server(srv_impl, pki, sopts, env)
    try:
        cres = client(cli_impl, pki, srv.addr, copts, env)
        sres = srv.events(conns)
    finally:
        srv.stop()
    STATS["connections"] += conns
    return cres, sres


def fail(msg):
    raise AssertionError(msg)


def norm(text):
    return re.sub(r"\d+\.\d+\.\d+\.\d+:\d+", "ADDR", text)


def cell(pki, name, opts, conns=1, expect=None, fields=PAIR, same_as_go=("version", "cipher", "alpn", "peer_cn", "chains", "peers")):
    """A connection that must succeed in both directions with agreeing state."""
    STATS["cells"] += 1
    base_c, base_s = run_pair(pki, "go", "go", opts, conns)
    for b in base_c + base_s:
        if "error" in b:
            fail(f"{name}: Go<->Go baseline failed: {b}")
    for srv_impl, cli_impl in (("rust", "go"), ("go", "rust")):
        label = f"{name} [{cli_impl} client -> {srv_impl} server]"
        cres, sres = run_pair(pki, srv_impl, cli_impl, opts, conns)
        if len(cres) != conns or len(sres) != conns:
            fail(f"{label}: got {len(cres)} client / {len(sres)} server reports")
        for i, (c, s) in enumerate(zip(cres, sres)):
            if "error" in c or "error" in s:
                fail(f"{label}: conn {i}: client={c} server={s}")
            for f in fields:
                if c.get(f) != s.get(f):
                    fail(f"{label}: conn {i}: {f} differs client={c.get(f)!r} server={s.get(f)!r}")
            if expect:
                for k, v in expect.items():
                    got = s.get(k[2:]) if k.startswith("s.") else (c if k in c else s).get(k)
                    want = v[i] if isinstance(v, list) else v
                    if got != want:
                        fail(f"{label}: conn {i}: {k}={got!r}, want {want!r}")
            # Behaviour must match what Go does with Go.
            ref = base_c[i]
            for f in same_as_go:
                if c.get(f) != ref.get(f):
                    fail(f"{label}: conn {i}: {f} {c.get(f)!r} differs from Go<->Go {ref.get(f)!r}")
        print(f"  ok {label}")


def failing(pki, name, opts):
    """A handshake that must fail in every pairing."""
    STATS["cells"] += 1
    for srv_impl, cli_impl in (("go", "go"), ("rust", "go"), ("go", "rust"), ("rust", "rust")):
        cres, sres = run_pair(pki, srv_impl, cli_impl, opts, 1)
        if not any("error" in x for x in cres):
            # TLS 1.3 reports a client-certificate failure only after the
            # client's own handshake completed; the server must still fail.
            if not any("error" in x for x in sres):
                fail(f"{name} [{cli_impl} -> {srv_impl}]: connection succeeded: {cres} {sres}")
        print(f"  ok {name} [{cli_impl} client -> {srv_impl} server] fails")


def text_cell(pki, name, opts, side="client"):
    """The error text must be identical to Go's for the same failure."""
    STATS["text_checks"] += 1
    ref_c, ref_s = run_pair(pki, "go", "go", opts, 1)
    ref = (ref_c if side == "client" else ref_s)[0]
    if "error" not in ref:
        fail(f"{name}: Go baseline did not fail: {ref}")
    want = norm(ref["error"])
    # (server, client) pairings: the Go reference is compared with each mixed one.
    combos = (("go", "rust"), ("rust", "go")) if side == "client" else (("rust", "go"),)
    for srv_impl, cli_impl in combos:
        cres, sres = run_pair(pki, srv_impl, cli_impl, opts, 1)
        got = (cres if side == "client" else sres)[0]
        if "error" not in got:
            fail(f"{name} [{cli_impl}->{srv_impl}]: no {side} error: {got}")
        if norm(got["error"]) != want:
            fail(f"{name} [{cli_impl}->{srv_impl}]: {side} error\n  got:  {got['error']!r}\n  Go:   {ref['error']!r}")
        print(f"  ok {name} [{cli_impl} client -> {srv_impl} server] {side} error == Go: {want[:90]}")


def tables_check():
    go = subprocess.run([str(GO), "tables"], capture_output=True, text=True, env=ENV, check=True).stdout
    rs = subprocess.run([str(RUST), "tables"], capture_output=True, text=True, env=ENV, check=True).stdout
    if go != rs:
        a, b = go.splitlines(), rs.splitlines()
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                fail(f"tables line {i}: Go {x!r} vs Rust {y!r}")
        fail(f"tables length differs: {len(a)} vs {len(b)}")
    STATS["vectors"] += len(go.splitlines())
    print(f"  ok String/name tables identical ({len(go.splitlines())} lines)")


def session_vectors():
    rng = random.Random(0x7157)

    def u24(n):
        return n.to_bytes(3, "big")

    def vec(version, extra, ems, early, curve):
        b = version.to_bytes(2, "big") + b"\x01" + (0xC02F).to_bytes(2, "big") + (1700000000).to_bytes(8, "big")
        secret = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 49)))
        b += bytes([len(secret)]) + secret
        ex = b"".join(u24(len(e)) + e for e in extra)
        b += u24(len(ex)) + ex + bytes([ems, early]) + u24(0) + u24(0)
        if early:
            alpn = b"h2"
            b += bytes([len(alpn)]) + alpn
        if version < 0x0304:
            b += curve.to_bytes(2, "big")
        return b

    vectors = []
    for _ in range(600):
        extra = [bytes(rng.randrange(256) for _ in range(rng.randrange(0, 20))) for _ in range(rng.randrange(0, 4))]
        v = vec(rng.choice([0x0301, 0x0303, 0x0304]), extra, rng.randrange(2), rng.randrange(2), rng.choice([23, 24, 29]))
        vectors.append(v)
        for _ in range(3):
            m = bytearray(v)
            if m and rng.random() < 0.5:
                m[rng.randrange(len(m))] ^= 1 << rng.randrange(8)
            else:
                m = m[:rng.randrange(len(m) + 1)]
            vectors.append(bytes(m))
    inp = "\n".join(v.hex() for v in vectors) + "\n"
    go = subprocess.run([str(GO), "session"], input=inp, capture_output=True, text=True, env=ENV, check=True).stdout.splitlines()
    rs = subprocess.run([str(RUST), "session"], input=inp, capture_output=True, text=True, env=ENV, check=True).stdout.splitlines()
    if go != rs:
        for i, (x, y) in enumerate(zip(go, rs)):
            if x != y:
                fail(f"session vector {i} ({vectors[i].hex()}): Go {x!r} vs Rust {y!r}")
        fail(f"session output length {len(go)} vs {len(rs)}")
    ok = sum(1 for l in go if l.startswith("ok "))
    STATS["vectors"] += len(vectors)
    print(f"  ok SessionState parse/encode: {len(vectors)} vectors ({ok} valid) identical")


TLS12_SUITES = [
    ("0xc02b", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ecdsa"),
    ("0xc02c", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ecdsa"),
    ("0xcca9", "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ecdsa"),
    ("0xc02f", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "rsa"),
    ("0xc030", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "rsa"),
    ("0xcca8", "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "rsa"),
]
TLS13_SUITES = [
    ("0x1301", "TLS_AES_128_GCM_SHA256"),
    ("0x1302", "TLS_AES_256_GCM_SHA384"),
    ("0x1303", "TLS_CHACHA20_POLY1305_SHA256"),
]


def matrix(pki):
    print("TLS 1.2 cipher suites")
    for sid, name, cert in TLS12_SUITES:
        cell(pki, name, {"min": "1.2", "max": "1.2", "suites": sid, "certs": cert},
             expect={"version": "TLS 1.2", "cipher": name})
    print("TLS 1.3 cipher suites (the suite is pinned on the Rust end; Go cannot pin TLS 1.3 suites)")
    for sid, name in TLS13_SUITES:
        cell(pki, name, {"min": "1.3", "max": "1.3", "certs": "ecdsa", "s:suites13": sid, "c:suites13": sid},
             expect={"version": "TLS 1.3", "cipher": name}, same_as_go=("version", "alpn", "peer_cn"))
    print("Certificate key types")
    for cert in ("ecdsa", "rsa", "ed25519"):
        for v in ("1.2", "1.3"):
            cell(pki, f"{cert} cert / TLS {v}", {"min": v, "max": v, "certs": cert},
                 expect={"version": f"TLS {v}", "peer_cn": f"{cert}.test"}, same_as_go=("version", "peer_cn", "chains"))
    print("Verified chains (ECDSA leaf issued by an intermediate)")
    cell(pki, "chain length 3", {"certs": "ecdsa", "min": "1.3", "max": "1.3"},
         expect={"chains": [[["ecdsa.test", "gotls intermediate", "gotls test CA"]]]}, fields=PAIR)
    print("ALPN")
    cell(pki, "alpn h2 preferred by server", {"s:alpn": "h2,http/1.1", "c:alpn": "http/1.1,h2", "certs": "ecdsa"},
         expect={"alpn": "h2"})
    cell(pki, "alpn http/1.1 only", {"s:alpn": "http/1.1", "c:alpn": "h2,http/1.1", "certs": "ecdsa"},
         expect={"alpn": "http/1.1"})
    cell(pki, "alpn client none", {"s:alpn": "h2", "certs": "ecdsa"}, expect={"alpn": ""})
    failing(pki, "alpn no overlap", {"s:alpn": "h2", "c:alpn": "spdy/3", "certs": "ecdsa"})
    print("SNI and certificate selection")
    for sni, cn in (("ecdsa.test", "ecdsa.test"), ("rsa.test", "rsa.test"), ("ed25519.test", "ed25519.test")):
        cell(pki, f"GetCertificate sni={sni}", {"getcert": "1", "sni": sni}, expect={"peer_cn": cn, "sni": sni})
        cell(pki, f"Certificates list sni={sni}", {"certs": "ecdsa,rsa,ed25519", "sni": sni},
             expect={"peer_cn": cn, "sni": sni}, same_as_go=("peer_cn",))
    cell(pki, "IP address server name", {"certs": "ecdsa", "sni": "127.0.0.1"}, expect={"sni": ""})
    print("Client authentication")
    for v in ("1.2", "1.3"):
        pre = {"min": v, "max": v, "certs": "ecdsa"}
        cell(pki, f"NoClientCert / TLS {v}", dict(pre, clientcert="ecdsa"), expect={"s.peers": 0})
        cell(pki, f"RequestClientCert with cert / TLS {v}",
             dict(pre, clientauth="RequestClientCert", clientcert="ecdsa"), expect={"s.peers": 1, "s.chains": None})
        cell(pki, f"RequestClientCert without cert / TLS {v}", dict(pre, clientauth="RequestClientCert"), expect={"s.peers": 0})
        cell(pki, f"RequireAnyClientCert untrusted / TLS {v}",
             dict(pre, clientauth="RequireAnyClientCert", clientcert="untrusted", forcecert="1"), expect={"s.peers": 1, "s.chains": None})
        cell(pki, f"VerifyClientCertIfGiven none / TLS {v}", dict(pre, clientauth="VerifyClientCertIfGiven"))
        cell(pki, f"VerifyClientCertIfGiven trusted / TLS {v}",
             dict(pre, clientauth="VerifyClientCertIfGiven", clientcert="ecdsa"),
             expect={"s.peers": 1, "s.chains": [[["client.test", "gotls test CA"]]]})
        cell(pki, f"RequireAndVerifyClientCert trusted / TLS {v}",
             dict(pre, clientauth="RequireAndVerifyClientCert", clientcert="ecdsa"),
             expect={"s.peers": 1, "s.chains": [[["client.test", "gotls test CA"]]]})
        failing(pki, f"RequireAnyClientCert none / TLS {v}", dict(pre, clientauth="RequireAnyClientCert"))
        failing(pki, f"VerifyClientCertIfGiven untrusted / TLS {v}",
                dict(pre, clientauth="VerifyClientCertIfGiven", clientcert="untrusted", forcecert="1"))
        failing(pki, f"RequireAndVerifyClientCert none / TLS {v}", dict(pre, clientauth="RequireAndVerifyClientCert"))
        failing(pki, f"RequireAndVerifyClientCert untrusted / TLS {v}",
                dict(pre, clientauth="RequireAndVerifyClientCert", clientcert="untrusted", forcecert="1"))
    print("Session resumption")
    for v in ("1.2", "1.3"):
        # Rustls keeps no key exchange for resumed TLS 1.2 connections: the
        # curve is zero there (deviation recorded for ConnectionState.CurveID).
        cell(pki, f"resumption / TLS {v}", {"min": v, "max": v, "certs": "ecdsa", "sessions": "1", "c:now": ""}, conns=3,
             expect={"resumed": [False, True, True]}, same_as_go=("version",),
             fields=[f for f in PAIR if f != "curve"])
        cell(pki, f"tickets disabled / TLS {v}",
             {"min": v, "max": v, "certs": "ecdsa", "sessions": "1", "s:tickets": "0", "c:now": ""}, conns=2,
             expect={"resumed": [False, False]}, same_as_go=("version",))
    print("Key exchange groups")
    for cid, name in (("29", "X25519"), ("23", "CurveP256"), ("24", "CurveP384")):
        cell(pki, f"curve {name}", {"curves": cid, "certs": "ecdsa"}, expect={"curve": name}, same_as_go=("version",))
    # Go sends more than one key share, so only Rustls (one share) is retried.
    hrr = {"s:curves": "29", "c:curves": "23,29", "min": "1.3", "max": "1.3", "certs": "ecdsa"}
    cell(pki, "HelloRetryRequest", hrr, expect={"curve": "X25519"}, same_as_go=("version",))
    for srv_impl in ("go", "rust"):
        cres, sres = run_pair(pki, srv_impl, "rust", hrr, 1)
        if not (cres[0].get("hrr") is True and sres[0].get("hrr") is True):
            fail(f"HelloRetryRequest [rust client -> {srv_impl} server]: not retried: {cres} {sres}")
        print(f"  ok HelloRetryRequest observed on both ends [rust client -> {srv_impl} server]")
    print("InsecureSkipVerify (explicitly requested)")
    cell(pki, "skipverify untrusted server", {"certs": "untrusted", "c:skipverify": "1"}, expect={"chains": None},
         same_as_go=("version", "peer_cn"))


def failures(pki):
    print("Verification failures: error text must equal Go's")
    for v in ("1.2", "1.3"):
        pre = {"min": v, "max": v}
        text_cell(pki, f"expired / TLS {v}", dict(pre, certs="expired"))
        text_cell(pki, f"not yet valid / TLS {v}", dict(pre, certs="notyet"))
        text_cell(pki, f"wrong host / TLS {v}", dict(pre, certs="wronghost"))
        text_cell(pki, f"wrong IP / TLS {v}", dict(pre, certs="wronghost", sni="127.0.0.1"))
        text_cell(pki, f"unknown authority / TLS {v}", dict(pre, certs="untrusted"))
        text_cell(pki, f"unknown authority (other roots) / TLS {v}", dict(pre, certs="ecdsa", **{"c:roots": "other"}))
        text_cell(pki, f"server: no client cert / TLS {v}",
                  dict(pre, certs="ecdsa", clientauth="RequireAndVerifyClientCert"), side="server")
        text_cell(pki, f"server: untrusted client cert / TLS {v}",
                  dict(pre, certs="ecdsa", clientauth="RequireAndVerifyClientCert", clientcert="untrusted", forcecert="1"), side="server")
        text_cell(pki, f"client sees client-cert rejection / TLS {v}",
                  dict(pre, certs="ecdsa", clientauth="RequireAndVerifyClientCert", clientcert="untrusted", forcecert="1"))
    failing(pki, "no common version", {"s:min": "1.2", "s:max": "1.2", "c:min": "1.3", "c:max": "1.3", "certs": "ecdsa"})
    failing(pki, "no common cipher suite", {"s:min": "1.2", "s:max": "1.2", "c:min": "1.2", "c:max": "1.2",
                                           "s:suites": "0xc02b", "c:suites": "0xc02c", "certs": "ecdsa"})


def system_roots(pki):
    """nil RootCAs and ClientCAs load the system roots from SSL_CERT_FILE and
    SSL_CERT_DIR, as Go's loadSystemRoots does. The directory is empty so that
    no operating system roots leak in."""
    print("System roots: nil RootCAs / ClientCAs (SSL_CERT_FILE, empty SSL_CERT_DIR)")
    cadir = pki / "no-roots"
    cadir.mkdir(exist_ok=True)
    (pki / "empty.pem").write_text("")
    ca_env = {"e:SSL_CERT_FILE": str(pki / "ca.pem"), "e:SSL_CERT_DIR": str(cadir)}
    for v in ("1.2", "1.3"):
        cell(pki, f"nil RootCAs verifies the server / TLS {v}",
             dict(ca_env, min=v, max=v, certs="ecdsa", **{"c:roots": "system"}),
             expect={"peer_cn": "ecdsa.test"})
        cell(pki, f"nil ClientCAs verifies the client / TLS {v}",
             dict(ca_env, min=v, max=v, certs="ecdsa", clientauth="RequireAndVerifyClientCert",
                  clientcert="ecdsa", **{"s:clientcas": "system"}),
             expect={"peer_cn": "ecdsa.test"})
    absent = {"e:SSL_CERT_DIR": str(cadir), "certs": "ecdsa", "c:roots": "system"}
    for v in ("1.2", "1.3"):
        text_cell(pki, f"nil RootCAs, CA absent from SSL_CERT_FILE / TLS {v}",
                  dict(absent, min=v, max=v, **{"e:SSL_CERT_FILE": str(pki / "other-ca.pem")}))
        text_cell(pki, f"nil RootCAs, empty SSL_CERT_FILE / TLS {v}",
                  dict(absent, min=v, max=v, **{"e:SSL_CERT_FILE": str(pki / "empty.pem")}))
        text_cell(pki, f"server: nil ClientCAs, CA absent / TLS {v}",
                  {"e:SSL_CERT_DIR": str(cadir), "e:SSL_CERT_FILE": str(pki / "other-ca.pem"), "certs": "ecdsa",
                   "min": v, "max": v, "clientauth": "RequireAndVerifyClientCert", "clientcert": "ecdsa",
                   "s:clientcas": "system", "c:roots": "ca"}, side="server")


def main():
    build()
    with tempfile.TemporaryDirectory() as tmp:
        pki = pathlib.Path(tmp) / "pki"
        subprocess.run([str(GO), "certs", str(pki)], check=True, env=ENV)
        print("Tables and encodings")
        tables_check()
        session_vectors()
        matrix(pki)
        failures(pki)
        system_roots(pki)
    print(f"crypto/tls differential: {STATS['cells']} cells, {STATS['connections']} connections, "
          f"{STATS['text_checks']} error-text checks, {STATS['vectors']} table/encoding vectors: all agree with Go")


if __name__ == "__main__":
    main()
