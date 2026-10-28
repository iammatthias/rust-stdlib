#!/usr/bin/env python3
"""Differentially check package net's parsers and formatters against Go: ParseIP and
every IP method, ParseCIDR, IPNet, IPMask, CIDRMask, ParseMAC, SplitHostPort,
JoinHostPort, the socket address types and the error texts (exact output)."""
import pathlib
import random
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import netip_check as gen  # noqa: E402

MAC_FRAGMENTS = [":", "-", ".", "0", "f", "g", "00", "ff", "FF", " ", "é", "::", "--"]
HOSTS = ["", "localhost", "example.com", "1.2.3.4", "::1", "[::1]", "fe80::1%eth0", "[fe80::1%eth0]", "a:b", "[", "]",
         "[]", "[a]", "a]", "[a", "%", "é", "a b"]
PORTS = ["", "80", "http", "0", "65536", "-1", ":", "::", "80:", "[80]", "a:80", "%x"]


def mac(rng):
    n = rng.choice([6, 6, 6, 8, 8, 20, 5, 7, 19, 21, 4])
    octets = [f"{rng.randrange(256):02x}" for _ in range(n)]
    style = rng.randrange(4)
    if style == 0:
        return ":".join(octets)
    if style == 1:
        return "-".join(octets)
    if style == 2:
        return ".".join("".join(octets[i:i + 2]) for i in range(0, n - 1, 2))
    return "".join(octets).upper() if rng.random() < 0.5 else "".join(octets)


def hostport(rng):
    style = rng.randrange(6)
    h, p = rng.choice(HOSTS), rng.choice(PORTS)
    if style == 0:
        return f"{h}:{p}"
    if style == 1:
        return f"[{h}]:{p}"
    if style == 2:
        return h + p
    if style == 3:
        return gen.mutate(rng, f"[{h}]:{p}")
    if style == 4:
        return gen.mutate(rng, f"{gen.addr(rng)}:{rng.randrange(70000)}")
    return gen.mutate(rng, f"[{gen.addr(rng)}]:{rng.randrange(70000)}")


def rawip(rng):
    kind = rng.randrange(6)
    if kind == 0:
        return bytes(rng.randrange(256) for _ in range(4))
    if kind == 1:
        return bytes(rng.randrange(256) for _ in range(16))
    if kind == 2:
        return b"\0" * 10 + b"\xff\xff" + bytes(rng.randrange(256) for _ in range(4))
    if kind == 3:
        return bytes(rng.choice([0, 0, 1, 255, 254, 169, 10, 0xfe, 0x80, 0xfc, 0xff, 2, 224]) for _ in range(rng.choice([4, 16])))
    return bytes(rng.randrange(256) for _ in range(rng.choice([0, 1, 2, 3, 5, 8, 15, 17, 20])))


def hx(b):
    data = b if isinstance(b, bytes) else str(b).encode("utf-8")
    return data.hex() if data else "_"


def main():
    rng = random.Random(0x4E37)
    req = []
    ipstrs = [gen.addr(rng) for _ in range(2200)]
    ipstrs += [gen.mutate(rng, s) for s in ipstrs[:1400]]
    ipstrs += ["", "::ffff:1.2.3.4", "1.2.3.4", "::", "0.0.0.0", "255.255.255.255", "::1", "fe80::1%x", "224.0.0.1", "ff02::1",
               "ff01::1", "169.254.1.1", "fe80::", "10.0.0.1", "172.16.0.1", "172.32.0.1", "fc00::1", "fd00::1", "::ffff:224.0.0.1"]
    req += [("I", [s]) for s in ipstrs]
    req += [("R", [rawip(rng)]) for _ in range(1500)]
    cidrs = []
    for _ in range(1800):
        a = gen.addr(rng)
        bits = rng.choice([0, 1, 8, 16, 24, 32, 33, 64, 128, 129, rng.randrange(0, 130), "", "-1", "+8", "08", "8 ", "99999999", "x", "1e1"])
        cidrs.append(f"{a}/{bits}")
    cidrs += [gen.mutate(rng, c) for c in cidrs[:1200]]
    cidrs += ["10.0.0.0/8", "192.168.1.77/24", "::1/128", "2001:db8::/32", "::ffff:10.1.2.3/104", "10.1.2.3/0", "1.2.3.4", "/8", "1.2.3.4/", "1.2.3.4/8/8"]
    req += [("D", [c]) for c in cidrs]
    for _ in range(1500):
        ip = rawip(rng)
        mask = rng.choice([bytes([0xff] * rng.choice([0, 1, 2, 3, 4, 8, 16, 17]) ),
                           bytes(rng.randrange(256) for _ in range(rng.choice([4, 16, 3]))),
                           bytes([0xff, 0xff, 0xff, 0xf0]), bytes([0xff] * 12 + [0xff, 0xff, 0xc0, 0]),
                           bytes([0xff] * 4 + [0] * 12), bytes([0x80, 0, 0xff, 0]), bytes(4), bytes(16)])
        req.append(("N", [ip, mask]))
        req.append(("M", [mask]))
    for m in [b"", b"\xff", b"\xff\x80", b"\xfe\xff", b"\xff\x00\x01", b"\x00\x80"]:
        req.append(("M", [m]))
    for ones in list(range(-2, 36)) + list(range(120, 133)):
        for bits in [0, 8, 32, 128, 129, -1]:
            req.append(("K", [str(ones), str(bits)]))
    macs = [mac(rng) for _ in range(1200)]
    macs += [gen.mutate(rng, m) for m in macs[:900]]
    macs += ["", "00:00:5e:00:53:01", "0000.5e00.5301", "00005e005301", "00-00-5e-00-53-01", "00:00:5e:00:53:0", "00:00:5e:00:53:01:",
             "0:0:5e:0:53:1:00:00", "gg:00:5e:00:53:01", "00:00:5e:00-53:01"]
    req += [("H", [m]) for m in macs]
    hps = [hostport(rng) for _ in range(2200)]
    hps += [gen.mutate(rng, h) for h in hps[:800]]
    hps += ["", ":", "[", "]", "[]", "[]:", "[]:80", "[::1]:80", "::1", "a:b:c", "[a]b:80", "[a]:b:80", "[a:80", "a]:80", "[[a]]:80"]
    req += [("S", [h]) for h in hps]
    req += [("J", [rng.choice(HOSTS), rng.choice(PORTS)]) for _ in range(500)]
    for _ in range(1200):
        ip = rawip(rng)
        port = rng.choice([0, 80, 65535, 65536, -1, 70000, rng.randrange(100000)])
        zone = rng.choice(["", "", "eth0", "x y", "é"])
        req.append(("T", [ip, str(port), zone]))
        req.append(("U", [ip, str(port), zone]))
    for _ in range(300):
        req.append(("P", [rawip(rng), rng.choice(["", "eth0"]), rng.choice(["", "/tmp/x.sock", "@abs"]), rng.choice(["unix", "unixgram", ""])]))
    for _ in range(600):
        req.append(("Q", [rng.choice(["dial", "read", "accept", "listen", ""]), rng.choice(["tcp", "udp6", ""]),
                          rng.choice(["-", "127.0.0.1:1", "[::1]:2"]), rng.choice(["-", "10.0.0.1:80", "[::1]:3"]),
                          rng.choice(["timeout", "addr", "unknown", "closed", "parse", "plain"]), rng.choice(["boom", "no suitable address found", "e e"])]))
    for _ in range(300):
        req.append(("X", [rng.choice(["no such host", "i/o timeout", "server misbehaving"]), rng.choice(["example.com", "a.test.", ""]),
                          rng.choice(["", "127.0.0.1:53", "[::1]:53"]), rng.choice(["0", "1"]), rng.choice(["0", "1"])]))
    req.append(("Y", []))

    lines = ["".join([op] + [" " + hx(a) for a in args]) for op, args in req]
    payload = "\n".join(lines) + "\n"
    rust_run = subprocess.run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "net_probe"],
                              input=payload, text=True, capture_output=True, cwd=ROOT)
    if rust_run.returncode:
        raise RuntimeError(f"Rust net probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(["go", "run", str(ROOT / "tools/net_oracle.go")], input=payload, text=True,
                            capture_output=True, cwd=ROOT)
    if go_run.returncode:
        raise RuntimeError(f"Go net oracle failed:\n{go_run.stderr}")
    rust, go = rust_run.stdout.splitlines(), go_run.stdout.splitlines()
    if len(rust) != len(lines) or len(go) != len(lines):
        raise AssertionError(f"wrong number of records: {len(rust)} {len(go)} {len(lines)}")
    for i, (actual, expected) in enumerate(zip(rust, go)):
        if actual != expected:
            raise AssertionError(f"vector {i}, request={lines[i]!r} ({req[i]!r})\nRust={actual!r}\nGo={expected!r}")
    print(f"net Go differential: {len(lines)} IP, CIDR, mask, MAC, host:port, address and error-text vectors passed")


if __name__ == "__main__":
    main()
