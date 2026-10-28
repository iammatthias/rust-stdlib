#!/usr/bin/env python3
"""Differentially check net/netip against Go: ParseAddr, ParsePrefix, ParseAddrPort,
every Addr/Prefix/AddrPort method, the text and binary codecs, Compare, Contains
and Overlaps, on generated and mutated strings (exact output and error text)."""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]

ZONES = ["", "", "", "%eth0", "%en1", "%1", "%", "%%", "%a b", "%é", "%25", "%z1", "%\x00"]
FRAGMENTS = [":", "::", ".", "%", "/", "[", "]", "0", "00", "01", "256", "255", "1.2.3.4", "ffff", "fffff", "g",
             "-", "+", " ", "\t", "\n", "é", "\U0001f600", "::ffff:", "0x1", "1e3", "٣", "_", ",", ":0", "0:"]


def v4(rng):
    kind = rng.random()
    if kind < 0.3:
        return ".".join(str(rng.choice([0, 1, 9, 10, 127, 169, 172, 192, 224, 255, 254, 100])) for _ in range(4))
    return ".".join(str(rng.randrange(256)) for _ in range(4))


def v6(rng):
    groups = [rng.choice(["0", "0", "0", "1", "ffff", "FFFF", "fe80", "2001", "db8", "fc00", "ff02", "ff01", "a", "00ab", "0000", "d3ad"])
              for _ in range(8)]
    style = rng.randrange(7)
    if style == 0:
        return ":".join(groups)
    if style == 1:
        i = rng.randrange(8)
        j = rng.randrange(i, 9)
        return ":".join(groups[:i]) + "::" + ":".join(groups[j:])
    if style == 2:
        return "::ffff:" + v4(rng)
    if style == 3:
        return ":".join(groups[:6]) + ":" + v4(rng)
    if style == 4:
        return "::" + v4(rng) if rng.random() < 0.5 else "::" + ":".join(groups[:rng.randrange(1, 7)])
    if style == 5:
        return rng.choice(["fe80::", "ff02::1", "ff01::1", "ff0e::1", "::1", "::", "fc00::1", "fd12:3456::", "2001:db8::1",
                           "0:0:0:0:0:ffff:1.2.3.4", "64:ff9b::1.2.3.4", "::ffff:0:1.2.3.4"])
    return ":".join(groups[:rng.randrange(1, 8)]) + "::"


def addr(rng):
    if rng.random() < 0.4:
        return v4(rng)
    s = v6(rng)
    return s + rng.choice(ZONES)


def prefix(rng):
    a = addr(rng)
    bits = rng.choice([0, 1, 8, 16, 24, 31, 32, 33, 64, 96, 120, 127, 128, 129, 255, 256, rng.randrange(0, 130),
                       "-1", "+1", "01", "08", "", " 1", "1 ", "0x10", "1_0", "99999999999999999999"])
    return f"{a}/{bits}"


def addrport(rng):
    a = addr(rng)
    port = rng.choice([0, 80, 65535, 65536, 1, rng.randrange(70000), "", "-1", "+1", "0080", "a", "1_0", " 1", "00000000000080"])
    style = rng.randrange(6)
    if style == 0:
        return f"{a}:{port}"
    if style <= 3:
        return f"[{a}]:{port}"
    if style == 4:
        return f"[{a}:{port}"
    return f"{a}]:{port}"


def mutate(rng, s):
    s = list(s)
    for _ in range(rng.randrange(1, 4)):
        op = rng.randrange(4)
        pos = rng.randrange(len(s) + 1)
        if op == 0:
            s[pos:pos] = list(rng.choice(FRAGMENTS))
        elif op == 1 and s:
            pos = min(pos, len(s) - 1)
            s[pos:pos + 1] = list(rng.choice(FRAGMENTS))
        elif op == 2 and s:
            del s[min(pos, len(s) - 1)]
        else:
            s = s[:pos]
    return "".join(s)


def hx(s):
    data = s if isinstance(s, bytes) else s.encode("utf-8")
    return data.hex() if data else "_"


def main():
    rng = random.Random(0x4E7197)
    addrs, prefixes, ports = [], [], []
    for _ in range(2500):
        addrs.append(addr(rng))
    for _ in range(1200):
        prefixes.append(prefix(rng))
    for _ in range(1200):
        ports.append(addrport(rng))
    addrs += [mutate(rng, a) for a in addrs[:1600]]
    prefixes += [mutate(rng, a) for a in prefixes[:1000]]
    ports += [mutate(rng, a) for a in ports[:1000]]
    addrs += ["", "1.2.3", "1.2.3.4.5", "01.2.3.4", "256.1.1.1", "1..2.3", ".1.2.3", "1.2.3.", "::1::", ":", "::::",
              "1:2:3:4:5:6:7:8:9", "1:2:3:4:5:6:7", "1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7", "::1:2:3:4:5:6:7:8",
              "%eth0", "fe80::1%", "1.2.3.4%eth0", "::1.2.3.4%x", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4",
              "::ffff:1.2.3.4", "::FFFF:1.2.3.4%zone", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "255.255.255.255",
              "0.0.0.0", "::", "00000::", "0:0:0:0:0:0:0:0", "1:2:3:4:5:6:7:8%a", "::1.2.3", "::1.2.3.4.5", "f:f:f:f:f:f:f::f"]
    requests = [("A", [a]) for a in addrs]
    requests += [("N", [a]) for a in addrs[:700]]
    requests += [("A", ["~"]), ("N", ["~"]), ("N", ["255.255.255.255"]), ("N", ["0.0.0.0"]), ("N", ["::"]),
                 ("N", ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]), ("N", ["::ffff:255.255.255.255"]),
                 ("N", ["fe80::1%en0"]), ("S", [])]
    requests += [("P", [p]) for p in prefixes]
    requests += [("T", [p]) for p in ports]
    requests += [("U", [x]) for x in addrs[:400] + prefixes[:400] + ports[:400] + [""]]
    valid = [a for a in addrs[:2500]]
    pairs = []
    for _ in range(2500):
        pairs.append((rng.choice(valid), rng.choice(valid)))
    requests += [("C", [x, y]) for x, y in pairs]
    requests += [("C", ["~", "1.2.3.4"]), ("C", ["~", "~"]), ("C", ["fe80::1%a", "fe80::1%b"]), ("C", ["fe80::1", "fe80::1%a"])]
    pfx_valid = [f"{a}/{b}" for a in valid[:600] for b in [rng.choice([0, 8, 16, 24, 32, 64, 96, 128])]]
    pfx_valid = [p for p in pfx_valid if "%" not in p]
    pfx_valid += ["~", "!1.2.3.4/33", "!::1/129", "!1.2.3.4/-1", "!~/8"]
    for _ in range(2500):
        requests.append(("K", [rng.choice(pfx_valid), rng.choice(valid)]))
    for _ in range(2500):
        requests.append(("O", [rng.choice(pfx_valid), rng.choice(pfx_valid)]))
    nested = ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.3/32", "0.0.0.0/0", "::/0", "::ffff:10.0.0.0/104", "::ffff:0.0.0.0/96",
              "fe80::/10", "fe80::1/128", "2001:db8::/32", "2001:db8:1::/48", "10.1.2.3/8", "10.200.0.0/9"]
    for p in nested:
        for q in nested:
            requests.append(("O", [p, q]))
        for a in ["10.1.2.3", "::ffff:10.1.2.3", "fe80::1", "2001:db8::1", "0.0.0.0", "::", "fe80::1%x"]:
            requests.append(("K", [p, a]))
    for n in list(range(0, 40)) + [4, 4, 16, 16, 17, 18, 19, 20, 21, 22]:
        for _ in range(12):
            # Zones are Rust strings: bytes past the 16-byte address stay ASCII.
            requests.append(("B", [bytes(rng.randrange(256) if i < 16 else rng.randrange(1, 128) for i in range(n))]))
    lines = []
    for op, args in requests:
        lines.append(op + "".join(" " + hx(a) for a in args))
    # Arbitrary mutations may contain invalid UTF-8 only via lone surrogates, which cannot occur here.
    payload = "\n".join(lines) + "\n"

    rust_run = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", "netip_probe"],
        input=payload, text=True, capture_output=True, cwd=ROOT)
    if rust_run.returncode:
        raise RuntimeError(f"Rust netip probe failed:\n{rust_run.stderr}")
    go_run = subprocess.run(["go", "run", str(ROOT / "tools/netip_oracle.go")],
                            input=payload, text=True, capture_output=True, cwd=ROOT)
    if go_run.returncode:
        raise RuntimeError(f"Go netip oracle failed:\n{go_run.stderr}")
    rust, go = rust_run.stdout.splitlines(), go_run.stdout.splitlines()
    if len(rust) != len(lines) or len(go) != len(lines):
        raise AssertionError(f"oracle returned the wrong number of records: {len(rust)} {len(go)} {len(lines)}")
    for i, (actual, expected) in enumerate(zip(rust, go)):
        if actual != expected:
            raise AssertionError(f"vector {i}, request={lines[i]!r} ({requests[i]!r})\nRust={actual!r}\nGo={expected!r}")
    print(f"netip Go differential: {len(lines)} Addr, Prefix, AddrPort, codec, compare and containment vectors passed")


if __name__ == "__main__":
    main()
