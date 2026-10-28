#!/usr/bin/env python3
"""Differentially check rust_stdlib_sys against Go (docs/adr/0004).

tools/sys_oracle.go and crates/sys/examples/sys_probe run the same scripted
scenarios (one tab-separated line each) and print one observation line per
scenario: ids, groups and hostname, Errno/Signal text and numbers, Chtimes and
Link results, signalling, then the network scenarios (interfaces, socket
options, deadlines, raw sockets). Each side runs in its own scratch directory
holding the same prepared files. The wake scenarios block a call on one thread and change a deadline or close from another, asserting the call returns promptly. Output lines must match exactly.
"""
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IFACE_SCENARIOS = ("ifaces", "ifaddrs", "iflookup")
# One initial sample plus three resamples.
IFACE_ATTEMPTS = 4


def os_scenarios(rng):
    out = ["ids", "groups", "hostname", "errnos"]
    out += [f"errno\t{n}" for n in list(range(0, 140)) + [-1, 100000]]
    out += [f"signal\t{n}" for n in list(range(0, 36)) + [-1, 1000]]
    out += [f"errno_class\t{n}" for n in range(0, 120)]
    stamps = [("0", "0"), ("1", "5"), ("1700000000", "123456789"), ("-5", "250"), ("2000000000", "999999999"),
              ("86400", "0"), ("-1", "999999999")]
    for name in ["f", "g", "d", "nosuch", "nosuch/x", "", "f/x", "d/"]:
        for _ in range(6):
            a, m = rng.choice(stamps + [("-", "-")]), rng.choice(stamps + [("-", "-")])
            out.append(f"chtimes\t{name}\t{a[0]}\t{a[1]}\t{m[0]}\t{m[1]}")
    out.append("chtimes\tf\t7\t7\t-\t-")
    out.append("chtimes\tf\t-\t-\t8\t8")
    out.append("chtimes\tf\t-\t-\t-\t-")
    out += ["link\tf\tl1", "link\tf\tl1", "link\tf\td/l2", "link\tnosuch\tl3", "link\td\tl4", "link\tf\tnosuch/l5",
            "link\tl1\tl6", "link\tf\tf", "link\tf\t", "link\t\tl7", "link\tf\td"]
    out += ["kill\tself\t0", "kill\tppid\t0", "kill\t1\t0", "kill\t999999\t0", "kill\t0\t0", "kill\t-1\t0",
            "kill\t999999\t15", "kill\tself\t1000", "kill\tself\t-1"]
    out += ["child\t15", "child\t9", "child\t2", "child\t0", "child\t1000"]
    return out


def net_scenarios(rng):
    out = ["ifaces", "ifaddrs", "iflookup", "badfd", "rawconn"]
    tcp_ops = ["linger:0", "linger:5", "linger:-1", "linger:100", "rcvbuf:65536", "rcvbuf:4096", "rcvbuf:1000000",
               "rcvbuf:0", "sndbuf:32768", "sndbuf:1", "sndbuf:262144", "nodelay:0", "nodelay:1", "keepalive:1",
               "keepalive:0", "period:30000", "period:1", "period:1500", "period:0", "period:-1", "period:999",
               "cfg:1:0:0:0", "cfg:1:1500:-1:3", "cfg:0:20000:5000:0", "cfg:1:-1:-1:-1", "cfg:1:2000:2001:7",
               "cfg:1:60000:10000:2"]
    for size in (0, 1, 100, 1400, 9000):
        for rsize in (0, 5, 2000, 65536):
            out.append(f"udpmsg\t{size}\t{rsize}\tnone")
    for size in (0, 7, 1400):
        out.append(f"udpmsg\t{size}\t2000\tttl")
    out += ["udpmsg_ap", "udpmsg_conn", "unixmsg", "unixmsg_stream"]
    out.append("tcpopts\t" + " ".join(tcp_ops))
    for _ in range(30):
        out.append("tcpopts\t" + " ".join(rng.choice(tcp_ops) for _ in range(rng.randrange(1, 6))))
    buf_ops = ["rcvbuf:65536", "rcvbuf:4096", "rcvbuf:262144", "sndbuf:32768", "sndbuf:8192", "rcvbuf:1", "sndbuf:1",
               "rcvbuf:0", "sndbuf:1000000"]
    for kind in ("udpopts", "unixopts"):
        out.append(kind + "\t" + " ".join(buf_ops))
        for _ in range(10):
            out.append(kind + "\t" + " ".join(rng.choice(buf_ops) for _ in range(rng.randrange(1, 5))))
    return out


def file_scenarios():
    out = ["fdl_pipe_kind", "fdl_rw", "fdl_files", "fdl_past", "fdl_extend", "fdl_shorten_now", "fdl_cancel", "fdl_close", "fdl_write"]
    out += [f"fdl_timeout\t{ms}" for ms in (20, 60, 150)]
    return out


def dial_scenarios():
    out = []
    for network, host, lnet, laddr in [("tcp", "127.0.0.1:{p}", "tcp", "127.0.0.1:0"), ("tcp4", "localhost:{p}", "tcp", "127.0.0.1:0"),
                                       ("tcp", "localhost:{p}", "tcp", "127.0.0.1:0"), ("tcp6", "[::1]:{p}", "tcp", "[::1]:0"),
                                       ("tcp", ":{p}", "tcp", "127.0.0.1:0"), ("tcp", "[::1]:{p}", "tcp", "[::1]:0"),
                                       ("tcp4", "127.0.0.1:{p}", "tcp4", "127.0.0.1:0")]:
        out.append(f"dial_basic\t{network}\t{host}\t{lnet}\t{laddr}")
    for network, address in [("tcp", "127.0.0.1:1"), ("tcpx", "127.0.0.1:1"), ("tcp", ""), ("tcp", "1.2.3.4"), ("tcp", "[::1"),
                             ("tcp", "::1:80"), ("tcp", "[::1]80"), ("tcp", "a]:80"), ("tcp", "[a[:80"), ("udp", "127.0.0.1:99999"),
                             ("udp", "127.0.0.1:foo"), ("tcp", "127.0.0.1:http-nosuch"), ("unix", ""), ("ip4:icmp", "127.0.0.1"),
                             ("ip4:foo", "127.0.0.1"), ("ip", "127.0.0.1"), ("ip6:ipv6-icmp", "::1"), ("ip4:255", "127.0.0.1"),
                             ("unixpacket", "nosuch.sock"), ("unix", "nosuch.sock"), ("unixgram", "nosuch.sock"),
                             ("tcp", "nosuch.invalid:80"), ("tcp6", "127.0.0.1:80"), ("tcp4", "[::1]:80"), ("tcp", "10.255.255.1:81"),
                             ("udp", "127.0.0.1:0"), ("tcp:x", "127.0.0.1:80"), ("tcp", "127.0.0.1:-1")]:
        out.append(f"dial_err\t{network}\t{address}")
    out.append("dial_unix_refused")
    out += [f"dial_local\t{spec}" for spec in ("none", "ip", "ipport", "udp", "v6", "wild")]
    out += [f"dial_control\t{mode}" for mode in ("ok", "error", "ctx")]
    keep = ["0\t0\t0\t0\t0", "-1\t0\t0\t0\t0", "30000\t0\t0\t0\t0", "0\t1\t2000\t3000\t4", "0\t1\t0\t-1\t-1", "5000\t1\t0\t0\t0",
            "-1\t1\t1500\t0\t0", "100\t0\t7000\t8000\t9"]
    out += [f"dial_keepalive\t{k}" for k in keep] + [f"listen_keepalive\t{k}" for k in keep]
    out += ["listen_accept_deadline", "listen_unix"]
    out += ["listen_err\ttcp\t127.0.0.1:99999", "listen_err\ttcpx\t:0", "listen_err\tunix\tlu2.sock", "listen_err\tunixpacket\tlp.sock",
            "listen_err\tudp\t:0", "listen_err\ttcp\t", "listen_err\ttcp\t1.2.3.4:5", "listen_err\ttcp\tnosuch.invalid:80",
            "listen_err\ttcp4\t[::1]:0", "listen_err\tunix\t",
            "listenpacket_err\ttcp\t:0", "listenpacket_err\tip4:icmp\t0.0.0.0", "listenpacket_err\tudp\t1.2.3.4:5",
            "listenpacket_err\tunixpacket\tlp.sock", "listenpacket_err\tbogus\t:0", "listenpacket_err\tudp\t:99999",
            "listenpacket_udp\tudp\t127.0.0.1:0", "listenpacket_udp\tudp4\t:0", "listenpacket_udp\tudp\t:0", "listenpacket_unixgram"]
    out += ["dialunix\tunix\t-\t-", "dialunix\tunix\t-\tnosuch.sock", "dialunix\tunixgram\t-\t-", "dialunix\tunixgram\tdg1.sock\t-",
            "dialunix\tunixpacket\t-\tnosuch.sock", "dialunix\tbogus\t-\tx", "listenunix\tunix\t-", "listenunix\tbogus\tx",
            "listenunix\tunixpacket\tlp3.sock", "listenunix\tunixgram\tlp4.sock"]
    out += ["dialip\tip4:icmp\t-\t127.0.0.1", "dialip\tip4:icmp\t-\t-", "dialip\tip4:icmp\t127.0.0.1\t127.0.0.1",
            "dialip\tip6:ipv6-icmp\t-\t::1", "dialip\tip4:1\t-\t127.0.0.1", "dialip\tip\t-\t127.0.0.1", "dialip\ttcp\t-\t127.0.0.1",
            "listenip\tip4:icmp\t-", "listenip\tip4:icmp\t127.0.0.1", "listenip\tip6:58\t::1", "listenip\tip4:foo\t-"]
    out += ["dialtcp\ttcp\t-\t127.0.0.1", "dialtcp\ttcp\t-\t-", "dialtcp\tudp\t-\t127.0.0.1", "dialtcp\ttcp\t127.0.0.1\t127.0.0.1",
            "dialtcp\ttcp6\t::1\t127.0.0.1", "dialtcp\ttcp4\t-\t127.0.0.1"]
    out += ["multicast\tudp4\t-\t239.1.2.3:5000", "multicast\tudp4\tlo0\t239.1.2.3:5000", "multicast\tudp6\t-\t[ff02::1234]:5002",
            "multicast\tudp6\tlo0\t[ff02::1235]:5003", "multicast\tudp\t-\t-:5000", "multicast\ttcp\t-\t239.1.2.3:5000",
            "multicast\tudp4\t-\t1.2.3.4:5000", "multicast\tudp4\tnosuch0\t239.1.2.3:5000"]
    out.append("fileconn")
    return out


def wake_scenarios():
    """A call blocked on one thread is woken by a deadline change or Close from another, within a small bound."""
    reads = ["now", "both", "past", "shorten", "close", "extend", "clear"]
    out = []
    for kind, hows in [("tcp_read", reads), ("unix_read", reads), ("udp_read", reads), ("unixgram_read", reads),
                       ("tcp_write", ["now", "both", "shorten", "close"]), ("unix_write", ["now", "both", "shorten", "close"]),
                       ("tcp_accept", reads), ("unix_accept", reads)]:
        out += [f"wake\t{kind}\t{how}" for how in hows]
    # Repeat to shake out races between the waiter and the waker.
    return out * 3


# rust_stdlib_sys resolves names through the C library, so the oracle uses Go's cgo
# resolver. Go on Linux would otherwise use its own, whose errors name the server.
ORACLE_ENV = dict(os.environ, GODEBUG="netdns=cgo")


def build_probe():
    p = subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--manifest-path", "crates/sys/Cargo.toml",
                        "--example", "sys_probe"], cwd=ROOT, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"build failed:\n{p.stderr}")
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                                               "--no-deps", "--manifest-path", "crates/sys/Cargo.toml"],
                                              cwd=ROOT, text=True))
    return Path(meta["target_directory"]) / "debug" / "examples" / "sys_probe"


def main():
    probe = build_probe()
    tmp = Path(tempfile.mkdtemp(prefix="sysdiff"))
    goexe = tmp / "oracle"
    subprocess.run(["go", "build", "-o", str(goexe), str(ROOT / "tools" / "sys_oracle.go"),
                    str(ROOT / "tools" / "sys_oracle_net.go"), str(ROOT / "tools" / "sys_oracle_file.go"), str(ROOT / "tools" / "sys_oracle_msg.go"),
                    str(ROOT / "tools" / "sys_oracle_dial.go"), str(ROOT / "tools" / "sys_oracle_wake.go")],
                   cwd=ROOT, check=True)
    rng = random.Random(0x5155)
    scenarios = [s for s in os_scenarios(rng) + net_scenarios(rng) + file_scenarios() + dial_scenarios() + wake_scenarios()
                 if s.split("\t")[0] not in IFACE_SCENARIOS]
    payload = "\n".join(scenarios) + "\n"
    results = {}
    for name, exe in (("rust", probe), ("go", goexe)):
        wd = tmp / name
        wd.mkdir()
        (wd / "f").write_text("data")
        (wd / "g").write_text("more")
        (wd / "d").mkdir()
        os.mkfifo(wd / "ff")
        results[name] = run_probe(exe, wd, payload, env=ORACLE_ENV if name == "go" else None)
    rust, go = normalize(results["rust"]), normalize(results["go"])
    if len(rust) != len(scenarios) or len(go) != len(scenarios):
        raise AssertionError(f"record count: expected {len(scenarios)}, rust {len(rust)}, go {len(go)}")
    bad = [(s, r, g) for s, r, g in zip(scenarios, rust, go) if r != g]
    bad += check_interfaces(probe, goexe, tmp)
    for s, r, g in bad[:15]:
        print(f"MISMATCH {s!r}\n  Rust: {r}\n  Go:   {g}")
    total = len(scenarios) + len(IFACE_SCENARIOS)
    if bad:
        raise SystemExit(f"{len(bad)} of {total} sys results differ")
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"Go/Rust sys differential: {total} scenarios passed")


def run_probe(exe, wd, payload, env=None):
    p = subprocess.run([str(exe)], input=payload, text=True, capture_output=True, cwd=wd, timeout=300, env=env)
    if p.returncode:
        raise RuntimeError(f"{exe.name} failed:\n{p.stderr[-2000:]}")
    return p.stdout.splitlines()


def normalize(lines):
    # Ephemeral ports differ between the two runs.
    lines = [re.sub(r":\d{4,5}\b", ":P", line) for line in lines]
    # Multicast tests (here and in other suites running concurrently) join and
    # leave groups in the administratively scoped 239/8 range, so interface
    # membership lists can change between the two samples; ignore that range.
    return [re.sub(r",?239\.\d+\.\d+\.\d+", "", line) for line in lines]


def check_interfaces(probe, goexe, tmp):
    """Compare the interface scenarios, sampling Rust between two Go samples.

    VM networking on the host (vmenet*, bridge*) adds and removes interfaces
    while the suite runs. Go is sampled before and after each Rust sample; the
    Rust sample is compared only when the two Go samples agree, so the
    interface list is known to be unchanged across it. Stable interfaces keep
    full-field comparison. Returns the mismatching (scenario, Rust, Go) records.
    """
    payload = "\n".join(IFACE_SCENARIOS) + "\n"
    for attempt in range(1, IFACE_ATTEMPTS + 1):
        go_before = normalize(run_probe(goexe, tmp / "go", payload))
        rust = normalize(run_probe(probe, tmp / "rust", payload))
        go_after = normalize(run_probe(goexe, tmp / "go", payload))
        if len(rust) != len(IFACE_SCENARIOS) or len(go_after) != len(IFACE_SCENARIOS):
            raise AssertionError(f"interface record count: rust {len(rust)}, go {len(go_after)}")
        if go_before == go_after:
            return [(s, r, g) for s, r, g in zip(IFACE_SCENARIOS, rust, go_after) if r != g]
        print(f"interface list changed during sample {attempt} of {IFACE_ATTEMPTS}; resampling")
    raise AssertionError(f"interface list did not stabilise in {IFACE_ATTEMPTS} samples; no comparison made")


if __name__ == "__main__":
    main()
