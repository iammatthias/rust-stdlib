#!/usr/bin/env python3
"""Differentially check live loopback TCP, UDP, Unix and net.Pipe behaviour against Go:
echo transfers, half-close, deadlines, closed-connection errors, refused dials, accept
unblocking, address and resolver error texts. Each scenario prints its observations
(error class and exact text); ephemeral ports are normalised."""
import pathlib
import re
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]

SCRIPT = []
for n in [0, 1, 5, 1000, 65536, 300000]:
    SCRIPT.append(f"tcp_echo {n}")
for n in [1, 17, 4096]:
    SCRIPT += [f"unix_echo {n}", f"pipe_echo {n}"]
for n in [0, 1, 100, 1400]:
    SCRIPT.append(f"udp_echo {n}")
for ms in [20, 60, 150]:
    SCRIPT.append(f"tcp_deadline {ms}")
# A blocked read and accept woken from another thread by a deadline change or
# Close return promptly (the std-based Rust types poll about every 50 ms; the
# bound here is looser than the crates/sys types are held to in sys_check.py).
SCRIPT += [f"tcp_wake {how}" for how in ("now", "shorten", "close")] * 2
SCRIPT += ["tcp_refused", "tcp_closed", "tcp_accept_close", "tcp_accept_deadline", "tcp_read_close", "tcp_in_use",
           "udp_connected", "unix_dgram", "pipe_deadline", "addr_errors", "resolve"]
# Repeat the concurrency-sensitive scenarios to shake out races.
SCRIPT += ["tcp_echo 100", "tcp_read_close", "tcp_accept_close", "tcp_closed", "pipe_echo 33", "udp_echo 64"] * 3


def run(cmd):
    p = subprocess.run(cmd, input="\n".join(SCRIPT) + "\n", text=True, capture_output=True, cwd=ROOT, timeout=600)
    if p.returncode:
        raise RuntimeError(f"{cmd} failed:\n{p.stderr}")
    return [re.sub(r":\d{4,5}\b", ":P", line) for line in p.stdout.splitlines()]


def main():
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "conn_probe"])
    go = run(["go", "run", str(ROOT / "tools/conn_oracle.go")])
    if len(rust) != len(SCRIPT) or len(go) != len(SCRIPT):
        raise AssertionError(f"wrong number of records: {len(rust)} {len(go)} {len(SCRIPT)}")
    bad = []
    for i, (a, b) in enumerate(zip(rust, go)):
        if a != b:
            bad.append(f"scenario {i} {SCRIPT[i]!r}\nRust: {a}\nGo:   {b}")
    if bad:
        raise AssertionError("\n\n".join(bad))
    print(f"conn Go differential: {len(SCRIPT)} loopback TCP, UDP, Unix, pipe and resolver scenarios passed")


if __name__ == "__main__":
    main()
