#!/usr/bin/env python3
"""Differentially check log and log/slog output against Go, byte for byte.

log: every flag combination with prefixes, messages and instants. Go has no
clock hook, so the Go oracle runs inside a testing/synctest bubble and sleeps
the fake clock to the requested instant (see tools/log_oracle.go). File names
and line numbers differ by construction and are masked.

log/slog: generated scenarios (handler kind, HandlerOptions, ReplaceAttr
transform chains, WithAttrs/WithGroup chains, records with attributes of every
kind, nested groups and special characters) through TextHandler, JSONHandler,
MultiHandler and Logger, comparing everything the handler writes.
"""
import json
import os
import pathlib
import random
import re
import socket
import struct
import subprocess
import tempfile
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]

# --------------------------------------------------------------------- log


def log_scenarios():
    rng = random.Random(0x106106)
    prefixes = ["", "p: ", "pre fix", "é:", "x\ty"]
    messages = ["", "hello", "multi\nline", "trail\n", "\n", "tab\there", "日本語   x"]
    delays = [0, 1, 999, 1000, 123456789, 59999999999, 86400 * 10**9,
              59 * 86400 * 10**9, 3155760000123456789, 1000000000000000000,
              8200000000123456000, 31556952 * 10**9 * 3 + 5, 7 * 10**9 + 999999999]
    calls = ["print", "printf", "println", "output"]
    out = []
    for flags in range(128):
        for _ in range(8):
            out.append({"flags": flags, "prefix": rng.choice(prefixes), "msg": rng.choice(messages),
                        "delay": str(rng.choice(delays) + rng.choice([0, 0, 1, 500, 1234567])),
                        "call": rng.choice(calls)})
        for call in calls[:2]:
            out.append({"flags": flags, "prefix": rng.choice(prefixes), "msg": rng.choice(messages),
                        "delay": str(rng.randrange(0, 8 * 10**18)), "call": call, "pkg": True})
    for _ in range(300):
        out.append({"flags": rng.randrange(0, 256), "prefix": rng.choice(prefixes),
                    "msg": rng.choice(messages), "delay": str(rng.randrange(0, 8 * 10**18)),
                    "call": rng.choice(calls), "pkg": rng.random() < 0.3})
    return out


ZONEINFO = ROOT / "src" / "time" / "tzdata" / "zoneinfo.zip"


def local_env():
    """Both sides see the same Local zone: America/New_York from the checked-in zoneinfo.zip."""
    return dict(os.environ, TZ="America/New_York", ZONEINFO=str(ZONEINFO),
                GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")


GO_LOC = re.compile(r"(?:\S*/)?log_oracle\.go:\d+: ")
RS_LOC = re.compile(r"(?:\S*/)?log_probe\.rs:\d+: ")


def run_pair(go_args, rust_example, payload, env_extra=None):
    env = local_env()
    rust = subprocess.run(
        ["cargo", "run", "--quiet", "--offline", "--locked", "--example", rust_example],
        input=payload, text=True, capture_output=True, cwd=ROOT, env=env)
    if rust.returncode:
        raise RuntimeError(f"Rust {rust_example} failed:\n{rust.stderr}")
    go = subprocess.run(["go", "run"] + go_args, input=payload, text=True,
                        capture_output=True, cwd=ROOT, env=env)
    if go.returncode:
        raise RuntimeError(f"Go oracle {go_args} failed:\n{go.stderr}{go.stdout[-2000:]}")
    return rust.stdout.splitlines(), go.stdout.splitlines()


def check_log():
    scenarios = log_scenarios()
    payload = "".join(json.dumps(s) + "\n" for s in scenarios)
    rust, go = run_pair([str(ROOT / "tools/log_oracle.go")], "log_probe", payload)
    go = [line for line in go if line.startswith("R:")]
    if len(rust) != len(scenarios) or len(go) != len(scenarios):
        raise AssertionError(f"log: got {len(rust)} Rust and {len(go)} Go results for {len(scenarios)} scenarios")
    for i, (r, g, s) in enumerate(zip(rust, go, scenarios)):
        rf, rp, ro = r[2:].split("|")
        gf, gp, go_out = g[2:].split("|")
        ro = RS_LOC.sub("@LOC@ ", bytes.fromhex(ro).decode("utf-8", "surrogateescape"))
        go_out = GO_LOC.sub("@LOC@ ", bytes.fromhex(go_out).decode("utf-8", "surrogateescape"))
        if s["flags"] & 24:
            if "@LOC@ " not in ro or "@LOC@ " not in go_out:
                raise AssertionError(f"log vector {i}: missing file:line header\n{s}\nRust={ro!r}\nGo={go_out!r}")
        if (rf, rp, ro) != (gf, gp, go_out):
            raise AssertionError(f"log vector {i}: {s}\nRust={ro!r}\nGo={go_out!r}")
    print(f"Log Go differential: {len(scenarios)} flag/prefix/message/instant vectors passed")


# -------------------------------------------------------------------- slog

STRINGS = [
    "", "plain", "with space", "k=v", 'quote"s', "back\\slash", "nl\nx", "tab\t", "cr\rx",
    "\x00", "\x1f", "\x7f", "\x08\x0c", "é", "日本語", "😀", " ", " ", "�",
    "\u0085", " ", "​", "﻿", "á", "<>&", "'", "a.b", "a b=c", "=", " ",
    "­", "͸", "\U000e0001", "x y", "ß", "İstanbul", "ǅ", "lone\\", '"',
    "{}", "[]", ":", ",", "null", "true", "1", "-1", "1.5", "\\u0041", "%s %v", "!BADKEY",
]
KEYS = ["a", "b", "c", "user", "id", "x", "key with space", "k=v", "a.b", "", "é", "日本",
        '"q"', "tab\t", "new\nline", "back\\slash", "=", "drop", "g", "emptyg", "inl", "lv",
        "time", "level", "msg", "source", "ts", " ", "😀", "dotted.key", "-", "_"]
FLOATS = [0.0, -0.0, 1.5, 1e21, 1e20, 1e-7, 1e-6, 123456789.0, 1e100, 5e-324, 1.7976931348623157e308,
          float("nan"), float("inf"), float("-inf"), 100000.0, 1e6, 0.1, 2 / 3, 1e-5, 12345.678,
          -1e21, 999999999999999999999.0, 1e-4, 0.0001234, 3.0, 1e15, 123456789012345678.0]
INTS = [0, 1, -1, 42, 2**63 - 1, -(2**63), 1000000, -999, 255, 2**31]
UINTS = [0, 1, 2**64 - 1, 2**63, 42, 255]
DURATIONS = [0, 1, 999, 1000, 10**6, 10**9, 3600 * 10**9, -1, 2**63 - 1, -(2**63), 90061001001001,
             -3600 * 10**9, 1500 * 10**6]
LEVELS = [-8, -4, -3, -1, 0, 1, 2, 3, 4, 5, 7, 8, 9, 12, 2**63 - 1, -(2**63)]
NANOS = [0, 1, 999999, 1000000, 123456789, 999999999, 500000000, 100000000, 120000000]
OFFSETS = [0, 3600, -18000, 19800, 3601, -43200, 50400, 3, -45, 86399, -86399, 0]
JSON_NUMS = ["0", "-0", "1", "1.5", "1e21", "1e-7", "123456789012", "0.1", "1e6", "1E2", "-12.5e3",
             "100000", "0.000001", "1e20", "123456789.123456789"]
MODES = ["drop_time", "rename", "drop_key", "upper", "level_num", "group_aware", "to_group",
         "zero_all", "time_unix", "lv_ret", "empty_str_drop"]
ZERO_UNIX = -62135596800


def f64_bits(x):
    return struct.pack(">d", x).hex()


def g_string(rng):
    if rng.random() < 0.7:
        return rng.choice(STRINGS)
    return "".join(rng.choice(rng.choice(STRINGS) or "x") for _ in range(rng.randint(1, 8))) + rng.choice(STRINGS)


def g_time(rng):
    if rng.random() < 0.05:
        return {"s": ZERO_UNIX, "n": 0, "off": rng.choice([0, 3600])}
    return {"s": rng.randint(ZERO_UNIX + 90000, 253402300799 - 90000),
            "n": rng.choice(NANOS), "off": rng.choice(OFFSETS)}


def g_json(rng, depth=0):
    r = rng.random()
    if depth > 2 or r < 0.5:
        k = rng.randrange(5)
        if k == 0:
            return None
        if k == 1:
            return rng.random() < 0.5
        if k == 2:
            return ("NUM", rng.choice(JSON_NUMS))
        return rng.choice(STRINGS)
    if r < 0.75:
        return [g_json(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {rng.choice(KEYS + STRINGS): g_json(rng, depth + 1) for _ in range(rng.randint(0, 4))}


def render_json(v):
    """json.dumps that preserves numeric literals marked ("NUM", text)."""
    if isinstance(v, tuple):
        return v[1]
    if isinstance(v, list):
        return "[" + ",".join(render_json(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k) + ":" + render_json(x) for k, x in v.items()) + "}"
    return json.dumps(v)


class Raw(str):
    """Marker for pre-rendered JSON."""


def g_value(rng, depth=0, allow_str=True):
    kinds = ["str", "int", "uint", "f64", "bool", "dur", "time", "group", "nil", "any", "err",
             "bytes", "level", "valuer"]
    weights = [14, 8, 4, 8, 4, 5, 6, 8 if depth < 2 else 0, 3, 8, 3, 3, 3, 4 if depth < 3 else 0]
    kind = rng.choices(kinds, weights)[0]
    if not allow_str and kind == "str":
        kind = "int"
    if kind == "str":
        return {"t": kind, "v": g_string(rng)}
    if kind == "int":
        return {"t": kind, "v": str(rng.choice(INTS) if rng.random() < 0.7 else rng.randint(-10**6, 10**6))}
    if kind == "uint":
        return {"t": kind, "v": str(rng.choice(UINTS) if rng.random() < 0.7 else rng.randrange(0, 10**6))}
    if kind == "f64":
        if rng.random() < 0.7:
            return {"t": kind, "v": f64_bits(rng.choice(FLOATS))}
        return {"t": kind, "v": "%016x" % rng.getrandbits(64)}
    if kind == "bool":
        return {"t": kind, "v": rng.random() < 0.5}
    if kind == "dur":
        return {"t": kind, "v": str(rng.choice(DURATIONS) if rng.random() < 0.7 else rng.randint(-10**12, 10**12))}
    if kind == "time":
        return {"t": kind, "v": g_time(rng)}
    if kind == "group":
        return {"t": kind, "v": [g_attr(rng, depth + 1) for _ in range(rng.choice([0, 0, 1, 2, 3]))]}
    if kind == "nil":
        return {"t": kind}
    if kind == "any":
        return {"t": kind, "v": Raw(render_json(g_json(rng)))}
    if kind == "err":
        return {"t": kind, "v": g_string(rng)}
    if kind == "bytes":
        return {"t": kind, "v": bytes(rng.randrange(256) for _ in range(rng.randint(0, 10))).hex()}
    if kind == "level":
        return {"t": kind, "v": str(rng.choice(LEVELS))}
    return {"t": "valuer", "v": g_value(rng, depth + 1)}


def g_attr(rng, depth=0):
    a = g_value(rng, depth)
    a["k"] = rng.choice(KEYS) if rng.random() < 0.8 else g_string(rng)
    return a


def g_args(rng, last_dangling_ok=True):
    items = []
    for _ in range(rng.randint(0, 3)):
        r = rng.random()
        if r < 0.4:
            items.append({"attr": g_attr(rng)})
        elif r < 0.85:
            items.append({"key": rng.choice(KEYS), "val": g_value(rng, 1)})
        else:
            # Including string-kind slog.Values: in key position they are
            # !BADKEY, not a key.
            items.append({"bad": g_value(rng, 1)})
    if last_dangling_ok and rng.random() < 0.1:
        items.append({"key": rng.choice(KEYS)})
    return items


def g_rep(rng, logger_mode, need_fix):
    modes = [m for m in MODES if rng.random() < 0.2]
    if rng.random() < 0.4:
        modes = []
    if logger_mode:
        modes = ["drop_time"] + [m for m in modes if m != "drop_time"]
    if need_fix:
        modes.append("fixsrc")
        # fixsrc must see the Source before another mode reshapes it.
        modes = ["fixsrc"] + [m for m in modes if m != "fixsrc"] if "drop_time" not in modes else \
            ["drop_time", "fixsrc"] + [m for m in modes if m not in ("drop_time", "fixsrc")]
    return modes


def g_handler_opts(rng, logger_mode, need_fix, spec):
    spec["add_source"] = rng.random() < 0.25 or (need_fix and rng.random() < 0.8)
    if rng.random() < 0.4:
        spec["level"] = str(rng.choice([-4, 0, 4, 8, -8, 2, 12]))
    modes = g_rep(rng, logger_mode, need_fix or (spec["add_source"] and logger_mode))
    if modes:
        spec["rep"] = modes


def g_scenario(rng):
    logger_mode = rng.random() < 0.2
    use_pc = (not logger_mode) and rng.random() < 0.25
    need_fix = use_pc or (logger_mode and rng.random() < 0.3)
    spec = {}
    kind = rng.choices(["text", "json", "multi", "discard"], [42, 42, 12, 4])[0]
    spec["h"] = kind
    if kind == "multi":
        spec["subs"] = []
        for _ in range(rng.randint(1, 3)):
            sub = {"h": rng.choice(["text", "json"])}
            g_handler_opts(rng, logger_mode, need_fix, sub)
            spec["subs"].append(sub)
    else:
        g_handler_opts(rng, logger_mode, need_fix, spec)
    if logger_mode:
        spec["via"] = 1
    ops = []
    for _ in range(rng.choice([0, 0, 1, 2, 3, 4])):
        if rng.random() < 0.4:
            ops.append({"group": rng.choice(KEYS[:12] + ["g", "h", ""] if rng.random() < 0.9 else STRINGS)})
        elif logger_mode:
            ops.append({"args": g_args(rng)})
        else:
            ops.append({"attrs": [g_attr(rng) for _ in range(rng.choice([0, 1, 1, 2, 3]))]})
    spec["ops"] = ops
    recs = []
    for _ in range(rng.randint(1, 3)):
        rec = {"msg": g_string(rng)}
        if logger_mode:
            api = rng.choice(["log", "attrs", "debug", "info", "warn", "error"])
            rec["api"] = api
            rec["lvl"] = str({"debug": -4, "info": 0, "warn": 4, "error": 8}.get(api, rng.choice(LEVELS)))
            args = g_args(rng, last_dangling_ok=api != "attrs")
            if api == "attrs":
                args = [a for a in args if "attr" in a]
            rec["args"] = args
        else:
            rec["lvl"] = str(rng.choice(LEVELS) if rng.random() < 0.25 else rng.choice([0, 0, 4, 8, -4]))
            rec["t"] = None if rng.random() < 0.25 else g_time(rng)
            rec["pc"] = use_pc
            if rng.random() < 0.9:
                rec["attrs"] = [g_attr(rng) for _ in range(rng.choice([0, 1, 2, 3, 5]))]
        recs.append(rec)
    spec["recs"] = recs
    return spec


def dumps(v):
    if isinstance(v, Raw):
        return str(v)
    if isinstance(v, dict):
        return "{" + ",".join(json.dumps(k) + ":" + dumps(x) for k, x in v.items()) + "}"
    if isinstance(v, list):
        return "[" + ",".join(dumps(x) for x in v) + "]"
    return json.dumps(v)


def check_slog():
    rng = random.Random(0x510610)
    scenarios = [g_scenario(rng) for _ in range(4000)]
    payload = "".join(dumps(s) + "\n" for s in scenarios)
    rust, go = run_pair([str(ROOT / "tools/slog_oracle.go")], "slog_probe", payload)
    if len(rust) != len(scenarios) or len(go) != len(scenarios):
        raise AssertionError(f"slog: got {len(rust)} Rust and {len(go)} Go results for {len(scenarios)} scenarios")
    records = 0
    nonempty = 0
    for i, (r, g, s) in enumerate(zip(rust, go, scenarios)):
        records += len(s["recs"])
        if r != g:
            rm, ro = r.split(":")
            gm, go_out = g.split(":")
            raise AssertionError(
                f"slog vector {i}:\n{dumps(s)}\nmarkers Rust={bytes.fromhex(rm)!r} Go={bytes.fromhex(gm)!r}\n"
                f"Rust={bytes.fromhex(ro)!r}\nGo={bytes.fromhex(go_out)!r}")
        if g.split(":")[1]:
            nonempty += 1
    print(f"Slog Go differential: {len(scenarios)} scenarios, {records} records "
          f"({nonempty} with output) passed")


# ------------------------------------------------------------------ syslog

SYSLOG_OPS = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug", "write"]
SYSLOG_MSGS = ["hello", "", "multi\nline", "trail\n", "tab\there", "日本語", "x" * 300, "<13>nested", "%s %d"]
UDP_TS = re.compile(r"^<(\d+)>(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:Z|[+-]\d\d:\d\d)) (\S+) (t\d+)\[(\d+)\]: (.*)$", re.S)
LOCAL_TS = re.compile(r"^<(\d+)>([A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) (t\d+)\[(\d+)\]: (.*)$", re.S)


def syslog_scenarios():
    rng = random.Random(0x5151)
    out = []
    for i in range(160):
        out.append({"priority": rng.choice([0, 1, 3, 6, 7, 8, 14, 22, 23 << 3, (23 << 3) | 7, 11 << 3, 100, 191]),
                    "tag": f"t{i}",
                    "ops": [[rng.choice(SYSLOG_OPS), rng.choice(SYSLOG_MSGS)] for _ in range(rng.randint(1, 3))]})
    return out


def collect(kind, tmp):
    """Start a listener; return (raddr, join) where join() yields the received messages."""
    messages = []
    if kind == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Loopback UDP drops what does not fit the receive buffer. Linux's default
        # (about 208 KiB) overflowed while this thread lagged the sender.
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        sock.bind(("127.0.0.1", 0))
        raddr = "127.0.0.1:%d" % sock.getsockname()[1]
    elif kind == "unixgram":
        raddr = os.path.join(tmp, "sock")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.bind(raddr)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(128)
        raddr = "127.0.0.1:%d" % sock.getsockname()[1]
    sock.settimeout(0.2)
    stop = threading.Event()

    def read_stream(conn):
        """Read one TCP connection to EOF; a reset only ends that connection."""
        data = b""
        conn.settimeout(5)
        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
        except OSError:
            # Timeout or reset: keep what arrived, the comparison reports any shortfall.
            pass
        finally:
            conn.close()
        return data

    def serve():
        # Poll until the sender has exited (join sets stop) and the queue is
        # drained; compiling the Rust example must not end the listener early.
        # No error may end the loop while senders can still connect: a dead
        # listener leaves its backlog to fill and resets later clients.
        while True:
            try:
                if kind == "tcp":
                    conn, _ = sock.accept()
                    data = read_stream(conn)
                    messages.extend(data.decode("utf-8", "surrogateescape").split("\n"))
                else:
                    data = sock.recv(65536)
                    messages.append(data.decode("utf-8", "surrogateescape"))
            except socket.timeout:
                if stop.is_set():
                    return
            except OSError:
                # e.g. ECONNABORTED from accept when a client already reset.
                if stop.is_set():
                    return

    thread = threading.Thread(target=serve)
    thread.start()

    def join():
        stop.set()
        thread.join()
        sock.close()
        return messages

    return raddr, join


def normalize_syslog(messages):
    out = []
    for m in messages:
        if m == "":
            continue
        mt = UDP_TS.match(m)
        if mt:
            # The clock value differs per run; the zone suffix must match Go's local zone.
            out.append(("net", mt.group(1), mt.group(2)[19:], mt.group(3), mt.group(4), mt.group(6)))
            continue
        ml = LOCAL_TS.match(m)
        if ml:
            out.append(("local", ml.group(1), "", ml.group(3), ml.group(5)))
            continue
        out.append(("raw", m))
    return out


def run_syslog_side(kind, command, payload):
    with tempfile.TemporaryDirectory() as tmp:
        raddr, join = collect(kind, tmp)
        env = local_env()
        run = subprocess.run(command(kind, raddr), input=payload, text=True, capture_output=True,
                             cwd=ROOT, env=env)
        got = join()
    if run.returncode:
        raise RuntimeError(f"syslog {command} failed:\n{run.stderr}")
    return run.stdout, normalize_syslog(got)


def check_syslog():
    scenarios = syslog_scenarios()
    payload = "".join(json.dumps(s) + "\n" for s in scenarios)
    total = 0
    for kind in ("udp", "tcp", "unixgram"):
        rust_out, rust_msgs = run_syslog_side(
            kind, lambda k, a: ["cargo", "run", "--quiet", "--offline", "--locked", "--example",
                                "syslog_probe", "--", k, a], payload)
        go_out, go_msgs = run_syslog_side(
            kind, lambda k, a: ["go", "run", str(ROOT / "tools/syslog_oracle.go"), k, a], payload)
        if rust_out != go_out:
            raise AssertionError(f"syslog {kind} diagnostics differ:\nRust={rust_out!r}\nGo={go_out!r}")
        expected_ops = sum(len(s["ops"]) for s in scenarios)
        if (kind != "tcp" and len(go_msgs) != expected_ops) or rust_msgs != go_msgs:
            for i, (r, g) in enumerate(zip(rust_msgs, go_msgs)):
                if r != g:
                    raise AssertionError(f"syslog {kind} message {i}:\nRust={r!r}\nGo={g!r}")
            raise AssertionError(f"syslog {kind}: Rust delivered {len(rust_msgs)}, Go {len(go_msgs)}, "
                                 f"expected {expected_ops}")
        total += len(go_msgs)
    print(f"Syslog Go differential: {total} datagrams over udp, tcp and unixgram passed")


def main():
    check_log()
    check_slog()
    check_syslog()


if __name__ == "__main__":
    main()
