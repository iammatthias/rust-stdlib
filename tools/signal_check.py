#!/usr/bin/env python3
"""Differentially check os/signal against Go with real signals.

Each scenario starts a Go oracle and a Rust probe (crates/sys/examples/
signal_probe.rs) as processes with the same initial signal dispositions, drives
both with the same Notify/Stop/Ignore/Reset/Ignored/NotifyContext commands and
delivers the same signals with kill(2). The signals each channel received (in
order, dropping on a full channel), Ignored results and the NotifyContext
error, cause and text must agree. Only signals whose handling the commands have
fixed (wanted by a channel, or ignored) are sent: the action of a signal
nobody asked about is the documented runtime difference.
"""
import os
import pathlib
import random
import signal
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
SYS = ROOT / "crates/sys"
TARGET = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", SYS / "target"))
NAMES = {"HUP": signal.SIGHUP, "INT": signal.SIGINT, "USR1": signal.SIGUSR1, "USR2": signal.SIGUSR2,
         "TERM": signal.SIGTERM, "ALRM": signal.SIGALRM, "WINCH": signal.SIGWINCH,
         "CHLD": signal.SIGCHLD}
SENDABLE = list(NAMES)
# Signals Go's runtime also uses itself, so they stay out of the random
# scenarios (Go raises SIGURG to preempt goroutines, which reaches a Notify
# channel at unpredictable times) and get a fixed scenario each. SIGPROF is
# given by number because the oracle names only the others.
RESERVED = {"URG": signal.SIGURG, "27": signal.SIGPROF}


class Proc:
    def __init__(self, command, initially_ignored):
        def setup():
            for name in initially_ignored:
                signal.signal(NAMES[name], signal.SIG_IGN)
        self.p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
                                  preexec_fn=setup)
        self.pid = int(self.ask("pid"))

    def ask(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        out = self.p.stdout.readline()
        if not out:
            raise RuntimeError(f"probe died on: {line}")
        return out.rstrip("\n")

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


def scenario(rng):
    """Returns (initially ignored signals, [commands]); a ("kill", sig) pair is
    delivered by the harness."""
    initially = rng.sample(["HUP", "INT"], rng.randrange(0, 3)) if rng.random() < 0.4 else []
    wanted = {}          # channel -> set of signals
    ignored = set(initially)
    chans = []
    ops = []
    ctxs = []

    def safe():
        out = set(ignored)
        for sigs in wanted.values():
            out |= sigs
        for _, sigs in ctxs:
            out |= sigs
        return sorted(out & set(SENDABLE))

    for _ in range(rng.randrange(4, 16)):
        roll = rng.random()
        if roll < 0.15 or not chans:
            name = f"c{len(chans)}"
            chans.append(name)
            wanted[name] = set()
            ops.append(f"chan {name} {rng.choice([0, 1, 1, 2, 4])}")
        elif roll < 0.35:
            c = rng.choice(chans)
            sigs = rng.sample(SENDABLE, rng.randrange(1, 4))
            ops.append(f"notify {c} {','.join(sigs)}")
            wanted[c] |= set(sigs)
            ignored -= set(sigs)
        elif roll < 0.4:
            c = rng.choice(chans)
            ops.append(f"stop {c}")
            wanted[c] = set()
        elif roll < 0.46:
            sigs = rng.sample(SENDABLE, rng.randrange(1, 3))
            ops.append(f"ignore {','.join(sigs)}")
            for k in wanted:
                wanted[k] -= set(sigs)
            ignored |= set(sigs)
        elif roll < 0.52:
            sigs = rng.sample(SENDABLE, rng.randrange(1, 3))
            ops.append(f"reset {','.join(sigs)}")
            for k in wanted:
                wanted[k] -= set(sigs)
        elif roll < 0.58:
            ops.append(f"ignored {rng.choice(SENDABLE)}")
        elif roll < 0.63:
            name = f"x{len(ctxs)}"
            sigs = set(rng.sample(["USR1", "USR2", "TERM", "ALRM"], rng.randrange(1, 3)))
            ctxs.append((name, sigs))
            ops.append(f"ctx {name} {','.join(sorted(sigs))}")
            ignored -= sigs
        elif roll < 0.67 and ctxs:
            name, sigs = rng.choice(ctxs)
            ops.append(f"ctxstop {name}")
            ctxs = [c for c in ctxs if c[0] != name]
        elif roll < 0.72 and ctxs:
            ops.append(f"ctxinfo {rng.choice(ctxs)[0]}")
        elif roll < 0.95 and safe():
            ops.append(("kill", rng.choice(safe())))
            ops.append(f"drain {rng.choice(chans)}")
            if ctxs:
                ops.append(f"ctxinfo {rng.choice(ctxs)[0]}")
        else:
            ops.append(f"drain {rng.choice(chans)}")
    for c in chans:
        ops.append(f"drain {c}")
    return initially, ops


def run_scenario(go_cmd, rust_cmd, initially, ops):
    go, rust = Proc(go_cmd, initially), Proc(rust_cmd, initially)
    log = []
    try:
        for op in ops:
            if isinstance(op, tuple):
                os.kill(go.pid, NAMES[op[1]])
                os.kill(rust.pid, NAMES[op[1]])
                time.sleep(0.03)
                log.append((f"kill {op[1]}", "", ""))
                continue
            g, r = go.ask(op), rust.ask(op)
            log.append((op, g, r))
    finally:
        go.close()
        rust.close()
    return log


def reserved(go_cmd, rust_cmd):
    """SIGURG is relayed to a Notify channel (Go may add preemption signals of
    its own, so only the first delivery is compared); SIGPROF is swallowed by
    the runtime profiler handler: the process survives and nothing is relayed."""
    for name, sig in RESERVED.items():
        go, rust = Proc(go_cmd, []), Proc(rust_cmd, [])
        try:
            got = []
            for p in (go, rust):
                p.ask("chan c 4")
                p.ask(f"notify c {name}")
                os.kill(p.pid, sig)
                time.sleep(0.1)
                got.append(p.ask("drain c"))
                p.ask("pid")  # still alive
            # Go's runtime raises SIGURG itself to preempt goroutines, so its
            # channel may hold extra copies: compare the first delivery only.
            first = [g.split(",")[0] for g in got]
            if first[0] != first[1] or bool(first[0]) != (name == "URG"):
                raise AssertionError(f"Notify({name}): Go={got[0]!r} Rust={got[1]!r}")
        finally:
            go.close()
            rust.close()


def main():
    started = time.monotonic()
    rng = random.Random(0x5349475F)
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "signal_probe"],
                   cwd=SYS, check=True)
    rust_cmd = [str(TARGET / "debug/examples/signal_probe")]
    count = int(os.environ.get("SIGNAL_SCENARIOS", "50"))
    delivered = 0
    with tempfile.TemporaryDirectory() as tmp:
        go_bin = os.path.join(tmp, "signal_oracle")
        subprocess.run(["go", "build", "-o", go_bin, str(ROOT / "tools/signal_oracle.go")], cwd=ROOT, check=True)
        for n in range(count):
            initially, ops = scenario(rng)
            log = run_scenario([go_bin], rust_cmd, initially, ops)
            for op, g, r in log:
                if g != r:
                    steps = "\n".join(f"  {o} -> go={a!r} rust={b!r}" for o, a, b in log)
                    raise AssertionError(f"scenario {n} (initially ignored {initially}): {op}\nGo  ={g!r}\nRust={r!r}\n{steps}")
                delivered += op.startswith("drain") and bool(g)
        reserved([go_bin], rust_cmd)
    print(f"signal Go differential: {count} scenarios of real signals ({delivered} non-empty deliveries compared) "
          f"passed in {time.monotonic() - started:.1f}s")


if __name__ == "__main__":
    main()
