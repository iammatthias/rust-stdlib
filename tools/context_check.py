#!/usr/bin/env python3
"""Differentially check context trees (cancel, cause, deadlines, values,
WithoutCancel, AfterFunc) against Go.

Scripts are random sequences of With*/cancel/AfterFunc/stop operations with
small real deadlines (25 ms "short" timers, one-hour "long" timers); see
tools/context_oracle.go for the grammar. Err, Cause, Deadline presence,
Done-nil-ness, Value, String (deadline payload elided) and the set of fired
AfterFuncs are compared. AfterFunc firing order is not compared: Go runs each
function in its own goroutine over a map, so it is unspecified.
"""
import pathlib
import random
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SHORT, LONG = 25, 3_600_000


def op_script(rng, nodes, afs, ops, allow_new=True):
    """Append one random operation to `ops`, tracking node/AfterFunc counts."""
    kind = rng.choices(
        ["cancel", "cause", "dl", "dlc", "dd", "ddc", "val", "woc", "af", "x", "xc", "stop", "snap"],
        [10, 8, 6, 4, 4, 3, 7, 3, 9, 9, 5, 4, 2],
    )[0]
    parent = rng.randrange(nodes)
    if kind in ("cancel", "cause", "woc") and allow_new:
        ops.append(f"{kind} {parent}")
        return nodes + 1, afs
    if kind in ("dl", "dlc") and allow_new:
        ops.append(f"{kind} {parent} {rng.choice([0, SHORT, LONG, LONG])}")
        return nodes + 1, afs
    if kind in ("dd", "ddc") and allow_new:
        ops.append(f"{kind} {parent} {rng.choice([-5, 0, SHORT, LONG, LONG])}")
        return nodes + 1, afs
    if kind == "val" and allow_new:
        ops.append(f"val {parent} {rng.randrange(3)} v{rng.randrange(100)}")
        return nodes + 1, afs
    if kind == "af":
        ops.append(f"af {parent}")
        return nodes, afs + 1
    if kind == "x":
        ops.append(f"x {parent}")
    elif kind == "xc":
        ops.append(f"xc {parent} why{rng.randrange(5)}")
    elif kind == "stop" and afs:
        ops.append(f"stop {rng.randrange(afs)}")
    elif kind == "snap":
        ops.append("snap")
    return nodes, afs


def make_script(rng):
    ops, nodes, afs = [], 1, 0
    for _ in range(rng.randint(3, 16)):
        nodes, afs = op_script(rng, nodes, afs, ops)
    ops.append("snap")
    ops.append("sleep 90")  # short timers expire in both implementations
    for _ in range(rng.randint(0, 6)):
        nodes, afs = op_script(rng, nodes, afs, ops)
    ops.append("snap")
    return " ".join(ops)


FIXED = [
    # Go's TestCause "stacked" cases.
    "cause 0 dlc 1 0 xc 1 early",
    "cause 0 dlc 1 3600000 xc 1 early",
    "cause 0 cause 1 xc 2 child xc 1 parent",
    "cause 0 cause 1 xc 1 parent xc 2 child",
    "cause 0 cancel 1 x 2 xc 1 parent",
    "cancel 0 cause 1 x 1 xc 2 child",
    # WithoutCancel keeps values and drops cancellation.
    "val 0 0 a cause 1 woc 2 cancel 3 xc 2 gone snap",
    "dl 0 25 woc 1 cancel 2 af 3 af 1 snap sleep 90",
    # Later deadlines degrade to WithCancel; equal ones keep WithDeadline.
    "dl 0 3600000 dl 1 3600001 dd 1 -5 dl 2 0",
    # AfterFunc stop semantics.
    "cancel 0 af 1 stop 0 x 1 stop 0",
    "cancel 0 af 1 x 1 stop 0 af 1 stop 1",
    "dl 0 25 af 1 af 1 stop 1 sleep 90 stop 0",
    "af 0 stop 0 stop 0",
    "woc 0 af 1 stop 0",
]


def run(cmd, payload):
    done = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if done.returncode:
        raise RuntimeError(f"{cmd[0]} {cmd[-1]} failed:\n{done.stderr}")
    return done.stdout.splitlines()


def both(scripts):
    payload = "".join(s + "\n" for s in scripts)
    rust = run(["cargo", "run", "--quiet", "--offline", "--locked", "--example", "context_probe"], payload)
    go = run(["go", "run", str(ROOT / "tools/context_oracle.go")], payload)
    if len(rust) != len(scripts) or len(go) != len(scripts):
        raise AssertionError("context oracle returned the wrong number of records")
    return rust, go


def main():
    rng = random.Random(0xC0417)
    scripts = FIXED + [make_script(rng) for _ in range(2500)]
    rust, go = both(scripts)
    suspects = [i for i, (a, b) in enumerate(zip(rust, go)) if a != b]
    # Real deadlines race with a loaded machine; re-run mismatches in isolation
    # (alone, 25 ms is ample) before declaring a difference.
    for attempt in range(3):
        if not suspects:
            break
        again_rust, again_go = both([scripts[i] for i in suspects])
        still = []
        for i, a, b in zip(suspects, again_rust, again_go):
            rust[i], go[i] = a, b
            if a != b:
                still.append(i)
        suspects = still
    for i in suspects:
        raise AssertionError(f"script {i}: {scripts[i]}\nRust={rust[i]}\nGo  ={go[i]}")
    print(f"Context Go differential: {len(scripts)} scripted context trees passed")


if __name__ == "__main__":
    main()
