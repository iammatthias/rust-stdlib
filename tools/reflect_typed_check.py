#!/usr/bin/env python3
"""Compare reflect on #[derive(Reflect)] types with reflect on the equivalent
real Go types: embedding, shadowing, promoted methods (value and pointer
receivers, through embedded pointers), interfaces, generics, recursion, struct
tags, unexported fields, Set/CanSet through embedded fields, and Call."""
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUST = ["cargo", "run", "--quiet", "--offline", "--locked", "--manifest-path",
        "tools/derive-check/Cargo.toml", "--example", "reflect_typed_probe"]
GO = ["go", "run", "tools/reflect_typed_oracle.go"]


def hx(s):
    return s.encode().hex() or "-"


STRUCTS = ["Base", "Named", "Mid", "Top", "Point", "Pair", "Pair2", "Node", "Wrap"]
ALL = STRUCTS + ["Color", "Shape", "Scaler", "Describer", "int", "string", "any", "error"]
NAMES = ["ID", "Name", "Extra", "Level", "Tags", "Val", "Next", "Kids", "Mid", "Base", "Named", "First",
         "Second", "X", "Y", "name", "secret", "Node", "Zip"]

BASE = "[7,%s,n]" % hx("bob")
NAMED = "[%s,3]" % hx("nm")
MID = "[%s,%s,9]" % (BASE, NAMED)
LITS = {
    "Base": BASE, "Named": NAMED, "Mid": MID, "Top": "[[%s],5,[%s,%s]]" % (MID, hx("a"), hx("b")),
    "Point": "[3,4,n]", "Pair": "[5,%s]" % hx("s"), "Node": "[1,[[2,n,[]]],[[3,n,n]]]",
    "Wrap": "[[1,n,n],%s]" % BASE,
}


def build():
    r = []
    for n in ALL:
        r.append("T " + n)
        r.append("T *" + n)
        r.append("T []" + n)
    for n in STRUCTS:
        r.append("V " + n)
        r.append("V " + n)
        for f in NAMES:
            r.append("N %s %s" % (n, hx(f)))
    for a in ALL + ["*" + x for x in ALL]:
        for b in ALL:
            r.append("R %s %s" % (a, b))
    calls = [
        ("Point", "Sum", []), ("Point", "Scale", ["3"]), ("Point", "Greet", [hx("w"), "9"]),
        ("Base", "Describe", []), ("Base", "Rename", [hx("new")]),
        ("Named", "Label", []), ("Mid", "Describe", []), ("Mid", "Label", []), ("Mid", "Rename", [hx("zz")]),
        ("Top", "Describe", []), ("Top", "Label", []), ("Top", "Rename", [hx("zz")]), ("Wrap", "Describe", []),
        ("Wrap", "Rename", [hx("q")]), ("Point", "Missing", []),
    ]
    for t, m, args in calls:
        for recv in ("val", "ptr"):
            r.append(" ".join(["CALL", t, recv, LITS[t], m] + args))
    # Wrong argument count and types.
    r.append("CALL Point ptr [1,2,n] Scale")
    r.append("CALL Point ptr [1,2,n] Greet %s" % hx("w"))
    for t, it, m in [("Point", "Shape", "Sum"), ("*Point", "Scaler", "Scale"), ("Mid", "Describer", "Describe"),
                     ("Top", "Describer", "Describe"), ("Point", "Scaler", "Scale"), ("Node", "Shape", "Sum")]:
        ty = t.lstrip("*")
        r.append("IFACE %s %s %s %s" % (ty, LITS[ty], it, m))
    for t in ["Point", "Base", "Mid", "Top", "Wrap", "Node", "Named"]:
        lit = LITS[t]
        r.append("D %s %s %s" % (t, lit, lit))
        r.append("D %s %s n" % (t, lit))
    r.append("D Top %s %s" % (LITS["Top"], LITS["Top"].replace("5", "6")))
    r += ["CONV Color int n", "CONV int Color 3", "CONV Point Point [1,2,n]", "CONV Point Named [1,2,n]",
          "CONV int string 65", "CONV Base Named [1,%s,n]" % hx("a")]
    sets = [("Point", "0", "8"), ("Point", "1", "9"), ("Point", "2", hx("x")), ("Base", "1", hx("zz")),
            ("Base", "2", "t"), ("Mid", "0.1", hx("ee")), ("Mid", "0", BASE), ("Mid", "1.0", hx("p")),
            ("Mid", "2", "77"), ("Top", "0.0.1", hx("mm")), ("Top", "1", "12"), ("Top", "2", "[%s]" % hx("t")),
            ("Wrap", "0.0", "55"), ("Wrap", "1.1", hx("w")), ("Top", "5", "1"), ("Point", "9", "1")]
    for t, path, lit in sets:
        r.append("SET %s %s %s %s" % (t, LITS[t], path, lit))
    return r


def run(cmd, payload, what):
    res = subprocess.run(cmd, input=payload, text=True, capture_output=True, cwd=ROOT)
    if res.returncode:
        raise RuntimeError(f"{what} failed:\n{res.stderr[-3000:]}")
    return res.stdout.split("\n")[:-1]


def main():
    reqs = build()
    payload = "".join(x + "\n" for x in reqs)
    rust = run(RUST, payload, "Rust typed reflect probe")
    go = run(GO, payload, "Go typed reflect oracle")
    if len(rust) != len(reqs) or len(go) != len(reqs):
        raise AssertionError(f"record count: rust={len(rust)} go={len(go)} want={len(reqs)}")
    bad = [i for i in range(len(reqs)) if rust[i] != go[i]]
    for i in bad[:12]:
        print(f"MISMATCH {reqs[i]}\n  rust: {rust[i]}\n  go:   {go[i]}")
    if bad:
        raise SystemExit(f"{len(bad)} of {len(reqs)} typed reflect vectors differ")
    panics = sum(1 for x in go if x.startswith("panic:"))
    print(f"reflect typed: {len(reqs)} vectors match Go ({panics} identical panics)")


if __name__ == "__main__":
    main()
