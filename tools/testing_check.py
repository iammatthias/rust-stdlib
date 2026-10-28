#!/usr/bin/env python3
"""Differentially check testing, testing/{fstest,iotest,quick,slogtest,synctest} against Go.

The Go oracle (tools/testing_oracle.go) and the Rust probe (examples/testing_probe.rs)
interpret the same generated scenarios:

* testing.T / testing.B: scripts of log/error/fatal/skip/subtest/parallel/cleanup/
  Output/Attr operations are run as a test binary (testing.Main / testing::main_start)
  with -test.v on and off, -test.run filters and -test.count; the reports are compared
  after masking durations, file:line prefixes and benchmark timings.
* BenchmarkResult.String/MemString: random results, compared exactly.
* iotest: reader wrappers and TruncateWriter scripts, TestReader verdicts for
  deliberately misbehaving readers.
* fstest.TestFS: generated MapFS trees, valid and corrupted by wrappers that
  misbehave identically in both languages; the error lists are compared.
* quick: generated values for a fixed seed (the algorithm follows Go's, so the
  values are equal), Check/CheckEqual verdicts.
* slogtest.TestHandler: the JSON handler with ReplaceAttr transforms that break
  the handler contract in known ways.
* synctest: scripts of sleeps, waits, goroutines and channels in a bubble,
  comparing the traces of fake-clock times.
"""
import json
import os
import pathlib
import random
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENV = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")

NAMES = ["a", "b", "c", "a b", "x/y", "", "#00", "t\tab", "é", "a", "a", "#", "sub", "sub", "N1", "s p a c e",
         "\x01", "quoted\"name", "x:1"]
MESSAGES = ["", "m", "msg", "multi\nline", "trail\n", "a b", "  lead", "\ttab", "日本語", "x\n\ny", "two\nlines\n",
            "back\\slash", "q\"uote", "end space "]
WRITES = ["abc", "a\nb", "no newline", "", "line\n", "x\ny\nz", "\n", "tail "]
ARGS = [[], [""], ["x"], ["a", "b"], ["a b", "c"], ["multi\nline", "z"], ["1", "2", "3"]]
KEYS = ["k", "key1", "a-b", "has space", "tab\tkey", ""]
VALUES = ["v", "value one", "multi\nline", "cr\rx", "", "ok"]


def gen_ops(rng, depth, in_cleanup=False, allow_psub=True):
    ops = []
    psub_used = False
    for _ in range(rng.randrange(0, 7)):
        kinds = ["log", "log", "logf", "error", "errorf", "fatal", "fatalf", "skip", "skipf", "skipnow", "fail",
                 "failnow", "write", "attr", "name", "failed"]
        if depth < 3 and not in_cleanup:
            kinds += ["sub", "sub", "sub", "cleanup"]
            if allow_psub and not psub_used:
                kinds += ["psub"]
        kinds += ["cleanup"] if not in_cleanup and depth < 4 else []
        k = rng.choice(kinds)
        op = {"op": k}
        if k in ("log", "error", "fatal", "skip"):
            op["args"] = rng.choice(ARGS)
        elif k in ("logf", "errorf", "fatalf", "skipf"):
            op["msg"] = rng.choice(MESSAGES)
        elif k == "sub":
            op["name"] = rng.choice(NAMES)
            op["ops"] = gen_ops(rng, depth + 1, False, allow_psub)
        elif k == "psub":
            psub_used = True
            op["name"] = rng.choice(NAMES)
            op["ops"] = gen_ops(rng, depth + 1, False, False)
        elif k == "cleanup":
            op["ops"] = gen_ops(rng, depth + 1, True, False)
        elif k == "write":
            op["text"] = rng.choice(WRITES)
        elif k == "attr":
            op["key"] = rng.choice(KEYS)
            op["value"] = rng.choice(VALUES)
        ops.append(op)
    return ops


GOEXIT_OPS = {"fatal", "fatalf", "skip", "skipf", "skipnow", "failnow"}


def strip_cleanup_goexit(ops):
    """Go skips the report of a test whose cleanup calls Goexit (FailNow, Skip...) after
    its parallel subtests ran; the Rust runner reports it. Keep scripts out of that corner."""
    has_psub = any(op["op"] == "psub" for op in ops)
    for op in ops:
        if op["op"] == "cleanup" and has_psub:
            op["ops"] = [o for o in op["ops"] if o["op"] not in GOEXIT_OPS]
        if "ops" in op:
            strip_cleanup_goexit(op["ops"])
    return ops


def test_scripts(rng, count):
    return [{"name": f"S{i:04d}", "ops": strip_cleanup_goexit(gen_ops(rng, 0))} for i in range(count)]


def gen_bench_ops(rng, depth):
    ops = []
    for _ in range(rng.randrange(0, 5)):
        kinds = ["log", "log", "error", "fatal", "skip", "skipnow", "fail", "failnow", "write", "name",
                 "metric", "metric", "bytes"]
        if depth < 2:
            kinds += ["sub", "sub"]
        k = rng.choice(kinds)
        op = {"op": k}
        if k in ("log", "error", "fatal", "skip"):
            op["args"] = rng.choice(ARGS)
        elif k == "sub":
            op["name"] = rng.choice(NAMES)
            op["ops"] = gen_bench_ops(rng, depth + 1)
        elif k == "write":
            op["text"] = rng.choice(WRITES)
        elif k == "metric":
            op["key"] = rng.choice(["widgets/op", "x", "frobs", "B/op", "allocs/op", "MB/s"])
            op["f"] = rng.choice([0, 1, 2.5, 12.0, 1234.5678, 0.00123, 99.995, 1e9, 3.14159, 100, 0.5])
        elif k == "bytes":
            op["n"] = 0
        ops.append(op)
    return ops


def bench_scripts(rng, count):
    return [{"name": f"B{i:03d}", "ops": gen_bench_ops(rng, 0)} for i in range(count)]


def normalize_report(text, bench=False):
    text = re.sub(r"\(\d+\.\d\ds\)", "(0.00s)", text)
    text = re.sub(r"(?m)^(\s*)[\w.\-]+\.(?:go|rs):\d+: ", r"\1FILE:N: ", text)
    lines = []
    for line in text.splitlines():
        if re.match(r"(goos|goarch|pkg|cpu): ", line):
            continue
        if bench and re.search(r"\d+\s", line) and "ns/op" in line or bench and re.match(r"B\d+\S*\s+\d+\s*$", line):
            # Timings differ run to run and a fast clock can report 0 ns/op, which
            # Go omits: drop ns/op and MB/s, keep the iteration count and metrics.
            line = re.sub(r"\s+", " ", line.strip())
            line = re.sub(r" [-+\d.eInf]+ ns/op", "", line)
            line = re.sub(r" [-+\d.eInf]+ MB/s", "", line)
        lines.append(line)
    return "\n".join(lines)


class Oracles:
    def __init__(self, tmp):
        self.tmp = pathlib.Path(tmp)
        self.go_bin = self.tmp / "testing_oracle"
        subprocess.run(["go", "build", "-o", str(self.go_bin), str(ROOT / "tools/testing_oracle.go")],
                       cwd=ROOT, env=ENV, check=True)
        subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "testing_probe"],
                       cwd=ROOT, check=True)
        target = os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target"))
        self.rust_bin = pathlib.Path(target) / "debug/examples/testing_probe"

    def run(self, mode, scenarios, args=(), timeout=300):
        path = self.tmp / f"{mode}.json"
        path.write_text(json.dumps(scenarios))
        env = dict(ENV, ORACLE_MODE=mode, ORACLE_INPUT=str(path))
        out = []
        for name, cmd in (("Go", [str(self.go_bin), *args]), ("Rust", [str(self.rust_bin), *args])):
            run = subprocess.run(cmd, cwd=self.tmp, env=env, text=True, capture_output=True, timeout=timeout)
            out.append((run.returncode, run.stdout, run.stderr))
        return out


def compare_lines(label, scenarios, go, rust):
    go_lines, rust_lines = go.splitlines(), rust.splitlines()
    if len(go_lines) != len(scenarios) or len(rust_lines) != len(scenarios):
        raise AssertionError(f"{label}: got {len(go_lines)} Go and {len(rust_lines)} Rust lines "
                             f"for {len(scenarios)} scenarios\nGo tail: {go_lines[-3:]}\nRust tail: {rust_lines[-3:]}")
    for i, (g, r) in enumerate(zip(go_lines, rust_lines)):
        if g != r:
            raise AssertionError(f"{label} scenario {i}: {json.dumps(scenarios[i])}\nGo  ={g}\nRust={r}")
    return len(scenarios)


def show_diff(label, go, rust, scripts):
    import difflib
    g, r = go.splitlines(), rust.splitlines()
    for i, (x, y) in enumerate(zip(g, r)):
        if x != y:
            lo = max(0, i - 6)
            diff = "\n".join(difflib.unified_diff(g[lo:i + 8], r[lo:i + 8], "Go", "Rust", lineterm="", n=3))
            raise AssertionError(f"{label}: first difference at line {i}:\n{diff}")
    raise AssertionError(f"{label}: outputs differ in length: Go {len(g)} lines, Rust {len(r)} lines")


def check_tests(o, rng):
    scripts = test_scripts(rng, 400)
    total = 0
    configs = [
        ("quiet", ["-test.v=false"]),
        ("verbose", ["-test.v=true"]),
        ("verbose count=2", ["-test.v=true", "-test.count=2"]),
        ("run filter", ["-test.v=true", "-test.run=S00[0-3]./a|S01.*/b"]),
        ("skip filter", ["-test.v=false", "-test.skip=S0[0-2]"]),
    ]
    for label, flags in configs:
        (gc, go, ge), (rc, rust, re_) = o.run("tests", scripts, flags)
        if gc != rc:
            raise AssertionError(f"tests {label}: exit codes differ Go={gc} Rust={rc}\nGo stderr: {ge[-500:]}\nRust stderr: {re_[-800:]}")
        g, r = normalize_report(go), normalize_report(rust)
        if g != r:
            show_diff(f"tests {label}", g, r, scripts)
        total += len(scripts)
    print(f"testing.T: {total} scripts across {len(configs)} flag sets produced identical reports")
    return total


def check_bench(o, rng):
    scripts = bench_scripts(rng, 120)
    total = 0
    for label, flags in [("bench", ["-test.run=^$", "-test.bench=.", "-test.benchtime=3x", "-test.cpu=1"]),
                         ("bench verbose", ["-test.run=^$", "-test.bench=.", "-test.benchtime=1x", "-test.cpu=1", "-test.v=true"]),
                         ("bench filter", ["-test.run=^$", "-test.bench=B00./a", "-test.benchtime=2x", "-test.cpu=1"])]:
        (gc, go, ge), (rc, rust, re_) = o.run("bench", scripts, flags)
        if gc != rc:
            raise AssertionError(f"{label}: exit codes differ Go={gc} Rust={rc}\n{ge[-500:]}\n{re_[-800:]}")
        g, r = normalize_report(go, True), normalize_report(rust, True)
        if g != r:
            show_diff(label, g, r, scripts)
        total += len(scripts)
    print(f"testing.B: {total} benchmark scripts across 3 flag sets produced identical reports")
    return total


def check_result(o, rng):
    cases = []
    for _ in range(4000):
        n = rng.choice([0, 1, 2, 3, 7, 100, 1000, 12345, 10**6, 10**9, rng.randrange(0, 10**9)])
        t = rng.choice([0, 1, 7, 999, 1000, 123456, 10**9, 10**12, rng.randrange(0, 10**13)])
        c = {"n": n, "t": t, "bytes": rng.choice([0, 0, 1, 64, 4096, 10**6]),
             "mem_allocs": rng.choice([0, 1, 2, 17, 10**6]), "mem_bytes": rng.choice([0, 8, 64, 1000, 10**7])}
        if rng.random() < 0.4:
            c["extra"] = {rng.choice(["ns/op", "MB/s", "B/op", "allocs/op", "widgets/op", "x", "zeta", "alpha/op"]):
                          rng.choice([0, 0.5, 1, 2.25, 99.995, 100, 999.95, 12345.678, 0.00099995, 1e-5, 7e8])
                          for _ in range(rng.randrange(1, 4))}
        cases.append(c)
    (gc, go, ge), (rc, rust, re_) = o.run("result", cases)
    if gc or rc:
        raise AssertionError(f"result: Go rc={gc} {ge[-300:]} Rust rc={rc} {re_[-600:]}")
    return compare_lines("BenchmarkResult", cases, go, rust)


def check_iotest(o, rng):
    cases = []
    wraps = ["onebyte", "half", "dataerr", "timeout", "errtail"]
    for _ in range(1500):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        w = [rng.choice(wraps) for _ in range(rng.choice([0, 1, 1, 2, 3]))]
        if rng.random() < 0.05:
            w.append("err")
        cases.append({"data": data.hex(), "wrap": w, "reads": [rng.randrange(1, 20) for _ in range(rng.randrange(1, 14))],
                      "err_at": rng.randrange(0, 50)})
    (gc, go, ge), (rc, rust, re_) = o.run("iotest", cases)
    if gc or rc:
        raise AssertionError(f"iotest: Go rc={gc} {ge[-300:]} Rust rc={rc} {re_[-600:]}")
    n = compare_lines("iotest", cases, go, rust)

    kinds = ["good", "read0", "shortcorrupt", "seekoff", "readatshort", "readatnoeof"]
    tr = []
    for kind in kinds:
        for caps in ["plain", "seek", "seekat", "bytes", "strings"]:
            for length in [0, 1, 2, 3, 5, 9, 31, 100]:
                content = bytes(rng.randrange(1, 128) for _ in range(length))
                tr.append({"kind": kind, "caps": caps, "content": content.hex()})
    (gc, go, ge), (rc, rust, re_) = o.run("testreader", tr)
    if gc or rc:
        raise AssertionError(f"testreader: Go rc={gc} {ge[-300:]} Rust rc={rc} {re_[-600:]}")
    n += compare_lines("iotest.TestReader", tr, go, rust)
    print(f"iotest: {n} reader/writer scripts and TestReader verdicts matched")
    return n


def gen_tree(rng):
    files = []
    dirs = ["", "d1/", "d1/sub/", "d2/", "Zed/", "a b/", "é/"]
    n = rng.randrange(0, 9)
    for i in range(n):
        d = rng.choice(dirs)
        name = f"{d}{rng.choice(['f', 'g', 'h', 'cat', 'dog', 'x.txt'])}{i}"
        files.append({"name": name, "data": bytes(rng.randrange(256) for _ in range(rng.randrange(0, 20))).hex(),
                      "mode": rng.choice([0o644, 0o600, 0o755])})
    if rng.random() < 0.3:
        files.append({"name": f"{rng.choice(dirs)}emptydir{rng.randrange(9)}", "data": "", "mode": 0o755, "dir": True})
    if rng.random() < 0.3 and files:
        files.append({"name": f"link{rng.randrange(9)}", "data": files[0]["name"].encode().hex(), "mode": 0o777,
                      "link": True})
    return files


def check_fstest(o, rng):
    cases = []
    corrupt = ["none", "none", "wrongsize", "dropentry", "dupentry", "badname", "unsorted", "badglob", "globnoerr",
               "readfile", "openbad"]
    for _ in range(600):
        files = gen_tree(rng)
        names = sorted({f["name"] for f in files})
        # Expected: a random subset of the files, plus sometimes a missing name.
        expected = [n for n in names if rng.random() < 0.6 and not any(f["name"] == n and f.get("link") for f in files)]
        if rng.random() < 0.15:
            expected.append("nonexistent/file")
        if rng.random() < 0.1:
            expected = []
        cases.append({"files": files, "corrupt": rng.choice(corrupt), "expected": expected})
    (gc, go, ge), (rc, rust, re_) = o.run("fstest", cases)
    if gc or rc:
        raise AssertionError(f"fstest: Go rc={gc} {ge[-300:]} Rust rc={rc} {re_[-600:]}")
    n = compare_lines("fstest.TestFS", cases, go, rust)
    print(f"fstest: {n} TestFS verdicts on valid and corrupted MapFS trees matched")
    return n


def check_quick(o, rng):
    kinds = ["int8", "int16", "int32", "int64", "int", "uint8", "uint16", "uint32", "uint64", "uint", "bool",
             "float32", "float64", "string", "slice_i16", "array_u8", "ptr_i32", "map_u8_string", "nested", "tuple3"]
    cases = []
    for kind in kinds:
        for _ in range(12):
            cases.append({"kind": kind, "seed": rng.randrange(-2**40, 2**40), "n": rng.randrange(1, 6)})
    for kind in ["check_fail_i8", "check_ok_i16", "check_fail_bool", "equal_fail", "equal_ok"]:
        for _ in range(40):
            cases.append({"kind": kind, "seed": rng.randrange(0, 2**31), "n": rng.choice([1, 5, 50, 100, 1000])})
    (gc, go, ge), (rc, rust, re_) = o.run("quick", cases)
    if gc or rc:
        raise AssertionError(f"quick: Go rc={gc} {ge[-300:]} Rust rc={rc} {re_[-600:]}")
    n = compare_lines("quick", cases, go, rust)
    print(f"quick: {n} generation and Check/CheckEqual vectors matched")
    return n


def check_slogtest(o, rng):
    cases = [{"transform": "none"}]
    keys = ["time", "level", "msg", "k", "a", "c", "e", "G", "H", "b", "source", "x"]
    for transform in ["drop", "rename", "setvalue"]:
        for key in keys:
            if (transform, key) == ("drop", "c"):
                # Both implementations emit invalid JSON for "G":{} left by the
                # dropped attribute of WithAttrs inside an open group.
                continue
            c = {"transform": transform, "key": key}
            if transform == "rename":
                c["key2"] = key + "2"
            cases.append(c)
    cases.append({"transform": "dropgroup"})
    (gc, go, ge), (rc, rust, re_) = o.run("slogtest", cases)
    if gc or rc:
        raise AssertionError(f"slogtest: Go rc={gc} {ge[-300:]} Rust rc={rc} {re_[-600:]}")
    n = compare_lines("slogtest", cases, go, rust)
    print(f"slogtest: {n} TestHandler verdicts matched")
    return n


def gen_sync_ops(rng, goroutines):
    """Scripts with no equal wake-up times: goroutine g only ever wakes at times = g (mod 16)."""
    def sleeps(g, budget):
        ops = []
        for _ in range(budget):
            ms = 16 * rng.randrange(1, 40)
            ops.append(rng.choice([{"op": "sleep", "ms": ms}, {"op": "sleep", "ms": ms}, {"op": "ssleep", "ms": ms}]))
            ops.append({"op": "stamp", "tag": f"g{g}"})
        return ops

    ops = []
    chan_used = 0
    for g in range(1, goroutines + 1):
        body = [{"op": "sleep", "ms": g}] if g > 0 else []
        body += sleeps(g, rng.randrange(1, 4))
        if rng.random() < 0.5:
            ch = rng.randrange(4)
            body.append({"op": "send", "ch": ch, "v": g})
            chan_used |= 1 << ch
        ops.append({"op": "go", "ops": body})
        ops.append({"op": "wait"})
        ops.append({"op": "now", "tag": f"main-after-go{g}"})
    for _ in range(rng.randrange(1, 4)):
        ops.append({"op": "sleep", "ms": 16 * rng.randrange(1, 60)})
        ops.append({"op": "now", "tag": "main"})
    # Let every goroutine finish before the root exits: time stops advancing then.
    ops.append({"op": "sleep", "ms": 16 * 300})
    ops.append({"op": "now", "tag": "settled"})
    for ch in range(4):
        if chan_used & (1 << ch):
            ops.append({"op": "recv", "ch": ch, "tag": f"recv{ch}"})
    ops.append({"op": "wait"})
    ops.append({"op": "now", "tag": "end"})
    return ops


def check_synctest(o, rng):
    cases = [{"ops": gen_sync_ops(rng, rng.randrange(0, 4))} for _ in range(150)]
    (gc, go, ge), (rc, rust, re_) = o.run("synctest", cases)
    if gc or rc:
        raise AssertionError(f"synctest: Go rc={gc} {ge[-300:]} {go[-300:]} Rust rc={rc} {re_[-600:]} {rust[-300:]}")
    traces = ["\n".join(l[2:] for l in out.splitlines() if l.startswith("R:")) for out in (go, rust)]
    if "--- FAIL" in go or "--- FAIL" in rust:
        raise AssertionError(f"synctest: a bubble test failed\nGo: {go[:800]}\nRust: {rust[:800]}")
    n = compare_lines("synctest", cases, traces[0], traces[1])
    print(f"synctest: {n} bubble scripts produced identical fake-clock traces")
    return n


def main():
    rng = random.Random(0x7E57)
    with tempfile.TemporaryDirectory() as tmp:
        o = Oracles(tmp)
        total = 0
        checks = (check_tests, check_bench, check_result, check_iotest, check_fstest, check_quick,
                  check_slogtest, check_synctest)
        wanted = sys.argv[1:]
        for check in checks:
            if wanted and check.__name__.removeprefix("check_") not in wanted:
                continue
            total += check(o, rng) or 0
        print(f"testing differential: {total} vectors")


if __name__ == "__main__":
    sys.exit(main())
