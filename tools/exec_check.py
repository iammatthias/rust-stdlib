#!/usr/bin/env python3
"""Differentially check os/exec against Go: outputs, exit codes, error text and LookPath."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def hx(value):
    return str(value).encode("utf-8").hex()


def cmd(mode, name, args=(), env=None, dir="", stdin="", timeout=0, wait_delay=0):
    return "\t".join([mode, hx(name), hx("\x1f".join(args)), "NIL" if env is None else hx("\x1f".join(env)),
                      hx(dir), hx(stdin), hx(timeout), hx(wait_delay)])


def setenv(k, v):
    return "\t".join(["setenv", hx(k), hx(v)])


def lookpath(name):
    return "\t".join(["lookpath", hx(name)])


def chdir(d):
    return "\t".join(["chdir", hx(d)])


def corpus(base, native=False):
    rows = []
    sh = "/bin/sh"
    scripts = [
        ("echo hello", ""),
        ("echo out; echo err >&2", ""),
        ("exit 3", ""),
        ("exit 0", ""),
        ("kill -9 $$", ""),
        ("kill -TERM $$", ""),
        ("kill -SEGV $$", ""),
        ("cat", "from stdin\nline2\n"),
        ("cat >&2", "to stderr"),
        ("printf 'no newline'", ""),
        ("head -c 70000 /dev/zero | tr '\\0' x", ""),
        ("i=0; while [ $i -lt 600 ]; do echo line $i >&2; i=$((i+1)); done; exit 7", ""),
        ("pwd", ""),
        ("echo $RS_A:$RS_B:${RS_C-unset}", ""),
        ("env | grep '^RS_' | sort", ""),
        ("echo $0 $1 $2", ""),
        ("read x; echo got:$x", "value\n"),
        ("exit 300", ""),
        ("echo a; echo b >&2; echo c; exit 1", ""),
        ("true", ""),
        ("false", ""),
    ]
    modes = ["run", "output", "combined", "same", "pipes", "stdinpipe", "pipesafter"]
    for script, stdin in scripts:
        for mode in modes:
            rows.append(cmd(mode, sh, ["-c", script], stdin=stdin))
    rows.append(cmd("run", sh, ["-c", "echo $0 $1 $2", "zero", "one", "two"]))
    # Direct programs.
    for mode in modes:
        rows.append(cmd(mode, "echo", ["a", "b  c", "", "d"]))
        rows.append(cmd(mode, "false"))
        rows.append(cmd(mode, "true"))
        rows.append(cmd(mode, "cat", [], stdin="cat me"))
        rows.append(cmd(mode, "/bin/echo", ["abs"]))
        rows.append(cmd(mode, "ls", ["/nonexistent-dir-xyz"]))
        rows.append(cmd(mode, "sh", ["-c", "exit 5"]))
    # Environment handling.
    env = ["RS_A=1", "RS_B=2", "RS_A=3", "PATH=/usr/bin:/bin", "RS_E="]
    rows.append(cmd("run", sh, ["-c", "echo $RS_A:$RS_B:$RS_E; env | grep '^RS_' | sort"], env=env))
    rows.append(cmd("run", sh, ["-c", "env | grep -c ."], env=[]))
    rows.append(cmd("run", sh, ["-c", "echo ${RS_A-unset}"], env=["NOEQUALS", "=weird=x", "RS_A=ok"]))
    rows.append(cmd("run", sh, ["-c", "echo ${RS_A-unset}"], env=["RS_A=1\x00x"]))
    rows.append(cmd("environ", "echo", env=env))
    rows.append(cmd("environ", "echo", env=["RS_X=1", "RS_X=2", "=Z=1", "Q", ""]))
    rows.append(cmd("environ", "echo"))
    rows.append(cmd("environ", "echo", dir="d1"))
    rows.append(cmd("environ", "echo", dir="d1", env=["RS_Y=1"]))
    # Dir.
    for d in ["d1", "d1/", ".", "nosuch", "plain", ""]:
        rows.append(cmd("run", sh, ["-c", "pwd; echo $PWD"], dir=d))
    rows.append(cmd("run", "ls", [], dir="d1"))
    # LookPath and errors.
    names = ["sh", "ls", "nosuchcmd-xyz", "", ".", "..", "./x.sh", "x.sh", "./noexec", "noexec", "./dirx", "dirx",
             "./nosuch", "/bin/sh", "/bin/nosuch", "bin/sh", "./bad", "sub/x.sh", "./sub/x.sh", "/", "d1", "a/b/c"]
    for pathval in ["/usr/bin:/bin", "/usr/bin:/bin:.", ".:/usr/bin", "", ":/bin", "/nonexistent:/bin", "/bin:" + str(base),
                    "/bin::/usr/bin", "sub:/bin", "/bin:sub"]:
        rows.append(setenv("PATH", pathval))
        for n in names:
            rows.append(lookpath(n))
        for n in ["sh", "x.sh", "nosuchcmd-xyz", "noexec", "dirx", "bad", "sub/x.sh"]:
            rows.append(cmd("run", n, ["-c", "echo ok"]))
            rows.append(cmd("string", n, ["-c", "echo ok"]))
            rows.append(cmd("pathargs", n, ["a"]))
    rows.append(setenv("PATH", "/usr/bin:/bin"))
    for n in ["./x.sh", "./noexec", "./dirx", "./bad", "./nosuch", "sub/x.sh", "/bin/sh", ""]:
        for mode in ["run", "output", "combined"]:
            rows.append(cmd(mode, n, ["arg"]))
    # State misuse.
    rows.append(cmd("twice", "echo", ["hi"]))
    rows.append(cmd("twice", "nosuchcmd-xyz"))
    rows.append(cmd("waitfirst", "echo", ["hi"]))
    rows.append(cmd("string", "echo", ["a", "b c"]))
    rows.append(cmd("string", "nosuchcmd-xyz", ["a"]))
    # Contexts and delays.
    rows.append(cmd("run", "sleep", ["30"], timeout=150))
    rows.append(cmd("output", "sleep", ["30"], timeout=150))
    rows.append(cmd("run", sh, ["-c", "echo started; sleep 2"], timeout=300))
    rows.append(cmd("run", sh, ["-c", "echo fast"], timeout=20000))
    rows.append(cmd("run", sh, ["-c", "sleep 30 & echo bg"], wait_delay=200, timeout=0))
    rows.append(cmd("run", sh, ["-c", "(sleep 5 &) ; echo done"], wait_delay=150))
    rows.append(cmd("output", sh, ["-c", "(sleep 5 >/dev/null 2>&1 &) ; echo done"], wait_delay=150))
    if sys.platform == "darwin" and not native:
        # std spawns with posix_spawn, which macOS falls back to /bin/sh for
        # an executable without a shebang; Go reports "exec format error".
        rows = [r for r in rows if bytes.fromhex("626164").hex() not in r.split("\t")[1:2]
                and bytes.fromhex("2e2f626164").hex() not in r.split("\t")[1:2]]
    return rows


def sys_rows(base):
    """The os/exec rows rust_stdlib_sys::os::exec answers: the common corpus without
    the context timeouts (CommandContext is not part of the sys crate), plus
    ExtraFiles, StartProcess descriptors, process handles and WaitDelay interrupting
    a copier."""
    rows = [r for r in corpus(base, native=True) if bytes.fromhex(r.split("\t")[6] if len(r.split("\t")) > 6 else "30").decode() in ("0", "")
            or r.split("\t")[0] in ("setenv", "chdir", "lookpath")]
    # Closing the parent's pipe ends in Wait is the root crate's (mapped) behavior.
    rows = [r for r in rows if r.split("\t")[0] != "pipesafter"]
    sh = "/bin/sh"
    files = "extra3.txt,extra4.txt"
    for script in ["cat <&3; cat <&4", "cat <&3", "cat <&4", "cat <&5", "exec 5<&3; cat <&5; echo done",
                   "echo out; cat <&3 >&2; echo end", "exit 7"]:
        for stdin in [files, "extra3.txt", "", "extra4.txt,extra3.txt,extra4.txt"]:
            rows.append(cmd("extra", sh, ["-c", script], stdin=stdin))
    rows.append(cmd("extra", "nosuchcmd-xyz", [], stdin=files))
    rows.append(cmd("extra", "./bad", [], stdin=files))
    for script in ["cat <&3; echo out; echo err >&2", "cat <&4", "cat <&3 <&5", "cat <&5; echo $0", "pwd; exit 3"]:
        for fl in ["extra3.txt", "extra3.txt,extra4.txt,extra3.txt", "extra3.txt,-,extra4.txt", "-,-,extra4.txt", ""]:
            rows.append(cmd("procattr", sh, ["-c", script], stdin=fl))
    for n in ["./bad", "./x.sh", "./noexec", "./nosuch", "./dirx", "bad", "/bin/nosuch", "/bin/sh", "sub/x.sh", ""]:
        rows.append(cmd("procattr", n, ["a1"], stdin="extra3.txt"))
    for d in ["d1", "nosuch", "plain", "d1/", "."]:
        rows.append(cmd("procattr", sh, ["-c", "pwd"], dir=d))
    rows.append(cmd("handle", sh, ["-c", "exit 0"]))
    rows.append(cmd("handle", sh, ["-c", "sleep 0.1"]))
    # After every handle row: a released child stays a zombie of the oracle.
    rows.append(cmd("released", sh, ["-c", "exit 0"]))
    rows.append(cmd("released", sh, ["-c", "sleep 0.1"]))
    # WaitDelay interrupts copiers blocked on a pipe a grandchild still holds.
    big = "x" * 300000
    rows.append(cmd("run", sh, ["-c", "exec 3<&0; sleep 3 & exit 0"], stdin=big, wait_delay=200))
    rows.append(cmd("run", sh, ["-c", "exec 3<&0; sleep 3 & exit 3"], stdin=big, wait_delay=200))
    rows.append(cmd("run", sh, ["-c", "sleep 3 & echo hi"], wait_delay=150))
    rows.append(cmd("output", sh, ["-c", "sleep 3 & echo hi; echo err >&2"], wait_delay=150))
    rows.append(cmd("combined", sh, ["-c", "sleep 3 & echo hi"], wait_delay=150))
    rows.append(cmd("pipes", sh, ["-c", "echo a; echo b >&2"], wait_delay=150))
    rows.append(cmd("run", sh, ["-c", "(sleep 3 &); echo done >&2"], wait_delay=100))
    return rows


def build():
    p = subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "exec_probe"],
                       cwd=ROOT, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"build failed:\n{p.stderr}")
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                                               "--no-deps"], cwd=ROOT, text=True))
    return Path(meta["target_directory"]) / "debug" / "examples" / "exec_probe"


def build_sys():
    p = subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--manifest-path", "crates/sys/Cargo.toml",
                        "--example", "exec_probe"], cwd=ROOT, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"build failed:\n{p.stderr}")
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                                               "--no-deps", "--manifest-path", "crates/sys/Cargo.toml"],
                                              cwd=ROOT, text=True))
    return Path(meta["target_directory"]) / "debug" / "examples" / "exec_probe"


def compare(label, probe, goexe, work, rows):
    payload = "\n".join(rows) + "\n"
    results = {}
    for name, exe in (("rust", probe), ("go", goexe)):
        env = os.environ.copy()
        env["PWD"] = str(work)
        env["PATH"] = "/usr/bin:/bin"
        p = subprocess.run([str(exe)], input=payload, text=True, capture_output=True, cwd=work, env=env)
        if p.returncode:
            raise RuntimeError(f"{label} {name} failed:\n{p.stderr[-2000:]}")
        results[name] = p.stdout.splitlines()
    rust, go = results["rust"], results["go"]
    if len(rust) != len(rows) or len(go) != len(rows):
        raise AssertionError(f"{label} record count: rows={len(rows)} rust={len(rust)} go={len(go)}")
    bad = 0
    for i, (r, g) in enumerate(zip(rust, go)):
        if r != g:
            bad += 1
            if bad <= 15:
                req = rows[i].split("\t")
                shown = [req[0]] + [bytes.fromhex(a).decode("utf-8", "replace") if a != "NIL" else a for a in req[1:]]
                print(f"MISMATCH {label} #{i}: {[x[:80] for x in shown]!r}")
                for who, rec in (("Rust", r), ("Go  ", g)):
                    parts = rec.split("|")
                    dec = [parts[0]] + [bytes.fromhex(x).decode("utf-8", "replace") if x and all(c in "0123456789abcdef" for c in x) and len(x) % 2 == 0 else x for x in parts[1:]]
                    print(f"  {who}: {[d[:160] if isinstance(d, str) else d for d in dec]}")
    if bad:
        raise SystemExit(f"{bad} of {len(rows)} {label} exec results differ")
    return len(rows)


def main():
    probe = build()
    sys_probe = build_sys()
    tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="execdiff")))
    goexe = tmp / "oracle"
    subprocess.run(["go", "build", "-o", str(goexe), str(ROOT / "tools" / "exec_oracle.go")], cwd=ROOT, check=True)
    work = tmp / "work"
    work.mkdir()
    (work / "x.sh").write_text("#!/bin/sh\necho x.sh $1\n")
    (work / "x.sh").chmod(0o755)
    (work / "noexec").write_text("#!/bin/sh\necho no\n")
    (work / "noexec").chmod(0o644)
    (work / "bad").write_text("echo no shebang\n")
    (work / "bad").chmod(0o755)
    (work / "dirx").mkdir()
    (work / "d1").mkdir()
    (work / "plain").write_text("file")
    (work / "sub").mkdir()
    (work / "sub" / "x.sh").write_text("#!/bin/sh\necho sub x $1\n")
    (work / "sub" / "x.sh").chmod(0o755)
    (work / "extra3.txt").write_text("three\n")
    (work / "extra4.txt").write_text("four\n")
    n_root = compare("root", probe, goexe, work, corpus(work))
    n_sys = compare("sys", sys_probe, goexe, work, sys_rows(work))
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"Go/Rust os/exec differential: {n_root} vectors passed; rust_stdlib_sys::os::exec: {n_sys} vectors passed")


if __name__ == "__main__":
    main()
