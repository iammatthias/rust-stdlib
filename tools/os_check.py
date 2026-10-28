#!/usr/bin/env python3
"""Differentially check package os against Go with scripted operation sequences.

Every script runs in a fresh temporary directory; the check compares each
operation's result (including the error text and the IsExist/IsNotExist/...
classes) and the resulting tree (names, modes, sizes, contents, link targets).
"""
import json
import os
import random
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def hx(value):
    if isinstance(value, int):
        value = str(value)
    return value.encode("utf-8").hex()


def op(name, *args):
    return "\t".join([name] + [hx(a) for a in args])


HARD = ["h1", "h2", "h3"]
NAMES = ["a", "b", "c", "d", "a/x", "a/y", "b/x", "d/e/f", "d/e", "e", "l1", "l2", "ln", "a/", "d/e/", ".",
         "a/../b", "./a", "", "a/x/z", "nosuch/y"]
DATA = ["", "hello", "0123456789" * 7, "é雪"]
MODES = ["755", "700", "644", "600", "000", "1777", "2755", "4755", "444", "111"]
FLAGSETS = ["", "W", "RW", "WC", "RWC", "WCT", "RWCT", "WCX", "RWCX", "WA", "WAC", "RWA", "WT", "RWT", "CX"]
FILE_SCRIPTS = [
    "w:%s;r:4;s:0:0;r:4;st;c;c;w:%s",
    "s:2:0;w:%s;s:0:0;all;st",
    "ra:0:5;ra:3:100;wa:2:%s;ra:0:20;tr:3;st;tr:30;all",
    "s:-3:2;r:10;s:-100:1;s:0:1;s:3:0",
    "rd:-1;rdn:-1;rdi:-1;rd:1;rd:1;rdn:2",
    "wt;rf:%s;st;sync;dl;rdl;name;chmod:600;st",
    "w:%s;ws:%s;ra:-1:3;wa:-1:%s;tr:-1",
]


def rand_script(rng):
    ops = [op("NEW")]
    nm = lambda: rng.choice(NAMES)
    for _ in range(rng.randrange(8, 40)):
        k = rng.random()
        if k < 0.08:
            ops.append(op("mkdir", nm(), rng.choice(MODES)))
        elif k < 0.14:
            ops.append(op("mkdirall", nm(), rng.choice(MODES)))
        elif k < 0.26:
            ops.append(op("writefile", rng.choice(NAMES + HARD), rng.choice(DATA), rng.choice(MODES)))
        elif k < 0.31:
            ops.append(op("readfile", nm()))
        elif k < 0.37:
            ops.append(op("remove", nm()))
        elif k < 0.41:
            ops.append(op("removeall", nm()))
        elif k < 0.47:
            ops.append(op("rename", nm(), nm()))
        elif k < 0.51:
            # Hard links use their own names: macOS link(2) follows symbolic
            # links where std (linkat without AT_SYMLINK_FOLLOW) does not.
            ops.append(op("link", rng.choice(HARD), rng.choice(HARD + ["h9/x", ""])))
        elif k < 0.56:
            ops.append(op("symlink", rng.choice(NAMES + ["../x", "/nonexistent", "a/x"]), nm()))
        elif k < 0.59:
            ops.append(op("readlink", nm()))
        elif k < 0.67:
            ops.append(op(rng.choice(["stat", "lstat"]), nm()))
        elif k < 0.70:
            ops.append(op("chmod", nm(), rng.choice(MODES)))
        elif k < 0.73:
            ops.append(op("truncate", nm(), rng.choice([0, 3, 100, -1])))
        elif k < 0.77:
            ops.append(op("readdir", nm()))
        elif k < 0.79:
            ops.append(op("samefile", nm(), nm()))
        elif k < 0.85:
            ops.append(op("openw", nm(), rng.choice(FLAGSETS), rng.choice(MODES), rng.choice(DATA)))
        elif k < 0.93:
            script = rng.choice(FILE_SCRIPTS)
            script = script.replace("%s", hx(rng.choice(DATA)))
            ops.append(op("file", nm(), rng.choice(FLAGSETS), rng.choice(MODES), script))
        elif k < 0.95:
            target = nm()
            # Go sets times by path; std needs to open the file.
            ops.append(op("chmod", target, "644"))
            ops.append(op("chtimes", target, rng.choice([0, 1000000000, 1500000000]), rng.choice([1200000000, 1300000000])))
            ops.append(op("stattime", target))
        elif k < 0.97:
            ops.append(op("copyfs", nm(), rng.choice(["cp1", "cp2", "a"])))
        elif k < 0.98:
            ops.append(op("dirfsread", rng.choice([".", "a", "d"]), rng.choice(["x", "y", "e/f", "../x", "/x", "", "."])))
        else:
            ops.append(op("chdir", nm()))
            ops.append(op("getwd"))
    return ops


def root_script(rng):
    ops = [op("NEW"), op("mkdir", "r", "755"), op("mkdir", "out", "755"),
           op("writefile", "out/secret", "top secret", "644"), op("writefile", "r/f", "data", "644"),
           op("mkdir", "r/sub", "755"), op("writefile", "r/sub/g", "gee", "644"),
           op("symlink", "f", "r/inl"), op("symlink", "sub", "r/inls"), op("symlink", "../out/secret", "r/esc"),
           op("symlink", "../out", "r/escdir"), op("symlink", "/etc/passwd", "r/abs"),
           op("symlink", "sub/../f", "r/dots"), op("symlink", "loop", "r/loop"),
           op("symlink", "inls/g", "r/chain"),
           # Escapes through links created later, links to links, and a ring of nine.
           op("symlink", "../out", "r/sub/up"), op("symlink", "sub/up", "r/viasub"),
           op("symlink", "../../out/secret", "r/sub/up2"), op("symlink", "/", "r/rootlink"),
           op("symlink", "sub/..", "r/self"), op("symlink", "..", "r/sub/parent"),
           op("symlink", "l1", "r/l0"), op("symlink", "l2", "r/l1"), op("symlink", "l3", "r/l2"),
           op("symlink", "l4", "r/l3"), op("symlink", "l5", "r/l4"), op("symlink", "l6", "r/l5"),
           op("symlink", "l7", "r/l6"), op("symlink", "l8", "r/l7"), op("symlink", "f", "r/l8"),
           op("symlink", "sub/", "r/slashlink"), op("symlink", "f/", "r/filelink"),
           op("rootopen", "r")]
    names = ["f", "sub", "sub/g", "inl", "inls", "inls/g", "esc", "escdir", "escdir/secret", "abs", "dots", "loop",
             "chain", "../out/secret", "/etc/passwd", "sub/../f", "sub/../../out", "nosuch", "nosuch/x", "", ".", "..",
             "./f", "f/", "sub/", "f/x", "new", "sub/new", "inls/new", "escdir/new", "a/b/c", "sub/..", "x/../f",
             "sub/up", "sub/up/secret", "viasub", "viasub/secret", "sub/up2", "rootlink", "rootlink/etc", "self", "self/f",
             "sub/parent", "sub/parent/f", "sub/parent/../f", "sub/parent/parent", "l0", "l1", "l8", "esc/", "escdir/", "slashlink",
             "slashlink/g", "filelink", "sub/../../out", "sub/../sub/../f", "a/../../out/secret", "sub//g", "./sub/./g",
             "sub/g/", "sub/g/.", "sub/./", "sub/../", "escdir/../f", "escdir/../r/f", "..//out"]
    nm = lambda: rng.choice(names)
    for name in names:
        ops.append(op("rread", name))
        ops.append(op("rstat", name))
        ops.append(op("rlstat", name))
        ops.append(op("rreadlink", name))
    for _ in range(rng.randrange(30, 70)):
        k = rng.random()
        if k < 0.12:
            ops.append(op("rwrite", nm(), rng.choice(DATA), rng.choice(["644", "600"])))
        elif k < 0.22:
            ops.append(op("rmkdir", nm(), rng.choice(["755", "700"])))
        elif k < 0.32:
            ops.append(op("rmkdirall", nm(), "755"))
        elif k < 0.40:
            ops.append(op("rsymlink", rng.choice(names + ["../z", "../out", "sub/../..", "/tmp"]), nm()))
        elif k < 0.46:
            ops.append(op("rlink", nm(), nm()))
        elif k < 0.54:
            ops.append(op("rrename", nm(), nm()))
        elif k < 0.62:
            ops.append(op("rremove", nm()))
        elif k < 0.66:
            ops.append(op("rremoveall", nm()))
        elif k < 0.70:
            ops.append(op("rchmod", nm(), rng.choice(["600", "644"])))
        elif k < 0.78:
            ops.append(op("rfile", nm(), rng.choice(FLAGSETS), "644", "w:%s;st;name" % hx("zz")))
        elif k < 0.82:
            ops.append(op("rsub", nm()))
        elif k < 0.86:
            ops.append(op("rfsread", rng.choice(["f", "sub/g", "../f", "/f", "inl", "esc", ".", ""])))
        elif k < 0.90:
            ops.append(op("rfsreaddir", rng.choice([".", "sub", "..", "nosuch", "inls", "escdir"])))
        elif k < 0.94:
            ops.append(op("inroot", "r", nm()))
        else:
            ops.append(op("rcreate", nm()))
    ops.append(op("rootclose"))
    ops.append(op("rread", "f"))
    ops.append(op("rstat", "f"))
    return ops


def misc_script():
    ops = [op("NEW")]
    for k, v in [("RS_A", "alpha"), ("RS_B", "beta"), ("RS_E", ""), ("", "x"), ("A=B", "x"), ("K", "v\0w"), ("K\0", "v"),
                 ("RS_é", "uni")]:
        ops.append(op("setenv", k, v))
    for k in ["RS_A", "RS_B", "RS_E", "NOPE_X", "", "A=B", "RS_é"]:
        ops.append(op("getenv", k))
        ops.append(op("lookupenv", k))
    ops.append(op("unsetenv", "RS_B"))
    ops.append(op("unsetenv", "bad=key"))
    ops.append(op("lookupenv", "RS_B"))
    for s in ["$RS_A", "${RS_A}x", "$RS_Ax", "$$", "$", "a$", "${", "${}", "${RS_A", "$1$2", "${1}", "$*$#$@$!$?$-$0",
              "${*}x", "$RS_A$RS_E.", "é$RS_A雪", "$-x", "${RS_A}}", "$ {RS_A}", "\\$RS_A", "$RS_é", "x${a b}y", "${=}", "$a.b",
              "$_x1-"]:
        ops.append(op("expandenv", s))
        ops.append(op("expand", s))
    for env in [{"HOME": "/home/u", "XDG_CACHE_HOME": "/xc", "XDG_CONFIG_HOME": "/xg", "TMPDIR": "/tmp/t"},
                {"HOME": "", "XDG_CACHE_HOME": "", "XDG_CONFIG_HOME": "", "TMPDIR": ""},
                {"HOME": "/h", "XDG_CACHE_HOME": "rel", "XDG_CONFIG_HOME": "rel2", "TMPDIR": "/t/"}]:
        for k, v in env.items():
            ops.append(op("setenv", k, v))
        ops.append(op("userdirs"))
    ops.append(op("info"))
    ops.append(op("consts"))
    for m in ["644", "755", "0", "1777"]:
        ops.append(op("modes", m))
    for data in ["", "pipe data", "x" * 4000]:
        ops.append(op("pipe", data))
    # Temp files.
    ops += [op("mkdir", "t", "755"), op("createtemp", "t", "pre*suf"), op("createtemp", "t", "noStar"),
            op("createtemp", "t", "a*b*c"), op("createtemp", "t", "bad/pat"), op("createtemp", "nosuchdir", "x*"),
            op("mkdirtemp", "t", "d*"), op("mkdirtemp", "t", "bad/pat"), op("mkdirtemp", "nosuchdir", "x*"),
            op("createtemp", "t/", "slash*"), op("mkdirtemp", "t/", "slash*")]
    ops.append(op("setenv", "TMPDIR", "."))
    ops.append(op("createtemp", "", "inenv*"))
    ops.append(op("mkdirtemp", "", "dinenv*"))
    return ops


def file_scripts(rng):
    """Deterministic scenarios on a prepared tree."""
    out = []
    for flags in FLAGSETS + ["RWCXT", "WAT", "RWAC"]:
        for mode in ["644", "000"]:
            ops = [op("NEW"), op("writefile", "f", "0123456789", "644"), op("mkdir", "d", "755"),
                   op("writefile", "d/in", "inner", "644"), op("symlink", "f", "lf"), op("symlink", "nosuch", "dangling")]
            for target in ["f", "new", "d", "lf", "dangling", "nosuch/new", "f/x"]:
                for script in FILE_SCRIPTS[:4] + ["rd:-1;rdn:-1;st;w:" + hx("zz")]:
                    ops.append(op("file", target, flags, mode, script.replace("%s", hx("ab"))))
                ops.append(op("lstat", target))
            out.append(ops)
    return out


def dir_scripts():
    ops = [op("NEW")]
    ops.append(op("mkdir", "d", "755"))
    for i in range(7):
        ops.append(op("writefile", f"d/f{i}", "x" * i, "644"))
    ops.append(op("mkdir", "d/sub", "755"))
    ops.append(op("symlink", "f1", "d/ln"))
    ops.append(op("file", "d", "", "644", "rd:3;rd:3;rd:3;rd:3;rd:-1;rd:1;rd:0"))
    ops.append(op("file", "d", "", "644", "rdn:2;rdn:2;rdn:-1;rdn:2;rdn:0"))
    ops.append(op("file", "d", "", "644", "rdi:4;rdi:-1;rdi:2"))
    ops.append(op("file", "d", "", "644", "rd:2;s:0:0;rd:-1"))
    ops.append(op("file", "d/f1", "", "644", "rd:-1;rdn:1;rdi:1"))
    ops.append(op("file", "d", "", "644", "r:4;ra:0:3;st;wa:0:" + hx("a")))
    ops.append(op("readdir", "d"))
    ops.append(op("readdir", "d/f1"))
    ops.append(op("readdir", "nosuch"))
    ops.append(op("dirfsreaddir", "d", "."))
    ops.append(op("dirfsreaddir", ".", "d"))
    ops.append(op("dirfsstat", "d", "ln"))
    ops.append(op("dirfsstat", "d", "../x"))
    ops.append(op("dirfsread", "d", "f3"))
    ops.append(op("dirfsread", "d", "sub"))
    ops.append(op("copyfs", "d", "copy"))
    ops.append(op("copyfs", "d", "copy"))
    ops.append(op("removeall", "d"))
    ops.append(op("removeall", "d/"))
    ops.append(op("removeall", "copy/."))
    ops.append(op("removeall", "copy/sub/"))
    ops.append(op("removeall", "nosuch"))
    ops.append(op("removeall", "copy/f1/x"))
    ops.append(op("removeall", "copy"))
    ops.append(op("removeall", ""))
    return [ops]


def build_root_probe():
    p = subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--manifest-path", "crates/sys/Cargo.toml",
                        "--example", "root_probe"], cwd=ROOT, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"build failed:\n{p.stderr}")
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                                               "--no-deps", "--manifest-path", "crates/sys/Cargo.toml"],
                                              cwd=ROOT, text=True))
    return Path(meta["target_directory"]) / "debug" / "examples" / "root_probe"


def build_probe():
    p = subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "os_probe"],
                       cwd=ROOT, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"build failed:\n{p.stderr}")
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                                               "--no-deps"], cwd=ROOT, text=True))
    return Path(meta["target_directory"]) / "debug" / "examples" / "os_probe"


def compare(label, probe, goexe, tmp, scripts):
    lines = [line for s in scripts for line in s]
    payload = "\n".join(lines) + "\n"
    results = {}
    for name, exe in (("rust", probe), ("go", goexe)):
        wd = tmp / (label + name)
        wd.mkdir()
        env = os.environ.copy()
        env["PWD"] = str(wd)
        env.pop("TMPDIR", None)
        p = subprocess.run([str(exe)], input=payload, text=True, capture_output=True, cwd=wd, env=env)
        if p.returncode:
            raise RuntimeError(f"{name} failed:\n{p.stderr[-2000:]}")
        results[name] = p.stdout.splitlines()
    rust, go = results["rust"], results["go"]
    # One result line per operation plus one TREE line per script.
    expected = sum(1 for line in lines if not line.startswith("NEW")) + len(scripts)
    if len(rust) != expected or len(go) != expected:
        raise AssertionError(f"record count: expected {expected}, rust {len(rust)}, go {len(go)}")
    reqs = []
    for s in scripts:
        for line in s[1:]:
            reqs.append(line)
        reqs.append("TREE")
    bad = 0
    for i, (r, g) in enumerate(zip(rust, go)):
        if r != g:
            bad += 1
            if bad <= 12:
                what = reqs[i]
                if what != "TREE":
                    what = " ".join([what.split("\t")[0]] + [bytes.fromhex(a).decode("utf-8", "replace") for a in what.split("\t")[1:]])
                else:
                    r = bytes.fromhex(r.split("|", 1)[1]).decode("utf-8", "replace")
                    g = bytes.fromhex(g.split("|", 1)[1]).decode("utf-8", "replace")
                print(f"MISMATCH {label} #{i}: {what!r}\n  Rust: {r}\n  Go:   {g}")
                if os.environ.get("OS_CHECK_CONTEXT"):
                    j = i
                    while j > 0 and reqs[j - 1] != "TREE":
                        j -= 1
                    for line in reqs[max(j, i - 7):i + 1]:
                        if line != "TREE":
                            print("    ", " ".join([line.split("\t")[0]] + [bytes.fromhex(a).decode("utf-8", "replace") for a in line.split("\t")[1:]]))
    if bad:
        raise SystemExit(f"{bad} of {expected} os {label} results differ")
    return expected


def main():
    probe = build_probe()
    root_probe = build_root_probe()
    tmp = Path(tempfile.mkdtemp(prefix="osdiff"))
    goexe = tmp / "oracle"
    subprocess.run(["go", "build", "-o", str(goexe), str(ROOT / "tools" / "os_oracle.go")], cwd=ROOT, check=True)
    rng = random.Random(0x05D1FF)
    scripts = []
    for _ in range(260):
        scripts.append(rand_script(rng))
    # The os.Root scripts run against rust_stdlib_sys::os::Root (openat based).
    root_scripts = [root_script(rng) for _ in range(120)]
    scripts.append(misc_script())
    scripts.extend(file_scripts(rng))
    scripts.extend(dir_scripts())
    expected = compare("os", probe, goexe, tmp, scripts)
    expected_root = compare("root", root_probe, goexe, tmp, root_scripts)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"Go/Rust os differential: {expected} operation/tree results passed ({len(scripts)} scripts); "
          f"os.Root (rust_stdlib_sys): {expected_root} results passed ({len(root_scripts)} scripts)")


if __name__ == "__main__":
    main()
