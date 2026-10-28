#!/usr/bin/env python3
"""Differentially check path/filepath (lexical functions and tree walks) against Go."""
import os
import random
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def hx(value):
    return value.encode("utf-8").hex()


def build_tree(base):
    """A small tree with links, loops, a locked directory and policy triggers."""
    def mk(rel, data=None, link=None):
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if link is not None:
            os.symlink(link, p)
        elif data is None:
            p.mkdir(exist_ok=True)
        else:
            p.write_text(data)
    for rel in ["a", "b/c", "b/d/e", "b/d/f", "skipdir/x", "skipdir/y", "bm/aa", "bm/boom", "bm/zz",
                "st/a1", "st/stop", "st/z", "sf/a", "sf/skipfile", "sf/z", "locked/inside",
                "é/雪", "dot.d/.hidden", "dot.d/v"]:
        mk(rel, "x")
    mk("empty")
    mk("sl", link="b")
    mk("dang", link="nowhere")
    mk("loop1", link="loop2")
    mk("loop2", link="loop1")
    mk("rel", link="b/d/../c")
    mk("abs", link=str(base / "b" / "c"))
    mk("up", link="../" + base.name)
    (base / "locked").chmod(0)


def corpus():
    rng = random.Random(0xF11E9A7)
    rows = []
    alphabet = ["a", "b", ".", "/", "..", "", "é", "雪", "\\", "x.y", "//"]
    fixed = ["", ".", "..", "./", "a/..", "a//b/../c/", "/../../a", "../../a/../b", "///", "a\\b/../c",
             "é/../雪", "/é/雪", "a.txt", ".hidden", "a.", "a/b.tar.gz", "a/", "//a", "/", "a/b/c/..", "./a/./b/.",
             "\x00", "a\x00b", "../a", "a/../..", "/a/..", "a/b/../../..", "..a", "a..", ".../a"]
    values = list(fixed)
    for _ in range(1500):
        values.append("".join(rng.choice(alphabet) for _ in range(rng.randrange(0, 12))))
    for value in values:
        a = hx(value)
        for op in "CSBDEALZPVTF":
            rows.append(f"{op}\t{a}")
        rows.append(f"H\t{a}\t{hx(rng.choice(values)[:3])}")
    for _ in range(600):
        n = rng.randrange(0, 6)
        rows.append("J\t" + "\t".join(hx(rng.choice(values)) for _ in range(n)))
    rows.append("J")
    # Rel: related and unrelated pairs.
    comps = ["a", "b", "c", "..", ".", "", "d"]
    for _ in range(1200):
        def p():
            s = "/".join(rng.choice(comps) for _ in range(rng.randrange(0, 5)))
            return ("/" if rng.random() < 0.3 else "") + s
        rows.append(f"R\t{hx(p())}\t{hx(p())}")
    for _ in range(100):
        v = rng.choice(values)
        rows.append(f"R\t{hx(v)}\t{hx(v)}")
    # SplitList.
    for v in ["", ":", "a:b", "a::b:", ":a", "/usr/bin:/bin", "a:b:c:d", "::"]:
        rows.append(f"P\t{hx(v)}")
    # Match.
    patterns = ["", "*", "**", "*.txt", "a?c", "a\\*b", "[a-c]at", "[^a-c]at", "[/]", "?", "??",
                "[α-ω]", "[\\-]", "**/x", "\\", "[", "[]", "[^]", "[-a]", "[a-]", "a[", "x\\", "[a-b-c]",
                "[\\]a]", "a*b*c", "*a*", "[!a]", "[a-\\]]"]
    names = ["", "a", "abc", "a/c", "name.txt", "dir/name.txt", "a*b", "bat", "dat", "zat", "/", "雪", "β", "-",
             "a/x", "other", "]", "aXbYc"]
    rows.extend(f"M\t{hx(pt)}\t{hx(nm)}" for pt in patterns for nm in names)
    for _ in range(1500):
        pt = "".join(rng.choice("abc/*?[]^-\\.é") for _ in range(rng.randrange(0, 15)))
        nm = "".join(rng.choice(["a", "b", "c", "/", "é", "雪", "-", "]"]) for _ in range(rng.randrange(0, 12)))
        rows.append(f"M\t{hx(pt)}\t{hx(nm)}")
    return rows


def tree_corpus(base):
    rng = random.Random(0x7EE5)
    rows = []
    parts = ["a", "b", "c", "d", "e", "sl", "dang", "loop1", "loop2", "rel", "abs", "up", "..", ".", "empty",
             "nosuch", "é", "locked", "skipdir", "st", "sf", "dot.d", ""]
    fixed = ["", ".", "..", "sl", "sl/c", "dang", "loop1", "rel", "abs", "b/../sl", "./sl/./d/..", "a/x", "sl/d/e/..",
             "up/" + base.name + "/b", "b/d/../../sl/d", "nosuch/..", "é/雪", "locked/inside", "sl/", "//" + str(base),
             str(base) + "/sl/c", "a/", "b//c", "../" + base.name + "/a"]
    paths = list(fixed)
    for _ in range(1200):
        paths.append("/".join(rng.choice(parts) for _ in range(rng.randrange(1, 6))))
    for p in paths:
        rows.append(f"X\t{hx(p)}")
        rows.append(f"Y\t{hx(p)}")
    pats = ["*", "b/*", "*/c", "b/d/[ef]", "[a-b]*", "sl/*", "nosuch*", "b/*/e", "*/*/*", "[", "b/[", "\\a", "a\\",
            "*/", "./*", "b/d/*", "?", "*/*", "./", "locked/*", "dot.d/*", "dot.d/.*", "é/*", "/", "b/", "",
            "sl/*/e", "[a-", "b/d/", "*/d/*", "../*", "nosuch/*", "a/*", "**/*", "b/\\d", "b/\\*"]
    for _ in range(400):
        pats.append("".join(rng.choice(["a", "b", "c", "d", "e", "*", "?", "[", "]", "/", "\\", "^", "-", ".", "sl", "é"])
                            for _ in range(rng.randrange(1, 9))))
    for p in pats:
        rows.append(f"G\t{hx(p)}")
    roots = [".", "b", "skipdir", "bm", "st", "sf", "nosuch", "sl", "sl/", "locked", "a", "empty", "dot.d", "é",
             "./b/", "b/d", "up/" + base.name + "/b", "dang", "loop1", "", "b/../b", str(base) + "/b"]
    for r in roots:
        rows.append(f"W\t{hx(r)}")
        rows.append(f"K\t{hx(r)}")
    return rows


def run(cmd, rows, cwd, what):
    env = os.environ.copy()
    env["PWD"] = str(cwd)
    p = subprocess.run(cmd, input="\n".join(rows) + "\n", text=True, capture_output=True, cwd=cwd, env=env)
    if p.returncode:
        raise RuntimeError(f"{what} failed:\n{p.stderr}")
    return p.stdout.splitlines()


def main():
    build = subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "filepath_probe"],
                           cwd=ROOT, capture_output=True, text=True)
    if build.returncode:
        raise RuntimeError(f"build failed:\n{build.stderr}")
    probe = ROOT / "target" / "debug" / "examples" / "filepath_probe"
    if not probe.exists():
        target = subprocess.check_output(["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                                          "--no-deps"], cwd=ROOT, text=True)
        import json
        probe = Path(json.loads(target)["target_directory"]) / "debug" / "examples" / "filepath_probe"
    goexe = Path(tempfile.mkdtemp(prefix="fpgo")) / "oracle"
    env = os.environ.copy()
    subprocess.run(["go", "build", "-o", str(goexe), str(ROOT / "tools" / "filepath_oracle.go")],
                   cwd=ROOT, check=True, env=env)
    work = Path(os.path.realpath(tempfile.mkdtemp(prefix="fptree")))
    try:
        base = work / "tree"
        base.mkdir()
        build_tree(base)
        rows = corpus() + tree_corpus(base)
        rust = run([str(probe)], rows, base, "Rust probe")
        go = run([str(goexe)], rows, base, "Go oracle")
        if len(rust) != len(rows) or len(go) != len(rows):
            raise AssertionError(f"record count: rows={len(rows)} rust={len(rust)} go={len(go)}")
        for i, (r, g) in enumerate(zip(rust, go)):
            if r != g:
                raise AssertionError(f"vector {i}: {rows[i]!r}\nRust: {r}\nGo:   {g}")
        print(f"Go/Rust path/filepath differential: {len(rows)} vectors passed")
    finally:
        try:
            (work / "tree" / "locked").chmod(0o755)
        except OSError:
            pass
        shutil.rmtree(work, ignore_errors=True)
        shutil.rmtree(goexe.parent, ignore_errors=True)


if __name__ == "__main__":
    main()
