#!/usr/bin/env python3
"""Differentially check os/user against Go's cgo build (getpwuid_r, getpwnam_r,
getgrgid_r, getgrnam_r and getgrouplist through the C library), which on macOS
includes Open Directory users."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SYS = ROOT / "crates" / "sys"


def hx(value):
    return value.encode("utf-8").hex()


def names(path, index):
    out = []
    try:
        for line in Path(path).read_text(errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) > index and not line.startswith("#"):
                out.append(parts[index])
    except OSError:
        pass
    return out


def database(kind, field):
    """Names or ids from the system's name service (Open Directory on macOS,
    NSS elsewhere), which /etc files alone do not list."""
    try:
        if sys.platform == "darwin":
            args = ["dscl", ".", "-list", f"/{kind.capitalize()}s"] + (["UniqueID" if kind == "user" else "PrimaryGroupID"] if field else [])
            out = subprocess.run(args, capture_output=True, text=True, timeout=30).stdout
            return [l.split()[-1] for l in out.splitlines() if l.split()] if field else out.split()
        out = subprocess.run(["getent", "passwd" if kind == "user" else "group"], capture_output=True, text=True,
                             timeout=30).stdout
        return [l.split(":")[2 if field else 0] for l in out.splitlines() if l.count(":") >= 2]
    except (OSError, subprocess.SubprocessError):
        return []


def corpus():
    users = sorted(set(names("/etc/passwd", 0) + database("user", False) + [os.environ.get("USER", "")]))
    uids = sorted(set(names("/etc/passwd", 2) + database("user", True)))
    groups = sorted(set(names("/etc/group", 0) + database("group", False)))
    gids = sorted(set(names("/etc/group", 2) + database("group", True)))
    rows = ["current"]
    for n in users + ["", "nosuchuser", "root ", " root", "+", "-x", "a:b", "ROOT", "é"]:
        rows += [f"lookup\t{hx(n)}", f"groupids\t{hx(n)}"]
    for i in uids + ["", "-1", "0", "+0", "00", "abc", "1.5", "99999999", "9999999999999999999999", str(os.getuid())]:
        rows.append(f"lookupid\t{hx(i)}")
    for n in groups + ["", "nosuchgroup", "wheel", "+", "-"]:
        rows.append(f"group\t{hx(n)}")
    for i in gids + ["", "-1", "0", "abc", "99999999", str(os.getgid())]:
        rows.append(f"groupid\t{hx(i)}")
    for n in users[:20]:
        for gid in ["0", "20", "x", "-5", ""]:
            rows.append(f"groupidsfor\t{hx(n + ',' + gid)}")
    rows.append(f"groupidsfor\t{hx(',0')}")
    return rows


def main():
    p = subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--example", "os_user_probe"],
                       cwd=SYS, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"build failed:\n{p.stderr}")
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
                                               "--no-deps"], cwd=SYS, text=True))
    probe = Path(meta["target_directory"]) / "debug" / "examples" / "os_user_probe"
    tmp = Path(tempfile.mkdtemp(prefix="userdiff"))
    goexe = tmp / "oracle"
    subprocess.run(["go", "build", "-o", str(goexe), str(ROOT / "tools" / "os_user_oracle.go")],
                   cwd=ROOT, check=True, env={**os.environ, "CGO_ENABLED": "1"})
    rows = corpus()
    payload = "\n".join(rows) + "\n"
    res = {}
    for name, exe in (("rust", probe), ("go", goexe)):
        env = os.environ.copy()
        env.setdefault("USER", "tester")
        q = subprocess.run([str(exe)], input=payload, text=True, capture_output=True, env=env)
        if q.returncode:
            raise RuntimeError(f"{name} failed:\n{q.stderr[-1500:]}")
        res[name] = q.stdout.splitlines()
    shutil.rmtree(tmp, ignore_errors=True)
    if len(res["rust"]) != len(rows) or len(res["go"]) != len(rows):
        raise AssertionError("record count mismatch")
    for i, (r, g) in enumerate(zip(res["rust"], res["go"])):
        if r != g:
            raise SystemExit(f"vector {i}: {rows[i]!r}\nRust: {r}\nGo:   {g}")
    print(f"Go/Rust os/user differential: {len(rows)} vectors passed")


if __name__ == "__main__":
    main()
