#!/usr/bin/env python3
"""Check rust_stdlib_sys::syscall against Go's syscall package for linux/amd64.

1. The generated files (constants, structs, wrappers, expected tables, the
   probe and docs/api/syscall.json) must be what tools/gen_syscall.go emits.
2. tools/gen_syscall.go writes a Go oracle program that prints every
   constant, struct size and field offset and every error and signal message
   with the real syscall package. It is built for GOOS=linux GOARCH=amd64 and
   run on Linux (directly on a linux/amd64 host, otherwise in a
   `--platform linux/amd64` container when Docker is available; set
   SYSCALL_ORACLE_IMAGE to choose the image, default busybox).
3. crates/sys/examples/syscall_probe prints the same lines from Rust.
4. The Go output, the Rust output and the go/constant + go/types expectation
   must be identical. Without a Linux runtime step 2 is skipped (and said so)
   and the Rust output is compared with the expectation only.
5. The Rust tests of the module run (crates/sys/tests/syscall.rs).
"""
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
GO_ENV = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")


def run(cmd, **kw):
    return subprocess.run(cmd, cwd=ROOT, check=True, text=True, **kw)


def run_go_oracle(exe, tmp):
    """The oracle's output, or None if no linux/amd64 runtime is available."""
    if sys.platform.startswith("linux") and platform.machine() in ("x86_64", "AMD64"):
        return subprocess.run([str(exe)], check=True, text=True, capture_output=True).stdout
    if not shutil.which("docker"):
        return None
    image = os.environ.get("SYSCALL_ORACLE_IMAGE", "busybox")
    cmd = ["docker", "run", "--rm", "--platform", "linux/amd64", "-v", f"{tmp}:/o:ro", image, "/o/oracle"]
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode:
        print(f"syscall oracle: no linux/amd64 container runtime ({p.stderr.strip()[-200:]})")
        return None
    return p.stdout


def main():
    run(["go", "run", "tools/gen_syscall.go", "-check"], env=GO_ENV)
    tmp = Path(tempfile.mkdtemp(prefix="syscallcheck"))
    try:
        src = tmp / "src"
        src.mkdir()
        expected = tmp / "expected.txt"
        run(["go", "run", "tools/gen_syscall.go", "-check", "-oracle-go", str(src), "-oracle-txt", str(expected)], env=GO_ENV)
        run(["go", "build", "-o", str(tmp / "oracle"), str(src / "main.go")],
            env=dict(GO_ENV, GOOS="linux", GOARCH="amd64", CGO_ENABLED="0"))
        want = expected.read_text()
        probe = run(["cargo", "run", "--offline", "--quiet", "--manifest-path", "crates/sys/Cargo.toml",
                     "--example", "syscall_probe"], capture_output=True).stdout
        if probe != want:
            diff = [(a, b) for a, b in zip(probe.splitlines(), want.splitlines()) if a != b][:10]
            raise SystemExit(f"Rust probe differs from the go/types expectation: {diff}")
        got = run_go_oracle(tmp / "oracle", tmp)
        if got is None:
            print("syscall differential: Go oracle built for linux/amd64 but not run (no Linux runtime); "
                  f"Rust matches the go/types expectation on {len(want.splitlines())} lines")
        else:
            if got != probe:
                diff = [(a, b) for a, b in zip(got.splitlines(), probe.splitlines()) if a != b][:10]
                raise SystemExit(f"Go oracle and Rust probe differ ({len(got.splitlines())} vs "
                                 f"{len(probe.splitlines())} lines): {diff}")
            print(f"syscall differential: Go (linux/amd64) and Rust agree on {len(got.splitlines())} lines")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    run(["cargo", "test", "--offline", "--locked", "--manifest-path", "crates/sys/Cargo.toml", "--test", "syscall"])


if __name__ == "__main__":
    main()
