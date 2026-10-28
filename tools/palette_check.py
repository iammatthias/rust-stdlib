#!/usr/bin/env python3
"""Compare the Plan9 and WebSafe palette tables against Go's image/color/palette.

Both tables are printed entry by entry (table, index, non-premultiplied RGBA)
by the Rust probe and by the Go oracle; every line must match exactly and the
entry counts must agree (256 Plan9 entries, 216 WebSafe entries).
"""
import os
import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    started = time.monotonic()
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off"})
    subprocess.run(["cargo", "build", "--offline", "--locked", "--example", "palette_probe"],
                   cwd=ROOT, env=env, check=True)
    probe = ROOT / "target/debug/examples" / ("palette_probe.exe" if os.name == "nt" else "palette_probe")
    rust = subprocess.run([str(probe)], cwd=ROOT, env=env, text=True, capture_output=True,
                          check=True).stdout.splitlines()
    go = subprocess.run(["go", "run", str(ROOT / "tools/palette_oracle.go")], cwd=ROOT, env=env,
                        text=True, capture_output=True, check=True).stdout.splitlines()
    counts = {name: sum(1 for line in go if line.startswith(name + " ")) for name in ("plan9", "websafe")}
    if counts != {"plan9": 256, "websafe": 216}:
        raise AssertionError(f"unexpected Go palette sizes: {counts}")
    if len(rust) != len(go):
        raise AssertionError(f"line count mismatch: Rust {len(rust)}, Go {len(go)}")
    for index, (actual, expected) in enumerate(zip(rust, go)):
        if actual != expected:
            raise AssertionError(f"entry {index}: Rust={actual!r} Go={expected!r}")
    print(f"Palette Go conformance: {len(go)} entries (Plan9 256, WebSafe 216) passed "
          f"in {time.monotonic() - started:.3f}s")


if __name__ == "__main__":
    main()
