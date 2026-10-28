#!/usr/bin/env python3
"""http.DefaultTransport differential: Go's settings against backends/sysnet.

Go's tools/sysnet_oracle.go prints every field of http.DefaultTransport that
has an observable value, plus the keep-alive socket options of a socket dialed
through its DialContext. backends/sysnet's default_transport_probe prints the
same lines for rust_stdlib_sysnet::default_transport(); they must be identical.
"""
import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ENV = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off")


def main():
    subprocess.run(["cargo", "build", "--quiet", "--offline", "--locked", "--manifest-path",
                    "backends/sysnet/Cargo.toml", "--example", "default_transport_probe"],
                   cwd=ROOT, check=True, env=ENV)
    go = subprocess.run(["go", "run", "tools/sysnet_oracle.go"], cwd=ROOT, check=True, env=ENV,
                        capture_output=True, text=True).stdout.splitlines()
    rust = subprocess.run([str(ROOT / "backends/sysnet/target/debug/examples/default_transport_probe")],
                          cwd=ROOT, check=True, env=ENV, capture_output=True, text=True).stdout.splitlines()
    # Go prints booleans as true/false, as does Rust's Display.
    if go != rust:
        for line in sorted(set(go) ^ set(rust)):
            print(("go   " if line in go else "rust ") + line)
        sys.exit("sysnet: DefaultTransport settings differ from Go's")
    print(f"sysnet: {len(go)} DefaultTransport settings match Go")


if __name__ == "__main__":
    main()
