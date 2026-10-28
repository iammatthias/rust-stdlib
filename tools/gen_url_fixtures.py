#!/usr/bin/env python3
"""Regenerate tests/fixtures/url_go_tables.json from Go's net/url/url_test.go.

The tables are private to package url, so a dump test is injected with
`go test -overlay`; nothing under GOROOT is modified.
"""
import json
import os
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    goroot = subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()
    target = pathlib.Path(goroot) / "src/net/url/zz_dump_test.go"
    with tempfile.TemporaryDirectory() as tmp:
        overlay = pathlib.Path(tmp) / "overlay.json"
        overlay.write_text(json.dumps({"Replace": {str(target): str(ROOT / "tools/url_tables_dump.go.txt")}}))
        env = dict(os.environ, URL_FIXTURE_OUT=str(ROOT / "tests/fixtures/url_go_tables.json"),
                   GOTOOLCHAIN="local", GOFLAGS="-mod=mod")
        subprocess.run(["go", "test", "-overlay", str(overlay), "-run", "TestDumpTables", "-count=1", "net/url"],
                       check=True, env=env, cwd=ROOT)


if __name__ == "__main__":
    main()
