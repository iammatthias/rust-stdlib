#!/usr/bin/env python3
"""Regenerate tests/fixtures/template/*.jsonl from Go's own template tests.

For each package, the Go package sources and *_test.go files are copied into a
scratch module together with tools/template_fixtures/<pkg>_dump_test.go, which
dumps the inputs of Go's test tables as differential requests. The requests
are then answered by tools/template_oracle.go (the real Go library) and stored
as {"req": ..., "ok": bool, "out": "...", "partial": "..."} lines. The Rust
tests replay them offline, so `cargo test` needs no Go toolchain.

Go's internal packages are not importable from outside GOROOT, so the few the
template packages use are shimmed in the scratch module.

Usage: python3 tools/template_fixtures.py [parse|text|html ...]
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
PACKAGES = {
    "parse": "text/template/parse",
    "text": "text/template",
    "html": "html/template",
}

GODEBUG_SHIM = """package godebug

type Setting struct{ name string }

func New(name string) *Setting { return &Setting{name} }
func (s *Setting) Value() string { return "" }
func (s *Setting) IncNonDefault() {}
func (s *Setting) Name() string { return s.name }
"""

TESTENV_SHIM = """package testenv

import "testing"

func SetGODEBUG(t testing.TB, value string) {}
func MustHaveGoBuild(t testing.TB) { t.Skip("no go build in fixture generation") }
func GoToolPath(t testing.TB) string { return "go" }
"""


def go_env():
    env = os.environ.copy()
    env.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": "-mod=mod"})
    return env


def goroot():
    return pathlib.Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())


def rewrite(text, module="scratch"):
    for name in ("fmtsort", "godebug", "testenv"):
        text = text.replace(f'"internal/{name}"', f'"{module}/internal/{name}"')
    text = text.replace('"text/template/parse"', f'"{module}/text/template/parse"')
    text = text.replace('"text/template"', f'"{module}/text/template"')
    return text


def copy_package(src, dst, keep_tests=True):
    dst.mkdir(parents=True, exist_ok=True)
    for f in src.glob("*.go"):
        if not keep_tests and f.name.endswith("_test.go"):
            continue
        text = f.read_text()
        if re.search(r"^package \w+_test", text, re.M):
            continue  # external test packages are not needed
        (dst / f.name).write_text(rewrite(text))
    if (src / "testdata").is_dir():
        shutil.copytree(src / "testdata", dst / "testdata", dirs_exist_ok=True)


HOOKED_HTML_TESTS = [
    "TestEscape", "TestEscapeSet", "TestErrors", "TestEscapeText", "TestTypedContent",
    "TestJSValEscaper", "TestJSStrEscaper", "TestJSRegexpEscaper",
    "TestEscapersOnLower7AndSelectHighCodepoints", "TestURLNormalizer", "TestSrcsetFilter",
    "TestStripTags", "TestCSSValueFilter",
]


def patch_hooks(pkg):
    """Inserts a dumpHook call in the first table loop of each hooked test."""
    for f in pkg.glob("*_test.go"):
        lines = f.read_text().split("\n")
        out = []
        current = None
        done = set()
        for line in lines:
            m = re.match(r"func (Test\w+)\(", line)
            if m:
                current = m.group(1)
            out.append(line)
            if (current in HOOKED_HTML_TESTS and current not in done
                    and line.strip() == "for _, test := range tests {"):
                out.append(f'\tdumpHook("{current}", test)')
                done.add(current)
        f.write_text("\n".join(out))


def dump_requests(name):
    goroot_src = goroot() / "src"
    with tempfile.TemporaryDirectory() as tmp:
        tmp = pathlib.Path(tmp)
        (tmp / "go.mod").write_text("module scratch\n\ngo 1.27\n")
        # Shims for internal packages.
        shutil.copytree(goroot_src / "internal/fmtsort", tmp / "internal/fmtsort",
                        ignore=shutil.ignore_patterns("*_test.go"))
        (tmp / "internal/godebug").mkdir(parents=True)
        (tmp / "internal/godebug/godebug.go").write_text(GODEBUG_SHIM)
        (tmp / "internal/testenv").mkdir(parents=True)
        (tmp / "internal/testenv/testenv.go").write_text(TESTENV_SHIM)
        for f in (tmp / "internal/fmtsort").glob("*.go"):
            f.write_text(rewrite(f.read_text()))
        # The package under test and, for html/template, the packages it uses.
        if name in ("text", "html"):
            copy_package(goroot_src / "text/template/parse", tmp / "text/template/parse", keep_tests=False)
        if name == "html":
            copy_package(goroot_src / "text/template", tmp / "text/template", keep_tests=False)
        pkg = tmp / "pkg"
        copy_package(goroot_src / PACKAGES[name], pkg)
        shutil.copy(ROOT / "tools/template_fixtures" / f"{name}_dump_test.go", pkg / "zz_dump_test.go")
        out = tmp / "requests.jsonl"
        env = go_env()
        env["FIXTURE_OUT"] = str(out)
        if name == "html":
            patch_hooks(pkg)
            run = "^(" + "|".join(HOOKED_HTML_TESTS) + ")$"
            # The hooked tests' own assertions are not the point; the dump is.
            subprocess.run(["go", "test", "-run", run, "-count=1", "./pkg"], cwd=tmp, env=env, check=False)
        else:
            subprocess.run(["go", "test", "-run", "TestDumpFixtures", "-count=1", "./pkg"], cwd=tmp, env=env, check=True)
        return [json.loads(line) for line in out.read_text().splitlines()]


def oracle_cmd():
    return ["go", "run", str(ROOT / "tools/template_oracle.go"), str(ROOT / "tools/template_oracle_data.go"), str(ROOT / "tools/template_oracle_html.go")]


def answer(requests):
    payload = "".join(json.dumps(r).encode().hex() + "\n" for r in requests)
    res = subprocess.run(oracle_cmd(), input=payload, text=True,
                         capture_output=True, cwd=ROOT, env=go_env())
    if res.returncode:
        raise SystemExit(res.stderr)
    replies = res.stdout.splitlines()
    assert len(replies) == len(requests)
    return replies


def main(argv):
    names = argv or ["parse", "text", "html"]
    for name in names:
        requests = dump_requests(name)
        replies = answer(requests)
        out = ROOT / "tests/fixtures/template" / f"{name}.jsonl"
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w") as f:
            for req, reply in zip(requests, replies):
                parts = reply.split(" ")
                dec = [bytes.fromhex(p).decode("utf-8", "replace") for p in parts[1:]]
                rec = {"req": req, "ok": parts[0] == "OK", "out": dec[0]}
                if parts[0] == "ERR":
                    rec["partial"] = dec[1] if len(dec) > 1 else ""
                f.write(json.dumps(rec, ensure_ascii=True) + "\n")
        print(f"{name}: {len(requests)} vectors -> {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main(sys.argv[1:])
