#!/usr/bin/env python3
"""Find Go-shaped public API (ADR 0005) and ratchet the count toward zero.

  api_shape.py             report findings per module and the total
  api_shape.py --check     fail if the total exceeds tools/api_shape_baseline.json
  api_shape.py --update    lower the baseline to the current total (never raises it)

Rules, applied to `pub` items in the shipped crates:
  go-name        an identifier containing `go`/`GO` as a word (`go_sprintf`, `GO_STANDARD`),
                 a CamelCase `Go` word (`GoKind`), a public field (`go_compat`),
                 or a module named `go*` (`gotime`, `gohttp`)
  go-constructor `pub fn new_<word>(` (Go's `NewReader`), unless allow-listed
  string-method  `pub fn string(self)`/`(&self)`, or a trait's `fn string(&self)`,
                 instead of `impl Display`
  std-mirror     a public module that mirrors a Go package Rust's std already covers
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tools/api_shape_baseline.json"
SOURCES = ["src", "crates/crypto/src", "crates/sys/src", "crates/derive/src", "backends/tls/src", "backends/sysnet/src"]
SKIP = {"api_surface.rs"}

# Go packages whose capability Rust's std already provides (ADR 0005, item 1).
STD_MIRRORS = {"strings", "bytes", "sort", "slices", "maps", "cmp", "iter", "container",
               "sync", "errors", "fmt", "utf8", "utf16", "bits"}

# Legitimate `new_*` constructors, each with a reason.
ALLOWED_CONSTRUCTORS = {
    "new_v4": "UUID version naming, as in the uuid crate",
    "new_v7": "UUID version naming, as in the uuid crate",
}

GO_WORD = re.compile(r"(?:^|_)(?:go|GO)(?:_|$)|(?:^|[a-z0-9])Go(?:[A-Z]|$)")
PUB_ITEM = re.compile(
    r"^\s*pub(?:\([^)]*\))?\s+(?:const\s+|static\s+|unsafe\s+|async\s+|extern\s+\"C\"\s+)*"
    r"(fn|struct|enum|trait|type|const|static|mod|use)\s+(?:r#)?([A-Za-z_][A-Za-z0-9_]*)")
MACRO = re.compile(r"^\s*macro_rules!\s*([A-Za-z_][A-Za-z0-9_]*)")
STRING_METHOD = re.compile(r"^\s*pub\s+fn\s+string\s*\(\s*&?\s*(?:mut\s+)?self\s*\)")
TRAIT_STRING = re.compile(r"^\s*fn\s+string\s*\(\s*&?\s*self\s*\)[^{]*;")
PUB_FIELD = re.compile(r"^\s*pub(?:\([^)]*\))?\s+([a-z_][a-z0-9_]*)\s*:[^:]")


def module_of(path):
    rel = path.relative_to(ROOT)
    parts = list(rel.parts)
    crate = "rust_stdlib"
    if parts[0] in ("crates", "backends"):
        crate = "rust_stdlib_" + parts[1]
        parts = parts[3:]
    else:
        parts = parts[1:]
    stem = parts[-1][:-3]
    parts = parts[:-1] + ([] if stem in ("mod", "lib") else [stem])
    return "::".join([crate] + parts)


def scan():
    findings = []
    for source in SOURCES:
        base = ROOT / source
        if not base.exists():
            continue
        for path in sorted(base.rglob("*.rs")):
            if path.name in SKIP or "tests" in path.relative_to(base).parts:
                continue
            module = module_of(path)
            in_tests = False
            for number, line in enumerate(path.read_text().splitlines(), 1):
                if re.match(r"\s*#\[cfg\(test\)\]", line):
                    in_tests = True
                if in_tests:
                    continue
                where = f"{path.relative_to(ROOT)}:{number}"
                m = PUB_ITEM.match(line)
                if m:
                    kind, name = m.groups()
                    if kind != "use" and GO_WORD.search(name):
                        findings.append(("go-name", module, where, name))
                    if kind == "fn" and name.startswith("new_") and name not in ALLOWED_CONSTRUCTORS:
                        findings.append(("go-constructor", module, where, name))
                    if kind == "mod" and name.startswith("go") and not name.startswith(("gob", "goto")):
                        findings.append(("go-name", module, where, name))
                    if kind == "mod" and name in STD_MIRRORS:
                        findings.append(("std-mirror", module, where, name))
                m = MACRO.match(line)
                if m and GO_WORD.search(m.group(1)):
                    findings.append(("go-name", module, where, m.group(1) + "!"))
                m = PUB_FIELD.match(line)
                if m and not PUB_ITEM.match(line) and GO_WORD.search(m.group(1)):
                    findings.append(("go-name", module, where, m.group(1)))
                if STRING_METHOD.match(line) or TRAIT_STRING.match(line):
                    findings.append(("string-method", module, where, "string"))
    return findings


def main(argv):
    findings = scan()
    total = len(findings)
    baseline = json.loads(BASELINE.read_text())["max"] if BASELINE.exists() else None
    if "--update" in argv:
        new = total if baseline is None else min(total, baseline)
        BASELINE.write_text(json.dumps({"max": new}, indent=2) + "\n")
        print(f"baseline {baseline} -> {new}")
        return 0
    per_module = {}
    for rule, module, where, name in findings:
        per_module.setdefault(module, []).append((rule, where, name))
    if "--check" not in argv or "--verbose" in argv:
        for module in sorted(per_module, key=lambda m: -len(per_module[m])):
            print(f"{len(per_module[module]):4} {module}")
            if "--verbose" in argv:
                for rule, where, name in per_module[module]:
                    print(f"       {rule:14} {name:28} {where}")
    print(f"Go-shaped public items: {total} (baseline {baseline})")
    if "--check" in argv and baseline is not None and total > baseline:
        print("api_shape: more Go-shaped public items than the baseline; see ADR 0005", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
