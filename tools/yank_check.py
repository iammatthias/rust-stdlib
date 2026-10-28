#!/usr/bin/env python3
"""Fail when a direct registry pin in any manifest is yanked on crates.io.

A lock keeps a yanked version building here, but a crate that depends on ours
by path resolves without our lock and cannot select a yanked `=` pin. Needs the
network, so it is not part of the offline gate; run it before a release and
when a dependency is bumped:

    python3 tools/yank_check.py
"""
import json
import sys
import urllib.request

from dependency_policy import MANIFESTS

INDEX = "https://index.crates.io"


def index_path(name):
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def yanked(name, version):
    request = urllib.request.Request(f"{INDEX}/{index_path(name)}", headers={"User-Agent": "rust-stdlib yank_check"})
    with urllib.request.urlopen(request, timeout=30) as response:
        for line in response.read().decode().splitlines():
            entry = json.loads(line)
            if entry["vers"] == version:
                return entry["yanked"]
    raise RuntimeError(f"{name} {version} is not in the crates.io index")


def main():
    failures = []
    for manifest, (_, dependencies) in sorted(MANIFESTS.items()):
        for name, spec in sorted(dependencies.items()):
            requirement = spec if isinstance(spec, str) else spec.get("version")
            if requirement is None:
                continue
            version = requirement.removeprefix("=")
            if yanked(name, version):
                failures.append(f"{manifest}: {name} {requirement} is yanked")
    print("\n".join(failures) or "no direct pin is yanked")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
