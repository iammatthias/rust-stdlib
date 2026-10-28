#!/usr/bin/env python3
"""Rewrite an exception ledger's packages and resolved_contract from its lock.

Run after a reviewed `cargo update` in an exception graph, then review the diff.
Other ledger keys (advisories, scope) are kept as they are and stay hand-written.

    python3 tools/dependency_ledger.py crates/crypto/Cargo.toml
"""
import argparse
import json
import subprocess
import sys
import tomllib

from dependency_policy import EXCEPTIONS, ROOT, _lock_record, resolved_contract


def merge_packages(reviewed, lock, licenses):
    """Lock fields and licenses come from Cargo; the matched reviewed entry's
    other keys carry over, and the gate rejects any it does not check. An
    entry matches on name and version, or on name alone when the ledger and
    the lock each hold one version of it (a reviewed bump)."""
    exact = {(package["name"], package["version"]): package for package in reviewed}
    by_name = {}
    for package in reviewed:
        by_name.setdefault(package["name"], []).append(package)
    in_lock = {}
    for package in lock:
        in_lock[package["name"]] = in_lock.get(package["name"], 0) + 1
    packages = []
    for package in sorted(lock, key=lambda p: (p["name"], p["version"])):
        record = _lock_record(package)
        previous = exact.get((record["name"], record["version"]))
        candidates = by_name.get(record["name"], [])
        if previous is None and len(candidates) == 1 and in_lock[record["name"]] == 1:
            previous = candidates[0]
        previous = previous or {"name": None, "version": None, "license": None}
        packages.append({**previous, **record, "license": licenses[(record["name"], record["version"])]})
    return packages


def regenerate(manifest):
    run = subprocess.run(["cargo", "metadata", "--manifest-path", manifest, "--offline", "--locked", "--all-features", "--format-version", "1"],
                         cwd=ROOT, text=True, capture_output=True, timeout=60, check=True)
    data = json.loads(run.stdout)
    licenses = {(p["name"], p["version"]): p.get("license") for p in data["packages"]}
    lock = tomllib.loads((ROOT / manifest).with_name("Cargo.lock").read_text())["package"]
    path = ROOT / EXCEPTIONS[manifest]
    ledger = json.loads(path.read_text())
    ledger["packages"] = merge_packages(ledger["packages"], lock, licenses)
    ledger["resolved_contract"] = resolved_contract(data)
    path.write_text(json.dumps(ledger, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", choices=sorted(EXCEPTIONS))
    try:
        regenerate(parser.parse_args().manifest)
    except subprocess.CalledProcessError as error:
        print(error.stderr, file=sys.stderr)
        sys.exit(1)
