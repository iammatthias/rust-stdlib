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


def regenerate(manifest):
    run = subprocess.run(["cargo", "metadata", "--manifest-path", manifest, "--offline", "--locked", "--all-features", "--format-version", "1"],
                         cwd=ROOT, text=True, capture_output=True, timeout=60, check=True)
    data = json.loads(run.stdout)
    licenses = {(p["name"], p["version"]): p.get("license") for p in data["packages"]}
    lock = tomllib.loads((ROOT / manifest).with_name("Cargo.lock").read_text())["package"]
    path = ROOT / EXCEPTIONS[manifest]
    ledger = json.loads(path.read_text())
    # Reviewed packages keep their hand-written keys; only the checked ones move.
    reviewed = {package["name"]: package for package in ledger["packages"]}
    packages = []
    for package in sorted(lock, key=lambda p: (p["name"], p["version"])):
        record = _lock_record(package)
        previous = reviewed.get(record["name"], {"name": None, "version": None, "license": None})
        license = licenses[(record["name"], record["version"])] if record["source"] else previous.get("license")
        packages.append({**previous, **record, "license": license})
    ledger["packages"] = packages
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
