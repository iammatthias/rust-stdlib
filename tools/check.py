#!/usr/bin/env python3
"""Run all release gates; missing toolchains are failures, never silent skips."""
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]

def source_fingerprint():
    """Hash source paths and bytes, including pending files."""
    try:
        names = subprocess.check_output(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT, stderr=subprocess.DEVNULL,
        ).decode("utf-8").split("\0")
    except (OSError, subprocess.CalledProcessError):
        names = [path.relative_to(ROOT).as_posix() for path in ROOT.rglob("*")
                 if path.is_file() and not any(part in {".git", "target", "__pycache__"}
                                               for part in path.relative_to(ROOT).parts)]
    digest = hashlib.sha256()
    for name in sorted(set(names)):
        if not name:
            continue
        path = ROOT / name
        if not path.is_file():
            continue
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()

# Representative crates/crypto feature sets: nothing, a hash with its MAC, AES
# without DES (the cipher engine's DES arms gated off), HPKE (ecdh without
# ecdsa) and x509 (every signature algorithm).
CRYPTO_FEATURE_SETS = {"no_features": "", "hmac_sha256": "sha256,hmac", "aes": "aes", "hpke": "hpke", "x509": "x509"}

# Hash availability follows the enabled hash packages, as in Go. The library's
# unit tests pin it for rsa alone (SHA-3 only), ecdsa alone (SHA-3 and the
# SHA-512 family) and rsa with ecdsa. Each set must run at least one
# hash_availability test, so a cfg guard that stops matching fails the gate.
CRYPTO_TEST_FEATURE_SETS = {"rsa": "rsa", "ecdsa": "ecdsa", "rsa_ecdsa": "rsa,ecdsa"}

# The per-package Go differentials grow with every package; give them room.
LONG_STEPS = {"stdlib_parity_differential": 3600}

def step_env(name, environment):
    """Rustdoc steps deny warnings so broken intra-doc links fail the gate."""
    if name.endswith("rustdoc"):
        return {**environment, "RUSTDOCFLAGS": (environment.get("RUSTDOCFLAGS", "") + " -D warnings").strip()}
    return environment

def clear_doc_output(command):
    """Remove a crate's target/doc before rustdoc runs: rustdoc reloads the
    search index it left there, and a stale index can crash it (an internal
    compiler error in search_index::load seen with rustc 1.99)."""
    manifest = "Cargo.toml"
    if "--manifest-path" in command:
        manifest = command[command.index("--manifest-path") + 1]
    doc = ROOT / Path(manifest).parent / "target" / "doc"
    if doc.is_dir():
        shutil.rmtree(doc)

def main():
    initial_source = source_fingerprint()
    environment = os.environ.copy()
    environment.update({"GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "PYTHONUTF8": "1"})
    steps = [
        ("dependency_manifest_policy", [sys.executable, "tools/dependency_policy.py"]),
        ("dependency_policy_regressions", [sys.executable, "tools/policy_tests.py"]),
        ("rust_toolchain", ["rustc", "--version"]),
        ("core_format", ["cargo", "fmt", "--check"]),
        ("tls_format", ["cargo", "fmt", "--check", "--manifest-path", "backends/tls/Cargo.toml"]),
        ("sysnet_format", ["cargo", "fmt", "--check", "--manifest-path", "backends/sysnet/Cargo.toml"]),
        ("crypto_format", ["cargo", "fmt", "--check", "--manifest-path", "crates/crypto/Cargo.toml"]),
        ("sys_format", ["cargo", "fmt", "--check", "--manifest-path", "crates/sys/Cargo.toml"]),
        ("derive_format", ["cargo", "fmt", "--check", "--manifest-path", "crates/derive/Cargo.toml"]),
        ("derive_consumer_format", ["cargo", "fmt", "--check", "--manifest-path", "tools/derive-check/Cargo.toml"]),
        ("fuzz_format", ["cargo", "fmt", "--check", "--manifest-path", "fuzz/Cargo.toml"]),
        ("fuzz_check", ["cargo", "check", "--offline", "--locked", "--manifest-path", "fuzz/Cargo.toml", "--bins"]),
        ("cargo_resolved_dependency_graph", [sys.executable, "tools/dependency_policy.py", "--metadata"]),
        ("rust_tests", ["cargo", "test", "--offline", "--locked", "--all-targets"]),
        ("rust_doctests", ["cargo", "test", "--offline", "--locked", "--doc"]),
        ("minimal_feature_tests", ["cargo", "test", "--offline", "--locked", "--no-default-features"]),
        ("tzdata_feature_tests", ["cargo", "test", "--offline", "--locked", "--features", "tzdata", "--lib", "--test", "tzif"]),
        ("build_examples", ["cargo", "build", "--offline", "--locked", "--examples"]),
        ("go_rust_differential", [sys.executable, "tools/conformance.py"]),
        ("csv_xml_differential", [sys.executable, "tools/encoding_conformance.py"]),
        ("archive_differential", [sys.executable, "tools/check_archives.py"]),
        ("regexp_differential", [sys.executable, "tools/regexp/check.py"]),
        ("stdlib_parity_differential", [sys.executable, "tools/parity_check.py"]),
        ("derive_integration", [sys.executable, "tools/derive-check/check.py"]),
        ("http_interoperability", [sys.executable, "tools/smoke.py"]),
        ("tls_adapter", ["cargo", "test", "--offline", "--locked", "--all-targets", "--manifest-path", "backends/tls/Cargo.toml"]),
        ("tls_application", [sys.executable, "tools/tls_check.py"]),
        ("crypto_clippy", ["cargo", "clippy", "--offline", "--locked", "--all-targets", "--manifest-path", "crates/crypto/Cargo.toml", "--", "-D", "warnings"]),
        # Partial feature sets keep the cfg-gated code compiling (docs/adr/0003,
        # "Features"); the library only, since tests and examples use every package.
        *((f"crypto_{name}_clippy", ["cargo", "clippy", "--offline", "--locked", "--lib", "--manifest-path", "crates/crypto/Cargo.toml", "--no-default-features", "--features", features, "--", "-D", "warnings"])
          for name, features in CRYPTO_FEATURE_SETS.items()),
        ("crypto_tests", ["cargo", "test", "--offline", "--locked", "--all-targets", "--manifest-path", "crates/crypto/Cargo.toml"]),
        *((f"crypto_{name}_tests", [sys.executable, "tools/crypto_feature_tests.py", features])
          for name, features in CRYPTO_TEST_FEATURE_SETS.items()),
        ("crypto_doctests", ["cargo", "test", "--offline", "--locked", "--doc", "--manifest-path", "crates/crypto/Cargo.toml"]),
        ("sys_clippy", ["cargo", "clippy", "--offline", "--locked", "--all-targets", "--manifest-path", "crates/sys/Cargo.toml", "--", "-D", "warnings"]),
        ("sys_tests", ["cargo", "test", "--offline", "--locked", "--all-targets", "--manifest-path", "crates/sys/Cargo.toml"]),
        ("sys_doctests", ["cargo", "test", "--offline", "--locked", "--doc", "--manifest-path", "crates/sys/Cargo.toml"]),
        ("sysnet_clippy", ["cargo", "clippy", "--offline", "--locked", "--all-targets", "--manifest-path", "backends/sysnet/Cargo.toml", "--", "-D", "warnings"]),
        ("sysnet_http_only_clippy", ["cargo", "clippy", "--offline", "--locked", "--all-targets", "--manifest-path", "backends/sysnet/Cargo.toml", "--no-default-features", "--", "-D", "warnings"]),
        ("sysnet_tests", ["cargo", "test", "--offline", "--locked", "--all-targets", "--manifest-path", "backends/sysnet/Cargo.toml"]),
        ("sysnet_http_only_tests", ["cargo", "test", "--offline", "--locked", "--all-targets", "--manifest-path", "backends/sysnet/Cargo.toml", "--no-default-features"]),
        ("sysnet_doctests", ["cargo", "test", "--offline", "--locked", "--doc", "--manifest-path", "backends/sysnet/Cargo.toml"]),
        ("sysnet_http_only_doctests", ["cargo", "test", "--offline", "--locked", "--doc", "--manifest-path", "backends/sysnet/Cargo.toml", "--no-default-features"]),
        ("sysnet_differential", [sys.executable, "tools/sysnet_check.py"]),
        ("rustdoc", ["cargo", "doc", "--offline", "--locked", "--no-deps"]),
        ("crypto_rustdoc", ["cargo", "doc", "--offline", "--locked", "--no-deps", "--manifest-path", "crates/crypto/Cargo.toml"]),
        ("crypto_hmac_sha256_rustdoc", ["cargo", "doc", "--offline", "--locked", "--no-deps", "--manifest-path", "crates/crypto/Cargo.toml", "--no-default-features", "--features", CRYPTO_FEATURE_SETS["hmac_sha256"]]),
        ("sys_rustdoc", ["cargo", "doc", "--offline", "--locked", "--no-deps", "--manifest-path", "crates/sys/Cargo.toml"]),
        ("derive_rustdoc", ["cargo", "doc", "--offline", "--locked", "--no-deps", "--manifest-path", "crates/derive/Cargo.toml"]),
        ("sysnet_rustdoc", ["cargo", "doc", "--offline", "--locked", "--no-deps", "--manifest-path", "backends/sysnet/Cargo.toml"]),
        ("sysnet_http_only_rustdoc", ["cargo", "doc", "--offline", "--locked", "--no-deps", "--manifest-path", "backends/sysnet/Cargo.toml", "--no-default-features"]),
        ("tls_rustdoc", ["cargo", "doc", "--offline", "--locked", "--no-deps", "--manifest-path", "backends/tls/Cargo.toml"]),
        ("api_parity", [sys.executable, "tools/api_parity.py", "--check"]),
        ("api_shape", [sys.executable, "tools/api_shape.py", "--check"]),
    ]
    results = []
    for name, command in steps:
        print(f"\n== {name} ==", flush=True)
        start = time.monotonic()
        try:
            if name.endswith("rustdoc"):
                clear_doc_output(command)
            run = subprocess.run(command, cwd=ROOT, env=step_env(name, environment), timeout=LONG_STEPS.get(name, 1200))
            status, detail = ("passed", "") if run.returncode == 0 else ("failed", f"exit {run.returncode}")
        except (OSError, subprocess.TimeoutExpired) as error:
            status, detail = "failed", str(error)
        results.append({"check": name, "status": status, "detail": detail, "elapsed_seconds": round(time.monotonic() - start, 3)})
        if status != "passed":
            for pending, _ in steps[len(results):]:
                results.append({"check": pending, "status": "not_run", "detail": "blocked by earlier failure"})
            break
    final_source = source_fingerprint()
    source_changed = initial_source != final_source
    report = {"status": "passed" if all(r["status"] == "passed" for r in results) and not source_changed else "failed", "checks": results,
              "source_sha256": initial_source, "source_changed_during_run": source_changed}
    (ROOT / "target").mkdir(exist_ok=True)
    (ROOT / "target/check-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1

if __name__ == "__main__":
    sys.exit(main())
