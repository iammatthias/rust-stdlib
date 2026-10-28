#!/usr/bin/env python3
"""Enforce the zero-dependency core and explicit isolated exception graphs.

Inventories are review artifacts, not an authority that can approve new manifests
or direct dependencies. Lock identities include source/checksum and resolved edges.
Cargo metadata additionally validates resolved manifests and licenses offline.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

# Build output and agent worktrees are local state, not repository content.
LOCAL_STATE = {"target", ".claude"}

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
MANIFESTS = {
    "Cargo.toml": ("rust-stdlib", {}),
    "crates/derive/Cargo.toml": ("rust-stdlib-derive", {}),
    "crates/sys/Cargo.toml": ("rust-stdlib-sys", {}),
    "tools/derive-check/Cargo.toml": ("rust-stdlib-derive-check", {
        "rust-stdlib": {"path": "../..", "default-features": False},
        "rust-stdlib-derive": {"path": "../../crates/derive"},
    }),
    "backends/tls/Cargo.toml": ("rust-stdlib-tls", {
        "rust-stdlib": {"path": "../.."},
        "rustls": {"version": "=0.23.46", "default-features": False, "features": ["std", "ring", "tls12"]},
    }),
    # Glue between the root crate and crates/sys (docs/adr/0006). Its only
    # third-party graph is the optional, default-on `tls` feature's rust-stdlib-tls.
    "backends/sysnet/Cargo.toml": ("rust-stdlib-sysnet", {
        "rust-stdlib": {"path": "../.."},
        "rust-stdlib-sys": {"path": "../../crates/sys"},
        "rust-stdlib-tls": {"path": "../tls", "optional": True},
    }),
    "crates/crypto/Cargo.toml": ("rust-stdlib-crypto", {
        "digest": {"version": "=0.11.3", "default-features": False, "optional": True},
        "sha1": {"version": "=0.11.0", "default-features": False, "features": ["oid"], "optional": True},
        "sha2": {"version": "=0.11.0", "default-features": False, "features": ["oid"], "optional": True},
        "sha3": {"version": "=0.11.0", "default-features": False, "features": ["oid"], "optional": True},
        "cshake": {"version": "=0.2.1", "default-features": False, "optional": True},
        "md-5": {"version": "=0.11.0", "default-features": False, "features": ["oid"], "optional": True},
        "hmac": {"version": "=0.13.0", "default-features": False, "optional": True},
        "hkdf": {"version": "=0.13.0", "default-features": False, "optional": True},
        "pbkdf2": {"version": "=0.13.0", "default-features": False, "features": ["hmac"], "optional": True},
        "subtle": {"version": "=2.6.1", "default-features": False, "optional": True},
        "getrandom": {"version": "=0.4.3", "default-features": False, "optional": True},
        "aes": {"version": "=0.9.2", "default-features": False, "optional": True},
        "des": {"version": "=0.9.0", "default-features": False, "optional": True},
        "rc4": {"version": "=0.2.0", "default-features": False, "optional": True},
        "cbc": {"version": "=0.2.1", "default-features": False, "optional": True},
        "cfb-mode": {"version": "=0.9.1", "default-features": False, "optional": True},
        "ctr": {"version": "=0.10.1", "default-features": False, "optional": True},
        "ofb": {"version": "=0.7.1", "default-features": False, "optional": True},
        "aes-gcm": {"version": "=0.11.1", "default-features": False, "features": ["aes"], "optional": True},
        "ed25519-dalek": {"version": "=3.0.0", "default-features": False, "features": ["alloc", "digest", "pkcs8"], "optional": True},
        "x25519-dalek": {"version": "=3.0.0", "default-features": False, "features": ["static_secrets"], "optional": True},
        "p224": {"version": "=0.14.0-rc.15", "default-features": False, "features": ["arithmetic", "ecdh", "ecdsa", "pkcs8"], "optional": True},
        "p256": {"version": "=0.14.0", "default-features": False, "features": ["arithmetic", "ecdh", "ecdsa", "pkcs8"], "optional": True},
        "p384": {"version": "=0.14.0", "default-features": False, "features": ["arithmetic", "ecdh", "ecdsa", "pkcs8"], "optional": True},
        "p521": {"version": "=0.14.0", "default-features": False, "features": ["arithmetic", "ecdh", "ecdsa", "pkcs8"], "optional": True},
        "ecdsa": {"version": "=0.17.0", "default-features": False, "features": ["algorithm", "alloc", "der"], "optional": True},
        "rsa": {"version": "=0.10.0-rc.19", "default-features": False, "features": ["encoding"], "optional": True},
        "dsa": {"version": "=0.7.0", "default-features": False, "features": ["hazmat", "pkcs8"], "optional": True},
        "ml-kem": {"version": "=0.3.2", "default-features": False, "features": ["alloc"], "optional": True},
        "ml-dsa": {"version": "=0.1.1", "default-features": False, "features": ["alloc", "rand_core"], "optional": True},
        "crypto-bigint": {"version": "=0.7.10", "default-features": False, "features": ["alloc"], "optional": True},
        "crypto-primes": {"version": "=0.7.2", "default-features": False, "optional": True},
        "rand_core": {"version": "=0.10.1", "default-features": False, "optional": True},
        "hpke": {"version": "=0.14.1", "default-features": False, "features": ["alloc", "aes", "chacha", "nistp", "x25519"], "optional": True},
    }),
    "fuzz/Cargo.toml": ("rust-stdlib-fuzz", {
        "rust-stdlib": {"path": ".."}, "libfuzzer-sys": "=0.4.13",
    }),
}
# The one manifest approved for FFI (docs/adr/0004): unsafe is denied crate-wide
# and allowed only on the modules under FFI_DIR.
FFI_MANIFEST = "crates/sys/Cargo.toml"
FFI_DIR = "crates/sys/src/ffi"
FFI_ROOT = "crates/sys/src/lib.rs"
# First-party manifests with path dependencies on other first-party crates only;
# their locks and resolved graphs are checked against this table, not a ledger.
FIRST_PARTY_GRAPHS = {
    "tools/derive-check/Cargo.toml": {"rust-stdlib-derive-check": ["rust-stdlib", "rust-stdlib-derive"], "rust-stdlib": [], "rust-stdlib-derive": []},
}
# Feature tables are part of the reviewed contract where a feature gates a dependency.
FEATURES = {
    "backends/sysnet/Cargo.toml": {"default": ["tls"], "tls": ["dep:rust-stdlib-tls"]},
    # Every crypto dependency is optional: one feature per Go package, `full` by
    # default (docs/adr/0003, "Features").
    "crates/crypto/Cargo.toml": {
        "default": ["full"],
        "full": ["aes", "cipher", "des", "dsa", "ecdh", "ecdsa", "ed25519", "elliptic", "hkdf", "hmac", "hpke", "md5", "mldsa", "mlkem", "pbkdf2", "rand", "rc4", "rsa", "sha1", "sha256", "sha3", "sha512", "subtle", "x509"],
        "md5": ["dep:digest", "dep:md-5"],
        "sha1": ["dep:digest", "dep:sha1"],
        "sha256": ["dep:digest", "dep:sha2"],
        "sha512": ["dep:digest", "dep:sha2"],
        "sha3": ["dep:digest", "dep:sha3", "dep:cshake"],
        "subtle": ["dep:subtle"],
        "rand": ["dep:sha2", "dep:getrandom", "dep:rand_core", "dep:crypto-bigint", "dep:crypto-primes"],
        "hmac": ["sha3", "subtle", "dep:hmac"],
        "hkdf": ["hmac", "dep:hkdf"],
        "pbkdf2": ["hmac", "dep:pbkdf2"],
        "cipher": ["rand", "dep:aes", "dep:aes-gcm", "dep:cbc", "dep:cfb-mode", "dep:ctr", "dep:ofb"],
        "aes": ["cipher"],
        "des": ["cipher", "dep:des"],
        "rc4": ["cipher", "dep:rc4"],
        "nistec": ["rand", "dep:p224", "dep:p256", "dep:p384", "dep:p521", "dep:ecdsa", "dep:sha2"],
        "ecdh": ["nistec", "subtle", "dep:x25519-dalek"],
        "elliptic": ["nistec"],
        "ecdsa": ["ecdh", "elliptic", "sha3", "sha512", "subtle"],
        "ed25519": ["rand", "subtle", "dep:ed25519-dalek", "dep:sha2"],
        "rsa": ["rand", "sha3", "subtle", "dep:rsa", "dep:crypto-bigint", "dep:md-5", "dep:sha1", "dep:sha2"],
        "dsa": ["rand", "dep:dsa"],
        "mlkem": ["rand", "dep:ml-kem"],
        "mldsa": ["rand", "subtle", "dep:ml-dsa"],
        "hpke": ["ecdh", "sha256", "sha3", "sha512", "dep:hpke"],
        "x509": ["dsa", "ecdh", "ecdsa", "ed25519", "elliptic", "md5", "mldsa", "rsa", "sha1", "sha256", "sha512"],
    },
}
# First-party path packages, besides the root crate and the manifest's own
# package, that an exception lock may contain.
EXCEPTION_FIRST_PARTY = {
    "backends/sysnet/Cargo.toml": {"rust-stdlib-sys", "rust-stdlib-tls"},
}
EXCEPTIONS = {
    "backends/tls/Cargo.toml": "docs/tls-dependencies.json",
    "backends/sysnet/Cargo.toml": "docs/sysnet-dependencies.json",
    "crates/crypto/Cargo.toml": "docs/crypto-dependencies.json",
    "fuzz/Cargo.toml": "docs/fuzz-dependencies.json",
}


def _load(path, format):
    try:
        return format(path.read_text())
    except (OSError, ValueError, TypeError) as error:
        raise RuntimeError(f"cannot read policy input {path}: {error}") from error


def _identity(package):
    return package.get("name"), package.get("version")


def _lock_record(package):
    return {
        "name": package.get("name"), "version": package.get("version"),
        "source": package.get("source"), "checksum": package.get("checksum"),
        "lock_dependencies": sorted(package.get("dependencies", [])),
    }


# A ledger holds only what the gate checks, plus the hand-written scope and
# advisories notes; anything else would go stale unseen.
LEDGER_KEYS = {"scope", "advisories", "packages", "resolved_contract"}
LEDGER_PACKAGE_KEYS = {"name", "version", "source", "checksum", "license", "lock_dependencies"}


def _records(packages, label, violations):
    result = {}
    if not isinstance(packages, list):
        violations.append(f"{label}: packages must be an array")
        return result
    for package in packages:
        if not isinstance(package, dict):
            violations.append(f"{label}: package must be an object")
            continue
        identity = _identity(package)
        if not all(isinstance(v, str) and v for v in identity):
            violations.append(f"{label}: invalid package name/version")
            continue
        if identity in result:
            violations.append(f"{label}: duplicate package identity {identity}")
        result[identity] = package
    return result


def _exception_inventory(root, manifest, violations):
    ledger = _load(root / EXCEPTIONS[manifest], json.loads)
    if not isinstance(ledger, dict):
        violations.append(f"{manifest}: inventory must be an object")
        return {}
    records = _records(ledger.get("packages"), manifest + " inventory", violations)
    lock = _load(root / Path(manifest).parent / "Cargo.lock", tomllib.loads)
    actual = _records(lock.get("package"), manifest + " lock", violations)
    expected_name = MANIFESTS[manifest][0]
    if len({identity[0] for identity in records}) != len(records):
        violations.append(f"{manifest}: duplicate package names are outside the reviewed contract")
    if not isinstance(ledger.get("resolved_contract"), dict):
        violations.append(f"{manifest}: missing reviewed feature/kind graph")
    if set(ledger) - LEDGER_KEYS:
        violations.append(f"{manifest}: unverified ledger keys {sorted(set(ledger) - LEDGER_KEYS)}")
    if set(records) != set(actual):
        violations.append(f"{manifest}: lock package set differs from reviewed inventory")
    for identity, reviewed in records.items():
        source = reviewed.get("source")
        checksum = reviewed.get("checksum")
        if source is None:
            if identity[0] not in {"rust-stdlib", expected_name, *EXCEPTION_FIRST_PARTY.get(manifest, ())} or checksum is not None:
                violations.append(f"{manifest}: unapproved first-party/path package {identity}")
            else:
                own = next((m for m, spec in MANIFESTS.items() if spec[0] == identity[0]), None)
                declared = _load(root / own, tomllib.loads)["package"].get("license") if own else None
                if reviewed.get("license") != declared:
                    violations.append(f"{manifest}: path package license differs from its manifest for {identity}")
        elif source != REGISTRY or not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            violations.append(f"{manifest}: invalid reviewed registry source/checksum for {identity}")
        if set(reviewed) - LEDGER_PACKAGE_KEYS:
            violations.append(f"{manifest}: unverified ledger keys {sorted(set(reviewed) - LEDGER_PACKAGE_KEYS)} for {identity}")
        edges = reviewed.get("lock_dependencies")
        if not isinstance(edges, list) or not all(isinstance(edge, str) for edge in edges):
            violations.append(f"{manifest}: missing reviewed resolved lock edges for {identity}")
            continue
        record = {key: reviewed.get(key) for key in ("name", "version", "source", "checksum")}
        record["lock_dependencies"] = sorted(edges)
        if identity in actual and _lock_record(actual[identity]) != record:
            violations.append(f"{manifest}: lock source/checksum/resolved edges differ for {identity}")
    return records


def verify(root=ROOT):
    root = Path(root).resolve()
    violations = []
    manifests = sorted({p for p in root.rglob("Cargo.toml") if not LOCAL_STATE.intersection(p.relative_to(root).parts)} | {root / relative for relative in MANIFESTS if (root / relative).is_file()})
    inventory = {}

    def walk(value, location):
        if not isinstance(value, dict):
            return
        for key, child in value.items():
            if key in {"dependencies", "dev-dependencies", "build-dependencies", "patch", "replace"} and child:
                violations.append(f"{location}.{key}: nonempty dependency/override table")
            walk(child, f"{location}.{key}")

    for path in manifests:
        relative = path.relative_to(root).as_posix()
        if path.is_symlink() or path.resolve() != path:
            violations.append(f"{relative}: manifest symlinks are not approved")
        data = _load(path, tomllib.loads)
        contract = MANIFESTS.get(relative)
        if contract is None:
            violations.append(f"{relative}: unexpected Cargo manifest")
            walk(data, relative)
            continue
        name, expected = contract
        expected_lint = "deny" if relative == FFI_MANIFEST else "forbid"
        if data.get("lints", {}).get("rust", {}).get("unsafe_code") != expected_lint:
            violations.append(f"{relative}: first-party targets must {expected_lint} unsafe at compiler level")
        if data.get("package", {}).get("name") != name:
            violations.append(f"{relative}: first-party package identity changed")
        if data.get("dependencies", {}) != expected:
            violations.append(f"{relative}: direct dependency contract changed")
        if relative in FEATURES and data.get("features") != FEATURES[relative]:
            violations.append(f"{relative}: feature contract changed")
        walk({key: value for key, value in data.items() if key != "dependencies"}, relative)
        workspace = data.get("workspace")
        if workspace is not None and not (relative == "fuzz/Cargo.toml" and workspace == {"members": ["."]}):
            violations.append(f"{relative}: unapproved workspace configuration")
        if data.get("package", {}).get("build") not in {None, False}:
            violations.append(f"{relative}: custom build script")
        for section in ("lib", "bin", "example", "test", "bench"):
            targets = data.get(section, [])
            if isinstance(targets, dict):
                targets = [targets]
            for target in targets:
                source = target.get("path")
                if source and (Path(source).is_absolute() or not (path.parent / source).resolve().is_relative_to(path.parent.resolve())):
                    violations.append(f"{relative}: target source escapes first-party package")
        if relative in EXCEPTIONS:
            inventory[relative] = _exception_inventory(root, relative, violations)

    for path in root.rglob("build.rs"):
        if not LOCAL_STATE.intersection(path.relative_to(root).parts):
            violations.append(f"{path.relative_to(root)}: auto-discovered build script")
    for directory in root.rglob(".cargo"):
        if not LOCAL_STATE.intersection(directory.relative_to(root).parts):
            if (directory / "config").exists() or (directory / "config.toml").exists():
                violations.append(f"{directory.relative_to(root)}: unreviewed Cargo configuration")
    lock = _load(root / "Cargo.lock", tomllib.loads)
    packages = lock.get("package", [])
    root_manifest = _load(root / "Cargo.toml", tomllib.loads)
    root_version = root_manifest.get("package", {}).get("version")
    if len(packages) != 1 or _lock_record(packages[0]) != {"name": "rust-stdlib", "version": root_version, "source": None, "checksum": None, "lock_dependencies": []}:
        violations.append("Cargo.lock must contain exactly the first-party root package")
    approved_locks = {(Path(manifest).parent / "Cargo.lock").as_posix(): manifest for manifest in MANIFESTS}
    for path in root.rglob("Cargo.lock"):
        relative = path.relative_to(root).as_posix()
        if LOCAL_STATE.intersection(path.relative_to(root).parts):
            continue
        manifest = approved_locks.get(relative)
        if manifest is None or not (root / manifest).is_file():
            violations.append(f"{relative}: unexpected Cargo lockfile")
        elif manifest in {"crates/derive/Cargo.toml", FFI_MANIFEST, *FIRST_PARTY_GRAPHS}:
            locked = _load(path, tomllib.loads).get("package", [])
            graph = FIRST_PARTY_GRAPHS.get(manifest, {MANIFESTS[manifest][0]: []})
            names = set(graph)
            expected = {name: {"name": name, "version": _load(root / next(m for m, spec in MANIFESTS.items() if spec[0] == name), tomllib.loads)["package"]["version"], "source": None, "checksum": None, "lock_dependencies": sorted(graph[name])} for name in names}
            actual = _records(locked, relative, violations)
            if {key[0] for key in actual} != names or len(actual) != len(names) or any(_lock_record(p) != expected[p["name"]] for p in actual.values() if p["name"] in names):
                violations.append(f"{relative}: first-party lock graph changed")

    source_files = sorted(p for p in root.rglob("*.rs") if not LOCAL_STATE.intersection(p.relative_to(root).parts))
    for path in source_files:
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            violations.append(f"{relative}: source symlinks are not approved")
        source = path.read_text()
        ffi = relative.startswith(FFI_DIR + "/")
        for pattern in [r"\bunsafe\s*(?:\{|fn\b|impl\b|trait\b|extern\b)", r"\bextern\s*(?:\"[^\"]*\"|\{)"]:
            if re.search(pattern, source) and not ffi:
                violations.append(f"{relative}: disallowed source pattern {pattern}")
        if re.search(r"\b(?:todo|unimplemented)!\s*\(", source):
            violations.append(f"{relative}: disallowed source pattern todo!/unimplemented!")
        if ffi:
            lines = source.splitlines()
            for number, line in enumerate(lines):
                if re.search(r"\bunsafe\s*(?:\{|impl\b|trait\b)", line) and not line.lstrip().startswith("//"):
                    nearby = lines[max(0, number - 8):number + 1]
                    if not any("// SAFETY:" in near for near in nearby):
                        violations.append(f"{relative}:{number + 1}: unsafe block without a // SAFETY: comment")
        if re.search(r"allow\s*\(\s*unsafe_code", source) and relative != FFI_ROOT:
            violations.append(f"{relative}: allow(unsafe_code) is only approved on the ffi module declaration")
    for source in ("src/lib.rs", "crates/derive/src/lib.rs", "crates/crypto/src/lib.rs", "backends/tls/src/lib.rs", "backends/sysnet/src/lib.rs"):
        path = root / source
        if path.exists() and "#![forbid(unsafe_code)]" not in path.read_text():
            violations.append(f"{source}: crate must forbid unsafe code")
    sys_lib = root / FFI_ROOT
    if sys_lib.exists():
        text = sys_lib.read_text()
        if "#![deny(unsafe_code)]" not in text:
            violations.append(f"{FFI_ROOT}: crate must deny unsafe code at the root")
        if len(re.findall(r"allow\s*\(\s*unsafe_code", text)) != 1 or not re.search(r"#\[allow\(unsafe_code\)\]\s*mod ffi;", text):
            violations.append(f"{FFI_ROOT}: allow(unsafe_code) is only approved on `mod ffi;`")
    if not (root / "src/lib.rs").is_file():
        violations.append("missing root crate source")
    if violations:
        raise RuntimeError("\n".join(violations))
    return {"manifests": len(manifests), "application_packages": len(packages), "declared_third_party_dependencies": 0, "exception_packages": {manifest: sum(p.get("source") is not None for p in records.values()) for manifest, records in inventory.items()}, "source_files": len(source_files), "status": "passed"}


def resolved_contract(data):
    """Normalize Cargo IDs to relocatable identities while retaining feature/kind edges."""
    identities = {p["id"]: f"{p['name']}@{p['version']}" for p in data["packages"]}
    nodes = []
    for node in data["resolve"]["nodes"]:
        deps = [{"name": edge["name"], "package": identities[edge["pkg"]],
                 "dep_kinds": sorted(edge["dep_kinds"], key=lambda kind: json.dumps(kind, sort_keys=True))}
                for edge in node["deps"]]
        nodes.append({"package": identities[node["id"]], "features": sorted(node["features"]),
                      "dependencies": sorted(identities[dep] for dep in node["dependencies"]),
                      "deps": sorted(deps, key=lambda dep: (dep["name"], dep["package"]))})
    return {"root": identities[data["resolve"]["root"]], "nodes": sorted(nodes, key=lambda node: node["package"])}


def metadata(root=ROOT):
    root = Path(root).resolve()
    verify(root)
    for manifest in ("Cargo.toml", *FIRST_PARTY_GRAPHS, FFI_MANIFEST, *EXCEPTIONS):
        if not (root / manifest).is_file():
            continue
        run = subprocess.run(["cargo", "metadata", "--manifest-path", manifest, "--offline", "--locked", "--all-features", "--format-version", "1"], cwd=root, text=True, capture_output=True, timeout=60)
        if run.returncode:
            raise RuntimeError(run.stderr)
        data = json.loads(run.stdout)
        violations = []
        if manifest in EXCEPTIONS:
            approved = _exception_inventory(root, manifest, violations)
        else:
            names = {"rust-stdlib"} if manifest == "Cargo.toml" else {MANIFESTS[FFI_MANIFEST][0]} if manifest == FFI_MANIFEST else set(FIRST_PARTY_GRAPHS[manifest])
            approved = {(name, _load(root / next(m for m, spec in MANIFESTS.items() if spec[0] == name), tomllib.loads)["package"]["version"]): None for name in names}
        actual = _records(data.get("packages"), manifest + " metadata", violations)
        if set(actual) != set(approved):
            violations.append(f"{manifest}: resolved package set changed")
        by_id = {p["id"]: p for p in actual.values()}
        for identity, package in actual.items():
            ledger = approved.get(identity)
            if package.get("source") is None:
                known = next((m for m, spec in MANIFESTS.items() if spec[0] == identity[0]), None)
                if known is None or Path(package["manifest_path"]).resolve() != root / known:
                    violations.append(f"{manifest}: resolved unapproved path package {identity}")
                if identity[0] in {"rust-stdlib", "rust-stdlib-derive", "rust-stdlib-sys"} and package.get("dependencies"):
                    violations.append(f"{manifest}: third-party dependency intrusion into core/derive")
            elif ledger is None or package.get("source") != ledger.get("source") or package.get("license") != ledger.get("license"):
                violations.append(f"{manifest}: resolved source/license differs for {identity}")
        if manifest in EXCEPTIONS:
            ledger = _load(root / EXCEPTIONS[manifest], json.loads)
            if resolved_contract(data) != ledger.get("resolved_contract"):
                violations.append(f"{manifest}: resolved feature/kind graph differs from reviewed inventory")
            lock = _load(root / Path(manifest).parent / "Cargo.lock", tomllib.loads)["package"]
            by_name = {p["name"]: p for p in lock}
            for node in data["resolve"]["nodes"]:
                package = by_id[node["id"]]
                # Inventories currently forbid duplicate names, so Cargo's lock
                # edge names are unambiguous in these pinned exception graphs.
                resolved = sorted(by_id[dep]["name"] for dep in node["dependencies"])
                if resolved != sorted(by_name[package["name"]].get("dependencies", [])):
                    violations.append(f"{manifest}: metadata resolved edges differ for {package['name']}")
        if violations:
            raise RuntimeError("\n".join(violations))
    return "passed"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", action="store_true")
    args = parser.parse_args()
    try:
        result = verify()
        if args.metadata:
            result["cargo_metadata"] = metadata()
        print(json.dumps(result, indent=2))
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
