#!/usr/bin/env python3
"""Regression tests for the dependency policy; standard-library-only."""
import json
import shutil
import tomllib
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
from pathlib import Path
import unittest
from dependency_policy import ROOT, MANIFESTS, EXCEPTIONS, metadata, verify

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        for filename in ["Cargo.toml", "Cargo.lock", "src/lib.rs"]:
            shutil.copyfile(ROOT / filename, self.root / filename)
    def tearDown(self):
        self.temp.cleanup()
    def replace_manifest(self, old, new):
        p = self.root / "Cargo.toml"
        p.write_text(p.read_text().replace(old, new))
    def rejected(self):
        with self.assertRaises(RuntimeError):
            verify(self.root)
    def test_clean_baseline(self):
        self.assertEqual(verify(self.root)["declared_third_party_dependencies"], 0)
    def test_runtime_dependency(self):
        self.replace_manifest("[dependencies]", '[dependencies]\nexample = "1"')
        self.rejected()
    def test_dev_dependency(self):
        self.replace_manifest("[dev-dependencies]", '[dev-dependencies]\nexample = "1"')
        self.rejected()
    def test_build_dependency(self):
        self.replace_manifest("[build-dependencies]", '[build-dependencies]\nexample = "1"')
        self.rejected()
    def test_optional_dependency(self):
        self.replace_manifest("[dependencies]", '[dependencies]\nexample = { version = "1", optional = true }')
        self.rejected()
    def test_target_dependency(self):
        with (self.root / "Cargo.toml").open("a") as out:
            out.write('\n[target.\'cfg(windows)\'.dependencies]\nexample = "1"\n')
        self.rejected()
    def test_workspace_dependency(self):
        with (self.root / "Cargo.toml").open("a") as out:
            out.write('\n[workspace.dependencies]\nexample = "1"\n')
        self.rejected()
    def test_override(self):
        with (self.root / "Cargo.toml").open("a") as out:
            out.write('\n[patch.crates-io]\nexample = { path = "vendor/example" }\n')
        self.rejected()
    def test_build_script(self):
        (self.root / "build.rs").write_text("fn main() {}")
        self.rejected()
    def test_lockfile_dependency(self):
        with (self.root / "Cargo.lock").open("a") as out:
            out.write('\n[[package]]\nname = "example"\nversion = "1.0.0"\n')
        self.rejected()
    def test_missing_unsafe_lint(self):
        (self.root / "src/lib.rs").write_text("pub fn empty() {}")
        self.rejected()
    def test_unsafe_block(self):
        with (self.root / "src/lib.rs").open("a") as out:
            out.write("\nfn bad() { unsafe {} }\n")
        self.rejected()
    def test_placeholder(self):
        with (self.root / "src/lib.rs").open("a") as out:
            out.write("\nfn bad() { unimplemented!() }\n")
        self.rejected()

    def copy_optional(self, kind):
        base = {"tls": "backends/tls", "fuzz": "fuzz", "derive": "crates/derive", "crypto": "crates/crypto", "sys": "crates/sys", "sysnet": "backends/sysnet"}[kind]
        paths = [base + "/Cargo.toml"]
        if kind == "sys":
            paths += [base + "/Cargo.lock"]
        elif kind != "derive":
            paths += [base + "/Cargo.lock", f"docs/{kind}-dependencies.json"]
        if kind in {"tls", "derive", "crypto", "sys", "sysnet"}:
            paths += [base + "/src/lib.rs"]
        for relative in paths:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        return base

    def edit(self, relative, old, new):
        path = self.root / relative
        source = path.read_text()
        self.assertIn(old, source)
        path.write_text(source.replace(old, new, 1))

    def reject_matching(self, message):
        with self.assertRaisesRegex(RuntimeError, message):
            verify(self.root)

    def test_optional_exceptions_are_isolated(self):
        self.copy_optional("tls")
        self.copy_optional("fuzz")
        self.copy_optional("derive")
        report = verify(self.root)
        self.assertEqual(report["application_packages"], 1)
        self.assertEqual(report["exception_packages"], {"backends/tls/Cargo.toml": 25, "fuzz/Cargo.toml": 10})

    def test_sysnet_tls_feature_graph_is_reviewed(self):
        self.copy_optional("sysnet")
        report = verify(self.root)
        self.assertEqual(report["exception_packages"], {"backends/sysnet/Cargo.toml": 25})
        self.assertEqual(report["manifests"], 2)

    def test_sysnet_rejects_third_party_dependency(self):
        self.copy_optional("sysnet")
        self.edit("backends/sysnet/Cargo.toml", "[dependencies]", '[dependencies]\nexample = "1"')
        self.reject_matching("direct dependency contract changed")

    def test_sysnet_tls_must_stay_optional(self):
        self.copy_optional("sysnet")
        self.edit("backends/sysnet/Cargo.toml", ', optional = true', "")
        self.reject_matching("direct dependency contract changed")

    def test_sysnet_rejects_changed_feature_contract(self):
        self.copy_optional("sysnet")
        self.edit("backends/sysnet/Cargo.toml", 'default = ["tls"]', "default = []")
        self.reject_matching("feature contract changed")

    def test_sysnet_rejects_changed_lock_graph(self):
        self.copy_optional("sysnet")
        with (self.root / "backends/sysnet/Cargo.lock").open("a") as stream:
            stream.write('\n[[package]]\nname = "example"\nversion = "1.0.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
        self.reject_matching("lock package set differs from reviewed inventory")

    def test_sysnet_requires_forbid_unsafe(self):
        self.copy_optional("sysnet")
        self.edit("backends/sysnet/src/lib.rs", "#![forbid(unsafe_code)]", "")
        self.reject_matching("crate must forbid unsafe code")

    def test_sysnet_rejects_unsafe_code(self):
        self.copy_optional("sysnet")
        with (self.root / "backends/sysnet/src/lib.rs").open("a") as stream:
            stream.write("\nfn bad() { unsafe {} }\n")
        self.reject_matching("disallowed source pattern")

    def test_crypto_exception_is_isolated(self):
        self.copy_optional("crypto")
        report = verify(self.root)
        self.assertEqual(report["application_packages"], 1)
        self.assertEqual(report["exception_packages"], {"crates/crypto/Cargo.toml": 93})

    def test_root_cannot_import_crypto_path(self):
        self.copy_optional("crypto")
        self.replace_manifest("[dependencies]", '[dependencies]\nrust-stdlib-crypto = { path = "crates/crypto" }')
        self.reject_matching("direct dependency contract changed")

    def test_crypto_direct_dependencies_are_pinned(self):
        for old, new in [('sha2 = { version = "=0.11.0"', 'sha2 = { version = "0.11.0"'),
                         ('hmac = { version = "=0.13.0", default-features = false', 'hmac = { version = "=0.13.0"'),
                         ('features = ["hmac"]', 'features = ["hmac", "std"]'),
                         ('aes = { version = "=0.9.2"', 'aes = { version = "0.9.2"'),
                         ('cbc = { version = "=0.2.1", default-features = false', 'cbc = { version = "=0.2.1"'),
                         ('features = ["aes"]', 'features = ["aes", "alloc"]'),
                         ('des = { version = "=0.9.0"', 'des = { version = "=0.9.1"'),
                         ("[dependencies]", '[dependencies]\nrust-stdlib = { path = "../.." }'),
                         ("[dependencies]", '[dependencies]\nring = "=0.17.14"')]:
            with self.subTest(old=old):
                self.copy_optional("crypto")
                self.edit("crates/crypto/Cargo.toml", old, new)
                self.reject_matching("direct dependency contract changed")

    def test_crypto_dependencies_must_stay_optional(self):
        self.copy_optional("crypto")
        self.edit("crates/crypto/Cargo.toml", 'features = ["oid"], optional = true }', 'features = ["oid"] }')
        self.reject_matching("direct dependency contract changed")

    def test_crypto_rejects_changed_feature_contract(self):
        for old, new in [('default = ["full"]', "default = []"),
                         ('sha256 = ["dep:digest", "dep:sha2"]', 'sha256 = ["dep:digest", "dep:sha2", "sha2/asm"]'),
                         ('rand = ["dep:sha2", ', 'rand = ["sha256", "dep:sha2", '),
                         ('ecdsa = ["ecdh", "elliptic", "sha3", "sha512", "subtle"]', 'ecdsa = ["elliptic", "sha512", "subtle"]'),
                         ("[features]", '[features]\nextra = ["dep:des"]')]:
            with self.subTest(old=old):
                self.copy_optional("crypto")
                self.edit("crates/crypto/Cargo.toml", old, new)
                self.reject_matching("feature contract changed")

    def test_crypto_lock_and_ledger_are_pinned(self):
        self.copy_optional("crypto")
        lock = self.root / "crates/crypto/Cargo.lock"
        original = lock.read_text()
        checksum = next(p for p in tomllib.loads(original)["package"] if p.get("checksum"))["checksum"]
        for old, new, message in [(checksum, "0" * 64, "lock source/checksum/resolved edges differ"),
                                  ('name = "sha2"\nversion = "0.11.0"', 'name = "sha2"\nversion = "0.11.1"', "lock package set differs"),
                                  ("registry+https://github.com/rust-lang/crates.io-index", "registry+https://malicious.example/index", "lock source/checksum/resolved edges differ")]:
            with self.subTest(message=message):
                lock.write_text(original)
                self.edit("crates/crypto/Cargo.lock", old, new)
                self.reject_matching(message)
        lock.write_text(original + '\n[[package]]\nname="surprise"\nversion="1.0.0"\n')
        self.reject_matching("lock package set differs")

    def test_crypto_ledger_cannot_approve_extra_first_party_package(self):
        self.copy_optional("crypto")
        path = self.root / "docs/crypto-dependencies.json"
        data = json.loads(path.read_text())
        data["packages"].append({"name": "rogue", "version": "1.0.0", "source": None, "checksum": None, "lock_dependencies": []})
        path.write_text(json.dumps(data))
        self.reject_matching("unapproved first-party/path")

    def test_crypto_must_forbid_unsafe(self):
        self.copy_optional("crypto")
        (self.root / "crates/crypto/src/lib.rs").write_text("pub fn empty() {}")
        self.reject_matching("crate must forbid unsafe")
        (self.root / "crates/crypto/src/lib.rs").write_text("#![forbid(unsafe_code)]\nfn bad() { unsafe {} }\n")
        self.reject_matching("disallowed source pattern")

    def write_sys_ffi(self, name, text):
        path = self.root / "crates/sys/src/ffi" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def test_sys_crate_is_isolated_and_dependency_free(self):
        self.copy_optional("sys")
        self.write_sys_ffi("proc.rs", 'extern "C" { fn getpid() -> i32; }\nfn pid() -> i32 {\n    // SAFETY: no arguments.\n    unsafe { getpid() }\n}\n')
        self.assertEqual(verify(self.root)["application_packages"], 1)

    def test_sys_may_not_have_dependencies(self):
        self.copy_optional("sys")
        self.edit("crates/sys/Cargo.toml", "[dependencies]", '[dependencies]\nlibc = "=0.2.170"')
        self.reject_matching("direct dependency contract changed")

    def test_sys_may_not_import_the_root(self):
        self.copy_optional("sys")
        self.edit("crates/sys/Cargo.toml", "[dependencies]", '[dependencies]\nrust-stdlib = { path = "../.." }')
        self.reject_matching("direct dependency contract changed")

    def test_root_cannot_import_sys_path(self):
        self.copy_optional("sys")
        self.replace_manifest("[dependencies]", '[dependencies]\nrust-stdlib-sys = { path = "crates/sys" }')
        self.reject_matching("direct dependency contract changed")

    def test_sys_must_deny_unsafe_at_manifest_and_root(self):
        self.copy_optional("sys")
        self.edit("crates/sys/Cargo.toml", 'unsafe_code = "deny"', 'unsafe_code = "allow"')
        self.reject_matching("must deny unsafe at compiler level")
        self.copy_optional("sys")
        (self.root / "crates/sys/src/lib.rs").write_text("#[allow(unsafe_code)]\nmod ffi;\n")
        self.reject_matching("crate must deny unsafe code at the root")

    def test_sys_unsafe_needs_safety_comment(self):
        self.copy_optional("sys")
        self.write_sys_ffi("proc.rs", 'extern "C" { fn getpid() -> i32; }\nfn pid() -> i32 {\n    unsafe { getpid() }\n}\n')
        self.reject_matching("without a // SAFETY: comment")

    def test_sys_unsafe_only_in_ffi_directory(self):
        self.copy_optional("sys")
        (self.root / "crates/sys/src/os.rs").write_text("fn bad() {\n    // SAFETY: none.\n    unsafe {}\n}\n")
        self.reject_matching("disallowed source pattern")

    def test_sys_allow_unsafe_only_on_ffi_module(self):
        self.copy_optional("sys")
        self.write_sys_ffi("proc.rs", "#![allow(unsafe_code)]\n")
        self.reject_matching("allow\\(unsafe_code\\) is only approved")
        self.copy_optional("sys")
        (self.root / "crates/sys/src/lib.rs").write_text("#![deny(unsafe_code)]\n#[allow(unsafe_code)]\nmod ffi;\n#[allow(unsafe_code)]\nmod os;\n")
        self.reject_matching("only approved on `mod ffi;`")

    def test_other_manifests_may_not_use_deny(self):
        self.replace_manifest('unsafe_code = "forbid"', 'unsafe_code = "deny"')
        self.rejected()

    def test_unexpected_zero_dependency_manifest(self):
        path = self.root / "rogue/Cargo.toml"
        path.parent.mkdir()
        path.write_text('[package]\nname="rogue"\nversion="0.1.0"\n')
        self.reject_matching("unexpected Cargo manifest")

    def test_unexpected_lockfile(self):
        path = self.root / "rogue/Cargo.lock"
        path.parent.mkdir()
        path.write_text('version=4\n')
        self.reject_matching("unexpected Cargo lockfile")

    def test_approved_path_cannot_change_identity(self):
        self.copy_optional("derive")
        self.edit("crates/derive/Cargo.toml", 'name = "rust-stdlib-derive"', 'name = "trojan"')
        self.reject_matching("package identity changed")

    def test_root_cannot_import_tls_path(self):
        self.copy_optional("tls")
        self.replace_manifest("[dependencies]", '[dependencies]\nrust-stdlib-tls = { path = "backends/tls" }')
        self.reject_matching("direct dependency contract changed")

    def test_root_cannot_add_workspace_members(self):
        with (self.root / "Cargo.toml").open("a") as stream:
            stream.write('\n[workspace]\nmembers=["backends/tls"]\n')
        self.reject_matching("unapproved workspace")

    def test_tls_crypto_features_are_pinned(self):
        self.copy_optional("tls")
        self.edit("backends/tls/Cargo.toml", '["std", "ring", "tls12"]', '["std", "ring", "aws_lc_rs", "tls12"]')
        self.reject_matching("direct dependency contract changed")

    def test_tls_cannot_enable_default_features(self):
        self.copy_optional("tls")
        self.edit("backends/tls/Cargo.toml", "default-features = false", "default-features = true")
        self.reject_matching("direct dependency contract changed")

    def test_tls_cannot_switch_first_party_path(self):
        self.copy_optional("tls")
        self.edit("backends/tls/Cargo.toml", 'path = "../.."', 'path = "../../rogue"')
        self.reject_matching("direct dependency contract changed")

    def test_fuzz_workspace_cannot_expand(self):
        self.copy_optional("fuzz")
        self.edit("fuzz/Cargo.toml", 'members = ["."]', 'members = [".", "../backends/tls"]')
        self.reject_matching("unapproved workspace")

    def test_exception_transitive_version_changes(self):
        for kind in ("tls", "fuzz"):
            with self.subTest(kind=kind):
                base = self.copy_optional(kind)
                self.edit(base + "/Cargo.lock", 'version = "1.8.0"', 'version = "1.8.1"')
                self.reject_matching("lock package set differs")
                shutil.copyfile(ROOT / base / "Cargo.lock", self.root / base / "Cargo.lock")

    def test_exception_transitive_checksums_are_pinned(self):
        for kind in ("tls", "fuzz"):
            with self.subTest(kind=kind):
                base = self.copy_optional(kind)
                source = (self.root / base / "Cargo.lock").read_text()
                checksum = tomllib.loads(source)["package"][0]["checksum"]
                self.edit(base + "/Cargo.lock", checksum, "0" * 64)
                self.reject_matching("lock source/checksum/resolved edges differ")
                shutil.copyfile(ROOT / base / "Cargo.lock", self.root / base / "Cargo.lock")

    def test_exception_registry_source_is_pinned(self):
        for kind in ("tls", "fuzz"):
            with self.subTest(kind=kind):
                base = self.copy_optional(kind)
                self.edit(base + "/Cargo.lock", 'registry+https://github.com/rust-lang/crates.io-index', 'registry+https://malicious.example/index')
                self.reject_matching("lock source/checksum/resolved edges differ")
                shutil.copyfile(ROOT / base / "Cargo.lock", self.root / base / "Cargo.lock")

    def test_exception_resolved_edges_are_pinned(self):
        for kind in ("tls", "fuzz"):
            with self.subTest(kind=kind):
                base = self.copy_optional(kind)
                self.edit(base + "/Cargo.lock", ' "find-msvc-tools",', ' "find-msvc-tools",\n "rust-stdlib",')
                self.reject_matching("lock source/checksum/resolved edges differ")
                shutil.copyfile(ROOT / base / "Cargo.lock", self.root / base / "Cargo.lock")

    def test_exception_unreviewed_transitive_package(self):
        self.copy_optional("tls")
        with (self.root / "backends/tls/Cargo.lock").open("a") as stream:
            stream.write('\n[[package]]\nname="surprise"\nversion="1.0.0"\n')
        self.reject_matching("lock package set differs")

    def test_missing_exception_inventory_is_diagnostic(self):
        self.copy_optional("fuzz")
        (self.root / "docs/fuzz-dependencies.json").unlink()
        self.reject_matching("cannot read policy input")

    def test_duplicate_inventory_entry_rejected(self):
        self.copy_optional("tls")
        path = self.root / "docs/tls-dependencies.json"
        data = json.loads(path.read_text())
        data["packages"].append(data["packages"][0])
        path.write_text(json.dumps(data))
        self.reject_matching("duplicate package identity")

    def test_exception_inventory_cannot_approve_arbitrary_path_package(self):
        self.copy_optional("tls")
        path = self.root / "docs/tls-dependencies.json"
        data = json.loads(path.read_text())
        data["packages"].append({"name": "rogue", "version": "1.0.0", "source": None, "checksum": None, "lock_dependencies": []})
        path.write_text(json.dumps(data))
        self.reject_matching("unapproved first-party/path")

    def test_derive_test_contract(self):
        self.copy_optional("derive")
        for relative in ("tools/derive-check/Cargo.toml", "tools/derive-check/Cargo.lock"):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        verify(self.root)
        self.edit("tools/derive-check/Cargo.toml", "default-features = false", "default-features = true")
        self.reject_matching("direct dependency contract changed")

    def test_derive_test_lock_intrusion(self):
        self.copy_optional("derive")
        for relative in ("tools/derive-check/Cargo.toml", "tools/derive-check/Cargo.lock"):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.edit("tools/derive-check/Cargo.lock", 'name = "rust-stdlib-derive"', 'name = "third-party"')
        self.reject_matching("first-party lock graph changed")

    def test_unsafe_and_ffi_scans_cover_optional_and_test_sources(self):
        for relative, source in [("crates/derive/src/nested/evil.rs", "unsafe fn invoke() {}"), ("backends/tls/tests/evil.rs", 'extern "C" { fn invoke(); }'), ("examples/evil.rs", "unsafe impl Send for Evil {}"), ("fuzz/fuzz_targets/evil.rs", "fn invoke(){ unsafe {} }")]:
            with self.subTest(relative=relative):
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
                self.reject_matching("disallowed source pattern")
                path.unlink()

    def test_build_scripts_in_optional_paths_rejected(self):
        self.copy_optional("tls")
        (self.root / "backends/tls/build.rs").write_text("fn main() {}")
        self.reject_matching("auto-discovered build script")

    def test_source_target_outside_package_rejected(self):
        self.copy_optional("derive")
        self.edit("crates/derive/Cargo.toml", "[lib]", '[lib]\npath="../../../external.rs"')
        self.reject_matching("target source escapes")

    def test_cargo_config_cannot_weaken_compiler_lints(self):
        path = self.root / ".cargo/config.toml"
        path.parent.mkdir()
        path.write_text('[build]\nrustflags=["--cap-lints=allow"]\n')
        self.reject_matching("unreviewed Cargo configuration")

    def test_optional_package_directory_symlink_rejected(self):
        self.copy_optional("tls")
        original = self.root / "backends/tls"
        moved = self.root / "relocated-tls"
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
        self.reject_matching("manifest symlinks are not approved")


    def test_compiler_unsafe_lint_cannot_be_weakened(self):
        self.replace_manifest('unsafe_code = "forbid"', 'unsafe_code = "allow"')
        self.reject_matching("compiler level")

    def test_optional_fuzz_targets_inherit_forbidden_unsafe(self):
        self.copy_optional("fuzz")
        self.edit("fuzz/Cargo.toml", 'unsafe_code = "forbid"', 'unsafe_code = "allow"')
        self.reject_matching("compiler level")


    def mock_metadata(self, mutation=None):
        def run(command, **kwargs):
            manifest = command[command.index("--manifest-path") + 1]
            if manifest in EXCEPTIONS:
                ledger = json.loads((self.root / EXCEPTIONS[manifest]).read_text())
                packages = []
                for entry in ledger["packages"]:
                    name = entry["name"]
                    local = next((m for m, spec in MANIFESTS.items() if spec[0] == name), None)
                    packages.append({"id": f"{name}@{entry['version']}", "name": name, "version": entry["version"], "source": entry["source"], "license": entry["license"], "manifest_path": str(self.root / local) if local else "/registry/Cargo.toml", "dependencies": []})
                contract = ledger["resolved_contract"]
                nodes = [{"id": node["package"], "features": node["features"], "dependencies": node["dependencies"], "deps": [{"name": edge["name"], "pkg": edge["package"], "dep_kinds": edge["dep_kinds"]} for edge in node["deps"]]} for node in contract["nodes"]]
                data = {"packages": packages, "resolve": {"root": contract["root"], "nodes": nodes}}
            else:
                own = manifest if manifest in MANIFESTS and manifest.startswith("crates/sys") else "Cargo.toml"
                version = tomllib.loads((self.root / own).read_text())["package"]["version"]
                data = {"packages": [{"id": "root", "name": MANIFESTS[own][0], "version": version, "source": None, "manifest_path": str(self.root / own), "dependencies": []}], "resolve": {"root": "root", "nodes": []}}
            if mutation:
                mutation(manifest, data)
            return SimpleNamespace(returncode=0, stdout=json.dumps(data), stderr="")
        return patch("dependency_policy.subprocess.run", side_effect=run)

    def test_metadata_clean_optional_graphs(self):
        self.copy_optional("tls")
        self.copy_optional("fuzz")
        self.copy_optional("crypto")
        with self.mock_metadata():
            self.assertEqual(metadata(self.root), "passed")

    def test_metadata_sys_clean_and_rejects_dependencies(self):
        self.copy_optional("sys")
        with self.mock_metadata():
            self.assertEqual(metadata(self.root), "passed")
        def mutate(manifest, data):
            if manifest == "crates/sys/Cargo.toml":
                data["packages"][0]["dependencies"].append({"name": "libc"})
        with self.mock_metadata(mutate), self.assertRaisesRegex(RuntimeError, "intrusion into core/derive"):
            metadata(self.root)

    def test_metadata_rejects_unreviewed_crypto_crate_features(self):
        self.copy_optional("crypto")
        def mutate(manifest, data):
            if manifest == "crates/crypto/Cargo.toml":
                next(n for n in data["resolve"]["nodes"] if n["id"].startswith("sha2@"))["features"].append("asm")
        with self.mock_metadata(mutate), self.assertRaisesRegex(RuntimeError, "feature/kind graph differs"):
            metadata(self.root)

    def test_metadata_rejects_crypto_license_changes(self):
        self.copy_optional("crypto")
        def mutate(manifest, data):
            if manifest == "crates/crypto/Cargo.toml":
                next(p for p in data["packages"] if p["name"] == "subtle")["license"] = "proprietary"
        with self.mock_metadata(mutate), self.assertRaisesRegex(RuntimeError, "source/license differs"):
            metadata(self.root)

    def test_metadata_rejects_unreviewed_crypto_features(self):
        self.copy_optional("tls")
        def mutate(manifest, data):
            if manifest == "backends/tls/Cargo.toml":
                next(n for n in data["resolve"]["nodes"] if n["id"].startswith("rustls@"))["features"].append("aws_lc_rs")
        with self.mock_metadata(mutate), self.assertRaisesRegex(RuntimeError, "feature/kind graph differs"):
            metadata(self.root)

    def test_metadata_rejects_license_changes(self):
        self.copy_optional("tls")
        def mutate(manifest, data):
            if manifest == "backends/tls/Cargo.toml":
                next(p for p in data["packages"] if p["name"] == "ring")["license"] = "proprietary"
        with self.mock_metadata(mutate), self.assertRaisesRegex(RuntimeError, "source/license differs"):
            metadata(self.root)

    def test_metadata_rejects_path_substitution(self):
        self.copy_optional("tls")
        def mutate(manifest, data):
            if manifest == "backends/tls/Cargo.toml":
                next(p for p in data["packages"] if p["name"] == "rust-stdlib")["manifest_path"] = str(self.root / "rogue/Cargo.toml")
        with self.mock_metadata(mutate), self.assertRaisesRegex(RuntimeError, "unapproved path package"):
            metadata(self.root)

    def test_metadata_root_intrusion_even_with_clean_lock(self):
        def mutate(manifest, data):
            data["packages"][0]["dependencies"].append({"name": "surprise"})
        with self.mock_metadata(mutate), self.assertRaisesRegex(RuntimeError, "intrusion into core/derive"):
            metadata(self.root)


class LedgerTests(unittest.TestCase):
    def lock(self, name, version, source=None):
        return {"name": name, "version": version, "source": source}

    def test_two_versions_keep_their_own_keys(self):
        from dependency_ledger import merge_packages
        reviewed = [
            {"name": "getrandom", "version": "0.2.16", "license": "MIT", "note": "old"},
            {"name": "getrandom", "version": "0.4.1", "license": "MIT", "note": "new"},
        ]
        lock = [self.lock("getrandom", "0.4.1"), self.lock("getrandom", "0.2.16")]
        merged = merge_packages(reviewed, lock, {})
        self.assertEqual([(p["version"], p["note"]) for p in merged], [("0.2.16", "old"), ("0.4.1", "new")])

    def test_new_second_version_starts_unreviewed(self):
        from dependency_ledger import merge_packages
        reviewed = [{"name": "getrandom", "version": "0.2.16", "license": "MIT", "note": "old"}]
        lock = [self.lock("getrandom", "0.2.16"), self.lock("getrandom", "0.4.1")]
        merged = merge_packages(reviewed, lock, {})
        self.assertEqual([(p["version"], p.get("note"), p["license"]) for p in merged],
                         [("0.2.16", "old", "MIT"), ("0.4.1", None, None)])

    def test_single_version_bump_keeps_keys(self):
        from dependency_ledger import merge_packages
        reviewed = [{"name": "rustls", "version": "0.23.45", "license": "MIT", "note": "kept"}]
        lock = [self.lock("rustls", "0.23.46", "registry+https://github.com/rust-lang/crates.io-index")]
        merged = merge_packages(reviewed, lock, {("rustls", "0.23.46"): "Apache-2.0"})
        self.assertEqual((merged[0]["version"], merged[0]["note"], merged[0]["license"]), ("0.23.46", "kept", "Apache-2.0"))

    def test_path_package_bump_keeps_its_license(self):
        from dependency_ledger import merge_packages
        reviewed = [{"name": "rust-stdlib", "version": "0.1.0", "license": "BSD-3-Clause"}]
        merged = merge_packages(reviewed, [self.lock("rust-stdlib", "0.2.0")], {})
        self.assertEqual((merged[0]["version"], merged[0]["license"]), ("0.2.0", "BSD-3-Clause"))

if __name__ == "__main__":
    unittest.main()
