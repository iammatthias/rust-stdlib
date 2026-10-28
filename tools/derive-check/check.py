#!/usr/bin/env python3
"""Execute real derive expansions and unsupported-syntax compiler diagnostics."""
import json
import pathlib
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
subprocess.run(["cargo", "test", "--offline", "--locked", "--manifest-path", str(ROOT / "tools/derive-check/Cargo.toml")], check=True)
subprocess.run(["cargo", "run", "--offline", "--locked", "--manifest-path", str(ROOT / "tools/derive-check/Cargo.toml")], check=True)
CASES = [
    ("Serialize", "enum Discriminant { One = 1, Two = 2 }", "explicit enum discriminants"),
    ("Serialize", "union Unsupported { value: u64 }", "structs and enums only"),
    ("Serialize", "#[repr(C)] struct Repr { value: u64 }", "unsupported derive attribute"),
    ("Deserialize", "struct Borrowed<'a> { value: &'a str }", "borrowed field deserialization is unsupported"),
    ("Deserialize", "struct NestedBorrowed<'a> { value: Vec<&'a str> }", "borrowed field deserialization is unsupported"),
    ("Marshal", "enum Choice { A, B }", "XML derives support structs with named fields only"),
    ("Unmarshal", "struct Pair(String, String);", "XML derives support structs with named fields only"),
    ("Marshal", "struct Generic<T> { value: T }", "XML derives do not support generic structs"),
    ("Marshal", 'struct TwoTags { #[xml("a", "b")] value: String }', "duplicate xml tag string"),
    ("Unmarshal", "struct BadArgument { #[xml(nope)] value: String }", "expected #[xml("),
    ("Marshal", '#[xml("x")] struct OnContainer { value: String }', "attributes belong on fields"),
    ("Marshal", "struct BadAttr { #[serde(skip)] value: String }", "unsupported derive attribute"),
    ("Serialize", "struct Keyword { #[json(bogus)] value: u8 }", "unsupported json attribute keyword"),
    ("Serialize", "struct Rename { #[json(rename = 5)] value: u8 }", "expected a string literal"),
    ("Serialize", "struct Bare { #[json] value: u8 }", "malformed json attribute"),
    ("Serialize", "struct Syntax { #[json(rename = 'a' 1)] value: u8 }", "unsupported json attribute syntax"),
    ("Serialize", "struct Foreign { #[serde(skip)] value: u8 }", "unsupported derive attribute"),
    ("Serialize", "struct Tuple(#[json(skip)] u8);", "unsupported derive attribute"),
    ("Deserialize", "enum Variant { #[json(skip)] One }", "unsupported derive attribute"),
    ("Serialize", "#[json(skip)] struct Container { value: u8 }", "unsupported derive attribute"),
    ("Reflect", "struct Borrowed<'a> { value: &'a str }", "does not support lifetime parameters"),
    ("Reflect", "enum Data { One(u8), Two }", "unit-only enums"),
    ("Reflect", "enum Explicit { One = 1 }", "unit-only enums"),
    ("Reflect", "union Unsupported { value: u64 }", "structs and unit-only enums"),
    ("Reflect", "struct Bare { #[reflect] value: u8 }", "malformed reflect attribute"),
    ("Reflect", "struct Bad { #[reflect(bogus)] value: u8 }", "unsupported reflect attribute keyword"),
    ("Reflect", 'struct Twice { #[reflect("a", "b")] value: u8 }', "duplicate reflect tag string"),
    ("Reflect", 'struct Key { #[reflect(color = "a")] value: u8 }', "unsupported reflect attribute key"),
]

with tempfile.TemporaryDirectory(prefix="rust-stdlib-derive-diagnostics-") as tmp:
    project = pathlib.Path(tmp)
    (project / "src").mkdir()
    manifest = '\n'.join([
        '[package]', 'name = "derive-diagnostic-consumer"', 'version = "0.0.0"', 'edition = "2021"',
        '[dependencies]',
        'rust-stdlib = { path = ' + json.dumps(str(ROOT)) + ', default-features = false }',
        'rust-stdlib-derive = { path = ' + json.dumps(str(ROOT / "crates/derive")) + ' }',
    ])
    (project / "Cargo.toml").write_text(manifest)
    for macro, definition, expected in CASES:
        source = f'use rust_stdlib_derive::{macro};\n#[derive({macro})]\n' + definition + '\n'
        (project / "src/lib.rs").write_text(source)
        result = subprocess.run(["cargo", "check", "--offline", "--manifest-path", str(project / "Cargo.toml")], text=True, capture_output=True)
        if result.returncode == 0 or expected not in result.stderr:
            raise RuntimeError(f"wrong diagnostic for {definition}:\n{result.stdout}\n{result.stderr}")
        if 'proc macro panicked' in result.stderr:
            raise RuntimeError(result.stderr)
        print(f"PASS compiler diagnostic: {expected}")
    EMBED_CASES = [
        ('pub fn f() { let _ = rust_stdlib_derive::embed!("missing-dir"); }', "no matching files found"),
        ('pub fn f() { let _ = rust_stdlib_derive::embed!("../escape"); }', "invalid embed pattern"),
        ('pub fn f() { let _ = rust_stdlib_derive::embed!(42); }', "string literals"),
    ]
    for source, expected in EMBED_CASES:
        (project / "src/lib.rs").write_text(source + "\n")
        result = subprocess.run(["cargo", "check", "--offline", "--manifest-path", str(project / "Cargo.toml")], text=True, capture_output=True)
        if result.returncode == 0 or expected not in result.stderr or 'proc macro panicked' in result.stderr:
            raise RuntimeError(f"wrong embed diagnostic for {source}:\n{result.stdout}\n{result.stderr}")
        print(f"PASS embed diagnostic: {expected}")
print(f"PASS {len(CASES) + len(EMBED_CASES)} unsupported syntax diagnostics")
