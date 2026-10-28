#!/usr/bin/env python3
"""Regenerate src/html/entities.rs from CPython 3.12's standard HTML5 data."""
import hashlib
import html.entities
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXPECTED_COUNT = 2231
EXPECTED_SHA256 = "2153dd01901680634b4bc936dcb5f8a058c12bfc563fc7a87752c6b546c75f7b"
GO_OMISSIONS = {"nGt;", "nLt;"}


def rust_string(value):
    return '"' + "".join(f"\\u{{{ord(char):x}}}" for char in value) + '"'


def main():
    items = sorted(html.entities.html5.items())
    canonical = "".join(f"{key}\t{value}\n" for key, value in items).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    if len(items) != EXPECTED_COUNT or digest != EXPECTED_SHA256:
        raise SystemExit(
            "unexpected Python html.entities.html5 data; review the updated WHATWG table, "
            "then update EXPECTED_COUNT and EXPECTED_SHA256 deliberately"
        )
    rows = [
        f"    ({rust_string(key)}, {rust_string(value)}),"
        for key, value in items
        if key not in GO_OMISSIONS
    ]
    content = """// HTML named character reference data derived from CPython 3.12's
// `html.entities.html5`, which tracks the WHATWG HTML Living Standard named
// character reference table (https://html.spec.whatwg.org/multipage/named-characters.html).
// This file contains only the standard's factual name-to-codepoint data, not
// CPython or Go implementation code. CPython is distributed under PSF-2.0.
// Regenerate with `python3 tools/generate_html_entities.py`; expected upstream
// mapping SHA-256: 2153dd01901680634b4bc936dcb5f8a058c12bfc563fc7a87752c6b546c75f7b.
// Go 1.27 omits nGt; and nLt;, so those two names remain literal here to match
// its html.UnescapeString behavior.
static ENTITIES: &[(&str, &str)] = &[\n"""
    content += "\n".join(rows)
    content += "\n];\n\npub(super) fn lookup(name: &str) -> Option<&'static str> {\n"
    content += "    ENTITIES\n        .binary_search_by(|(key, _)| key.cmp(&name))\n"
    content += "        .ok()\n        .map(|index| ENTITIES[index].1)\n}\n"
    destination = ROOT / "src/html/entities.rs"
    destination.write_text(content, encoding="utf-8")
    print(f"wrote {len(rows)} Go-compatible named references to {destination.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
