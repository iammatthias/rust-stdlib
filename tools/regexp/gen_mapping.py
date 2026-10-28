#!/usr/bin/env python3
"""Regenerate docs/api/regexp.json and docs/api/regexp_syntax.json.

The Go-to-Rust naming is mechanical (CamelCase to snake_case methods and
SCREAMING_CASE associated constants); the exceptions are listed explicitly.
Review the output; run tools/api_parity.py afterwards.
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2]
SURFACE = json.loads((ROOT / "docs/api/go-surface.json").read_text())["packages"]


def snake(n):
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", n).lower()


def screaming(n):
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", n).upper()


R = "rust_stdlib::regexp::"
RS = R + "syntax::"
TOSTR = {"rust": "std::string::ToString::to_string"}
FUNCS = {"Compile": "compile", "CompilePOSIX": "compile_posix", "Match": "match_bytes",
         "MatchReader": "match_reader", "MatchString": "match_string", "MustCompile": "must_compile",
         "MustCompilePOSIX": "must_compile_posix", "QuoteMeta": "quote_meta"}
FLAGS = {"FoldCase", "Literal", "ClassNL", "DotNL", "OneLine", "NonGreedy", "PerlX", "UnicodeGroups",
         "WasDollar", "Simple", "MatchNL", "Perl", "POSIX"}


def regexp_map():
    out = {}
    for s in SURFACE["regexp"]:
        n = s["name"]
        if n == "Regexp":
            out[n] = {"rust": R + "Regexp"}
        elif n.startswith("Regexp."):
            meth = n[7:]
            if meth == "String":
                out[n] = dict(TOSTR)
            elif meth == "Copy":
                out[n] = {"rust": "std::clone::Clone::clone",
                          "note": "Regexp is Clone; clones share the program and the machine pool"}
            elif meth == "Match":
                out[n] = {"rust": R + "Regexp::match_bytes"}
            else:
                out[n] = {"rust": R + "Regexp::" + snake(meth)}
        else:
            out[n] = {"rust": R + FUNCS[n]}
    return out


def syntax_map():
    out = {}
    for s in SURFACE["regexp/syntax"]:
        n, k = s["name"], s["kind"]
        if n in FLAGS:
            out[n] = {"rust": RS + "Flags::" + screaming(n)}
        elif n.startswith("Empty") and n not in ("EmptyOp", "EmptyOpContext"):
            out[n] = {"rust": RS + "EmptyOp::" + screaming(n[5:])}
        elif n.startswith("InstOp") or n == "InstOp":
            out[n] = {"rust": RS + "InstOp"} if "." not in n else dict(TOSTR)
        elif n.startswith("Inst") and k == "const":
            out[n] = {"rust": RS + "InstOp::" + screaming(n[4:])}
        elif n.startswith("Op") and k == "const":
            out[n] = {"rust": RS + "Op::" + screaming(n[2:])}
        elif n.startswith("Err") and k == "const":
            out[n] = {"rust": RS + "ErrorCode::" + screaming(n[3:])}
        elif n in ("Compile", "Parse"):
            out[n] = {"rust": RS + n.lower()}
        elif n == "EmptyOpContext":
            out[n] = {"rust": RS + "empty_op_context"}
        elif n == "IsWordChar":
            out[n] = {"rust": RS + "is_word_char"}
        elif "." in n:
            typ, mem = n.split(".")
            if mem in ("String", "Error"):
                out[n] = dict(TOSTR)
            elif mem in ("Sub0", "Rune0"):
                out[n] = {"deviation": "storage-arrays",
                          "note": "Go's small-storage arrays for Sub and Rune; a Rust Vec owns its storage so nothing aliases"}
            else:
                out[n] = {"rust": RS + typ + "::" + snake(mem)}
        else:
            out[n] = {"rust": RS + n}
    return out


def main():
    regexp_notes = ("regexp: Go 1.27 semantics (leftmost-first; leftmost-longest for POSIX and Longest), linear "
                    "time, on Go's three matchers chosen as Go's find does: one-pass, the bit-state backtracker, "
                    "and the Pike VM. nil slices become Option or an empty Vec, unmatched groups are None (-1 in "
                    "submatch index vectors), single matches are (start, end) tuples, readers take "
                    "RuneReader/Utf8RuneReader over io::Read. patterns are &str, so invalid-UTF-8 patterns cannot "
                    "be passed. Additions without a Go symbol: find_index_at and find_submatch_index_at expose "
                    "the search from an offset that Go runs internally (FindAll), and find_anchored_index_at and "
                    "find_anchored_submatch_index_at accept only a match beginning at the offset.")
    syntax_notes = ("regexp/syntax: port of parse, simplify, compile and the prog dumps, checked against Go on "
                    "thousands of patterns. Flags, Op, InstOp, EmptyOp and ErrorCode are newtypes with associated "
                    "constants. Sub holds Arc<Regexp>; parse takes &str and parse_bytes takes bytes (the only "
                    "way to reach ErrInvalidUTF8); Error.Expr is lossy UTF-8. Go's limits (maxHeight 1000, "
                    "maxSize, maxRunes) are kept.")
    for name, notes, symbols in (("regexp", regexp_notes, regexp_map()),
                                 ("regexp_syntax", syntax_notes, syntax_map())):
        package = name.replace("_", "/")
        (ROOT / f"docs/api/{name}.json").write_text(
            json.dumps({"package": package, "notes": notes, "symbols": symbols}, indent=2) + "\n")


if __name__ == "__main__":
    main()
