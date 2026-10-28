#!/usr/bin/env python3
"""Regenerate tests/fixtures/regexp_tables.rs from Go's regexp test tables.

The tables live in unexported variables of Go's own *_test.go files, so this
copies the relevant files of the local Go toolchain into a scratch module,
adds a test that prints the tables as Rust source and runs it. Re-run after a
Go upgrade. The checked-in output is BSD-licensed Go test data (see NOTICE).
"""
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "tests/fixtures/regexp_tables.rs"

HELPERS = r'''
import (
	"fmt"
	"os"
	"strings"
	"unicode/utf8"
)

func rs(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, `\u{%x}`, r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func rb(s string) string {
	var b strings.Builder
	b.WriteString(`b"`)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func strList(w *strings.Builder, name string, list []string) {
	fmt.Fprintf(w, "pub const %s: &[&[u8]] = &[\n", name)
	for _, s := range list {
		if len(s) > 300 {
			continue // repeated-pattern cases are built in the test
		}
		fmt.Fprintf(w, "    %s,\n", rb(s))
	}
	w.WriteString("];\n\n")
}

func pairList(w *strings.Builder, name string, n int, f func(i int) (string, string)) {
	fmt.Fprintf(w, "pub const %s: &[(&str, &str)] = &[\n", name)
	for i := 0; i < n; i++ {
		a, b := f(i)
		if !utf8.ValidString(a) || !utf8.ValidString(b) {
			continue
		}
		fmt.Fprintf(w, "    (%s, %s),\n", rs(a), rs(b))
	}
	w.WriteString("];\n\n")
}

func write(w *strings.Builder, file string) {
	if err := os.WriteFile(file, []byte(w.String()), 0o644); err != nil {
		panic(err)
	}
}
'''

SYNTAX_GEN = r'''package syntax

import "testing"
''' + HELPERS + r'''
func TestGen(t *testing.T) {
	var w strings.Builder
	w.WriteString("// Parse, simplify and compile tables of Go's regexp/syntax tests.\n\n")
	pt := func(name string, tests []parseTest) {
		pairList(&w, name, len(tests), func(i int) (string, string) { return tests[i].Regexp, tests[i].Dump })
	}
	pt("PARSE_TESTS", parseTests)
	pt("FOLDCASE_TESTS", foldcaseTests)
	pt("LITERAL_TESTS", literalTests)
	pt("MATCHNL_TESTS", matchnlTests)
	pt("NOMATCHNL_TESTS", nomatchnlTests)
	strList(&w, "INVALID_REGEXPS", invalidRegexps)
	strList(&w, "ONLY_PERL", onlyPerl)
	strList(&w, "ONLY_POSIX", onlyPOSIX)
	pairList(&w, "STRING_TESTS", len(stringTests), func(i int) (string, string) { return stringTests[i].re, stringTests[i].out })
	pairList(&w, "COMPILE_TESTS", len(compileTests), func(i int) (string, string) { return compileTests[i].Regexp, compileTests[i].Prog })
	pairList(&w, "SIMPLIFY_TESTS", len(simplifyTests), func(i int) (string, string) { return simplifyTests[i].Regexp, simplifyTests[i].Simple })
	write(&w, os.Getenv("GEN_OUT"))
}
'''

REGEXP_GEN = r'''package regexp

import "testing"
''' + HELPERS + r'''
func TestGen(t *testing.T) {
	var w strings.Builder
	w.WriteString("// Tables of Go's regexp tests (all_test.go, find_test.go).\n\n")
	strList(&w, "GOOD_RE", goodRe)
	fmt.Fprintf(&w, "pub const BAD_RE: &[(&str, &str)] = &[\n")
	for _, b := range badRe {
		if len(b.re) > 200 {
			continue // the 27000-fold \pL case is built in the test
		}
		fmt.Fprintf(&w, "    (%s, %s),\n", rs(b.re), rs(b.err))
	}
	w.WriteString("];\n\n")
	// (pattern, text, max, matches as flat [lo, hi, lo, hi, ...] rows)
	w.WriteString("pub type FindTest = (&'static str, &'static [u8], isize, &'static [&'static [isize]]);\n")
	w.WriteString("pub const FIND_TESTS: &[FindTest] = &[\n")
	for _, ft := range findTests {
		if !utf8.ValidString(ft.pat) {
			continue
		}
		fmt.Fprintf(&w, "    (%s, %s, %d, &[", rs(ft.pat), rb(ft.text), ft.max)
		for _, m := range ft.matches {
			w.WriteString("&[")
			for _, v := range m {
				fmt.Fprintf(&w, "%d,", v)
			}
			w.WriteString("],")
		}
		w.WriteString("]),\n")
	}
	w.WriteString("];\n\n")
	// (pattern, replacement, input, output)
	for _, set := range []struct {
		name  string
		tests []ReplaceTest
	}{{"REPLACE_TESTS", replaceTests}, {"REPLACE_LITERAL_TESTS", replaceLiteralTests}} {
		fmt.Fprintf(&w, "pub const %s: &[(&str, &str, &str, &str)] = &[\n", set.name)
		for _, r := range set.tests {
			fmt.Fprintf(&w, "    (%s, %s, %s, %s),\n", rs(r.pattern), rs(r.replacement), rs(r.input), rs(r.output))
		}
		w.WriteString("];\n\n")
	}
	// (pattern, quoted, literal prefix, is literal)
	for _, set := range []struct {
		name  string
		tests []MetaTest
	}{{"META_TESTS", metaTests}, {"LITERAL_PREFIX_TESTS", literalPrefixTests}} {
		fmt.Fprintf(&w, "pub const %s: &[(&str, &str, &str, bool)] = &[\n", set.name)
		for _, m := range set.tests {
			fmt.Fprintf(&w, "    (%s, %s, %s, %v),\n", rs(m.pattern), rs(m.output), rs(m.literal), m.isLiteral)
		}
		w.WriteString("];\n\n")
	}
	// (pattern, subexp count, names (empty if unchecked), (name, index) lookups)
	w.WriteString("pub type SubexpCase = (&'static str, usize, &'static [&'static str], &'static [(&'static str, isize)]);\n")
	w.WriteString("pub const SUBEXP_CASES: &[SubexpCase] = &[\n")
	for _, c := range subexpCases {
		fmt.Fprintf(&w, "    (%s, %d, &[", rs(c.input), c.num)
		for _, n := range c.names {
			fmt.Fprintf(&w, "%s,", rs(n))
		}
		w.WriteString("], &[")
		for _, ix := range c.indices {
			fmt.Fprintf(&w, "(%s, %d),", rs(ix.name), ix.index)
		}
		w.WriteString("]),\n")
	}
	w.WriteString("];\n\n")
	// (input, pattern, n, pieces)
	w.WriteString("pub type SplitTest = (&'static str, &'static str, isize, &'static [&'static str]);\n")
	w.WriteString("pub const SPLIT_TESTS: &[SplitTest] = &[\n")
	for _, s := range splitTests {
		fmt.Fprintf(&w, "    (%s, %s, %d, &[", rs(s.s), rs(s.r), s.n)
		for _, o := range s.out {
			fmt.Fprintf(&w, "%s,", rs(o))
		}
		w.WriteString("]),\n")
	}
	w.WriteString("];\n")
	write(&w, os.Getenv("GEN_OUT"))
}
'''


def goroot():
    return pathlib.Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip())


def run_gen(tmp, name, files, source, out):
    pkg = tmp / name
    pkg.mkdir()
    for f in files:
        shutil.copy(f, pkg / f.name)
    (pkg / "go.mod").write_text("module gen\ngo 1.27\n")
    (pkg / "gen_test.go").write_text(source)
    exec_test = pkg / "exec_test.go"
    if exec_test.exists():
        text = exec_test.read_text()
        text = text.replace('"internal/testenv"', "")
        text = re.sub(r'strings\.HasSuffix\(testenv\.Builder\(\), "-race"\)', "false", text)
        exec_test.write_text(text)
    env = dict(os.environ, GEN_OUT=str(out), GOTOOLCHAIN="local", GOFLAGS="-mod=mod")
    result = subprocess.run(["go", "test", "-run", "TestGen", "-count=1", "."], cwd=pkg, env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)


def main():
    src = goroot() / "src/regexp"
    with tempfile.TemporaryDirectory(prefix="rust-stdlib-regexp-gen-") as t:
        tmp = pathlib.Path(t)
        syntax_out, regexp_out = tmp / "syntax.rs", tmp / "regexp.rs"
        run_gen(tmp, "syntax", [src / "syntax" / n for n in
                ("compile.go", "doc.go", "op_string.go", "parse.go", "perl_groups.go", "prog.go", "regexp.go", "simplify.go",
                 "parse_test.go", "prog_test.go", "simplify_test.go")], SYNTAX_GEN, syntax_out)
        run_gen(tmp, "regexp", [src / n for n in
                ("regexp.go", "exec.go", "backtrack.go", "onepass.go", "all_test.go", "find_test.go", "exec_test.go")],
                REGEXP_GEN, regexp_out)
        text = ("//! Generated by tools/regexp/gen_fixtures.py from the Go regexp tests; do not edit.\n"
                "//! Go's test data is BSD-licensed (see NOTICE).\n\n"
                "pub mod syntax {\n" + "".join("    " + l if l.strip() else l for l in syntax_out.read_text().splitlines(True)) + "}\n\n"
                "pub mod regexp {\n" + "".join("    " + l if l.strip() else l for l in regexp_out.read_text().splitlines(True)) + "}\n")
        OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(text.splitlines())} lines")


if __name__ == "__main__":
    sys.exit(main())
