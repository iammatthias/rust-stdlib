#!/usr/bin/env python3
"""Regenerates tests/fixtures/fmt_tests.rs from Go's fmt_test.go.

The `fmtTests` table of $(go env GOROOT)/src/fmt/fmt_test.go has arbitrary Go
values as operands, so it is evaluated by Go itself: this script copies the
test file into a scratch module (dropping the one `internal/race` use), adds a
test that walks `fmtTests` with reflection and prints each entry as Rust
source (Value constructors, the format and Go's expected output), and runs it.
Entries that cannot be expressed (reflect.Value operands, functions, channels
and unsafe pointers other than nil, heap addresses) are skipped and counted.

    python3 tools/gen_fmt_fixtures.py

The generated file is consumed by tests/fmt.rs, which implements the methods of
the table's named types (I, F, G, ...). Go is BSD-licensed; see NOTICE.
"""
import os
import pathlib
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "tests/fixtures/fmt_tests.rs"

DUMP = r'''
package fmt_test

import (
	"fmt"
	"math"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Stand-ins for fmt's export_test.go and scan_test.go globals the file uses.
var IsSpace func(rune) bool
var Parsenum func(string, int, int) (int, bool, int)

var skipped = map[string]int{}
var methodTypes = map[string]bool{}

func rbytes(s string) string {
	var b strings.Builder
	b.WriteString(`b"`)
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c >= 0x20 && c < 0x7f:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	b.WriteString(`"`)
	return b.String()
}

func rstr(s string) string { return strconv.Quote(s) }

// rb is a Rust byte slice literal for a Go string that may hold any bytes.
func rb(s string) string { return "&" + rbytes(s) + "[..]" }

type skip struct{ why string }

func enc(v reflect.Value) string {
	t := v.Type()
	var base string
	switch v.Kind() {
	case reflect.Bool:
		base = fmt.Sprintf("Value::Bool(%v)", v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		k := strings.ToUpper(t.Kind().String()[:1]) + t.Kind().String()[1:]
		base = fmt.Sprintf("Value::Int(%d, IntKind::%s)", v.Int(), k)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		k := strings.ToUpper(t.Kind().String()[:1]) + t.Kind().String()[1:]
		base = fmt.Sprintf("Value::Uint(%d, UintKind::%s)", v.Uint(), k)
	case reflect.Float32:
		base = fmt.Sprintf("Value::Float32(f32::from_bits(0x%x))", math.Float32bits(float32(v.Float())))
	case reflect.Float64:
		base = fmt.Sprintf("Value::Float64(f64::from_bits(0x%x))", math.Float64bits(v.Float()))
	case reflect.Complex64:
		c := v.Complex()
		base = fmt.Sprintf("Value::Complex64(f32::from_bits(0x%x), f32::from_bits(0x%x))", math.Float32bits(float32(real(c))), math.Float32bits(float32(imag(c))))
	case reflect.Complex128:
		c := v.Complex()
		base = fmt.Sprintf("Value::Complex128(f64::from_bits(0x%x), f64::from_bits(0x%x))", math.Float64bits(real(c)), math.Float64bits(imag(c)))
	case reflect.String:
		base = fmt.Sprintf("Value::String(%s.to_vec())", rbytes(v.String()))
	case reflect.Slice, reflect.Array:
		var items []string
		for i := 0; i < v.Len(); i++ {
			items = append(items, elem(v.Index(i)))
		}
		base = fmt.Sprintf("seq(%s, %s, %v, %v, %v, vec![%s])", rstr(t.String()), rstr(t.Elem().String()),
			t.Elem().Kind() == reflect.Uint8, v.Kind() == reflect.Array, v.Kind() == reflect.Slice && v.IsNil(), strings.Join(items, ", "))
	case reflect.Map:
		var items []string
		iter := v.MapRange()
		for iter.Next() {
			items = append(items, fmt.Sprintf("(%s, %s)", elem(iter.Key()), elem(iter.Value())))
		}
		sort.Strings(items)
		base = fmt.Sprintf("mapv(%s, %v, vec![%s])", rstr(t.String()), v.IsNil(), strings.Join(items, ", "))
	case reflect.Struct:
		var items []string
		for i := 0; i < v.NumField(); i++ {
			items = append(items, fmt.Sprintf("(%s, %s)", rstr(t.Field(i).Name), elem(v.Field(i))))
		}
		base = fmt.Sprintf("strukt(%s, vec![%s])", rstr(t.String()), strings.Join(items, ", "))
	case reflect.Pointer:
		if v.IsNil() {
			base = fmt.Sprintf("Value::nil_pointer(%s)", rstr(t.String()))
		} else {
			base = fmt.Sprintf("Value::pointer(%s, 0xc000010000, %s)", rstr(t.String()), elem(v.Elem()))
		}
	case reflect.Func, reflect.Chan, reflect.UnsafePointer:
		if !v.IsNil() {
			panic(skip{"non-nil " + v.Kind().String()})
		}
		base = fmt.Sprintf("Value::raw_pointer(%s, 0)", rstr(t.String()))
	default:
		panic(skip{"kind " + v.Kind().String()})
	}
	hasMethods := t.NumMethod() > 0
	if hasMethods {
		methodTypes[t.String()] = true
		return fmt.Sprintf("meth(%s, %s)", rstr(t.String()), base)
	}
	if t.PkgPath() != "" && t.Kind() != reflect.Struct && t.Kind() != reflect.Slice && t.Kind() != reflect.Array && t.Kind() != reflect.Map && t.Kind() != reflect.Pointer {
		return fmt.Sprintf("Value::named(%s, %s)", rstr(t.String()), base)
	}
	return base
}

// elem encodes a value found inside a composite (interface slots unwrap).
func elem(v reflect.Value) string {
	if v.Kind() == reflect.Interface {
		if v.IsNil() {
			return fmt.Sprintf("Value::NilIface(%s.into())", rstr(v.Type().String()))
		}
		return enc(v.Elem())
	}
	return enc(v)
}

func top(val any) (s string, why string) {
	defer func() {
		if r := recover(); r != nil {
			if sk, ok := r.(skip); ok {
				why = sk.why
				return
			}
			panic(r)
		}
	}()
	if val == nil {
		return "Value::Nil", ""
	}
	v := reflect.ValueOf(val)
	if v.Type().String() == "reflect.Value" {
		return "", "reflect.Value operand"
	}
	code := enc(v)
	if strings.Contains(code, "reflect.Value") || strings.Contains(code, "abi.Type") {
		return "", "reflect internals"
	}
	return code, ""
}

func derefOut(o any) any { return o }

// destKind names the scan destination type of a pointer operand.
func destKind(p any) string {
	switch p.(type) {
	case *Xs:
		return "Xs"
	case *IntString:
		return "IntString"
	}
	t := reflect.TypeOf(p).Elem()
	switch t.Kind() {
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return "bytes"
		}
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128, reflect.String:
		return t.Kind().String()
	}
	panic("dest " + t.String())
}

func TestDumpFixtures(t *testing.T) {
	var b strings.Builder
	b.WriteString("// @generated by tools/gen_fmt_fixtures.py from Go's fmt/fmt_test.go (fmtTests).\n")
	b.WriteString("// Go's BSD license applies to the table; see NOTICE.\n\n")
	b.WriteString("pub fn fmt_tests() -> Vec<(&'static [u8], Value, &'static [u8])> {\n    vec![\n")
	n := 0
	for _, tt := range fmtTests {
		if strings.Contains(tt.out, "PTR") {
			skipped["heap address in expected output"]++
			continue
		}
		code, why := top(tt.val)
		if why != "" {
			skipped[why]++
			continue
		}
		fmt.Fprintf(&b, "        (%s, %s, %s),\n", rb(tt.fmt), code, rb(tt.out))
		n++
	}
	b.WriteString("    ]\n}\n\n")
	b.WriteString("pub fn reorder_tests() -> Vec<(&'static [u8], Vec<Value>, &'static [u8])> {\n    vec![\n")
	for _, tt := range reorderTests {
		var items []string
		for _, a := range tt.val {
			c, why := top(a)
			if why != "" {
				panic(why)
			}
			items = append(items, c)
		}
		fmt.Fprintf(&b, "        (%s, vec![%s], %s),\n", rb(tt.fmt), strings.Join(items, ", "), rb(tt.out))
	}
	b.WriteString("    ]\n}\n\n")
	b.WriteString("pub fn star_tests() -> Vec<(&'static [u8], Vec<Value>, &'static [u8])> {\n    vec![\n")
	for _, tt := range startests {
		var items []string
		for _, a := range tt.in {
			c, why := top(a)
			if why != "" {
				panic(why)
			}
			items = append(items, c)
		}
		fmt.Fprintf(&b, "        (%s, vec![%s], %s),\n", rb(tt.fmt), strings.Join(items, ", "), rb(tt.out))
	}
	b.WriteString("    ]\n}\n")

	b.WriteString("\npub type ScanfRow = (&'static [u8], &'static [u8], &'static str, Option<Value>);\n")
	b.WriteString("pub type MultiRow = (&'static [u8], &'static [u8], Vec<&'static str>, Option<Vec<Value>>, &'static str);\n\n")
	// scanTests: (text, dest kind, expected)
	b.WriteString("pub fn scan_tests() -> Vec<(&'static [u8], &'static str, Value)> {\n    vec![\n")
	for _, tt := range scanTests {
		code, why := top(derefOut(tt.out))
		if why != "" {
			panic(why)
		}
		fmt.Fprintf(&b, "        (%s, %s, %s),\n", rb(tt.text), rstr(destKind(tt.in)), code)
	}
	b.WriteString("    ]\n}\n\n")
	// scanfTests: (format, text, dest kind, expected or None)
	b.WriteString("pub fn scanf_tests() -> Vec<ScanfRow> {\n    vec![\n")
	for _, tt := range scanfTests {
		exp := "None"
		if tt.out != nil {
			code, why := top(tt.out)
			if why != "" {
				panic(why)
			}
			exp = "Some(" + code + ")"
		}
		fmt.Fprintf(&b, "        (%s, %s, %s, %s),\n", rb(tt.format), rb(tt.text), rstr(destKind(tt.in)), exp)
	}
	b.WriteString("    ]\n}\n\n")
	b.WriteString("pub fn overflow_tests() -> Vec<(&'static [u8], &'static str)> {\n    vec![\n")
	for _, tt := range overflowTests {
		fmt.Fprintf(&b, "        (%s, %s),\n", rb(tt.text), rstr(destKind(tt.in)))
	}
	b.WriteString("    ]\n}\n\n")
	// multiTests: (format, text, dest kinds, expected values or None, error substring)
	b.WriteString("pub fn multi_tests() -> Vec<MultiRow> {\n    vec![\n")
	for _, tt := range multiTests {
		var kinds []string
		for _, in := range tt.in {
			kinds = append(kinds, rstr(destKind(in)))
		}
		out := "None"
		if tt.out != nil {
			var vs []string
			for _, o := range tt.out {
				code, why := top(o)
				if why != "" {
					panic(why)
				}
				vs = append(vs, code)
			}
			out = "Some(vec![" + strings.Join(vs, ", ") + "])"
		}
		fmt.Fprintf(&b, "        (%s, %s, vec![%s], %s, %s),\n", rb(tt.format), rb(tt.text), strings.Join(kinds, ", "), out, rstr(tt.err))
	}
	b.WriteString("    ]\n}\n\n")
	b.WriteString("pub fn eof_kinds() -> Vec<(&'static str, &'static str)> {\n    vec![\n")
	for _, tt := range eofTests {
		fmt.Fprintf(&b, "        (%s, %s),\n", rstr(tt.format), rstr(destKind(tt.v)))
	}
	b.WriteString("    ]\n}\n")
	os.WriteFile(os.Getenv("FMT_FIXTURE_OUT"), []byte(b.String()), 0o644)
	fmt.Fprintf(os.Stderr, "fmtTests: %d of %d entries written\n", n, len(fmtTests))
	for k, v := range skipped {
		fmt.Fprintf(os.Stderr, "  skipped %d: %s\n", v, k)
	}
	for k := range methodTypes {
		fmt.Fprintf(os.Stderr, "  method type: %s\n", k)
	}
}
'''


def main():
    goroot = subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()
    src = (pathlib.Path(goroot) / "src/fmt/fmt_test.go").read_text()
    # The tests themselves are not run; drop the one internal/race use.
    src = src.replace('\t"internal/race"\n', "").replace("case race.Enabled:", "case false:")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="fmtfix"))
    try:
        (tmp / "go.mod").write_text("module fmtfix\n\ngo 1.21\n")
        (tmp / "fmt_test.go").write_text(src)
        scan = (pathlib.Path(goroot) / "src/fmt/scan_test.go").read_text()
        (tmp / "scan_test.go").write_text(scan)
        (tmp / "dump_test.go").write_text(DUMP)
        env = dict(os.environ, GOTOOLCHAIN="local", GOPROXY="off", GOSUMDB="off", GOFLAGS="-mod=mod",
                   FMT_FIXTURE_OUT=str(tmp / "out.rs"))
        run = subprocess.run(["go", "test", "-v", "-count=1", "-run", "^TestDumpFixtures$", "."], cwd=tmp, env=env,
                             text=True, capture_output=True)
        print(run.stdout + run.stderr)
        if run.returncode:
            raise SystemExit("go test failed")
        OUT.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(tmp / "out.rs", OUT)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
