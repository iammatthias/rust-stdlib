// Generates tests/fixtures/big_golden.rs from the local Go toolchain's
// math/big tests. Nothing is hand-typed: every slice literal of the test files
// below (package-level tables and tables inline in test functions) is parsed
// with go/parser, and each row is flattened to string tokens in struct field
// order (keyed fields are resolved against the struct type). Constants are
// evaluated with go/constant: strings unquoted, integers in decimal, floats as
// the shortest float64 text, NewInt(x)/conversions as their argument,
// math.Inf(±1) as "+Inf"/"-Inf", math.Copysign(0, -1) as "-0", nested
// literals as "[a,b,...]". Anything else becomes "?" plus its source text, so
// tests can skip rows they cannot interpret.
//
// Tables are named after their variable (sumZZ -> SUM_ZZ) or, when inline,
// after the enclosing function and ordinal (TestFloatSign -> TEST_FLOAT_SIGN_0).
//
// Usage, from the repository root:
//
//	go run tools/big_vectors.go
//	rustfmt --edition 2021 tests/fixtures/big_golden.rs
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/printer"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var files = []string{"int_test.go", "intconv_test.go", "intmarsh_test.go", "rat_test.go",
	"ratconv_test.go", "ratmarsh_test.go", "float_test.go", "floatconv_test.go",
	"floatmarsh_test.go", "prime_test.go", "sqrt_test.go"}

var fset = token.NewFileSet()

var consts = map[string]constant.Value{
	"math.MaxInt64":  constant.MakeInt64(math.MaxInt64),
	"math.MinInt64":  constant.MakeInt64(math.MinInt64),
	"math.MaxInt32":  constant.MakeInt64(math.MaxInt32),
	"math.MinInt32":  constant.MakeInt64(math.MinInt32),
	"math.MaxUint64": constant.MakeUint64(math.MaxUint64),
	"math.MaxUint32": constant.MakeUint64(math.MaxUint32),
	"MaxExp":         constant.MakeInt64(math.MaxInt32),
	"MinExp":         constant.MakeInt64(math.MinInt32),
	"MaxPrec":        constant.MakeUint64(math.MaxUint32),
	"_W":             constant.MakeInt64(64),
	"math.MaxFloat64": constant.MakeFloat64(math.MaxFloat64),
	"math.SmallestNonzeroFloat64": constant.MakeFloat64(math.SmallestNonzeroFloat64),
	"math.MaxFloat32":             constant.MakeFloat64(math.MaxFloat32),
	"math.SmallestNonzeroFloat32": constant.MakeFloat64(math.SmallestNonzeroFloat32),
}

func src(e ast.Node) string {
	var b bytes.Buffer
	printer.Fprint(&b, fset, e)
	return b.String()
}

func eval(e ast.Expr) (constant.Value, bool) {
	switch e := e.(type) {
	case *ast.BasicLit:
		v := constant.MakeFromLiteral(e.Value, e.Kind, 0)
		return v, v.Kind() != constant.Unknown
	case *ast.ParenExpr:
		return eval(e.X)
	case *ast.UnaryExpr:
		x, ok := eval(e.X)
		if !ok {
			return nil, false
		}
		return constant.UnaryOp(e.Op, x, 0), true
	case *ast.BinaryExpr:
		x, ok1 := eval(e.X)
		y, ok2 := eval(e.Y)
		if !ok1 || !ok2 {
			return nil, false
		}
		if e.Op == token.SHL || e.Op == token.SHR {
			s, ok := constant.Uint64Val(y)
			if !ok {
				return nil, false
			}
			return constant.Shift(x, e.Op, uint(s)), true
		}
		if e.Op == token.QUO && x.Kind() == constant.Int && y.Kind() == constant.Int {
			return constant.BinaryOp(x, token.QUO_ASSIGN, y), true
		}
		return constant.BinaryOp(x, e.Op, y), true
	case *ast.Ident:
		v, ok := consts[e.Name]
		return v, ok
	case *ast.SelectorExpr:
		v, ok := consts[src(e)]
		return v, ok
	case *ast.CallExpr:
		if len(e.Args) == 1 {
			if id, ok := e.Fun.(*ast.Ident); ok {
				switch id.Name {
				case "int", "int32", "int64", "uint", "uint32", "uint64", "float64", "float32", "Word", "byte":
					return eval(e.Args[0])
				}
			}
		}
	}
	return nil, false
}

func valueText(v constant.Value) string {
	switch v.Kind() {
	case constant.String:
		return constant.StringVal(v)
	case constant.Bool:
		return strconv.FormatBool(constant.BoolVal(v))
	case constant.Int:
		return v.ExactString()
	case constant.Float:
		if i := constant.ToInt(v); i.Kind() == constant.Int {
			return i.ExactString()
		}
		f, _ := constant.Float64Val(v)
		return strconv.FormatFloat(f, 'g', -1, 64)
	}
	return "?" + v.String()
}

func tok(e ast.Expr) string {
	if v, ok := eval(e); ok {
		if lit, isLit := e.(*ast.BasicLit); isLit && lit.Kind == token.CHAR {
			r, _ := constant.Int64Val(v)
			return string(rune(r))
		}
		return valueText(v)
	}
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.CompositeLit:
		parts := []string{}
		for _, el := range e.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				el = kv.Value
			}
			parts = append(parts, tok(el))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return tok(e.X)
		}
	case *ast.CallExpr:
		name := src(e.Fun)
		switch {
		case name == "NewInt" && len(e.Args) == 1:
			return tok(e.Args[0])
		case name == "math.Inf" && len(e.Args) == 1:
			if v, ok := eval(e.Args[0]); ok && constant.Sign(v) < 0 {
				return "-Inf"
			}
			return "+Inf"
		case name == "math.NaN":
			return "NaN"
		case name == "math.Copysign" && len(e.Args) == 2:
			x, ok1 := eval(e.Args[0])
			y, ok2 := eval(e.Args[1])
			if ok1 && ok2 && constant.Sign(x) == 0 && constant.Sign(y) < 0 {
				return "-0"
			}
		}
	}
	return "?" + src(e)
}

// field is a struct field name and whether its type is an interface (any),
// whose tokens carry a kind prefix: "s:" (string), "f32:" (float32
// conversion) or "f64:" (other constants).
type field struct {
	name  string
	isAny bool
}

// structFields returns the fields, in order, of a struct type expression.
func structFields(t ast.Expr, types map[string]*ast.StructType) []field {
	var st *ast.StructType
	switch t := t.(type) {
	case *ast.StructType:
		st = t
	case *ast.Ident:
		st = types[t.Name]
	}
	if st == nil {
		return nil
	}
	var fields []field
	for _, f := range st.Fields.List {
		typ := src(f.Type)
		isAny := typ == "any" || typ == "interface{}"
		if len(f.Names) == 0 {
			fields = append(fields, field{typ, isAny})
		}
		for _, n := range f.Names {
			fields = append(fields, field{n.Name, isAny})
		}
	}
	return fields
}

func anyTok(e ast.Expr) string {
	if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		return "s:" + tok(e)
	}
	if call, ok := e.(*ast.CallExpr); ok && src(call.Fun) == "float32" {
		return "f32:" + tok(e)
	}
	return "f64:" + tok(e)
}

func fieldTok(e ast.Expr, f field) string {
	if f.isAny {
		return anyTok(e)
	}
	return tok(e)
}

func row(el ast.Expr, fields []field) []string {
	cl, ok := el.(*ast.CompositeLit)
	if !ok || cl.Type != nil || fields == nil {
		return []string{tok(el)}
	}
	keyed := len(cl.Elts) > 0
	for _, e := range cl.Elts {
		if _, ok := e.(*ast.KeyValueExpr); !ok {
			keyed = false
		}
	}
	if !keyed {
		out := make([]string, 0, len(cl.Elts))
		for i, e := range cl.Elts {
			f := field{}
			if i < len(fields) {
				f = fields[i]
			}
			out = append(out, fieldTok(e, f))
		}
		return out
	}
	out := make([]string, len(fields))
	for _, e := range cl.Elts {
		kv := e.(*ast.KeyValueExpr)
		key := src(kv.Key)
		for i, f := range fields {
			if f.name == key {
				out[i] = fieldTok(kv.Value, f)
			}
		}
	}
	return out
}

type table struct {
	name string
	rows [][]string
}

func upperSnake(s string) string {
	var b strings.Builder
	rs := []rune(s)
	for i, r := range rs {
		if i > 0 && unicode.IsUpper(r) && rs[i-1] != '_' {
			prevLower := unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1])
			acronymEnd := unicode.IsUpper(rs[i-1]) && i+1 < len(rs) && unicode.IsLower(rs[i+1])
			if prevLower || acronymEnd {
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToUpper(r))
	}
	return b.String()
}

func rustString(s string) (string, bool) {
	if !utf8.ValidString(s) {
		return "", false
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\r':
			b.WriteString(`\r`)
		case r >= 0x20 && r < 0x7f:
			b.WriteRune(r)
		default:
			fmt.Fprintf(&b, `\u{%x}`, r)
		}
	}
	b.WriteByte('"')
	return b.String(), true
}

func main() {
	dir := filepath.Join(runtime.GOROOT(), "src", "math", "big")
	var parsed []*ast.File
	types := map[string]*ast.StructType{}
	for _, name := range files {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			panic(err)
		}
		parsed = append(parsed, f)
		ast.Inspect(f, func(n ast.Node) bool {
			// Package-level and function-local constants (const max = 100,
			// below1e23 = ...) become evaluable names.
			if gd, ok := n.(*ast.GenDecl); ok && gd.Tok == token.CONST {
				for _, spec := range gd.Specs {
					vs := spec.(*ast.ValueSpec)
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							if v, ok := eval(vs.Values[i]); ok {
								consts[name.Name] = v
							}
						}
					}
				}
			}
			if ts, ok := n.(*ast.TypeSpec); ok {
				if st, ok := ts.Type.(*ast.StructType); ok {
					types[ts.Name.Name] = st
				}
			}
			return true
		})
	}
	var tables []table
	seen := map[string]bool{}
	add := func(name string, cl *ast.CompositeLit) {
		at, ok := cl.Type.(*ast.ArrayType)
		if !ok || len(cl.Elts) == 0 {
			return
		}
		fields := structFields(at.Elt, types)
		t := table{name: name}
		for _, el := range cl.Elts {
			t.rows = append(t.rows, row(el, fields))
		}
		if seen[t.name] {
			panic("duplicate table " + t.name)
		}
		seen[t.name] = true
		tables = append(tables, t)
	}
	for _, f := range parsed {
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, v := range vs.Values {
						if cl, ok := v.(*ast.CompositeLit); ok {
							add(upperSnake(vs.Names[i].Name), cl)
						}
					}
				}
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				n := 0
				ast.Inspect(d.Body, func(node ast.Node) bool {
					cl, ok := node.(*ast.CompositeLit)
					if !ok {
						return true
					}
					if _, ok := cl.Type.(*ast.ArrayType); !ok {
						return true
					}
					if len(cl.Elts) == 0 {
						return false
					}
					add(fmt.Sprintf("%s_%d", upperSnake(d.Name.Name), n), cl)
					n++
					return false
				})
			}
		}
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].name < tables[j].name })
	var out bytes.Buffer
	out.WriteString("// Generated by tools/big_vectors.go from Go's math/big *_test.go tables. Do not edit.\n\n")
	rows, unknown, skipped := 0, 0, 0
	for _, t := range tables {
		fmt.Fprintf(&out, "pub const %s: &[&[&str]] = &[\n", t.name)
		for _, r := range t.rows {
			parts := make([]string, 0, len(r))
			ok := true
			for _, s := range r {
				q, valid := rustString(s)
				if !valid {
					ok = false
					break
				}
				if strings.HasPrefix(s, "?") {
					unknown++
				}
				parts = append(parts, q)
			}
			if !ok {
				skipped++
				continue
			}
			rows++
			fmt.Fprintf(&out, "&[%s],\n", strings.Join(parts, ", "))
		}
		out.WriteString("];\n\n")
	}
	path := filepath.Join("tests", "fixtures", "big_golden.rs")
	if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %s: %d tables, %d rows, %d uninterpreted tokens, %d rows skipped (invalid UTF-8)\n",
		path, len(tables), rows, unknown, skipped)
}
