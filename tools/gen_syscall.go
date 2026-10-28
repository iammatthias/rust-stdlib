// Generate crates/sys/src/syscall/{consts,types,zsyscall}.rs, the expected-value
// table crates/sys/tests/syscall_expected/mod.rs, the Go oracle and docs/api/syscall.json
// from Go's syscall package for linux/amd64.
//
// Usage (from the repository root):
//
//	go run tools/gen_syscall.go            # write the generated files
//	go run tools/gen_syscall.go -check     # fail if a generated file is stale
//	go run tools/gen_syscall.go -oracle-go DIR -oracle-txt FILE
//	                                       # write the Go oracle program and its expected output
//
// The package is parsed with go/parser and type-checked with go/types for
// GOOS=linux GOARCH=amd64 (types.SizesFor("gc", "amd64")), so constant values,
// struct layouts and the zsyscall wrapper shapes come from Go's own sources and
// not from a hand-typed copy. Function bodies are only parsed; the wrappers in
// zsyscall_linux_amd64.go follow the single pattern mksyscall.pl emits and the
// generator rejects anything else.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

const rustPrefix = "rust_stdlib_sys::syscall::"

var (
	fset  = token.NewFileSet()
	pkg   *types.Package
	files []*ast.File
	sizes = types.SizesFor("gc", "amd64")
	root  string
)

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gen_syscall: "+format+"\n", args...)
	os.Exit(1)
}

// ---- naming ---------------------------------------------------------------

var rustKeywords = map[string]bool{
	"as": true, "break": true, "const": true, "continue": true, "crate": true, "else": true,
	"enum": true, "extern": true, "false": true, "fn": true, "for": true, "if": true, "impl": true,
	"in": true, "let": true, "loop": true, "match": true, "mod": true, "move": true, "mut": true,
	"pub": true, "ref": true, "return": true, "self": true, "Self": true, "static": true,
	"struct": true, "super": true, "trait": true, "true": true, "type": true, "unsafe": true,
	"use": true, "where": true, "while": true, "async": true, "await": true, "dyn": true,
	"abstract": true, "become": true, "box": true, "do": true, "final": true, "macro": true,
	"override": true, "priv": true, "typeof": true, "unsized": true, "virtual": true, "yield": true,
	"try": true,
}

var acronyms = strings.NewReplacer("ICMPv6", "Icmpv6", "IPv6", "Ipv6", "IPv4", "Ipv4")

// snake turns a Go identifier into a Rust snake_case identifier.
func snake(s string) string {
	s = acronyms.Replace(s)
	rs := []rune(s)
	var b strings.Builder
	for i, c := range rs {
		if unicode.IsUpper(c) && i > 0 {
			prev := rs[i-1]
			switch {
			case unicode.IsLower(prev) || unicode.IsDigit(prev):
				b.WriteByte('_')
			case unicode.IsUpper(prev) && i+1 < len(rs) && unicode.IsLower(rs[i+1]):
				b.WriteByte('_')
			}
		}
		b.WriteRune(unicode.ToLower(c))
	}
	return b.String()
}

func ident(s string) string {
	if rustKeywords[s] {
		return s + "_"
	}
	return s
}

func fieldName(s string) string {
	if strings.Contains(s, "_") {
		return ident(strings.ToLower(s))
	}
	return ident(snake(s))
}

func constName(s string) string {
	if s == strings.ToUpper(s) {
		return s
	}
	if strings.Contains(s, "_") {
		return strings.ToUpper(s)
	}
	return strings.ToUpper(snake(s))
}

func funcName(s string) string { return ident(snake(s)) }

// ---- loading --------------------------------------------------------------

func load() {
	build.Default.GOOS, build.Default.GOARCH, build.Default.CgoEnabled = "linux", "amd64", false
	dir := filepath.Join(runtime.GOROOT(), "src", "syscall")
	bp, err := build.Default.ImportDir(dir, 0)
	if err != nil {
		fatalf("%v", err)
	}
	for _, name := range bp.GoFiles {
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.ParseComments)
		if err != nil {
			fatalf("%v", err)
		}
		files = append(files, f)
	}
	conf := types.Config{
		Importer:         importer.ForCompiler(fset, "source", nil),
		Sizes:            sizes,
		IgnoreFuncBodies: true,
		Error:            func(err error) {}, // unresolved imports in skipped bodies are harmless
	}
	pkg, _ = conf.Check("syscall", fset, files, nil)
	if pkg == nil {
		fatalf("type-checking syscall failed")
	}
}

func fileOf(obj types.Object) string {
	return filepath.Base(fset.Position(obj.Pos()).Filename)
}

// ---- Rust types -----------------------------------------------------------

func basicRust(b *types.Basic) string {
	switch b.Kind() {
	case types.Int:
		return "isize"
	case types.Uint, types.Uintptr:
		return "usize"
	case types.Int8:
		return "i8"
	case types.Int16:
		return "i16"
	case types.Int32:
		return "i32"
	case types.Int64:
		return "i64"
	case types.Uint8:
		return "u8"
	case types.Uint16:
		return "u16"
	case types.Uint32:
		return "u32"
	case types.Uint64:
		return "u64"
	case types.Float32:
		return "f32"
	case types.Float64:
		return "f64"
	case types.Bool, types.UntypedBool:
		return "bool"
	case types.String, types.UntypedString:
		return "&str"
	case types.UnsafePointer:
		return "usize"
	}
	fatalf("unsupported basic type %v", b)
	return ""
}

// rustType renders a ztypes field type.
func rustType(t types.Type) string {
	switch t := t.(type) {
	case *types.Basic:
		return basicRust(t)
	case *types.Named:
		name := t.Obj().Name()
		if strings.HasPrefix(name, "_") {
			return rustType(t.Underlying())
		}
		return name
	case *types.Pointer:
		return "*mut " + rustType(t.Elem())
	case *types.Array:
		return fmt.Sprintf("[%s; %d]", rustType(t.Elem()), t.Len())
	}
	fatalf("unsupported type %v", t)
	return ""
}

func zeroExpr(t types.Type) string {
	switch u := t.Underlying().(type) {
	case *types.Basic:
		switch u.Kind() {
		case types.Float32, types.Float64:
			return "0.0"
		case types.Bool:
			return "false"
		}
		return "0"
	case *types.Pointer:
		return "std::ptr::null_mut()"
	case *types.Array:
		return fmt.Sprintf("[%s; %d]", zeroExpr(u.Elem()), u.Len())
	case *types.Struct:
		return rustType(t) + "::default()"
	}
	fatalf("no zero for %v", t)
	return ""
}

// ---- output buffers -------------------------------------------------------

var outputs = map[string]*bytes.Buffer{}

func out(path string) *bytes.Buffer {
	if outputs[path] == nil {
		outputs[path] = &bytes.Buffer{}
	}
	return outputs[path]
}

// ---- expected tables (shared by the Rust test and the Go oracle) ----------

type constEntry struct {
	Go, Rust, Value, Kind string // Kind: int, errno, signal, bool
}
type fieldEntry struct {
	Go, Rust string
	Offset   int64
}
type structEntry struct {
	Name        string
	Size, Align int64
	// RustSize differs from Size only for a struct ending in a zero-length
	// array: gc pads such a struct by a byte (InotifyEvent is 20 bytes) but C,
	// and so #[repr(C)], does not.
	RustSize int64
	Fields   []fieldEntry
}

var (
	constTable  []constEntry
	structTable []structEntry
	errorsTable = map[int]string{}
	signalTable = map[int]string{}
	symbolPath  = map[string]string{} // Go symbol -> Rust path (without the crate prefix)

	exportedFuncs []string
)

// ---- constants ------------------------------------------------------------

func genConsts() {
	b := out("crates/sys/src/syscall/consts.rs")
	b.WriteString("//! Generated by tools/gen_syscall.go from Go's zerrors, zsysnum and ztypes for\n")
	b.WriteString("//! linux/amd64. Do not edit.\n")
	b.WriteString("#![allow(non_upper_case_globals, dead_code)]\n")
	b.WriteString("use super::errno::{Errno, Signal};\n\n")
	seen := map[string]string{}
	for _, name := range pkg.Scope().Names() {
		c, ok := pkg.Scope().Lookup(name).(*types.Const)
		if !ok {
			continue
		}
		if !c.Exported() {
			continue
		}
		rn := constName(name)
		if prev, dup := seen[rn]; dup {
			fatalf("constants %s and %s both map to %s", prev, name, rn)
		}
		seen[rn] = name
		symbolPath[name] = rn
		doc := fmt.Sprintf("`syscall.%s`.", name)
		val := c.Val()
		typeName := ""
		if n, ok := c.Type().(*types.Named); ok {
			typeName = n.Obj().Name()
		}
		switch {
		case typeName == "Errno" || typeName == "Signal":
			v, _ := constant.Int64Val(constant.ToInt(val))
			fmt.Fprintf(b, "/// %s\npub const %s: %s = %s(%d);\n", doc, rn, typeName, typeName, v)
			constTable = append(constTable, constEntry{name, rn, strconv.FormatInt(v, 10), strings.ToLower(typeName)})
		case val.Kind() == constant.Bool:
			fmt.Fprintf(b, "/// %s\npub const %s: bool = %v;\n", doc, rn, constant.BoolVal(val))
			constTable = append(constTable, constEntry{name, rn, fmt.Sprint(constant.BoolVal(val)), "bool"})
		case val.Kind() == constant.Int:
			iv := constant.ToInt(val)
			ty := ""
			var lit string
			if bt, ok := c.Type().Underlying().(*types.Basic); ok && bt.Info()&types.IsUntyped == 0 {
				ty = basicRust(bt)
			}
			if i, exact := constant.Int64Val(iv); exact {
				lit = strconv.FormatInt(i, 10)
				if ty == "" {
					ty = "isize"
					if strings.HasPrefix(name, "SYS_") {
						ty = "usize"
					}
				}
			} else if u, exact := constant.Uint64Val(iv); exact {
				lit = strconv.FormatUint(u, 10)
				if ty == "" {
					ty = "usize"
				}
			} else {
				fatalf("constant %s does not fit 64 bits", name)
			}
			fmt.Fprintf(b, "/// %s\npub const %s: %s = %s;\n", doc, rn, ty, lit)
			constTable = append(constTable, constEntry{name, rn, lit, "int"})
		default:
			fatalf("unsupported constant %s (%v)", name, val)
		}
	}
	// zsysnum constants whose names are unexported but used by zsyscall.
	for _, name := range pkg.Scope().Names() {
		if c, ok := pkg.Scope().Lookup(name).(*types.Const); ok && !c.Exported() && strings.HasPrefix(name, "_SYS_") {
			v, _ := constant.Int64Val(constant.ToInt(c.Val()))
			fmt.Fprintf(b, "pub(crate) const %s: usize = %d;\n", strings.ToUpper(name), v)
		}
	}
}

// ---- types ----------------------------------------------------------------

func genTypes() {
	b := out("crates/sys/src/syscall/types.rs")
	b.WriteString("//! Generated by tools/gen_syscall.go from Go's ztypes_linux_amd64.go. Do not edit.\n")
	b.WriteString("//!\n//! Every struct is `#[repr(C)]` and has Go's linux/amd64 size, alignment and field\n")
	b.WriteString("//! offsets; crates/sys/tests/syscall_expected/mod.rs checks them against go/types.\n")
	b.WriteString("#![allow(non_camel_case_types, non_snake_case, dead_code, clippy::derivable_impls)]\n\n")
	for _, name := range pkg.Scope().Names() {
		tn, ok := pkg.Scope().Lookup(name).(*types.TypeName)
		if !ok || !strings.HasPrefix(fileOf(tn), "ztypes_") {
			continue
		}
		named := tn.Type().(*types.Named)
		exported := tn.Exported()
		rn := name
		switch u := named.Underlying().(type) {
		case *types.Basic:
			if exported {
				fmt.Fprintf(b, "/// `syscall.%s`.\npub type %s = %s;\n\n", name, name, basicRust(u))
				symbolPath[name] = name
			} else if name == "_Socklen" {
				fmt.Fprintf(b, "/// Go's unexported `_Socklen`.\npub type Socklen = u32;\n\n")
			}
		case *types.Struct:
			if !exported {
				continue // pollFd
			}
			symbolPath[name] = rn
			doc := fmt.Sprintf("`syscall.%s`.", name)
			fmt.Fprintf(b, "/// %s\n#[repr(C)]\n#[derive(Clone, Copy, Debug, PartialEq)]\npub struct %s {\n", doc, rn)
			ent := structEntry{Name: rn, Size: sizes.Sizeof(named), Align: sizes.Alignof(named)}
			var vars []*types.Var
			for i := 0; i < u.NumFields(); i++ {
				vars = append(vars, u.Field(i))
			}
			offs := sizes.Offsetsof(vars)
			names := map[string]string{}
			for i, f := range vars {
				fn := fieldName(f.Name())
				if prev, dup := names[fn]; dup {
					fatalf("%s: fields %s and %s collide", name, prev, f.Name())
				}
				names[fn] = f.Name()
				fmt.Fprintf(b, "    /// `%s.%s`.\n    pub %s: %s,\n", name, f.Name(), fn, rustType(f.Type()))
				symbolPath[name+"."+f.Name()] = rn + "::" + fn
				ent.Fields = append(ent.Fields, fieldEntry{f.Name(), fn, offs[i]})
			}
			b.WriteString("}\n\n")
			ent.RustSize = ent.Size
			if last := vars[len(vars)-1]; true {
				if arr, ok := last.Type().(*types.Array); ok && arr.Len() == 0 {
					ent.RustSize = (offs[len(vars)-1] + ent.Align - 1) / ent.Align * ent.Align
				}
			}
			fmt.Fprintf(b, "impl Default for %s {\n    fn default() -> %s {\n        %s {\n", rn, rn, rn)
			for _, f := range vars {
				fmt.Fprintf(b, "            %s: %s,\n", fieldName(f.Name()), zeroExpr(f.Type()))
			}
			b.WriteString("        }\n    }\n}\n\n")
			structTable = append(structTable, ent)
		}
	}
}

// ---- errno and signal tables ----------------------------------------------

func loadTables() {
	for _, f := range files {
		if filepath.Base(fset.Position(f.Pos()).Filename) != "zerrors_linux_amd64.go" {
			continue
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				var dst map[int]string
				switch vs.Names[0].Name {
				case "errors":
					dst = errorsTable
				case "signals":
					dst = signalTable
				default:
					continue
				}
				for _, e := range vs.Values[0].(*ast.CompositeLit).Elts {
					kv := e.(*ast.KeyValueExpr)
					k, _ := strconv.Atoi(kv.Key.(*ast.BasicLit).Value)
					v, err := strconv.Unquote(kv.Value.(*ast.BasicLit).Value)
					if err != nil {
						fatalf("%v", err)
					}
					dst[k] = v
				}
			}
		}
	}
	if len(errorsTable) == 0 || len(signalTable) == 0 {
		fatalf("errors/signals tables not found")
	}
}

// ---- zsyscall wrappers ----------------------------------------------------

// Parameters that the kernel writes through; every other []byte is read-only.
var writtenSlices = map[string]bool{
	"Getcwd.buf": true, "Getdents.buf": true, "Getxattr.dest": true, "Listxattr.dest": true,
	"Klogctl.buf": true, "read.p": true, "pread.p": true, "readlinkat.buf": true,
	"recvfrom.p": true, "EpollWait.events": true,
}

// Pointer parameters that Go callers pass as nil.
var nullable = map[string]bool{
	"Select.r": true, "Select.w": true, "Select.e": true, "Select.timeout": true,
	"Nanosleep.leftover": true, "EpollCtl.event": true, "Splice.roff": true, "Splice.woff": true,
}

type param struct {
	name, goType string
}

func exprStr(e ast.Expr) string { return types.ExprString(e) }

func fieldsOf(fl *ast.FieldList) []param {
	var ps []param
	if fl == nil {
		return nil
	}
	for _, f := range fl.List {
		for _, n := range f.Names {
			ps = append(ps, param{n.Name, exprStr(f.Type)})
		}
	}
	return ps
}

func scalarRust(goType string) (string, bool) {
	switch goType {
	case "int":
		return "isize", true
	case "uint", "uintptr":
		return "usize", true
	case "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64":
		return map[string]string{"int8": "i8", "int16": "i16", "int32": "i32", "int64": "i64", "uint8": "u8", "uint16": "u16", "uint32": "u32", "uint64": "u64"}[goType], true
	case "Signal":
		return goType, true
	case "byte":
		return "u8", true
	case "_Socklen", "_Gid_t":
		return "u32", true
	case "_C_int":
		return "i32", true
	case "unsafe.Pointer", "*byte":
		return "usize", true
	}
	return "", false
}

func genZsyscall() {
	b := out("crates/sys/src/syscall/zsyscall.rs")
	b.WriteString("//! Generated by tools/gen_syscall.go from Go's zsyscall_linux_amd64.go. Do not edit.\n")
	b.WriteString("//!\n//! Each wrapper is the mksyscall.pl pattern: arguments become `usize` words, the\n")
	b.WriteString("//! call goes through `sc` (a real system call on linux/x86_64, the portable\n")
	b.WriteString("//! subset or ENOSYS elsewhere) and a failure becomes `Err(Errno)`. Where Go\n")
	b.WriteString("//! returns the raw result alongside an error, only the error is returned.\n")
	b.WriteString("#![allow(dead_code, clippy::unnecessary_cast, clippy::useless_conversion)]\n")
	b.WriteString("use super::consts::*;\n")
	b.WriteString("use super::errno::{Errno, Signal};\n")
	b.WriteString("use super::raw::{byte_ptr_from_string, sc, sc_no_error};\n")
	b.WriteString("use super::types::*;\n\n")
	for _, f := range files {
		if filepath.Base(fset.Position(f.Pos()).Filename) != "zsyscall_linux_amd64.go" {
			continue
		}
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil {
				genWrapper(b, fd)
			}
		}
	}
	// The wrappers are re-exported by name; the unexported ones stay in zsyscall,
	// whose names would otherwise collide with Go's exported hand-written ones
	// (read and Read are both `read` in snake case).
	e := out("crates/sys/src/syscall/zexports.rs")
	e.WriteString("//! Generated by tools/gen_syscall.go. Do not edit.\n")
	e.WriteString("pub use super::zsyscall::{\n")
	sort.Strings(exportedFuncs)
	for _, n := range exportedFuncs {
		fmt.Fprintf(e, "    %s,\n", n)
	}
	e.WriteString("};\n")
}

type ptrSrc struct {
	kind string // "str" or "slice"
	name string
}

func genWrapper(b *bytes.Buffer, fd *ast.FuncDecl) {
	goName := fd.Name.Name
	params := fieldsOf(fd.Type.Params)
	results := fieldsOf(fd.Type.Results)
	exported := fd.Name.IsExported()

	// Rust signature.
	pty := map[string]string{} // Go param -> Go type
	var sig []string
	for _, p := range params {
		pty[p.name] = p.goType
		var rt string
		switch {
		case p.goType == "string":
			rt = "&str"
		case p.goType == "[]byte":
			if writtenSlices[goName+"."+p.name] {
				rt = "&mut [u8]"
			} else {
				rt = "&[u8]"
			}
		case strings.HasPrefix(p.goType, "[]"):
			rt = "&mut [" + strings.TrimPrefix(p.goType, "[]") + "]"
		case strings.HasPrefix(p.goType, "*") && p.goType != "*byte":
			elem := strings.TrimPrefix(p.goType, "*")
			et := elem
			if strings.HasPrefix(elem, "[") { // *[2]_C_int
				et = rustArray(elem)
			} else if r, ok := scalarRust(elem); ok {
				et = r
			} else if strings.HasPrefix(elem, "_") {
				et = map[string]string{"_Gid_t": "u32", "_Socklen": "u32", "_C_int": "i32"}[elem]
			}
			switch {
			case !exported:
				rt = "*mut " + et
			case nullable[goName+"."+p.name]:
				rt = "Option<&mut " + et + ">"
			default:
				rt = "&mut " + et
			}
		default:
			r, ok := scalarRust(p.goType)
			if !ok {
				fatalf("%s: unsupported parameter type %s", goName, p.goType)
			}
			rt = r
		}
		sig = append(sig, fmt.Sprintf("%s: %s", ident(snake(p.name)), rt))
	}
	hasErr := len(results) > 0 && results[len(results)-1].goType == "error"
	var val *param
	for i := range results {
		if results[i].goType != "error" {
			val = &results[i]
		}
	}
	ret := ""
	switch {
	case hasErr && val != nil:
		r, ok := scalarRust(val.goType)
		if !ok {
			fatalf("%s: result type %s", goName, val.goType)
		}
		ret = fmt.Sprintf(" -> Result<%s, Errno>", r)
	case hasErr:
		ret = " -> Result<(), Errno>"
	case val != nil:
		r, ok := scalarRust(val.goType)
		if !ok {
			fatalf("%s: result type %s", goName, val.goType)
		}
		ret = " -> " + r
	}

	// Scan the body.
	srcs := map[string]ptrSrc{}
	var call *ast.CallExpr
	noError := false
	conv := ""
	for _, st := range fd.Body.List {
		switch s := st.(type) {
		case *ast.AssignStmt:
			if len(s.Rhs) != 1 {
				continue
			}
			ce, ok := s.Rhs[0].(*ast.CallExpr)
			if !ok {
				continue
			}
			fn := exprStr(ce.Fun)
			switch fn {
			case "BytePtrFromString":
				srcs[exprStr(s.Lhs[0])] = ptrSrc{"str", exprStr(ce.Args[0])}
			case "Syscall", "Syscall6", "RawSyscall", "RawSyscall6":
				call = ce
			case "rawSyscallNoError":
				call, noError = ce, true
			default:
				if len(ce.Args) == 1 && exprStr(ce.Args[0]) == "r0" && val != nil && exprStr(s.Lhs[0]) == val.name {
					conv = fn
				}
			}
		case *ast.IfStmt:
			// if len(buf) > 0 { _p0 = unsafe.Pointer(&buf[0]) } else {...}
			if len(s.Body.List) == 1 {
				if as, ok := s.Body.List[0].(*ast.AssignStmt); ok && strings.HasPrefix(exprStr(as.Lhs[0]), "_p") {
					rhs := exprStr(as.Rhs[0]) // unsafe.Pointer(&buf[0])
					i, j := strings.Index(rhs, "&"), strings.LastIndex(rhs, "[0]")
					if i < 0 || j < 0 {
						fatalf("%s: unexpected slice pointer %s", goName, rhs)
					}
					srcs[exprStr(as.Lhs[0])] = ptrSrc{"slice", rhs[i+1 : j]}
				}
			}
		case *ast.ExprStmt:
			if ce, ok := s.X.(*ast.CallExpr); ok {
				if fn := exprStr(ce.Fun); fn == "Syscall" || fn == "Syscall6" || fn == "RawSyscall" {
					call = ce
				}
			}
		}
	}
	if call == nil {
		fatalf("%s: no system call found", goName)
	}

	// Rust arguments.
	trap := exprStr(call.Args[0])
	if strings.HasPrefix(trap, "_SYS_") {
		trap = strings.ToUpper(trap)
	}
	var words []string
	for _, a := range call.Args[1:] {
		words = append(words, argWord(goName, a, pty, srcs))
	}
	for len(words) < 6 {
		words = append(words, "0")
	}

	vis := "pub"
	if !exported {
		vis = "pub(crate)"
	}
	rn := funcName(goName)
	if exported {
		symbolPath[goName] = rn
		exportedFuncs = append(exportedFuncs, rn)
		fmt.Fprintf(b, "/// `syscall.%s`.\n", goName)
	}
	fmt.Fprintf(b, "%s fn %s(%s)%s {\n", vis, rn, strings.Join(sig, ", "), ret)
	var pnames []string
	for k := range srcs {
		pnames = append(pnames, k)
	}
	sort.Strings(pnames)
	for _, k := range pnames {
		if srcs[k].kind == "str" {
			fmt.Fprintf(b, "    let %s = byte_ptr_from_string(%s)?;\n", k, ident(snake(srcs[k].name)))
		}
	}
	args := strings.Join(words, ", ")
	cast := func(v string) string {
		if conv == "" {
			return v
		}
		r, _ := scalarRust(conv)
		return fmt.Sprintf("%s as %s", v, r)
	}
	switch {
	case noError:
		fmt.Fprintf(b, "    %s\n", cast(fmt.Sprintf("sc_no_error(%s, [%s])", trap, args)))
	case hasErr && val != nil:
		fmt.Fprintf(b, "    let r0 = sc(%s, [%s])?;\n    Ok(%s)\n", trap, args, cast("r0"))
	case hasErr:
		fmt.Fprintf(b, "    sc(%s, [%s])?;\n    Ok(())\n", trap, args)
	case val != nil:
		fmt.Fprintf(b, "    let r0 = sc(%s, [%s]).unwrap_or(usize::MAX);\n    %s\n", trap, args, cast("r0"))
	default:
		fmt.Fprintf(b, "    let _ = sc(%s, [%s]);\n", trap, args)
	}
	b.WriteString("}\n\n")
}

func rustArray(goType string) string { // "[2]_C_int"
	i := strings.Index(goType, "]")
	n, elem := goType[1:i], goType[i+1:]
	e := elem
	if r, ok := scalarRust(elem); ok {
		e = r
	} else if elem == "_C_int" {
		e = "i32"
	}
	return fmt.Sprintf("[%s; %s]", e, n)
}

// argWord renders one uintptr(...) argument of a Syscall call as a usize word.
func argWord(fn string, a ast.Expr, pty map[string]string, srcs map[string]ptrSrc) string {
	if lit, ok := a.(*ast.BasicLit); ok && lit.Value == "0" {
		return "0"
	}
	ce, ok := a.(*ast.CallExpr)
	if !ok || exprStr(ce.Fun) != "uintptr" || len(ce.Args) != 1 {
		fatalf("%s: unexpected argument %s", fn, exprStr(a))
	}
	inner := ce.Args[0]
	if c2, ok := inner.(*ast.CallExpr); ok {
		switch exprStr(c2.Fun) {
		case "len":
			return ident(snake(exprStr(c2.Args[0]))) + ".len()"
		case "unsafe.Pointer":
			inner = c2.Args[0]
		default:
			fatalf("%s: unexpected argument %s", fn, exprStr(a))
		}
	}
	name := exprStr(inner)
	if src, ok := srcs[name]; ok {
		if src.kind == "str" {
			return name + ".as_ptr() as usize"
		}
		s := ident(snake(src.name))
		if writtenSlices[fn+"."+src.name] {
			return s + ".as_mut_ptr() as usize"
		}
		return s + ".as_ptr() as usize"
	}
	gt, ok := pty[name]
	if !ok {
		fatalf("%s: unknown name %s", fn, name)
	}
	p := ident(snake(name))
	switch {
	case gt == "Signal":
		return p + ".0 as usize"
	case strings.HasPrefix(gt, "*") && gt != "*byte":
		if token.IsExported(fn) {
			if nullable[fn+"."+name] {
				return p + ".map_or(0, |r| r as *mut _ as usize)"
			}
			return p + " as *mut _ as usize"
		}
		return p + " as usize"
	}
	return p + " as usize"
}

// ---- mapping JSON ---------------------------------------------------------

type surfaceSymbol struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

type entry struct {
	Rust      string `json:"rust,omitempty"`
	Deviation string `json:"deviation,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Hand-written symbols whose Rust path is not the default snake/screaming
// conversion, and the documented deviations.
var overrides = map[string]entry{
	"Conn":                    {Rust: "rust_stdlib_sys::net::AsSocket", Note: "Any socket or file with a descriptor (std's AsRawFd) is a Conn; net::syscall_conn turns it into a RawConn."},
	"Conn.SyscallConn":        {Rust: "rust_stdlib_sys::net::syscall_conn"},
	"RawConn":                 {Rust: "rust_stdlib_sys::net::RawConn"},
	"RawConn.Control":         {Rust: "rust_stdlib_sys::net::RawConn::control"},
	"RawConn.Read":            {Rust: "rust_stdlib_sys::net::RawConn::read"},
	"RawConn.Write":           {Rust: "rust_stdlib_sys::net::RawConn::write"},
	"ParseNetlinkRouteAttr":   {Rust: "parse_netlink_route_attr", Note: "Returns EINVAL where Go panics (slice bounds out of range) when a message is shorter than its fixed header."},
	"SysProcAttr.UidMappings": {Rust: "SysProcAttr::uid_mappings", Deviation: "no-nil-empty", Note: "An empty Vec is Go's nil: no mapping is written. Go's non-nil empty slice would still synchronise with the child and write nothing."},
	"SysProcAttr.GidMappings": {Rust: "SysProcAttr::gid_mappings", Note: "An empty Vec is Go's nil: no mapping is written."},
	"Signal.String":           {Rust: "std::string::ToString::to_string", Note: "Display"},
	"InotifyEvent":            {Rust: "InotifyEvent", Deviation: "sizeof-padding", Note: "#[repr(C)] with C's layout: 16 bytes (SizeofInotifyEvent). gc's unsafe.Sizeof reports 20 because it pads a struct that ends in a zero-length array; the field offsets are identical."},
	"SysProcAttr.PidFD":       {Rust: "SysProcAttr::pid_fd", Note: "An Option<Arc<AtomicIsize>> in place of *int: the cell receives the pidfd, or -1, and the caller owns the descriptor."},
	"Stdin":                   {Rust: "STDIN", Note: "A constant: Go's Stdin is a variable that is never reassigned in practice."},
	"Stdout":                  {Rust: "STDOUT", Note: "A constant: Go's Stdout is a variable that is never reassigned in practice."},
	"Stderr":                  {Rust: "STDERR", Note: "A constant: Go's Stderr is a variable that is never reassigned in practice."},
	"ForkLock":                {Rust: "FORK_LOCK", Note: "A std::sync::RwLock<()>; Go's sync.RWMutex has the same read/write locking shape."},
	"SocketDisableIPv6":       {Rust: "SOCKET_DISABLE_IPV6", Note: "A std::sync::atomic::AtomicBool."},
	"BytePtrFromString":       {Rust: "byte_ptr_from_string", Deviation: "go-unsafe-pointer", Note: "Go returns a *byte into a fresh []byte; Rust returns the owned, NUL-terminated std::ffi::CString (as_ptr gives the pointer). The error cases (EINVAL for an embedded NUL) match."},
	"ByteSliceFromString":     {Rust: "byte_slice_from_string"},
	"StringBytePtr":           {Rust: "string_byte_ptr", Deviation: "go-unsafe-pointer", Note: "Deprecated. Returns an owned std::ffi::CString instead of a *byte; panics on an embedded NUL as Go does."},
	"StringByteSlice":         {Rust: "string_byte_slice"},
	"SlicePtrFromStrings":     {Rust: "slice_ptr_from_strings", Deviation: "go-unsafe-pointer", Note: "Go returns []*byte; Rust returns a CStringVec that owns the strings and exposes the NUL-terminated pointer array through as_ptr."},
	"StringSlicePtr":          {Rust: "string_slice_ptr", Deviation: "go-unsafe-pointer", Note: "Deprecated. Returns a CStringVec instead of []*byte; panics on an embedded NUL as Go does."},
	"AllThreadsSyscall":       {Rust: "all_threads_syscall", Deviation: "go-runtime-all-threads", Note: "Go's runtime stops every thread and runs the call on each; Rust has no such runtime, so the call runs on the calling thread only. Setuid, Setgid and the other id setters use the C library, which does synchronise all threads."},
	"AllThreadsSyscall6":      {Rust: "all_threads_syscall6", Deviation: "go-runtime-all-threads", Note: "As AllThreadsSyscall."},
}

func surfaceMapping() {
	data, err := os.ReadFile(filepath.Join(root, "docs/api/go-surface.json"))
	if err != nil {
		fatalf("%v", err)
	}
	var surf struct {
		Packages map[string][]surfaceSymbol `json:"packages"`
	}
	if err := json.Unmarshal(data, &surf); err != nil {
		fatalf("%v", err)
	}
	syms := map[string]entry{}
	for _, s := range surf.Packages["syscall"] {
		if e, ok := overrides[s.Name]; ok {
			if !strings.HasPrefix(e.Rust, "rust_stdlib_sys::") && !strings.HasPrefix(e.Rust, "std::") {
				e.Rust = rustPrefix + e.Rust
			}
			syms[s.Name] = e
			continue
		}
		var path string
		switch s.Kind {
		case "const":
			path = constName(s.Name)
		case "type":
			path = s.Name
		case "func":
			path = funcName(s.Name)
		case "field":
			i := strings.Index(s.Name, ".")
			path = s.Name[:i] + "::" + fieldName(s.Name[i+1:])
		case "method":
			i := strings.Index(s.Name, ".")
			path = s.Name[:i] + "::" + funcName(s.Name[i+1:])
		default:
			fatalf("no mapping rule for %s (%s)", s.Name, s.Kind)
		}
		syms[s.Name] = entry{Rust: rustPrefix + path}
	}
	doc := map[string]any{
		"package": "syscall",
		"notes":   "syscall: linux/amd64 constants, struct layouts and zsyscall wrappers generated by tools/gen_syscall.go from Go's own sources into rust_stdlib_sys::syscall; hand-written helpers port the rest. System calls run for real on linux/x86_64 (extern \"C\" syscall from the C library); other targets get the portable libc subset (read, write, close, dup, fsync, ftruncate, the id and process queries, umask, wait4, fork/exec) and ENOSYS for the rest. Errno and Signal use the Linux tables on every host. Names are snake_case functions and SCREAMING constants; Go struct names are kept (Stat_t, RawSockaddrInet4). Go's int is isize, uint and uintptr are usize, string is &str, []byte is &[u8] or &mut [u8], pointers are references (Option for nil-able ones). Wrappers return Result<T, Errno> and drop Go's raw result on failure.",
		"symbols": syms,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fatalf("%v", err)
	}
	out("docs/api/syscall.json").Write(buf.Bytes())
}

// ---- expected tables ------------------------------------------------------

func intLit(v string) string { return v }

func genExpected() {
	b := out("crates/sys/tests/syscall_expected/mod.rs")
	b.WriteString("// Generated by tools/gen_syscall.go from go/constant and go/types (linux/amd64). Do not edit.\n")
	b.WriteString("#![allow(clippy::all)]\n")
	b.WriteString("use rust_stdlib_sys::syscall as sc;\nuse std::mem::{align_of, offset_of, size_of};\n\n")
	b.WriteString("#[test]\nfn constants_match_go() {\n")
	for _, c := range constTable {
		switch c.Kind {
		case "errno":
			fmt.Fprintf(b, "    assert_eq!(sc::%s.0 as i128, %s, %q);\n", c.Rust, c.Value, c.Go)
		case "signal":
			fmt.Fprintf(b, "    assert_eq!(sc::%s.0 as i128, %s, %q);\n", c.Rust, c.Value, c.Go)
		case "bool":
			fmt.Fprintf(b, "    assert_eq!(sc::%s, %s, %q);\n", c.Rust, c.Value, c.Go)
		default:
			fmt.Fprintf(b, "    assert_eq!(sc::%s as i128, %s, %q);\n", c.Rust, c.Value, c.Go)
		}
	}
	b.WriteString("}\n\n")
	b.WriteString("#[test]\nfn struct_layouts_match_go() {\n")
	for _, s := range structTable {
		fmt.Fprintf(b, "    assert_eq!(size_of::<sc::%s>(), %d, \"sizeof %s\");\n", s.Name, s.RustSize, s.Name)
		fmt.Fprintf(b, "    assert_eq!(align_of::<sc::%s>(), %d, \"alignof %s\");\n", s.Name, s.Align, s.Name)
		for _, f := range s.Fields {
			fmt.Fprintf(b, "    assert_eq!(offset_of!(sc::%s, %s), %d, \"offsetof %s.%s\");\n", s.Name, f.Rust, f.Offset, s.Name, f.Go)
		}
	}
	b.WriteString("}\n\n")
	emitTable := func(fnName, ctor string, tbl map[int]string, fallback string) {
		fmt.Fprintf(b, "#[test]\nfn %s() {\n", fnName)
		var keys []int
		for k := range tbl {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		for _, k := range keys {
			fmt.Fprintf(b, "    assert_eq!(%s(%d).to_string(), %q);\n", ctor, k, tbl[k])
		}
		max := keys[len(keys)-1]
		fmt.Fprintf(b, "    assert_eq!(%s(%d).to_string(), %q);\n", ctor, max+1, fmt.Sprintf("%s %d", fallback, max+1))
		b.WriteString("}\n")
	}
	emitTable("error_strings_match_go", "sc::Errno", errorsTable, "errno")
	b.WriteString("\n")
	emitTable("signal_strings_match_go", "sc::Signal", signalTable, "signal")
}

// genOracle writes three views of the same table, one line per fact:
//
//   - a Go program that prints it using the real syscall package (built with
//     GOOS=linux GOARCH=amd64 and run on Linux by tools/syscall_check.py),
//   - the text it must print, from go/constant and go/types,
//   - crates/sys/examples/syscall_probe.rs, which prints the same lines from
//     the Rust side.
//
// The lines are "const NAME value", "size TYPE size align", "offset TYPE.Field
// offset", "errno N text" and "signal N text".
func genOracle(dir, txt string) {
	var prog, want, probe bytes.Buffer
	prog.WriteString("// Generated by tools/gen_syscall.go. Do not edit.\npackage main\n\nimport (\n\t\"fmt\"\n\t\"syscall\"\n\t\"unsafe\"\n)\n\nfunc main() {\n")
	probe.WriteString("// Generated by tools/gen_syscall.go. Do not edit.\n//\n// Prints every constant, struct size and field offset and the error and signal\n// messages of rust_stdlib_sys::syscall in the format of the Go oracle\n// (tools/gen_syscall.go -oracle-go); tools/syscall_check.py diffs the two.\n#![cfg(all(\n    any(target_os = \"linux\", target_os = \"macos\"),\n    target_pointer_width = \"64\"\n))]\nuse rust_stdlib_sys::syscall as sc;\nuse std::mem::{align_of, offset_of, size_of};\n\n#[rustfmt::skip]\nfn main() {\n")
	for _, c := range constTable {
		switch c.Kind {
		case "errno", "signal":
			fmt.Fprintf(&prog, "\tfmt.Println(\"const %s\", int64(syscall.%s))\n", c.Go, c.Go)
			fmt.Fprintf(&probe, "    println!(\"const %s {}\", sc::%s.0 as i64);\n", c.Go, c.Rust)
		case "bool":
			fmt.Fprintf(&prog, "\tfmt.Println(\"const %s\", syscall.%s)\n", c.Go, c.Go)
			fmt.Fprintf(&probe, "    println!(\"const %s {}\", sc::%s);\n", c.Go, c.Rust)
		default:
			fmt.Fprintf(&prog, "\tfmt.Println(\"const %s\", int64(syscall.%s))\n", c.Go, c.Go)
			fmt.Fprintf(&probe, "    println!(\"const %s {}\", sc::%s as i64);\n", c.Go, c.Rust)
		}
		fmt.Fprintf(&want, "const %s %s\n", c.Go, c.Value)
	}
	for _, s := range structTable {
		size := "unsafe.Sizeof(v)"
		if s.RustSize != s.Size {
			// gc pads a trailing zero-length array; C does not.
			last := s.Fields[len(s.Fields)-1]
			size = fmt.Sprintf("(unsafe.Offsetof(v.%s) + %d) / %d * %d", last.Go, s.Align-1, s.Align, s.Align)
		}
		fmt.Fprintf(&prog, "\t{\n\t\tvar v syscall.%s\n\t\tfmt.Println(\"size %s\", %s, unsafe.Alignof(v))\n", s.Name, s.Name, size)
		fmt.Fprintf(&probe, "    println!(\"size %s {} {}\", size_of::<sc::%s>(), align_of::<sc::%s>());\n", s.Name, s.Name, s.Name)
		fmt.Fprintf(&want, "size %s %d %d\n", s.Name, s.RustSize, s.Align)
		for _, f := range s.Fields {
			fmt.Fprintf(&prog, "\t\tfmt.Println(\"offset %s.%s\", unsafe.Offsetof(v.%s))\n", s.Name, f.Go, f.Go)
			fmt.Fprintf(&probe, "    println!(\"offset %s.%s {}\", offset_of!(sc::%s, %s));\n", s.Name, f.Go, s.Name, f.Rust)
			fmt.Fprintf(&want, "offset %s.%s %d\n", s.Name, f.Go, f.Offset)
		}
		prog.WriteString("\t}\n")
	}
	for _, kv := range []struct {
		kind, goCtor, goMethod, rustCtor, rustMethod string
		tbl                                          map[int]string
	}{
		{"errno", "syscall.Errno", "Error", "sc::Errno", "error", errorsTable},
		{"signal", "syscall.Signal", "String", "sc::Signal", "", signalTable},
	} {
		max := 0
		for k := range kv.tbl {
			if k > max {
				max = k
			}
		}
		fmt.Fprintf(&prog, "\tfor i := 0; i <= %d; i++ {\n\t\tfmt.Printf(\"%s %%d %%s\\n\", i, %s(i).%s())\n\t}\n", max+1, kv.kind, kv.goCtor, kv.goMethod)
		rustCall := kv.rustCtor + "(i)"
		if kv.rustMethod != "" {
			rustCall += "." + kv.rustMethod + "()"
		}
		fmt.Fprintf(&probe, "    for i in 0..=%d {\n        println!(\"%s {} {}\", i, %s);\n    }\n", max+1, kv.kind, rustCall)
		for i := 0; i <= max+1; i++ {
			s := kv.tbl[i]
			if s == "" {
				s = fmt.Sprintf("%s %d", kv.kind, i)
			}
			fmt.Fprintf(&want, "%s %d %s\n", kv.kind, i, s)
		}
	}
	prog.WriteString("}\n")
	probe.WriteString("}\n")
	if dir != "" {
		out(filepath.Join(dir, "main.go")).Write(prog.Bytes())
	}
	if txt != "" {
		out(txt).Write(want.Bytes())
	}
	out("crates/sys/examples/syscall_probe.rs").Write(probe.Bytes())
}

// ---- main -----------------------------------------------------------------

func main() {
	check := flag.Bool("check", false, "fail if a generated file differs")
	oracleDir := flag.String("oracle-go", "", "write the Go oracle program into this directory")
	oracleTxt := flag.String("oracle-txt", "", "write the oracle's expected output to this file")
	flag.Parse()
	wd, _ := os.Getwd()
	root = wd
	load()
	loadTables()
	genConsts()
	genTypes()
	genZsyscall()
	genExpected()
	genOracle(*oracleDir, *oracleTxt)
	surfaceMapping()
	merged := map[string]*bytes.Buffer{}
	for p, b := range outputs {
		merged[p] = b
	}
	stale := false
	var paths []string
	for p := range merged {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		dest := p
		if !filepath.IsAbs(p) {
			dest = filepath.Join(root, p)
		}
		if *check && !filepath.IsAbs(p) {
			old, _ := os.ReadFile(dest)
			if !bytes.Equal(old, merged[p].Bytes()) {
				fmt.Fprintf(os.Stderr, "gen_syscall: %s is stale\n", p)
				stale = true
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			fatalf("%v", err)
		}
		if err := os.WriteFile(dest, merged[p].Bytes(), 0o644); err != nil {
			fatalf("%v", err)
		}
	}
	if stale {
		os.Exit(1)
	}
}
