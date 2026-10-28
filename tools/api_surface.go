// Emit the exported API surface of in-scope Go stdlib packages as JSON.
//
// Usage: go run tools/api_surface.go < package-list > docs/api/go-surface.json
//
// Packages are parsed for GOOS=linux GOARCH=amd64 so the surface is
// deterministic. Symbols are named "Name" for package-level funcs, types,
// consts and vars, and "Type.Name" for methods, exported struct fields and
// interface methods. Embedded fields and methods promoted from them are not
// listed separately; the embedded type is listed as a field.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type symbol struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Deprecated bool   `json:"deprecated,omitempty"`
}

func deprecated(text string) bool {
	for _, para := range strings.Split(text, "\n\n") {
		if strings.HasPrefix(strings.TrimSpace(para), "Deprecated:") {
			return true
		}
	}
	return false
}

func fieldNames(field *ast.Field) []string {
	if len(field.Names) > 0 {
		var names []string
		for _, n := range field.Names {
			names = append(names, n.Name)
		}
		return names
	}
	// Embedded field: its name is the type name.
	expr := field.Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if index, ok := expr.(*ast.IndexExpr); ok {
		expr = index.X
	}
	switch t := expr.(type) {
	case *ast.Ident:
		return []string{t.Name}
	case *ast.SelectorExpr:
		return []string{t.Sel.Name}
	}
	return nil
}

func surface(importPath string) ([]symbol, error) {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "linux", "amd64", true
	pkg, err := ctx.Import(importPath, "", 0)
	if err != nil {
		return nil, err
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range append(append([]string{}, pkg.GoFiles...), pkg.CgoFiles...) {
		file, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, name), nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		files = append(files, file)
	}
	docPkg, err := doc.NewFromFiles(fset, files, importPath)
	if err != nil {
		return nil, err
	}
	var out []symbol
	add := func(name, kind, text string) {
		if ast.IsExported(name[strings.LastIndex(name, ".")+1:]) {
			out = append(out, symbol{name, kind, deprecated(text)})
		}
	}
	values := func(list []*doc.Value, kind string) {
		for _, v := range list {
			for _, spec := range v.Decl.Specs {
				for _, n := range spec.(*ast.ValueSpec).Names {
					add(n.Name, kind, v.Doc)
				}
			}
		}
	}
	values(docPkg.Consts, "const")
	values(docPkg.Vars, "var")
	for _, f := range docPkg.Funcs {
		add(f.Name, "func", f.Doc)
	}
	for _, t := range docPkg.Types {
		add(t.Name, "type", t.Doc)
		values(t.Consts, "const")
		values(t.Vars, "var")
		for _, f := range t.Funcs {
			add(f.Name, "func", f.Doc)
		}
		for _, m := range t.Methods {
			add(t.Name+"."+m.Name, "method", m.Doc)
		}
		spec := t.Decl.Specs[0].(*ast.TypeSpec)
		switch st := spec.Type.(type) {
		case *ast.StructType:
			for _, field := range st.Fields.List {
				for _, name := range fieldNames(field) {
					text := ""
					if field.Doc != nil {
						text = field.Doc.Text()
					}
					add(t.Name+"."+name, "field", text)
				}
			}
		case *ast.InterfaceType:
			for _, m := range st.Methods.List {
				for _, n := range m.Names {
					text := ""
					if m.Doc != nil {
						text = m.Doc.Text()
					}
					add(t.Name+"."+n.Name, "interface-method", text)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func main() {
	result := map[string]any{"go_version": runtime.Version(), "goos": "linux", "goarch": "amd64"}
	packages := map[string][]symbol{}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		path := strings.TrimSpace(in.Text())
		if path == "" {
			continue
		}
		symbols, err := surface(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			os.Exit(1)
		}
		if symbols == nil {
			symbols = []symbol{}
		}
		packages[path] = symbols
	}
	result["packages"] = packages
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(result); err != nil {
		panic(err)
	}
}
