// html/template mode of the template differential oracle. The data types are
// adapted from Go's html/template tests (BSD-licensed, see NOTICE); the Rust
// side rebuilds them in tests/support/template_html_data.rs.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	htemplate "html/template"
	"strings"
)

type badMarshaler struct{}

func (x *badMarshaler) MarshalJSON() ([]byte, error) {
	// Keys in valid JSON must be double quoted as must all strings.
	return []byte("{ foo: 'not quite valid JSON' }"), nil
}

type goodMarshaler struct{}

func (x *goodMarshaler) MarshalJSON() ([]byte, error) {
	return []byte(`{ "<foo>": "O'Reilly" }`), nil
}

type jsonErrType struct{}

func (e *jsonErrType) MarshalJSON() ([]byte, error) {
	return nil, errors.New("a */ b <script c </script d <!-- e <sCrIpT f </sCrIpT")
}

type myStringer struct{ v int }

func (s *myStringer) String() string { return fmt.Sprintf("string=%d", s.v) }

type errorer struct{ v int }

func (s *errorer) Error() string { return fmt.Sprintf("error=%d", s.v) }

type escapeDataT struct {
	F, T       bool
	C, G, H, I string
	A, E       []string
	B, M       json.Marshaler
	N          int
	U          any  // untyped nil
	Z          *int // typed nil
	W          htemplate.HTML
}

func escapeData() escapeDataT {
	return escapeDataT{
		F: false,
		T: true,
		C: "<Cincinnati>",
		G: "<Goodbye>",
		H: "<Hello>",
		A: []string{"<a>", "<b>"},
		E: []string{},
		N: 42,
		B: &badMarshaler{},
		M: &goodMarshaler{},
		U: nil,
		Z: nil,
		W: htemplate.HTML(`&iexcl;<b class="foo">Hello</b>, <textarea>O'World</textarea>!`),
		I: "${ asd `` }",
	}
}

type dataItem struct {
	Children []*dataItem
	X        string
}

func dataItems() dataItem {
	return dataItem{
		Children: []*dataItem{
			{X: "foo"},
			{X: "<bar>"},
			{Children: []*dataItem{{X: "baz"}}},
		},
	}
}

type jsFields struct{ X, Y int }

func htmlRefs(name string) (any, bool) {
	switch name {
	case "escapeData":
		return escapeData(), true
	case "&escapeData":
		d := escapeData()
		return &d, true
	case "dataItem":
		return dataItems(), true
	case "jsonErr":
		return &jsonErrType{}, true
	case "stringer3":
		return &myStringer{3}, true
	case "errorer7":
		return &errorer{7}, true
	case "xyStruct":
		return struct{ X, Y int }{1, 2}, true
	case "errIface":
		return struct{ E error }{}, true
	case "anyIface":
		return struct{ E any }{}, true
	case "stringsAngle":
		return []string{"<!--", "</script>", "-->"}, true
	case "anySlice":
		return []any{42, "foo", nil}, true
	case "emptyAnySlice":
		return []any{}, true
	}
	return nil, false
}

func htmlTyped(t string, spec map[string]any) (any, bool) {
	s, _ := spec["v"].(string)
	switch t {
	case "html":
		return htemplate.HTML(s), true
	case "css":
		return htemplate.CSS(s), true
	case "js":
		return htemplate.JS(s), true
	case "jsstr":
		return htemplate.JSStr(s), true
	case "url":
		return htemplate.URL(s), true
	case "srcset":
		return htemplate.Srcset(s), true
	case "htmlattr":
		return htemplate.HTMLAttr(s), true
	}
	return nil, false
}

func doHTML(r *request) (string, error) {
	tmpl := htemplate.New(r.Name)
	if len(r.Opts) > 0 {
		tmpl.Option(r.Opts...)
	}
	tmpl.Delims(r.Ld, r.Rd)
	if !r.NoFuncs {
		tmpl.Funcs(htmlFuncs)
	}
	if _, err := tmpl.Parse(r.Src); err != nil {
		return "", err
	}
	for _, d := range r.Defs {
		if _, err := tmpl.New(d[0]).Parse(d[1]); err != nil {
			return "", err
		}
	}
	var spec any
	if len(r.Data) > 0 {
		if err := json.Unmarshal(r.Data, &spec); err != nil {
			panic(err)
		}
	}
	data := build(spec)
	exec := func(sb *strings.Builder) error {
		if r.ExecName != "" {
			return tmpl.ExecuteTemplate(sb, r.ExecName, data)
		}
		return tmpl.Execute(sb, data)
	}
	times := 1
	if r.Twice {
		times = 2
	}
	var all strings.Builder
	for i := 0; i < times; i++ {
		var sb strings.Builder
		err := exec(&sb)
		if times == 1 {
			return sb.String(), err
		}
		if err != nil {
			fmt.Fprintf(&all, "[%d ERR %s | %s]", i, err, sb.String())
		} else {
			fmt.Fprintf(&all, "[%d OK %s]", i, sb.String())
		}
	}
	// Report the defined templates and the tree of the main template, so the
	// escaped parse trees are compared too.
	if t := tmpl.Lookup(r.Name); t != nil && t.Tree != nil && t.Tree.Root != nil {
		fmt.Fprintf(&all, "\ntree: %s", t.Tree.Root.String())
	}
	return all.String(), nil
}

var htmlFuncs = func() htemplate.FuncMap {
	m := htemplate.FuncMap{}
	for k, v := range stdFuncs {
		m[k] = v
	}
	m["pred"] = func(a ...any) (any, error) {
		if len(a) == 1 {
			if i, _ := a[0].(int); i > 0 {
				return i - 1, nil
			}
		}
		return nil, fmt.Errorf("undefined pred(%v)", a)
	}
	return m
}()
