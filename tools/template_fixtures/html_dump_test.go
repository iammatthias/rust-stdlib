package template

// Dumps the inputs of Go's html/template test tables as differential requests
// (one JSON object per line) for tools/template_fixtures.py. The fixtures
// script inserts a dumpHook call into the first loop over a local table of
// each test listed in hookedTests, so the tables need not be exported.

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

var (
	dumpMu  sync.Mutex
	dumpOut *json.Encoder
)

func typedSpec(t string, v any) map[string]any {
	return map[string]any{"$t": t, "v": v}
}

func specFromReflect(v reflect.Value) (any, bool) {
	if !v.IsValid() {
		return nil, true
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return nil, true
		}
		return specFromReflect(v.Elem())
	case reflect.Bool:
		return v.Bool(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return typedSpec(v.Type().Name(), v.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return typedSpec(v.Type().Name(), v.Uint()), true
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		if f == 0 && math.Signbit(f) {
			return map[string]any{"$t": "negzero"}, true
		}
		return typedSpec(v.Type().Name(), f), true
	case reflect.String:
		s := v.String()
		if !utf8.ValidString(s) {
			return nil, false
		}
		if v.Type().Name() != "string" {
			return typedSpec(strings.ToLower(v.Type().Name()), s), true
		}
		return s, true
	case reflect.Struct:
		if v.NumField() == 2 && v.Type().Field(0).Name == "X" {
			return map[string]any{"$ref": "xyStruct"}, true
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.String {
			items := []any{}
			for i := 0; i < v.Len(); i++ {
				items = append(items, v.Index(i).String())
			}
			if reflect.DeepEqual(items, []any{"<!--", "</script>", "-->"}) {
				return map[string]any{"$ref": "stringsAngle"}, true
			}
			return map[string]any{"$t": "slice", "e": "string", "v": items}, true
		}
		items := []any{}
		for i := 0; i < v.Len(); i++ {
			s, ok := specFromReflect(v.Index(i))
			if !ok {
				return nil, false
			}
			items = append(items, s)
		}
		return items, true
	case reflect.Pointer:
		if v.Type().Elem().Name() == "jsonErrType" {
			return map[string]any{"$ref": "jsonErr"}, true
		}
	}
	return nil, false
}

func emitHTML(m map[string]any) {
	dumpMu.Lock()
	defer dumpMu.Unlock()
	if dumpOut == nil {
		f, err := os.Create(os.Getenv("FIXTURE_OUT"))
		if err != nil {
			panic(err)
		}
		dumpOut = json.NewEncoder(f)
	}
	m["mode"] = "html"
	// Requests must survive JSON: skip any with invalid UTF-8.
	for _, k := range []string{"src", "name"} {
		if s, ok := m[k].(string); ok && !utf8.ValidString(s) {
			return
		}
	}
	if err := dumpOut.Encode(m); err != nil {
		panic(err)
	}
}

func field(rv reflect.Value, name string) reflect.Value {
	return rv.FieldByName(name)
}

var typedData = []any{
	`<b> "foo%" O'Reilly &bar;`,
	map[string]any{"$t": "css", "v": `a[href =~ "//example.com"]#foo`},
	map[string]any{"$t": "html", "v": `Hello, <b>World</b> &amp;tc!`},
	map[string]any{"$t": "htmlattr", "v": ` dir="ltr"`},
	map[string]any{"$t": "js", "v": `c && alert("Hello, World!");`},
	map[string]any{"$t": "jsstr", "v": `Hello, World & O'Reilly!`},
	map[string]any{"$t": "url", "v": `greeting=H%69,&addressee=(World)`},
	map[string]any{"$t": "srcset", "v": `greeting=H%69,&addressee=(World) 2x, https://golang.org/favicon.ico 500.5w`},
	map[string]any{"$t": "url", "v": `,foo/,`},
}

func dumpHook(fn string, v any) {
	rv := reflect.ValueOf(v)
	str := func(f string) string { return field(rv, f).String() }
	switch fn {
	case "TestEscape":
		src := str("input")
		emitHTML(map[string]any{"name": str("name"), "src": src, "data": map[string]any{"$ref": "escapeData"}, "origin": "TestEscape"})
		emitHTML(map[string]any{"name": str("name"), "src": src, "data": map[string]any{"$ref": "&escapeData"}, "origin": "TestEscape"})
	case "TestEscapeSet":
		inputs := field(rv, "inputs")
		names := []string{}
		for _, k := range inputs.MapKeys() {
			names = append(names, k.String())
		}
		sort.Strings(names)
		source := ""
		for _, name := range names {
			source += fmt.Sprintf("{{define %q}}%s{{end}} ", name, inputs.MapIndex(reflect.ValueOf(name)).String())
		}
		emitHTML(map[string]any{"name": "root", "src": source, "exec": "main", "data": map[string]any{"$ref": "dataItem"}, "origin": "TestEscapeSet"})
	case "TestErrors":
		emitHTML(map[string]any{"name": "z", "src": str("input"), "data": nil, "twice": true, "origin": "TestErrors"})
	case "TestEscapeText":
		emitHTML(map[string]any{"name": "z", "src": str("input"), "data": nil, "origin": "TestEscapeText"})
	case "TestTypedContent":
		for i, x := range typedData {
			emitHTML(map[string]any{"name": "x", "src": str("input"), "data": x, "origin": fmt.Sprintf("TestTypedContent[%d]", i)})
		}
	case "TestJSValEscaper":
		x, ok := specFromReflect(field(rv, "x"))
		if !ok {
			return
		}
		emitHTML(map[string]any{"name": "x", "src": "<script>{{.}}</script>", "data": x, "origin": "TestJSValEscaper"})
		emitHTML(map[string]any{"name": "x", "src": "<script>{{.}}</script>", "data": []any{x}, "origin": "TestJSValEscaper(nested)"})
		emitHTML(map[string]any{"name": "x", "src": `<a onclick="f({{.}})">`, "data": x, "origin": "TestJSValEscaper(attr)"})
	case "TestJSStrEscaper":
		x, ok := specFromReflect(field(rv, "x"))
		if !ok {
			return
		}
		emitHTML(map[string]any{"name": "x", "src": "<script>var x = '{{.}}'</script>", "data": x, "origin": "TestJSStrEscaper"})
		emitHTML(map[string]any{"name": "x", "src": "<script>var x = \"{{.}}\"</script>", "data": x, "origin": "TestJSStrEscaper"})
		emitHTML(map[string]any{"name": "x", "src": "<script>var x = `{{.}}`</script>", "data": x, "origin": "TestJSStrEscaper"})
	case "TestJSRegexpEscaper":
		x, ok := specFromReflect(field(rv, "x"))
		if !ok {
			return
		}
		emitHTML(map[string]any{"name": "x", "src": "<script>var x = /{{.}}/</script>", "data": x, "origin": "TestJSRegexpEscaper"})
	case "TestEscapersOnLower7AndSelectHighCodepoints":
		input := "\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f" +
			"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f" +
			` !"#$%&'()*+,-./` +
			`0123456789:;<=>?` +
			`@ABCDEFGHIJKLMNO` +
			`PQRSTUVWXYZ[\]^_` +
			"`abcdefghijklmno" +
			"pqrstuvwxyz{|}~\x7f" +
			"\u00A0\u0100\u2028\u2029\ufeff\U0001D11E"
		for _, src := range []string{
			"<script>var x = '{{.}}'</script>", "<script>var x = /{{.}}/</script>", "<style>a { b: {{.}} }</style>",
			`<a href="/{{.}}">`, `<a href="?q={{.}}">`, `<a href="{{.}}">`, `<p>{{.}}</p>`, `<a b={{.}}>`, `<a b="{{.}}">`,
			`<textarea>{{.}}</textarea>`, `<a {{.}}>`, `<div style="{{.}}">`, `<a onclick="f('{{.}}')">`,
		} {
			emitHTML(map[string]any{"name": "x", "src": src, "data": input, "origin": "TestEscapersOnLower7"})
		}
	case "TestURLNormalizer":
		for _, src := range []string{`<a href="/{{.}}">`, `<a href="{{.}}">`, `<a href="?x={{.}}">`} {
			emitHTML(map[string]any{"name": "x", "src": src, "data": str("url"), "origin": "TestURLNormalizer"})
		}
	case "TestSrcsetFilter":
		emitHTML(map[string]any{"name": "x", "src": `<img srcset="{{.}}">`, "data": str("input"), "origin": "TestSrcsetFilter"})
		emitHTML(map[string]any{"name": "x", "src": `<img srcset=x{{.}}>`, "data": str("input"), "origin": "TestSrcsetFilter"})
	case "TestStripTags":
		in := str("input")
		emitHTML(map[string]any{"name": "x", "src": `<a title="{{.}}">`, "data": map[string]any{"$t": "html", "v": in}, "origin": "TestStripTags"})
		emitHTML(map[string]any{"name": "x", "src": `<a title={{.}}>`, "data": map[string]any{"$t": "html", "v": in}, "origin": "TestStripTags"})
		emitHTML(map[string]any{"name": "x", "src": `<textarea>{{.}}</textarea>`, "data": map[string]any{"$t": "html", "v": in}, "origin": "TestStripTags"})
	case "TestCSSValueFilter":
		css := str("css")
		emitHTML(map[string]any{"name": "x", "src": `<style>a { b: {{.}} }</style>`, "data": css, "origin": "TestCSSValueFilter"})
		emitHTML(map[string]any{"name": "x", "src": `<div style="color: {{.}}">`, "data": css, "origin": "TestCSSValueFilter"})
	}
}

func TestDumpFixtures(t *testing.T) {
	// The hooked tests run for real in this process; the dump is a side effect.
	// This test only checks that the hook fired.
	if dumpOut == nil {
		t.Skip("run with -run to execute the hooked tests")
	}
}
