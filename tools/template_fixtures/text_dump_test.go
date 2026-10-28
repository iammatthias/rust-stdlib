package template

// Dumps the inputs of Go's own exec tests as differential requests (one JSON
// object per line) for tools/template_fixtures.py. Data values are described
// with the "$ref"/"$t" specs understood by tools/template_oracle_data.go.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"reflect"
	"strings"
	"testing"
)

func typed(t string, v any) map[string]any {
	return map[string]any{"$t": t, "v": v}
}

func specOf(data any) any {
	switch v := data.(type) {
	case nil:
		return nil
	case int:
		return typed("int", v)
	case int8:
		return typed("int8", v)
	case int16:
		return typed("int16", v)
	case int32:
		return typed("int32", v)
	case int64:
		return typed("int64", v)
	case uint:
		return typed("uint", v)
	case uint8:
		return typed("uint8", v)
	case uint16:
		return typed("uint16", v)
	case uint32:
		return typed("uint32", v)
	case uint64:
		return typed("uint64", v)
	case uintptr:
		return typed("uintptr", v)
	case float64:
		return typed("float64", v)
	case complex128:
		return map[string]any{"$t": "complex128", "re": real(v), "im": imag(v)}
	case bool:
		return v
	case string:
		return v
	case []int:
		items := []any{}
		for _, x := range v {
			items = append(items, x)
		}
		return map[string]any{"$t": "slice", "e": "int", "v": items}
	case map[string]int:
		entries := []any{}
		for k, x := range v {
			entries = append(entries, []any{k, x})
		}
		return map[string]any{"$t": "map", "k": "string", "e": "int", "v": entries}
	case map[string]string:
		entries := []any{}
		for k, x := range v {
			entries = append(entries, []any{k, x})
		}
		return map[string]any{"$t": "map", "k": "string", "e": "string", "v": entries}
	case map[string]any:
		out := map[string]any{}
		for k, x := range v {
			out[k] = specOf(x)
		}
		return out
	case *bytes.Buffer:
		return map[string]any{"$ref": "buf:" + v.String()}
	case *T:
		if v == tVal {
			return map[string]any{"$ref": "tVal"}
		}
	case []*T:
		return map[string]any{"$ref": "tSliceOfNil"}
	case *I:
		return map[string]any{"$ref": "&iVal"}
	case T:
		return map[string]any{"$ref": "T{}"}
	case iter.Seq[int]:
		n := 0
		for range v {
			n++
		}
		return map[string]any{"$ref": fmt.Sprintf("fVal1(%d)", n)}
	case iter.Seq2[int, int]:
		n := 0
		for range v {
			n++
		}
		return map[string]any{"$ref": fmt.Sprintf("fVal2(%d)", n)}
	}
	if reflect.TypeOf(data).Kind() == reflect.Struct && reflect.TypeOf(data).NumField() == 2 {
		return map[string]any{"$ref": "anon_ab"}
	}
	panic(fmt.Sprintf("no spec for %T", data))
}

func TestDumpFixtures(t *testing.T) {
	f, err := os.Create(os.Getenv("FIXTURE_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	emit := func(m map[string]any) {
		m["mode"] = "text"
		if err := enc.Encode(m); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range execTests {
		emit(map[string]any{"name": test.name, "src": test.input, "data": specOf(test.data), "origin": "execTests"})
	}
	for _, test := range cmpTests {
		emit(map[string]any{"name": "empty", "src": fmt.Sprintf("{{if %s}}true{{else}}false{{end}}", test.expr), "data": map[string]any{"$ref": "cmp"}, "origin": "cmpTests"})
	}
	for i := 0; i < len(delimPairs); i += 2 {
		left, right := delimPairs[i], delimPairs[i+1]
		trueLeft, trueRight := left, right
		if left == "" {
			trueLeft = "{{"
		}
		if right == "" {
			trueRight = "}}"
		}
		action := trueLeft + ".Str" + trueRight
		comment := trueLeft + "/*comment*/" + trueRight
		strAction := trueLeft + `"` + trueLeft + `"` + trueRight
		emit(map[string]any{"name": "delims", "src": action + comment + strAction, "ld": left, "rd": right,
			"data": map[string]any{"$t": "struct", "fields": []any{[]any{"Str", "Hello, world"}}}, "origin": "TestDelims"})
	}
	emit(map[string]any{"name": "top", "src": execErrorText, "data": typed("int", 5), "origin": "TestExecError"})
	emit(map[string]any{"name": "root", "src": treeTemplate, "ld": "(", "rd": ")", "exec": "tree", "data": map[string]any{"$ref": "tree"}, "origin": "TestTree"})
	for _, opt := range []string{"missingkey=default", "missingkey=zero", "missingkey=error", "missingkey=invalid"} {
		m := map[string]any{"$t": "map", "k": "string", "e": "int", "v": []any{[]any{"x", 99}}}
		emit(map[string]any{"name": "t1", "src": "{{.x}} {{.y}}", "opts": []string{opt}, "data": m, "origin": "TestMissingMapKey"})
		emit(map[string]any{"name": "t1", "src": "{{.x}} {{.y}}", "opts": []string{opt}, "data": nil, "origin": "TestMissingMapKey"})
	}
	for _, tc := range []struct {
		src  string
		spec any
	}{
		{"{{.MissingField}}", map[string]any{"$ref": "nilT"}},
		{"{{.MissingField}}", map[string]any{"$ref": "&T{}"}},
		{"{{.X}}", map[string]any{"$ref": "nilT"}},
		{"{{.MissingKey}}", map[string]any{"$ref": "nilMapPtr"}},
		{"{{.MissingKey}}", map[string]any{"$ref": "mapPtr"}},
		{"{{ .S }}", map[string]any{"$ref": "B{}"}},
	} {
		emit(map[string]any{"name": "tmpl", "src": tc.src, "data": tc.spec, "origin": "TestEvalFieldErrors"})
	}
	emit(map[string]any{"name": "tmpl", "src": `{{template "tmpl" .}}`, "origin": "TestMaxExecDepth", "data": nil})
	for _, tt := range []string{
		`{{index .Nil 1}}`, `{{index .Slice 2}}`, `{{index .Slice .Two}}`, `{{call .Nil 1}}`, `{{call .PlusOne 1}}`, `{{call .PlusOne .One}}`,
		`{{and (index .Slice 0) true}}`, `{{and .Zero true}}`, `{{and (index .Slice 1) false}}`, `{{and .One false}}`,
		`{{or (index .Slice 0) false}}`, `{{or .Zero false}}`, `{{or (index .Slice 1) true}}`, `{{or .One true}}`,
		`{{not (index .Slice 0)}}`, `{{not .Zero}}`, `{{not (index .Slice 1)}}`, `{{not .One}}`,
		`{{eq (index .Slice 0) .Zero}}`, `{{eq (index .Slice 1) .One}}`, `{{ne (index .Slice 0) .Zero}}`, `{{ne (index .Slice 1) .One}}`,
		`{{ge (index .Slice 0) .One}}`, `{{ge (index .Slice 1) .Zero}}`, `{{gt (index .Slice 0) .One}}`, `{{gt (index .Slice 1) .Zero}}`,
		`{{le (index .Slice 0) .One}}`, `{{le (index .Slice 1) .Zero}}`, `{{lt (index .Slice 0) .One}}`, `{{lt (index .Slice 1) .Zero}}`,
	} {
		data := map[string]any{
			"PlusOne": map[string]any{"$t": "func", "n": "plusone"},
			"Slice":   map[string]any{"$t": "slice", "e": "int", "v": []any{0, 1, 2, 3}},
			"One":     typed("int", 1), "Two": typed("int", 2), "Nil": nil, "Zero": typed("int", 0),
		}
		emit(map[string]any{"name": "tmpl", "src": tt, "data": data, "origin": "TestInterfaceValues"})
	}
	for _, tc := range []struct{ name, input string }{
		{"direct func call panics", "{{doPanic}}"},
		{"indirect func call panics", "{{call doPanic}}"},
		{"direct method call panics", "{{.GetU}}"},
		{"indirect method call panics", "{{call .GetU}}"},
	} {
		emit(map[string]any{"name": "t", "src": tc.input, "data": map[string]any{"$ref": "nilT"}, "origin": "TestExecutePanicDuringCall:" + tc.name})
	}
	for _, in := range []string{"{{call .PanicFunc}}", "{{.NonEmptyInterfaceNil.Method0}}"} {
		emit(map[string]any{"name": "t", "src": in, "data": map[string]any{"$ref": "tVal"}, "origin": "TestExecutePanicDuringCall"})
	}
	for _, in := range []string{"{{call}}", "{{call .True}}", "{{call .BinaryFunc 1}}", "{{call .VariadicFuncInt}}", "{{call .TooFewReturnCountFunc}}",
		"{{call .TooManyReturnCountFunc}}", "{{call .InvalidReturnTypeFunc}}"} {
		emit(map[string]any{"name": "t", "src": in, "data": map[string]any{"$ref": "tVal"}, "nofuncs": true, "origin": "TestFunctionCheckDuringCall"})
	}
	emit(map[string]any{"name": "t", "src": `{{call (len "test")}}`, "data": nil, "nofuncs": true, "origin": "TestFunctionCheckDuringCall"})
	emit(map[string]any{"name": "", "src": "{{ (.)  }}", "data": "result", "origin": "TestIssue31810"})
	emit(map[string]any{"name": "", "src": "{{ (.)  }}", "data": map[string]any{"$t": "func", "n": "result"}, "origin": "TestIssue31810"})
	emit(map[string]any{"name": "", "src": "{{ (call .)  }}", "data": map[string]any{"$t": "func", "n": "result"}, "origin": "TestIssue31810"})
	emit(map[string]any{"name": "", "src": "{{range .}}{{end}}", "data": map[string]any{"$ref": "sendchan"}, "origin": "TestIssue43065"})
	emit(map[string]any{"name": "", "src": "{{ .S }}", "data": map[string]any{"$ref": "B{}"}, "origin": "TestIssue48215"})
	for _, tc := range []string{"{{.X.Y}}", "hello, {{.X.Y}}"} {
		emit(map[string]any{"name": "X", "src": tc, "data": typed("int", 0), "origin": "TestExecuteGivesExecError"})
	}
	_ = strings.Contains
}
