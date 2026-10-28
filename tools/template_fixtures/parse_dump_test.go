package parse

// Dumps the inputs of Go's own parse and lex test tables as differential
// requests (one JSON object per line) for tools/template_fixtures.py.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestDumpFixtures(t *testing.T) {
	f, err := os.Create(os.Getenv("FIXTURE_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	emit := func(m map[string]any) {
		m["mode"] = "parse"
		if err := enc.Encode(m); err != nil {
			t.Fatal(err)
		}
	}
	funcs := []string{"printf", "contains"}
	for _, test := range parseTests {
		// Go's tests run with maxStackDepth = 3; the oracle uses the default.
		if strings.Contains(test.name, "exceeds limit") {
			continue
		}
		emit(map[string]any{"name": test.name, "src": test.input, "funcs": funcs, "origin": "parseTests"})
	}
	for _, test := range errorTests {
		emit(map[string]any{"name": test.name, "src": test.input, "funcs": funcs, "origin": "errorTests"})
	}
	for _, in := range []string{"{{/*\n\n\n*/}}", "x \r\n\t{{- /* hi */}}", "{{/* hi */ -}}\n\n\ty", "x \r\n\t{{- /* */ -}}\n\n\ty"} {
		emit(map[string]any{"name": "comment", "src": in, "pmode": int(ParseComments), "origin": "TestParseWithComments"})
	}
	for _, in := range []string{`[[.X]]`, `[[/* a comment */]]`, `[[if .X]]y[[else]]z[[end]]`, `[[range .X]][[break]][[continue]][[end]]`, `[[with .X]]y[[end]]`, `[[template "name" .]]`} {
		emit(map[string]any{"name": "test", "src": in, "ld": "[[", "rd": "]]", "pmode": int(ParseComments), "origin": "TestDelimsStringRoundtrip"})
	}
	inp := `{{range .X}}{{break 20}}{{end}}`
	emit(map[string]any{"name": "", "src": inp, "funcs": []string{"break"}, "origin": "TestKeywordsAndFuncs"})
	emit(map[string]any{"name": "", "src": inp, "funcs": []string{}, "origin": "TestKeywordsAndFuncs"})
	emit(map[string]any{"name": "skip func check", "src": "{{fn 1 2}}", "pmode": int(SkipFuncCheck), "origin": "TestSkipFuncCheck"})
	for _, test := range isEmptyTests {
		emit(map[string]any{"name": "root", "src": test.input, "origin": "isEmptyTests"})
	}
	emit(map[string]any{"name": "outer", "src": `a{{block "inner" .}}bar{{.}}baz{{end}}b`, "origin": "TestBlock"})
	for _, test := range lexTests {
		emit(map[string]any{"name": test.name, "src": test.input, "pmode": int(ParseComments | SkipFuncCheck), "origin": "lexTests"})
	}
	for _, test := range lexDelimTests {
		emit(map[string]any{"name": test.name, "src": test.input, "ld": "$$", "rd": "@@", "pmode": int(ParseComments | SkipFuncCheck), "origin": "lexDelimTests"})
	}
	emit(map[string]any{"name": "alnum", "src": "{{hub .host hub}}", "ld": "{{hub", "rd": "hub}}", "pmode": int(SkipFuncCheck), "origin": "TestDelimsAlphaNumeric"})
	emit(map[string]any{"name": "markers", "src": "{{- .x -}} {{- - .x - -}}", "ld": "{{- ", "rd": " -}}", "origin": "TestDelimsAndMarkers"})
	for _, test := range lexPosTests {
		emit(map[string]any{"name": test.name, "src": test.input, "pmode": int(ParseComments | SkipFuncCheck), "origin": "lexPosTests"})
	}
	for _, test := range numberTests {
		emit(map[string]any{"name": "number", "src": "{{" + test.text + "}}", "origin": "numberTests"})
	}
}
