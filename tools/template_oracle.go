// Go oracle for the template differential (tools/template_check.py).
//
// Each stdin line is the hex of a JSON request; each stdout line is
// "OK <hex output>" or "ERR <hex error text> <hex partial output>".
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"
	"text/template/parse"
)

type request struct {
	Mode     string          `json:"mode"`
	Name     string          `json:"name"`
	Src      string          `json:"src"`
	Ld       string          `json:"ld"`
	Rd       string          `json:"rd"`
	PMode    int             `json:"pmode"`
	Funcs    []string        `json:"funcs"`
	Data     json.RawMessage `json:"data"`
	Opts     []string        `json:"opts"`
	Defs     [][2]string     `json:"defs"`
	ExecName string          `json:"exec"`
	NoFuncs  bool            `json:"nofuncs"`
	Twice    bool            `json:"twice"`
}

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 1<<20), 1<<26)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		raw, err := hex.DecodeString(strings.TrimSpace(s.Text()))
		if err != nil {
			panic(err)
		}
		var r request
		if err := json.Unmarshal(raw, &r); err != nil {
			panic(err)
		}
		out, err := handle(&r)
		if err != nil {
			fmt.Fprintf(w, "ERR %s %s\n", hex.EncodeToString([]byte(err.Error())), hex.EncodeToString([]byte(out)))
		} else {
			fmt.Fprintf(w, "OK %s\n", hex.EncodeToString([]byte(out)))
		}
	}
}

func handle(r *request) (out string, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	switch r.Mode {
	case "parse":
		return doParse(r)
	case "text":
		return doText(r)
	case "html":
		return doHTML(r)
	}
	return "", fmt.Errorf("unknown mode %q", r.Mode)
}

func doParse(r *request) (string, error) {
	funcs := map[string]any{}
	for _, f := range r.Funcs {
		funcs[f] = func() {}
	}
	tr := parse.New(r.Name)
	tr.Mode = parse.Mode(r.PMode)
	set := map[string]*parse.Tree{}
	if _, err := tr.Parse(r.Src, r.Ld, r.Rd, set, funcs); err != nil {
		return "", err
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		t := set[n]
		fmt.Fprintf(&sb, "%q parse=%q root=%s\n", n, t.ParseName, t.Root.String())
		if len(t.Root.Nodes) > 0 {
			loc, ctx := t.ErrorContext(t.Root.Nodes[0])
			fmt.Fprintf(&sb, "  ctx %s | %s\n", loc, ctx)
		}
	}
	cp := tr.Copy()
	fmt.Fprintf(&sb, "copy %s\n", cp.Root.String())
	return sb.String(), nil
}

func doText(r *request) (string, error) {
	tmpl := template.New(r.Name)
	if len(r.Opts) > 0 {
		tmpl.Option(r.Opts...)
	}
	tmpl.Delims(r.Ld, r.Rd)
	if !r.NoFuncs {
		tmpl.Funcs(stdFuncs)
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
	var sb strings.Builder
	var err error
	if r.ExecName != "" {
		err = tmpl.ExecuteTemplate(&sb, r.ExecName, data)
	} else {
		err = tmpl.Execute(&sb, data)
	}
	if err != nil {
		return sb.String(), err
	}
	// The set of defined templates is part of the observable result.
	return sb.String(), nil
}
