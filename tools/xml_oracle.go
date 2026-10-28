// Go encoding/xml oracle for tools/xml_check.py.
//
// Line protocol: one request per line, tab separated, every byte string as
// lower-case hex; one response line per request.
//
//	T <flags> <input>        decode with Token/RawToken, one record per token
//	E <input>                EscapeText and Escape output
//	K <prefix> <indent> <ops...>   Encoder.EncodeToken sequence
//	M <struct> <prefix> <indent> <value spec>   typed Marshal (see xml_typed.go)
//	U <struct> <input>       typed Unmarshal (see xml_typed.go)
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"
)

func hx(b []byte) string { return hex.EncodeToString(b) }

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// lossy replaces every invalid UTF-8 byte with U+FFFD, one for one.
func lossy(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 {
			b.WriteRune(utf8.RuneError)
		} else {
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

// errText normalizes an error for comparison with the Rust port: invalid
// bytes become U+FFFD and type names lose their package qualifier.
func errText(err error) string {
	s := lossy(err.Error())
	s = strings.ReplaceAll(s, "main.", "")
	return s
}

func recName(n xml.Name) string { return hx([]byte(n.Space)) + "/" + hx([]byte(n.Local)) }

func record(t xml.Token) string {
	switch t := t.(type) {
	case xml.StartElement:
		parts := []string{"S", recName(t.Name)}
		for _, a := range t.Attr {
			parts = append(parts, recName(a.Name)+"="+hx([]byte(a.Value)))
		}
		return strings.Join(parts, " ")
	case xml.EndElement:
		return "E " + recName(t.Name)
	case xml.CharData:
		return "C " + hx(t)
	case xml.Comment:
		return "M " + hx(t)
	case xml.ProcInst:
		return "P " + hx([]byte(t.Target)) + " " + hx(t.Inst)
	case xml.Directive:
		return "D " + hx(t)
	}
	return "?"
}

func decodeMode(flags string, input []byte) string {
	d := xml.NewDecoder(bytes.NewReader(input))
	strict, auto, ent, def, mode := flags[0] == '1', flags[1] == '1', flags[2], flags[3] == '1', flags[4]
	d.Strict = strict
	if auto {
		d.AutoClose = xml.HTMLAutoClose
	}
	switch ent {
	case '1':
		d.Entity = xml.HTMLEntity
	case '2':
		d.Entity = map[string]string{"foo": "bar", "x": "<&>", "e": "", "amp": "NOT", "lt": "NOT"}
	}
	if def {
		d.DefaultSpace = "urn:default"
	}
	var out []string
	d.CharsetReader = func(charset string, r io.Reader) (io.Reader, error) {
		out = append(out, "charset "+hx([]byte(lossy(charset))))
		if charset == "fail" {
			return nil, errors.New("boom")
		}
		return r, nil
	}
	for i := 0; i < 4000; i++ {
		var t xml.Token
		var err error
		switch mode {
		case '1':
			t, err = d.RawToken()
		default:
			t, err = d.Token()
		}
		line, col := d.InputPos()
		pos := fmt.Sprintf(" @%d,%d,%d", d.InputOffset(), line, col)
		if err != nil {
			if err == io.EOF {
				out = append(out, "EOF"+pos)
			} else {
				out = append(out, "ERR "+hx([]byte(errText(err)))+pos)
			}
			break
		}
		out = append(out, record(t)+pos)
		if mode == '2' && i%3 == 2 {
			err := d.Skip()
			line, col := d.InputPos()
			pos := fmt.Sprintf(" @%d,%d,%d", d.InputOffset(), line, col)
			if err != nil {
				if err == io.EOF {
					out = append(out, "SKIP-EOF"+pos)
				} else {
					out = append(out, "SKIP-ERR "+hx([]byte(errText(err)))+pos)
				}
				break
			}
			out = append(out, "SKIP"+pos)
		}
	}
	return strings.Join(out, "|")
}

func escapeMode(input []byte) string {
	var a, b bytes.Buffer
	xml.EscapeText(&a, input)
	xml.Escape(&b, input)
	return hx(a.Bytes()) + " " + hx(b.Bytes())
}

// parseToken decodes "kind:hex:hex..." into a token for EncodeToken.
func parseToken(s string) xml.Token {
	f := strings.Split(s, ":")
	name := func(i int) xml.Name { return xml.Name{Space: string(unhex(f[i])), Local: string(unhex(f[i+1]))} }
	switch f[0] {
	case "S":
		st := xml.StartElement{Name: name(1)}
		for i := 3; i+2 < len(f); i += 3 {
			st.Attr = append(st.Attr, xml.Attr{Name: name(i), Value: string(unhex(f[i+2]))})
		}
		return st
	case "E":
		return xml.EndElement{Name: name(1)}
	case "C":
		return xml.CharData(unhex(f[1]))
	case "M":
		return xml.Comment(unhex(f[1]))
	case "P":
		return xml.ProcInst{Target: string(unhex(f[1])), Inst: unhex(f[2])}
	case "D":
		return xml.Directive(unhex(f[1]))
	}
	return nil
}

func encodeTokens(prefix, indent []byte, ops []string) string {
	var buf bytes.Buffer
	e := xml.NewEncoder(&buf)
	e.Indent(string(prefix), string(indent))
	var out []string
	for _, op := range ops {
		switch op {
		case "FLUSH":
			if err := e.Flush(); err != nil {
				out = append(out, "err "+hx([]byte(errText(err))))
			} else {
				out = append(out, "ok")
			}
			continue
		}
		t := parseToken(op)
		if err := e.EncodeToken(t); err != nil {
			out = append(out, "err "+hx([]byte(errText(err))))
		} else {
			out = append(out, "ok")
		}
	}
	if err := e.Close(); err != nil {
		out = append(out, "close-err "+hx([]byte(errText(err))))
	} else {
		out = append(out, "close-ok")
	}
	return strings.Join(out, "|") + " " + hx(buf.Bytes())
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		var resp string
		func() {
			defer func() {
				if r := recover(); r != nil {
					resp = fmt.Sprintf("PANIC %v", r)
				}
			}()
			resp = respond(f)
		}()
		fmt.Fprintln(w, resp)
	}
}

func respond(f []string) (resp string) {
	{
		switch f[0] {
		case "T":
			resp = decodeMode(f[1], unhex(f[2]))
		case "E":
			resp = escapeMode(unhex(f[1]))
		case "K":
			ops := []string{}
			if len(f) > 3 && f[3] != "" {
				ops = strings.Split(f[3], " ")
			}
			resp = encodeTokens(unhex(f[1]), unhex(f[2]), ops)
		case "M":
			resp = typedMarshal(f[1], unhex(f[2]), unhex(f[3]), f[4])
		case "U":
			resp = typedUnmarshal(f[1], unhex(f[2]))
		default:
			resp = "bad request " + strconv.Quote(f[0])
		}
		return resp
	}
}
