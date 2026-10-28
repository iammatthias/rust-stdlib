// Line-oriented Go encoding/json/jsontext oracle for tools/jsontext_check.py.
//
// Run with GOEXPERIMENT=jsonv2. Binary fields are hex ("-" is empty). Every
// request is "op field..." and produces one response line; see the cases in
// main for the grammar. examples/jsontext_probe.rs answers the same protocol.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

func dec(s string) []byte {
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func enc(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func encs(s string) string { return enc([]byte(s)) }

// errText renders an error: EOF, or the hex text, plus the position of a
// SyntacticError.
func errText(err error) string {
	if err == nil {
		return "nil"
	}
	if err == io.EOF {
		return "EOF"
	}
	var se *jsontext.SyntacticError
	if errors.As(err, &se) && se == err {
		return fmt.Sprintf("E%s@%d@%s", encs(err.Error()), se.ByteOffset, encs(string(se.JSONPointer)))
	}
	return "E" + encs(err.Error())
}

func options(letters string) []jsontext.Options {
	var opts []jsontext.Options
	if letters == "-" {
		return nil
	}
	for _, c := range letters {
		switch c {
		case 'd':
			opts = append(opts, jsontext.AllowDuplicateNames(true))
		case 'u':
			opts = append(opts, jsontext.AllowInvalidUTF8(true))
		case 'h':
			opts = append(opts, jsontext.EscapeForHTML(true))
		case 'j':
			opts = append(opts, jsontext.EscapeForJS(true))
		case 'p':
			opts = append(opts, jsontext.PreserveRawStrings(true))
		case 'i':
			opts = append(opts, jsontext.CanonicalizeRawInts(true))
		case 'f':
			opts = append(opts, jsontext.CanonicalizeRawFloats(true))
		case 'r':
			opts = append(opts, jsontext.ReorderRawObjects(true))
		case 'm':
			opts = append(opts, jsontext.Multiline(true))
		case ':':
			opts = append(opts, jsontext.SpaceAfterColon(true))
		case ',':
			opts = append(opts, jsontext.SpaceAfterComma(true))
		case 'I':
			opts = append(opts, jsontext.WithIndent("  "))
		case 'T':
			opts = append(opts, jsontext.WithIndent("\t"))
		case 'P':
			opts = append(opts, jsontext.WithIndentPrefix("> "))
		case 'X':
			opts = append(opts, jsontext.WithIndent(""))
		case 'D':
			opts = append(opts, jsontext.AllowDuplicateNames(false))
		case 'U':
			opts = append(opts, jsontext.AllowInvalidUTF8(false))
		case 'c':
			opts = append(opts, jsontext.SpaceAfterColon(false))
		case 'k':
			opts = append(opts, jsontext.SpaceAfterComma(false))
		case 'n':
			opts = append(opts, jsontext.Multiline(false))
		case 'e':
			opts = append(opts, jsontext.EscapeForHTML(false))
		case 'q':
			opts = append(opts, jsontext.PreserveRawStrings(false))
		default:
			panic("unknown option letter " + string(c))
		}
	}
	return opts
}

type chunkReader struct {
	data []byte
	n    int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	want := min(len(p), len(c.data))
	if c.n > 0 {
		want = min(want, c.n)
	}
	copy(p, c.data[:want])
	c.data = c.data[want:]
	return want, nil
}

func kindChar(k jsontext.Kind) string {
	if k == 0 {
		return "_"
	}
	return string([]byte{byte(k)})
}

func try(f func() string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "P" + encs(fmt.Sprint(r))
		}
	}()
	return f()
}

func tokText(t jsontext.Token) string {
	k := t.Kind()
	var sb strings.Builder
	sb.WriteString(kindChar(k))
	sb.WriteString(":")
	sb.WriteString(encs(t.String()))
	sb.WriteString(":b")
	sb.WriteString(try(func() string { return strconv.FormatBool(t.Bool()) }))
	sb.WriteString(":f")
	sb.WriteString(try(func() string {
		f, err := t.Float()
		return fmt.Sprintf("%x/%s", math.Float64bits(f), errText(err))
	}))
	sb.WriteString(":g")
	sb.WriteString(try(func() string {
		f, err := t.Float32()
		return fmt.Sprintf("%x/%s", math.Float32bits(f), errText(err))
	}))
	sb.WriteString(":i")
	sb.WriteString(try(func() string {
		i, err := t.Int()
		return fmt.Sprintf("%d/%s", i, errText(err))
	}))
	sb.WriteString(":u")
	sb.WriteString(try(func() string {
		u, err := t.Uint()
		return fmt.Sprintf("%d/%s", u, errText(err))
	}))
	return sb.String()
}

func stackText(depth int, index func(int) (jsontext.Kind, int64)) string {
	var parts []string
	for i := 0; i <= depth; i++ {
		k, n := index(i)
		parts = append(parts, kindChar(k)+strconv.FormatInt(n, 10))
	}
	return strings.Join(parts, ",")
}

func decodeOp(chunk, optLetters, ops string, doc []byte) string {
	var rd io.Reader
	opts := options(optLetters)
	var d *jsontext.Decoder
	if chunk == "b" {
		d = jsontext.NewDecoder(bytes.NewBuffer(doc), opts...)
	} else {
		n, _ := strconv.Atoi(chunk)
		rd = &chunkReader{data: doc, n: n}
		d = jsontext.NewDecoder(rd, opts...)
	}
	var recs []string
	for step := 0; step < 400; step++ {
		op := ops[step%len(ops)]
		var res string
		var err error
		stop := false
		switch op {
		case 'T':
			var t jsontext.Token
			t, err = d.ReadToken()
			if err == nil {
				res = "t" + tokText(t)
			}
		case 'V':
			var v jsontext.Value
			v, err = d.ReadValue()
			if err == nil {
				res = "v" + enc(v)
			}
		case 'D':
			for err == nil {
				_, err = d.ReadToken()
			}
		case 'K':
			res = "k" + kindChar(d.PeekKind())
		case 'S':
			err = d.SkipValue()
			if err == nil {
				res = "s"
			}
		}
		if err != nil {
			res = "x" + errText(err)
			stop = true
		}
		rec := fmt.Sprintf("%c:%s|o%d|d%d|p%s|i%s|u%s", op, res, d.InputOffset(), d.StackDepth(),
			encs(string(d.StackPointer())), stackText(d.StackDepth(), d.StackIndex), enc(d.UnreadBuffer()))
		recs = append(recs, rec)
		if stop {
			break
		}
	}
	return strings.Join(recs, " ")
}

type plainWriter struct{ buf *bytes.Buffer }

func (w plainWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }

func parseToken(op string) (tok jsontext.Token, ok bool) {
	switch op[0] {
	case 'n':
		return jsontext.Null, true
	case 'f':
		return jsontext.False, true
	case 't':
		return jsontext.True, true
	case '{':
		return jsontext.BeginObject, true
	case '}':
		return jsontext.EndObject, true
	case '[':
		return jsontext.BeginArray, true
	case ']':
		return jsontext.EndArray, true
	case 's':
		return jsontext.String(string(dec(op[1:]))), true
	case 'i':
		n, _ := strconv.ParseInt(op[1:], 10, 64)
		return jsontext.Int(n), true
	case 'u':
		n, _ := strconv.ParseUint(op[1:], 10, 64)
		return jsontext.Uint(n), true
	case 'F':
		n, _ := strconv.ParseUint(op[1:], 16, 64)
		return jsontext.Float(math.Float64frombits(n)), true
	case 'G':
		n, _ := strconv.ParseUint(op[1:], 16, 32)
		return jsontext.Float32(math.Float32frombits(uint32(n))), true
	case 'b':
		return jsontext.Bool(op[1] == '1'), true
	case 'x':
		return jsontext.Token{}, true
	}
	return jsontext.Token{}, false
}

func encodeOp(mode, optLetters string, ops []string) string {
	var buf bytes.Buffer
	opts := options(optLetters)
	var e *jsontext.Encoder
	if mode == "b" {
		e = jsontext.NewEncoder(&buf, opts...)
	} else {
		e = jsontext.NewEncoder(plainWriter{&buf}, opts...)
	}
	var recs []string
	for _, op := range ops {
		var res string
		switch op[0] {
		case 't':
			tok, _ := parseToken(op[1:])
			res = try(func() string { return errText(e.WriteToken(tok)) })
		case 'v':
			res = try(func() string { return errText(e.WriteValue(jsontext.Value(dec(op[1:])))) })
		case '?':
			res = "q"
		}
		recs = append(recs, fmt.Sprintf("%s|o%d|d%d|p%s|i%s", res, e.OutputOffset(), e.StackDepth(),
			encs(string(e.StackPointer())), stackText(e.StackDepth(), e.StackIndex)))
	}
	final := "-"
	if e.StackDepth() == 0 {
		final = enc(buf.Bytes())
	}
	return strings.Join(recs, " ") + " w=" + final
}

func valueOp(op, optLetters string, doc []byte) string {
	opts := options(optLetters)
	v := jsontext.Value(append([]byte(nil), doc...))
	switch op {
	case "valid":
		return strconv.FormatBool(v.IsValid(opts...))
	case "kind":
		return kindChar(v.Kind())
	case "string":
		return encs(v.String())
	case "clone":
		return enc(v.Clone())
	case "marshal":
		b, err := v.MarshalJSON()
		return fmt.Sprintf("%s %s", enc(b), errText(err))
	case "appendformat":
		out, err := jsontext.AppendFormat([]byte("pre"), v, opts...)
		return fmt.Sprintf("%s %s", enc(out), errText(err))
	}
	var err error
	switch op {
	case "format":
		err = v.Format(opts...)
	case "compact":
		err = v.Compact(opts...)
	case "indent":
		err = v.Indent(opts...)
	case "canon":
		err = v.Canonicalize(opts...)
	default:
		panic("unknown value op " + op)
	}
	return fmt.Sprintf("%s %s", enc(v), errText(err))
}

func pointerOp(op string, p jsontext.Pointer, arg string) string {
	switch op {
	case "valid":
		return strconv.FormatBool(p.IsValid())
	case "parent":
		return encs(string(p.Parent()))
	case "last":
		return encs(p.LastToken())
	case "append":
		return encs(string(p.AppendToken(arg)))
	case "contains":
		return strconv.FormatBool(p.Contains(jsontext.Pointer(arg)))
	case "tokens":
		var parts []string
		for t := range p.Tokens() {
			parts = append(parts, encs(t))
		}
		return strconv.Itoa(len(parts)) + " " + strings.Join(parts, ",")
	}
	panic("unknown pointer op " + op)
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<28)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		f := strings.Split(sc.Text(), " ")
		var out string
		func() {
			defer func() {
				if r := recover(); r != nil {
					out = "panic " + encs(fmt.Sprint(r))
				}
			}()
			switch f[0] {
			case "decode":
				out = decodeOp(f[1], f[2], f[3], dec(f[4]))
			case "encode":
				out = encodeOp(f[1], f[2], f[3:])
			case "value":
				out = valueOp(f[1], f[2], dec(f[3]))
			case "quote":
				b, err := jsontext.AppendQuote([]byte("pre"), dec(f[1]))
				out = enc(b) + " " + errText(err)
			case "unquote":
				b, err := jsontext.AppendUnquote([]byte("pre"), dec(f[1]))
				out = enc(b) + " " + errText(err)
			case "float":
				bits, _ := strconv.Atoi(f[1])
				n, _ := strconv.ParseUint(f[2], 16, 64)
				v := math.Float64frombits(n)
				if bits == 32 {
					v = float64(math.Float32frombits(uint32(n)))
				}
				out = encs(string(jsontext.AppendFloat([]byte("pre"), v, bits)))
			case "pointer":
				out = pointerOp(f[1], jsontext.Pointer(dec(f[2])), string(dec(f[3])))
			case "options":
				out = optionsOp(f[1], f[2])
			case "tokacc":
				out = tokAccOp(f[1], f[2])
			default:
				out = "unknown op " + f[0]
			}
		}()
		fmt.Fprintln(w, out)
	}
}

// optionsOp round-trips WithIndent validation and Options.
func optionsOp(op, arg string) string {
	switch op {
	case "indent":
		return try(func() string { _ = jsontext.WithIndent(string(dec(arg))); return "ok" })
	case "prefix":
		return try(func() string { _ = jsontext.WithIndentPrefix(string(dec(arg))); return "ok" })
	}
	panic("unknown options op " + op)
}

// tokAccOp builds a Token with one of the constructors and describes the
// results of all its accessors.
func tokAccOp(ctor, arg string) string {
	var tok jsontext.Token
	switch ctor {
	case "zero":
	case "null":
		tok = jsontext.Null
	case "false":
		tok = jsontext.False
	case "true":
		tok = jsontext.True
	case "bo":
		tok = jsontext.BeginObject
	case "eo":
		tok = jsontext.EndObject
	case "ba":
		tok = jsontext.BeginArray
	case "ea":
		tok = jsontext.EndArray
	case "bool":
		tok = jsontext.Bool(arg == "1")
	case "string":
		tok = jsontext.String(string(dec(arg)))
	case "f32":
		n, _ := strconv.ParseUint(arg, 16, 32)
		tok = jsontext.Float32(math.Float32frombits(uint32(n)))
	case "f64":
		n, _ := strconv.ParseUint(arg, 16, 64)
		tok = jsontext.Float(math.Float64frombits(n))
	case "int":
		n, _ := strconv.ParseInt(arg, 10, 64)
		tok = jsontext.Int(n)
	case "uint":
		n, _ := strconv.ParseUint(arg, 10, 64)
		tok = jsontext.Uint(n)
	case "raw":
		d := jsontext.NewDecoder(bytes.NewBuffer(dec(arg)))
		var err error
		tok, err = d.ReadToken()
		if err != nil {
			return "decode error " + errText(err)
		}
	default:
		panic("unknown token constructor " + ctor)
	}
	return tokText(tok) + " clone=" + tokText(tok.Clone())
}
