// gob_oracle is the Go side of the encoding/gob differential. It reads one
// request per line from stdin and answers one line each:
//
//	ENC (key literal)...     encode the values with one Encoder: OK hex | ERR msg hex
//	DEC hex key[=init]...    decode the stream into the types: printed values | ERR msg
//
// Types come from tools/gob_types_gen.go; literals are defined in
// tools/gob_spec.py. Run with:
//
//	go run tools/gob_oracle.go tools/gob_types_gen.go
package main

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// GE implements GobEncoder with a value receiver.
type GE struct {
	A int
	B []byte
}

func (g GE) GobEncode() ([]byte, error) {
	if g.A < 0 {
		return nil, errors.New("negative A")
	}
	return append([]byte(strconv.Itoa(g.A)+"|"), g.B...), nil
}

func (g *GE) GobDecode(b []byte) error {
	s := string(b)
	i := strings.IndexByte(s, '|')
	if i < 0 {
		return errors.New("bad GE")
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return errors.New("bad GE number")
	}
	g.A, g.B = n, []byte(s[i+1:])
	return nil
}

// BM implements encoding.BinaryMarshaler.
type BM struct {
	N uint16
	S []byte
}

func (b BM) MarshalBinary() ([]byte, error) {
	return append([]byte{byte(b.N >> 8), byte(b.N)}, b.S...), nil
}

func (b *BM) UnmarshalBinary(d []byte) error {
	if len(d) < 2 {
		return errors.New("short BM")
	}
	b.N = uint16(d[0])<<8 | uint16(d[1])
	b.S = append([]byte(nil), d[2:]...)
	return nil
}

// GP implements GobEncoder with a pointer receiver.
type GP struct {
	A int
	B []byte
}

func (g *GP) GobEncode() ([]byte, error) {
	if g.A < 0 {
		return nil, errors.New("negative A")
	}
	return append([]byte(strconv.Itoa(g.A)+"|"), g.B...), nil
}

func (g *GP) GobDecode(b []byte) error {
	s := string(b)
	i := strings.IndexByte(s, '|')
	if i < 0 {
		return errors.New("bad GP")
	}
	n, err := strconv.Atoi(s[:i])
	if err != nil {
		return errors.New("bad GP number")
	}
	g.A, g.B = n, []byte(s[i+1:])
	return nil
}

var (
	typeTable map[string]reflect.Type
	keyOf     = map[reflect.Type]string{}
)

type scan struct {
	s string
	i int
}

func (p *scan) peek() byte {
	if p.i >= len(p.s) {
		return 0
	}
	return p.s[p.i]
}

func (p *scan) eat(c byte) bool {
	if p.peek() == c {
		p.i++
		return true
	}
	return false
}

func (p *scan) must(c byte) {
	if !p.eat(c) {
		panic(fmt.Sprintf("literal: expected %q at %d in %q", c, p.i, p.s))
	}
}

func (p *scan) atom() string {
	j := p.i
	for p.i < len(p.s) && !strings.ContainsRune(",]};=:)", rune(p.s[p.i])) {
		p.i++
	}
	return p.s[j:p.i]
}

func unhex(s string) []byte {
	if s == "-" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex " + s)
	}
	return b
}

func hx(b []byte) string {
	if len(b) == 0 {
		return "-"
	}
	return hex.EncodeToString(b)
}

func fill(p *scan, v reflect.Value) {
	t := v.Type()
	switch t.Kind() {
	case reflect.Bool:
		v.SetBool(p.atom() == "t")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(p.atom(), 10, 64)
		if err != nil {
			panic(err)
		}
		v.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(p.atom(), 10, 64)
		if err != nil {
			panic(err)
		}
		v.SetUint(n)
	case reflect.Float32:
		n, err := strconv.ParseUint(p.atom(), 10, 32)
		if err != nil {
			panic(err)
		}
		v.SetFloat(float64(math.Float32frombits(uint32(n))))
	case reflect.Float64:
		n, err := strconv.ParseUint(p.atom(), 10, 64)
		if err != nil {
			panic(err)
		}
		v.SetFloat(math.Float64frombits(n))
	case reflect.Complex128:
		re, err := strconv.ParseUint(p.atom(), 10, 64)
		if err != nil {
			panic(err)
		}
		p.must(':')
		im, err := strconv.ParseUint(p.atom(), 10, 64)
		if err != nil {
			panic(err)
		}
		v.SetComplex(complex(math.Float64frombits(re), math.Float64frombits(im)))
	case reflect.String:
		v.SetString(string(unhex(p.atom())))
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			a := p.atom()
			if a != "n" {
				v.SetBytes(unhex(a))
			}
			return
		}
		if p.peek() == 'n' {
			p.atom()
			return
		}
		p.must('[')
		var items []reflect.Value
		for !p.eat(']') {
			e := reflect.New(t.Elem()).Elem()
			fill(p, e)
			items = append(items, e)
			p.eat(',')
		}
		s := reflect.MakeSlice(t, len(items), len(items))
		for i, e := range items {
			s.Index(i).Set(e)
		}
		v.Set(s)
	case reflect.Array:
		p.must('[')
		for i := 0; i < t.Len(); i++ {
			fill(p, v.Index(i))
			p.eat(',')
		}
		p.must(']')
	case reflect.Map:
		if p.peek() == 'n' {
			p.atom()
			return
		}
		p.must('m')
		p.must('[')
		m := reflect.MakeMap(t)
		for !p.eat(']') {
			k := reflect.New(t.Key()).Elem()
			fill(p, k)
			p.must('=')
			e := reflect.New(t.Elem()).Elem()
			fill(p, e)
			m.SetMapIndex(k, e)
			p.eat(';')
		}
		v.Set(m)
	case reflect.Pointer:
		if p.peek() == 'n' {
			p.atom()
			return
		}
		p.must('&')
		n := reflect.New(t.Elem())
		fill(p, n.Elem())
		v.Set(n)
	case reflect.Interface:
		if p.peek() == 'n' {
			p.atom()
			return
		}
		p.must('@')
		j := strings.IndexByte(p.s[p.i:], ':')
		key := p.s[p.i : p.i+j]
		p.i += j
		p.must(':')
		ct, ok := typeTable[key]
		if !ok {
			panic("unknown interface key " + key)
		}
		c := reflect.New(ct).Elem()
		fill(p, c)
		v.Set(c)
	case reflect.Struct:
		p.must('{')
		for i := 0; i < t.NumField(); i++ {
			if t.Field(i).IsExported() {
				fill(p, v.Field(i))
			} else {
				p.must('_')
			}
			p.eat(',')
		}
		p.must('}')
	default:
		panic("cannot fill " + t.String())
	}
}

func pv(v reflect.Value) string {
	t := v.Type()
	switch t.Kind() {
	case reflect.Bool:
		if v.Bool() {
			return "t"
		}
		return "f"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10)
	case reflect.Float32:
		return strconv.FormatUint(uint64(math.Float32bits(float32(v.Float()))), 10)
	case reflect.Float64:
		return strconv.FormatUint(math.Float64bits(v.Float()), 10)
	case reflect.Complex128:
		c := v.Complex()
		return strconv.FormatUint(math.Float64bits(real(c)), 10) + ":" + strconv.FormatUint(math.Float64bits(imag(c)), 10)
	case reflect.String:
		return hx([]byte(v.String()))
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return hx(v.Bytes())
		}
		if v.IsNil() {
			return "n"
		}
		parts := make([]string, v.Len())
		for i := range parts {
			parts[i] = pv(v.Index(i))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case reflect.Array:
		parts := make([]string, v.Len())
		for i := range parts {
			parts[i] = pv(v.Index(i))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case reflect.Map:
		if v.IsNil() {
			return "n"
		}
		var items []string
		for it := v.MapRange(); it.Next(); {
			items = append(items, pv(it.Key())+"="+pv(it.Value()))
		}
		sort.Strings(items)
		return "m[" + strings.Join(items, ";") + "]"
	case reflect.Pointer:
		if v.IsNil() {
			return "n"
		}
		return "&" + pv(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return "n"
		}
		e := v.Elem()
		key, ok := keyOf[e.Type()]
		if !ok {
			key = "?" + e.Type().String()
		}
		return "@" + key + ":" + pv(e)
	case reflect.Struct:
		parts := make([]string, t.NumField())
		for i := range parts {
			if t.Field(i).IsExported() {
				parts[i] = pv(v.Field(i))
			} else {
				parts[i] = "_"
			}
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return "?" + t.String()
}

func encode(f []string) string {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	for i := 0; i+1 < len(f); i += 2 {
		typ, ok := typeTable[f[i]]
		if !ok {
			return "unknown type " + f[i]
		}
		v := reflect.New(typ).Elem()
		fill(&scan{s: f[i+1]}, v)
		if err := enc.EncodeValue(v); err != nil {
			return "ERR " + err.Error() + " " + hx(buf.Bytes())
		}
	}
	return "OK " + hx(buf.Bytes())
}

func decode(f []string) string {
	dec := gob.NewDecoder(bytes.NewReader(unhex(f[0])))
	var outs []string
	for _, spec := range f[1:] {
		key, init, _ := strings.Cut(spec, "=")
		typ, ok := typeTable[key]
		if !ok {
			return "unknown type " + key
		}
		p := reflect.New(typ)
		if init != "" {
			fill(&scan{s: init}, p.Elem())
		}
		if err := dec.DecodeValue(p); err != nil {
			outs = append(outs, "ERR "+err.Error())
			return strings.Join(outs, " ")
		}
		outs = append(outs, pv(p.Elem()))
	}
	if err := dec.Decode(nil); err == io.EOF {
		outs = append(outs, "EOF")
	} else if err != nil {
		outs = append(outs, "ERR "+err.Error())
	} else {
		outs = append(outs, "MORE")
	}
	return strings.Join(outs, " ")
}

func handle(f []string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Sprint("PANIC ", r)
		}
	}()
	switch f[0] {
	case "ENC":
		return encode(f[1:])
	case "DEC":
		return decode(f[1:])
	}
	return "unknown request " + f[0]
}

func main() {
	var ifaces []string
	typeTable, ifaces = genTypes()
	for _, k := range ifaces {
		if _, dup := keyOf[typeTable[k]]; !dup {
			keyOf[typeTable[k]] = k
		}
	}
	for _, k := range ifaces {
		gob.Register(reflect.Zero(typeTable[k]).Interface())
	}
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	for {
		line, err := in.ReadString('\n')
		if line = strings.TrimRight(line, "\n"); line != "" {
			fmt.Println(handle(strings.Fields(line)))
		}
		if err != nil {
			return
		}
	}
}
