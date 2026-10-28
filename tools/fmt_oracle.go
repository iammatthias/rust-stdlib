// Go reference implementation for tools/fmt_check.py.
//
// Reads one request per line (tab separated fields) and prints one result
// line each. Arguments are written in a small token language that both this
// oracle and examples/fmt_probe.rs build values from:
//
//	nil | bool:0|1 | int:N ... uintptr:N | float32:HEXBITS | float64:HEXBITS
//	complex64:HEXBITS,HEXBITS | complex128:... | string:HEX
//	slice:ELEMTYPEHEX:N:NIL item*N | array:ELEMTYPEHEX:N item*N
//	map:KEYHEX:VALHEX:N:NIL (key value)*N
//	struct:N (NAMEHEX TYPEHEX value)*N          (anonymous struct type)
//	ptr:ELEMTYPEHEX:0|1 [elem] | raw:TYPEHEX:0|1 (chan, func, unsafe.Pointer)
//	named:NAME[:PAYLOAD]                         (the catalog types below)
//
// Requests:
//
//	P fmt args...   Sprintf        S args...   Sprint       L args...   Sprintln
//	E fmt args...   Errorf (message and Unwrap results)
//	Z mode input fmt dests          Sscan/Sscanln/Sscanf into typed destinations
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"unsafe"
)

// ---- catalog of named types (mirrored in examples/fmt_probe.rs)

type MyInt int
type MyUint uint
type MyFloat float64
type MyStr string
type MyBool bool
type MyBytes []byte
type MyC complex128

type SInt int

func (s SInt) String() string { return "SInt(" + strconv.Itoa(int(s)) + ")" }

type SStr string

func (s SStr) String() string { return "<" + string(s) + ">" }

type ErrT struct{ Code int }

func (e ErrT) Error() string { return "E" + strconv.Itoa(e.Code) }

type GoS struct{ A int }

func (g GoS) GoString() string { return "GoS!" + strconv.Itoa(g.A) }
func (g GoS) String() string   { return "S" + strconv.Itoa(g.A) }

type Fmt struct{ N int }

func (f Fmt) Format(s fmt.State, verb rune) {
	w, wok := s.Width()
	p, pok := s.Precision()
	fmt.Fprintf(s, "<%s|%d|%v %d|%v %d|%v%v%v%v%v>", fmt.FormatString(s, verb), f.N, wok, w, pok, p,
		s.Flag('+'), s.Flag('-'), s.Flag('#'), s.Flag(' '), s.Flag('0'))
}

type PanicS int

func (p PanicS) String() string { panic("boom") }

type PanicE struct{}

func (p PanicE) Error() string { panic(errors.New("bad")) }

type NP struct{ s string }

func (p *NP) String() string { return "np" + p.s }

type PtrS struct{ A int }

func (p *PtrS) String() string { return "PtrS" + strconv.Itoa(p.A) }

type Pt struct{ X, Y int }

type Mixed struct {
	A int
	b SInt
	C SInt
	d interface{}
	E interface{}
}

type Wrap struct {
	P *Pt
	I interface{}
	S []SInt
}

type Gen struct{ V any }

type cs struct{ s string }

func (c *cs) Scan(state fmt.ScanState, verb rune) error {
	w, ok := state.Width()
	tok, err := state.Token(true, nil)
	if err != nil {
		return err
	}
	c.s = strings.ToUpper(string(tok))
	if ok {
		c.s += "/" + strconv.Itoa(w)
	}
	return nil
}

var ifaceT = reflect.TypeOf((*interface{})(nil)).Elem()
var errorT = reflect.TypeOf((*error)(nil)).Elem()
var stringerT = reflect.TypeOf((*fmt.Stringer)(nil)).Elem()

var basic = map[string]reflect.Type{}

func init() {
	for _, v := range []any{false, int(0), int8(0), int16(0), int32(0), int64(0), uint(0), uint8(0), uint16(0),
		uint32(0), uint64(0), uintptr(0), float32(0), float64(0), complex64(0), complex128(0), "",
		MyInt(0), MyUint(0), MyFloat(0), MyStr(""), MyBool(false), MyBytes(nil), MyC(0), SInt(0), SStr(""),
		ErrT{}, GoS{}, Fmt{}, PanicS(0), PanicE{}, NP{}, PtrS{}, Pt{}, Mixed{}, Wrap{}, Gen{}} {
		t := reflect.TypeOf(v)
		basic[t.String()] = t
	}
	basic["interface {}"] = ifaceT
	basic["error"] = errorT
	basic["fmt.Stringer"] = stringerT
	basic["unsafe.Pointer"] = reflect.TypeOf(unsafe.Pointer(nil))
}

func parseType(s string) reflect.Type {
	switch {
	case strings.HasPrefix(s, "[]"):
		return reflect.SliceOf(parseType(s[2:]))
	case strings.HasPrefix(s, "["):
		i := strings.IndexByte(s, ']')
		n, _ := strconv.Atoi(s[1:i])
		return reflect.ArrayOf(n, parseType(s[i+1:]))
	case strings.HasPrefix(s, "map["):
		depth := 0
		for i := 3; i < len(s); i++ {
			if s[i] == '[' {
				depth++
			} else if s[i] == ']' {
				depth--
				if depth == 0 {
					return reflect.MapOf(parseType(s[4:i]), parseType(s[i+1:]))
				}
			}
		}
	case strings.HasPrefix(s, "*"):
		return reflect.PointerTo(parseType(s[1:]))
	case strings.HasPrefix(s, "chan "):
		return reflect.ChanOf(reflect.BothDir, parseType(s[5:]))
	case s == "func()":
		return reflect.FuncOf(nil, nil, false)
	}
	if t, ok := basic[s]; ok {
		return t
	}
	panic("unknown type " + s)
}

type toks struct {
	t []string
	i int
}

func (k *toks) next() string {
	s := k.t[k.i]
	k.i++
	return s
}

func unhex(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

func bits(s string, size int) uint64 {
	u, err := strconv.ParseUint(s, 16, size)
	if err != nil {
		panic(err)
	}
	return u
}

// value parses one value. The result is the zero reflect.Value for nil.
func value(k *toks) reflect.Value {
	tok := k.next()
	if tok == "nil" {
		return reflect.Value{}
	}
	p := strings.Split(tok, ":")
	switch p[0] {
	case "bool":
		return reflect.ValueOf(p[1] == "1")
	case "int", "int8", "int16", "int32", "int64":
		n, err := strconv.ParseInt(p[1], 10, 64)
		if err != nil {
			panic(err)
		}
		return reflect.ValueOf(n).Convert(basic[p[0]])
	case "uint", "uint8", "uint16", "uint32", "uint64", "uintptr":
		n, err := strconv.ParseUint(p[1], 10, 64)
		if err != nil {
			panic(err)
		}
		return reflect.ValueOf(n).Convert(basic[p[0]])
	case "float32":
		return reflect.ValueOf(math.Float32frombits(uint32(bits(p[1], 32))))
	case "float64":
		return reflect.ValueOf(math.Float64frombits(bits(p[1], 64)))
	case "complex64":
		q := strings.Split(p[1], ",")
		return reflect.ValueOf(complex(math.Float32frombits(uint32(bits(q[0], 32))), math.Float32frombits(uint32(bits(q[1], 32)))))
	case "complex128":
		q := strings.Split(p[1], ",")
		return reflect.ValueOf(complex(math.Float64frombits(bits(q[0], 64)), math.Float64frombits(bits(q[1], 64))))
	case "string":
		return reflect.ValueOf(unhex(p[1]))
	case "slice":
		et := parseType(unhex(p[1]))
		n := atoi(p[2])
		if p[3] == "1" {
			return reflect.Zero(reflect.SliceOf(et))
		}
		s := reflect.MakeSlice(reflect.SliceOf(et), n, n)
		for i := 0; i < n; i++ {
			if v := value(k); v.IsValid() {
				s.Index(i).Set(v)
			}
		}
		return s
	case "array":
		et := parseType(unhex(p[1]))
		n := atoi(p[2])
		a := reflect.New(reflect.ArrayOf(n, et)).Elem()
		for i := 0; i < n; i++ {
			if v := value(k); v.IsValid() {
				a.Index(i).Set(v)
			}
		}
		return a
	case "map":
		kt, vt := parseType(unhex(p[1])), parseType(unhex(p[2]))
		n := atoi(p[3])
		mt := reflect.MapOf(kt, vt)
		if p[4] == "1" {
			return reflect.Zero(mt)
		}
		m := reflect.MakeMapWithSize(mt, n)
		for i := 0; i < n; i++ {
			kv, vv := value(k), value(k)
			if !kv.IsValid() {
				kv = reflect.Zero(kt)
			}
			if !vv.IsValid() {
				vv = reflect.Zero(vt)
			}
			m.SetMapIndex(kv, vv)
		}
		return m
	case "struct":
		n := atoi(p[1])
		var fields []reflect.StructField
		var vals []reflect.Value
		for i := 0; i < n; i++ {
			name := unhex(k.next())
			ft := parseType(unhex(k.next()))
			fields = append(fields, reflect.StructField{Name: name, Type: ft})
			vals = append(vals, value(k))
		}
		sv := reflect.New(reflect.StructOf(fields)).Elem()
		for i, v := range vals {
			if v.IsValid() {
				sv.Field(i).Set(v)
			}
		}
		return sv
	case "ptr":
		et := parseType(unhex(p[1]))
		if p[2] == "0" {
			return reflect.Zero(reflect.PointerTo(et))
		}
		np := reflect.New(et)
		if v := value(k); v.IsValid() {
			np.Elem().Set(v)
		}
		return np
	case "raw":
		t := parseType(unhex(p[1]))
		if p[2] == "0" {
			return reflect.Zero(t)
		}
		switch t.Kind() {
		case reflect.Chan:
			return reflect.MakeChan(t, 0)
		case reflect.Func:
			return reflect.MakeFunc(t, func([]reflect.Value) []reflect.Value { return nil })
		default:
			x := 5
			return reflect.ValueOf(unsafe.Pointer(&x))
		}
	case "named":
		return named(p, k)
	}
	panic("bad token " + tok)
}

func named(p []string, k *toks) reflect.Value {
	arg := func() int64 {
		n, _ := strconv.ParseInt(p[2], 10, 64)
		return n
	}
	switch p[1] {
	case "MyInt":
		return reflect.ValueOf(MyInt(arg()))
	case "MyUint":
		return reflect.ValueOf(MyUint(arg()))
	case "MyFloat":
		return reflect.ValueOf(MyFloat(math.Float64frombits(bits(p[2], 64))))
	case "MyStr":
		return reflect.ValueOf(MyStr(unhex(p[2])))
	case "MyBool":
		return reflect.ValueOf(MyBool(p[2] == "1"))
	case "MyBytes":
		if p[2] == "nil" {
			return reflect.ValueOf(MyBytes(nil))
		}
		return reflect.ValueOf(MyBytes(unhex(p[2])))
	case "MyC":
		q := strings.Split(p[2], ",")
		return reflect.ValueOf(MyC(complex(math.Float64frombits(bits(q[0], 64)), math.Float64frombits(bits(q[1], 64)))))
	case "SInt":
		return reflect.ValueOf(SInt(arg()))
	case "SStr":
		return reflect.ValueOf(SStr(unhex(p[2])))
	case "ErrT":
		return reflect.ValueOf(ErrT{int(arg())})
	case "GoS":
		return reflect.ValueOf(GoS{int(arg())})
	case "Fmt":
		return reflect.ValueOf(Fmt{int(arg())})
	case "PanicS":
		return reflect.ValueOf(PanicS(arg()))
	case "PanicE":
		return reflect.ValueOf(PanicE{})
	case "NilPS": // *NP: nil, or non-nil with the hex string
		if p[2] == "0" {
			return reflect.ValueOf((*NP)(nil))
		}
		return reflect.ValueOf(&NP{unhex(p[3])})
	case "PtrS": // value (not pointer) of a type with pointer-receiver String
		return reflect.ValueOf(PtrS{int(arg())})
	case "PtrSP":
		return reflect.ValueOf(&PtrS{int(arg())})
	case "Pt":
		return reflect.ValueOf(Pt{int(arg()), int(atoi(p[3]))})
	case "PtP":
		return reflect.ValueOf(&Pt{int(arg()), int(atoi(p[3]))})
	case "Mixed": // A b C d E: d and E are value tokens
		m := Mixed{A: int(arg()), b: SInt(atoi(p[3])), C: SInt(atoi(p[4]))}
		d := value(k)
		e := value(k)
		if d.IsValid() {
			f := reflect.ValueOf(&m).Elem().Field(3)
			reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(d)
		}
		if e.IsValid() {
			m.E = e.Interface()
		}
		return reflect.ValueOf(m)
	case "Wrap": // P(0/1 x y) I(value) S(n ints)
		w := Wrap{}
		if p[2] == "1" {
			w.P = &Pt{atoi(p[3]), atoi(p[4])}
		}
		if i := value(k); i.IsValid() {
			w.I = i.Interface()
		}
		for i := 0; i < atoi(p[5]); i++ {
			w.S = append(w.S, SInt(atoi(strings.Split(k.next(), ":")[1])))
		}
		return reflect.ValueOf(w)
	case "Gen":
		g := Gen{}
		if i := value(k); i.IsValid() {
			g.V = i.Interface()
		}
		return reflect.ValueOf(g)
	case "ErrNew":
		return reflect.ValueOf(errors.New(unhex(p[2])))
	case "ErrWrap": // fmt.Errorf("w:%w", ErrT{n})
		return reflect.ValueOf(fmt.Errorf("w:%w", ErrT{int(arg())}))
	}
	panic("bad named " + p[1])
}

func args(fields []string) []any {
	var out []any
	for _, f := range fields {
		k := &toks{t: strings.Fields(f)}
		if v := value(k); v.IsValid() {
			out = append(out, v.Interface())
		} else {
			out = append(out, nil)
		}
	}
	return out
}

// ---- scanning

func canon(v any) string {
	switch x := v.(type) {
	case *bool:
		return fmt.Sprint(*x)
	case *int:
		return fmt.Sprint(*x)
	case *int8:
		return fmt.Sprint(*x)
	case *int16:
		return fmt.Sprint(*x)
	case *int32:
		return fmt.Sprint(*x)
	case *int64:
		return fmt.Sprint(*x)
	case *uint:
		return fmt.Sprint(*x)
	case *uint8:
		return fmt.Sprint(*x)
	case *uint16:
		return fmt.Sprint(*x)
	case *uint32:
		return fmt.Sprint(*x)
	case *uint64:
		return fmt.Sprint(*x)
	case *uintptr:
		return fmt.Sprint(*x)
	case *float32:
		return fmt.Sprintf("%08x", math.Float32bits(*x))
	case *float64:
		return fmt.Sprintf("%016x", math.Float64bits(*x))
	case *complex64:
		return fmt.Sprintf("%08x,%08x", math.Float32bits(real(*x)), math.Float32bits(imag(*x)))
	case *complex128:
		return fmt.Sprintf("%016x,%016x", math.Float64bits(real(*x)), math.Float64bits(imag(*x)))
	case *string:
		return hex.EncodeToString([]byte(*x))
	case *[]byte:
		return hex.EncodeToString(*x)
	case *cs:
		return hex.EncodeToString([]byte(x.s))
	}
	panic("canon")
}

func dest(kind string) any {
	switch kind {
	case "bool":
		return new(bool)
	case "int":
		return new(int)
	case "int8":
		return new(int8)
	case "int16":
		return new(int16)
	case "int32":
		return new(int32)
	case "int64":
		return new(int64)
	case "uint":
		return new(uint)
	case "uint8":
		return new(uint8)
	case "uint16":
		return new(uint16)
	case "uint32":
		return new(uint32)
	case "uint64":
		return new(uint64)
	case "uintptr":
		return new(uintptr)
	case "float32":
		return new(float32)
	case "float64":
		return new(float64)
	case "complex64":
		return new(complex64)
	case "complex128":
		return new(complex128)
	case "string":
		return new(string)
	case "bytes":
		return new([]byte)
	case "scanner":
		return new(cs)
	}
	panic("dest " + kind)
}

func scanLine(f []string) string {
	mode, input, format := f[1], unhex(f[2]), unhex(f[3])
	var dests []any
	if f[4] != "" {
		for _, k := range strings.Split(f[4], ",") {
			dests = append(dests, dest(k))
		}
	}
	var n int
	var err error
	switch mode {
	case "f":
		n, err = fmt.Sscanf(input, format, dests...)
	case "s":
		n, err = fmt.Sscan(input, dests...)
	case "l":
		n, err = fmt.Sscanln(input, dests...)
	}
	var vals []string
	for _, d := range dests {
		vals = append(vals, canon(d))
	}
	es := "-"
	if err != nil {
		es = "e" + hex.EncodeToString([]byte(err.Error()))
	}
	return strconv.Itoa(n) + "|" + es + "|" + strings.Join(vals, ",")
}

func safeError(e error) (s string) {
	defer func() {
		if recover() != nil {
			s = "PANIC"
		}
	}()
	return e.Error()
}

func run(f []string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "GOPANIC " + fmt.Sprint(r)
		}
	}()
	switch f[0] {
	case "P":
		return hex.EncodeToString([]byte(fmt.Sprintf(unhex(f[1]), args(f[2:])...)))
	case "S":
		return hex.EncodeToString([]byte(fmt.Sprint(args(f[1:])...)))
	case "L":
		return hex.EncodeToString([]byte(fmt.Sprintln(args(f[1:])...)))
	case "E":
		err := fmt.Errorf(unhex(f[1]), args(f[2:])...)
		res := hex.EncodeToString([]byte(err.Error())) + ":"
		var errs []error
		switch u := err.(type) {
		case interface{ Unwrap() error }:
			if e := u.Unwrap(); e != nil {
				errs = []error{e}
			}
		case interface{ Unwrap() []error }:
			errs = u.Unwrap()
		}
		res += strconv.Itoa(len(errs))
		for _, e := range errs {
			res += ":" + hex.EncodeToString([]byte(safeError(e)))
		}
		return res
	case "Z":
		return scanLine(f)
	}
	panic("bad request")
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		if len(line) > 0 {
			line = strings.TrimRight(line, "\n")
			out.WriteString(run(strings.Split(line, "\t")))
			out.WriteByte('\n')
		}
		if err != nil {
			break
		}
	}
}
