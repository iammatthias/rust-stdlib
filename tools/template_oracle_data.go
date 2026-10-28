// Data and functions for the template differential. T and its helpers are
// adapted from Go's text/template exec_test.go (BSD-licensed, see NOTICE); the
// Rust side rebuilds the same values in tests/support/template_harness.rs.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"iter"
	"math"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"unsafe"
)

// T has lots of interesting pieces to use to test execution.
type T struct {
	// Basics
	True        bool
	I           int
	U16         uint16
	X, S        string
	FloatZero   float64
	ComplexZero complex128
	// Nested structs.
	U *U
	// Struct with String method.
	V0     V
	V1, V2 *V
	// Struct with Error method.
	W0     W
	W1, W2 *W
	// Slices
	SI      []int
	SICap   []int
	SIEmpty []int
	SB      []bool
	// Arrays
	AI  [3]int
	PAI *[3]int // pointer to array
	// Maps
	MSI      map[string]int
	MSIone   map[string]int // one element, for deterministic output
	MSIEmpty map[string]int
	MXI      map[any]int
	MII      map[int]int
	MI32S    map[int32]string
	MI64S    map[int64]string
	MUI32S   map[uint32]string
	MUI64S   map[uint64]string
	MI8S     map[int8]string
	MUI8S    map[uint8]string
	SMSI     []map[string]int
	// Empty interfaces; used to see if we can dig inside one.
	Empty0 any // nil
	Empty1 any
	Empty2 any
	Empty3 any
	Empty4 any
	// Non-empty interfaces.
	NonEmptyInterface         I
	NonEmptyInterfacePtS      *I
	NonEmptyInterfaceNil      I
	NonEmptyInterfaceTypedNil I
	// Stringer.
	Str fmt.Stringer
	Err error
	// Pointers
	PI       *int
	PS       *string
	PSI      *[]int
	NIL      *int
	UPI      unsafe.Pointer
	EmptyUPI unsafe.Pointer
	// Function (not method)
	BinaryFunc             func(string, string) string
	VariadicFunc           func(...string) string
	VariadicFuncInt        func(int, ...string) string
	NilOKFunc              func(*int) bool
	ErrFunc                func() (string, error)
	PanicFunc              func() string
	TooFewReturnCountFunc  func()
	TooManyReturnCountFunc func() (string, error, int)
	InvalidReturnTypeFunc  func() (string, bool)
	// Template to test evaluation of templates.
	Tmpl *template.Template
	// Unexported field; cannot be accessed by template.
	unexported int
}

type S []string

func (S) Method0() string {
	return "M0"
}

type U struct {
	V string
}

type V struct {
	j int
}

func (v *V) String() string {
	if v == nil {
		return "nilV"
	}
	return fmt.Sprintf("<%d>", v.j)
}

type W struct {
	k int
}

func (w *W) Error() string {
	if w == nil {
		return "nilW"
	}
	return fmt.Sprintf("[%d]", w.k)
}

var siVal = I(S{"a", "b"})

var tVal = &T{
	True:   true,
	I:      17,
	U16:    16,
	X:      "x",
	S:      "xyz",
	U:      &U{"v"},
	V0:     V{6666},
	V1:     &V{7777}, // leave V2 as nil
	W0:     W{888},
	W1:     &W{999}, // leave W2 as nil
	SI:     []int{3, 4, 5},
	SICap:  make([]int, 5, 10),
	AI:     [3]int{3, 4, 5},
	PAI:    &[3]int{3, 4, 5},
	SB:     []bool{true, false},
	MSI:    map[string]int{"one": 1, "two": 2, "three": 3},
	MSIone: map[string]int{"one": 1},
	MXI:    map[any]int{"one": 1},
	MII:    map[int]int{1: 1},
	MI32S:  map[int32]string{1: "one", 2: "two"},
	MI64S:  map[int64]string{2: "i642", 3: "i643"},
	MUI32S: map[uint32]string{2: "u322", 3: "u323"},
	MUI64S: map[uint64]string{2: "ui642", 3: "ui643"},
	MI8S:   map[int8]string{2: "i82", 3: "i83"},
	MUI8S:  map[uint8]string{2: "u82", 3: "u83"},
	SMSI: []map[string]int{
		{"one": 1, "two": 2},
		{"eleven": 11, "twelve": 12},
	},
	Empty1:                    3,
	Empty2:                    "empty2",
	Empty3:                    []int{7, 8},
	Empty4:                    &U{"UinEmpty"},
	NonEmptyInterface:         &T{X: "x"},
	NonEmptyInterfacePtS:      &siVal,
	NonEmptyInterfaceTypedNil: (*T)(nil),
	Str:                       bytes.NewBuffer([]byte("foozle")),
	Err:                       errors.New("erroozle"),
	PI:                        newInt(23),
	PS:                        newString("a string"),
	PSI:                       newIntSlice(21, 22, 23),
	UPI:                       newUnsafePointer(23),
	BinaryFunc:                func(a, b string) string { return fmt.Sprintf("[%s=%s]", a, b) },
	VariadicFunc:              func(s ...string) string { return fmt.Sprint("<", strings.Join(s, "+"), ">") },
	VariadicFuncInt:           func(a int, s ...string) string { return fmt.Sprint(a, "=<", strings.Join(s, "+"), ">") },
	NilOKFunc:                 func(s *int) bool { return s == nil },
	ErrFunc:                   func() (string, error) { return "bla", nil },
	PanicFunc:                 func() string { panic("test panic") },
	TooFewReturnCountFunc:     func() {},
	TooManyReturnCountFunc:    func() (string, error, int) { return "", nil, 0 },
	InvalidReturnTypeFunc:     func() (string, bool) { return "", false },
	Tmpl:                      template.Must(template.New("x").Parse("test template")), // "x" is the value of .X
}

var tSliceOfNil = []*T{nil}

// A non-empty interface.
type I interface {
	Method0() string
}

var iVal I = tVal

func newInt(n int) *int {
	return &n
}

func newUnsafePointer(n int) unsafe.Pointer {
	return unsafe.Pointer(&n)
}

func newString(s string) *string {
	return &s
}

func newIntSlice(n ...int) *[]int {
	p := new([]int)
	*p = make([]int, len(n))
	copy(*p, n)
	return p
}

// Simple methods with and without arguments.
func (t *T) Method0() string {
	return "M0"
}

func (t *T) Method1(a int) int {
	return a
}

func (t *T) Method2(a uint16, b string) string {
	return fmt.Sprintf("Method2: %d %s", a, b)
}

func (t *T) Method3(v any) string {
	return fmt.Sprintf("Method3: %v", v)
}

func (t *T) Copy() *T {
	n := new(T)
	*n = *t
	return n
}

func (t *T) MAdd(a int, b []int) []int {
	v := make([]int, len(b))
	for i, x := range b {
		v[i] = x + a
	}
	return v
}

var myError = errors.New("my error")

// MyError returns a value and an error according to its argument.
func (t *T) MyError(error bool) (bool, error) {
	if error {
		return true, myError
	}
	return false, nil
}

// A few methods to test chaining.
func (t *T) GetU() *U {
	return t.U
}

func (u *U) TrueFalse(b bool) string {
	if b {
		return "true"
	}
	return ""
}

func typeOf(arg any) string {
	return fmt.Sprintf("%T", arg)
}

func fVal1(i int) iter.Seq[int] {
	return func(yield func(int) bool) {
		for v := range i {
			if !yield(v) {
				break
			}
		}
	}
}

func fVal2(i int) iter.Seq2[int, int] {
	return func(yield func(int, int) bool) {
		for v := range i {
			if !yield(v, v+1) {
				break
			}
		}
	}
}

func zeroArgs() string {
	return "zeroArgs"
}

func oneArg(a string) string {
	return "oneArg=" + a
}

func twoArgs(a, b string) string {
	return "twoArgs=" + a + b
}

func dddArg(a int, b ...string) string {
	return fmt.Sprintln(a, b)
}

// count returns a channel that will deliver n sequential 1-letter strings starting at "a"
func count(n int) chan string {
	if n == 0 {
		return nil
	}
	c := make(chan string)
	go func() {
		for i := 0; i < n; i++ {
			c <- "abcdefghijklmnop"[i : i+1]
		}
		close(c)
	}()
	return c
}

// vfunc takes a *V and a V
func vfunc(V, *V) string {
	return "vfunc"
}

// valueString takes a string, not a pointer.
func valueString(v string) string {
	return "value is ignored"
}

// returnInt returns an int
func returnInt() int {
	return 7
}

func add(args ...int) int {
	sum := 0
	for _, x := range args {
		sum += x
	}
	return sum
}

func echo(arg any) any {
	return arg
}

func makemap(arg ...string) map[string]string {
	if len(arg)%2 != 0 {
		panic("bad makemap")
	}
	m := make(map[string]string)
	for i := 0; i < len(arg); i += 2 {
		m[arg[i]] = arg[i+1]
	}
	return m
}

func stringer(s fmt.Stringer) string {
	return s.String()
}

func mapOfThree() any {
	return map[string]int{"three": 3}
}

// stdFuncs is the function map every differential template gets.
var stdFuncs = template.FuncMap{
	"add":         add,
	"count":       count,
	"dddArg":      dddArg,
	"die":         func() bool { panic("die") },
	"echo":        echo,
	"makemap":     makemap,
	"mapOfThree":  mapOfThree,
	"oneArg":      oneArg,
	"returnInt":   returnInt,
	"stringer":    stringer,
	"twoArgs":     twoArgs,
	"typeOf":      typeOf,
	"valueString": valueString,
	"vfunc":       vfunc,
	"zeroArgs":    zeroArgs,
	// Used by the generated templates.
	"doPanic": func() string { panic("custom panic string") },
	"upper": strings.ToUpper,
	"join":  func(sep string, elems ...string) string { return strings.Join(elems, sep) },
	"dbl":   func(n int) int { return 2 * n },
	"fail":  func(s string) (string, error) { return "", errors.New("fail: " + s) },
	"pair":  func(a, b any) []any { return []any{a, b} },
	"nilf":  func() any { return nil },
	"seq":   func(n int) []int { r := make([]int, n); for i := range r { r[i] = i }; return r },
}

// A "cmpStruct" as used by TestComparison.
type cmpStruct struct {
	Uthree, Ufour    uint
	NegOne, Three    int
	Ptr, NilPtr      *int
	NonNilMap        map[int]int
	Map              map[int]int
	V1, V2           V
	Iface1, NilIface fmt.Stringer
}

type Tree struct {
	Val         int
	Left, Right *Tree
}

type A struct{ S string }
type B struct{ *A }

type namedInt int

func (n namedInt) String() string { return "namedInt(" + strconv.Itoa(int(n)) + ")" }

type namedStr string

type Embedded struct {
	Base
	Name string
}

type Base struct{ ID int }

func (b Base) Describe() string { return fmt.Sprintf("base#%d", b.ID) }
func (b *Base) PtrMethod() string { return "ptr" }

// refs maps the "$ref" names of data specs to values.
func refs(name string) any {
	if strings.HasPrefix(name, "buf:") {
		return bytes.NewBufferString(strings.TrimPrefix(name, "buf:"))
	}
	switch name {
	case "tVal":
		return tVal
	case "tSliceOfNil":
		return tSliceOfNil
	case "iVal":
		return iVal
	case "&iVal":
		return &iVal
	case "T{}":
		return T{}
	case "&T{}":
		return &T{}
	case "nilT":
		return (*T)(nil)
	case "cmp":
		b := new(strings.Builder)
		return &cmpStruct{Uthree: 3, Ufour: 4, NegOne: -1, Three: 3, Ptr: new(int), NonNilMap: make(map[int]int), Iface1: b}
	case "tree":
		return &Tree{1, &Tree{2, &Tree{3, &Tree{4, nil, nil}, nil}, &Tree{5, &Tree{6, nil, nil}, nil}}, &Tree{7, &Tree{8, &Tree{9, nil, nil}, nil}, &Tree{10, &Tree{11, nil, nil}, nil}}}
	case "B{}":
		return B{}
	case "fVal1(2)":
		return fVal1(2)
	case "fVal2(2)":
		return fVal2(2)
	case "fVal1(0)":
		return fVal1(0)
	case "fVal2(0)":
		return fVal2(0)
	case "nilchan":
		return (chan int)(nil)
	case "sendchan":
		return make(chan<- int)
	case "embedded":
		return Embedded{Base{7}, "emb"}
	case "&embedded":
		return &Embedded{Base{8}, "pemb"}
	case "namedInt":
		return namedInt(5)
	case "mapPtr":
		return &map[string]string{}
	case "nilMapPtr":
		return (*map[string]string)(nil)
	case "unsafe":
		return newUnsafePointer(1)
	case "anon_ab":
		return struct {
			a int
			b string
		}{7, "seven"}
	}
	if v, ok := htmlRefs(name); ok {
		return v
	}
	panic("unknown ref " + name)
}

// intTypes lists the numeric types a typed constructor can build.
func buildTyped(spec map[string]any) any {
	t, _ := spec["$t"].(string)
	num := func(key string) float64 {
		f, _ := spec[key].(float64)
		return f
	}
	switch t {
	case "int":
		return int(num("v"))
	case "int8":
		return int8(num("v"))
	case "int16":
		return int16(num("v"))
	case "int32":
		return int32(num("v"))
	case "int64":
		return int64(num("v"))
	case "uint":
		return uint(num("v"))
	case "uint8":
		return uint8(num("v"))
	case "uint16":
		return uint16(num("v"))
	case "uint32":
		return uint32(num("v"))
	case "uint64":
		return uint64(num("v"))
	case "uintptr":
		return uintptr(num("v"))
	case "float32":
		return float32(num("v"))
	case "float64":
		return num("v")
	case "complex64":
		return complex64(complex(num("re"), num("im")))
	case "complex128":
		return complex(num("re"), num("im"))
	case "bool":
		b, _ := spec["v"].(bool)
		return b
	case "string":
		s, _ := spec["v"].(string)
		return s
	case "inf":
		return math.Inf(int(num("v")))
	case "nan":
		return math.NaN()
	case "negzero":
		return math.Copysign(0, -1)
	case "slice":
		return buildSlice(spec)
	case "array":
		return buildArray(spec)
	case "map":
		return buildMap(spec)
	case "ptr":
		v := reflect.ValueOf(build(spec["v"]))
		p := reflect.New(v.Type())
		p.Elem().Set(v)
		return p.Interface()
	case "nilptr":
		return reflect.Zero(reflect.PointerTo(typeNamed(spec["e"].(string)))).Interface()
	case "struct":
		return buildStruct(spec)
	case "named":
		switch spec["n"] {
		case "namedInt":
			return namedInt(int(num("v")))
		case "namedStr":
			s, _ := spec["v"].(string)
			return namedStr(s)
		}
	case "nilmap":
		return reflect.Zero(reflect.MapOf(typeNamed(spec["k"].(string)), typeNamed(spec["e"].(string)))).Interface()
	case "nilslice":
		return reflect.Zero(reflect.SliceOf(typeNamed(spec["e"].(string)))).Interface()
	case "nilany":
		var x any
		return x
	case "func":
		switch spec["n"] {
		case "plusone":
			return func(n int) int { return n + 1 }
		case "result":
			return func() string { return "result" }
		}
	}
	if v, ok := htmlTyped(t, spec); ok {
		return v
	}
	panic("unknown typed spec " + t)
}

func typeNamed(name string) reflect.Type {
	switch name {
	case "int":
		return reflect.TypeFor[int]()
	case "int8":
		return reflect.TypeFor[int8]()
	case "int16":
		return reflect.TypeFor[int16]()
	case "int32":
		return reflect.TypeFor[int32]()
	case "int64":
		return reflect.TypeFor[int64]()
	case "uint":
		return reflect.TypeFor[uint]()
	case "uint8":
		return reflect.TypeFor[uint8]()
	case "uint16":
		return reflect.TypeFor[uint16]()
	case "uint32":
		return reflect.TypeFor[uint32]()
	case "uint64":
		return reflect.TypeFor[uint64]()
	case "float32":
		return reflect.TypeFor[float32]()
	case "float64":
		return reflect.TypeFor[float64]()
	case "bool":
		return reflect.TypeFor[bool]()
	case "string":
		return reflect.TypeFor[string]()
	case "any":
		return reflect.TypeFor[any]()
	case "V":
		return reflect.TypeFor[V]()
	}
	panic("unknown type name " + name)
}

func buildSlice(spec map[string]any) any {
	et := typeNamed(spec["e"].(string))
	items, _ := spec["v"].([]any)
	s := reflect.MakeSlice(reflect.SliceOf(et), 0, len(items))
	for _, it := range items {
		s = reflect.Append(s, convertTo(build(it), et))
	}
	return s.Interface()
}

func buildArray(spec map[string]any) any {
	et := typeNamed(spec["e"].(string))
	items, _ := spec["v"].([]any)
	a := reflect.New(reflect.ArrayOf(len(items), et)).Elem()
	for i, it := range items {
		a.Index(i).Set(convertTo(build(it), et))
	}
	return a.Interface()
}

func buildMap(spec map[string]any) any {
	kt := typeNamed(spec["k"].(string))
	et := typeNamed(spec["e"].(string))
	m := reflect.MakeMap(reflect.MapOf(kt, et))
	entries, _ := spec["v"].([]any)
	for _, e := range entries {
		pair := e.([]any)
		m.SetMapIndex(convertTo(build(pair[0]), kt), convertTo(build(pair[1]), et))
	}
	return m.Interface()
}

func convertTo(v any, t reflect.Type) reflect.Value {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() {
		return reflect.Zero(t)
	}
	if rv.Type().AssignableTo(t) {
		r := reflect.New(t).Elem()
		r.Set(rv)
		return r
	}
	return rv.Convert(t)
}

func buildStruct(spec map[string]any) any {
	fields, _ := spec["fields"].([]any)
	var sf []reflect.StructField
	var vals []reflect.Value
	for _, f := range fields {
		pair := f.([]any)
		v := build(pair[1])
		rv := reflect.ValueOf(v)
		var ft reflect.Type
		if rv.IsValid() {
			ft = rv.Type()
		} else {
			ft = reflect.TypeFor[any]()
		}
		if len(pair) > 2 && pair[2] == "any" {
			ft = reflect.TypeFor[any]()
		}
		sf = append(sf, reflect.StructField{Name: pair[0].(string), Type: ft})
		vals = append(vals, rv)
	}
	s := reflect.New(reflect.StructOf(sf)).Elem()
	for i, rv := range vals {
		if rv.IsValid() {
			s.Field(i).Set(rv)
		}
	}
	return s.Interface()
}

// build turns a data spec into a Go value. Plain JSON decodes like
// encoding/json into any; objects with "$ref" or "$t" build typed values.
func build(spec any) any {
	switch v := spec.(type) {
	case map[string]any:
		if r, ok := v["$ref"].(string); ok {
			return refs(r)
		}
		if _, ok := v["$t"]; ok {
			return buildTyped(v)
		}
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[k] = build(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = build(x)
		}
		return out
	}
	return spec
}
