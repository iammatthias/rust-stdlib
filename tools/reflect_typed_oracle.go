// reflect_typed_oracle checks reflect on real Go types with embedding,
// shadowing, promoted methods and interfaces: the cases StructOf cannot build.
// It is driven by tools/reflect_typed_check.py and compared with
// tools/derive-check/examples/reflect_typed_probe.rs on #[derive(Reflect)] types.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type Base struct {
	ID     int64
	Name   string `json:"name"`
	secret bool
}

func (b Base) Describe() string { return fmt.Sprintf("base %d %s", b.ID, b.Name) }
func (b *Base) Rename(n string) { b.Name = n }

type Named struct {
	Name  string
	Extra int32
}

func (n Named) Label() string { return "named " + n.Name }

type Mid struct {
	Base
	Named
	Level int32
}

type Top struct {
	*Mid
	Level int8
	Tags  []string
}

type Point struct {
	X    int32 `json:"x" xml:"px"`
	Y    int32
	name string
}

func (p Point) Sum() int32     { return p.X + p.Y }
func (p *Point) Scale(k int32) { p.X *= k; p.Y *= k }
func (p Point) Greet(who string, n int64) string {
	return fmt.Sprintf("%s %s %d", p.name, who, n)
}

type Pair[A, B any] struct {
	First  A
	Second B
}

type Color int

type Node struct {
	Val  int
	Next *Node
	Kids []Node
}

type Wrap struct {
	Node
	Base
}

type Shape interface{ Sum() int32 }
type Scaler interface{ Scale(int32) }
type Describer interface{ Describe() string }

var types = map[string]reflect.Type{
	"Base": reflect.TypeOf(Base{}), "Named": reflect.TypeOf(Named{}), "Mid": reflect.TypeOf(Mid{}),
	"Top": reflect.TypeOf(Top{}), "Point": reflect.TypeOf(Point{}), "Pair": reflect.TypeOf(Pair[int, string]{}),
	"Pair2": reflect.TypeOf(Pair[Point, []Base]{}),
	"Color": reflect.TypeOf(Color(0)), "Node": reflect.TypeOf(Node{}), "Wrap": reflect.TypeOf(Wrap{}),
	"Shape": reflect.TypeOf((*Shape)(nil)).Elem(), "Scaler": reflect.TypeOf((*Scaler)(nil)).Elem(),
	"Describer": reflect.TypeOf((*Describer)(nil)).Elem(),
	"int":       reflect.TypeOf(0), "string": reflect.TypeOf(""), "int32": reflect.TypeOf(int32(0)),
	"any": reflect.TypeOf((*any)(nil)).Elem(), "error": reflect.TypeOf((*error)(nil)).Elem(),
}

func typeOf(name string) reflect.Type {
	switch {
	case strings.HasPrefix(name, "*"):
		return reflect.PointerTo(typeOf(name[1:]))
	case strings.HasPrefix(name, "[]"):
		return reflect.SliceOf(typeOf(name[2:]))
	}
	t, ok := types[name]
	if !ok {
		panic("unknown type " + name)
	}
	return t
}

type scan struct {
	s string
	i int
}

func (p *scan) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

func (p *scan) has(prefix string) bool { return strings.HasPrefix(p.s[p.i:], prefix) }

func (p *scan) eat(prefix string) bool {
	if p.has(prefix) {
		p.i += len(prefix)
		return true
	}
	return false
}

func (p *scan) must(prefix string) {
	if !p.eat(prefix) {
		panic("spec: expected " + prefix + " at " + strconv.Itoa(p.i) + " in " + p.s)
	}
}

func (p *scan) until(stops string) string {
	j := p.i
	for j < len(p.s) && !strings.ContainsRune(stops, rune(p.s[j])) {
		j++
	}
	r := p.s[p.i:j]
	p.i = j
	return r
}

// ---- value literals ----

type node struct {
	atom string
	list []*node
	isL  bool
}

func parseNode(p *scan) *node {
	if p.eat("[") {
		n := &node{isL: true}
		for !p.has("]") {
			n.list = append(n.list, parseNode(p))
			p.eat(",")
		}
		p.must("]")
		return n
	}
	return &node{atom: p.until(",]")}
}

func unhex(s string) string {
	if s == "-" {
		return ""
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("bad hex")
	}
	return string(b)
}

func fill(v reflect.Value, n *node) {
	if !n.isL && n.atom == "n" {
		return
	}
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(n.atom == "t")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		x, err := strconv.ParseInt(n.atom, 10, 64)
		if err != nil {
			panic("bad int " + n.atom)
		}
		v.SetInt(x)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		x, err := strconv.ParseUint(n.atom, 10, 64)
		if err != nil {
			panic("bad uint " + n.atom)
		}
		v.SetUint(x)
	case reflect.Float32:
		x, _ := strconv.ParseUint(n.atom, 16, 32)
		v.SetFloat(float64(math.Float32frombits(uint32(x))))
	case reflect.Float64:
		x, _ := strconv.ParseUint(n.atom, 16, 64)
		v.SetFloat(math.Float64frombits(x))
	case reflect.Complex64:
		a, _ := strconv.ParseUint(n.list[0].atom, 16, 32)
		b, _ := strconv.ParseUint(n.list[1].atom, 16, 32)
		v.SetComplex(complex(float64(math.Float32frombits(uint32(a))), float64(math.Float32frombits(uint32(b)))))
	case reflect.Complex128:
		a, _ := strconv.ParseUint(n.list[0].atom, 16, 64)
		b, _ := strconv.ParseUint(n.list[1].atom, 16, 64)
		v.SetComplex(complex(math.Float64frombits(a), math.Float64frombits(b)))
	case reflect.String:
		v.SetString(unhex(n.atom))
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), len(n.list), len(n.list))
		for i, e := range n.list {
			fill(s.Index(i), e)
		}
		v.Set(s)
	case reflect.Array:
		for i, e := range n.list {
			fill(v.Index(i), e)
		}
	case reflect.Struct:
		for i, e := range n.list {
			fill(v.Field(i), e)
		}
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		for _, e := range n.list {
			k := reflect.New(v.Type().Key()).Elem()
			fill(k, e.list[0])
			x := reflect.New(v.Type().Elem()).Elem()
			fill(x, e.list[1])
			m.SetMapIndex(k, x)
		}
		v.Set(m)
	case reflect.Pointer:
		p := reflect.New(v.Type().Elem())
		fill(p.Elem(), n.list[0])
		v.Set(p)
	case reflect.Interface:
		t := typeOf(unhex(n.list[0].atom))
		x := reflect.New(t).Elem()
		fill(x, n.list[1])
		v.Set(x)
	default:
		panic("cannot fill " + v.Kind().String())
	}
}

func makeVal(spec, lit string) reflect.Value {
	t := typeOf(spec)
	v := reflect.New(t).Elem()
	fill(v, parseNode(&scan{s: lit}))
	return v
}

// ---- canonical printing ----

func hx(s string) string {
	if s == "" {
		return "-"
	}
	return hex.EncodeToString([]byte(s))
}

func pf(k reflect.Kind, f float64) string {
	if k == reflect.Float32 || k == reflect.Complex64 {
		return fmt.Sprintf("%08x", math.Float32bits(float32(f)))
	}
	return fmt.Sprintf("%016x", math.Float64bits(f))
}

func pv(v reflect.Value) string {
	if !v.IsValid() {
		return "inv"
	}
	switch v.Kind() {
	case reflect.Bool:
		if v.Bool() {
			return "t"
		}
		return "f"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "i" + strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return "u" + strconv.FormatUint(v.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return "f" + pf(v.Kind(), v.Float())
	case reflect.Complex64, reflect.Complex128:
		c := v.Complex()
		return "c(" + pf(v.Kind(), real(c)) + "," + pf(v.Kind(), imag(c)) + ")"
	case reflect.String:
		return "s" + hx(v.String())
	case reflect.Slice:
		if v.IsNil() {
			return "S-"
		}
		fallthrough
	case reflect.Array:
		var parts []string
		for i := 0; i < v.Len(); i++ {
			parts = append(parts, pv(v.Index(i)))
		}
		return v.Kind().String() + "[" + strings.Join(parts, ",") + "]"
	case reflect.Struct:
		var parts []string
		for i := 0; i < v.NumField(); i++ {
			parts = append(parts, pv(v.Field(i)))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case reflect.Map:
		if v.IsNil() {
			return "M-"
		}
		var parts []string
		for _, k := range v.MapKeys() {
			parts = append(parts, pv(k)+"="+pv(v.MapIndex(k)))
		}
		sort.Strings(parts)
		return "M{" + strings.Join(parts, ",") + "}"
	case reflect.Pointer:
		if v.IsNil() {
			return "P-"
		}
		return "&" + pv(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return "I-"
		}
		return "I(" + v.Elem().Type().String() + ":" + pv(v.Elem()) + ")"
	case reflect.Chan:
		if v.IsNil() {
			return "C-"
		}
		return "C+"
	case reflect.Func:
		if v.IsNil() {
			return "F-"
		}
		return "F+"
	}
	return "?" + v.Kind().String()
}

// ---- requests ----

func b2s(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func idx(ix []int) string {
	var p []string
	for _, i := range ix {
		p = append(p, strconv.Itoa(i))
	}
	return strings.Join(p, ".")
}

func info(t reflect.Type) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s|%s|%s|%s|%d|%d|%d", hx(t.String()), t.Kind(), hx(t.Name()), hx(t.PkgPath()), t.Size(), t.Align(), t.NumMethod())
	if t.Kind() == reflect.Struct {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fmt.Fprintf(&sb, ";%s,%s,%s,%s,%d,%s,%s", hx(f.Name), hx(f.PkgPath), b2s(f.Anonymous), b2s(f.IsExported()),
				f.Offset, hx(string(f.Tag)), hx(f.Type.String()))
		}
	}
	sb.WriteString("|")
	for i := 0; i < t.NumMethod(); i++ {
		m := t.Method(i)
		fmt.Fprintf(&sb, "%s:%s;", hx(m.Name), hx(m.Type.String()))
	}
	return sb.String()
}

func handle(f []string) string {
	switch f[0] {
	case "T":
		return info(typeOf(f[1]))
	case "V":
		var parts []string
		for _, vf := range reflect.VisibleFields(typeOf(f[1])) {
			parts = append(parts, hx(vf.Name)+":"+idx(vf.Index))
		}
		return strings.Join(parts, " ")
	case "N":
		sf, ok := typeOf(f[1]).FieldByName(unhex(f[2]))
		if !ok {
			return "none"
		}
		return idx(sf.Index) + " " + hx(sf.Type.String())
	case "R":
		a, b := typeOf(f[1]), typeOf(f[2])
		out := b2s(a.AssignableTo(b)) + b2s(a.ConvertibleTo(b)) + b2s(a.Comparable())
		if b.Kind() == reflect.Interface {
			out += b2s(a.Implements(b))
		}
		return out
	case "CALL":
		// CALL type ptr|val literal method args...
		t := typeOf(f[1])
		p := reflect.New(t)
		fill(p.Elem(), parseNode(&scan{s: f[3]}))
		recv := p.Elem()
		if f[2] == "ptr" {
			recv = p
		}
		m := recv.MethodByName(f[4])
		if !m.IsValid() {
			return "nomethod"
		}
		var args []reflect.Value
		for i, lit := range f[5:] {
			a := reflect.New(m.Type().In(i)).Elem()
			fill(a, parseNode(&scan{s: lit}))
			args = append(args, a)
		}
		var outs []string
		for _, r := range m.Call(args) {
			outs = append(outs, pv(r))
		}
		return strings.Join(outs, ";") + " " + pv(p.Elem())
	case "IFACE":
		// IFACE type literal iface method: call through an interface-typed value.
		t := typeOf(f[1])
		p := reflect.New(t)
		fill(p.Elem(), parseNode(&scan{s: f[2]}))
		it := typeOf(f[3])
		v := reflect.New(it).Elem()
		if !p.Type().Implements(it) && !t.Implements(it) {
			return "noimpl"
		}
		if t.Implements(it) {
			v.Set(p.Elem())
		} else {
			v.Set(p)
		}
		m := v.MethodByName(f[4])
		var outs []string
		for _, r := range m.Call(nil) {
			outs = append(outs, pv(r))
		}
		return strings.Join(outs, ";") + " " + b2s(v.NumMethod() > 0) + " " + strconv.Itoa(v.NumMethod())
	case "D":
		a, b := reflect.New(typeOf(f[1])).Elem(), reflect.New(typeOf(f[1])).Elem()
		fill(a, parseNode(&scan{s: f[2]}))
		fill(b, parseNode(&scan{s: f[3]}))
		return b2s(reflect.DeepEqual(a.Interface(), b.Interface()))
	case "CONV":
		a := reflect.New(typeOf(f[1])).Elem()
		fill(a, parseNode(&scan{s: f[3]}))
		dt := typeOf(f[2])
		out := b2s(a.Type().ConvertibleTo(dt))
		if a.Type().ConvertibleTo(dt) {
			out += " " + pv(a.Convert(dt))
		}
		return out
	case "SET":
		// SET type literal fieldpath literal
		t := typeOf(f[1])
		p := reflect.New(t)
		fill(p.Elem(), parseNode(&scan{s: f[2]}))
		cur := p.Elem()
		for _, s := range strings.Split(f[3], ".") {
			n, _ := strconv.Atoi(s)
			if cur.Kind() == reflect.Pointer {
				cur = cur.Elem()
			}
			cur = cur.Field(n)
		}
		nv := reflect.New(cur.Type()).Elem()
		fill(nv, parseNode(&scan{s: f[4]}))
		out := b2s(cur.CanSet()) + b2s(cur.CanInterface()) + b2s(cur.CanAddr())
		cur.Set(nv)
		return out + " " + pv(p.Elem())
	}
	return "unknown request " + f[0]
}

func safe(f []string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			switch e := r.(type) {
			case *reflect.ValueError:
				out = "panic:" + hx(e.Error())
			case error:
				out = "panic:" + hx(e.Error())
			case string:
				out = "panic:" + hx(e)
			default:
				out = "panic:" + hx(fmt.Sprint(r))
			}
		}
	}()
	return handle(f)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<26)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for in.Scan() {
		fmt.Fprintln(w, safe(strings.Split(in.Text(), " ")))
	}
}
