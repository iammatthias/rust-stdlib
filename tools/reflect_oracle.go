// reflect_oracle reads line requests (see tools/reflect_check.py) and prints Go's
// reflect behaviour for each. Types are built from a small spec language with
// reflect.SliceOf, StructOf, ...; values from a bracketed literal syntax.
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

// ---- type specs ----

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

var basics = map[string]reflect.Type{
	"bool": reflect.TypeOf(false), "int": reflect.TypeOf(int(0)), "int8": reflect.TypeOf(int8(0)),
	"int16": reflect.TypeOf(int16(0)), "int32": reflect.TypeOf(int32(0)), "int64": reflect.TypeOf(int64(0)),
	"uint": reflect.TypeOf(uint(0)), "uint8": reflect.TypeOf(uint8(0)), "uint16": reflect.TypeOf(uint16(0)),
	"uint32": reflect.TypeOf(uint32(0)), "uint64": reflect.TypeOf(uint64(0)), "uintptr": reflect.TypeOf(uintptr(0)),
	"float32": reflect.TypeOf(float32(0)), "float64": reflect.TypeOf(float64(0)),
	"complex64": reflect.TypeOf(complex64(0)), "complex128": reflect.TypeOf(complex128(0)),
	"string": reflect.TypeOf(""), "any": reflect.TypeOf((*any)(nil)).Elem(),
	"error": reflect.TypeOf((*error)(nil)).Elem(),
}

func parseType(p *scan) reflect.Type {
	switch {
	case p.eat("[]"):
		return reflect.SliceOf(parseType(p))
	case p.eat("["):
		n, err := strconv.Atoi(p.until("]"))
		if err != nil {
			panic("spec: bad array length")
		}
		p.must("]")
		return reflect.ArrayOf(n, parseType(p))
	case p.eat("*"):
		return reflect.PointerTo(parseType(p))
	case p.eat("map["):
		k := parseType(p)
		p.must("]")
		return reflect.MapOf(k, parseType(p))
	case p.eat("chan:"):
		return reflect.ChanOf(reflect.BothDir, parseType(p))
	case p.eat("rchan:"):
		return reflect.ChanOf(reflect.RecvDir, parseType(p))
	case p.eat("schan:"):
		return reflect.ChanOf(reflect.SendDir, parseType(p))
	case p.eat("func("):
		var ins, outs []reflect.Type
		variadic := false
		for !p.has(")") {
			if p.eat("...") {
				variadic = true
			}
			ins = append(ins, parseType(p))
			p.eat(",")
		}
		p.must(")(")
		for !p.has(")") {
			outs = append(outs, parseType(p))
			p.eat(",")
		}
		p.must(")")
		return reflect.FuncOf(ins, outs, variadic)
	case p.eat("{"):
		var fields []reflect.StructField
		for !p.has("}") {
			var f reflect.StructField
			if p.eat("@") {
				f.Anonymous = true
			}
			f.Name = p.until("^:")
			if p.eat("^") {
				f.PkgPath = "main"
			}
			p.must(":")
			f.Type = parseType(p)
			if p.eat("|") {
				b, _ := hex.DecodeString(p.until(";}"))
				f.Tag = reflect.StructTag(b)
			}
			fields = append(fields, f)
			p.eat(";")
		}
		p.must("}")
		return reflect.StructOf(fields)
	}
	name := p.until(";,)}]|")
	t, ok := basics[name]
	if !ok {
		panic("spec: unknown type " + name)
	}
	return t
}

func typeOf(spec string) reflect.Type { return parseType(&scan{s: spec}) }

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

func typeInfo(t reflect.Type) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s|%s|%s|%s|%s|%d|%d|%d|%d", hx(t.String()), t.Kind(), hx(t.Name()), hx(t.PkgPath()),
		b2s(t.Comparable()), t.Size(), t.Align(), t.FieldAlign(), t.NumMethod())
	switch t.Kind() {
	case reflect.Struct:
		fmt.Fprintf(&sb, "|%d", t.NumField())
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			fmt.Fprintf(&sb, ";%s,%s,%s,%s,%d,%v,%s,%s", hx(f.Name), hx(f.PkgPath), b2s(f.Anonymous), b2s(f.IsExported()),
				f.Offset, f.Index, hx(string(f.Tag)), hx(f.Type.String()))
		}
	case reflect.Array:
		fmt.Fprintf(&sb, "|%d,%s", t.Len(), hx(t.Elem().String()))
	case reflect.Slice, reflect.Pointer:
		fmt.Fprintf(&sb, "|%s", hx(t.Elem().String()))
	case reflect.Chan:
		fmt.Fprintf(&sb, "|%s,%s", t.ChanDir(), hx(t.Elem().String()))
	case reflect.Map:
		fmt.Fprintf(&sb, "|%s,%s", hx(t.Key().String()), hx(t.Elem().String()))
	case reflect.Func:
		fmt.Fprintf(&sb, "|%d,%d,%d", t.NumIn(), t.NumOut(), map[bool]int{false: 0, true: 1}[t.IsVariadic()])
		for i := 0; i < t.NumIn(); i++ {
			fmt.Fprintf(&sb, ",%s", hx(t.In(i).String()))
		}
		for i := 0; i < t.NumOut(); i++ {
			fmt.Fprintf(&sb, ",%s", hx(t.Out(i).String()))
		}
	case reflect.Interface:
		fmt.Fprintf(&sb, "|%d", t.NumMethod())
	}
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8,
		reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32, reflect.Float64,
		reflect.Complex64, reflect.Complex128:
		fmt.Fprintf(&sb, "|bits%d", t.Bits())
	}
	return sb.String()
}

func idx(ix []int) string {
	var p []string
	for _, i := range ix {
		p = append(p, strconv.Itoa(i))
	}
	return strings.Join(p, ".")
}

func handle(f []string) string {
	switch f[0] {
	case "T":
		return typeInfo(typeOf(f[1]))
	case "V":
		var parts []string
		for _, vf := range reflect.VisibleFields(typeOf(f[1])) {
			parts = append(parts, hx(vf.Name)+":"+idx(vf.Index))
		}
		return strings.Join(parts, " ")
	case "N":
		t := typeOf(f[1])
		name := unhex(f[2])
		sf, ok := t.FieldByName(name)
		if !ok {
			return "none"
		}
		return idx(sf.Index) + " " + hx(sf.Type.String()) + fmt.Sprintf(" %d", sf.Offset)
	case "NF":
		t := typeOf(f[1])
		prefix := unhex(f[2])
		sf, ok := t.FieldByNameFunc(func(s string) bool { return strings.HasPrefix(s, prefix) })
		if !ok {
			return "none"
		}
		return idx(sf.Index) + " " + hx(sf.Type.String())
	case "G":
		tag := reflect.StructTag(unhex(f[1]))
		key := unhex(f[2])
		v, ok := tag.Lookup(key)
		return hx(tag.Get(key)) + " " + hx(v) + " " + b2s(ok)
	case "D":
		a, b := makeVal(f[1], f[2]), makeVal(f[1], f[3])
		var ai, bi any
		if a.IsValid() {
			ai = a.Interface()
		}
		if b.IsValid() {
			bi = b.Interface()
		}
		out := b2s(reflect.DeepEqual(ai, bi))
		if a.Type().Comparable() && a.Comparable() && b.Comparable() {
			out += " eq=" + b2s(a.Equal(b))
		}
		return out
	case "C":
		src := makeVal(f[1], f[3])
		dt := typeOf(f[2])
		out := b2s(src.Type().ConvertibleTo(dt)) + " " + b2s(src.CanConvert(dt))
		if src.CanConvert(dt) {
			out += " " + pv(src.Convert(dt))
		}
		return out
	case "S":
		v := makeVal(f[1], f[2])
		out := hx(v.String()) + " " + v.Kind().String() + " " + pv(v)
		return out + " zero=" + b2s(v.IsZero())
	case "R":
		a, b := typeOf(f[1]), typeOf(f[2])
		return b2s(a.AssignableTo(b)) + b2s(a.ConvertibleTo(b)) + b2s(a.Comparable()) +
			b2s(a.Implements(basics["any"])) + b2s(a.Implements(basics["error"]))
	case "O":
		t := typeOf(f[1])
		v := reflect.New(t).Elem()
		switch {
		case t.Kind() >= reflect.Int && t.Kind() <= reflect.Int64:
			x, _ := strconv.ParseInt(f[2], 10, 64)
			return b2s(t.OverflowInt(x)) + b2s(v.OverflowInt(x))
		case t.Kind() >= reflect.Uint && t.Kind() <= reflect.Uintptr:
			x, _ := strconv.ParseUint(f[2], 10, 64)
			return b2s(t.OverflowUint(x)) + b2s(v.OverflowUint(x))
		default:
			x, _ := strconv.ParseUint(f[2], 16, 64)
			fl := math.Float64frombits(x)
			if t.Kind() == reflect.Complex64 || t.Kind() == reflect.Complex128 {
				return b2s(t.OverflowComplex(complex(fl, fl))) + b2s(v.OverflowComplex(complex(fl, 1)))
			}
			return b2s(t.OverflowFloat(fl)) + b2s(v.OverflowFloat(fl))
		}
	case "L":
		v := makeVal(f[1], f[2])
		i, _ := strconv.Atoi(f[3])
		j, _ := strconv.Atoi(f[4])
		if len(f) > 5 {
			k, _ := strconv.Atoi(f[5])
			s := v.Slice3(i, j, k)
			return fmt.Sprintf("%d %d %s", s.Len(), s.Cap(), pv(s))
		}
		s := v.Slice(i, j)
		return fmt.Sprintf("%d %d %s", s.Len(), s.Cap(), pv(s))
	case "A":
		v := makeVal(f[1], f[2])
		var xs []reflect.Value
		for _, lit := range f[3:] {
			if lit == "" {
				continue
			}
			x := reflect.New(v.Type().Elem()).Elem()
			fill(x, parseNode(&scan{s: lit}))
			xs = append(xs, x)
		}
		s := reflect.Append(v, xs...)
		return fmt.Sprintf("%d %s %s", s.Len(), b2s(s.Cap() >= s.Len()), pv(s))
	case "M":
		v := makeVal(f[1], f[2])
		kt := v.Type().Key()
		k := reflect.New(kt).Elem()
		fill(k, parseNode(&scan{s: f[3]}))
		return pv(v.MapIndex(k)) + " " + strconv.Itoa(v.Len()) + " " + strconv.Itoa(len(v.MapKeys()))
	case "Z":
		v := reflect.Zero(typeOf(f[1]))
		return pv(v) + " " + b2s(v.IsZero())
	case "E":
		// New(t).Elem(), fill with literal A, then set the element at a path
		// of field/index steps to literal B (as a Set from a fresh value).
		t := typeOf(f[1])
		p := reflect.New(t)
		fill(p.Elem(), parseNode(&scan{s: f[2]}))
		cur := p.Elem()
		for _, step := range strings.Split(f[3], ".") {
			if step == "" {
				continue
			}
			n, _ := strconv.Atoi(step)
			if cur.Kind() == reflect.Pointer {
				cur = cur.Elem()
			}
			if cur.Kind() == reflect.Struct {
				cur = cur.Field(n)
			} else {
				cur = cur.Index(n)
			}
		}
		nv := reflect.New(cur.Type()).Elem()
		fill(nv, parseNode(&scan{s: f[4]}))
		cur.Set(nv)
		return pv(p.Elem()) + " " + b2s(cur.CanSet()) + b2s(cur.CanAddr())
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
		line := in.Text()
		fmt.Fprintln(w, safe(strings.Split(line, " ")))
	}
}
