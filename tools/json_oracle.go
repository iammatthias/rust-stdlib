// Line-oriented Go encoding/json oracle for tools/json_check.py.
//
// Each request is "op field..." where binary fields are hex ("-" is empty).
// Each response is one line: "ok <hex>" or "err <hex message> <offset|->".
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"os"
	"reflect"
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

func fail(err error) string {
	// The Rust mirrors of the oracle's types are not in package main.
	msg := strings.ReplaceAll(err.Error(), "main.", "")
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Sprintf("err %s %d", enc([]byte(msg)), se.Offset)
	}
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return fmt.Sprintf("err %s t%d", enc([]byte(msg)), te.Offset)
	}
	return fmt.Sprintf("err %s -", enc([]byte(msg)))
}

func ok(b []byte) string { return "ok " + enc(b) }

func marshalAny(v any, escape bool) string {
	var buf bytes.Buffer
	e := json.NewEncoder(&buf)
	e.SetEscapeHTML(escape)
	if err := e.Encode(v); err != nil {
		return fail(err)
	}
	return ok(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
}

// tokenText renders a Token unambiguously.
func tokenText(t json.Token) string {
	switch v := t.(type) {
	case json.Delim:
		return "D" + string(v)
	case bool:
		if v {
			return "Btrue"
		}
		return "Bfalse"
	case float64:
		b, _ := json.Marshal(v)
		return "F" + string(b)
	case json.Number:
		return "N" + string(v)
	case string:
		return "S" + enc([]byte(v))
	case nil:
		return "Z"
	}
	return "?"
}

// chunkReader returns at most n bytes per Read; n == 0 means unlimited.
type chunkReader struct {
	r io.Reader
	n int
}

func (c chunkReader) Read(p []byte) (int, error) {
	if c.n > 0 && len(p) > c.n {
		p = p[:c.n]
	}
	return c.r.Read(p)
}

func errText(err error) string {
	if err == io.EOF {
		return "EOF"
	}
	var se *json.SyntaxError
	if errors.As(err, &se) {
		return fmt.Sprintf("E%s@%d", enc([]byte(err.Error())), se.Offset)
	}
	return "E" + enc([]byte(err.Error()))
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<28)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		f := strings.Fields(in.Text())
		var res string
		switch f[0] {
		case "valid":
			if json.Valid(dec(f[1])) {
				res = "ok 1"
			} else {
				res = "ok 0"
			}
		case "compact":
			var dst bytes.Buffer
			if err := json.Compact(&dst, dec(f[1])); err != nil {
				res = fail(err)
			} else {
				res = ok(dst.Bytes())
			}
		case "indent":
			var dst bytes.Buffer
			if err := json.Indent(&dst, dec(f[3]), string(dec(f[1])), string(dec(f[2]))); err != nil {
				res = fail(err)
			} else {
				res = ok(dst.Bytes())
			}
		case "html":
			var dst bytes.Buffer
			json.HTMLEscape(&dst, dec(f[1]))
			res = ok(dst.Bytes())
		case "unmarshal", "unmarshalnum":
			var v any
			d := dec(f[1])
			var err error
			if f[0] == "unmarshalnum" {
				dd := json.NewDecoder(bytes.NewReader(d))
				dd.UseNumber()
				err = dd.Decode(&v)
			} else {
				err = json.Unmarshal(d, &v)
			}
			if err != nil {
				res = fail(err)
			} else {
				res = marshalAny(v, true)
			}
		case "tokens":
			// tokens <chunk> <usenumber> <hex>
			chunk := 0
			fmt.Sscan(f[1], &chunk)
			d := json.NewDecoder(chunkReader{bytes.NewReader(dec(f[3])), chunk})
			if f[2] == "1" {
				d.UseNumber()
			}
			var parts []string
			for i := 0; i < 100000; i++ {
				more := d.More()
				t, err := d.Token()
				if err != nil {
					parts = append(parts, errText(err))
					break
				}
				parts = append(parts, fmt.Sprintf("%s|%d|%v", tokenText(t), d.InputOffset(), more))
			}
			res = "ok " + enc([]byte(strings.Join(parts, "\n")))
		case "decodes":
			// decodes <chunk> <usenumber> <hex>: Decode values until error.
			chunk := 0
			fmt.Sscan(f[1], &chunk)
			d := json.NewDecoder(chunkReader{bytes.NewReader(dec(f[3])), chunk})
			if f[2] == "1" {
				d.UseNumber()
			}
			var parts []string
			for i := 0; i < 100000; i++ {
				var v any
				err := d.Decode(&v)
				if err != nil {
					parts = append(parts, errText(err))
					break
				}
				b, _ := json.Marshal(v)
				rest, _ := io.ReadAll(d.Buffered())
				parts = append(parts, fmt.Sprintf("%s|%d|%s", enc(b), d.InputOffset(), enc(rest)))
			}
			res = "ok " + enc([]byte(strings.Join(parts, "\n")))
		case "marshal":
			res = marshalTyped(f[1], f[2], f[3:])
		case "unmarshaltyped":
			res = unmarshalTyped(f[1], f[2], dec(f[3]))
		case "gen":
			seed, _ := strconv.ParseInt(f[2], 10, 64)
			res = generate(f[1], seed, f[3] == "1")
		default:
			res = "err " + enc([]byte("unknown op "+f[0])) + " -"
		}
		fmt.Fprintln(out, res)
	}
}

// ---- Marshal differential -------------------------------------------------
//
// Request: "marshal <type> <mode> <atom>..." with mode h (Marshal), n
// (Encoder with SetEscapeHTML(false)), i (MarshalIndent("> ", "  ")).
// Request: "gen <type> <seed> <special>" prints the atoms of a random value.
// The types below are mirrored by examples/json_probe.rs.

type Inner struct {
	X int64   `json:"x,omitempty"`
	Y string  `json:"y"`
	Z []int64 `json:"z,omitempty"`
}

type Inner2 struct {
	X int64  `json:"x,omitempty"`
	Y string `json:"y"`
}

type Basic struct {
	A     int64   `json:"a"`
	B     string  `json:"b,omitempty"`
	C     bool    `json:"c,omitempty"`
	D     float64 `json:"d"`
	E     float32 `json:"e,omitempty"`
	F     uint8   `json:"f,string"`
	G     int32   `json:",string"`
	H     string  `json:"h,string"`
	I     bool    `json:"i,string,omitempty"`
	J     float64 `json:"j,string"`
	Skip  int64   `json:"-"`
	Dash  int64   `json:"-,"`
	Plain int64
	Bad   int64  `json:"a'b"`
	Space int64  `json:"a b"`
	Uni   string `json:"é,omitempty"`
	Html  int64  `json:"<&>"`
	Opt   *int64 `json:"opt,string"`
	In    Inner  `json:"in"`
}

type Opts struct {
	P1 *int64           `json:"p1,omitempty"`
	P2 *int64           `json:"p2,omitzero"`
	P3 *int64           `json:"p3"`
	S1 []int64          `json:"s1,omitempty"`
	M1 map[string]int64 `json:"m1,omitempty"`
	Z1 string           `json:"z1,omitzero"`
	Z2 int64            `json:"z2,omitzero"`
	Z3 bool             `json:"z3,omitzero"`
	Z4 float64          `json:"z4,omitzero"`
	Z5 [2]int64         `json:"z5,omitzero"`
	Z6 Inner2           `json:"z6,omitzero"`
	I1 any              `json:"i1,omitempty"`
	R1 json.RawMessage  `json:"r1,omitempty"`
	B1 bool             `json:"b1,omitempty"`
	F1 float64          `json:"f1,omitempty"`
	A1 [0]int64         `json:"a1,omitempty"`
	N1 json.Number      `json:"n1,omitempty"`
	Q1 *string          `json:"q1,omitempty,string"`
}

type Containers struct {
	Ints   map[int64]string
	Uints  map[uint8]bool
	Strs   map[string][]string
	Arr    [3]string
	Nested [][]int64
	Ptrs   []*string
	Bytes  []byte
	Num    json.Number
	Any    any
	Raw    json.RawMessage
	MapAny map[string]any
	I64s   map[int64]int8
}

type Base struct {
	ID     int64  `json:"id"`
	Name   string `json:"name,omitempty"`
	Hidden int64  `json:"-"`
}

type Base2 struct {
	ID int64 `json:"id"`
	Z  int64
}

type L2 struct{ Deep int64 }
type L1 struct {
	L2
	Mid int64
}

type A1 struct{ V int64 }
type A2 struct {
	V int64
	W int64 `json:"w"`
}
type A3 struct {
	V int64 `json:"V"`
}

type Embed1 struct {
	Base
	Name string
	Own  int64
}
type Embed2 struct {
	Base
	Base2
	Last int64
}
type Embed3 struct {
	Base
	X Base2 `json:"nested"`
}
type Embed4 struct {
	A1
	A2
	End int64
}
type Embed5 struct {
	A1
	A3
}
type Embed6 struct {
	Top int64
	L1
}
type Embed7 struct {
	*Base
	Tail string `json:"tail,omitempty"`
}
type Embed8 struct {
	Base `json:"b8"`
	Base2
}

// Custom marshals itself: Raw is its JSON text, "ERR" makes it fail.
type Custom struct{ Raw string }

func (c Custom) MarshalJSON() ([]byte, error) {
	if c.Raw == "ERR" {
		return nil, errors.New("boom")
	}
	return []byte(c.Raw), nil
}

func (c *Custom) UnmarshalJSON(b []byte) error {
	if string(b) == `"ERRDEC"` {
		return errors.New("bad decode")
	}
	c.Raw = string(b)
	return nil
}

type Customs struct {
	A Custom            `json:"a"`
	B *Custom           `json:"b"`
	C []Custom          `json:"c"`
	D map[string]Custom `json:"d"`
	E Custom            `json:"e,omitempty"`
	F Custom            `json:"f,omitzero"`
	G Custom            `json:",string"`
}

type Floats struct {
	F1 float64
	F2 float64
	F3 float64
	F4 float64
	G1 float32
	G2 float32
	G3 float32
	S1 float64 `json:",string"`
	S2 float32 `json:",string"`
}

type Strings struct {
	S1 string
	S2 string
	S3 string `json:",omitempty"`
	M  map[string]int64
	K  map[string]string `json:"<k>&"`
	Q  string            `json:",string"`
}

var registry = map[string]reflect.Type{
	"Basic":      reflect.TypeOf(Basic{}),
	"Inner2":     reflect.TypeOf(Inner2{}),
	"Opts":       reflect.TypeOf(Opts{}),
	"Containers": reflect.TypeOf(Containers{}),
	"Embed1":     reflect.TypeOf(Embed1{}),
	"Embed2":     reflect.TypeOf(Embed2{}),
	"Embed3":     reflect.TypeOf(Embed3{}),
	"Embed4":     reflect.TypeOf(Embed4{}),
	"Embed5":     reflect.TypeOf(Embed5{}),
	"Embed6":     reflect.TypeOf(Embed6{}),
	"Embed7":     reflect.TypeOf(Embed7{}),
	"Embed8":     reflect.TypeOf(Embed8{}),
	"Floats":     reflect.TypeOf(Floats{}),
	"Customs":    reflect.TypeOf(Customs{}),
	"Strings":    reflect.TypeOf(Strings{}),
}

var customPool = []string{`null`, `true`, `1`, `"x"`, `[1, 2]`, ` { "a" : 1 } `, `"<>&\u2028"`, `ERR`, ``, `nope`, `1 2`, `{`, `"\u00e9"`, `[]`}

var (
	customType = reflect.TypeOf(Custom{})
	rawType    = reflect.TypeOf(json.RawMessage(nil))
	numberType = reflect.TypeOf(json.Number(""))
)

// ---- random atoms ----

var stringPool = []string{
	"", "a", "abc", "hello world", "é", "日本語", "😀", "\u2028", "\u2029", "<script>", "&amp;", ">", "\"quoted\"",
	"back\\slash", "tab\there", "nl\n", "cr\r", "\x00", "\x01\x1f", "\x7f", "\b\f", "'", "/", "a b", "~", "0", "-1", "1e3",
	"null", "true", "\u00a0", "\ufeff", "\U0010ffff", "x\u2028y", "</script>",
}

var intPool = []int64{0, 1, -1, 2, 7, 10, 42, 99, 100, 127, -128, 255, 256, 1000, 32767, -32768, 65535, 65536,
	2147483647, -2147483648, 4294967295, 9007199254740993, math.MaxInt64, math.MinInt64}

var floatPool = []float64{0, math.Copysign(0, -1), 1, -1, 0.5, 0.1, 100, 1e20, 1e21, 1e22, 1e23, 1e-6, 1e-7, 9.999999e-7,
	123456789, 1.5, 3.14159, 5e-324, math.MaxFloat64, -math.MaxFloat64, math.SmallestNonzeroFloat64, 1e300, 1e-300,
	12345678901234567890, 0.000001, 0.0000001234, 2.5e-5, 4.9e-324, 1.7976931348623157e308, 100000000000000000000,
	1e21 - 1e5, 123456.789e3, 0.3, 2.0 / 3.0}

var float32Pool = []float32{0, float32(math.Copysign(0, -1)), 1, 0.1, 16777216, 3.4028235e38, 1e-7, 1e-6, 1e21, 1.1754944e-38, 1.4e-45, 0.3, 100, 1e10, 7e22}

var jsonPool = []string{`null`, `true`, `false`, `0`, `-1.5e3`, `"s<>&"`, `[]`, `{}`, `[1,2,{"a":null}]`, `{"b":1,"a":[true,"x"]}`,
	`1e2`, `10000000000000000000000`, ` [ 1 , 2 ] `, `"\u2028"`, `{"k":{"z":1,"y":2}}`}

var rawPool = []string{`null`, `true`, `1`, `"x"`, `[1,2]`, ` { "a" : [ 1 , 2 ] } `, `"<>&"`, `{"b":1,"a":2}`, `1e2`, `"\u2028 é"`,
	`[`, `nope`, `{"a":}`, `1 2`, ``}

var numberPool = []string{"0", "1", "-1", "1.5", "1e5", "-0", "123456789012345678901234567890", "1E+2", "0.1e-5", "",
	"abc", "1.", ".5", "01", "+1", "1e", "-"}

type gen struct {
	r       *rand.Rand
	special bool
	out     []string
}

func (g *gen) emit(s string) { g.out = append(g.out, s) }

func (g *gen) pick(n int) int { return g.r.Intn(n) }

func (g *gen) value(t reflect.Type) {
	switch t {
	case customType:
		g.emit("s" + enc([]byte(customPool[g.pick(len(customPool))])))
		return
	case rawType:
		x := rawPool[g.pick(len(rawPool))]
		if !g.special && g.pick(4) != 0 {
			x = rawPool[g.pick(10)]
		}
		g.emit("r" + enc([]byte(x)))
		return
	case numberType:
		x := numberPool[g.pick(len(numberPool))]
		if !g.special && g.pick(4) != 0 {
			x = numberPool[g.pick(6)]
		}
		g.emit("N" + enc([]byte(x)))
		return
	}
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		bits := uint(t.Bits())
		for {
			var n int64
			if g.pick(3) == 0 {
				n = int64(g.r.Uint64())
				if bits < 64 {
					n >>= (64 - bits)
				}
			} else {
				n = intPool[g.pick(len(intPool))]
			}
			if bits < 64 && (n < -(1<<(bits-1)) || n >= 1<<(bits-1)) {
				continue
			}
			g.emit("i" + strconv.FormatInt(n, 10))
			return
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		bits := uint(t.Bits())
		for {
			var n uint64
			if g.pick(3) == 0 {
				n = g.r.Uint64()
				if bits < 64 {
					n >>= (64 - bits)
				}
			} else {
				n = uint64(intPool[g.pick(len(intPool))])
			}
			if bits < 64 && n >= 1<<bits {
				continue
			}
			g.emit("u" + strconv.FormatUint(n, 10))
			return
		}
	case reflect.Float64:
		var f float64
		switch g.pick(4) {
		case 0:
			f = math.Float64frombits(g.r.Uint64())
			if math.IsNaN(f) || math.IsInf(f, 0) {
				f = 1.5
			}
		default:
			f = floatPool[g.pick(len(floatPool))]
		}
		if g.special && g.pick(6) == 0 {
			f = []float64{math.NaN(), math.Inf(1), math.Inf(-1)}[g.pick(3)]
		}
		g.emit(fmt.Sprintf("f%016x", math.Float64bits(f)))
	case reflect.Float32:
		var f float32
		switch g.pick(4) {
		case 0:
			f = math.Float32frombits(g.r.Uint32())
			if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
				f = 2.5
			}
		default:
			f = float32Pool[g.pick(len(float32Pool))]
		}
		if g.special && g.pick(6) == 0 {
			f = float32([]float64{math.NaN(), math.Inf(1), math.Inf(-1)}[g.pick(3)])
		}
		g.emit(fmt.Sprintf("g%08x", math.Float32bits(f)))
	case reflect.Bool:
		g.emit("b" + strconv.Itoa(g.pick(2)))
	case reflect.String:
		g.emit("s" + enc([]byte(stringPool[g.pick(len(stringPool))])))
	case reflect.Pointer:
		if g.pick(3) == 0 {
			g.emit("n")
			return
		}
		g.emit("p")
		g.value(t.Elem())
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			b := make([]byte, g.pick(6))
			for i := range b {
				b[i] = byte(g.r.Intn(256))
			}
			g.emit("y" + enc(b))
			return
		}
		n := g.pick(4)
		g.emit("l" + strconv.Itoa(n))
		for i := 0; i < n; i++ {
			g.value(t.Elem())
		}
	case reflect.Array:
		for i := 0; i < t.Len(); i++ {
			g.value(t.Elem())
		}
	case reflect.Map:
		n := g.pick(4)
		// Distinct keys, in generation order.
		keys := map[string]bool{}
		var atoms [][]string
		for i := 0; i < n; i++ {
			sub := &gen{r: g.r, special: g.special}
			sub.value(t.Key())
			k := strings.Join(sub.out, " ")
			if keys[k] {
				continue
			}
			keys[k] = true
			sub.value(t.Elem())
			atoms = append(atoms, sub.out)
		}
		g.emit("m" + strconv.Itoa(len(atoms)))
		for _, a := range atoms {
			g.out = append(g.out, a...)
		}
	case reflect.Interface:
		g.emit("v" + enc([]byte(jsonPool[g.pick(len(jsonPool))])))
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			g.value(t.Field(i).Type)
		}
	default:
		panic("gen: unsupported kind " + t.String())
	}
}

type atoms struct {
	toks []string
	i    int
}

func (a *atoms) next() string {
	if a.i >= len(a.toks) {
		panic("atoms exhausted")
	}
	a.i++
	return a.toks[a.i-1]
}

func fill(v reflect.Value, a *atoms) {
	t := v.Type()
	switch t {
	case rawType:
		tok := a.next()
		if tok[1:] != "-" {
			v.SetBytes(dec(tok[1:]))
		}
		return
	case numberType:
		v.SetString(string(dec(a.next()[1:])))
		return
	}
	switch t.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(a.next()[1:], 10, 64)
		if err != nil {
			panic(err)
		}
		v.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(a.next()[1:], 10, 64)
		if err != nil {
			panic(err)
		}
		v.SetUint(n)
	case reflect.Float64:
		n, err := strconv.ParseUint(a.next()[1:], 16, 64)
		if err != nil {
			panic(err)
		}
		v.SetFloat(math.Float64frombits(n))
	case reflect.Float32:
		n, err := strconv.ParseUint(a.next()[1:], 16, 32)
		if err != nil {
			panic(err)
		}
		v.SetFloat(float64(math.Float32frombits(uint32(n))))
	case reflect.Bool:
		v.SetBool(a.next() == "b1")
	case reflect.String:
		v.SetString(string(dec(a.next()[1:])))
	case reflect.Pointer:
		if a.next() == "p" {
			v.Set(reflect.New(t.Elem()))
			fill(v.Elem(), a)
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			v.SetBytes(dec(a.next()[1:]))
			if v.IsNil() {
				v.SetBytes([]byte{})
			}
			return
		}
		n, _ := strconv.Atoi(a.next()[1:])
		v.Set(reflect.MakeSlice(t, n, n))
		for i := 0; i < n; i++ {
			fill(v.Index(i), a)
		}
	case reflect.Array:
		for i := 0; i < t.Len(); i++ {
			fill(v.Index(i), a)
		}
	case reflect.Map:
		n, _ := strconv.Atoi(a.next()[1:])
		v.Set(reflect.MakeMap(t))
		for i := 0; i < n; i++ {
			k := reflect.New(t.Key()).Elem()
			fill(k, a)
			e := reflect.New(t.Elem()).Elem()
			fill(e, a)
			v.SetMapIndex(k, e)
		}
	case reflect.Interface:
		var x any
		if err := json.Unmarshal(dec(a.next()[1:]), &x); err != nil {
			panic(err)
		}
		if x != nil {
			v.Set(reflect.ValueOf(x))
		}
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			fill(v.Field(i), a)
		}
	default:
		panic("fill: unsupported kind " + t.String())
	}
}

// parseOptions maps the letters of an "o..." mode to v1 option switches.
func parseOptions(mode string) []jsonv2.Options {
	var opts []jsonv2.Options
	for _, c := range mode[1:] {
		switch c {
		case 'e':
			opts = append(opts, json.OmitEmptyWithLegacySemantics(false))
		case 's':
			opts = append(opts, json.StringifyWithLegacySemantics(false))
		case 'a':
			opts = append(opts, json.UnmarshalArrayFromAnyLength(false))
		case 'd':
			opts = append(opts, json.MatchCaseSensitiveDelimiter(false))
		case 'b':
			opts = append(opts, json.ParseBytesWithLooseRFC4648(false))
		case 'y':
			opts = append(opts, json.FormatBytesWithLegacySemantics(false))
		}
	}
	return opts
}

func marshalTyped(name, mode string, toks []string) string {
	t, found := registry[name]
	if !found {
		return "err " + enc([]byte("unknown type "+name)) + " -"
	}
	v := reflect.New(t)
	a := &atoms{toks: toks}
	fill(v.Elem(), a)
	if a.i != len(toks) {
		panic("atoms left over")
	}
	var b []byte
	var err error
	switch {
	case strings.HasPrefix(mode, "o"):
		b, err = jsonv2.Marshal(v.Interface(), append([]jsonv2.Options{json.DefaultOptionsV1()}, parseOptions(mode)...)...)
	case mode == "h":
		b, err = json.Marshal(v.Interface())
	case mode == "i":
		b, err = json.MarshalIndent(v.Interface(), "> ", "  ")
	default:
		var buf bytes.Buffer
		e := json.NewEncoder(&buf)
		e.SetEscapeHTML(false)
		err = e.Encode(v.Interface())
		b = bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	}
	if err != nil {
		return fail(err)
	}
	return ok(b)
}

func generate(name string, seed int64, special bool) string {
	t, found := registry[name]
	if !found {
		return "unknown"
	}
	g := &gen{r: rand.New(rand.NewSource(seed)), special: special}
	g.value(t)
	return strings.Join(g.out, " ")
}

// normalize replaces nil slices and maps with empty ones: Rust has no nil.
func normalize(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			normalize(v.Elem())
		}
	case reflect.Slice:
		if v.Type() == rawType {
			return
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			if v.IsNil() {
				v.Set(reflect.MakeSlice(v.Type(), 0, 0))
			}
			return
		}
		if v.IsNil() {
			v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		}
		for i := 0; i < v.Len(); i++ {
			normalize(v.Index(i))
		}
	case reflect.Map:
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
		for _, k := range v.MapKeys() {
			e := reflect.New(v.Type().Elem()).Elem()
			e.Set(v.MapIndex(k))
			normalize(e)
			v.SetMapIndex(k, e)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			normalize(v.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			normalize(v.Field(i))
		}
	case reflect.Interface:
		// Dynamic values keep their shape.
	}
}

func unmarshalTyped(name, mode string, data []byte) string {
	t, found := registry[name]
	if !found {
		return "err " + enc([]byte("unknown type "+name)) + " -"
	}
	v := reflect.New(t)
	var uerr error
	if strings.HasPrefix(mode, "o") {
		uerr = jsonv2.Unmarshal(data, v.Interface(), append([]jsonv2.Options{json.DefaultOptionsV1()}, parseOptions(mode)...)...)
	} else {
		uerr = json.Unmarshal(data, v.Interface())
	}
	if err := uerr; err != nil {
		var te *json.UnmarshalTypeError
		msg := strings.ReplaceAll(err.Error(), "main.", "")
		if errors.As(err, &te) {
			return fmt.Sprintf("err %s t%d", enc([]byte(msg)), te.Offset)
		}
		var se *json.SyntaxError
		if errors.As(err, &se) {
			return fmt.Sprintf("err %s %d", enc([]byte(msg)), se.Offset)
		}
		return "err " + enc([]byte(msg)) + " -"
	}
	normalize(v.Elem())
	b, err := json.Marshal(v.Interface())
	if err != nil {
		// Only the decode is under test here; marshal errors are covered
		// by marshalTyped.
		return "err " + enc([]byte("remarshal")) + " -"
	}
	return ok(b)
}
