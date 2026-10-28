// Line-oriented Go encoding/json/v2 oracle for tools/jsonv2_check.py.
//
// Each request is "op field..." with hex-encoded binary fields ("-" is
// empty). The types below are mirrored by
// tools/derive-check/examples/jsonv2_typed_probe.rs.
//
//	gen <type> <seed> <special>             atoms of a random value
//	marshal <type> <opts> <atoms...>        json.Marshal of the value
//	unmarshal <type> <opts> <hex> <atoms..> json.Unmarshal into a (pre-filled) value, then Marshal
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"
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

func normalizeMessage(s string) string {
	s = string([]rune(s)) // each invalid byte becomes U+FFFD, as Rust strings must be valid
	s = strings.ReplaceAll(s, "main.", "")
	return strings.ReplaceAll(s, "unable to", "cannot")
}

func kindChar(k jsontext.Kind) string {
	if k == 0 {
		return "_"
	}
	return string([]byte{byte(k)})
}

// errInfo describes the structured fields of an error.
func errInfo(err error) string {
	var se *json.SemanticError
	if errors.As(err, &se) {
		typ := "-"
		if se.GoType != nil {
			typ = enc([]byte(normalizeMessage(se.GoType.String())))
		}
		return fmt.Sprintf("s%d@%s@%s@%s@%s", se.ByteOffset, enc([]byte(se.JSONPointer)), kindChar(se.JSONKind), enc(se.JSONValue), typ)
	}
	var sy *jsontext.SyntacticError
	if errors.As(err, &sy) {
		return fmt.Sprintf("y%d@%s", sy.ByteOffset, enc([]byte(sy.JSONPointer)))
	}
	return "-"
}

func fail(err error) string {
	return "err " + enc([]byte(normalizeMessage(err.Error()))) + " " + errInfo(err)
}

// ---------------------------------------------------------------- types

type Inner struct {
	X int64   `json:"x,omitempty"`
	Y string  `json:"y"`
	Z []int64 `json:"z,omitempty"`
}

type Scalars struct {
	B   bool
	I8  int8
	I16 int16
	I32 int32
	I64 int64
	I   int
	U8  uint8
	U16 uint16
	U32 uint32
	U64 uint64
	U   uint
	F32 float32
	F64 float64
	S   string
}

type Tags struct {
	A     int64            `json:"a"`
	B     string           `json:"b,omitempty"`
	C     int64            `json:"c,omitzero"`
	D     float64          `json:",string"`
	E     int32            `json:"e,string"`
	F     uint8            `json:"f,omitempty"`
	G     bool             `json:"g,omitempty,omitzero"`
	H     *int64           `json:"h,omitempty"`
	I     *int64           `json:"i,omitzero"`
	J     []int64          `json:"j,omitempty"`
	K     map[string]int64 `json:"k,omitempty"`
	L     Inner            `json:"l,omitzero"`
	M     [2]int64         `json:"m,omitempty"`
	Skip  int64            `json:"-"`
	Dash  int64            `json:"-,"`
	Plain int64
	Uni   string `json:"é,omitempty"`
	Html  int64  `json:"<&>"`
	Ign   string `json:"ign,case:ignore"`
	Str   string `json:"str,case:strict"`
	Quo   string `json:"a\"b"`
}

type Omit struct {
	P1 *int64           `json:"p1,omitempty"`
	S1 []int64          `json:"s1,omitempty"`
	M1 map[string]int64 `json:"m1,omitempty"`
	Z1 string           `json:"z1,omitempty"`
	Z2 int64            `json:"z2,omitempty"`
	B1 bool             `json:"b1,omitempty"`
	F1 float64          `json:"f1,omitempty"`
	A1 [0]int64         `json:"a1,omitempty"`
	A2 [2]int64         `json:"a2,omitempty"`
	I1 any              `json:"i1,omitempty"`
	R1 jsontext.Value   `json:"r1,omitempty"`
	Y1 []byte           `json:"y1,omitempty"`
	Q1 *string          `json:"q1,omitempty"`
	In Inner            `json:"in,omitempty"`
	N1 *Inner           `json:"n1,omitempty"`
	Z3 bool             `json:"z3,omitzero"`
	Z4 float64          `json:"z4,omitzero"`
	Z5 [2]int64         `json:"z5,omitzero"`
	Z6 Inner            `json:"z6,omitzero"`
	Z7 []int64          `json:"z7,omitzero"`
	Z8 any              `json:"z8,omitzero"`
}

type Containers struct {
	Ints   map[int64]string
	Uints  map[uint8]bool
	Strs   map[string][]string
	Arr    [3]string
	Nested [][]int64
	Ptrs   []*string
	Bytes  []byte
	Any    any
	MapAny map[string]any
	I64s   map[int64]int8
	Raw    jsontext.Value
	Obj    map[string]Inner
}

type BoolKeys struct {
	M map[bool]int64
}

type Floats struct {
	F1 float64
	F2 float64
	F3 float64
	G1 float32
	G2 float32
	S1 float64 `json:",string"`
	S2 float32 `json:",string"`
	N1 float64 `json:",omitempty"`
}

type StrTags struct {
	A int64   `json:",string"`
	B uint16  `json:",string"`
	C float64 `json:",string"`
	D *int64  `json:",string"`
	E []int64 `json:"e,string,omitempty"`
}

type StrErr struct {
	S string `json:",string"`
}
type BoolErr struct {
	B bool `json:",string"`
}
type MapErr struct {
	M map[string]int64 `json:",string"`
}

type Names struct {
	S1 string
	S2 string `json:",omitempty"`
	M  map[string]int64
	K  map[string]string `json:"<k>&"`
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
type Embed9 struct {
	X Base `json:",embed"`
	Y int64
}
type Embed10 struct {
	Base  `json:",omitempty"`
	Other int64
}

type Conflict struct {
	A int64 `json:"x"`
	B int64 `json:"x"`
}

type BadTag1 struct {
	A int64 `json:"a,omitempty,omitempty"`
}
type BadTag2 struct {
	A int64 `json:"a,case:ignore,case:strict"`
}
type BadTag3 struct {
	A int64 `json:"a,format"`
}
type BadTag4 struct {
	A int64 `json:",bogus"`
	B int64 `json:"b,omitEmpty"`
}
type BadTag5 struct {
	A int64 `json:"a,"`
}
type BadTag6 struct {
	A int64 `json:"'a'"`
}
type BadTag7 struct {
	A int64 `json:"a,case"`
	B int64 `json:"b,case:wrong"`
}
type Fmt struct {
	A int64  `json:"a,format:hex"`
	B []byte `json:"b,format:base64url"`
}
type Empty struct{}
type NoFields struct {
	a int64
}

type Fall1 struct {
	A    int64
	Rest map[string]any `json:",embed"`
}
type Fall2 struct {
	A    int64          `json:"a"`
	Rest jsontext.Value `json:",embed"`
}
type Fall3 struct {
	Base
	Rest map[string]int64 `json:",embed"`
}
type Fall4 struct {
	*Inner
	Rest map[string]string `json:",embed"`
}
type FallBad struct {
	R1 map[string]any `json:",embed"`
	R2 jsontext.Value `json:",embed"`
}

// Cust marshals itself: Raw is its JSON text, "ERR" makes it fail.
type Cust struct{ Raw string }

func (c Cust) MarshalJSON() ([]byte, error) {
	if c.Raw == "ERR" {
		return nil, errors.New("boom")
	}
	if c.Raw == "UNSUP" {
		return nil, errors.ErrUnsupported
	}
	return []byte(c.Raw), nil
}

func (c *Cust) UnmarshalJSON(b []byte) error {
	if string(b) == `"ERRDEC"` {
		return errors.New("bad decode")
	}
	c.Raw = string(b)
	return nil
}

// To implements MarshalerTo and UnmarshalerFrom.
type To struct{ S string }

func (t To) MarshalJSONTo(e *jsontext.Encoder) error {
	switch t.S {
	case "unsupported":
		return errors.ErrUnsupported
	case "err":
		return errors.New("custom failure")
	case "two":
		if err := e.WriteToken(jsontext.String("a")); err != nil {
			return err
		}
		return e.WriteToken(jsontext.String("b"))
	case "none":
		return nil
	case "obj":
		for _, tok := range []jsontext.Token{jsontext.BeginObject, jsontext.String("k"), jsontext.Int(1), jsontext.EndObject} {
			if err := e.WriteToken(tok); err != nil {
				return err
			}
		}
		return nil
	case "dup":
		for _, tok := range []jsontext.Token{jsontext.BeginObject, jsontext.String("k"), jsontext.Int(1), jsontext.String("k")} {
			if err := e.WriteToken(tok); err != nil {
				return err
			}
		}
		return nil
	}
	return e.WriteToken(jsontext.String("<" + t.S + ">"))
}

func (t *To) UnmarshalJSONFrom(d *jsontext.Decoder) error {
	if d.PeekKind() == '[' {
		return errors.ErrUnsupported
	}
	tok, err := d.ReadToken()
	if err != nil {
		return err
	}
	switch tok.Kind() {
	case '"':
		if tok.String() == "bad" {
			return errors.New("bad value")
		}
		t.S = tok.String()
		return nil
	case '0':
		t.S = tok.String()
		return nil
	case '{':
		return d.SkipValue()
	}
	return errors.New("unexpected token " + tok.Kind().String())
}

// Txt implements encoding.TextMarshaler and encoding.TextUnmarshaler.
type Txt struct{ S string }

func (t Txt) MarshalText() ([]byte, error) {
	if t.S == "ERR" {
		return nil, errors.New("text failure")
	}
	return []byte("t:" + t.S), nil
}

func (t *Txt) UnmarshalText(b []byte) error {
	s, ok := strings.CutPrefix(string(b), "t:")
	if !ok {
		return errors.New("missing prefix")
	}
	t.S = s
	return nil
}

type Customs struct {
	A Cust            `json:"a"`
	B *Cust           `json:"b"`
	C []Cust          `json:"c"`
	D map[string]Cust `json:"d"`
	E Cust            `json:"e,omitempty"`
	F Cust            `json:"f,omitzero"`
	T To              `json:"t"`
	U []To            `json:"u"`
	X Txt             `json:"x"`
	Y map[string]Txt  `json:"y"`
	Z *Txt            `json:"z,omitempty"`
}

type Times struct {
	A time.Time            `json:"a"`
	B time.Time            `json:"b,omitzero"`
	C *time.Time           `json:"c,omitempty"`
	D []time.Time          `json:"d"`
	E map[string]time.Time `json:"e"`
	F time.Time            `json:"f,omitempty"`
}
type TimeFmts struct {
	U  time.Time `json:"u,format:unix"`
	UM time.Time `json:"um,format:unixmilli"`
	UU time.Time `json:"uu,format:unixmicro"`
	UN time.Time `json:"un,format:unixnano"`
	US time.Time `json:"us,string,format:unixmilli"`
	R  time.Time `json:"r,format:RFC3339"`
	RN time.Time `json:"rn,format:RFC3339Nano"`
	AN time.Time `json:"an,format:ANSIC"`
	UD time.Time `json:"ud,format:UnixDate"`
	RB time.Time `json:"rb,format:RubyDate"`
	R8 time.Time `json:"r8,format:RFC822"`
	RZ time.Time `json:"rz,format:RFC822Z"`
	R5 time.Time `json:"r5,format:RFC850"`
	R1 time.Time `json:"r1,format:RFC1123"`
	RY time.Time `json:"ry,format:RFC1123Z"`
	K  time.Time `json:"k,format:Kitchen"`
	SN time.Time `json:"sn,format:StampNano"`
	DT time.Time `json:"dt,format:DateTime"`
	DO time.Time `json:"do,format:DateOnly"`
	TO time.Time `json:"to,format:TimeOnly"`
	CU time.Time `json:"cu,format:'2006/01/02 15h04.000 -0700'"`
}
type TimeBad struct {
	A time.Time `json:"a,string"`
	B time.Time `json:"b,format:Bogus"`
}
type Durs struct {
	D time.Duration  `json:"d"`
	P *time.Duration `json:"p"`
}
type DurFmts struct {
	U  time.Duration `json:"u,format:units"`
	S  time.Duration `json:"s,format:sec"`
	SS time.Duration `json:"ss,string,format:sec"`
	M  time.Duration `json:"m,format:milli"`
	MI time.Duration `json:"mi,format:micro"`
	N  time.Duration `json:"n,format:nano"`
	I  time.Duration `json:"i,format:iso8601"`
	IZ time.Duration `json:"iz,omitzero,format:iso8601"`
}
type DurBad struct {
	A time.Duration `json:"a,string,format:units"`
	B time.Duration `json:"b,format:hours"`
}

var registry = map[string]reflect.Type{}

func register(vs ...any) {
	for _, v := range vs {
		t := reflect.TypeOf(v)
		registry[t.Name()] = t
	}
}

func init() {
	register(Inner{}, Scalars{}, Tags{}, Omit{}, Containers{}, BoolKeys{}, Floats{}, StrTags{}, StrErr{}, BoolErr{}, MapErr{},
		Names{}, Embed1{}, Embed2{}, Embed3{}, Embed4{}, Embed5{}, Embed6{}, Embed7{}, Embed8{}, Embed9{}, Embed10{},
		Conflict{}, BadTag1{}, BadTag2{}, BadTag3{}, BadTag4{}, BadTag5{}, BadTag6{}, BadTag7{}, Fmt{}, Empty{}, NoFields{},
		Fall1{}, Fall2{}, Fall3{}, Fall4{}, FallBad{}, Customs{}, Times{}, TimeFmts{}, TimeBad{}, Durs{}, DurFmts{},
		DurBad{})
}

var (
	custType = reflect.TypeOf(Cust{})
	toType   = reflect.TypeOf(To{})
	txtType  = reflect.TypeOf(Txt{})
	valType  = reflect.TypeOf(jsontext.Value(nil))
	timeType = reflect.TypeOf(time.Time{})
)

// formatTagSupport turns on the experimental `format` tag option, as
// github.com/go-json-experiment/json.ExperimentalSupportFormatTag does.
type formatTagSupport struct{ json.Options }

func (formatTagSupport) ExperimentalSupportFormatTag() bool { return true }

// ---------------------------------------------------------------- options

func parseOptions(letters string) []json.Options {
	opts := []json.Options{json.Deterministic(true)}
	if letters == "-" {
		return opts
	}
	for _, c := range letters {
		switch c {
		case 'n':
			opts = append(opts, json.StringifyNumbers(true))
		case 'o':
			opts = append(opts, json.OmitZeroStructFields(true))
		case 'i':
			opts = append(opts, json.MatchCaseInsensitiveNames(true))
		case 'r':
			opts = append(opts, json.RejectUnknownMembers(true))
		case 'h':
			opts = append(opts, jsontext.EscapeForHTML(true))
		case 'j':
			opts = append(opts, jsontext.EscapeForJS(true))
		case 'm':
			opts = append(opts, jsontext.Multiline(true))
		case 'x':
			opts = append(opts, jsontext.WithIndent("  "))
		case 'c':
			opts = append(opts, jsontext.SpaceAfterColon(true))
		case 'k':
			opts = append(opts, jsontext.SpaceAfterComma(true))
		case 'a':
			opts = append(opts, jsontext.AllowDuplicateNames(true))
		case 'v':
			opts = append(opts, jsontext.AllowInvalidUTF8(true))
		case 'p':
			opts = append(opts, json.FormatNilSliceAsNull(true))
		case 'q':
			opts = append(opts, json.FormatNilMapAsNull(true))
		case 'D':
			opts = append(opts, json.Deterministic(false))
		case 't':
			opts = append(opts, formatTagSupport{json.Deterministic(true)})
		case 'F':
			opts = append(opts, json.WithMarshalers(json.JoinMarshalers(
				json.MarshalFunc(func(v int64) ([]byte, error) {
					switch v {
					case 13:
						return nil, errors.New("unlucky")
					case 14:
						return []byte("nope"), nil
					case 15:
						return nil, errors.ErrUnsupported
					}
					return []byte(strconv.Quote("n" + strconv.FormatInt(v, 10))), nil
				}),
				json.MarshalToFunc(func(e *jsontext.Encoder, s string) error {
					switch s {
					case "":
						return errors.ErrUnsupported
					case "two":
						if err := e.WriteToken(jsontext.String("a")); err != nil {
							return err
						}
						return e.WriteToken(jsontext.String("b"))
					case "err":
						return errors.New("string failure")
					}
					return e.WriteToken(jsontext.String(strings.ToUpper(s)))
				}),
			)))
		case 'G':
			opts = append(opts, json.WithUnmarshalers(json.JoinUnmarshalers(
				json.UnmarshalFunc(func(b []byte, v *int64) error {
					s, err := strconv.Unquote(string(b))
					if err != nil {
						return errors.New("not a string")
					}
					n, err := strconv.ParseInt(strings.TrimPrefix(s, "n"), 10, 64)
					if err != nil {
						return errors.New("not a number")
					}
					*v = n
					return nil
				}),
				json.UnmarshalFromFunc(func(d *jsontext.Decoder, v *string) error {
					if d.PeekKind() == 'n' {
						return errors.ErrUnsupported
					}
					tok, err := d.ReadToken()
					if err != nil {
						return err
					}
					if tok.Kind() != '"' {
						return errors.New("want string")
					}
					*v = strings.ToUpper(tok.String())
					return nil
				}),
			)))
		default:
			panic("unknown option letter " + string(c))
		}
	}
	return opts
}

// ---------------------------------------------------------------- random atoms

var stringPool = []string{
	"", "a", "hello world", "é", "日本語", "😀", "\u2028", "\u2029", "<script>", "&amp;", ">", "\"quoted\"",
	"back\\slash", "tab\there", "nl\n", "cr\r", "\x00", "\x01\x1f", "\x7f", "\b\f", "'", "/", "a b", "~", "0", "-1", "1e3",
	"null", "true", "\u00a0", "\ufeff", "\U0010ffff", "x\u2028y", "</script>", "ID", "Name", "x", "ABC", "a_b", "a-b",
}

var intPool = []int64{0, 1, -1, 2, 7, 10, 42, 99, 100, 127, -128, 255, 256, 1000, 32767, -32768, 65535, 65536,
	2147483647, -2147483648, 4294967295, 9007199254740993, math.MaxInt64, math.MinInt64, 13, 14, 15}

var floatPool = []float64{0, math.Copysign(0, -1), 1, -1, 0.5, 0.1, 100, 1e20, 1e21, 1e22, 1e23, 1e-6, 1e-7, 9.999999e-7,
	123456789, 1.5, 3.14159, 5e-324, math.MaxFloat64, -math.MaxFloat64, 1e300, 1e-300, 12345678901234567890, 2.5e-5,
	1e21 - 1e5, 0.3, 2.0 / 3.0}

var float32Pool = []float32{0, float32(math.Copysign(0, -1)), 1, 0.1, 16777216, 3.4028235e38, 1e-7, 1e-6, 1e21, 1.1754944e-38, 1.4e-45, 0.3, 100, 1e10, 7e22}

var jsonPool = []string{`null`, `true`, `false`, `0`, `-1.5e3`, `"s<>&"`, `[]`, `{}`, `[1,2,{"a":null}]`, `{"b":1,"a":[true,"x"]}`,
	`1e2`, `10000000000000000000000`, `"\u2028"`, `{"k":{"z":1,"y":2}}`, `[[],{},"é"]`}

var rawPool = []string{`null`, `true`, `1`, `"x"`, `[1,2]`, ` { "a" : [ 1 , 2 ] } `, `"<>&"`, `{"b":1,"a":2}`, `1e2`, `"\u2028 é"`,
	`{"u":1,"v":[true]}`, `{"k":1,"k":2}`, `{}`, `[`, `nope`, `{"a":}`, `1 2`, ``}

var custPool = []string{`null`, `true`, `1`, `"x"`, `[1, 2]`, ` { "a" : 1 } `, `"<>&\u2028"`, `ERR`, `UNSUP`, ``, `nope`, `1 2`, `{`, `"é"`, `[]`}

// timePool holds Unix seconds at the edges of what RFC 3339 and the unix
// formats can represent; timeZones are fixed offsets in seconds, "u" being
// UTC.
var timePool = []int64{0, 1, -1, 1e9, 1767225600, -62135596800, -62135596801, 253402300799, 253402300800,
	-62167219200, -62198755200, math.MaxInt64 / 1000000000, math.MinInt64 / 1000000000, 1 << 40, -(1 << 40)}

var nanoPool = []int64{0, 1, 999999999, 500000000, 123456789, 1000, 1000000}

var timeZones = []string{"u", "u", "0", "19800", "-86340", "-3600", "3600", "-18000", "86400", "90000"}

var toPool = []string{"a", "", "unsupported", "err", "two", "none", "obj", "dup", "bad", "x y", "<&>"}

type gen struct {
	r       *rand.Rand
	special bool
	out     []string
}

func (g *gen) emit(s string) { g.out = append(g.out, s) }

func (g *gen) pick(n int) int { return g.r.Intn(n) }

func (g *gen) value(t reflect.Type) {
	switch t {
	case custType:
		g.emit("s" + enc([]byte(custPool[g.pick(len(custPool))])))
		return
	case toType:
		g.emit("s" + enc([]byte(toPool[g.pick(len(toPool))])))
		return
	case txtType:
		g.emit("s" + enc([]byte(stringPool[g.pick(len(stringPool))])))
		return
	case timeType:
		if !g.special && g.pick(4) == 0 {
			g.emit("t-")
			return
		}
		// Mostly years 1 to 9999 and offsets under 24 hours, which RFC 3339
		// can represent; the special values add the edges.
		sec := g.r.Int63n(253402300800+62135596800) - 62135596800
		zones := timeZones[:len(timeZones)-2]
		if g.special {
			sec, zones = timePool[g.pick(len(timePool))], timeZones
		}
		nsec := nanoPool[g.pick(len(nanoPool))]
		if g.pick(3) == 0 {
			nsec = g.r.Int63n(1e9)
		}
		g.emit(fmt.Sprintf("t%d.%d.%s", sec, nsec, zones[g.pick(len(zones))]))
		return
	case valType:
		x := rawPool[g.pick(len(rawPool))]
		if !g.special && g.pick(4) != 0 {
			x = rawPool[g.pick(10)]
		}
		g.emit("r" + enc([]byte(x)))
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
			if !t.Field(i).IsExported() {
				continue
			}
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

// timeAtom decodes "t-" (the zero time) or "t<sec>.<nsec>.<zone>".
func timeAtom(tok string) time.Time {
	if tok == "t-" {
		return time.Time{}
	}
	f := strings.Split(tok[1:], ".")
	sec, _ := strconv.ParseInt(f[0], 10, 64)
	nsec, _ := strconv.ParseInt(f[1], 10, 64)
	t := time.Unix(sec, nsec).UTC()
	if f[2] != "u" {
		off, _ := strconv.Atoi(f[2])
		t = t.In(time.FixedZone("", off))
	}
	return t
}

func fill(v reflect.Value, a *atoms) {
	t := v.Type()
	switch t {
	case custType:
		v.Field(0).SetString(string(dec(a.next()[1:])))
		return
	case toType, txtType:
		v.Field(0).SetString(string(dec(a.next()[1:])))
		return
	case timeType:
		v.Set(reflect.ValueOf(timeAtom(a.next())))
		return
	case valType:
		tok := a.next()
		if tok[1:] != "-" {
			v.SetBytes(dec(tok[1:]))
		}
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
			if b := dec(a.next()[1:]); len(b) > 0 {
				v.SetBytes(b)
			}
			return
		}
		n, _ := strconv.Atoi(a.next()[1:])
		if n > 0 {
			v.Set(reflect.MakeSlice(t, n, n))
		}
		for i := 0; i < n; i++ {
			fill(v.Index(i), a)
		}
	case reflect.Array:
		for i := 0; i < t.Len(); i++ {
			fill(v.Index(i), a)
		}
	case reflect.Map:
		n, _ := strconv.Atoi(a.next()[1:])
		if n > 0 {
			v.Set(reflect.MakeMap(t))
		}
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
			if !t.Field(i).IsExported() {
				continue
			}
			fill(v.Field(i), a)
		}
	default:
		panic("fill: unsupported kind " + t.String())
	}
}

// nilify turns empty non-nil slices and maps into nil ones: Rust has one
// empty value for both.
func nilify(v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			nilify(v.Elem())
		}
	case reflect.Slice:
		if v.Type() == valType || v.Type().Elem().Kind() == reflect.Uint8 {
			if v.Len() == 0 && v.CanSet() {
				v.SetZero()
			}
			return
		}
		if v.Len() == 0 {
			if v.CanSet() {
				v.SetZero()
			}
			return
		}
		for i := 0; i < v.Len(); i++ {
			nilify(v.Index(i))
		}
	case reflect.Map:
		if v.Len() == 0 {
			if v.CanSet() {
				v.SetZero()
			}
			return
		}
		for _, k := range v.MapKeys() {
			e := reflect.New(v.Type().Elem()).Elem()
			e.Set(v.MapIndex(k))
			nilify(e)
			v.SetMapIndex(k, e)
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			nilify(v.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				nilify(v.Field(i))
			}
		}
	case reflect.Interface:
		if !v.IsNil() {
			e := reflect.New(v.Elem().Type()).Elem()
			e.Set(v.Elem())
			nilify(e)
			v.Set(e)
		}
	}
}

func marshalTyped(name, opts string, toks []string) string {
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
	b, err := json.Marshal(v.Interface(), parseOptions(opts)...)
	if err != nil {
		return fail(err)
	}
	return "ok " + enc(b)
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

func unmarshalTyped(name, opts string, data []byte, toks []string) string {
	t, found := registry[name]
	if !found {
		return "err " + enc([]byte("unknown type "+name)) + " -"
	}
	v := reflect.New(t)
	a := &atoms{toks: toks}
	if len(toks) > 0 {
		fill(v.Elem(), a)
		if a.i != len(toks) {
			panic("atoms left over")
		}
	}
	uerr := json.Unmarshal(data, v.Interface(), parseOptions(opts)...)
	nilify(v.Elem())
	b, err := json.Marshal(v.Interface(), json.Deterministic(true), formatTagSupport{json.Deterministic(true)})
	res := "ok"
	if uerr != nil {
		res = fail(uerr)
	}
	if err != nil {
		return res + " remarshal-error"
	}
	return res + " | " + enc(b)
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
					out = "panic " + enc([]byte(fmt.Sprint(r)))
				}
			}()
			switch f[0] {
			case "gen":
				seed, _ := strconv.ParseInt(f[2], 10, 64)
				out = generate(f[1], seed, f[3] == "1")
			case "marshal":
				out = marshalTyped(f[1], f[2], f[3:])
			case "unmarshal":
				out = unmarshalTyped(f[1], f[2], dec(f[3]), f[4:])
			default:
				out = "unknown op " + f[0]
			}
		}()
		fmt.Fprintln(w, out)
	}
}
