// Standalone encoding/asn1 differential oracle using Go's standard library.
//
// Each request carries a schema tree; the oracle builds the matching Go type
// at runtime with reflect.StructOf/SliceOf (field tags become `asn1:"..."`),
// then marshals a JSON value or unmarshals DER through encoding/asn1.
package main

import (
	"bufio"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"time"
)

type schema struct {
	K string    `json:"k"`
	P string    `json:"p"`
	F []*schema `json:"f"`
	E *schema   `json:"e"`
}

type request struct {
	Op string          `json:"op"`
	S  *schema         `json:"s"`
	V  json.RawMessage `json:"v"`
	D  string          `json:"d"`
}

var (
	anyType   = reflect.TypeOf((*any)(nil)).Elem()
	typeCache = map[string]reflect.Type{}
)

func goType(s *schema) reflect.Type {
	switch s.K {
	case "bool":
		return reflect.TypeOf(false)
	case "int":
		return reflect.TypeOf(int(0))
	case "int32":
		return reflect.TypeOf(int32(0))
	case "big":
		return reflect.TypeOf((*big.Int)(nil))
	case "enum":
		return reflect.TypeOf(asn1.Enumerated(0))
	case "flag":
		return reflect.TypeOf(asn1.Flag(false))
	case "bits":
		return reflect.TypeOf(asn1.BitString{})
	case "octets":
		return reflect.TypeOf([]byte(nil))
	case "oid":
		return reflect.TypeOf(asn1.ObjectIdentifier(nil))
	case "string":
		return reflect.TypeOf("")
	case "time":
		return reflect.TypeOf(time.Time{})
	case "raw":
		return reflect.TypeOf(asn1.RawValue{})
	case "any":
		return anyType
	case "seq":
		key, _ := json.Marshal(s)
		if t, ok := typeCache[string(key)]; ok {
			return t
		}
		fields := make([]reflect.StructField, len(s.F))
		for i, f := range s.F {
			fields[i] = reflect.StructField{
				Name: fmt.Sprintf("F%d", i),
				Type: goType(f),
				Tag:  reflect.StructTag(fmt.Sprintf("asn1:%q", f.P)),
			}
		}
		t := reflect.StructOf(fields)
		typeCache[string(key)] = t
		return t
	case "seqof":
		return reflect.SliceOf(goType(s.E))
	}
	panic("unknown kind " + s.K)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	if len(b) == 0 {
		return nil
	}
	return b
}

func num(raw json.RawMessage) int64 {
	var n json.Number
	if err := json.Unmarshal(raw, &n); err != nil {
		panic(err)
	}
	v, err := n.Int64()
	if err != nil {
		panic(err)
	}
	return v
}

func twosToBig(b []byte) *big.Int {
	n := new(big.Int)
	if len(b) > 0 && b[0]&0x80 != 0 {
		inv := make([]byte, len(b))
		for i := range b {
			inv[i] = ^b[i]
		}
		n.SetBytes(inv)
		n.Add(n, big.NewInt(1))
		return n.Neg(n)
	}
	return n.SetBytes(b)
}

func bigToTwos(n *big.Int) string {
	der, err := asn1.Marshal(n)
	if err != nil {
		panic(err)
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		panic(err)
	}
	return hex.EncodeToString(raw.Bytes)
}

func makeTime(f []int64) time.Time {
	loc := time.UTC
	if f[7] != 0 {
		loc = time.FixedZone("", int(f[7]))
	}
	return time.Date(int(f[0]), time.Month(f[1]), int(f[2]), int(f[3]), int(f[4]), int(f[5]), int(f[6]), loc)
}

func fill(v reflect.Value, s *schema, raw json.RawMessage) {
	switch s.K {
	case "bool", "flag":
		var b bool
		json.Unmarshal(raw, &b)
		v.SetBool(b)
	case "int", "int32", "enum":
		v.SetInt(num(raw))
	case "big":
		var h *string
		json.Unmarshal(raw, &h)
		if h != nil {
			v.Set(reflect.ValueOf(twosToBig(mustHex(*h))))
		}
	case "bits":
		var b struct {
			B string `json:"b"`
			N int    `json:"n"`
		}
		json.Unmarshal(raw, &b)
		v.Set(reflect.ValueOf(asn1.BitString{Bytes: mustHex(b.B), BitLength: b.N}))
	case "octets":
		var h string
		json.Unmarshal(raw, &h)
		v.SetBytes(mustHex(h))
	case "oid":
		var arcs []int
		json.Unmarshal(raw, &arcs)
		if len(arcs) > 0 {
			v.Set(reflect.ValueOf(asn1.ObjectIdentifier(arcs)))
		}
	case "string":
		var str string
		json.Unmarshal(raw, &str)
		v.SetString(str)
	case "time":
		var f []int64
		json.Unmarshal(raw, &f)
		v.Set(reflect.ValueOf(makeTime(f)))
	case "raw":
		var r struct {
			C int    `json:"c"`
			T int    `json:"t"`
			X bool   `json:"x"`
			B string `json:"b"`
			F string `json:"f"`
		}
		json.Unmarshal(raw, &r)
		v.Set(reflect.ValueOf(asn1.RawValue{Class: r.C, Tag: r.T, IsCompound: r.X, Bytes: mustHex(r.B), FullBytes: mustHex(r.F)}))
	case "seq":
		var items []json.RawMessage
		json.Unmarshal(raw, &items)
		for i, f := range s.F {
			fill(v.Field(i), f, items[i])
		}
	case "seqof":
		var items []json.RawMessage
		json.Unmarshal(raw, &items)
		if len(items) == 0 {
			return
		}
		slice := reflect.MakeSlice(v.Type(), len(items), len(items))
		for i, item := range items {
			fill(slice.Index(i), s.E, item)
		}
		v.Set(slice)
	default:
		panic("cannot fill " + s.K)
	}
}

// deviation reports values Go accepts that time::DateTime cannot represent.
var deviation string

func timeJSON(t time.Time) any {
	_, offset := t.Zone()
	if t.Year() < 1 || offset <= -86400 || offset >= 86400 {
		deviation = "time-range"
	}
	return []int64{int64(t.Year()), int64(t.Month()), int64(t.Day()), int64(t.Hour()), int64(t.Minute()), int64(t.Second()), int64(t.Nanosecond()), int64(offset)}
}

func bitsJSON(b asn1.BitString) any {
	return map[string]any{"b": hex.EncodeToString(b.Bytes), "n": b.BitLength}
}

func oidJSON(o asn1.ObjectIdentifier) any {
	if o == nil {
		return []int{}
	}
	return []int(o)
}

func toJSON(v reflect.Value, s *schema) any {
	switch s.K {
	case "bool", "flag":
		return v.Bool()
	case "int", "int32", "enum":
		return v.Int()
	case "big":
		if v.IsNil() {
			return nil
		}
		return bigToTwos(v.Interface().(*big.Int))
	case "bits":
		return bitsJSON(v.Interface().(asn1.BitString))
	case "octets":
		return hex.EncodeToString(v.Bytes())
	case "oid":
		return oidJSON(v.Interface().(asn1.ObjectIdentifier))
	case "string":
		return v.String()
	case "time":
		return timeJSON(v.Interface().(time.Time))
	case "raw":
		r := v.Interface().(asn1.RawValue)
		return map[string]any{"c": r.Class, "t": r.Tag, "x": r.IsCompound, "b": hex.EncodeToString(r.Bytes), "f": hex.EncodeToString(r.FullBytes)}
	case "any":
		switch x := v.Interface().(type) {
		case nil:
			return nil
		case bool:
			return map[string]any{"bool": x}
		case int64:
			return map[string]any{"int": x}
		case asn1.BitString:
			return map[string]any{"bits": bitsJSON(x)}
		case asn1.ObjectIdentifier:
			return map[string]any{"oid": oidJSON(x)}
		case time.Time:
			return map[string]any{"time": timeJSON(x)}
		case string:
			return map[string]any{"string": x}
		case []byte:
			return map[string]any{"octets": hex.EncodeToString(x)}
		}
		panic(fmt.Sprintf("unexpected any %T", v.Interface()))
	case "seq":
		out := make([]any, len(s.F))
		for i, f := range s.F {
			out[i] = toJSON(v.Field(i), f)
		}
		return out
	case "seqof":
		out := make([]any, v.Len())
		for i := range out {
			out[i] = toJSON(v.Index(i), s.E)
		}
		return out
	}
	panic("cannot encode " + s.K)
}

func handle(req request) (result map[string]any) {
	defer func() {
		// encoding/asn1 reports errors by value; a panic here is an oracle bug.
		if r := recover(); r != nil {
			panic(fmt.Sprintf("%v for %+v", r, req))
		}
	}()
	t := goType(req.S)
	switch req.Op {
	case "marshal":
		v := reflect.New(t).Elem()
		fill(v, req.S, req.V)
		der, err := asn1.MarshalWithParams(v.Interface(), req.S.P)
		if err != nil {
			return map[string]any{"ok": false}
		}
		return map[string]any{"ok": true, "der": hex.EncodeToString(der)}
	case "unmarshal":
		der, err := hex.DecodeString(req.D)
		if err != nil {
			panic(err)
		}
		ptr := reflect.New(t)
		rest, err := asn1.UnmarshalWithParams(der, ptr.Interface(), req.S.P)
		if err != nil {
			return map[string]any{"ok": false}
		}
		deviation = ""
		value := toJSON(ptr.Elem(), req.S)
		out := map[string]any{"ok": true, "v": value, "rest": hex.EncodeToString(rest)}
		if deviation != "" {
			out["dev"] = deviation
		}
		return out
	}
	panic("unknown op " + req.Op)
}

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 16*1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		var req request
		if err := json.Unmarshal(s.Bytes(), &req); err != nil {
			panic(err)
		}
		out, err := json.Marshal(handle(req))
		if err != nil {
			panic(err)
		}
		w.Write(out)
		w.WriteByte('\n')
	}
	if err := s.Err(); err != nil {
		panic(err)
	}
}
