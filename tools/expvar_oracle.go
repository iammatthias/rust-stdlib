// Line-oriented Go expvar oracle used by tools/expvar_check.py. Each request
// line is a script of operations separated by '|':
//
//	<prefix>|<op>|<op>|...
//
// The prefix is prepended to every published name, so scripts do not collide
// in the process-wide registry. Operands are ASCII; string operands are hex.
// Each operation prints one record; a Go panic is "panic". Operations:
//
//	ni:N / nf:N / nm:N / ns:N   NewInt, NewFloat, NewMap, NewString as N
//	si:N / sf:N / sm:N / ss:N   standalone new(Int), Float, Map (Init), String as N
//	fn:N:K                      standalone Func K (0..3) as N
//	pub:N:HEX                   Publish(prefix+HEX, N)
//	get:HEX                     Get(prefix+HEX): "nil" or "some:" + hex(String)
//	add:N:D / addf:N:V          Int.Add(D) / Float.Add(V)
//	set:N:V                     Int.Set / Float.Set / String.Set (hex) by kind
//	mset:N:KEY:M                Map.Set(KEY, M)
//	madd:N:KEY:D / maddf:N:KEY:V   Map.Add / Map.AddFloat
//	mdel:N:KEY / minit:N        Map.Delete / Map.Init
//	mget:N:KEY                  "nil" or "some:" + hex(String) of the value
//	mdo:N                       Map.Do: hex(key)=hex(String) in order
//	str:N                       hex(String) of N
//	val:N                       Value of N: decimal, Go %g, or hex(string)
//
// examples/expvar_probe.rs runs the same scripts.
package main

import (
	"bufio"
	"encoding/hex"
	"expvar"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type obj struct {
	kind byte // 'i' Int, 'f' Float, 'm' Map, 's' String, 'c' Func
	v    expvar.Var
}

var funcs = []func() any{
	func() any { return []string{"a", "b<>& "} },
	func() any { return map[string]int{"z": 1, "a": 2} },
	func() any { return nil },
	func() any { return 3.5 },
}

func decode(text string) string {
	b, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func parseInt(text string) int64 {
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		panic(err)
	}
	return v
}

func parseFloat(text string) float64 {
	v, err := strconv.ParseFloat(text, 64)
	if err != nil {
		panic(err)
	}
	return v
}

func some(v expvar.Var) string {
	if v == nil {
		return "nil"
	}
	return "some:" + hex.EncodeToString([]byte(v.String()))
}

func run(prefix string, env map[string]obj, f []string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "panic"
		}
	}()
	switch f[0] {
	case "ni":
		env[f[1]] = obj{'i', expvar.NewInt(prefix + f[1])}
		return "ok"
	case "nf":
		env[f[1]] = obj{'f', expvar.NewFloat(prefix + f[1])}
		return "ok"
	case "nm":
		env[f[1]] = obj{'m', expvar.NewMap(prefix + f[1])}
		return "ok"
	case "ns":
		env[f[1]] = obj{'s', expvar.NewString(prefix + f[1])}
		return "ok"
	case "si":
		env[f[1]] = obj{'i', new(expvar.Int)}
		return "ok"
	case "sf":
		env[f[1]] = obj{'f', new(expvar.Float)}
		return "ok"
	case "sm":
		env[f[1]] = obj{'m', new(expvar.Map).Init()}
		return "ok"
	case "ss":
		env[f[1]] = obj{'s', new(expvar.String)}
		return "ok"
	case "fn":
		k, _ := strconv.Atoi(f[2])
		env[f[1]] = obj{'c', expvar.Func(funcs[k])}
		return "ok"
	case "pub":
		expvar.Publish(prefix+decode(f[2]), env[f[1]].v)
		return "ok"
	case "get":
		return some(expvar.Get(prefix + decode(f[1])))
	case "add":
		env[f[1]].v.(*expvar.Int).Add(parseInt(f[2]))
		return "ok"
	case "addf":
		env[f[1]].v.(*expvar.Float).Add(parseFloat(f[2]))
		return "ok"
	case "set":
		o := env[f[1]]
		switch o.kind {
		case 'i':
			o.v.(*expvar.Int).Set(parseInt(f[2]))
		case 'f':
			o.v.(*expvar.Float).Set(parseFloat(f[2]))
		case 's':
			o.v.(*expvar.String).Set(decode(f[2]))
		}
		return "ok"
	case "mset":
		env[f[1]].v.(*expvar.Map).Set(decode(f[2]), env[f[3]].v)
		return "ok"
	case "madd":
		env[f[1]].v.(*expvar.Map).Add(decode(f[2]), parseInt(f[3]))
		return "ok"
	case "maddf":
		env[f[1]].v.(*expvar.Map).AddFloat(decode(f[2]), parseFloat(f[3]))
		return "ok"
	case "mdel":
		env[f[1]].v.(*expvar.Map).Delete(decode(f[2]))
		return "ok"
	case "minit":
		env[f[1]].v.(*expvar.Map).Init()
		return "ok"
	case "mget":
		return some(env[f[1]].v.(*expvar.Map).Get(decode(f[2])))
	case "mdo":
		var items []string
		env[f[1]].v.(*expvar.Map).Do(func(kv expvar.KeyValue) {
			items = append(items, hex.EncodeToString([]byte(kv.Key))+"="+hex.EncodeToString([]byte(kv.Value.String())))
		})
		return strings.Join(items, ";")
	case "str":
		return hex.EncodeToString([]byte(env[f[1]].v.String()))
	case "val":
		o := env[f[1]]
		switch o.kind {
		case 'i':
			return strconv.FormatInt(o.v.(*expvar.Int).Value(), 10)
		case 'f':
			return strconv.FormatFloat(o.v.(*expvar.Float).Value(), 'g', -1, 64)
		case 's':
			return hex.EncodeToString([]byte(o.v.(*expvar.String).Value()))
		}
		return "-"
	}
	panic(fmt.Sprintf("bad op %q", f[0]))
}

func process(line string) string {
	parts := strings.Split(line, "|")
	prefix := parts[0]
	env := map[string]obj{}
	var rec []string
	for _, op := range parts[1:] {
		rec = append(rec, run(prefix, env, strings.Split(op, ":")))
	}
	return strings.Join(rec, " ")
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, process(in.Text()))
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
