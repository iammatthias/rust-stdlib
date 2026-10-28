// Line-protocol oracle for tools/flag_check.py. Each request line is a list of
// hex tokens ("_" is the empty string):
//
//	setName usageMode nflags {kind name default usage}... nargs args... nsets {name value}...
//
// The reply is one line of hex tokens: panic marker or parse outcome, the
// final flag values, the flags set, remaining arguments, everything written to
// the set's output, the PrintDefaults text, callback logs and Set outcomes.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

func enc(s string) string {
	if s == "" {
		return "_"
	}
	return hex.EncodeToString([]byte(s))
}

func dec(s string) string {
	if s == "_" {
		return ""
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// listValue joins its values with commas; its zero value prints as "".
type listValue []string

func (l *listValue) String() string     { return strings.Join(*l, ",") }
func (l *listValue) Set(s string) error { *l = append(*l, s); return nil }

// countValue is a boolean flag that counts its uses; its zero value prints "0".
type countValue int

func (c *countValue) String() string   { return strconv.Itoa(int(*c)) }
func (c *countValue) Set(string) error { *c++; return nil }
func (c *countValue) IsBoolFlag() bool { return true }

// upperText upper-cases its input; "bad" is rejected.
type upperText struct{ s string }

func (u *upperText) MarshalText() ([]byte, error) { return []byte(u.s), nil }
func (u *upperText) UnmarshalText(b []byte) error {
	if string(b) == "bad" {
		return errors.New("bad text")
	}
	u.s = strings.ToUpper(string(b))
	return nil
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		if line = strings.TrimSpace(line); line != "" {
			fmt.Fprintln(out, strings.Join(run(strings.Fields(line)), " "))
		}
		if err != nil {
			return
		}
	}
}

func run(tok []string) (reply []string) {
	pos := 0
	next := func() string { s := dec(tok[pos]); pos++; return s }
	atoi := func() int { n, _ := strconv.Atoi(next()); return n }

	setName := next()
	usageMode := atoi()
	nflags := atoi()
	type def struct{ kind, name, def, usage string }
	defs := make([]def, nflags)
	for i := range defs {
		defs[i] = def{next(), next(), next(), next()}
	}
	args := make([]string, atoi())
	for i := range args {
		args[i] = next()
	}
	type setReq struct{ name, value string }
	sets := make([]setReq, atoi())
	for i := range sets {
		sets[i] = setReq{next(), next()}
	}

	var buf bytes.Buffer
	fs := flag.NewFlagSet(setName, flag.ContinueOnError)
	fs.SetOutput(&buf)
	if usageMode == 1 {
		fs.Usage = func() { fmt.Fprintln(fs.Output(), "CUSTOM USAGE") }
	}
	var log []string

	defer func() {
		if r := recover(); r != nil {
			reply = []string{"PANIC", enc(fmt.Sprint(r)), enc(buf.String())}
		}
	}()

	for _, d := range defs {
		switch d.kind {
		case "bool":
			v, _ := strconv.ParseBool(d.def)
			fs.Bool(d.name, v, d.usage)
		case "int":
			v, _ := strconv.Atoi(d.def)
			fs.Int(d.name, v, d.usage)
		case "int64":
			v, _ := strconv.ParseInt(d.def, 10, 64)
			fs.Int64(d.name, v, d.usage)
		case "uint":
			v, _ := strconv.ParseUint(d.def, 10, 64)
			fs.Uint(d.name, uint(v), d.usage)
		case "uint64":
			v, _ := strconv.ParseUint(d.def, 10, 64)
			fs.Uint64(d.name, v, d.usage)
		case "string":
			fs.String(d.name, d.def, d.usage)
		case "float64":
			v, _ := strconv.ParseFloat(d.def, 64)
			fs.Float64(d.name, v, d.usage)
		case "duration":
			v, _ := time.ParseDuration(d.def)
			fs.Duration(d.name, v, d.usage)
		case "list":
			l := listValue(nil)
			if d.def != "" {
				l = listValue(strings.Split(d.def, ","))
			}
			fs.Var(&l, d.name, d.usage)
		case "count":
			n, _ := strconv.Atoi(d.def)
			c := countValue(n)
			fs.Var(&c, d.name, d.usage)
		case "text":
			t := &upperText{}
			fs.TextVar(t, d.name, &upperText{d.def}, d.usage)
		case "func":
			name := d.name
			fs.Func(name, d.usage, func(s string) error {
				log = append(log, name+"="+s)
				if s == "bad" {
					return errors.New("bad func value")
				}
				return nil
			})
		case "boolfunc":
			name := d.name
			fs.BoolFunc(name, d.usage, func(s string) error {
				log = append(log, name+"="+s)
				if s == "bad" {
					return errors.New("bad func value")
				}
				return nil
			})
		}
	}

	parseErr := fs.Parse(args)
	reply = []string{"OK"}
	if parseErr != nil {
		reply = []string{"ERR", enc(parseErr.Error()), flagBool(parseErr == flag.ErrHelp)}
	}
	reply = append(reply, flagBool(fs.Parsed()), fmt.Sprint(fs.NFlag()), fmt.Sprint(fs.NArg()))
	for _, a := range fs.Args() {
		reply = append(reply, enc(a))
	}
	reply = append(reply, enc(fs.Arg(0)), enc(fs.Arg(1)), enc(fs.Name()))

	var all []string
	fs.VisitAll(func(f *flag.Flag) {
		all = append(all, enc(f.Name), enc(f.Value.String()), enc(f.DefValue), enc(f.Usage))
	})
	reply = append(reply, "ALL", fmt.Sprint(len(all)/4))
	reply = append(reply, all...)
	var visited []string
	fs.Visit(func(f *flag.Flag) { visited = append(visited, enc(f.Name)) })
	reply = append(reply, "SET", fmt.Sprint(len(visited)))
	reply = append(reply, visited...)

	reply = append(reply, "OUT", enc(buf.String()))
	buf.Reset()
	fs.PrintDefaults()
	reply = append(reply, "DEFAULTS", enc(buf.String()))
	reply = append(reply, "LOG", enc(strings.Join(log, "|")))

	reply = append(reply, "SETS")
	for _, r := range sets {
		msg := ""
		if err := fs.Set(r.name, r.value); err != nil {
			msg = err.Error()
		}
		reply = append(reply, enc(msg))
	}
	var after []string
	fs.Visit(func(f *flag.Flag) { after = append(after, enc(f.Name), enc(f.Value.String())) })
	reply = append(reply, fmt.Sprint(len(after)/2))
	reply = append(reply, after...)
	for _, d := range defs {
		if f := fs.Lookup(d.name); f != nil {
			if g, ok := f.Value.(flag.Getter); ok {
				reply = append(reply, enc(fmt.Sprintf("%T", g.Get())))
			} else {
				reply = append(reply, "_")
			}
		}
	}
	return reply
}

func flagBool(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
