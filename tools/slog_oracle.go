// Go reference implementation for tools/log_check.py (log/slog half).
//
// Each stdin line is a JSON scenario: handler kind and options, a chain of
// WithAttrs/WithGroup calls and a list of records. The output line is the hex
// of everything the handler wrote, with "E0"/"E1" markers for Enabled.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// pcHere returns a real program counter for a Record.
func pcHere() uintptr {
	var pcs [1]uintptr
	runtime.Callers(1, pcs[:])
	return pcs[0]
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func i64(v any) int64 {
	s, ok := v.(string)
	if !ok {
		fail("expected decimal string, got %v", v)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		fail("bad int %q", s)
	}
	return n
}

func timeOf(v any) time.Time {
	m := v.(map[string]any)
	s := int64(m["s"].(float64))
	n := int64(m["n"].(float64))
	off := int(m["off"].(float64))
	return time.Unix(s, n).In(time.FixedZone("", off))
}

type lv struct{ inner slog.Value }

func (l lv) LogValue() slog.Value { return l.inner }

type errT struct{ msg string }

func (e errT) Error() string { return e.msg }

func toValue(spec map[string]any) slog.Value {
	v := spec["v"]
	switch str(spec, "t") {
	case "str":
		return slog.StringValue(v.(string))
	case "int":
		return slog.Int64Value(i64(v))
	case "uint":
		u, err := strconv.ParseUint(v.(string), 10, 64)
		if err != nil {
			fail("bad uint")
		}
		return slog.Uint64Value(u)
	case "f64":
		b, err := strconv.ParseUint(v.(string), 16, 64)
		if err != nil {
			fail("bad float bits")
		}
		return slog.Float64Value(math.Float64frombits(b))
	case "bool":
		return slog.BoolValue(v.(bool))
	case "dur":
		return slog.DurationValue(time.Duration(i64(v)))
	case "time":
		return slog.TimeValue(timeOf(v))
	case "group":
		return slog.GroupValue(toAttrs(list(v))...)
	case "nil":
		return slog.AnyValue(nil)
	case "any":
		return slog.AnyValue(v)
	case "err":
		return slog.AnyValue(errT{v.(string)})
	case "bytes":
		b, _ := hex.DecodeString(v.(string))
		return slog.AnyValue(b)
	case "level":
		return slog.AnyValue(slog.Level(i64(v)))
	case "valuer":
		return slog.AnyValue(lv{toValue(v.(map[string]any))})
	}
	fail("unknown value type %v", spec)
	return slog.Value{}
}

func toAttr(spec any) slog.Attr {
	m := spec.(map[string]any)
	return slog.Attr{Key: str(m, "k"), Value: toValue(m)}
}

func toAttrs(l []any) []slog.Attr {
	out := make([]slog.Attr, 0, len(l))
	for _, a := range l {
		out = append(out, toAttr(a))
	}
	return out
}

func upperASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func applyMode(mode string, groups []string, a slog.Attr) slog.Attr {
	switch mode {
	case "drop_time":
		if len(groups) == 0 && a.Key == "time" {
			return slog.Attr{}
		}
	case "rename":
		if len(groups) == 0 {
			switch a.Key {
			case "time":
				a.Key = "ts"
			case "msg":
				a.Key = "message"
			case "level":
				a.Key = "lvl"
			case "source":
				a.Key = "src"
			}
		}
	case "drop_key":
		if a.Key == "drop" {
			return slog.Attr{}
		}
	case "upper":
		if a.Value.Kind() == slog.KindString {
			a.Value = slog.StringValue(upperASCII(a.Value.String()))
		}
	case "level_num":
		if len(groups) == 0 && a.Key == "level" {
			if l, ok := a.Value.Any().(slog.Level); ok {
				a.Value = slog.Int64Value(int64(l))
			}
		}
	case "group_aware":
		if len(groups) > 0 {
			a.Key = strings.Join(groups, "/") + "/" + a.Key
		}
	case "to_group":
		switch {
		case a.Key == "g" && a.Value.Kind() == slog.KindInt64:
			n := a.Value.Int64()
			return slog.Group("g", slog.Int64("a", n), slog.Int64("b", n+1))
		case a.Key == "emptyg":
			return slog.Attr{Key: "emptyg", Value: slog.GroupValue()}
		case a.Key == "inl":
			return slog.Group("", slog.Int("p", 1), slog.String("q", "x"))
		}
	case "zero_all":
		return slog.Attr{}
	case "fixsrc":
		if a.Key == "source" {
			if s, ok := a.Value.Any().(*slog.Source); ok && (s.File != "" || s.Line != 0 || s.Function != "") {
				return slog.Any("source", &slog.Source{Function: "pkg.fn", File: "x/y.go", Line: 7})
			}
		}
	case "time_unix":
		if a.Value.Kind() == slog.KindTime {
			return slog.Int64(a.Key, a.Value.Time().Unix())
		}
	case "lv_ret":
		if a.Key == "lv" {
			return slog.Attr{Key: "lv2", Value: slog.AnyValue(lv{slog.StringValue("late")})}
		}
	case "empty_str_drop":
		if a.Value.Kind() == slog.KindString && a.Value.String() == "" {
			return slog.Attr{}
		}
	default:
		fail("unknown rep mode %q", mode)
	}
	return a
}

func options(spec map[string]any) *slog.HandlerOptions {
	opts := &slog.HandlerOptions{}
	if b, _ := spec["add_source"].(bool); b {
		opts.AddSource = true
	}
	if l, ok := spec["level"].(string); ok {
		opts.Level = slog.Level(i64(l))
	}
	modes := list(spec["rep"])
	if len(modes) > 0 {
		opts.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
			for _, m := range modes {
				a = applyMode(m.(string), groups, a)
				if a.Equal(slog.Attr{}) {
					return a
				}
			}
			return a
		}
	}
	return opts
}

func newHandler(kind string, spec map[string]any, w *bytes.Buffer) slog.Handler {
	switch kind {
	case "text":
		return slog.NewTextHandler(w, options(spec))
	case "json":
		return slog.NewJSONHandler(w, options(spec))
	case "multi":
		subs := list(spec["subs"])
		hs := make([]slog.Handler, 0, len(subs))
		for _, s := range subs {
			m := s.(map[string]any)
			hs = append(hs, newHandler(str(m, "h"), m, w))
		}
		return slog.NewMultiHandler(hs...)
	case "discard":
		return slog.DiscardHandler
	}
	fail("unknown handler %q", kind)
	return nil
}

func toArgs(l []any) []any {
	var args []any
	for _, a := range l {
		m := a.(map[string]any)
		switch {
		case m["attr"] != nil:
			args = append(args, toAttr(m["attr"]))
		case m["bad"] != nil:
			args = append(args, toValue(m["bad"].(map[string]any)))
		case m["val"] != nil:
			args = append(args, str(m, "key"), toValue(m["val"].(map[string]any)))
		default:
			args = append(args, str(m, "key"))
		}
	}
	return args
}

func run(spec map[string]any) string {
	var buf bytes.Buffer
	ctx := context.Background()
	h := newHandler(str(spec, "h"), spec, &buf)
	var logger *slog.Logger
	viaLogger := spec["via"] != nil
	if viaLogger {
		logger = slog.New(h)
	}
	for _, op := range list(spec["ops"]) {
		o := op.(map[string]any)
		if viaLogger {
			if g, ok := o["group"].(string); ok {
				logger = logger.WithGroup(g)
			} else {
				logger = logger.With(toArgs(list(o["args"]))...)
			}
			continue
		}
		if g, ok := o["group"].(string); ok {
			h = h.WithGroup(g)
		} else {
			h = h.WithAttrs(toAttrs(list(o["attrs"])))
		}
	}
	var out strings.Builder
	for _, r := range list(spec["recs"]) {
		rm := r.(map[string]any)
		level := slog.Level(i64(rm["lvl"]))
		if viaLogger {
			if logger.Enabled(ctx, level) {
				out.WriteString("E1")
			} else {
				out.WriteString("E0")
			}
			args := toArgs(list(rm["args"]))
			switch str(rm, "api") {
			case "attrs":
				var as []slog.Attr
				for _, a := range args {
					if at, ok := a.(slog.Attr); ok {
						as = append(as, at)
					}
				}
				logger.LogAttrs(ctx, level, rm["msg"].(string), as...)
			case "debug":
				logger.Debug(rm["msg"].(string), args...)
			case "info":
				logger.Info(rm["msg"].(string), args...)
			case "warn":
				logger.Warn(rm["msg"].(string), args...)
			case "error":
				logger.Error(rm["msg"].(string), args...)
			default:
				logger.Log(ctx, level, rm["msg"].(string), args...)
			}
			continue
		}
		var t time.Time
		if rm["t"] != nil {
			t = timeOf(rm["t"])
		}
		var pc uintptr
		if b, _ := rm["pc"].(bool); b {
			pc = pcHere()
		}
		rec := slog.NewRecord(t, level, rm["msg"].(string), pc)
		if rm["attrs"] != nil {
			rec.AddAttrs(toAttrs(list(rm["attrs"]))...)
		}
		if h.Enabled(ctx, level) {
			out.WriteString("E1")
			if err := h.Handle(ctx, rec); err != nil {
				fail("handle: %v", err)
			}
		} else {
			out.WriteString("E0")
		}
	}
	return hex.EncodeToString([]byte(out.String())) + ":" + hex.EncodeToString(buf.Bytes())
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<26)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		var spec map[string]any
		if err := json.Unmarshal(in.Bytes(), &spec); err != nil {
			fail("bad scenario: %v", err)
		}
		fmt.Fprintln(out, run(spec))
	}
	if err := in.Err(); err != nil {
		fail("%v", err)
	}
}
