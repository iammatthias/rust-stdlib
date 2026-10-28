// Go's side of examples/regexp_tokenizer_bench.rs: the same rules, text and
// calls, timed per call. Go has no anchored-at-offset search, so each rule is
// compiled as ^(?:rule) and run with FindIndex on text[pos:], the form a Go
// tokenizer uses. Run with GOTOOLCHAIN=local go run tools/regexp/bench/tokenizer.go.
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const source = "package main\n\nimport \"fmt\"\n\n// Point is a 2D point; see https://example.com/doc?q=1.\ntype Point struct {\n\tX, Y float64\n\tname string\n}\n\n/* block comment\n   spanning lines */\nfunc (p *Point) Scale(k float64) Point {\n\tif k == 0 || p == nil {\n\t\treturn Point{}\n\t}\n\tfor i := 0; i < 10; i++ {\n\t\tk += 0x1F * 3.25e-2\n\t}\n\ts := `raw string`\n\tc := '\\n'\n\tfmt.Println(\"scaled:\\t\", p.X*k, s, c)\n\treturn Point{X: p.X * k, Y: p.Y * k, name: p.name + \"'\"}\n}\n"

var rules = []string{
	`[ \t]+`,
	`\r?\n`,
	`//[^\n]*`,
	`/\*(?s:.)*?\*/`,
	`"(?:[^"\\\n]|\\.)*"`,
	"`[^`]*`",
	`'(?:[^'\\]|\\.)'`,
	`(?:break|case|chan|const|continue|default|defer|else|fallthrough|for|func|go|goto|if|import|interface|map|package|range|return|select|struct|switch|type|var)\b`,
	`(?:true|false|nil|iota)\b`,
	`(?:bool|byte|float64|int|rune|string|error)\b`,
	`https?://[^\s)]+`,
	`0[xX][0-9a-fA-F_]+`,
	`[0-9]+\.[0-9]*(?:[eE][+-]?[0-9]+)?`,
	`[0-9]+`,
	`[A-Za-z_]\w*\(`,
	`\.[A-Za-z_]\w*`,
	`[\pL_][\pL\pN_]*`,
	`:=|==|!=|<=|>=|&&|\|\||\+\+|--|<-|\.\.\.`,
	`[-+*/%<>=!&|^]=?`,
	`[{}()\[\];,.:]`,
}

const runs = 9
const targetNs = 40_000_000

type call struct {
	k, pos int
	hit    bool
}

func text(n int) []byte {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(source)
	}
	return []byte(b.String()[:n])
}

func trace(res []*regexp.Regexp, t []byte) []call {
	var calls []call
	pos := 0
outer:
	for pos < len(t) {
		for k, re := range res {
			m := re.FindIndex(t[pos:])
			hit := m != nil && m[1] > 0
			calls = append(calls, call{k, pos, hit})
			if hit {
				pos += m[1]
				continue outer
			}
		}
		pos++
	}
	return calls
}

func replay(res []*regexp.Regexp, t []byte, calls []call) uint {
	var check uint
	for _, c := range calls {
		if m := res[c.k].FindIndex(t[c.pos:]); m != nil {
			check = check*31 + uint((m[0]+c.pos)^((m[1]+c.pos)<<1))
		} else {
			check++
		}
	}
	return check
}

var sink uint

func bench(filter, name string, calls []call, f func() uint) {
	if !strings.Contains(name, filter) || len(calls) == 0 {
		return
	}
	check := f()
	start := time.Now()
	iters := 0
	for time.Since(start).Nanoseconds() < targetNs/10 || iters == 0 {
		sink += f()
		iters++
	}
	per := max(time.Since(start).Nanoseconds()/int64(iters), 1)
	n := max(targetNs/per, 1)
	res := make([]float64, runs)
	for r := range res {
		t := time.Now()
		for range n {
			sink += f()
		}
		res[r] = float64(time.Since(t).Nanoseconds()) / float64(n*int64(len(calls)))
	}
	sort.Float64s(res)
	fmt.Printf("%-32s %8.1f ns/call (min %.1f max %.1f, %d runs, %d calls) check=%d\n",
		name, res[runs/2], res[0], res[runs-1], runs, len(calls), check)
}

func main() {
	filter := ""
	if len(os.Args) > 1 {
		filter = os.Args[1]
	}
	var res []*regexp.Regexp
	var hasPrefix []bool
	for _, r := range rules {
		res = append(res, regexp.MustCompile("^(?:"+r+")"))
		p, _ := regexp.MustCompile(r).LiteralPrefix()
		hasPrefix = append(hasPrefix, p != "")
	}
	fixed := []*regexp.Regexp{regexp.MustCompile(`^[ -~\t\n]`), regexp.MustCompile(`^[\x00\x01]`)}
	for _, sz := range []struct {
		label string
		n     int
	}{{"2K", 2 << 10}, {"200K", 200 << 10}} {
		t := text(sz.n)
		tr := trace(res, t)
		pick := func(keep func(c call) bool) []call {
			var out []call
			for _, c := range tr {
				if keep(c) {
					out = append(out, c)
				}
			}
			return out
		}
		cases := []struct {
			name  string
			calls []call
		}{
			{"lex", tr},
			{"hit", pick(func(c call) bool { return c.hit })},
			{"miss", pick(func(c call) bool { return !c.hit })},
			{"miss_noprefix", pick(func(c call) bool { return !c.hit && !hasPrefix[c.k] })},
		}
		for _, c := range cases {
			bench(filter, "go/"+c.name+"/"+sz.label, c.calls, func() uint { return replay(res, t, c.calls) })
		}
		every := make([]call, len(t))
		everyMiss := make([]call, len(t))
		for p := range t {
			every[p] = call{0, p, false}
			everyMiss[p] = call{1, p, false}
		}
		bench(filter, "go/fixed_hit/"+sz.label, every, func() uint { return replay(fixed, t, every) })
		bench(filter, "go/fixed_miss/"+sz.label, everyMiss, func() uint { return replay(fixed, t, everyMiss) })
	}
}
