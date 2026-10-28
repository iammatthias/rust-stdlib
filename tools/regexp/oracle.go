// Go regexp and regexp/syntax oracle for tools/regexp/check.py.
//
// Line protocol (tab separated, strings and patterns hex encoded):
//
//	S <flags> <pattern>          regexp/syntax: Parse, Simplify, Compile, Prog
//	M <mode> <pattern> <input>   regexp: every Find/Replace/Expand/Split variant
//	A <mode> <pattern> <input>   regexp: the search from every offset
//	E <r1> <r2>                  EmptyOpContext and IsWordChar
//
// Mode is P (Compile), X (CompilePOSIX) or L (Compile then Longest). Output is
// one line per request made of space separated key=value fields in which every
// string is "h:" plus hex, so lines can be compared byte for byte. Slices that
// are nil in Go and empty in Rust both print as "nil".
//
// Go exports no search from an offset, so A requests call the unexported
// (*Regexp).find(r, b, s, pos, ncap, dstCap) through go:linkname (checked on
// go1.27.1, no build flags needed). That is the search FindAll runs from each
// position, with the text before pos as context. Go has no anchored search;
// the match anchored at pos is find's match when it begins at pos, since a
// leftmost search returns a match beginning at pos whenever one exists.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"unicode/utf8"
	_ "unsafe"
)

//go:linkname find regexp.(*Regexp).find
func find(re *regexp.Regexp, r io.RuneReader, b []byte, s string, pos int, ncap int, dstCap []int) []int

func hx(s string) string { return "h:" + hex.EncodeToString([]byte(s)) }

func ints(a []int) string {
	if len(a) == 0 {
		return "nil"
	}
	parts := make([]string, len(a))
	for i, v := range a {
		parts[i] = strconv.Itoa(v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func intss(a [][]int) string {
	if len(a) == 0 {
		return "nil"
	}
	parts := make([]string, len(a))
	for i, v := range a {
		parts[i] = ints(v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func strs(a []string) string {
	if len(a) == 0 {
		return "nil"
	}
	parts := make([]string, len(a))
	for i, v := range a {
		parts[i] = hx(v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func strss(a [][]string) string {
	if len(a) == 0 {
		return "nil"
	}
	parts := make([]string, len(a))
	for i, v := range a {
		parts[i] = strs(v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func bytess(a [][]byte) string {
	s := make([]string, len(a))
	for i, v := range a {
		s[i] = string(v)
	}
	return strs(s)
}

func bytesss(a [][][]byte) string {
	if len(a) == 0 {
		return "nil"
	}
	parts := make([]string, len(a))
	for i, v := range a {
		parts[i] = bytess(v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func dump(b *strings.Builder, re *syntax.Regexp) {
	fmt.Fprintf(b, "(%s f=%d", re.Op, re.Flags)
	switch re.Op {
	case syntax.OpLiteral, syntax.OpCharClass:
		fmt.Fprintf(b, " r=%x", re.Rune)
	case syntax.OpRepeat:
		fmt.Fprintf(b, " %d,%d", re.Min, re.Max)
	case syntax.OpCapture:
		fmt.Fprintf(b, " %d,%s", re.Cap, re.Name)
	}
	for _, s := range re.Sub {
		b.WriteByte(' ')
		dump(b, s)
	}
	b.WriteByte(')')
}

func syntaxCase(out *strings.Builder, flags syntax.Flags, pattern string) {
	re, err := syntax.Parse(pattern, flags)
	if err != nil {
		e := err.(*syntax.Error)
		fmt.Fprintf(out, "ERR code=%s msg=%s", hx(string(e.Code)), hx(e.Error()))
		return
	}
	var d strings.Builder
	dump(&d, re)
	fmt.Fprintf(out, "OK str=%s dump=%s maxcap=%d names=%s", hx(re.String()), hx(d.String()), re.MaxCap(), strs(re.CapNames()))
	again, err := syntax.Parse(re.String(), flags)
	fmt.Fprintf(out, " reparse=%v", err == nil && again.Equal(re))
	simp := re.Simplify()
	d.Reset()
	dump(&d, simp)
	fmt.Fprintf(out, " simp=%s simpdump=%s", hx(simp.String()), hx(d.String()))
	prog, err := syntax.Compile(simp)
	if err != nil {
		fmt.Fprintf(out, " cerr=%s", hx(err.Error()))
		return
	}
	prefix, complete := prog.Prefix()
	fmt.Fprintf(out, " prog=%s numcap=%d start=%d prefix=%s,%v cond=%d", hx(prog.String()), prog.NumCap, prog.Start, hx(prefix), complete, prog.StartCond())
	var mr []string
	for _, inst := range prog.Inst {
		switch inst.Op {
		case syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			var r []string
			for _, c := range []rune{'a', 'A', 'b', 'k', 'K', '0', ' ', '\n', 0, 0x3b1, 0x391, 0x212a, 0x17f, 0x10000, 0x10ffff, -1} {
				r = append(r, strconv.Itoa(inst.MatchRunePos(c)))
				if inst.MatchRune(c) != (inst.MatchRunePos(c) != -1) {
					panic("MatchRune")
				}
			}
			mr = append(mr, strings.Join(r, ":"))
		case syntax.InstEmptyWidth:
			var r []string
			for _, p := range [][2]rune{{-1, -1}, {-1, 'a'}, {'a', -1}, {'a', 'a'}, {'a', ' '}, {' ', 'a'}, {'\n', 'a'}, {'a', '\n'}, {' ', ' '}} {
				r = append(r, strconv.FormatBool(inst.MatchEmptyWidth(p[0], p[1])))
			}
			mr = append(mr, strings.Join(r, ":"))
		}
	}
	fmt.Fprintf(out, " mr=%s", strings.Join(mr, ";"))
}

var templates = []string{"", "x", "$0", "<$1>", "${1}x", "$1x", "$name", "${name}", "$$", "$", "${", "${1", "$2$1", "$a_b1", "$10", "[$0|$1|$2|$x]", "$n1$é", "$01", "$ 1"}

func compile(out *strings.Builder, mode string, pattern string) *regexp.Regexp {
	var re *regexp.Regexp
	var err error
	if mode == "X" {
		re, err = regexp.CompilePOSIX(pattern)
	} else {
		re, err = regexp.Compile(pattern)
		if err == nil && mode == "L" {
			re.Longest()
		}
	}
	if err != nil {
		fmt.Fprintf(out, "ERR msg=%s", hx(err.Error()))
		return nil
	}
	return re
}

func pair(m []int) string {
	if m == nil {
		return "nil"
	}
	return fmt.Sprintf("[%d,%d]", m[0], m[1])
}

func anchoredAt(m []int, pos int) []int {
	if m != nil && m[0] == pos {
		return m
	}
	return nil
}

func offsetCase(out *strings.Builder, mode string, pattern, input string) {
	re := compile(out, mode, pattern)
	if re == nil {
		return
	}
	b := []byte(input)
	ncap := 2 * (re.NumSubexp() + 1)
	// The linkname reaches an unexported method; if a later Go changes its
	// meaning, the search from 0 stops agreeing with the exported API.
	if got, want := find(re, nil, b, "", 0, 2, nil), re.FindIndex(b); fmt.Sprint(got) != fmt.Sprint(want) {
		panic(fmt.Sprintf("regexp.find(pos 0) = %v, FindIndex = %v: the linkname no longer matches this Go", got, want))
	}
	out.WriteString("OK")
	for pos := 0; pos <= len(b); pos++ {
		m := find(re, nil, b, "", pos, 2, nil)
		sm := find(re, nil, b, "", pos, ncap, nil)
		fmt.Fprintf(out, " %d:%s:%s:%s:%s", pos, pair(m), ints(sm), pair(anchoredAt(m, pos)), ints(anchoredAt(sm, pos)))
	}
}

func matchCase(out *strings.Builder, mode string, pattern, input string) {
	re := compile(out, mode, pattern)
	if re == nil {
		return
	}
	valid := utf8.ValidString(input)
	b := []byte(input)
	prefix, complete := re.LiteralPrefix()
	fmt.Fprintf(out, "OK expr=%s nsub=%d names=%s lp=%s,%v valid=%v", hx(re.String()), re.NumSubexp(), strs(re.SubexpNames()), hx(prefix), complete, valid)
	var idx []string
	for _, n := range append(re.SubexpNames(), "zzz", "") {
		idx = append(idx, strconv.Itoa(re.SubexpIndex(n)))
	}
	fmt.Fprintf(out, " sidx=%s", strings.Join(idx, ","))
	fmt.Fprintf(out, " match=%v matchb=%v", re.MatchString(input), re.Match(b))
	fmt.Fprintf(out, " mrd=%v", re.MatchReader(strings.NewReader(input)))
	fmt.Fprintf(out, " frdi=%s frdsi=%s", ints(re.FindReaderIndex(strings.NewReader(input))), ints(re.FindReaderSubmatchIndex(strings.NewReader(input))))
	fmt.Fprintf(out, " fi=%s fsi=%s", ints(re.FindIndex(b)), ints(re.FindSubmatchIndex(b)))
	fmt.Fprintf(out, " fb=%s fsb=%s", hx(string(re.Find(b))), bytess(re.FindSubmatch(b)))
	for _, n := range []int{-1, 0, 1, 2, 3} {
		fmt.Fprintf(out, " faib%d=%s fasib%d=%s fab%d=%s fasb%d=%s", n, intss(re.FindAllIndex(b, n)), n, intss(re.FindAllSubmatchIndex(b, n)), n, bytess(re.FindAll(b, n)), n, bytesss(re.FindAllSubmatch(b, n)))
	}
	for _, t := range templates {
		fmt.Fprintf(out, " rb=%s", hx(string(re.ReplaceAll(b, []byte(t)))))
	}
	fmt.Fprintf(out, " rlb=%s", hx(string(re.ReplaceAllLiteral(b, []byte("$1")))))
	fmt.Fprintf(out, " rfb=%s", hx(string(re.ReplaceAllFunc(b, func(m []byte) []byte { return append(append([]byte("<"), m...), '>') }))))
	if m := re.FindSubmatchIndex(b); m != nil {
		for _, t := range templates {
			fmt.Fprintf(out, " eb=%s", hx(string(re.Expand([]byte("pre:"), []byte(t), b, m))))
		}
	}
	if !valid {
		fmt.Fprintf(out, " strings=skipped")
		return
	}
	fmt.Fprintf(out, " fsi_=%s fss=%s fs=%s", ints(re.FindStringIndex(input)), strs(re.FindStringSubmatch(input)), hx(re.FindString(input)))
	fmt.Fprintf(out, " fssi=%s", ints(re.FindStringSubmatchIndex(input)))
	for _, n := range []int{-1, 0, 1, 2, 3} {
		fmt.Fprintf(out, " fasi%d=%s fassi%d=%s fas%d=%s fass%d=%s", n, intss(re.FindAllStringIndex(input, n)), n, intss(re.FindAllStringSubmatchIndex(input, n)), n, strs(re.FindAllString(input, n)), n, strss(re.FindAllStringSubmatch(input, n)))
	}
	for _, t := range templates {
		fmt.Fprintf(out, " rs=%s", hx(re.ReplaceAllString(input, t)))
	}
	fmt.Fprintf(out, " rls=%s", hx(re.ReplaceAllLiteralString(input, "$1")))
	fmt.Fprintf(out, " rfs=%s", hx(re.ReplaceAllStringFunc(input, func(m string) string { return "<" + m + ">" })))
	for _, n := range []int{-1, 0, 1, 2, 3, 5} {
		fmt.Fprintf(out, " split%d=%s", n, strs(re.Split(input, n)))
	}
	if m := re.FindStringSubmatchIndex(input); m != nil {
		for _, t := range templates {
			fmt.Fprintf(out, " es=%s", hx(string(re.ExpandString([]byte("pre:"), t, input, m))))
		}
	}
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	unhex := func(s string) string {
		b, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		return string(b)
	}
	for in.Scan() {
		f := strings.Split(in.Text(), "\t")
		var out strings.Builder
		switch f[0] {
		case "S":
			flags, _ := strconv.Atoi(f[1])
			syntaxCase(&out, syntax.Flags(flags), unhex(f[2]))
		case "M":
			matchCase(&out, f[1], unhex(f[2]), unhex(f[3]))
		case "A":
			offsetCase(&out, f[1], unhex(f[2]), unhex(f[3]))
		case "E":
			r1, _ := strconv.Atoi(f[1])
			r2, _ := strconv.Atoi(f[2])
			fmt.Fprintf(&out, "%d %v %v", syntax.EmptyOpContext(rune(r1), rune(r2)), syntax.IsWordChar(rune(r1)), syntax.IsWordChar(rune(r2)))
		default:
			panic("bad request " + f[0])
		}
		fmt.Fprintln(w, out.String())
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
