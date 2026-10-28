// Line-oriented Go oracle for unicode, unicode/utf8 and unicode/utf16.
// Requests (one per line):
//
//	sweep          every code point plus negative/out-of-range values, run-length packed
//	tables         structural dump of every exported table, map and case table
//	U8 <hex>       utf8 decoding walks, counts and validity of the bytes
//	U16 <hex>      utf16.Decode / Encode of 4-hex-digit units
//	R32 <hex>      utf16.Encode of 8-hex-digit runes
//
// examples/unicode_probe.rs implements the same protocol over the Rust crate.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

type fnv uint64

func newFnv() fnv { return 14695981039346656037 }

func (h *fnv) byte(b byte) { *h = (*h ^ fnv(b)) * 1099511628211 }
func (h *fnv) u32(v uint32) {
	for i := 0; i < 4; i++ {
		h.byte(byte(v >> (8 * i)))
	}
}

// domain mirrors the Rust probe: out-of-range values, then 0..0x110000+.
func domain() []rune {
	d := []rune{-2147483648, -2147483647, -0x7FFFFFFF, -0x110000, -0x10FFFF, -0xD800}
	for r := rune(-300); r < 0; r++ {
		d = append(d, r)
	}
	for r := rune(0); r < 0x110020; r++ {
		d = append(d, r)
	}
	return append(d, 0x1FFFFF, 0x200000, 0xFFFFFFF, 0x7FFFFFFE, 0x7FFFFFFF)
}

func b2i(b bool) uint {
	if b {
		return 1
	}
	return 0
}

func sweep(out *bufio.Writer) {
	letterDigit := []*unicode.RangeTable{unicode.Letter, unicode.Digit}
	mixed := []*unicode.RangeTable{unicode.Lu, unicode.Nd}
	hEnc, hP16, hDec := newFnv(), newFnv(), newFnv()
	var prev string
	var prevR rune
	first := true
	for _, r := range domain() {
		var mask uint
		for i, v := range []bool{
			unicode.IsUpper(r), unicode.IsLower(r), unicode.IsTitle(r), unicode.IsLetter(r),
			unicode.IsDigit(r), unicode.IsNumber(r), unicode.IsMark(r), unicode.IsPunct(r),
			unicode.IsSymbol(r), unicode.IsSpace(r), unicode.IsControl(r), unicode.IsGraphic(r),
			unicode.IsPrint(r), unicode.In(r, unicode.Letter, unicode.Digit), unicode.IsOneOf(mixed, r),
			unicode.Is(unicode.Han, r), unicode.Is(unicode.Latin, r), unicode.Is(unicode.White_Space, r),
			unicode.Is(unicode.Hex_Digit, r), unicode.In(r, letterDigit...),
			utf8.ValidRune(r), utf16.IsSurrogate(r),
		} {
			mask |= b2i(v) << i
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "%x", mask)
		d := func(v rune) { fmt.Fprintf(&sb, " %d", v-r) }
		d(unicode.ToUpper(r))
		d(unicode.ToLower(r))
		d(unicode.ToTitle(r))
		d(unicode.SimpleFold(r))
		for c := -1; c <= 3; c++ {
			if c < 0 || c >= unicode.MaxCase {
				fmt.Fprintf(&sb, " %d", unicode.To(c, r)) // constant ReplacementChar
			} else {
				d(unicode.To(c, r))
			}
		}
		for _, sc := range []unicode.SpecialCase{unicode.TurkishCase, unicode.AzeriCase} {
			d(sc.ToUpper(r))
			d(sc.ToLower(r))
			d(sc.ToTitle(r))
		}
		fmt.Fprintf(&sb, " %d %d", utf8.RuneLen(r), utf16.RuneLen(r))
		rec := sb.String()
		if first || rec != prev || r != prevR+1 {
			fmt.Fprintf(out, "%d %s\n", r, rec)
		}
		first, prev, prevR = false, rec, r

		var buf [4]byte
		n := utf8.EncodeRune(buf[:], r)
		hEnc.u32(uint32(n))
		for _, b := range buf[:n] {
			hEnc.byte(b)
		}
		app := utf8.AppendRune(nil, r)
		hEnc.u32(uint32(len(app)))
		for _, b := range app {
			hEnc.byte(b)
		}
		r1, r2 := utf16.EncodeRune(r)
		hP16.u32(uint32(r1))
		hP16.u32(uint32(r2))
		for _, u := range utf16.AppendRune(nil, r) {
			hP16.u32(uint32(u))
		}
	}
	// Surrogate pairs (and near misses) for utf16.DecodeRune.
	for r1 := rune(0xD7FE); r1 < 0xE002; r1++ {
		for r2 := rune(0xDBFE); r2 < 0xE002; r2++ {
			hDec.u32(uint32(utf16.DecodeRune(r1, r2)))
		}
	}
	for _, r1 := range domain()[:400] {
		for _, r2 := range []rune{r1, 0xDC00, 0xDFFF, -1, 0x10000} {
			hDec.u32(uint32(utf16.DecodeRune(r1, r2)))
			hDec.u32(uint32(utf16.DecodeRune(r2, r1)))
		}
	}
	fmt.Fprintf(out, "H utf8-encode %x\nH utf16-encode %x\nH utf16-decode %x\n", uint64(hEnc), uint64(hP16), uint64(hDec))
}

func tableHash(t *unicode.RangeTable) string {
	h := newFnv()
	h.u32(uint32(t.LatinOffset))
	for _, r := range t.R16 {
		h.u32(uint32(r.Lo))
		h.u32(uint32(r.Hi))
		h.u32(uint32(r.Stride))
	}
	h.u32(0xFFFFFFFF)
	for _, r := range t.R32 {
		h.u32(r.Lo)
		h.u32(r.Hi)
		h.u32(r.Stride)
	}
	return fmt.Sprintf("%d %d %x", len(t.R16), len(t.R32), uint64(h))
}

// sample hashes Is() at every range boundary and stride neighbour.
func sample(t *unicode.RangeTable) string {
	h := newFnv()
	n, ones := 0, 0
	probe := func(r rune) {
		n++
		v := unicode.Is(t, r)
		if v {
			ones++
		}
		h.byte(byte(b2i(v)))
	}
	for _, r := range t.R16 {
		lo, hi, st := rune(r.Lo), rune(r.Hi), rune(r.Stride)
		for _, p := range []rune{lo - 1, lo, lo + 1, lo + st, hi - 1, hi, hi + 1} {
			probe(p)
		}
	}
	for _, r := range t.R32 {
		lo, hi, st := rune(r.Lo), rune(r.Hi), rune(r.Stride)
		for _, p := range []rune{lo - 1, lo, lo + 1, lo + st, hi - 1, hi, hi + 1} {
			probe(p)
		}
	}
	return fmt.Sprintf("%d %d %x", n, ones, uint64(h))
}

func caseHash(cs []unicode.CaseRange) string {
	h := newFnv()
	for _, c := range cs {
		h.u32(c.Lo)
		h.u32(c.Hi)
		for _, d := range c.Delta {
			h.u32(uint32(d))
		}
	}
	return fmt.Sprintf("%d %x", len(cs), uint64(h))
}

func tables(out *bufio.Writer) {
	fmt.Fprintf(out, "version %s\n", unicode.Version)
	maps := []struct {
		name string
		m    map[string]*unicode.RangeTable
	}{{"Categories", unicode.Categories}, {"Scripts", unicode.Scripts}, {"Properties", unicode.Properties},
		{"FoldCategory", unicode.FoldCategory}, {"FoldScript", unicode.FoldScript}}
	for _, m := range maps {
		keys := make([]string, 0, len(m.m))
		for k := range m.m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(out, "%s %s %s | %s\n", m.name, k, tableHash(m.m[k]), sample(m.m[k]))
		}
	}
	aliases := map[string]*unicode.RangeTable{
		"Digit": unicode.Digit, "Letter": unicode.Letter, "Lower": unicode.Lower, "Mark": unicode.Mark,
		"Number": unicode.Number, "Other": unicode.Other, "Punct": unicode.Punct, "Space": unicode.Space,
		"Symbol": unicode.Symbol, "Title": unicode.Title, "Upper": unicode.Upper,
	}
	names := make([]string, 0)
	for k := range aliases {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fmt.Fprintf(out, "alias %s %s\n", k, tableHash(aliases[k]))
	}
	ak := make([]string, 0)
	for k := range unicode.CategoryAliases {
		ak = append(ak, k)
	}
	sort.Strings(ak)
	for _, k := range ak {
		fmt.Fprintf(out, "CategoryAliases %s %s\n", k, unicode.CategoryAliases[k])
	}
	for i, t := range unicode.GraphicRanges {
		fmt.Fprintf(out, "GraphicRanges %d %s\n", i, tableHash(t))
	}
	for i, t := range unicode.PrintRanges {
		fmt.Fprintf(out, "PrintRanges %d %s\n", i, tableHash(t))
	}
	fmt.Fprintf(out, "CaseRanges %s\nTurkishCase %s\nAzeriCase %s\n",
		caseHash(unicode.CaseRanges), caseHash(unicode.TurkishCase), caseHash(unicode.AzeriCase))
}

func join[T any](xs []T, f func(T) string) string {
	parts := make([]string, len(xs))
	for i, x := range xs {
		parts[i] = f(x)
	}
	return strings.Join(parts, ",")
}

func bits(n int, f func(i int) bool) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteByte('0' + byte(b2i(f(i))))
	}
	return sb.String()
}

func utf8Case(out *bufio.Writer, p []byte) {
	s := string(p)
	walk := func(dec func([]byte) (rune, int), fwd bool) string {
		var parts []string
		for rest := p; len(rest) > 0; {
			r, n := dec(rest)
			parts = append(parts, fmt.Sprintf("%x:%d", r, n))
			if fwd {
				rest = rest[n:]
			} else {
				rest = rest[:len(rest)-n]
			}
		}
		return strings.Join(parts, ",")
	}
	fwdS := func(b []byte) (rune, int) { return utf8.DecodeRuneInString(string(b)) }
	bwdS := func(b []byte) (rune, int) { return utf8.DecodeLastRuneInString(string(b)) }
	fmt.Fprintf(out, "f=%s l=%s fs=%s ls=%s c=%d cs=%d v=%d vs=%d fr=%s frs=%s rs=%s e=%s,%s\n",
		walk(utf8.DecodeRune, true), walk(utf8.DecodeLastRune, false),
		walk(fwdS, true), walk(bwdS, false),
		utf8.RuneCount(p), utf8.RuneCountInString(s), b2i(utf8.Valid(p)), b2i(utf8.ValidString(s)),
		bits(len(p)+1, func(i int) bool { return utf8.FullRune(p[:i]) }),
		bits(len(p)+1, func(i int) bool { return utf8.FullRuneInString(s[:i]) }),
		bits(len(p), func(i int) bool { return utf8.RuneStart(p[i]) }),
		r0(utf8.DecodeRune(nil)), r0(utf8.DecodeLastRune(nil)))
}

func r0(r rune, n int) string { return fmt.Sprintf("%x:%d", r, n) }

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<16), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		line := in.Text()
		kind, arg, _ := strings.Cut(line, " ")
		switch kind {
		case "sweep":
			sweep(out)
		case "tables":
			tables(out)
		case "U8":
			p, err := hex.DecodeString(arg)
			if err != nil {
				panic(err)
			}
			utf8Case(out, p)
		case "U16":
			var units []uint16
			for i := 0; i+4 <= len(arg); i += 4 {
				v, _ := strconv.ParseUint(arg[i:i+4], 16, 16)
				units = append(units, uint16(v))
			}
			runes := utf16.Decode(units)
			fmt.Fprintf(out, "%s | %s\n", join(runes, func(r rune) string { return fmt.Sprintf("%x", uint32(r)) }),
				join(utf16.Encode(runes), func(u uint16) string { return fmt.Sprintf("%x", u) }))
		case "R32":
			var runes []rune
			for i := 0; i+8 <= len(arg); i += 8 {
				v, _ := strconv.ParseUint(arg[i:i+8], 16, 32)
				runes = append(runes, rune(int32(uint32(v))))
			}
			fmt.Fprintln(out, join(utf16.Encode(runes), func(u uint16) string { return fmt.Sprintf("%x", u) }))
		default:
			panic("unknown request " + line)
		}
	}
}
