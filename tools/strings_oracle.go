// Line-oriented Go strings oracle. Each request is "OP\targ\targ..." where
// string arguments are hex and numbers are decimal. Each reply is one line.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

func list(a []string) string {
	p := make([]string, len(a))
	for i, s := range a {
		p[i] = hx(s)
	}
	return "[" + strings.Join(p, ",") + "]"
}

func b2s(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func collect(seq func(func(string) bool)) []string {
	out := []string{}
	for s := range seq {
		out = append(out, s)
	}
	return out
}

// pred must match examples/strings_probe.rs: non-ASCII runes (including
// RuneError) and 'a' satisfy it.
func pred(r rune) bool { return r == 'a' || r >= 0x80 }

// mapping must match the probe: drop 'a', 'b' becomes U+00E9, everything else
// stays; U+0394 maps to U+FFFD.
func mapping(r rune) rune {
	switch r {
	case 'a':
		return -1
	case 'b':
		return 0xE9
	case 0x394:
		return utf8.RuneError
	}
	return r
}

func cut3(b, a string, f bool) string {
	return b2s(f) + "," + hx(b) + "," + hx(a)
}

func readerScript(input, script string) string {
	r := strings.NewReader(input)
	var out []string
	errs := func(err error) string {
		if err == nil {
			return "ok"
		}
		if err == io.EOF {
			return "eof"
		}
		return "err"
	}
	for i := 0; i < len(script); i++ {
		switch script[i] {
		case 'r': // Read 3
			buf := make([]byte, 3)
			n, err := r.Read(buf)
			out = append(out, fmt.Sprintf("r%d:%s:%s", n, hx(string(buf[:n])), errs(err)))
		case 'b':
			c, err := r.ReadByte()
			out = append(out, fmt.Sprintf("b%d:%s", c, errs(err)))
		case 'B':
			out = append(out, "B:"+errs(r.UnreadByte()))
		case 'c':
			ch, size, err := r.ReadRune()
			out = append(out, fmt.Sprintf("c%d:%d:%s", ch, size, errs(err)))
		case 'C':
			out = append(out, "C:"+errs(r.UnreadRune()))
		case 'a': // ReadAt 4 at offset 1
			buf := make([]byte, 4)
			n, err := r.ReadAt(buf, 1)
			out = append(out, fmt.Sprintf("a%d:%s:%s", n, hx(string(buf[:n])), errs(err)))
		case 'n':
			_, err := r.ReadAt(make([]byte, 1), -1)
			out = append(out, "n:"+errs(err))
		case 's':
			p, err := r.Seek(2, io.SeekStart)
			out = append(out, fmt.Sprintf("s%d:%s", p, errs(err)))
		case 'S':
			p, err := r.Seek(-1, io.SeekCurrent)
			out = append(out, fmt.Sprintf("S%d:%s", p, errs(err)))
		case 'e':
			p, err := r.Seek(-2, io.SeekEnd)
			out = append(out, fmt.Sprintf("e%d:%s", p, errs(err)))
		case 'E':
			p, err := r.Seek(5, io.SeekEnd)
			out = append(out, fmt.Sprintf("E%d:%s", p, errs(err)))
		case 'z':
			p, err := r.Seek(-1000, io.SeekEnd)
			out = append(out, fmt.Sprintf("z%d:%s", p, errs(err)))
		case 'w':
			var sb strings.Builder
			n, err := r.WriteTo(&sb)
			out = append(out, fmt.Sprintf("w%d:%s:%s", n, hx(sb.String()), errs(err)))
		case 'l':
			out = append(out, fmt.Sprintf("l%d/%d", r.Len(), r.Size()))
		}
	}
	return strings.Join(out, " ")
}

func op(name string, f []string, field func(int) string) string {
	str := func(i int) string { return field(i) }
	num := func(i int) int {
		n, err := strconv.Atoi(field(i))
		if err != nil {
			panic(err)
		}
		return n
	}
	rn := func(i int) rune { return rune(num(i)) }
	opt := func(i int) string { return strconv.Itoa(i) }
	switch name {
	case "Index":
		return opt(strings.Index(str(0), str(1)))
	case "LastIndex":
		return opt(strings.LastIndex(str(0), str(1)))
	case "IndexByte":
		return opt(strings.IndexByte(str(0), byte(num(1))))
	case "LastIndexByte":
		return opt(strings.LastIndexByte(str(0), byte(num(1))))
	case "IndexRune":
		return opt(strings.IndexRune(str(0), rn(1)))
	case "IndexAny":
		return opt(strings.IndexAny(str(0), str(1)))
	case "LastIndexAny":
		return opt(strings.LastIndexAny(str(0), str(1)))
	case "IndexFunc":
		return opt(strings.IndexFunc(str(0), pred))
	case "LastIndexFunc":
		return opt(strings.LastIndexFunc(str(0), pred))
	case "Contains":
		return b2s(strings.Contains(str(0), str(1)))
	case "ContainsAny":
		return b2s(strings.ContainsAny(str(0), str(1)))
	case "ContainsRune":
		return b2s(strings.ContainsRune(str(0), rn(1)))
	case "ContainsFunc":
		return b2s(strings.ContainsFunc(str(0), pred))
	case "Count":
		return strconv.Itoa(strings.Count(str(0), str(1)))
	case "HasPrefix":
		return b2s(strings.HasPrefix(str(0), str(1)))
	case "HasSuffix":
		return b2s(strings.HasSuffix(str(0), str(1)))
	case "Compare":
		return strconv.Itoa(strings.Compare(str(0), str(1)))
	case "Cut":
		b, a, ok := strings.Cut(str(0), str(1))
		return cut3(b, a, ok)
	case "CutLast":
		b, a, ok := strings.CutLast(str(0), str(1))
		return cut3(b, a, ok)
	case "CutPrefix":
		a, ok := strings.CutPrefix(str(0), str(1))
		return b2s(ok) + "," + hx(a)
	case "CutSuffix":
		a, ok := strings.CutSuffix(str(0), str(1))
		return b2s(ok) + "," + hx(a)
	case "TrimPrefix":
		return hx(strings.TrimPrefix(str(0), str(1)))
	case "TrimSuffix":
		return hx(strings.TrimSuffix(str(0), str(1)))
	case "EqualFold":
		return b2s(strings.EqualFold(str(0), str(1)))
	case "Fields":
		return list(strings.Fields(str(0)))
	case "FieldsSeq":
		return list(collect(strings.FieldsSeq(str(0))))
	case "FieldsFunc":
		return list(strings.FieldsFunc(str(0), pred))
	case "FieldsFuncSeq":
		return list(collect(strings.FieldsFuncSeq(str(0), pred)))
	case "Lines":
		return list(collect(strings.Lines(str(0))))
	case "Split":
		return list(strings.Split(str(0), str(1)))
	case "SplitAfter":
		return list(strings.SplitAfter(str(0), str(1)))
	case "SplitN":
		return list(strings.SplitN(str(0), str(1), num(2)))
	case "SplitAfterN":
		return list(strings.SplitAfterN(str(0), str(1), num(2)))
	case "SplitSeq":
		return list(collect(strings.SplitSeq(str(0), str(1))))
	case "SplitAfterSeq":
		return list(collect(strings.SplitAfterSeq(str(0), str(1))))
	case "Join":
		// elements are the Split of arg 0 by "," so they exercise empty and odd bytes
		return hx(strings.Join(strings.Split(str(0), ","), str(1)))
	case "Repeat":
		return hx(strings.Repeat(str(0), num(1)))
	case "Replace":
		return hx(strings.Replace(str(0), str(1), str(2), num(3)))
	case "ReplaceAll":
		return hx(strings.ReplaceAll(str(0), str(1), str(2)))
	case "ToUpper":
		return hx(strings.ToUpper(str(0)))
	case "ToLower":
		return hx(strings.ToLower(str(0)))
	case "ToTitle":
		return hx(strings.ToTitle(str(0)))
	case "Title":
		return hx(strings.Title(str(0)))
	case "ToUpperSpecial":
		return hx(strings.ToUpperSpecial(special(str(1)), str(0)))
	case "ToLowerSpecial":
		return hx(strings.ToLowerSpecial(special(str(1)), str(0)))
	case "ToTitleSpecial":
		return hx(strings.ToTitleSpecial(special(str(1)), str(0)))
	case "ToValidUTF8":
		return hx(strings.ToValidUTF8(str(0), str(1)))
	case "Map":
		return hx(strings.Map(mapping, str(0)))
	case "Trim":
		return hx(strings.Trim(str(0), str(1)))
	case "TrimLeft":
		return hx(strings.TrimLeft(str(0), str(1)))
	case "TrimRight":
		return hx(strings.TrimRight(str(0), str(1)))
	case "TrimSpace":
		return hx(strings.TrimSpace(str(0)))
	case "TrimFunc":
		return hx(strings.TrimFunc(str(0), pred))
	case "TrimLeftFunc":
		return hx(strings.TrimLeftFunc(str(0), pred))
	case "TrimRightFunc":
		return hx(strings.TrimRightFunc(str(0), pred))
	case "Reader":
		return readerScript(str(0), string(str(1)))
	case "Replacer":
		// arg 0 is the input, the remaining args are old/new pairs.
		var oldnew []string
		for i := 1; i < len(f); i++ {
			oldnew = append(oldnew, str(i))
		}
		r := strings.NewReplacer(oldnew...)
		var sb strings.Builder
		n, err := r.WriteString(&sb, str(0))
		if err != nil {
			panic(err)
		}
		return hx(r.Replace(str(0))) + "," + strconv.Itoa(n) + "," + hx(sb.String())
	}
	panic("unknown op " + name)
}

func special(s string) unicode.SpecialCase {
	if s == "T" {
		return unicode.TurkishCase
	}
	return unicode.AzeriCase
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 4096), 64*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		parts := strings.Split(in.Text(), "\t")
		f := parts[1:]
		// Numeric and name arguments for Reader/special are passed as hex too;
		// the "num" accessor needs decimal, so hex is decoded lazily per use.
		name := parts[0]
		field := func(i int) string {
			if numeric(name, i) {
				return f[i]
			}
			b, err := hex.DecodeString(f[i])
			if err != nil {
				panic(err)
			}
			return string(b)
		}
		fmt.Fprintln(out, safe(name, f, field))
	}
}

// numeric reports whether argument i of op is a decimal number, not hex.
func numeric(name string, i int) bool {
	switch name {
	case "IndexByte", "LastIndexByte", "IndexRune", "ContainsRune":
		return i == 1
	case "SplitN", "SplitAfterN":
		return i == 2
	case "Repeat":
		return i == 1
	case "Replace":
		return i == 3
	}
	return false
}

func safe(name string, f []string, field func(int) string) (res string) {
	defer func() {
		if recover() != nil {
			res = "panic"
		}
	}()
	return op(name, f, field)
}
