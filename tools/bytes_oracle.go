// bytes_oracle reads tab-separated requests on stdin (hex-encoded byte
// arguments) and prints one result line per request. It is the Go side of
// tools/bytes_check.py; examples/bytes_probe.rs is the Rust side.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"
)

func fnv(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

// fb formats bytes: hex when short, otherwise length and hash.
func fb(b []byte) string {
	if len(b) > 64 {
		return fmt.Sprintf("%d:%016x", len(b), fnv(b))
	}
	return hex.EncodeToString(b)
}

func fl(parts [][]byte) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = fb(p)
	}
	return fmt.Sprintf("%d[%s]", len(parts), strings.Join(out, ","))
}

func fi(i int) string { return strconv.Itoa(i) }

func fe(err error) string {
	if err == nil {
		return "nil"
	}
	return err.Error()
}

func pred(id int) func(rune) bool {
	switch id {
	case 0:
		return func(r rune) bool { return r >= 0x80 }
	case 1:
		return func(r rune) bool { return r == 'a' || r == 0xFFFD }
	case 2:
		return func(r rune) bool { return '0' <= r && r <= '9' }
	}
	return unicode.IsSpace
}

func mapping(id int) func(rune) rune {
	switch id {
	case 0:
		return func(r rune) rune {
			if r == 'a' {
				return -1
			}
			return r
		}
	case 1:
		return func(r rune) rune {
			if r == 'x' {
				return 0xFFFD
			}
			if 'a' <= r && r <= 'z' {
				return r - 32
			}
			return r
		}
	}
	return func(r rune) rune {
		if r >= 0x80 {
			return 0xFFFD
		}
		return r
	}
}

type chunkReader struct {
	data  []byte
	chunk int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := min(c.chunk, len(p), len(c.data))
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

type limitWriter struct {
	limit int
	got   []byte
}

func (w *limitWriter) Write(p []byte) (int, error) {
	n := min(len(p), w.limit)
	w.limit -= n
	w.got = append(w.got, p[:n]...)
	return n, nil
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func num(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

func try(f func() string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "panic"
		}
	}()
	return f()
}

func bufScript(parts []string) string {
	var b *bytes.Buffer
	spec := strings.Split(parts[0], ":")
	switch spec[0] {
	case "NEW":
		b = new(bytes.Buffer)
	case "NB":
		data := unhex(spec[1])
		buf := make([]byte, len(data), num(spec[2]))
		copy(buf, data)
		b = bytes.NewBuffer(buf)
	case "NS":
		b = bytes.NewBufferString(string(unhex(spec[1])))
	}
	var out []string
	for _, op := range parts[1:] {
		f := strings.Split(op, ":")
		var r string
		switch f[0] {
		case "W":
			n, err := b.Write(unhex(f[1]))
			r = fi(n) + "," + fe(err)
		case "WS":
			n, err := b.WriteString(string(unhex(f[1])))
			r = fi(n) + "," + fe(err)
		case "WB":
			r = fe(b.WriteByte(unhex(f[1])[0]))
		case "WR":
			n, err := b.WriteRune(rune(num(f[1])))
			r = fi(n) + "," + fe(err)
		case "R":
			p := make([]byte, num(f[1]))
			n, err := b.Read(p)
			r = fi(n) + "," + fe(err) + "," + fb(p[:n])
		case "RB":
			c, err := b.ReadByte()
			r = fi(int(c)) + "," + fe(err)
		case "RR":
			c, n, err := b.ReadRune()
			r = fi(int(c)) + "," + fi(n) + "," + fe(err)
		case "UB":
			r = fe(b.UnreadByte())
		case "UR":
			r = fe(b.UnreadRune())
		case "N":
			r = fb(b.Next(num(f[1])))
		case "T":
			n := num(f[1])
			r = try(func() string { b.Truncate(n); return "ok" })
		case "G":
			n := num(f[1])
			r = try(func() string { b.Grow(n); return "ok" })
		case "P":
			p, err := b.Peek(num(f[1]))
			r = fb(p) + "," + fe(err)
		case "RBY":
			line, err := b.ReadBytes(unhex(f[1])[0])
			r = fb(line) + "," + fe(err)
		case "RS":
			line, err := b.ReadString(unhex(f[1])[0])
			r = fb([]byte(line)) + "," + fe(err)
		case "RST":
			b.Reset()
			r = "ok"
		case "STR":
			r = fb([]byte(b.String()))
		case "RF":
			n, err := b.ReadFrom(&chunkReader{unhex(f[1]), num(f[2])})
			r = fmt.Sprintf("%d,%s", n, fe(err))
		case "WT":
			w := &limitWriter{limit: num(f[1])}
			n, err := b.WriteTo(w)
			r = fmt.Sprintf("%d,%s,%s", n, fe(err), fb(w.got))
		}
		out = append(out, fmt.Sprintf("%s/%d,%d,%d,%s", r, b.Len(), b.Cap(), b.Available(), fb(b.Bytes())))
	}
	return strings.Join(out, ";")
}

func readerScript(parts []string) string {
	rd := bytes.NewReader(unhex(parts[0]))
	var out []string
	for _, op := range parts[1:] {
		f := strings.Split(op, ":")
		var r string
		switch f[0] {
		case "R":
			p := make([]byte, num(f[1]))
			n, err := rd.Read(p)
			r = fi(n) + "," + fe(err) + "," + fb(p[:n])
		case "RB":
			c, err := rd.ReadByte()
			r = fi(int(c)) + "," + fe(err)
		case "RR":
			c, n, err := rd.ReadRune()
			r = fi(int(c)) + "," + fi(n) + "," + fe(err)
		case "UB":
			r = fe(rd.UnreadByte())
		case "UR":
			r = fe(rd.UnreadRune())
		case "RA":
			p := make([]byte, num(f[1]))
			n, err := rd.ReadAt(p, int64(num(f[2])))
			r = fi(n) + "," + fe(err) + "," + fb(p[:n])
		case "SK":
			n, err := rd.Seek(int64(num(f[2])), num(f[1]))
			r = fmt.Sprintf("%d,%s", n, fe(err))
		case "WT":
			w := &limitWriter{limit: num(f[1])}
			n, err := rd.WriteTo(w)
			r = fmt.Sprintf("%d,%s,%s", n, fe(err), fb(w.got))
		case "RST":
			rd.Reset(unhex(f[1]))
			r = "ok"
		}
		out = append(out, fmt.Sprintf("%s/%d,%d", r, rd.Len(), rd.Size()))
	}
	return strings.Join(out, ";")
}

func seqList(it func(func([]byte) bool)) [][]byte {
	var out [][]byte
	for v := range it {
		out = append(out, v)
	}
	return out
}

func idx(i int) string { return fi(i) }

func request(line string) string {
	f := strings.Split(line, "\t")
	op := f[0]
	a := func(i int) []byte { return unhex(f[i]) }
	n := func(i int) int { return num(f[i]) }
	switch op {
	case "BUF":
		return bufScript(f[1:])
	case "RDR":
		return readerScript(f[1:])
	case "IDX":
		return idx(bytes.Index(a(1), a(2)))
	case "LIDX":
		return idx(bytes.LastIndex(a(1), a(2)))
	case "IB":
		return idx(bytes.IndexByte(a(1), a(2)[0]))
	case "LIB":
		return idx(bytes.LastIndexByte(a(1), a(2)[0]))
	case "IR":
		return idx(bytes.IndexRune(a(1), rune(n(2))))
	case "CR":
		return fmt.Sprint(bytes.ContainsRune(a(1), rune(n(2))))
	case "IA":
		return idx(bytes.IndexAny(a(1), string(a(2))))
	case "LIA":
		return idx(bytes.LastIndexAny(a(1), string(a(2))))
	case "CA":
		return fmt.Sprint(bytes.ContainsAny(a(1), string(a(2))))
	case "CNT":
		return idx(bytes.Count(a(1), a(2)))
	case "CONT":
		return fmt.Sprint(bytes.Contains(a(1), a(2)))
	case "SPL":
		switch n(4) {
		case 0:
			return fl(bytes.SplitN(a(1), a(2), n(3)))
		case 1:
			return fl(bytes.SplitAfterN(a(1), a(2), n(3)))
		case 2:
			return fl(seqList(bytes.SplitSeq(a(1), a(2))))
		}
		return fl(seqList(bytes.SplitAfterSeq(a(1), a(2))))
	case "FLD":
		return fl(bytes.Fields(a(1))) + " " + fl(seqList(bytes.FieldsSeq(a(1))))
	case "LN":
		return fl(seqList(bytes.Lines(a(1))))
	case "FF":
		return fl(bytes.FieldsFunc(a(1), pred(n(2)))) + " " + fl(seqList(bytes.FieldsFuncSeq(a(1), pred(n(2)))))
	case "IF":
		return idx(bytes.IndexFunc(a(1), pred(n(2)))) + "," + idx(bytes.LastIndexFunc(a(1), pred(n(2)))) + "," + fmt.Sprint(bytes.ContainsFunc(a(1), pred(n(2))))
	case "TF":
		return fb(bytes.TrimFunc(a(1), pred(n(2)))) + "," + fb(bytes.TrimLeftFunc(a(1), pred(n(2)))) + "," + fb(bytes.TrimRightFunc(a(1), pred(n(2))))
	case "MAP":
		return fb(bytes.Map(mapping(n(2)), a(1)))
	case "UP":
		return fb(bytes.ToUpper(a(1)))
	case "LOW":
		return fb(bytes.ToLower(a(1)))
	case "TIT":
		return fb(bytes.ToTitle(a(1)))
	case "TITLE":
		return fb(bytes.Title(a(1)))
	case "SPC":
		return fb(bytes.ToUpperSpecial(unicode.TurkishCase, a(1))) + "," + fb(bytes.ToLowerSpecial(unicode.TurkishCase, a(1))) + "," + fb(bytes.ToTitleSpecial(unicode.TurkishCase, a(1)))
	case "TVU":
		return fb(bytes.ToValidUTF8(a(1), a(2)))
	case "RUNES":
		rs := bytes.Runes(a(1))
		parts := make([]string, len(rs))
		for i, r := range rs {
			parts[i] = fi(int(r))
		}
		return strings.Join(parts, ",")
	case "TRIM":
		return fb(bytes.Trim(a(1), string(a(2)))) + "," + fb(bytes.TrimLeft(a(1), string(a(2)))) + "," + fb(bytes.TrimRight(a(1), string(a(2))))
	case "TSP":
		return fb(bytes.TrimSpace(a(1)))
	case "TPS":
		return fb(bytes.TrimPrefix(a(1), a(2))) + "," + fb(bytes.TrimSuffix(a(1), a(2)))
	case "REP":
		return fb(bytes.Replace(a(1), a(2), a(3), n(4)))
	case "EF":
		return fmt.Sprint(bytes.EqualFold(a(1), a(2)))
	case "CUT":
		x, y, ok := bytes.Cut(a(1), a(2))
		x2, y2, ok2 := bytes.CutLast(a(1), a(2))
		return fmt.Sprint(ok) + "," + fb(x) + "," + fb(y) + " " + fmt.Sprint(ok2) + "," + fb(x2) + "," + fb(y2)
	}
	panic("unknown op " + op)
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		if line != "" {
			fmt.Fprintln(out, request(line))
		}
		if err != nil {
			break
		}
	}
}
