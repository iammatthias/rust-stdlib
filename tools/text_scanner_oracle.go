// Line-oriented Go text/scanner oracle used by tools/text_scanner_check.py.
// Each request line is
//
//	<op>:<cfg>:<chunk>:<errAt>:<hex source>
//
// op S scans with Scan, op N steps with Peek and Next. The source is read
// through a reader that returns at most <chunk> bytes per call (0 means no
// limit) and fails with "boom" once <errAt> bytes were delivered (-1 means
// never). <cfg> selects one of configs(), shared with
// examples/text_scanner_probe.rs. The output line lists, in order, every token
// or character with its position, every error callback (message, Pos and
// TokenText) and finally the error count and the number of Read calls.
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/scanner"
)

type config struct {
	mode        uint
	ws          uint64
	customIdent bool
}

// configs are shared with examples/text_scanner_probe.rs: 12 mode sets, each
// with and without a custom identifier predicate.
func configs() []config {
	modes := []uint{
		scanner.GoTokens,
		0,
		scanner.ScanIdents,
		scanner.ScanInts,
		scanner.ScanFloats,
		scanner.ScanChars | scanner.ScanStrings | scanner.ScanRawStrings,
		scanner.GoTokens &^ scanner.SkipComments,
		scanner.ScanIdents | scanner.ScanInts | scanner.ScanComments | scanner.SkipComments,
		scanner.ScanFloats | scanner.ScanComments,
		scanner.ScanComments,
		scanner.SkipComments,
		scanner.ScanInts | scanner.ScanIdents | scanner.ScanFloats | scanner.ScanStrings,
	}
	wss := []uint64{scanner.GoWhitespace, 0, 1<<1 | 1<<' ' | 1<<'\t'}
	var out []config
	for i, m := range modes {
		for ident := 0; ident < 2; ident++ {
			out = append(out, config{m, wss[i%len(wss)], ident == 1})
		}
	}
	return out
}

var errBoom = errors.New("boom")

type reader struct {
	data  []byte
	pos   int
	chunk int
	errAt int
	reads *int
}

func (r *reader) Read(p []byte) (int, error) {
	*r.reads++
	if r.errAt >= 0 && r.pos >= r.errAt {
		return 0, errBoom
	}
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := len(p)
	if r.chunk > 0 && n > r.chunk {
		n = r.chunk
	}
	if rem := len(r.data) - r.pos; n > rem {
		n = rem
	}
	if r.errAt >= 0 && r.pos+n > r.errAt {
		n = r.errAt - r.pos
	}
	copy(p, r.data[r.pos:r.pos+n])
	r.pos += n
	return n, nil
}

func hx(s string) string {
	return hex.EncodeToString([]byte(s))
}

func process(line string, cfgs []config) string {
	parts := strings.Split(line, ":")
	if len(parts) != 5 {
		panic("bad request " + line)
	}
	cfgIndex, _ := strconv.Atoi(parts[1])
	chunk, _ := strconv.Atoi(parts[2])
	errAt, _ := strconv.Atoi(parts[3])
	data, err := hex.DecodeString(parts[4])
	if err != nil {
		panic(err)
	}
	c := cfgs[cfgIndex]

	var rec []string
	reads := 0
	var s scanner.Scanner
	s.Init(&reader{data: data, chunk: chunk, errAt: errAt, reads: &reads})
	s.Mode = c.mode
	s.Whitespace = c.ws
	if c.customIdent {
		s.IsIdentRune = func(ch rune, i int) bool {
			return ch == '_' || ch >= 'a' && ch <= 'z' || i > 0 && ch >= '0' && ch <= '9'
		}
	}
	s.Error = func(s *scanner.Scanner, msg string) {
		rec = append(rec, fmt.Sprintf("E%s@%s#%s", hx(msg), hx(s.Pos().String()), hx(string(s.TokenText()))))
	}

	switch parts[0] {
	case "S":
		for i := 0; i < 100000; i++ {
			tok := s.Scan()
			off, line, col := s.Offset, s.Line, s.Column
			text := s.TokenText()
			rec = append(rec, fmt.Sprintf("T%d:%s@%d,%d,%d", tok, hx(text), off, line, col))
			p := s.Pos()
			rec = append(rec, fmt.Sprintf("P%d,%d,%d", p.Offset, p.Line, p.Column))
			if tok == scanner.EOF {
				break
			}
		}
	case "N":
		for i := 0; i < 100000; i++ {
			pk := s.Peek()
			ch := s.Next()
			p := s.Pos()
			rec = append(rec, fmt.Sprintf("N%d/%d:%d,%d,%d,%d", pk, ch, p.Offset, p.Line, p.Column, s.Line))
			if ch == scanner.EOF {
				break
			}
		}
	default:
		panic("bad op " + parts[0])
	}
	rec = append(rec, fmt.Sprintf("C%d R%d", s.ErrorCount, reads))
	return strings.Join(rec, " ")
}

func main() {
	cfgs := configs()
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<26)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, process(in.Text(), cfgs))
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
