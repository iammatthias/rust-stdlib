// Line-oriented Go oracle for io, io/fs, bufio and embed-style file systems.
// Requests are tab-separated; byte strings are hex. tools/io_check.py feeds
// the same requests to examples/io_probe.rs and compares the output lines.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing/fstest"
	"time"
)

var errBoom = errors.New("boom")
var errFull = errors.New("full")
var errCustom = errors.New("custom")
var errSplit = errors.New("splitfail")

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

func ints(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ",") {
		if p != "" {
			out = append(out, atoi(p))
		}
	}
	return out
}

func es(err error) string {
	if err == nil {
		return "nil"
	}
	return err.Error()
}

// chunkReader returns data in the given chunk sizes and never returns data
// together with an error. At errAt (if >= 0) it fails with boom.
type chunkReader struct {
	data   []byte
	pos    int
	chunks []int
	ci     int
	errAt  int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if c.errAt >= 0 && c.pos >= c.errAt {
		return 0, errBoom
	}
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n := c.chunks[c.ci%len(c.chunks)]
	c.ci++
	limit := len(c.data) - c.pos
	if c.errAt >= 0 && c.errAt-c.pos < limit {
		limit = c.errAt - c.pos
	}
	if n > limit {
		n = limit
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.data[c.pos:c.pos+n])
	c.pos += n
	return n, nil
}

func newChunk(data, chunks, errAt string) *chunkReader {
	return &chunkReader{data: unhex(data), chunks: ints(chunks), errAt: atoi(errAt)}
}

// limWriter accepts at most one chunk per call and fails after failAfter bytes.
type limWriter struct {
	buf       []byte
	chunks    []int
	ci        int
	failAfter int
}

func (w *limWriter) Write(p []byte) (int, error) {
	if w.failAfter >= 0 && len(w.buf) >= w.failAfter {
		return 0, errFull
	}
	n := w.chunks[w.ci%len(w.chunks)]
	w.ci++
	if n > len(p) {
		n = len(p)
	}
	if w.failAfter >= 0 && len(w.buf)+n > w.failAfter {
		n = w.failAfter - len(w.buf)
	}
	w.buf = append(w.buf, p[:n]...)
	return n, nil
}

func newLim(chunks, failAfter string) *limWriter {
	return &limWriter{chunks: ints(chunks), failAfter: atoi(failAfter)}
}

func cut(s, sep string) (string, string) {
	a, b, _ := strings.Cut(s, sep)
	return a, b
}

// ---------------------------------------------------------------- bufio

func opBR(f []string) (res string) {
	r := bufio.NewReaderSize(newChunk(f[1], f[2], f[3]), atoi(f[4]))
	var out []string
	for _, op := range strings.Split(f[5], ";") {
		name, arg := cut(op, ":")
		switch name {
		case "peek":
			b, err := r.Peek(atoi(arg))
			out = append(out, fmt.Sprintf("P:%x:%s", b, es(err)))
		case "discard":
			n, err := r.Discard(atoi(arg))
			out = append(out, fmt.Sprintf("D:%d:%s", n, es(err)))
		case "rs":
			b, err := r.ReadSlice(unhex(arg)[0])
			out = append(out, fmt.Sprintf("RS:%x:%s", b, es(err)))
		case "rl":
			b, pre, err := r.ReadLine()
			out = append(out, fmt.Sprintf("RL:%x:%v:%s", b, pre, es(err)))
		case "rb":
			b, err := r.ReadBytes(unhex(arg)[0])
			out = append(out, fmt.Sprintf("RB:%x:%s", b, es(err)))
		case "rstr":
			s, err := r.ReadString(unhex(arg)[0])
			out = append(out, fmt.Sprintf("RT:%x:%s", s, es(err)))
		case "rbyte":
			b, err := r.ReadByte()
			out = append(out, fmt.Sprintf("RY:%d:%s", b, es(err)))
		case "ubyte":
			out = append(out, "UB:"+es(r.UnreadByte()))
		case "rrune":
			c, n, err := r.ReadRune()
			out = append(out, fmt.Sprintf("RR:%d:%d:%s", c, n, es(err)))
		case "urune":
			out = append(out, "UR:"+es(r.UnreadRune()))
		case "buffered":
			out = append(out, fmt.Sprintf("BU:%d", r.Buffered()))
		case "size":
			out = append(out, fmt.Sprintf("SZ:%d", r.Size()))
		case "read":
			n := atoi(arg)
			p := make([]byte, n)
			k, err := r.Read(p)
			if n == 0 {
				out = append(out, fmt.Sprintf("R0:%d", k))
			} else {
				out = append(out, fmt.Sprintf("R:%d:%x:%s", k, p[:k], es(err)))
			}
		case "wto":
			w := newLim(strings.ReplaceAll(arg, "+", ","), f[6])
			n, err := r.WriteTo(w)
			ns := "-"
			if err == nil {
				ns = strconv.FormatInt(n, 10)
			}
			out = append(out, fmt.Sprintf("W:%x:%s:%s", w.buf, ns, es(err)))
		default:
			panic("bad op " + op)
		}
	}
	return strings.Join(out, "|")
}

func opBW(f []string) string {
	w := newLim(f[2], f[3])
	b := bufio.NewWriterSize(w, atoi(f[1]))
	var out []string
	for _, op := range strings.Split(f[4], ";") {
		name, arg := cut(op, ":")
		switch name {
		case "w":
			n, err := b.Write(unhex(arg))
			out = append(out, fmt.Sprintf("W:%d:%s", n, es(err)))
		case "wb":
			out = append(out, "WB:"+es(b.WriteByte(unhex(arg)[0])))
		case "wr":
			n, err := b.WriteRune(rune(atoi(arg)))
			ns := "-" // the partial count of a failed WriteRune is not representable
			if err == nil {
				ns = strconv.Itoa(n)
			}
			out = append(out, fmt.Sprintf("WR:%s:%s", ns, es(err)))
		case "ws":
			n, err := b.WriteString(string(unhex(arg)))
			out = append(out, fmt.Sprintf("WS:%d:%s", n, es(err)))
		case "flush":
			out = append(out, "F:"+es(b.Flush()))
		case "avail":
			out = append(out, fmt.Sprintf("A:%d", b.Available()))
		case "buffered":
			out = append(out, fmt.Sprintf("BU:%d", b.Buffered()))
		case "size":
			out = append(out, fmt.Sprintf("SZ:%d", b.Size()))
		case "ab":
			ab := b.AvailableBuffer()
			ok := len(ab) == 0 && cap(ab) == b.Available()
			ab = append(ab, unhex(arg)...)
			n, err := b.Write(ab)
			out = append(out, fmt.Sprintf("AB:%v:%d:%s", ok, n, es(err)))
		case "rf":
			d, c := cut(arg, "+")
			n, err := b.ReadFrom(&chunkReader{data: unhex(d), chunks: ints(strings.ReplaceAll(c, "+", ",")), errAt: -1})
			ns := "-"
			if err == nil {
				ns = strconv.FormatInt(n, 10)
			}
			out = append(out, fmt.Sprintf("RF:%s:%s", ns, es(err)))
		case "reset":
			w = newLim(f[2], f[3])
			b.Reset(w)
			out = append(out, "RESET")
		default:
			panic("bad op " + op)
		}
	}
	out = append(out, fmt.Sprintf("DST:%x", w.buf))
	return strings.Join(out, "|")
}

func splitFor(name string) bufio.SplitFunc {
	switch name {
	case "lines":
		return bufio.ScanLines
	case "words":
		return bufio.ScanWords
	case "runes":
		return bufio.ScanRunes
	case "bytes":
		return bufio.ScanBytes
	case "comma":
		return func(data []byte, atEOF bool) (int, []byte, error) {
			if atEOF && len(data) == 0 {
				return 0, nil, nil
			}
			if i := bytes.IndexByte(data, ','); i >= 0 {
				return i + 1, data[:i], nil
			}
			if atEOF {
				return len(data), data, nil
			}
			return 0, nil, nil
		}
	case "dollar", "dollarnil":
		return func(data []byte, atEOF bool) (int, []byte, error) {
			if i := bytes.IndexByte(data, '$'); i >= 0 {
				if name == "dollarnil" {
					return i + 1, nil, bufio.ErrFinalToken
				}
				return i + 1, data[:i], bufio.ErrFinalToken
			}
			if atEOF && len(data) == 0 {
				return 0, nil, nil
			}
			if atEOF {
				return len(data), data, nil
			}
			return 0, nil, nil
		}
	case "negadv":
		return func(data []byte, atEOF bool) (int, []byte, error) {
			if len(data) > 0 {
				return -1, data[:1], nil
			}
			return 0, nil, nil
		}
	case "toofar":
		return func(data []byte, atEOF bool) (int, []byte, error) {
			if len(data) > 0 {
				return len(data) + 1, data, nil
			}
			return 0, nil, nil
		}
	case "emptytok":
		return func(data []byte, atEOF bool) (int, []byte, error) {
			if atEOF {
				return 0, []byte{}, nil
			}
			return bufio.ScanBytes(data, atEOF)
		}
	case "errsplit":
		return func(data []byte, atEOF bool) (int, []byte, error) {
			if bytes.IndexByte(data, 'X') >= 0 {
				return 0, nil, errSplit
			}
			return bufio.ScanLines(data, atEOF)
		}
	case "needmore":
		return func(data []byte, atEOF bool) (int, []byte, error) {
			if atEOF {
				return len(data), data, nil
			}
			return 0, nil, nil
		}
	}
	panic("bad split " + name)
}

func opSC(f []string) (res string) {
	s := bufio.NewScanner(newChunk(f[1], f[2], f[3]))
	s.Split(splitFor(f[4]))
	if init := atoi(f[5]); init >= 0 {
		s.Buffer(make([]byte, 0, init), atoi(f[6]))
	}
	var toks []string
	defer func() {
		if r := recover(); r != nil {
			res = strings.Join(toks, ",") + ";panic"
		}
	}()
	for len(toks) < 3000 && s.Scan() {
		toks = append(toks, hex.EncodeToString(s.Bytes()))
	}
	return strings.Join(toks, ",") + ";" + es(s.Err())
}

// ---------------------------------------------------------------- io

func opRAL(f []string) string {
	r := newChunk(f[1], f[2], f[3])
	p := make([]byte, atoi(f[4]))
	var n int
	var err error
	if f[5] == "full" {
		n, err = io.ReadFull(r, p)
	} else {
		n, err = io.ReadAtLeast(r, p, atoi(f[5]))
	}
	return fmt.Sprintf("%d:%x:%s", n, p[:n], es(err))
}

func opCP(f []string) string {
	r := newChunk(f[1], f[2], f[3])
	w := newLim(f[4], f[5])
	var n int64
	var err error
	mode, arg := cut(f[6], ":")
	switch mode {
	case "copy":
		n, err = io.Copy(w, struct{ io.Reader }{r})
	case "copyn":
		n, err = io.CopyN(w, struct{ io.Reader }{r}, int64(atoi(arg)))
	case "copybuf":
		n, err = io.CopyBuffer(w, struct{ io.Reader }{r}, make([]byte, atoi(arg)))
	}
	return fmt.Sprintf("%d:%s:%x", n, es(err), w.buf)
}

func opRALL(f []string) string {
	b, err := io.ReadAll(newChunk(f[1], f[2], f[3]))
	if err != nil {
		return "err:" + err.Error()
	}
	return fmt.Sprintf("ok:%x", b)
}

// fmtRead renders a Read result canonically: data and EOF never come
// together in Rust, and a partial count with another error is not
// representable, so those print as "-:-:msg".
func fmtRead(k int, p []byte, err error) string {
	switch {
	case err == nil:
		return fmt.Sprintf("%d:%x:nil", k, p[:k])
	case err == io.EOF && k == 0:
		return "0::EOF"
	case err == io.EOF:
		return fmt.Sprintf("%d:%x:nil", k, p[:k])
	}
	return "-:-:" + err.Error()
}

func readSizes(r io.Reader, sizes []int) []string {
	var out []string
	for _, n := range sizes {
		p := make([]byte, n)
		k, err := r.Read(p)
		out = append(out, fmtRead(k, p, err))
	}
	return out
}

func opLR(f []string) string {
	lr := io.LimitReader(newChunk(f[1], f[2], "-1"), int64(atoi(f[3]))).(*io.LimitedReader)
	out := readSizes(lr, ints(f[4]))
	return strings.Join(out, "|") + fmt.Sprintf("|N=%d", lr.N)
}

func opMR(f []string) string {
	var rs []io.Reader
	for _, d := range strings.Split(f[1], ",") {
		rs = append(rs, &chunkReader{data: unhex(d), chunks: ints(f[2]), errAt: -1})
	}
	return strings.Join(readSizes(io.MultiReader(rs...), ints(f[3])), "|")
}

func opMW(f []string) string {
	// f[1]: writer specs "chunks/failAfter" joined by ';'; f[2]: writes (hex) joined by ','
	var ws []*limWriter
	var iw []io.Writer
	for _, spec := range strings.Split(f[1], ";") {
		c, fa := cut(spec, "/")
		w := newLim(strings.ReplaceAll(c, "+", ","), fa)
		ws = append(ws, w)
		iw = append(iw, w)
	}
	mw := io.MultiWriter(iw...)
	var out []string
	for _, d := range strings.Split(f[2], ",") {
		n, err := mw.Write(unhex(d))
		ns := "-"
		if err == nil {
			ns = strconv.Itoa(n)
		}
		out = append(out, fmt.Sprintf("%s:%s", ns, es(err)))
	}
	for _, w := range ws {
		out = append(out, fmt.Sprintf("%x", w.buf))
	}
	return strings.Join(out, "|")
}

func opTR(f []string) string {
	w := newLim(f[3], f[4])
	t := io.TeeReader(newChunk(f[1], f[2], "-1"), w)
	out := readSizes(t, ints(f[5]))
	return strings.Join(out, "|") + fmt.Sprintf("|DST:%x", w.buf)
}

func opSR(f []string) string {
	data := unhex(f[1])
	br := bytes.NewReader(data)
	s := io.NewSectionReader(br, int64(atoi(f[2])), int64(atoi(f[3])))
	var out []string
	for _, op := range strings.Split(f[4], ";") {
		name, arg := cut(op, ":")
		switch name {
		case "read":
			p := make([]byte, atoi(arg))
			k, err := s.Read(p)
			if len(p) == 0 {
				out = append(out, fmt.Sprintf("R0:%d", k))
			} else {
				out = append(out, "R:"+fmtRead(k, p, err))
			}
		case "readat":
			a, b := cut(arg, "@")
			p := make([]byte, atoi(a))
			k, err := s.ReadAt(p, int64(atoi(b)))
			out = append(out, fmt.Sprintf("RA:%d:%x:%s", k, p[:k], es(err)))
		case "seek":
			a, b := cut(arg, "@")
			n, err := s.Seek(int64(atoi(b)), atoi(a))
			out = append(out, fmt.Sprintf("S:%d:%s", n, es(err)))
		case "size":
			out = append(out, fmt.Sprintf("SZ:%d", s.Size()))
		case "outer":
			r, off, n := s.Outer()
			out = append(out, fmt.Sprintf("O:%v:%d:%d", r == io.ReaderAt(br), off, n))
		}
	}
	return strings.Join(out, "|")
}

type memAt struct{ b []byte }

func (m *memAt) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("neg")
	}
	end := int(off) + len(p)
	for len(m.b) < end {
		m.b = append(m.b, 0)
	}
	copy(m.b[off:], p)
	return len(p), nil
}

func opOW(f []string) string {
	m := &memAt{}
	o := io.NewOffsetWriter(m, int64(atoi(f[1])))
	var out []string
	for _, op := range strings.Split(f[2], ";") {
		name, arg := cut(op, ":")
		switch name {
		case "write":
			n, err := o.Write(unhex(arg))
			out = append(out, fmt.Sprintf("W:%d:%s", n, es(err)))
		case "writeat":
			a, b := cut(arg, "@")
			n, err := o.WriteAt(unhex(a), int64(atoi(b)))
			out = append(out, fmt.Sprintf("WA:%d:%s", n, es(err)))
		case "seek":
			a, b := cut(arg, "@")
			n, err := o.Seek(int64(atoi(b)), atoi(a))
			out = append(out, fmt.Sprintf("S:%d:%s", n, es(err)))
		}
	}
	out = append(out, fmt.Sprintf("MEM:%x", m.b))
	return strings.Join(out, "|")
}

func opPIPE(f []string) string {
	// f[1] writes (hex, ','), f[2] read sizes, f[3] writer close (nil|err),
	// f[4] reader closes after N reads (-1 never), f[5] reader close kind (nil|err)
	var chunks [][]byte
	for _, c := range strings.Split(f[1], ",") {
		chunks = append(chunks, unhex(c))
	}
	pr, pw := io.Pipe()
	type wres struct {
		n   int
		err error
	}
	var wr []wres
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, c := range chunks {
			n, err := pw.Write(c)
			wr = append(wr, wres{n, err})
		}
		if f[3] == "err" {
			pw.CloseWithError(errCustom)
		} else {
			pw.Close()
		}
	}()
	var out []string
	closeAfter := atoi(f[4])
	sizes := ints(f[2])
	for i, n := range sizes {
		if i == closeAfter {
			rcloseGo(pr, f[5])
		}
		p := make([]byte, n)
		k, err := pr.Read(p)
		// A zero-length Write is consumed by a Read that returns (0, nil);
		// Rust's Read cannot express that (Ok(0) is EOF), so the Rust pipe
		// reads again and the oracle does the same.
		for k == 0 && err == nil {
			k, err = pr.Read(p)
		}
		out = append(out, fmtRead(k, p, err))
	}
	if closeAfter >= len(sizes) || closeAfter < 0 {
		pr.Close()
	}
	wg.Wait()
	for _, r := range wr {
		out = append(out, fmt.Sprintf("W%d:%s", r.n, es(r.err)))
	}
	return strings.Join(out, "|")
}

func rcloseGo(pr *io.PipeReader, kind string) {
	if kind == "err" {
		pr.CloseWithError(errCustom)
	} else {
		pr.Close()
	}
}

// ---------------------------------------------------------------- io/fs

func parseTree(s string) fstest.MapFS {
	m := fstest.MapFS{}
	if s == "" {
		return m
	}
	for _, e := range strings.Split(s, ",") {
		if strings.HasSuffix(e, "/") {
			m[strings.TrimSuffix(e, "/")] = &fstest.MapFile{Mode: fs.ModeDir | 0755}
			continue
		}
		name, data := cut(e, "=")
		m[name] = &fstest.MapFile{Data: unhex(data), Mode: 0644}
	}
	return m
}

func kind(d fs.DirEntry) string {
	if d == nil {
		return "nil"
	}
	if d.IsDir() {
		return "d"
	}
	return "f"
}

func opWALK(f []string) string {
	fsys := parseTree(f[1])
	rules := map[string]string{}
	for _, r := range strings.Split(f[3], ";") {
		k, p := cut(r, ":")
		if k != "" {
			rules[p] = k
		}
	}
	var out []string
	err := fs.WalkDir(fsys, f[2], func(p string, d fs.DirEntry, err error) error {
		extra := ""
		if d != nil {
			extra = ":" + d.Name() + ":" + d.Type().String()
		}
		out = append(out, fmt.Sprintf("%s|%s%s|%s", p, kind(d), extra, es(err)))
		switch rules[p] {
		case "skipdir":
			return fs.SkipDir
		case "skipall":
			return fs.SkipAll
		case "err":
			return errors.New("stop")
		}
		return nil
	})
	return strings.Join(out, ";") + "=>" + es(err)
}

func opGLOB(f []string) string {
	m, err := fs.Glob(parseTree(f[1]), f[2])
	if err != nil {
		return "err:" + err.Error()
	}
	return "ok:" + strings.Join(m, ",")
}

func opVALID(f []string) string {
	return strconv.FormatBool(fs.ValidPath(string(unhex(f[1]))))
}

func listDir(fsys fs.FS, name string) string {
	es_, err := fs.ReadDir(fsys, name)
	if err != nil {
		return "err:" + err.Error()
	}
	var out []string
	for _, e := range es_ {
		info, ierr := e.Info()
		s := fmt.Sprintf("%s:%s:%s:%s", e.Name(), kind(e), e.Type(), fs.FormatDirEntry(e))
		if ierr == nil {
			s += ":" + fs.FormatFileInfo(info)
		}
		out = append(out, s)
	}
	return "ok:" + strings.Join(out, ",")
}

func statFile(fsys fs.FS, name string) string {
	info, err := fs.Stat(fsys, name)
	var s string
	if err != nil {
		s = "err:" + err.Error()
	} else {
		s = fmt.Sprintf("%s:%d:%s:%v:%v", info.Name(), info.Size(), info.Mode(), info.IsDir(), info.ModTime().Equal(time.Time{}))
	}
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return s + "|err:" + err.Error()
	}
	return s + fmt.Sprintf("|ok:%x", data)
}

func opRDIR(f []string) string {
	return listDir(parseTree(f[1]), f[2])
}

func opSTAT(f []string) string {
	return statFile(parseTree(f[1]), f[2])
}

func opSUBO(f []string) string {
	sub, err := fs.Sub(parseTree(f[1]), f[2])
	if err != nil {
		return "err:" + err.Error()
	}
	var out []string
	for _, op := range strings.Split(f[3], ";") {
		name, arg := cut(op, ":")
		switch name {
		case "readfile":
			b, err := fs.ReadFile(sub, arg)
			if err != nil {
				out = append(out, "err:"+err.Error())
			} else {
				out = append(out, fmt.Sprintf("ok:%x", b))
			}
		case "readdir":
			out = append(out, listDir(sub, arg))
		case "stat":
			out = append(out, statFile(sub, arg))
		case "glob":
			m, err := fs.Glob(sub, arg)
			if err != nil {
				out = append(out, "err:"+err.Error())
			} else {
				out = append(out, "ok:"+strings.Join(m, ","))
			}
		case "sub":
			s2, err := fs.Sub(sub, arg)
			if err != nil {
				out = append(out, "err:"+err.Error())
			} else {
				out = append(out, listDir(s2, "."))
			}
		}
	}
	return strings.Join(out, "|")
}

type fakeInfo struct{ m fs.FileMode }

func (fakeInfo) Name() string        { return "n" }
func (fakeInfo) Size() int64         { return 1234 }
func (i fakeInfo) Mode() fs.FileMode { return i.m }
func (fakeInfo) ModTime() time.Time  { return time.Unix(86400*365, 5).UTC() }
func (i fakeInfo) IsDir() bool       { return i.m.IsDir() }
func (fakeInfo) Sys() any            { return nil }

func opFMODE(f []string) string {
	m := fs.FileMode(uint32(atoi(f[1])))
	info := fakeInfo{m}
	return fmt.Sprintf("%s|%v|%v|%s|%s|%s|%s", m.String(), m.IsDir(), m.IsRegular(), m.Perm(), m.Type(),
		fs.FormatFileInfo(info), fs.FormatDirEntry(fs.FileInfoToDirEntry(info)))
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<16), 1<<26)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	ops := map[string]func([]string) string{
		"BR": opBR, "BW": opBW, "SC": opSC, "RAL": opRAL, "CP": opCP, "RALL": opRALL,
		"LR": opLR, "MR": opMR, "MW": opMW, "TR": opTR, "SR": opSR, "OW": opOW, "PIPE": opPIPE,
		"WALK": opWALK, "GLOB": opGLOB, "VALID": opVALID, "RDIR": opRDIR, "STAT": opSTAT,
		"SUBO": opSUBO, "FMODE": opFMODE,
	}
	for in.Scan() {
		f := strings.Split(in.Text(), "\t")
		fn, ok := ops[f[0]]
		if !ok {
			panic("unknown request " + f[0])
		}
		fmt.Fprintln(out, fn(f))
	}
}
