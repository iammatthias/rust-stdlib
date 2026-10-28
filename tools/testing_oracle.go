// Go reference implementation for tools/testing_check.py.
//
// ORACLE_MODE selects what is exercised; the scenario file is read from the
// path in ORACLE_INPUT (JSON). The modes that run a test binary ("tests",
// "bench") are driven through testing.Main with the usual -test.* flags, so
// the output is exactly what `go test` prints; the others answer one line per
// scenario. examples/testing_probe.rs interprets the same scenarios.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"math/rand"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"testing/iotest"
	"testing/quick"
	"testing/slogtest"
	"testing/synctest"
	"time"
)

type Op struct {
	Op    string   `json:"op"`
	Args  []string `json:"args"`
	Msg   string   `json:"msg"`
	Name  string   `json:"name"`
	Ops   []Op     `json:"ops"`
	Text  string   `json:"text"`
	Key   string   `json:"key"`
	Value string   `json:"value"`
	N     int64    `json:"n"`
	F     float64  `json:"f"`
}

type Script struct {
	Name string `json:"name"`
	Ops  []Op   `json:"ops"`
}

func anys(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func runTestOps(t *testing.T, ops []Op) {
	for _, op := range ops {
		op := op
		switch op.Op {
		case "log":
			t.Log(anys(op.Args)...)
		case "logf":
			t.Logf("%s", op.Msg)
		case "error":
			t.Error(anys(op.Args)...)
		case "errorf":
			t.Errorf("%s", op.Msg)
		case "fatal":
			t.Fatal(anys(op.Args)...)
		case "fatalf":
			t.Fatalf("%s", op.Msg)
		case "skip":
			t.Skip(anys(op.Args)...)
		case "skipf":
			t.Skipf("%s", op.Msg)
		case "skipnow":
			t.SkipNow()
		case "fail":
			t.Fail()
		case "failnow":
			t.FailNow()
		case "sub":
			t.Run(op.Name, func(t *testing.T) { runTestOps(t, op.Ops) })
		case "psub":
			t.Run(op.Name, func(t *testing.T) {
				t.Parallel()
				runTestOps(t, op.Ops)
			})
		case "cleanup":
			t.Cleanup(func() { runTestOps(t, op.Ops) })
		case "write":
			t.Output().Write([]byte(op.Text))
		case "attr":
			t.Attr(op.Key, op.Value)
		case "name":
			t.Log(t.Name())
		case "failed":
			t.Logf("failed=%v skipped=%v", t.Failed(), t.Skipped())
		default:
			panic("unknown op " + op.Op)
		}
	}
}

func runBenchOps(b *testing.B, ops []Op) {
	for i := 0; i < b.N; i++ {
	}
	for _, op := range ops {
		op := op
		switch op.Op {
		case "log":
			b.Log(anys(op.Args)...)
		case "logf":
			b.Logf("%s", op.Msg)
		case "error":
			b.Error(anys(op.Args)...)
		case "fatal":
			b.Fatal(anys(op.Args)...)
		case "skip":
			b.Skip(anys(op.Args)...)
		case "skipnow":
			b.SkipNow()
		case "fail":
			b.Fail()
		case "failnow":
			b.FailNow()
		case "sub":
			b.Run(op.Name, func(b *testing.B) { runBenchOps(b, op.Ops) })
		case "metric":
			b.ReportMetric(op.F, op.Key)
		case "bytes":
			b.SetBytes(op.N)
		case "write":
			b.Output().Write([]byte(op.Text))
		case "name":
			b.Log(b.Name())
		default:
			panic("unknown op " + op.Op)
		}
	}
}

func readInput(v any) {
	data, err := os.ReadFile(os.Getenv("ORACLE_INPUT"))
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		panic(err)
	}
}

func matchString(pat, str string) (bool, error) { return regexp.MatchString(pat, str) }

func main() {
	switch os.Getenv("ORACLE_MODE") {
	case "tests":
		var scripts []Script
		readInput(&scripts)
		var tests []testing.InternalTest
		for _, s := range scripts {
			s := s
			tests = append(tests, testing.InternalTest{Name: s.Name, F: func(t *testing.T) { runTestOps(t, s.Ops) }})
		}
		testing.Main(matchString, tests, nil, nil)
	case "bench":
		var scripts []Script
		readInput(&scripts)
		var benches []testing.InternalBenchmark
		for _, s := range scripts {
			s := s
			benches = append(benches, testing.InternalBenchmark{Name: s.Name, F: func(b *testing.B) { runBenchOps(b, s.Ops) }})
		}
		testing.Main(matchString, nil, benches, nil)
	case "result":
		runResult()
	case "iotest":
		runIotest()
	case "testreader":
		runTestReader()
	case "fstest":
		runFstest()
	case "quick":
		runQuick()
	case "slogtest":
		runSlogtest()
	case "synctest":
		runSynctest()
	default:
		fmt.Fprintln(os.Stderr, "unknown ORACLE_MODE")
		os.Exit(2)
	}
}

// ---------------------------------------------------------------- result

type resultCase struct {
	N         int64              `json:"n"`
	T         int64              `json:"t"`
	Bytes     int64              `json:"bytes"`
	MemAllocs uint64             `json:"mem_allocs"`
	MemBytes  uint64             `json:"mem_bytes"`
	Extra     map[string]float64 `json:"extra"`
}

func runResult() {
	var cases []resultCase
	readInput(&cases)
	for _, c := range cases {
		r := testing.BenchmarkResult{N: int(c.N), T: time.Duration(c.T), Bytes: c.Bytes, MemAllocs: c.MemAllocs, MemBytes: c.MemBytes}
		if len(c.Extra) > 0 {
			r.Extra = c.Extra
		}
		fmt.Printf("%q|%q|%d|%d|%d\n", r.String(), r.MemString(), r.NsPerOp(), r.AllocsPerOp(), r.AllocedBytesPerOp())
	}
}

// ---------------------------------------------------------------- iotest

type readerCase struct {
	Data  string   `json:"data"` // hex
	Wrap  []string `json:"wrap"`
	Reads []int    `json:"reads"`
	ErrAt int      `json:"err_at"`
}

// errAfterReader returns data and then a custom error instead of EOF.
type errAfterReader struct {
	r   io.Reader
	err error
}

func (e *errAfterReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err == io.EOF {
		return n, e.err
	}
	return n, err
}

// splitReader turns a result with data and an error into the data now and the
// error from the next call, which is all a Rust reader can express.
type splitReader struct {
	r       io.Reader
	pending error
	has     bool
}

func (s *splitReader) Read(p []byte) (int, error) {
	if s.has {
		s.has = false
		return 0, s.pending
	}
	n, err := s.r.Read(p)
	if n > 0 && err != nil {
		s.pending, s.has = err, true
		return n, nil
	}
	return n, err
}

func errString(err error) string {
	switch err {
	case nil:
		return "nil"
	case io.EOF:
		return "EOF"
	}
	return "E:" + err.Error()
}

func runIotest() {
	var cases []readerCase
	readInput(&cases)
	for _, c := range cases {
		data, _ := hex.DecodeString(c.Data)
		var r io.Reader = bytes.NewReader(data)
		for _, w := range c.Wrap {
			switch w {
			case "onebyte":
				r = iotest.OneByteReader(r)
			case "half":
				r = iotest.HalfReader(r)
			case "dataerr":
				// Rust's Read cannot return data together with an error, so the
				// error of such a result is delivered by the next read.
				r = &splitReader{r: iotest.DataErrReader(r)}
			case "timeout":
				r = iotest.TimeoutReader(r)
			case "errtail":
				r = &errAfterReader{r, errors.New("tail error")}
			case "err":
				r = iotest.ErrReader(errors.New("boom"))
			}
		}
		var out []string
		for _, n := range c.Reads {
			buf := make([]byte, n)
			got, err := r.Read(buf)
			// Rust's Read cannot return data together with an error, so a
			// result with both is reported as the data and then the error.
			out = append(out, fmt.Sprintf("%d:%x:%s", got, buf[:got], errString(err)))
		}
		// Writers.
		var sb bytes.Buffer
		tw := iotest.TruncateWriter(&sb, int64(c.ErrAt))
		var wl []string
		for _, n := range c.Reads {
			chunk := bytes.Repeat([]byte{'x'}, n)
			wn, werr := tw.Write(chunk)
			wl = append(wl, fmt.Sprintf("%d:%s", wn, errString(werr)))
		}
		fmt.Printf("%s|%s|%s\n", strings.Join(out, ","), strings.Join(wl, ","), hex.EncodeToString(sb.Bytes()))
	}
}

// brokenReader misbehaves in a way selected by kind; the same kinds are
// implemented in examples/testing_probe.rs.
type brokenReader struct {
	kind    string
	content []byte
	off     int64
}

func (b *brokenReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		if b.kind == "read0" {
			return 1, nil
		}
		return 0, nil
	}
	if b.off >= int64(len(b.content)) {
		if b.kind == "noeof" {
			return 1, nil
		}
		return 0, io.EOF
	}
	n := copy(p, b.content[b.off:])
	if b.kind == "shortcorrupt" && b.off == 0 {
		p[0] ^= 0xff
	}
	b.off += int64(n)
	if b.kind == "readerr" && b.off > 3 {
		return n, errors.New("synthetic failure")
	}
	return n, nil
}

type brokenSeeker struct {
	brokenReader
}

func (b *brokenSeeker) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0:
	case 1:
		offset += b.off
	case 2:
		offset += int64(len(b.content))
	}
	if b.kind == "seekoff" {
		offset++
	}
	if offset < 0 || offset > int64(len(b.content)) {
		return 0, errors.New("bad seek")
	}
	b.off = offset
	return offset, nil
}

type brokenReaderAt struct {
	brokenSeeker
}

func (b *brokenReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > int64(len(b.content)) {
		return 0, errors.New("bad readat")
	}
	n := copy(p, b.content[off:])
	if b.kind == "readatshort" && n > 0 {
		n--
	}
	if b.kind == "readatnoeof" {
		return n, nil
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

type trCase struct {
	Kind    string `json:"kind"`
	Caps    string `json:"caps"` // plain | seek | seekat
	Content string `json:"content"`
}

func runTestReader() {
	var cases []trCase
	readInput(&cases)
	for _, c := range cases {
		content, _ := hex.DecodeString(c.Content)
		base := brokenReader{kind: c.Kind, content: content}
		var r io.Reader
		switch c.Caps {
		case "plain":
			r = &base
		case "seek":
			r = &brokenSeeker{base}
		case "seekat":
			r = &brokenReaderAt{brokenSeeker{base}}
		case "bytes":
			r = bytes.NewReader(content)
		case "strings":
			r = strings.NewReader(string(content))
		}
		err := iotest.TestReader(r, content)
		if err == nil {
			fmt.Println("nil")
		} else {
			fmt.Printf("%q\n", err.Error())
		}
	}
}

// ---------------------------------------------------------------- fstest

type fsFile struct {
	Name string `json:"name"`
	Data string `json:"data"` // hex
	Mode uint32 `json:"mode"`
	Link bool   `json:"link"`
	Dir  bool   `json:"dir"`
}

type fsCase struct {
	Files    []fsFile `json:"files"`
	Corrupt  string   `json:"corrupt"`
	Expected []string `json:"expected"`
}

// corrupt wraps a MapFS with a misbehaviour selected by kind; the same kinds
// are implemented in examples/testing_probe.rs.
type corruptFS struct {
	m    fstest.MapFS
	kind string
	opens map[string]int
}

func (c *corruptFS) Open(name string) (fs.File, error) {
	f, err := c.m.Open(name)
	if err != nil {
		return nil, err
	}
	if c.kind == "openroot" && name == "." {
		return f, nil
	}
	return c.wrap(name, f), nil
}

type badFile struct {
	fs.File
	c    *corruptFS
	name string
}

func (c *corruptFS) wrap(name string, f fs.File) fs.File { return &badFile{f, c, name} }

func (b *badFile) Stat() (fs.FileInfo, error) {
	info, err := b.File.Stat()
	if err != nil {
		return nil, err
	}
	if b.c.kind == "wrongsize" && !info.IsDir() {
		return sizeInfo{info}, nil
	}
	return info, nil
}

type sizeInfo struct{ fs.FileInfo }

func (s sizeInfo) Size() int64 { return s.FileInfo.Size() + 1 }

func (b *badFile) ReadDir(n int) ([]fs.DirEntry, error) {
	rd, ok := b.File.(fs.ReadDirFile)
	if !ok {
		return nil, errors.New("not a directory")
	}
	list, err := rd.ReadDir(n)
	if err != nil {
		return list, err
	}
	switch b.c.kind {
	case "dropentry":
		if len(list) > 1 && n <= 0 {
			b.c.opens[b.name]++
			if b.c.opens[b.name] == 2 {
				list = list[1:]
			}
		}
	case "dupentry":
		if len(list) > 0 && n <= 0 {
			list = append(list, list[0])
		}
	case "badname":
		if len(list) > 0 && n <= 0 {
			list = append([]fs.DirEntry{renamed{list[0]}}, list[1:]...)
		}
	}
	return list, nil
}

type renamed struct{ fs.DirEntry }

func (r renamed) Name() string { return r.DirEntry.Name() + "x" }

func (c *corruptFS) ReadFile(name string) ([]byte, error) {
	if c.kind == "readfile" {
		data, err := fs.ReadFile(c.m, name)
		if len(data) > 0 {
			data = append([]byte{}, data...)
			data[0] ^= 1
		}
		return data, err
	}
	return fs.ReadFile(c.m, name)
}

func (c *corruptFS) ReadDir(name string) ([]fs.DirEntry, error) {
	list, err := fs.ReadDir(c.m, name)
	if c.kind == "unsorted" && len(list) > 1 {
		out := append([]fs.DirEntry{}, list...)
		out[0], out[1] = out[1], out[0]
		return out, err
	}
	return list, err
}

func (c *corruptFS) Glob(pattern string) ([]string, error) {
	names, err := fs.Glob(c.m, pattern)
	if c.kind == "badglob" && len(names) > 0 {
		names = append(names, names[0]+"x")
	}
	if c.kind == "globnoerr" && strings.Contains(pattern, "[]") {
		return nil, nil
	}
	return names, err
}

type plainOpenFS struct{ c *corruptFS }

func (p plainOpenFS) Open(name string) (fs.File, error) {
	if strings.HasPrefix(name, "/") {
		f, err := p.c.m.Open(strings.TrimPrefix(name, "/"))
		return f, err
	}
	return p.c.Open(name)
}

func buildMap(files []fsFile) fstest.MapFS {
	m := fstest.MapFS{}
	for _, f := range files {
		data, _ := hex.DecodeString(f.Data)
		mode := fs.FileMode(f.Mode)
		if f.Dir {
			mode |= fs.ModeDir
		}
		if f.Link {
			mode |= fs.ModeSymlink
		}
		m[f.Name] = &fstest.MapFile{Data: data, Mode: mode}
	}
	return m
}

func normalizeFsErr(s string) string {
	s = regexp.MustCompile(`File type \S+,`).ReplaceAllString(s, "File type T,")
	return s
}

func runFstest() {
	var cases []fsCase
	readInput(&cases)
	for _, c := range cases {
		m := buildMap(c.Files)
		cfs := &corruptFS{m: m, kind: c.Corrupt, opens: map[string]int{}}
		var err error
		switch c.Corrupt {
		case "none":
			err = fstest.TestFS(m, c.Expected...)
		case "openbad":
			err = fstest.TestFS(plainOpenFS{cfs}, c.Expected...)
		default:
			err = fstest.TestFS(cfs, c.Expected...)
		}
		if err == nil {
			fmt.Println("nil")
		} else {
			fmt.Printf("%q\n", normalizeFsErr(err.Error()))
		}
	}
}

// ---------------------------------------------------------------- quick

type quickCase struct {
	Kind string `json:"kind"`
	Seed int64  `json:"seed"`
	N    int    `json:"n"`
}

func fmtVal(v any) string {
	switch x := v.(type) {
	case float32:
		return fmt.Sprintf("f32:%08x", math.Float32bits(x))
	case float64:
		return fmt.Sprintf("f64:%016x", math.Float64bits(x))
	case string:
		return fmt.Sprintf("s:%x", x)
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		var parts []string
		for i := 0; i < rv.Len(); i++ {
			parts = append(parts, fmtVal(rv.Index(i).Interface()))
		}
		return "[" + strings.Join(parts, ",") + "]"
	case reflect.Struct:
		var parts []string
		for i := 0; i < rv.NumField(); i++ {
			parts = append(parts, fmtVal(rv.Field(i).Interface()))
		}
		return strings.Join(parts, ",")
	case reflect.Pointer:
		if rv.IsNil() {
			return "nil"
		}
		return "&" + fmtVal(rv.Elem().Interface())
	case reflect.Map:
		var parts []string
		for _, k := range rv.MapKeys() {
			parts = append(parts, fmtVal(k.Interface())+"="+fmtVal(rv.MapIndex(k).Interface()))
		}
		sort.Strings(parts)
		return "{" + strings.Join(parts, ",") + "}"
	}
	return fmt.Sprintf("%T:%v", v, v)
}

func genKind(kind string, r *rand.Rand) any {
	var t reflect.Type
	switch kind {
	case "int8":
		t = reflect.TypeOf(int8(0))
	case "int16":
		t = reflect.TypeOf(int16(0))
	case "int32":
		t = reflect.TypeOf(int32(0))
	case "int64":
		t = reflect.TypeOf(int64(0))
	case "int":
		t = reflect.TypeOf(int(0))
	case "uint8":
		t = reflect.TypeOf(uint8(0))
	case "uint16":
		t = reflect.TypeOf(uint16(0))
	case "uint32":
		t = reflect.TypeOf(uint32(0))
	case "uint64":
		t = reflect.TypeOf(uint64(0))
	case "uint":
		t = reflect.TypeOf(uint(0))
	case "bool":
		t = reflect.TypeOf(false)
	case "float32":
		t = reflect.TypeOf(float32(0))
	case "float64":
		t = reflect.TypeOf(float64(0))
	case "string":
		t = reflect.TypeOf("")
	case "slice_i16":
		t = reflect.TypeOf([]int16{})
	case "array_u8":
		t = reflect.TypeOf([4]uint8{})
	case "ptr_i32":
		t = reflect.TypeOf((*int32)(nil))
	case "map_u8_string":
		t = reflect.TypeOf(map[uint8]string{})
	case "nested":
		t = reflect.TypeOf([][]string{})
	case "tuple3":
		t = reflect.TypeOf(struct {
			A int8
			B string
			C []bool
		}{})
	}
	v, ok := quick.Value(t, r)
	if !ok {
		return "!ok"
	}
	return v.Interface()
}

func runQuick() {
	var cases []quickCase
	readInput(&cases)
	for _, c := range cases {
		r := rand.New(rand.NewSource(c.Seed))
		var parts []string
		switch c.Kind {
		case "check_fail_i8":
			err := quick.Check(func(x int8) bool { return x != 17 && x != -3 }, &quick.Config{Rand: r, MaxCount: c.N})
			parts = append(parts, errText(err))
		case "check_ok_i16":
			err := quick.Check(func(x, y int16) bool { return int32(x)+int32(y) == int32(y)+int32(x) }, &quick.Config{Rand: r, MaxCount: c.N})
			parts = append(parts, errText(err))
		case "check_fail_bool":
			err := quick.Check(func(a, b bool, c uint8) bool { return a || b || c > 3 }, &quick.Config{Rand: r, MaxCount: c.N})
			parts = append(parts, errText(err))
		case "equal_fail":
			err := quick.CheckEqual(func(x int8) int8 { return x * 2 }, func(x int8) int8 {
				if x == 77 {
					return 0
				}
				return x + x
			}, &quick.Config{Rand: r, MaxCount: c.N})
			parts = append(parts, errText(err))
		case "equal_ok":
			err := quick.CheckEqual(func(x uint16) uint16 { return x &^ 1 }, func(x uint16) uint16 { return x & 0xfffe }, &quick.Config{Rand: r, MaxCount: c.N})
			parts = append(parts, errText(err))
		default:
			for i := 0; i < c.N; i++ {
				parts = append(parts, fmtVal(genKind(c.Kind, r)))
			}
		}
		fmt.Println(strings.Join(parts, ";"))
	}
}

func errText(err error) string {
	if err == nil {
		return "nil"
	}
	var ce *quick.CheckError
	if errors.As(err, &ce) {
		return fmt.Sprintf("check:%d:%v", ce.Count, ce.In)
	}
	var ee *quick.CheckEqualError
	if errors.As(err, &ee) {
		return fmt.Sprintf("equal:%d:%v:%v:%v", ee.Count, ee.In, ee.Out1, ee.Out2)
	}
	return "other:" + err.Error()
}

// ---------------------------------------------------------------- slogtest

type slogCase struct {
	Transform string `json:"transform"`
	Key       string `json:"key"`
	Key2      string `json:"key2"`
	Format    string `json:"format"`
}

func replaceFor(c slogCase) func([]string, slog.Attr) slog.Attr {
	return func(groups []string, a slog.Attr) slog.Attr {
		switch c.Transform {
		case "drop":
			if a.Key == c.Key {
				return slog.Attr{}
			}
		case "rename":
			if a.Key == c.Key {
				a.Key = c.Key2
			}
		case "setvalue":
			if a.Key == c.Key {
				a.Value = slog.StringValue("zzz")
			}
		case "dropgroup":
			if len(groups) > 0 {
				return slog.Attr{}
			}
		}
		return a
	}
}

func runSlogtest() {
	var cases []slogCase
	readInput(&cases)
	for _, c := range cases {
		var buf bytes.Buffer
		opts := &slog.HandlerOptions{ReplaceAttr: replaceFor(c)}
		h := slog.NewJSONHandler(&buf, opts)
		err := slogtest.TestHandler(h, func() []map[string]any {
			var ms []map[string]any
			dec := json.NewDecoder(&buf)
			for {
				var m map[string]any
				if err := dec.Decode(&m); err != nil {
					if err != io.EOF {
						panic(err)
					}
					break
				}
				ms = append(ms, m)
			}
			return ms
		})
		if err == nil {
			fmt.Println("nil")
		} else {
			s := regexp.MustCompile(` \([^()]*:\d+\)`).ReplaceAllString(err.Error(), "")
			fmt.Printf("%q\n", s)
		}
	}
}

// ---------------------------------------------------------------- synctest

type syncOp struct {
	Op string `json:"op"`
	Ms int64  `json:"ms"`
	Ch int    `json:"ch"`
	V  int    `json:"v"`
	Ops []syncOp `json:"ops"`
	Tag string `json:"tag"`
}

type syncCase struct {
	Ops []syncOp `json:"ops"`
}

func runSyncOps(trace func(string), start time.Time, chans []chan int, ops []syncOp) {
	for _, op := range ops {
		switch op.Op {
		case "sleep":
			time.Sleep(time.Duration(op.Ms) * time.Millisecond)
		case "wait":
			synctest.Wait()
		case "ssleep":
			synctest.Sleep(time.Duration(op.Ms) * time.Millisecond)
		case "now":
			trace(fmt.Sprintf("%s now=%d", op.Tag, time.Since(start).Milliseconds()))
		case "send":
			chans[op.Ch] <- op.V
		case "recv":
			v := <-chans[op.Ch]
			trace(fmt.Sprintf("%s recv ch%d=%d at %d", op.Tag, op.Ch, v, time.Since(start).Milliseconds()))
		case "go":
			ops := op.Ops
			go func() { runSyncOps(trace, start, chans, ops) }()
		case "stamp":
			trace(fmt.Sprintf("%s stamp %d", op.Tag, time.Since(start).Milliseconds()))
		}
	}
}

func runSynctest() {
	var cases []syncCase
	readInput(&cases)
	tests := []testing.InternalTest{}
	results := make([][]string, len(cases))
	for i := range cases {
		i := i
		tests = append(tests, testing.InternalTest{Name: fmt.Sprintf("C%d", i), F: func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()
				var mu chan struct{} = make(chan struct{}, 1)
				mu <- struct{}{}
				trace := func(s string) {
					<-mu
					results[i] = append(results[i], s)
					mu <- struct{}{}
				}
				chans := make([]chan int, 4)
				for k := range chans {
					chans[k] = make(chan int, 64)
				}
				trace(fmt.Sprintf("start %s", start.UTC().Format(time.RFC3339)))
				runSyncOps(trace, start, chans, cases[i].Ops)
			})
		}})
	}
	ctx := context.Background()
	_ = ctx
	// testing.Main exits the process, so the traces are printed by a last test.
	tests = append(tests, testing.InternalTest{Name: "Zprint", F: func(t *testing.T) {
		for _, r := range results {
			fmt.Println("R:" + strings.Join(r, ";"))
		}
	}})
	_ = flag.Parse
	testing.Main(matchString, tests, nil, nil)
}
