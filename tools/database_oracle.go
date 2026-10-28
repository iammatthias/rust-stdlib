// Go oracle for tools/database_check.py: Scan conversions
// (sql.ConvertAssign), driver value converters and scripted pool and
// transaction sequences against the fake driver in database_fakedb.go.
//
// Run as: go run tools/database_oracle.go tools/database_fakedb.go
// Requests arrive one per line on stdin; examples/database_probe.rs answers
// the same protocol.
package main

import (
	"bufio"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
	"uuid"
)

var plainDriver = &fakeDriver{}
var ctxDriver = &fakeDriverCtx{}

func init() {
	sql.Register("test", plainDriver)
	sql.Register("testctx", ctxDriver)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	must(err)
	return b
}

func fmtFloat(f float64, bits int) string {
	return strconv.FormatFloat(f, 'g', -1, bits)
}

func parseTime(spec string) time.Time {
	if spec == "zero" {
		return time.Time{}
	}
	parts := strings.Split(spec, ":")
	sec, err := strconv.ParseInt(parts[0], 10, 64)
	must(err)
	nsec, err := strconv.ParseInt(parts[1], 10, 64)
	must(err)
	off, err := strconv.Atoi(parts[2])
	must(err)
	return time.Unix(sec, nsec).In(time.FixedZone("X", off))
}

// dec is a decimal with Go's decimalDecompose and decimalCompose methods.
// String prints the General Decimal Arithmetic to-scientific-string, the
// text driver::Decimal displays as.
type dec struct {
	form byte
	neg  bool
	coef []byte
	exp  int32
}

func (d dec) Decompose([]byte) (byte, bool, []byte, int32) {
	return d.form, d.neg, d.coef, d.exp
}

func (d *dec) Compose(form byte, neg bool, coef []byte, exp int32) error {
	d.form, d.neg, d.coef, d.exp = form, neg, append([]byte{}, coef...), exp
	return nil
}

func (d dec) String() string {
	sign := ""
	if d.neg {
		sign = "-"
	}
	switch d.form {
	case 1:
		return sign + "Infinity"
	case 2:
		return sign + "NaN"
	}
	digits := new(big.Int).SetBytes(d.coef).String()
	exp := int64(d.exp)
	adjusted := exp + int64(len(digits)) - 1
	if exp <= 0 && adjusted >= -6 {
		point := int64(len(digits)) + exp
		switch {
		case exp == 0:
			return sign + digits
		case point > 0:
			return sign + digits[:point] + "." + digits[point:]
		default:
			return sign + "0." + strings.Repeat("0", int(-point)) + digits
		}
	}
	out := sign + digits[:1]
	if len(digits) > 1 {
		out += "." + digits[1:]
	}
	if adjusted >= 0 {
		return out + "E+" + strconv.FormatInt(adjusted, 10)
	}
	return out + "E" + strconv.FormatInt(adjusted, 10)
}

// parseDec reads form:neg:coefhex:exp.
func parseDec(spec string) dec {
	p := strings.Split(spec, ":")
	form, err := strconv.ParseUint(p[0], 10, 8)
	must(err)
	neg, err := strconv.ParseBool(p[1])
	must(err)
	exp, err := strconv.ParseInt(p[3], 10, 32)
	must(err)
	return dec{byte(form), neg, unhex(p[2]), int32(exp)}
}

type decomposer interface {
	Decompose([]byte) (byte, bool, []byte, int32)
}

func showDec(d decomposer) string {
	form, neg, coef, exp := d.Decompose(nil)
	return fmt.Sprintf("dec:%d:%t:%s:%d", form, neg, hex.EncodeToString(coef), exp)
}

// parseSrc builds a driver.Value from its token.
func parseSrc(tok string) any {
	if tok == "nil" {
		return nil
	}
	kind, rest, _ := strings.Cut(tok, ":")
	switch kind {
	case "i":
		v, err := strconv.ParseInt(rest, 10, 64)
		must(err)
		return v
	case "f":
		v, err := strconv.ParseFloat(rest, 64)
		must(err)
		return v
	case "b":
		return unhex(rest)
	case "s":
		return string(unhex(rest))
	case "B":
		v, err := strconv.ParseBool(rest)
		must(err)
		return v
	case "t":
		return parseTime(rest)
	case "d":
		return parseDec(rest)
	}
	panic("bad value token " + tok)
}

func showAny(v any) string {
	switch x := v.(type) {
	case nil:
		return "nil"
	case int64:
		return fmt.Sprintf("i64:%d", x)
	case float64:
		return "f64:" + fmtFloat(x, 64)
	case bool:
		return fmt.Sprintf("bool:%t", x)
	case []byte:
		return "bytes:" + hex.EncodeToString(x)
	case string:
		return "str:" + hex.EncodeToString([]byte(x))
	case time.Time:
		return "time:" + x.Format(time.RFC3339Nano)
	case decomposer:
		// A driver sees a *dec as the decimal it decomposes into.
		return showDec(x)
	}
	return fmt.Sprintf("other:%T", v)
}

type dest struct {
	ptr  any
	show func() string
}

func showStr(s string) string { return "str:" + hex.EncodeToString([]byte(s)) }
func showBytes(b []byte) string {
	return "bytes:" + hex.EncodeToString(b)
}
func showTime(t time.Time) string { return "time:" + t.Format(time.RFC3339Nano) }

var sentinelTime = time.Unix(1000, 0).UTC()

func nullShow[T any](valid bool, v T, show func(T) string) string {
	return fmt.Sprintf("valid=%t v=%s", valid, show(v))
}

func newDest(kind string) dest {
	if rest, ok := strings.CutPrefix(kind, "p:"); ok {
		switch rest {
		case "i64":
			v := new(int64)
			*v = 77
			p := v
			return dest{&p, func() string {
				if p == nil {
					return "nil"
				}
				return fmt.Sprintf("&i:%d", *p)
			}}
		case "string":
			v := new(string)
			*v = "init"
			p := v
			return dest{&p, func() string {
				if p == nil {
					return "nil"
				}
				return "&" + showStr(*p)
			}}
		case "bytes":
			v := new([]byte)
			*v = []byte("init")
			p := v
			return dest{&p, func() string {
				if p == nil {
					return "nil"
				}
				return "&" + showBytes(*p)
			}}
		case "time":
			v := new(time.Time)
			*v = sentinelTime
			p := v
			return dest{&p, func() string {
				if p == nil {
					return "nil"
				}
				return "&" + showTime(*p)
			}}
		case "bool":
			v := new(bool)
			*v = true
			p := v
			return dest{&p, func() string {
				if p == nil {
					return "nil"
				}
				return fmt.Sprintf("&bool:%t", *p)
			}}
		case "f64":
			v := new(float64)
			*v = 7.5
			p := v
			return dest{&p, func() string {
				if p == nil {
					return "nil"
				}
				return "&f64:" + fmtFloat(*p, 64)
			}}
		case "ns":
			v := &sql.NullString{String: "init", Valid: true}
			p := v
			return dest{&p, func() string {
				if p == nil {
					return "nil"
				}
				return "&" + nullShow(p.Valid, p.String, showStr)
			}}
		}
		panic("bad pointer dest " + kind)
	}
	if rest, ok := strings.CutPrefix(kind, "N:"); ok {
		switch rest {
		case "i64":
			n := &sql.Null[int64]{V: 77, Valid: true}
			return dest{n, func() string { return nullShow(n.Valid, n.V, func(v int64) string { return fmt.Sprintf("i:%d", v) }) }}
		case "string":
			n := &sql.Null[string]{V: "init", Valid: true}
			return dest{n, func() string { return nullShow(n.Valid, n.V, showStr) }}
		case "bytes":
			n := &sql.Null[[]byte]{V: []byte("init"), Valid: true}
			return dest{n, func() string { return nullShow(n.Valid, n.V, showBytes) }}
		case "time":
			n := &sql.Null[time.Time]{V: sentinelTime, Valid: true}
			return dest{n, func() string { return nullShow(n.Valid, n.V, showTime) }}
		case "bool":
			n := &sql.Null[bool]{V: true, Valid: true}
			return dest{n, func() string { return nullShow(n.Valid, n.V, func(v bool) string { return fmt.Sprintf("bool:%t", v) }) }}
		case "f64":
			n := &sql.Null[float64]{V: 7.5, Valid: true}
			return dest{n, func() string { return nullShow(n.Valid, n.V, func(v float64) string { return "f64:" + fmtFloat(v, 64) }) }}
		case "u8":
			n := &sql.Null[uint8]{V: 77, Valid: true}
			return dest{n, func() string { return nullShow(n.Valid, n.V, func(v uint8) string { return fmt.Sprintf("u:%d", v) }) }}
		case "any":
			n := &sql.Null[any]{V: "init", Valid: true}
			return dest{n, func() string { return nullShow(n.Valid, n.V, showAny) }}
		}
		panic("bad Null dest " + kind)
	}
	switch kind {
	case "string":
		v := "init"
		return dest{&v, func() string { return showStr(v) }}
	case "bytes":
		v := []byte("init")
		return dest{&v, func() string { return showBytes(v) }}
	case "raw":
		v := sql.RawBytes("init")
		return dest{&v, func() string { return "raw:" + hex.EncodeToString(v) }}
	case "bool":
		v := true
		return dest{&v, func() string { return fmt.Sprintf("bool:%t", v) }}
	case "any":
		var v any = "init"
		return dest{&v, func() string { return showAny(v) }}
	case "time":
		v := sentinelTime
		return dest{&v, func() string { return showTime(v) }}
	case "dec":
		v := dec{2, true, []byte{9}, 9}
		return dest{&v, func() string { return showDec(v) }}
	case "i8":
		v := int8(77)
		return dest{&v, func() string { return fmt.Sprintf("i:%d", v) }}
	case "i16":
		v := int16(77)
		return dest{&v, func() string { return fmt.Sprintf("i:%d", v) }}
	case "i32":
		v := int32(77)
		return dest{&v, func() string { return fmt.Sprintf("i:%d", v) }}
	case "i64":
		v := int64(77)
		return dest{&v, func() string { return fmt.Sprintf("i:%d", v) }}
	case "int":
		v := int(77)
		return dest{&v, func() string { return fmt.Sprintf("i:%d", v) }}
	case "u8":
		v := uint8(77)
		return dest{&v, func() string { return fmt.Sprintf("u:%d", v) }}
	case "u16":
		v := uint16(77)
		return dest{&v, func() string { return fmt.Sprintf("u:%d", v) }}
	case "u32":
		v := uint32(77)
		return dest{&v, func() string { return fmt.Sprintf("u:%d", v) }}
	case "u64":
		v := uint64(77)
		return dest{&v, func() string { return fmt.Sprintf("u:%d", v) }}
	case "uint":
		v := uint(77)
		return dest{&v, func() string { return fmt.Sprintf("u:%d", v) }}
	case "f32":
		v := float32(7.5)
		return dest{&v, func() string { return "f32:" + fmtFloat(float64(v), 32) }}
	case "f64":
		v := 7.5
		return dest{&v, func() string { return "f64:" + fmtFloat(v, 64) }}
	case "ns":
		n := &sql.NullString{String: "init", Valid: true}
		return dest{n, func() string { return nullShow(n.Valid, n.String, showStr) }}
	case "ni64":
		n := &sql.NullInt64{Int64: 77, Valid: true}
		return dest{n, func() string { return nullShow(n.Valid, n.Int64, func(v int64) string { return fmt.Sprintf("i:%d", v) }) }}
	case "ni32":
		n := &sql.NullInt32{Int32: 77, Valid: true}
		return dest{n, func() string { return nullShow(n.Valid, n.Int32, func(v int32) string { return fmt.Sprintf("i:%d", v) }) }}
	case "ni16":
		n := &sql.NullInt16{Int16: 77, Valid: true}
		return dest{n, func() string { return nullShow(n.Valid, n.Int16, func(v int16) string { return fmt.Sprintf("i:%d", v) }) }}
	case "nbyte":
		n := &sql.NullByte{Byte: 77, Valid: true}
		return dest{n, func() string { return nullShow(n.Valid, n.Byte, func(v byte) string { return fmt.Sprintf("u:%d", v) }) }}
	case "nf64":
		n := &sql.NullFloat64{Float64: 7.5, Valid: true}
		return dest{n, func() string { return nullShow(n.Valid, n.Float64, func(v float64) string { return "f64:" + fmtFloat(v, 64) }) }}
	case "nbool":
		n := &sql.NullBool{Bool: true, Valid: true}
		return dest{n, func() string { return nullShow(n.Valid, n.Bool, func(v bool) string { return fmt.Sprintf("bool:%t", v) }) }}
	case "ntime":
		n := &sql.NullTime{Time: sentinelTime, Valid: true}
		return dest{n, func() string { return nullShow(n.Valid, n.Time, showTime) }}
	}
	panic("bad dest " + kind)
}

func newDests(spec string) []dest {
	if spec == "-" {
		return nil
	}
	var out []dest
	for _, k := range strings.Split(spec, ",") {
		out = append(out, newDest(k))
	}
	return out
}

func ptrs(ds []dest) []any {
	out := make([]any, len(ds))
	for i, d := range ds {
		out[i] = d.ptr
	}
	return out
}

func shows(ds []dest) string {
	out := make([]string, len(ds))
	for i, d := range ds {
		out[i] = d.show()
	}
	return strings.Join(out, ";")
}

func errText(err error) string {
	return "err " + err.Error()
}

// ----------------------------------------------------------- C: conversions

func convertRequest(f []string) string {
	src := parseSrc(f[1])
	d := newDest(f[2])
	err := sql.ConvertAssign(driver.ScanContext{}, d.ptr, src)
	if err != nil {
		return errText(err) + " | " + d.show()
	}
	return "ok " + d.show()
}

// ------------------------------------------------------------ V: converters

type userValuer struct {
	v   any
	err error
}

func (u userValuer) Value() (driver.Value, error) { return u.v, u.err }

func parseArg(tok string) any {
	if tok == "nil" {
		return nil
	}
	kind, rest, _ := strings.Cut(tok, ":")
	switch kind {
	case "bool":
		v, err := strconv.ParseBool(rest)
		must(err)
		return v
	case "int":
		v, err := strconv.ParseInt(rest, 10, 64)
		must(err)
		return int(v)
	case "i8":
		v, err := strconv.ParseInt(rest, 10, 8)
		must(err)
		return int8(v)
	case "i16":
		v, err := strconv.ParseInt(rest, 10, 16)
		must(err)
		return int16(v)
	case "i32":
		v, err := strconv.ParseInt(rest, 10, 32)
		must(err)
		return int32(v)
	case "i64":
		v, err := strconv.ParseInt(rest, 10, 64)
		must(err)
		return v
	case "uint":
		v, err := strconv.ParseUint(rest, 10, 64)
		must(err)
		return uint(v)
	case "u8":
		v, err := strconv.ParseUint(rest, 10, 8)
		must(err)
		return uint8(v)
	case "u16":
		v, err := strconv.ParseUint(rest, 10, 16)
		must(err)
		return uint16(v)
	case "u32":
		v, err := strconv.ParseUint(rest, 10, 32)
		must(err)
		return uint32(v)
	case "u64":
		v, err := strconv.ParseUint(rest, 10, 64)
		must(err)
		return v
	case "f32":
		v, err := strconv.ParseFloat(rest, 32)
		must(err)
		return float32(v)
	case "f64":
		v, err := strconv.ParseFloat(rest, 64)
		must(err)
		return v
	case "str":
		return string(unhex(rest))
	case "bytes":
		return unhex(rest)
	case "time":
		return parseTime(rest)
	case "ptrnil":
		return (*int)(nil)
	case "ptr":
		v, err := strconv.ParseInt(rest, 10, 64)
		must(err)
		x := int(v)
		return &x
	case "slice":
		if rest == "int" {
			return []int{1, 2}
		}
		return []string{"a"}
	case "struct":
		return struct{ A int }{1}
	case "map":
		return map[string]int{}
	case "func":
		return func() {}
	case "complex":
		return complex(1, 2)
	case "uintptr":
		return uintptr(5)
	case "array":
		return [2]int{1, 2}
	case "ns":
		if rest == "null" {
			return sql.NullString{}
		}
		return sql.NullString{String: string(unhex(rest)), Valid: true}
	case "ni":
		if rest == "null" {
			return sql.NullInt64{}
		}
		v, err := strconv.ParseInt(rest, 10, 64)
		must(err)
		return sql.NullInt64{Int64: v, Valid: true}
	case "valuererr":
		return userValuer{err: errors.New("boom")}
	case "valuernil":
		return userValuer{}
	case "valuerstr":
		return userValuer{v: "v"}
	case "dec":
		return parseDec(rest)
	case "ptrdec":
		d := parseDec(rest)
		return &d
	case "uuid":
		var u uuid.UUID
		copy(u[:], unhex(rest))
		return u
	case "ptruuid":
		var u uuid.UUID
		copy(u[:], unhex(rest))
		return &u
	}
	panic("bad arg token " + tok)
}

func converterByName(name string) driver.ValueConverter {
	if rest, ok := strings.CutPrefix(name, "null:"); ok {
		return driver.Null{Converter: converterByName(rest)}
	}
	if rest, ok := strings.CutPrefix(name, "notnull:"); ok {
		return driver.NotNull{Converter: converterByName(rest)}
	}
	switch name {
	case "default":
		return driver.DefaultParameterConverter
	case "bool":
		return driver.Bool
	case "int32":
		return driver.Int32
	case "string":
		return driver.String
	}
	panic("bad converter " + name)
}

func converterRequest(f []string) string {
	arg := parseArg(f[2])
	if f[1] == "isvalue" {
		return fmt.Sprintf("bool:%t", driver.IsValue(arg))
	}
	v, err := converterByName(f[1]).ConvertValue(arg)
	if err != nil {
		return errText(err)
	}
	return "ok " + showAny(v)
}

// ---------------------------------------------------------------- scripts

type script struct {
	driverFor *fakeDriver
	db        *sql.DB
	conns     [4]*sql.Conn
	txs       [4]*sql.Tx
	txOwner   [4]string
	stmts     [4]*sql.Stmt
	stmtBound [4]bool
	stmtOwner [4]string
	rows      [4]*sql.Rows
	rowOwner  [4]string
	openBase  int
	closeBase int
}

func slot(tok string, prefix byte) int {
	if len(tok) != 2 || tok[0] != prefix || tok[1] < '0' || tok[1] > '3' {
		panic("bad slot " + tok)
	}
	return int(tok[1] - '0')
}

func parseArgs(toks []string) []any {
	out := make([]any, len(toks))
	for i, t := range toks {
		kind, rest, _ := strings.Cut(t, ":")
		switch {
		case t == "n":
			out[i] = nil
		case kind == "i":
			v, err := strconv.ParseInt(rest, 10, 64)
			must(err)
			out[i] = v
		case kind == "i32":
			v, err := strconv.ParseInt(rest, 10, 32)
			must(err)
			out[i] = int32(v)
		case kind == "f":
			v, err := strconv.ParseFloat(rest, 64)
			must(err)
			out[i] = v
		case kind == "s":
			out[i] = rest
		case kind == "b":
			out[i] = unhex(rest)
		case kind == "B":
			v, err := strconv.ParseBool(rest)
			must(err)
			out[i] = v
		case kind == "t":
			sec, err := strconv.ParseInt(rest, 10, 64)
			must(err)
			out[i] = time.Unix(sec, 0).UTC()
		case kind == "ns":
			if rest == "null" {
				out[i] = sql.NullString{}
			} else {
				out[i] = sql.NullString{String: rest, Valid: true}
			}
		case kind == "named":
			name, val, _ := strings.Cut(rest, "=")
			out[i] = sql.Named(name, parseArgs([]string{val})[0])
		default:
			panic("bad arg " + t)
		}
	}
	return out
}

func resultText(res sql.Result, err error) string {
	if err != nil {
		return errText(err)
	}
	id, idErr := res.LastInsertId()
	n, nErr := res.RowsAffected()
	var a, b string
	if idErr != nil {
		a = "err:" + idErr.Error()
	} else {
		a = strconv.FormatInt(id, 10)
	}
	if nErr != nil {
		b = "err:" + nErr.Error()
	} else {
		b = strconv.FormatInt(n, 10)
	}
	return "ok li=" + a + " ra=" + b
}

func (s *script) poolExhausted() bool {
	st := s.db.Stats()
	return st.MaxOpenConnections > 0 && st.OpenConnections >= st.MaxOpenConnections && st.Idle == 0
}

// ctxFor returns the context for an operation. Operations that need a
// connection from an exhausted pool get a short deadline instead of blocking
// the script forever.
func (s *script) ctxFor(cancelled, needsPool bool) (context.Context, context.CancelFunc) {
	if cancelled {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx, func() {}
	}
	if needsPool && s.db != nil && s.poolExhausted() {
		return context.WithTimeout(context.Background(), poolWait)
	}
	return context.Background(), func() {}
}

type queryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	PrepareContext(ctx context.Context, query string) (*sql.Stmt, error)
}

// target resolves "d", "cN" or "tN"; ok is false for an empty slot.
func (s *script) target(tok string) (q queryer, needsPool bool, ok bool) {
	switch tok[0] {
	case 'd':
		return s.db, true, s.db != nil
	case 'c':
		c := s.conns[slot(tok, 'c')]
		if c == nil {
			return nil, false, false
		}
		return c, false, true
	case 't':
		t := s.txs[slot(tok, 't')]
		if t == nil {
			return nil, false, false
		}
		return t, false, true
	}
	panic("bad target " + tok)
}

func (s *script) closeOwnedRows(owner string) {
	for i, r := range s.rows {
		if r != nil && s.rowOwner[i] == owner {
			r.Close()
		}
	}
}

func (s *script) run(line string) string {
	f := strings.Fields(line)
	cancelled := false
	if f[0] == "@cancelled" {
		cancelled = true
		f = f[1:]
	}
	cmd := f[0]
	if s.db == nil && cmd != "open" {
		return "skip nodb"
	}
	switch cmd {
	case "open":
		d := plainDriver
		if f[1] == "testctx" {
			d = &ctxDriver.fakeDriver
		}
		db, err := sql.Open(f[1], f[2])
		if err != nil {
			return errText(err)
		}
		s.db = db
		s.driverFor = d
		s.openBase, s.closeBase = d.openCount, d.closeCount
		return "ok"
	case "maxopen":
		n, _ := strconv.Atoi(f[1])
		s.db.SetMaxOpenConns(n)
		return "ok"
	case "maxidle":
		n, _ := strconv.Atoi(f[1])
		s.db.SetMaxIdleConns(n)
		return "ok"
	case "stats":
		st := s.db.Stats()
		return fmt.Sprintf("ok max=%d open=%d inuse=%d idle=%d wait=%d idleclosed=%d idletimeclosed=%d lifetimeclosed=%d",
			st.MaxOpenConnections, st.OpenConnections, st.InUse, st.Idle, st.WaitCount,
			st.MaxIdleClosed, st.MaxIdleTimeClosed, st.MaxLifetimeClosed)
	case "fake":
		return fmt.Sprintf("ok open=%d close=%d", s.driverFor.openCount-s.openBase, s.driverFor.closeCount-s.closeBase)
	case "dbclose":
		if err := s.db.Close(); err != nil {
			return errText(err)
		}
		return "ok"
	case "exec":
		q, needs, ok := s.target(f[1])
		if !ok {
			return "skip"
		}
		ctx, cancel := s.ctxFor(cancelled, needs)
		defer cancel()
		return resultText(q.ExecContext(ctx, f[2], parseArgs(f[3:])...))
	case "query":
		q, needs, ok := s.target(f[1])
		if !ok {
			return "skip"
		}
		i := slot(f[2], 'r')
		if s.rows[i] != nil {
			return "skip busy"
		}
		ctx, cancel := s.ctxFor(cancelled, needs)
		defer cancel()
		rows, err := q.QueryContext(ctx, f[3], parseArgs(f[4:])...)
		if err != nil {
			return errText(err)
		}
		s.rows[i] = rows
		s.rowOwner[i] = f[1]
		return "ok"
	case "queryrow":
		q, needs, ok := s.target(f[1])
		if !ok {
			return "skip"
		}
		ctx, cancel := s.ctxFor(cancelled, needs)
		defer cancel()
		ds := newDests(f[2])
		err := q.QueryRowContext(ctx, f[3], parseArgs(f[4:])...).Scan(ptrs(ds)...)
		if err != nil {
			return errText(err) + " | " + shows(ds)
		}
		return "ok " + shows(ds)
	case "next", "scan", "cols", "coltypes", "nextset", "rerr", "rclose":
		return s.rowsOp(cmd, f)
	case "begin":
		i := slot(f[2], 't')
		if s.txs[i] != nil {
			return "skip busy"
		}
		var opts *sql.TxOptions
		for _, o := range f[3:] {
			if opts == nil {
				opts = &sql.TxOptions{}
			}
			if o == "ro" {
				opts.ReadOnly = true
			} else if v, ok := strings.CutPrefix(o, "iso="); ok {
				n, _ := strconv.Atoi(v)
				opts.Isolation = sql.IsolationLevel(n)
			}
		}
		var tx *sql.Tx
		var err error
		if f[1] == "d" {
			ctx, cancel := s.ctxFor(cancelled, true)
			defer cancel()
			tx, err = s.db.BeginTx(ctx, opts)
		} else {
			c := s.conns[slot(f[1], 'c')]
			if c == nil {
				return "skip"
			}
			ctx, cancel := s.ctxFor(cancelled, false)
			defer cancel()
			tx, err = c.BeginTx(ctx, opts)
		}
		if err != nil {
			return errText(err)
		}
		s.txs[i] = tx
		s.txOwner[i] = f[1]
		return "ok"
	case "commit", "rollback":
		i := slot(f[1], 't')
		tx := s.txs[i]
		if tx == nil {
			return "skip"
		}
		var err error
		if cmd == "commit" {
			err = tx.Commit()
		} else {
			err = tx.Rollback()
		}
		if err != nil {
			return errText(err)
		}
		return "ok"
	case "prepare":
		q, needs, ok := s.target(f[1])
		if !ok {
			return "skip"
		}
		i := slot(f[2], 's')
		if s.stmts[i] != nil {
			return "skip busy"
		}
		ctx, cancel := s.ctxFor(cancelled, needs)
		defer cancel()
		st, err := q.PrepareContext(ctx, f[3])
		if err != nil {
			return errText(err)
		}
		s.stmts[i] = st
		s.stmtBound[i] = f[1][0] != 'd'
		s.stmtOwner[i] = f[1]
		return "ok"
	case "txstmt":
		t := s.txs[slot(f[1], 't')]
		src := s.stmts[slot(f[2], 's')]
		j := slot(f[3], 's')
		if t == nil || src == nil || s.stmts[j] != nil {
			return "skip"
		}
		s.stmts[j] = t.Stmt(src)
		s.stmtBound[j] = true
		s.stmtOwner[j] = f[1]
		return "ok"
	case "stmtexec", "stmtquery", "stmtqueryrow":
		return s.stmtOp(cmd, f, cancelled)
	case "stmtclose":
		i := slot(f[1], 's')
		st := s.stmts[i]
		if st == nil {
			return "skip"
		}
		err := st.Close()
		s.stmts[i] = nil
		if err != nil {
			return errText(err)
		}
		return "ok"
	case "conn":
		i := slot(f[1], 'c')
		if s.conns[i] != nil {
			return "skip busy"
		}
		ctx, cancel := s.ctxFor(false, true)
		defer cancel()
		c, err := s.db.Conn(ctx)
		if err != nil {
			return errText(err)
		}
		err = c.Raw(func(dc any) error {
			dc.(*fakeConn).skipDirtySession = true
			return nil
		})
		if err != nil {
			return errText(err)
		}
		s.conns[i] = c
		return "ok"
	case "stickybad":
		c := s.conns[slot(f[1], 'c')]
		if c == nil {
			return "skip"
		}
		err := c.Raw(func(dc any) error {
			dc.(*fakeConn).stickyBad = true
			return nil
		})
		if err != nil {
			return errText(err)
		}
		return "ok"
	case "connclose":
		i := slot(f[1], 'c')
		c := s.conns[i]
		if c == nil {
			return "skip"
		}
		s.closeOwnedRows(f[1])
		for j, t := range s.txs {
			if t != nil && s.txOwner[j] == f[1] {
				t.Rollback()
			}
		}
		err := c.Close()
		s.conns[i] = nil
		if err != nil {
			return errText(err)
		}
		return "ok"
	case "ping":
		var err error
		if f[1] == "d" {
			ctx, cancel := s.ctxFor(cancelled, true)
			defer cancel()
			err = s.db.PingContext(ctx)
		} else {
			c := s.conns[slot(f[1], 'c')]
			if c == nil {
				return "skip"
			}
			ctx, cancel := s.ctxFor(cancelled, false)
			defer cancel()
			err = c.PingContext(ctx)
		}
		if err != nil {
			return errText(err)
		}
		return "ok"
	}
	panic("bad command " + line)
}

func (s *script) rowsOp(cmd string, f []string) string {
	i := slot(f[1], 'r')
	r := s.rows[i]
	if r == nil {
		return "skip"
	}
	switch cmd {
	case "next":
		return fmt.Sprintf("ok %t", r.Next())
	case "scan":
		ds := newDests(f[2])
		if err := r.Scan(ptrs(ds)...); err != nil {
			return errText(err) + " | " + shows(ds)
		}
		return "ok " + shows(ds)
	case "cols":
		cols, err := r.Columns()
		if err != nil {
			return errText(err)
		}
		return "ok " + strings.Join(cols, ",")
	case "coltypes":
		cts, err := r.ColumnTypes()
		if err != nil {
			return errText(err)
		}
		var parts []string
		for _, ct := range cts {
			nullable, nok := ct.Nullable()
			length, lok := ct.Length()
			p, sc, dok := ct.DecimalSize()
			parts = append(parts, fmt.Sprintf("%s:%s:%s:%t/%t:%d/%t:%d,%d/%t", ct.Name(), ct.DatabaseTypeName(), ct.ScanType().String(), nullable, nok, length, lok, p, sc, dok))
		}
		return "ok " + strings.Join(parts, ";")
	case "nextset":
		return fmt.Sprintf("ok %t", r.NextResultSet())
	case "rerr":
		if err := r.Err(); err != nil {
			return errText(err)
		}
		return "ok"
	case "rclose":
		err := r.Close()
		s.rows[i] = nil
		if err != nil {
			return errText(err)
		}
		return "ok"
	}
	panic("unreachable")
}

func (s *script) stmtOp(cmd string, f []string, cancelled bool) string {
	i := slot(f[1], 's')
	st := s.stmts[i]
	if st == nil {
		return "skip"
	}
	ctx, cancel := s.ctxFor(cancelled, !s.stmtBound[i])
	defer cancel()
	switch cmd {
	case "stmtexec":
		return resultText(st.ExecContext(ctx, parseArgs(f[2:])...))
	case "stmtquery":
		j := slot(f[2], 'r')
		if s.rows[j] != nil {
			return "skip busy"
		}
		rows, err := st.QueryContext(ctx, parseArgs(f[3:])...)
		if err != nil {
			return errText(err)
		}
		s.rows[j] = rows
		s.rowOwner[j] = s.stmtOwner[i]
		return "ok"
	default:
		ds := newDests(f[2])
		err := st.QueryRowContext(ctx, parseArgs(f[3:])...).Scan(ptrs(ds)...)
		if err != nil {
			return errText(err) + " | " + shows(ds)
		}
		return "ok " + shows(ds)
	}
}

// opTimeout bounds one scripted operation. Go's closemu waits for open
// rows, so a failed operation on a Conn that still has rows can wait forever;
// the same script then hangs in the Rust port, and both report "hang".
const opTimeout = 250 * time.Millisecond

// poolWait is how long an operation that needs a connection from an
// exhausted pool waits before giving up.
const poolWait = 10 * time.Millisecond

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	var cur *script
	hung := false
	n := 0
	for {
		line, err := in.ReadString('\n')
		if line = strings.TrimRight(line, "\r\n"); line != "" {
			f := strings.Fields(line)
			switch f[0] {
			case "C":
				fmt.Fprintln(out, convertRequest(f))
			case "V":
				fmt.Fprintln(out, converterRequest(f))
			case "BEGIN":
				cur = &script{}
				hung = false
				n = 0
			case "END":
				if cur.db != nil && !hung {
					cur.db.Close()
				}
				fmt.Fprintln(out, "END")
				cur = nil
			default:
				if hung {
					break
				}
				n++
				done := make(chan string, 1)
				go func(c *script, l string) {
					defer func() {
						if r := recover(); r != nil {
							done <- fmt.Sprintf("panic %v", r)
						}
					}()
					done <- c.run(l)
				}(cur, line)
				select {
				case r := <-done:
					fmt.Fprintf(out, "%d %s\n", n, r)
				case <-time.After(opTimeout):
					fmt.Fprintf(out, "%d hang\n", n)
					hung = true
				}
			}
		}
		if err != nil {
			return
		}
	}
}
