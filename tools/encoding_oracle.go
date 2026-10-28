// Standalone standard-library CSV/XML differential oracle.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

// byteOrder maps the probe's BE, LE and NE names onto Go's byte orders.
func byteOrder(name string) binary.ByteOrder {
	switch name {
	case "BE":
		return binary.BigEndian
	case "LE":
		return binary.LittleEndian
	}
	return binary.NativeEndian
}

// parseValue reads one value of a fixed-size type: decimal integers, hex bit
// patterns for floats, and true or false for bool.
func parseValue(typ, text string) (any, error) {
	switch typ {
	case "u8", "u16", "u32", "u64":
		bits, _ := strconv.Atoi(typ[1:])
		v, err := strconv.ParseUint(text, 10, bits)
		switch typ {
		case "u8":
			return uint8(v), err
		case "u16":
			return uint16(v), err
		case "u32":
			return uint32(v), err
		}
		return v, err
	case "i8", "i16", "i32", "i64":
		bits, _ := strconv.Atoi(typ[1:])
		v, err := strconv.ParseInt(text, 10, bits)
		switch typ {
		case "i8":
			return int8(v), err
		case "i16":
			return int16(v), err
		case "i32":
			return int32(v), err
		}
		return v, err
	case "f32":
		v, err := strconv.ParseUint(text, 16, 32)
		return math.Float32frombits(uint32(v)), err
	case "f64":
		v, err := strconv.ParseUint(text, 16, 64)
		return math.Float64frombits(v), err
	case "bool":
		return text == "true", nil
	}
	return nil, fmt.Errorf("unknown type %s", typ)
}

// repr renders a decoded value the way the Rust probe does: decimal integers,
// bit patterns for floats, and true or false.
func repr(v any) string {
	switch x := v.(type) {
	case float32:
		return strconv.FormatUint(uint64(math.Float32bits(x)), 16)
	case float64:
		return strconv.FormatUint(math.Float64bits(x), 16)
	}
	return fmt.Sprint(v)
}

func decodeAs[T any](buf []byte, o binary.ByteOrder) (any, error) {
	var v T
	n, err := binary.Decode(buf, o, &v)
	if err != nil {
		return nil, err
	}
	return []any{repr(v), n}, nil
}

func readAs[T any](buf []byte, o binary.ByteOrder) (any, error) {
	var v T
	if err := binary.Read(bytes.NewReader(buf), o, &v); err != nil {
		return nil, err
	}
	return repr(v), nil
}

// decodeType dispatches decodeAs or readAs on the type name.
func decodeType(format, typ string, buf []byte, o binary.ByteOrder) (any, error) {
	read := format == "binary_read"
	switch typ {
	case "u8":
		if read {
			return readAs[uint8](buf, o)
		}
		return decodeAs[uint8](buf, o)
	case "i8":
		if read {
			return readAs[int8](buf, o)
		}
		return decodeAs[int8](buf, o)
	case "u16":
		if read {
			return readAs[uint16](buf, o)
		}
		return decodeAs[uint16](buf, o)
	case "i16":
		if read {
			return readAs[int16](buf, o)
		}
		return decodeAs[int16](buf, o)
	case "u32":
		if read {
			return readAs[uint32](buf, o)
		}
		return decodeAs[uint32](buf, o)
	case "i32":
		if read {
			return readAs[int32](buf, o)
		}
		return decodeAs[int32](buf, o)
	case "u64":
		if read {
			return readAs[uint64](buf, o)
		}
		return decodeAs[uint64](buf, o)
	case "i64":
		if read {
			return readAs[int64](buf, o)
		}
		return decodeAs[int64](buf, o)
	case "f32":
		if read {
			return readAs[float32](buf, o)
		}
		return decodeAs[float32](buf, o)
	case "f64":
		if read {
			return readAs[float64](buf, o)
		}
		return decodeAs[float64](buf, o)
	case "bool":
		if read {
			return readAs[bool](buf, o)
		}
		return decodeAs[bool](buf, o)
	}
	return nil, fmt.Errorf("unknown type %s", typ)
}

func bytesOf(b []byte) []int {
	out := []int{}
	for _, x := range b {
		out = append(out, int(x))
	}
	return out
}

// binaryRun answers the fixed-size, byte-order and varint formats. The
// boolean reports whether the format belongs to this group.
func binaryRun(format, input string) (any, bool, error) {
	switch format {
	case "binary_encode":
		// order|type|value|buffer length
		parts := strings.Split(input, "|")
		v, err := parseValue(parts[1], parts[2])
		if err != nil {
			return nil, true, err
		}
		size, err := strconv.Atoi(parts[3])
		if err != nil {
			return nil, true, err
		}
		buf := make([]byte, size)
		n, err := binary.Encode(buf, byteOrder(parts[0]), v)
		if err != nil {
			return nil, true, err
		}
		return bytesOf(buf[:n]), true, nil
	case "binary_write":
		parts := strings.Split(input, "|")
		v, err := parseValue(parts[1], parts[2])
		if err != nil {
			return nil, true, err
		}
		var w bytes.Buffer
		if err := binary.Write(&w, byteOrder(parts[0]), v); err != nil {
			return nil, true, err
		}
		return bytesOf(w.Bytes()), true, nil
	case "binary_decode", "binary_read":
		// order|type|hex bytes
		parts := strings.Split(input, "|")
		buf, err := hex.DecodeString(parts[2])
		if err != nil {
			return nil, true, err
		}
		v, err := decodeType(format, parts[1], buf, byteOrder(parts[0]))
		return v, true, err
	case "append_uvarint", "append_varint":
		if format == "append_uvarint" {
			v, err := strconv.ParseUint(input, 10, 64)
			if err != nil {
				return nil, true, err
			}
			return bytesOf(binary.AppendUvarint(nil, v)), true, nil
		}
		v, err := strconv.ParseInt(input, 10, 64)
		if err != nil {
			return nil, true, err
		}
		return bytesOf(binary.AppendVarint(nil, v)), true, nil
	case "uvarint_get", "varint_get", "read_uvarint", "read_varint":
		buf, err := hex.DecodeString(input)
		if err != nil {
			return nil, true, err
		}
		switch format {
		case "uvarint_get":
			v, n := binary.Uvarint(buf)
			if n <= 0 {
				return nil, true, fmt.Errorf("uvarint %d", n)
			}
			return []any{strconv.FormatUint(v, 10), n}, true, nil
		case "varint_get":
			v, n := binary.Varint(buf)
			if n <= 0 {
				return nil, true, fmt.Errorf("varint %d", n)
			}
			return []any{strconv.FormatInt(v, 10), n}, true, nil
		case "read_uvarint":
			v, err := binary.ReadUvarint(bytes.NewReader(buf))
			return strconv.FormatUint(v, 10), true, err
		}
		v, err := binary.ReadVarint(bytes.NewReader(buf))
		return strconv.FormatInt(v, 10), true, err
	}
	return nil, false, nil
}

func run(format, input string, options json.RawMessage) (any, error) {
	if v, ok, err := binaryRun(format, input); ok {
		return v, err
	}
	if format == "uvarint" || format == "varint" {
		buf := make([]byte, 10)
		var n int
		if format == "uvarint" {
			value, e := strconv.ParseUint(input, 10, 64)
			if e != nil {
				return nil, e
			}
			n = binary.PutUvarint(buf, value)
		} else {
			value, e := strconv.ParseInt(input, 10, 64)
			if e != nil {
				return nil, e
			}
			n = binary.PutVarint(buf, value)
		}
		out := []int{}
		for _, b := range buf[:n] {
			out = append(out, int(b))
		}
		return out, nil
	}

	if format == "csv" || format == "csv_read" || format == "csv_write" || format == "csv_raw_read" {
		return csvRun(format, input, options)
	}
	r := xml.NewDecoder(strings.NewReader(input))
	r.Strict = true
	out := []any{}
	for {
		t, e := r.Token()
		if e == io.EOF {
			return out, nil
		}
		if e != nil {
			return nil, e
		}
		switch t := t.(type) {
		case xml.StartElement:
			a := []any{}
			for _, v := range t.Attr {
				if format == "xmlns" {
					if v.Name.Space == "xmlns" || (v.Name.Space == "" && v.Name.Local == "xmlns") {
						continue
					}
					a = append(a, []any{[]any{v.Name.Space, v.Name.Local}, v.Value})
				} else {
					a = append(a, []any{v.Name.Local, v.Value})
				}
			}
			if format == "xmlns" {
				out = append(out, []any{"start", []any{t.Name.Space, t.Name.Local}, a})
			} else {
				out = append(out, []any{"start", t.Name.Local, a})
			}
		case xml.EndElement:
			if format == "xmlns" {
				out = append(out, []any{"end", []any{t.Name.Space, t.Name.Local}})
			} else {
				out = append(out, []any{"end", t.Name.Local})
			}
		case xml.CharData:
			out = append(out, []any{"text", string(t)})
		case xml.Comment:
			out = append(out, []any{"comment", string(t)})
		case xml.ProcInst:
			out = append(out, []any{"pi", t.Target, string(t.Inst)})
		}
	}
}

// csvOptions are the Reader and Writer settings of a csv vector. Numbers are
// strings so both sides parse them the same way.
type csvOptions struct {
	Comma   *string `json:"comma"`
	Comment string  `json:"comment"`
	Fields  string  `json:"fields"`
	Lazy    bool    `json:"lazy"`
	Trim    bool    `json:"trim"`
	CRLF    bool    `json:"crlf"`
	FailAt  string  `json:"fail_at"`
}

// firstRune is Go's rune value for a setting; empty is the zero rune.
func firstRune(s string) rune {
	for _, r := range s {
		return r
	}
	return 0
}

// commaOf is the Comma setting: an absent key keeps Go's default ','.
func commaOf(comma *string) rune {
	if comma == nil {
		return ','
	}
	return firstRune(*comma)
}

// csvRun answers csv (ReadAll with defaults), csv_read (every Read result, with
// field positions and input offsets) and csv_write (WriteAll of JSON records).
func csvRun(format, input string, options json.RawMessage) (any, error) {
	var o csvOptions
	if len(options) > 0 {
		if err := json.Unmarshal(options, &o); err != nil {
			return nil, err
		}
	}
	if format == "csv" {
		r := csv.NewReader(strings.NewReader(input))
		rows, err := r.ReadAll()
		if rows == nil {
			rows = [][]string{}
		}
		return rows, err
	}
	if format == "csv_write" {
		var records [][]string
		if err := json.Unmarshal([]byte(input), &records); err != nil {
			return nil, err
		}
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		w.Comma = commaOf(o.Comma)
		w.UseCRLF = o.CRLF
		if err := w.WriteAll(records); err != nil {
			return nil, err
		}
		return buf.String(), nil
	}
	if format == "csv_raw_read" {
		raw, err := hex.DecodeString(input)
		if err != nil {
			return nil, err
		}
		var src io.Reader = bytes.NewReader(raw)
		if o.FailAt != "" {
			n, _ := strconv.Atoi(o.FailAt)
			src = &failingReader{data: raw, failAt: n}
		}
		return csvEvents(csv.NewReader(src), o, true), nil
	}
	return csvEvents(csv.NewReader(strings.NewReader(input)), o, false), nil
}

// failingReader yields data[:failAt] and then an I/O error.
type failingReader struct {
	data   []byte
	failAt int
	pos    int
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.pos >= f.failAt || f.pos >= len(f.data) {
		if f.pos >= f.failAt {
			return 0, errors.New("injected read failure")
		}
		return 0, io.EOF
	}
	n := copy(p, f.data[:min(f.failAt, len(f.data))][f.pos:])
	f.pos += n
	return n, nil
}

// csvEvents reads every record, reporting each Read result with its partial
// record. Fields are hex strings when asHex is set, since they may not be UTF-8.
func csvEvents(r *csv.Reader, o csvOptions, asHex bool) []any {
	r.Comma = commaOf(o.Comma)
	if o.Comment != "" {
		r.Comment = firstRune(o.Comment)
	}
	r.FieldsPerRecord, _ = strconv.Atoi(o.Fields)
	r.LazyQuotes = o.Lazy
	r.TrimLeadingSpace = o.Trim
	show := func(record []string) []string {
		out := []string{}
		for _, f := range record {
			if asHex {
				f = hex.EncodeToString([]byte(f))
			}
			out = append(out, f)
		}
		return out
	}
	events := []any{}
	for len(events) < 1000 {
		record, err := r.Read()
		if err == io.EOF {
			events = append(events, []any{"eof"})
			break
		}
		var pe *csv.ParseError
		if errors.As(err, &pe) {
			events = append(events, []any{"parse", pe.StartLine, pe.Line, pe.Column, pe.Err.Error(), pe.Error(), show(record)})
			continue
		}
		if err != nil {
			events = append(events, []any{"error", err.Error(), show(record)})
			break
		}
		positions := [][]int{}
		for j := range record {
			line, col := r.FieldPos(j)
			positions = append(positions, []int{line, col})
		}
		events = append(events, []any{"record", show(record), positions, r.InputOffset()})
	}
	return events
}

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 16*1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		var v struct {
			Format  string          `json:"format"`
			Input   string          `json:"input"`
			Options json.RawMessage `json:"options"`
		}
		if e := json.Unmarshal(s.Bytes(), &v); e != nil {
			panic(e)
		}
		value, e := run(v.Format, v.Input, v.Options)
		var response any
		if e == nil {
			response = map[string]any{"ok": true, "value": value}
		} else {
			response = map[string]any{"ok": false}
		}
		b, e := json.Marshal(response)
		if e != nil {
			panic(e)
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	if e := s.Err(); e != nil {
		panic(e)
	}
}
