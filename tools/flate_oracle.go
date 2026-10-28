// Differential oracle for compress/flate, compress/gzip and compress/zlib.
//
// One request per input line, fields separated by single spaces; hex fields
// use "-" for an absent value. Replies are tab separated, one line each.
//
//	dec <fmt> <hex stream> <dict: - | + | hex> <ms: 0|1>
//	    -> ok|err <hex bytes delivered> <error text> <unread input bytes> <gzip header summary>
//	enc <fmt> <level> <hex data> <dict: - | + | hex> <plan> <gzip header: - | name|comment|extra|os|mtime>
//	    -> ok <hex stream> <comma separated output sizes after each flush>
//	    -> err <hex> <error text>
//
// The plan is a ';' separated list of chunks, each "<size>" or "<size>f"
// (flush after the chunk); chunks consume the data in order and the rest is
// written last. Reads use a small buffer and keep the bytes returned together
// with an error, as io.ReadAll does.
package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func dictArg(s string) (dict []byte, present bool) {
	switch s {
	case "-":
		return nil, false
	case "+":
		return []byte{}, true
	}
	return unhex(s), true
}

func readAll(r io.Reader) ([]byte, error) {
	var out []byte
	buf := make([]byte, 509)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

func clean(s string) string {
	return strings.NewReplacer("\t", " ", "\n", " ").Replace(s)
}

func headerSummary(h *gzip.Header) string {
	extra := "-"
	if h.Extra != nil {
		extra = "+" + hex.EncodeToString(h.Extra)
	}
	mtime := int64(0)
	if !h.ModTime.IsZero() {
		mtime = h.ModTime.Unix()
	}
	return fmt.Sprintf("%s|%s|%s|%d|%d", hex.EncodeToString([]byte(h.Name)), hex.EncodeToString([]byte(h.Comment)), extra, h.OS, mtime)
}

func decode(f string, stream []byte, dictField string, multistream bool) string {
	dict, _ := dictArg(dictField)
	src := bytes.NewReader(stream)
	var out []byte
	var err error
	summary := "-"
	switch f {
	case "flate":
		var r io.ReadCloser
		if dict != nil {
			r = flate.NewReaderDict(src, dict)
		} else {
			r = flate.NewReader(src)
		}
		out, err = readAll(r)
	case "zlib":
		var r io.ReadCloser
		if r, err = zlib.NewReaderDict(src, dict); err == nil {
			out, err = readAll(r)
		}
	case "gzip":
		var r *gzip.Reader
		if r, err = gzip.NewReader(src); err == nil {
			summary = headerSummary(&r.Header)
			r.Multistream(multistream)
			out, err = readAll(r)
		}
	}
	status, text := "ok", ""
	if err != nil {
		status, text = "err", clean(err.Error())
	}
	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s", status, hex.EncodeToString(out), text, src.Len(), summary)
}

type plan struct {
	size  int
	flush bool
}

func parsePlan(s string) []plan {
	var out []plan
	if s == "-" {
		return out
	}
	for _, part := range strings.Split(s, ";") {
		p := plan{}
		if strings.HasSuffix(part, "f") {
			p.flush = true
			part = strings.TrimSuffix(part, "f")
		}
		p.size, _ = strconv.Atoi(part)
		out = append(out, p)
	}
	return out
}

type flusher interface {
	io.Writer
	Flush() error
	Close() error
}

func encode(f string, level int, data []byte, dictField string, planField string, hdrField string) string {
	dict, hasDict := dictArg(dictField)
	var buf bytes.Buffer
	var w flusher
	var err error
	switch f {
	case "flate":
		if hasDict {
			w, err = flate.NewWriterDict(&buf, level, dict)
		} else {
			w, err = flate.NewWriter(&buf, level)
		}
	case "zlib":
		if hasDict {
			w, err = zlib.NewWriterLevelDict(&buf, level, dict)
		} else {
			w, err = zlib.NewWriterLevel(&buf, level)
		}
	case "gzip":
		var gw *gzip.Writer
		if gw, err = gzip.NewWriterLevel(&buf, level); err == nil {
			if hdrField != "-" {
				parts := strings.Split(hdrField, "|")
				gw.Name = string(unhex(parts[0]))
				gw.Comment = string(unhex(parts[1]))
				if parts[2] != "-" {
					gw.Extra = unhex(parts[2][1:])
				}
				osv, _ := strconv.Atoi(parts[3])
				gw.OS = byte(osv)
				mt, _ := strconv.ParseInt(parts[4], 10, 64)
				if mt != 0 {
					gw.ModTime = time.Unix(mt, 0)
				}
			}
			w = gw
		}
	}
	if err != nil {
		return "err\t\t" + clean(err.Error())
	}
	var flushes []string
	rest := data
	fail := func(err error) string {
		return fmt.Sprintf("err\t%s\t%s", hex.EncodeToString(buf.Bytes()), clean(err.Error()))
	}
	for _, p := range parsePlan(planField) {
		n := p.size
		if n > len(rest) {
			n = len(rest)
		}
		if _, err := w.Write(rest[:n]); err != nil {
			return fail(err)
		}
		rest = rest[n:]
		if p.flush {
			if err := w.Flush(); err != nil {
				return fail(err)
			}
			flushes = append(flushes, strconv.Itoa(buf.Len()))
		}
	}
	if _, err := w.Write(rest); err != nil {
		return fail(err)
	}
	if err := w.Close(); err != nil {
		return fail(err)
	}
	return fmt.Sprintf("ok\t%s\t%s", hex.EncodeToString(buf.Bytes()), strings.Join(flushes, ","))
}

func handle(line string) string {
	fields := strings.Split(line, " ")
	switch fields[0] {
	case "dec":
		stream := []byte{}
		if fields[2] != "-" {
			stream = unhex(fields[2])
		}
		return decode(fields[1], stream, fields[3], fields[4] == "1")
	case "enc":
		level, _ := strconv.Atoi(fields[2])
		data := []byte{}
		if fields[3] != "-" {
			data = unhex(fields[3])
		}
		return encode(fields[1], level, data, fields[4], fields[5], fields[6])
	}
	return "err\t\tunknown op"
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			fmt.Fprintln(out, handle(line))
		}
		if err != nil {
			return
		}
	}
}
