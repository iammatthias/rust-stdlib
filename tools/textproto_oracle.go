// Line-oriented Go net/textproto oracle. Requests are MODE:hex lines; every
// response field is hex so CR, LF and 8-bit bytes survive transport.
//
// Values that are not valid UTF-8 are reported as "err": the Rust port stores
// strings and rejects non-UTF-8 header and line bytes as a documented boundary.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	_ "unsafe" // for the limit-aware readMIMEHeader linkname
)

//go:linkname readMIMEHeader net/textproto.readMIMEHeader
func readMIMEHeader(r *textproto.Reader, maxMemory, maxHeaders int64) (textproto.MIMEHeader, error)

func reader(data []byte) *textproto.Reader {
	return textproto.NewReader(bufio.NewReader(bytes.NewReader(data)))
}

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

func headerMap(m textproto.MIMEHeader) (string, bool) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if !utf8.ValidString(k) {
			return "", false
		}
		values := make([]string, 0, len(m[k]))
		for _, v := range m[k] {
			if !utf8.ValidString(v) {
				return "", false
			}
			values = append(values, hx(v))
		}
		parts = append(parts, hx(k)+"="+strings.Join(values, ","))
	}
	return strings.Join(parts, ";"), true
}

// rest returns the remaining raw lines after a framed read, hex encoded.
func rest(r *textproto.Reader) string {
	var lines []string
	for {
		line, err := r.ReadLineBytes()
		if err != nil {
			break
		}
		lines = append(lines, hex.EncodeToString(line))
	}
	return strings.Join(lines, ",")
}

func header(m textproto.MIMEHeader, err error) string {
	if err != nil && err != io.EOF {
		return "err"
	}
	text, ok := headerMap(m)
	if !ok {
		return "err"
	}
	if err == io.EOF {
		return "eof"
	}
	return "ok\t" + text
}

func response(code int, message string, err error) string {
	var protocol *textproto.Error
	switch {
	case err == nil:
		if !utf8.ValidString(message) {
			return "err"
		}
		return fmt.Sprintf("ok\t%d\t%s", code, hx(message))
	case errors.As(err, &protocol):
		if !utf8.ValidString(protocol.Msg) {
			return "err"
		}
		return fmt.Sprintf("code\t%d\t%s", protocol.Code, hx(protocol.Msg))
	default:
		return "err"
	}
}

// errText classifies an error the way the Rust probe does: sentinels by name,
// textproto errors with their full Error() text, anything else as "io".
var errUTF8 = errors.New("not valid UTF-8")

func errText(err error) string {
	var response *textproto.Error
	var protocol textproto.ProtocolError
	switch {
	case err == nil:
		return ""
	case err == errUTF8:
		return "utf8"
	case err == io.EOF:
		return "EOF"
	case err == io.ErrUnexpectedEOF:
		return "UEOF"
	case errors.As(err, &response):
		return "E:" + hx(err.Error())
	case errors.As(err, &protocol):
		return "P:" + hx(err.Error())
	}
	return "io"
}

func listValid(lines []string) (string, bool) {
	encoded := make([]string, len(lines))
	for i, line := range lines {
		if !utf8.ValidString(line) {
			return "", false
		}
		encoded[i] = hx(line)
	}
	return strings.Join(encoded, ","), true
}

// serve plays the server half of a transcript: every G/S blob is written at
// once and the write side is shut, so the client's reads see data and then EOF
// and can never block; the server then collects whatever the client sent.
func serve(ln net.Listener, ops [][]byte, received chan<- []byte) {
	c, err := ln.Accept()
	if err != nil {
		received <- nil
		return
	}
	defer c.Close()
	for _, op := range ops {
		if op[0] == 'G' || op[0] == 'S' {
			c.Write(op[1:])
		}
	}
	c.(*net.TCPConn).CloseWrite()
	data, _ := io.ReadAll(c)
	received <- data
}

// transcript dials a loopback server that replays the script and runs the
// client operations against it with textproto.Conn.
func transcript(script []byte) string {
	ops := bytes.Split(script, []byte{0x1e})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer ln.Close()
	received := make(chan []byte, 1)
	go serve(ln, ops, received)
	conn, err := textproto.Dial("tcp", ln.Addr().String())
	if err != nil {
		panic(err)
	}
	var out []string
	var id uint
	for _, op := range ops {
		arg := string(op[1:])
		var res string
		switch op[0] {
		case 'G', 'S':
			continue
		case 'C':
			var err error
			id, err = conn.Cmd("%s", arg)
			if err != nil {
				res = "C:" + errText(err)
			} else {
				res = fmt.Sprintf("C:ok:%d", id)
			}
		case 'T':
			conn.StartResponse(id)
			res = "T"
		case 'E':
			conn.EndResponse(id)
			res = "E"
		case 'R', 'Q':
			expect, _ := strconv.Atoi(arg)
			var code int
			var msg string
			var err error
			if op[0] == 'R' {
				code, msg, err = conn.ReadResponse(expect)
			} else {
				code, msg, err = conn.ReadCodeLine(expect)
			}
			if err != nil {
				code, msg = 0, ""
			}
			res = fmt.Sprintf("%c:%d:%s:%s", op[0], code, hx(msg), errText(err))
		case 'l':
			line, err := conn.ReadLine()
			if err != nil {
				line = ""
			}
			res = "l:" + hx(line) + ":" + errText(err)
		case 'D':
			lines, err := conn.ReadDotLines()
			text, ok := listValid(lines)
			if err != nil {
				text = ""
			} else if !ok {
				err, text = errUTF8, ""
			}
			res = "D:" + text + ":" + errText(err)
		case 'B':
			body, err := conn.ReadDotBytes()
			if err != nil {
				body = nil
			}
			res = "B:" + hex.EncodeToString(body) + ":" + errText(err)
		case 'H':
			header, err := conn.ReadMIMEHeader()
			text, ok := headerMap(header)
			if err != nil {
				text = ""
			} else if !ok {
				err, text = errUTF8, ""
			}
			res = "H:" + text + ":" + errText(err)
		default:
			panic("unknown transcript op")
		}
		out = append(out, res)
	}
	if err := conn.Close(); err != nil {
		out = append(out, "close:io")
	}
	select {
	case data := <-received:
		out = append(out, "sent:"+hex.EncodeToString(data))
	case <-time.After(10 * time.Second):
		out = append(out, "server-timeout")
	}
	return strings.Join(out, "|")
}

func handle(mode string, data []byte) string {
	switch {
	case mode == "X":
		return transcript(data)
	case mode == "K":
		return hx(textproto.CanonicalMIMEHeaderKey(string(data)))
	case mode == "T":
		return hx(textproto.TrimString(string(data)))
	case mode == "H":
		return header(reader(data).ReadMIMEHeader())
	case strings.HasPrefix(mode, "HL"):
		limits := strings.Split(mode[2:], ",")
		memory, _ := strconv.ParseInt(limits[0], 10, 64)
		count, _ := strconv.ParseInt(limits[1], 10, 64)
		return header(readMIMEHeader(reader(data), memory, count))
	case mode == "C":
		r := reader(data)
		var lines []string
		for {
			line, err := r.ReadContinuedLine()
			if err != nil {
				if err == io.EOF {
					return "ok\t" + strings.Join(lines, ",")
				}
				return "err"
			}
			if !utf8.ValidString(line) {
				return "err"
			}
			lines = append(lines, hx(line))
		}
	case mode == "D":
		r := reader(data)
		body, err := r.ReadDotBytes()
		if err != nil {
			return "err"
		}
		return "ok\t" + hex.EncodeToString(body) + "\t" + rest(r)
	case mode == "S":
		// Partially read a dot body, then read lines: the abandoned DotReader
		// must be drained to its terminator first.
		r := reader(data)
		var one [1]byte
		if _, err := r.DotReader().Read(one[:]); err != nil {
			return "err"
		}
		line, err := r.ReadLineBytes()
		if err != nil {
			return "err"
		}
		return "ok\t" + hex.EncodeToString(one[:]) + "\t" + hex.EncodeToString(line)
	case mode == "L":
		r := reader(data)
		lines, err := r.ReadDotLines()
		if err != nil {
			return "err"
		}
		encoded := make([]string, len(lines))
		for i, line := range lines {
			if !utf8.ValidString(line) {
				return "err"
			}
			encoded[i] = hx(line)
		}
		return "ok\t" + strings.Join(encoded, ",") + "\t" + rest(r)
	case strings.HasPrefix(mode, "R"):
		expect, _ := strconv.Atoi(mode[1:])
		return response(reader(data).ReadResponse(expect))
	case strings.HasPrefix(mode, "Q"):
		expect, _ := strconv.Atoi(mode[1:])
		return response(reader(data).ReadCodeLine(expect))
	case mode == "W":
		var out bytes.Buffer
		bw := bufio.NewWriter(&out)
		w := textproto.NewWriter(bw).DotWriter()
		if _, err := w.Write(data); err != nil {
			panic(err)
		}
		if err := w.Close(); err != nil {
			panic(err)
		}
		return hex.EncodeToString(out.Bytes())
	}
	panic("unknown mode " + mode)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 4096), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		mode, payload, ok := strings.Cut(in.Text(), ":")
		if !ok {
			panic("bad request")
		}
		data, err := hex.DecodeString(payload)
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(out, handle(mode, data))
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
