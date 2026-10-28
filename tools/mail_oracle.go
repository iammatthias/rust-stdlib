// Line-oriented Go net/mail and mime encoded-word oracle. Requests are
// MODE:hex lines; every response field is hex.
//
// Results containing non-UTF-8 strings are reported as "err" because the Rust
// port rejects them explicitly. Dates are compared as unix seconds, nanoseconds
// and zone offset over the whole range Go accepts.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/mail"
	"os"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

func address(a *mail.Address) (string, bool) {
	if !utf8.ValidString(a.Name) || !utf8.ValidString(a.Address) {
		return "", false
	}
	return hx(a.Name) + "," + hx(a.Address) + "," + hx(a.String()), true
}

func handle(mode string, data []byte) string {
	text := string(data)
	switch mode {
	case "A":
		a, err := mail.ParseAddress(text)
		if err != nil {
			return "err"
		}
		s, ok := address(a)
		if !ok {
			return "err"
		}
		return "ok\t" + s
	case "L":
		list, err := mail.ParseAddressList(text)
		if err != nil {
			return "err"
		}
		parts := make([]string, len(list))
		for i, a := range list {
			s, ok := address(a)
			if !ok {
				return "err"
			}
			parts[i] = s
		}
		return "ok\t" + strings.Join(parts, ";")
	case "F":
		name, addr, _ := strings.Cut(text, "\x00")
		return hx((&mail.Address{Name: name, Address: addr}).String())
	case "D":
		t, err := mail.ParseDate(text)
		if err != nil {
			return "err"
		}
		_, offset := t.Zone()
		return fmt.Sprintf("ok\t%d\t%d\t%d", t.Unix(), t.Nanosecond(), offset)
	case "M":
		msg, err := mail.ReadMessage(bytes.NewReader(data))
		if err != nil {
			return "err"
		}
		body, err := io.ReadAll(msg.Body)
		if err != nil {
			panic(err)
		}
		keys := make([]string, 0, len(msg.Header))
		for k := range msg.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			if !utf8.ValidString(k) {
				return "err"
			}
			values := make([]string, len(msg.Header[k]))
			for i, v := range msg.Header[k] {
				if !utf8.ValidString(v) {
					return "err"
				}
				values[i] = hx(v)
			}
			parts = append(parts, hx(k)+"="+strings.Join(values, ","))
		}
		return "ok\t" + strings.Join(parts, ";") + "\t" + hex.EncodeToString(body)
	case "G", "H", "T":
		// Header lookups on a message: payload is key, NUL, raw message.
		key, raw, _ := strings.Cut(text, "\x00")
		msg, err := mail.ReadMessage(strings.NewReader(raw))
		if err != nil {
			return "err"
		}
		switch mode {
		case "G":
			v := msg.Header.Get(key)
			if v == "" {
				return "none"
			}
			if !utf8.ValidString(v) {
				return "err"
			}
			return "ok\t" + hx(v)
		case "T":
			t, err := msg.Header.Date()
			if errors.Is(err, mail.ErrHeaderNotPresent) {
				return "missing"
			}
			if err != nil {
				return "err"
			}
			_, offset := t.Zone()
			return fmt.Sprintf("ok\t%d\t%d\t%d", t.Unix(), t.Nanosecond(), offset)
		default:
			list, err := msg.Header.AddressList(key)
			if errors.Is(err, mail.ErrHeaderNotPresent) {
				return "missing"
			}
			if err != nil {
				return "err"
			}
			parts := make([]string, len(list))
			for i, a := range list {
				s, ok := address(a)
				if !ok {
					return "err"
				}
				parts[i] = s
			}
			return "ok\t" + strings.Join(parts, ";")
		}
	case "W":
		decoded, err := new(mime.WordDecoder).DecodeHeader(text)
		if err != nil || !utf8.ValidString(decoded) {
			return "err"
		}
		return "ok\t" + hx(decoded)
	case "B":
		return hx(mime.BEncoding.Encode("utf-8", text))
	case "Q":
		return hx(mime.QEncoding.Encode("utf-8", text))
	}
	panic("unknown mode " + mode)
}

func main() {
	// Zone abbreviations resolve through time.Local; pin it so results do not
	// depend on the machine's configured zone.
	time.Local = time.UTC
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
