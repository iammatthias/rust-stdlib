// Line-oriented Go mime oracle for tools/mime_check.py. Requests are MODE:hex
// lines, processed in order because AddExtensionType changes global state.
//
//	P  ParseMediaType(payload)
//	F  FormatMediaType: payload is type, NUL, then key NUL value pairs
//	T  TypeByExtension(payload)
//	E  ExtensionsByType(payload)
//	A  AddExtensionType: payload is extension, NUL, media type
//
// Results are hex-encoded fields. Responses "err" and "invalid" (only for P)
// mark errors; "utf8" marks a result that is not valid UTF-8, which the Rust
// port reports as an error by design.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

func handle(mode string, data []byte) string {
	text := string(data)
	switch mode {
	case "P":
		mediatype, params, err := mime.ParseMediaType(text)
		if errors.Is(err, mime.ErrInvalidMediaParameter) {
			if !utf8.ValidString(mediatype) {
				return "utf8"
			}
			return "invalid\t" + hx(mediatype)
		}
		if err != nil {
			return "err"
		}
		if !utf8.ValidString(mediatype) {
			return "utf8"
		}
		keys := make([]string, 0, len(params))
		for k := range params {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			v := params[k]
			if !utf8.ValidString(k) || !utf8.ValidString(v) {
				return "utf8"
			}
			parts = append(parts, hx(k)+"="+hx(v))
		}
		return "ok\t" + hx(mediatype) + "\t" + strings.Join(parts, ";")
	case "F":
		fields := strings.Split(text, "\x00")
		params := map[string]string{}
		for i := 1; i+1 < len(fields); i += 2 {
			params[fields[i]] = fields[i+1]
		}
		return hx(mime.FormatMediaType(fields[0], params))
	case "T":
		return hx(mime.TypeByExtension(text))
	case "E":
		list, err := mime.ExtensionsByType(text)
		if err != nil {
			return "err"
		}
		parts := make([]string, len(list))
		for i, ext := range list {
			if !utf8.ValidString(ext) {
				return "utf8"
			}
			parts[i] = hx(ext)
		}
		return "ok\t" + strings.Join(parts, ",")
	case "A":
		ext, typ, _ := bytes.Cut(data, []byte{0})
		if err := mime.AddExtensionType(string(ext), string(typ)); err != nil {
			return "err"
		}
		return "ok"
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
