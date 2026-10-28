// Line-oriented Go mime/multipart oracle for tools/multipart_check.py.
// Requests are MODE:hex lines; payload fields are separated by NUL bytes, and
// the results are hex-encoded fields.
//
//	R  NextPart over payload: boundary, NUL, body
//	F  ReadForm(maxMemory): boundary, NUL, decimal maxMemory, NUL, body
//	T  ReadForm(maxMemory) as F, then the sizes of the multipart-* files left
//	   in $TMPDIR (a private directory), the contents read back, and the
//	   sizes after Form.RemoveAll (the same payload as F)
//	D  FileContentDisposition: fieldname, NUL, filename
//	B  Writer with SetBoundary(payload), then the script in the remaining
//	   NUL-separated items: "F" name value (WriteField), "C" name filename
//	   content (CreateFormFile), "H" name content (CreateFormField), and
//	   "P" key value content (CreatePart with one header and the content)
//	   The output is the written bytes.
//	S  SetBoundary validity: "ok" or "err"
//	M  FormDataContentType after SetBoundary: boundary
//
// "toolarge" marks ErrMessageTooLarge, and "err" other errors.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

func headerFields(h textproto.MIMEHeader) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := make([]string, len(h[k]))
		for i, v := range h[k] {
			vals[i] = hx(v)
		}
		parts = append(parts, hx(k)+"="+strings.Join(vals, ","))
	}
	return strings.Join(parts, ";")
}

// invalidHeaders reports whether a part header up to the first parse error
// holds a name or value that is not valid UTF-8: the Rust port stores header
// text as String and rejects such parts, so those records are skipped.
func invalidHeaders(boundary string, body []byte) bool {
	r := multipart.NewReader(bytes.NewReader(body), boundary)
	for {
		p, err := r.NextRawPart()
		if err != nil {
			return false
		}
		for k, vs := range p.Header {
			if !utf8.ValidString(k) {
				return true
			}
			for _, v := range vs {
				if !utf8.ValidString(v) {
					return true
				}
			}
		}
		io.Copy(io.Discard, p)
	}
}

func readParts(boundary string, body []byte, raw bool) string {
	r := multipart.NewReader(bytes.NewReader(body), boundary)
	var out []string
	for {
		var p *multipart.Part
		var err error
		if raw {
			p, err = r.NextRawPart()
		} else {
			p, err = r.NextPart()
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "err"
		}
		data, err := io.ReadAll(p)
		if err != nil {
			return "err"
		}
		out = append(out, strings.Join([]string{hx(p.FormName()), hx(p.FileName()), headerFields(p.Header), hx(string(data))}, ","))
	}
	return "ok\t" + strings.Join(out, "\t")
}

func readForm(boundary string, maxMemory int64, body []byte) string {
	r := multipart.NewReader(bytes.NewReader(body), boundary)
	form, err := r.ReadForm(maxMemory)
	if errors.Is(err, multipart.ErrMessageTooLarge) {
		return "toolarge"
	}
	if err != nil {
		return "err"
	}
	var out []string
	names := make([]string, 0, len(form.Value))
	for k, vs := range form.Value {
		for _, v := range vs {
			if !utf8.ValidString(v) {
				return "skip" // the Rust Form holds values as String
			}
		}
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		for _, v := range form.Value[k] {
			out = append(out, "v:"+hx(k)+","+hx(v))
		}
	}
	names = names[:0]
	for k := range form.File {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		for _, fh := range form.File[k] {
			f, err := fh.Open()
			if err != nil {
				return "err"
			}
			data, err := io.ReadAll(f)
			f.Close()
			if err != nil {
				return "err"
			}
			out = append(out, fmt.Sprintf("f:%s,%s,%d,%s,%s", hx(k), hx(fh.Filename), fh.Size, hx(string(data)), headerFields(fh.Header)))
		}
	}
	return "ok\t" + strings.Join(out, "\t")
}

// tmpSizes lists the sizes of the multipart-* files in $TMPDIR, sorted, as
// "n:size,size". Files from earlier records are removed first by clearTmp.
func tmpSizes() string {
	entries, err := os.ReadDir(os.TempDir())
	if err != nil {
		panic(err)
	}
	var sizes []int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "multipart-") {
			info, err := e.Info()
			if err != nil {
				panic(err)
			}
			sizes = append(sizes, int(info.Size()))
		}
	}
	sort.Ints(sizes)
	parts := make([]string, len(sizes))
	for i, n := range sizes {
		parts[i] = strconv.Itoa(n)
	}
	return strconv.Itoa(len(sizes)) + ":" + strings.Join(parts, ",")
}

func clearTmp() {
	entries, _ := os.ReadDir(os.TempDir())
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "multipart-") {
			os.Remove(os.TempDir() + "/" + e.Name())
		}
	}
}

func readFormTmp(boundary string, maxMemory int64, body []byte) string {
	clearTmp()
	r := multipart.NewReader(bytes.NewReader(body), boundary)
	form, err := r.ReadForm(maxMemory)
	left := tmpSizes()
	if errors.Is(err, multipart.ErrMessageTooLarge) {
		return "toolarge\t" + left
	}
	if err != nil {
		return "err\t" + left
	}
	defer clearTmp()
	for _, vs := range form.Value {
		for _, v := range vs {
			if !utf8.ValidString(v) {
				return "skip"
			}
		}
	}
	names := make([]string, 0, len(form.File))
	for k := range form.File {
		names = append(names, k)
	}
	sort.Strings(names)
	var out []string
	for _, k := range names {
		for _, fh := range form.File[k] {
			f, err := fh.Open()
			if err != nil {
				return "err"
			}
			data, err := io.ReadAll(f)
			if err == nil {
				// ReadAt and Seek must see the same bytes as Read.
				buf := make([]byte, 3)
				n, _ := f.ReadAt(buf, 1)
				pos, _ := f.Seek(-2, io.SeekEnd)
				out = append(out, fmt.Sprintf("%s,%d,%d,%s", hx(k), n, pos, hx(string(data))))
			}
			f.Close()
			if err != nil {
				return "err"
			}
		}
	}
	rerr := form.RemoveAll()
	return "ok\t" + left + "\t" + strings.Join(out, ";") + "\t" + tmpSizes() + "\t" + fmt.Sprint(rerr == nil)
}

func writeScript(boundary string, items []string) string {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary(boundary); err != nil {
		return "err"
	}
	for _, item := range items {
		fields := strings.SplitN(item, "\x1f", 4)
		switch fields[0] {
		case "F":
			if err := w.WriteField(fields[1], fields[2]); err != nil {
				return "err"
			}
		case "C":
			fw, err := w.CreateFormFile(fields[1], fields[2])
			if err != nil {
				return "err"
			}
			if _, err := fw.Write([]byte(fields[3])); err != nil {
				return "err"
			}
		case "H":
			fw, err := w.CreateFormField(fields[1])
			if err != nil {
				return "err"
			}
			if _, err := fw.Write([]byte(fields[2])); err != nil {
				return "err"
			}
		case "P":
			h := textproto.MIMEHeader{}
			h[fields[1]] = []string{fields[2]}
			fw, err := w.CreatePart(h)
			if err != nil {
				return "err"
			}
			if _, err := fw.Write([]byte(fields[3])); err != nil {
				return "err"
			}
		default:
			panic("unknown script item " + fields[0])
		}
	}
	if err := w.Close(); err != nil {
		return "err"
	}
	return hx(buf.String())
}

func handle(mode string, data []byte) string {
	fields := bytes.Split(data, []byte{0})
	switch mode {
	case "R", "W", "F", "T":
		if invalidHeaders(string(fields[0]), fields[len(fields)-1]) {
			return "skip"
		}
	}
	switch mode {
	case "R":
		return readParts(string(fields[0]), fields[1], false)
	case "W":
		return readParts(string(fields[0]), fields[1], true)
	case "F":
		maxMemory, err := strconv.ParseInt(string(fields[1]), 10, 64)
		if err != nil {
			panic(err)
		}
		return readForm(string(fields[0]), maxMemory, fields[2])
	case "T":
		maxMemory, err := strconv.ParseInt(string(fields[1]), 10, 64)
		if err != nil {
			panic(err)
		}
		return readFormTmp(string(fields[0]), maxMemory, fields[2])
	case "D":
		return hx(multipart.FileContentDisposition(string(fields[0]), string(fields[1])))
	case "B":
		items := make([]string, 0, len(fields)-1)
		for _, f := range fields[1:] {
			if len(f) > 0 {
				items = append(items, string(f))
			}
		}
		return writeScript(string(fields[0]), items)
	case "S":
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if err := w.SetBoundary(string(data)); err != nil {
			return "err"
		}
		return "ok"
	case "M":
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		if err := w.SetBoundary(string(data)); err != nil {
			return "err"
		}
		return hx(w.FormDataContentType())
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
