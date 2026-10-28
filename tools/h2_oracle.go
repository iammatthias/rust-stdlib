// Line-oriented Go HTTP/2 oracle used by tools/h2_check.py. tools/h2_check.py
// builds it inside a scratch module together with copies of Go's hpack and
// internal http2 sources (the originals are not importable), so this file
// imports "h2oracle/hpack" and "h2oracle/http2".
//
// HPACK requests (hex strings, ';' separates header blocks, ',' separates ops):
//
//	E:<ops>;<ops>...     encode with one persistent Encoder. ops: f<name>/<value>/<s>
//	                     (WriteField), t<n> (SetMaxDynamicTableSize), l<n>
//	                     (SetMaxDynamicTableSizeLimit). Answer: one hex block per ops.
//	D<size>,<maxstr>:<block>;<block>...
//	                     decode blocks with one Decoder (NewDecoder(size), SetMaxStringLength).
//	                     Answer per block: fields "n/v/s" joined by ',' or "err:<text>".
//	P<size>,<maxstr>,<emit>:<split>:<block>
//	                     Write the block in two pieces, then Close.
//	H:<hex>              HuffmanDecode, then HuffmanEncodeLength of the input.
//	J:<hex>              AppendHuffmanString and HuffmanEncodeLength.
//
// Frame requests are documented in the frame section below.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"h2oracle/hpack"
)

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

func fieldsText(fs []hpack.HeaderField) string {
	parts := make([]string, len(fs))
	for i, f := range fs {
		s := "0"
		if f.Sensitive {
			s = "1"
		}
		parts[i] = hex.EncodeToString([]byte(f.Name)) + "/" + hex.EncodeToString([]byte(f.Value)) + "/" + s
	}
	return strings.Join(parts, ",")
}

type bufWriter struct{ b []byte }

func (w *bufWriter) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }

func hpackEncode(req string) string {
	var w bufWriter
	enc := hpack.NewEncoder(&w)
	var out []string
	for _, block := range strings.Split(req, ";") {
		w.b = w.b[:0]
		if block != "" {
			for _, op := range strings.Split(block, ",") {
				switch op[0] {
				case 'f':
					p := strings.Split(op[1:], "/")
					enc.WriteField(hpack.HeaderField{Name: string(unhex(p[0])), Value: string(unhex(p[1])), Sensitive: p[2] == "1"})
				case 't':
					enc.SetMaxDynamicTableSize(uint32(atoi(op[1:])))
				case 'l':
					enc.SetMaxDynamicTableSizeLimit(uint32(atoi(op[1:])))
				}
			}
		}
		out = append(out, hex.EncodeToString(w.b))
	}
	return strings.Join(out, ";")
}

func hpackDecode(head, body string) string {
	p := strings.Split(head, ",")
	var got []hpack.HeaderField
	dec := hpack.NewDecoder(uint32(atoi(p[0])), func(f hpack.HeaderField) { got = append(got, f) })
	dec.SetMaxStringLength(atoi(p[1]))
	var out []string
	for _, block := range strings.Split(body, ";") {
		got = nil
		_, err := dec.Write(unhex(block))
		if err == nil {
			err = dec.Close()
		}
		if err != nil {
			out = append(out, "err:"+err.Error())
			break
		}
		out = append(out, fieldsText(got))
	}
	return strings.Join(out, ";")
}

func hpackPartial(head, rest string) string {
	p := strings.Split(head, ",")
	var got []hpack.HeaderField
	dec := hpack.NewDecoder(uint32(atoi(p[0])), func(f hpack.HeaderField) { got = append(got, f) })
	dec.SetMaxStringLength(atoi(p[1]))
	dec.SetEmitEnabled(p[2] == "1")
	q := strings.SplitN(rest, ":", 2)
	block := unhex(q[1])
	split := atoi(q[0])
	if split > len(block) {
		split = len(block)
	}
	_, err := dec.Write(block[:split])
	if err == nil {
		_, err = dec.Write(block[split:])
	}
	if err == nil {
		err = dec.Close()
	}
	if err != nil {
		return "err:" + err.Error() + "|" + fieldsText(got)
	}
	return fieldsText(got)
}

func huffDecode(h string) string {
	in := unhex(h)
	s, err := hpack.HuffmanDecodeToString(in)
	if err != nil {
		return "err:" + err.Error()
	}
	return hex.EncodeToString([]byte(s)) + " " + strconv.Itoa(int(hpack.HuffmanEncodeLength(s)))
}

func huffEncode(h string) string {
	in := string(unhex(h))
	return hex.EncodeToString(hpack.AppendHuffmanString(nil, in)) + " " + strconv.FormatUint(hpack.HuffmanEncodeLength(in), 10)
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		head, rest := line[:i], line[i+1:]
		var out string
		switch {
		case head == "E":
			out = hpackEncode(rest)
		case head[0] == 'D':
			out = hpackDecode(head[1:], rest)
		case head[0] == 'P':
			out = hpackPartial(head[1:], rest)
		case head == "H":
			out = huffDecode(rest)
		case head == "J":
			out = huffEncode(rest)
		default:
			out = frameRequest(head, rest)
		}
		fmt.Fprintln(w, out)
	}
}
