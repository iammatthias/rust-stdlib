// Line-oriented Go index/suffixarray oracle used by tools/suffixarray_check.py.
// Each request line is one of
//
//	W:<hex data>                       New(data).Write: the serialized bytes, in hex
//	R:<hex serialized>                 Read into a new Index, then Write it back in hex
//	L:<hex data>:<hex pattern>:<n>     New(data).Lookup(pattern, n), in lookup order
//	F:<hex data>:<hex pattern>:<n>     FindAllIndex(regexp.Compile(pattern), n)
//
// A Go panic is reported as "panic". A pattern that does not compile is
// reported as "regex-error". Empty results print as "none".
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"index/suffixarray"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func decode(text string) []byte {
	b, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return b
}

func process(line string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "panic"
		}
	}()
	parts := strings.Split(line, ":")
	switch parts[0] {
	case "W":
		x := suffixarray.New(decode(parts[1]))
		var buf bytes.Buffer
		if err := x.Write(&buf); err != nil {
			return "err:" + err.Error()
		}
		return hex.EncodeToString(buf.Bytes())
	case "R":
		var x suffixarray.Index
		if err := x.Read(bytes.NewReader(decode(parts[1]))); err != nil {
			return "err:" + err.Error()
		}
		var buf bytes.Buffer
		if err := x.Write(&buf); err != nil {
			return "err:" + err.Error()
		}
		return "ok:" + hex.EncodeToString(buf.Bytes())
	case "L":
		n, _ := strconv.Atoi(parts[3])
		x := suffixarray.New(decode(parts[1]))
		res := x.Lookup(decode(parts[2]), n)
		if len(res) == 0 {
			return "none"
		}
		items := make([]string, len(res))
		for i, v := range res {
			items[i] = strconv.Itoa(v)
		}
		return strings.Join(items, ",")
	case "F":
		n, _ := strconv.Atoi(parts[3])
		rx, err := regexp.Compile(string(decode(parts[2])))
		if err != nil {
			return "regex-error"
		}
		x := suffixarray.New(decode(parts[1]))
		res := x.FindAllIndex(rx, n)
		if len(res) == 0 {
			return "none"
		}
		items := make([]string, len(res))
		for i, m := range res {
			items[i] = fmt.Sprintf("%d-%d", m[0], m[1])
		}
		return strings.Join(items, ",")
	}
	panic("bad request " + line)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<28)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, process(in.Text()))
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
