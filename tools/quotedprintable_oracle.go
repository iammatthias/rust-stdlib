package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	qp "mime/quotedprintable"
	"os"
	"strings"
)

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 16*1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		fields := strings.SplitN(s.Text(), " ", 2)
		if len(fields) != 2 {
			panic("invalid oracle input")
		}
		op, raw := fields[0], fields[1]
		if raw == "-" {
			raw = ""
		}
		b, e := hex.DecodeString(raw)
		if e != nil {
			panic(e)
		}
		var out []byte
		var err error
		if strings.HasPrefix(op, "decode") {
			out, err = io.ReadAll(qp.NewReader(strings.NewReader(string(b))))
		} else {
			var dst strings.Builder
			wr := qp.NewWriter(&dst)
			wr.Binary = strings.HasSuffix(op, "binary")
			_, err = wr.Write(b)
			if err == nil {
				err = wr.Close()
			}
			out = []byte(dst.String())
		}
		msg := "-"
		if err != nil {
			msg = err.Error()
		}
		fmt.Fprintf(w, "%s\t%s\n", hex.EncodeToString(out), hex.EncodeToString([]byte(msg)))
	}
	if e := s.Err(); e != nil {
		panic(e)
	}
}
