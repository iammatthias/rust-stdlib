package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 16*1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		p := strings.Fields(s.Text())
		if len(p) != 6 && len(p) != 7 {
			panic("invalid input")
		}
		v := make([]int, 5)
		for i := 0; i < 3; i++ {
			x, e := strconv.Atoi(p[i])
			if e != nil {
				panic(e)
			}
			v[i] = x
		}
		pcb, e := hex.DecodeString(p[3])
		if e != nil {
			panic(e)
		}
		flags, e := strconv.Atoi(p[4])
		if e != nil {
			panic(e)
		}
		data, e := hex.DecodeString(strings.TrimPrefix(p[5], "-"))
		if e != nil {
			panic(e)
		}
		var out bytes.Buffer
		var tw *tabwriter.Writer
		if len(p) == 7 {
			// A reused writer: unflushed text and configuration must not survive Init.
			reuse, e := hex.DecodeString(strings.TrimPrefix(p[6], "-"))
			if e != nil {
				panic(e)
			}
			stale := tabwriter.NewWriter(io.Discard, 0, 8, 3, '#', uint(tabwriter.FilterHTML))
			stale.Write(reuse)
			tw = stale.Init(&out, v[0], v[1], v[2], pcb[0], uint(flags))
		} else {
			tw = tabwriter.NewWriter(&out, v[0], v[1], v[2], pcb[0], uint(flags))
		}
		_, err := tw.Write(data)
		if err == nil {
			err = tw.Flush()
		}
		msg := "-"
		if err != nil {
			msg = err.Error()
		}
		fmt.Fprintf(w, "%s\t%s\n", hex.EncodeToString(out.Bytes()), hex.EncodeToString([]byte(msg)))
	}
}
