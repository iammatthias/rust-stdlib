package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"strings"
)

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 1<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		fields := strings.Split(s.Text(), "\t")
		get := func(i int) string {
			if i < len(fields) {
				return fields[i]
			}
			return ""
		}
		op := get(0)
		aBytes, err := hex.DecodeString(get(1))
		if err != nil {
			panic(err)
		}
		a := string(aBytes)
		encode := func(s string) string { return hex.EncodeToString([]byte(s)) }
		var result string
		switch op {
		case "C":
			result = "C|" + encode(path.Clean(a))
		case "S":
			d, f := path.Split(a)
			result = "S|" + encode(d) + "|" + encode(f)
		case "B":
			result = "B|" + encode(path.Base(a))
		case "D":
			result = "D|" + encode(path.Dir(a))
		case "E":
			result = "E|" + encode(path.Ext(a))
		case "A":
			result = fmt.Sprintf("A|%t", path.IsAbs(a))
		case "J":
			parts := make([]string, 0, len(fields)-1)
			for _, value := range fields[1:] {
				b, e := hex.DecodeString(value)
				if e != nil {
					panic(e)
				}
				parts = append(parts, string(b))
			}
			result = "J|" + encode(path.Join(parts...))
		case "M":
			nameBytes, e := hex.DecodeString(get(2))
			if e != nil {
				panic(e)
			}
			matched, e := path.Match(a, string(nameBytes))
			if e != nil {
				result = "M|error"
			} else {
				result = fmt.Sprintf("M|%t", matched)
			}
		default:
			panic("unknown operation")
		}
		fmt.Fprintln(w, result)
	}
	if err := s.Err(); err != nil {
		panic(err)
	}
}
