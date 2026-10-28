// Standalone standard-library HTML escape and unescape differential oracle.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"html"
)

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 16*1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		var request struct {
			Op    string `json:"op"`
			Input string `json:"input"`
		}
		if err := json.Unmarshal(s.Bytes(), &request); err != nil {
			panic(err)
		}
		var result string
		switch request.Op {
		case "escape":
			result = html.EscapeString(request.Input)
		case "unescape":
			result = html.UnescapeString(request.Input)
		default:
			panic(fmt.Sprintf("unknown op %q", request.Op))
		}
		out, err := json.Marshal(result)
		if err != nil {
			panic(err)
		}
		w.Write(out)
		w.WriteByte('\n')
	}
	if err := s.Err(); err != nil {
		panic(err)
	}
}
