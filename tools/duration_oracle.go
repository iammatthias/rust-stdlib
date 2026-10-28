// Go reference implementation for tools/duration_check.py.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type result struct {
	OK     bool   `json:"ok"`
	Nanos  int64  `json:"nanos"`
	String string `json:"string"`
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		duration, err := time.ParseDuration(in.Text())
		var value any = map[string]bool{"ok": false}
		if err == nil {
			value = result{OK: true, Nanos: int64(duration), String: duration.String()}
		}
		if err := json.NewEncoder(out).Encode(value); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
