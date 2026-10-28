// Go reference implementation for tools/log_check.py (log half).
//
// Go's log package has no clock hook, so every scenario runs in a
// testing/synctest bubble whose fake clock starts at 2000-01-01T00:00:00Z and
// is advanced to the requested instant with time.Sleep. testing.Main is the
// only way to obtain a *testing.T outside `go test`; result lines are marked
// "R:" so the harness can ignore testing's own "PASS" line.
//
// The harness sets TZ and ZONEINFO for both sides, so Local is the same zone.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"testing"
	"testing/synctest"
	"time"
)

type scenario struct {
	Flags  int    `json:"flags"`
	Prefix string `json:"prefix"`
	Msg    string `json:"msg"`
	Delay  string `json:"delay"`
	Call   string `json:"call"`
	Pkg    bool   `json:"pkg"`
}

func run(t *testing.T, s scenario) string {
	var out string
	synctest.Test(t, func(t *testing.T) {
		delay, err := strconv.ParseInt(s.Delay, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Duration(delay))
		var buf bytes.Buffer
		var l *log.Logger
		if s.Pkg {
			log.SetOutput(&buf)
			log.SetFlags(s.Flags)
			log.SetPrefix(s.Prefix)
			defer log.SetOutput(os.Stderr)
			l = log.Default()
		} else {
			l = log.New(&buf, s.Prefix, s.Flags)
		}
		switch {
		case s.Pkg && s.Call == "print":
			log.Print(s.Msg)
		case s.Pkg && s.Call == "printf":
			log.Printf("%s", s.Msg)
		case s.Pkg && s.Call == "println":
			log.Println(s.Msg)
		case s.Pkg && s.Call == "output":
			log.Output(1, s.Msg)
		case s.Call == "print":
			l.Print(s.Msg)
		case s.Call == "printf":
			l.Printf("%s", s.Msg)
		case s.Call == "println":
			l.Println(s.Msg)
		case s.Call == "output":
			l.Output(1, s.Msg)
		default:
			t.Fatalf("unknown call %q", s.Call)
		}
		out = fmt.Sprintf("%d|%s|%s", l.Flags(), hex.EncodeToString([]byte(l.Prefix())), hex.EncodeToString(buf.Bytes()))
	})
	return out
}

func main() {
	var scenarios []scenario
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<26)
	for in.Scan() {
		var s scenario
		if err := json.Unmarshal(in.Bytes(), &s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		scenarios = append(scenarios, s)
	}
	out := bufio.NewWriter(os.Stdout)
	tests := []testing.InternalTest{{Name: "Scenarios", F: func(t *testing.T) {
		for _, s := range scenarios {
			fmt.Fprintf(out, "R:%s\n", run(t, s))
		}
		out.Flush()
	}}}
	testing.Main(func(pat, str string) (bool, error) { return true, nil }, tests, nil, nil)
}
