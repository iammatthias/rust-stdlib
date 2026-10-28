// Go reference implementation for tools/log_check.py (log/syslog half).
//
// argv: network raddr. Each stdin line is a JSON scenario with a priority, a
// tag and a list of operations; messages are delivered to the harness's
// listener at raddr.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/syslog"
	"os"
	"time"
)

type scenario struct {
	Priority int        `json:"priority"`
	Tag      string     `json:"tag"`
	Ops      [][]string `json:"ops"`
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(2)
}

func main() {
	network, raddr := os.Args[1], os.Args[2]
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<26)
	for in.Scan() {
		var s scenario
		if err := json.Unmarshal(in.Bytes(), &s); err != nil {
			fail("bad scenario: %v", err)
		}
		w, err := syslog.Dial(network, raddr, syslog.Priority(s.Priority), s.Tag)
		if err != nil {
			fmt.Println("dial-error:", err)
			continue
		}
		for _, op := range s.Ops {
			var err error
			switch op[0] {
			case "emerg":
				err = w.Emerg(op[1])
			case "alert":
				err = w.Alert(op[1])
			case "crit":
				err = w.Crit(op[1])
			case "err":
				err = w.Err(op[1])
			case "warning":
				err = w.Warning(op[1])
			case "notice":
				err = w.Notice(op[1])
			case "info":
				err = w.Info(op[1])
			case "debug":
				err = w.Debug(op[1])
			case "write":
				_, err = w.Write([]byte(op[1]))
			default:
				fail("unknown op %q", op[0])
			}
			if err != nil {
				fmt.Println("op-error:", err)
			}
			if network == "unixgram" {
				// Unix datagram queues are tiny and Go's sockets never block.
				time.Sleep(2 * time.Millisecond)
			}
		}
		w.Close()
	}
	// Invalid priorities are rejected before any connection.
	for _, p := range []int{-1, 192, 1000} {
		_, err := syslog.Dial(network, raddr, syslog.Priority(p), "x")
		fmt.Println("invalid", p, err)
	}
}
