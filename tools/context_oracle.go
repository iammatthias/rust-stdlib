// Line-oriented Go context oracle for tools/context_check.py.
//
// Each input line is a script of whitespace-separated operations over a tree
// of contexts (id 0 is Background); each output line is the resulting trace.
// Scripts run concurrently so their real-time sleeps overlap.
//
//	cancel P | cause P | dl P ms | dlc P ms | dd P ms | ddc P ms
//	val P K V | woc P | af P | x I | xc I NAME | stop A | sleep ms | snap
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type node struct {
	ctx    context.Context
	cancel context.CancelFunc
	causeF context.CancelCauseFunc
}

var deadlineText = regexp.MustCompile(`\.WithDeadline\([^\]]*\]\)`)

func errName(err error) string {
	switch err {
	case nil:
		return "nil"
	case context.Canceled:
		return "canceled"
	case context.DeadlineExceeded:
		return "deadline"
	}
	return "other:" + err.Error()
}

func run(script string) string {
	toks := strings.Fields(script)
	nodes := []node{{ctx: context.Background()}}
	var stops []func() bool
	var mu sync.Mutex
	fired := map[int]bool{}
	var log []string
	num := func(i int) int {
		n, err := strconv.Atoi(toks[i])
		if err != nil {
			panic(err)
		}
		return n
	}
	snap := func(final bool) {
		var parts []string
		for i, n := range nodes {
			dl := "0"
			if _, ok := n.ctx.Deadline(); ok {
				dl = "1"
			}
			var vs []string
			for _, k := range []string{"k0", "k1", "k2"} {
				if v, ok := n.ctx.Value(k).(string); ok {
					vs = append(vs, v)
				} else {
					vs = append(vs, "-")
				}
			}
			cause := "nil"
			if c := context.Cause(n.ctx); c != nil {
				cause = c.Error()
			}
			never := "0"
			if n.ctx.Done() == nil {
				never = "1"
			}
			parts = append(parts, fmt.Sprintf("%d:E%s/C%s/D%s/N%s/V%s/S%s", i, errName(n.ctx.Err()), cause, dl, never,
				strings.Join(vs, ","), deadlineText.ReplaceAllString(fmt.Sprint(n.ctx), ".WithDeadline(*)")))
		}
		if final {
			mu.Lock()
			var ids []int
			for id := range fired {
				ids = append(ids, id)
			}
			mu.Unlock()
			sort.Ints(ids)
			parts = append(parts, fmt.Sprint("fired", ids))
		}
		log = append(log, strings.Join(parts, " "))
	}
	for i := 0; i < len(toks); {
		add := func(c context.Context, cancel context.CancelFunc, cf context.CancelCauseFunc) {
			nodes = append(nodes, node{c, cancel, cf})
		}
		switch toks[i] {
		case "cancel":
			c, f := context.WithCancel(nodes[num(i+1)].ctx)
			add(c, f, nil)
			i += 2
		case "cause":
			c, f := context.WithCancelCause(nodes[num(i+1)].ctx)
			add(c, nil, f)
			i += 2
		case "dl", "dlc", "dd", "ddc":
			p := nodes[num(i+1)].ctx
			d := time.Duration(num(i+2)) * time.Millisecond
			cause := errors.New("dlcause" + strconv.Itoa(len(nodes)))
			var c context.Context
			var f context.CancelFunc
			switch toks[i] {
			case "dl":
				c, f = context.WithTimeout(p, d)
			case "dlc":
				c, f = context.WithTimeoutCause(p, d, cause)
			case "dd":
				c, f = context.WithDeadline(p, time.Now().Add(d))
			default:
				c, f = context.WithDeadlineCause(p, time.Now().Add(d), cause)
			}
			if pd, ok := p.Deadline(); ok {
				cd, _ := c.Deadline()
				log = append(log, fmt.Sprintf("inherit%d=%v", len(nodes), cd.Equal(pd)))
			}
			add(c, f, nil)
			i += 3
		case "val":
			c := context.WithValue(nodes[num(i+1)].ctx, "k"+toks[i+2], toks[i+3])
			add(c, nil, nil)
			i += 4
		case "woc":
			add(context.WithoutCancel(nodes[num(i+1)].ctx), nil, nil)
			i += 2
		case "af":
			id := len(stops)
			stops = append(stops, context.AfterFunc(nodes[num(i+1)].ctx, func() {
				mu.Lock()
				fired[id] = true
				mu.Unlock()
			}))
			i += 2
		case "x":
			n := nodes[num(i+1)]
			if n.cancel != nil {
				n.cancel()
			} else if n.causeF != nil {
				n.causeF(nil)
			}
			i += 2
		case "xc":
			n := nodes[num(i+1)]
			if n.causeF != nil {
				n.causeF(errors.New(toks[i+2]))
			} else if n.cancel != nil {
				n.cancel()
			}
			i += 3
		case "stop":
			log = append(log, fmt.Sprintf("stop%d=%v", num(i+1), stops[num(i+1)]()))
			i += 2
		case "sleep":
			time.Sleep(time.Duration(num(i+1)) * time.Millisecond)
			i += 2
		case "snap":
			snap(false)
			i++
		default:
			panic("bad op " + toks[i])
		}
	}
	time.Sleep(60 * time.Millisecond)
	snap(true)
	return strings.Join(log, " | ")
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	var scripts []string
	for in.Scan() {
		scripts = append(scripts, in.Text())
	}
	results := make([]string, len(scripts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 256)
	for i, s := range scripts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, s string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = run(s)
		}(i, s)
	}
	wg.Wait()
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for _, r := range results {
		fmt.Fprintln(out, r)
	}
}
