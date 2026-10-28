// Go os/signal oracle for tools/signal_check.py: a process driven over stdin.
//
//	pid                       prints the process id
//	chan <name> <cap>         make(chan os.Signal, cap)
//	notify <name> <sigs>      signal.Notify; <sigs> is a comma list of names
//	                          (HUP, INT, USR1, ...) or "-" for none (all signals)
//	stop <name>               signal.Stop
//	ignore <sigs>             signal.Ignore
//	reset <sigs>              signal.Reset
//	ignored <sig>             prints signal.Ignored
//	ctx <name> <sigs>         signal.NotifyContext(context.Background(), ...)
//	ctxstop <name>            the stop function
//	ctxinfo <name>            prints "err=... cause=... str=..."
//	drain <name>              waits briefly, prints and clears the signals
//	                          the channel has received
//
// Every command prints one line.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var names = map[string]os.Signal{
	"HUP": syscall.SIGHUP, "INT": syscall.SIGINT, "QUIT": syscall.SIGQUIT, "USR1": syscall.SIGUSR1,
	"USR2": syscall.SIGUSR2, "ALRM": syscall.SIGALRM, "TERM": syscall.SIGTERM, "WINCH": syscall.SIGWINCH,
	"URG": syscall.SIGURG, "CHLD": syscall.SIGCHLD, "KILL": syscall.SIGKILL, "STOP": syscall.SIGSTOP,
	"CONT": syscall.SIGCONT,
}

func sigs(s string) []os.Signal {
	if s == "-" || s == "" {
		return nil
	}
	var out []os.Signal
	for _, n := range strings.Split(s, ",") {
		if sig, ok := names[n]; ok {
			out = append(out, sig)
		} else if v, err := strconv.Atoi(n); err == nil {
			out = append(out, syscall.Signal(v))
		} else {
			panic("unknown signal " + n)
		}
	}
	return out
}

type ctxEntry struct {
	ctx  context.Context
	stop context.CancelFunc
}

func main() {
	chans := map[string]chan os.Signal{}
	ctxs := map[string]ctxEntry{}
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		f := strings.Fields(in.Text())
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "pid":
			fmt.Println(os.Getpid())
		case "chan":
			n, _ := strconv.Atoi(f[2])
			chans[f[1]] = make(chan os.Signal, n)
			fmt.Println("ok")
		case "notify":
			signal.Notify(chans[f[1]], sigs(f[2])...)
			fmt.Println("ok")
		case "stop":
			signal.Stop(chans[f[1]])
			fmt.Println("ok")
		case "ignore":
			signal.Ignore(sigs(f[1])...)
			fmt.Println("ok")
		case "reset":
			signal.Reset(sigs(f[1])...)
			fmt.Println("ok")
		case "ignored":
			fmt.Println(signal.Ignored(sigs(f[1])[0]))
		case "ctx":
			ctx, stop := signal.NotifyContext(context.Background(), sigs(f[2])...)
			ctxs[f[1]] = ctxEntry{ctx, stop}
			fmt.Println("ok")
		case "ctxstop":
			ctxs[f[1]].stop()
			fmt.Println("ok")
		case "ctxinfo":
			e := ctxs[f[1]]
			time.Sleep(40 * time.Millisecond)
			fmt.Printf("err=%v cause=%v str=%v\n", e.ctx.Err(), context.Cause(e.ctx), e.ctx)
		case "drain":
			time.Sleep(40 * time.Millisecond)
			var got []string
			for {
				select {
				case s := <-chans[f[1]]:
					got = append(got, s.String())
					continue
				default:
				}
				break
			}
			fmt.Println(strings.Join(got, ","))
		default:
			fmt.Println("unknown command")
		}
	}
}
