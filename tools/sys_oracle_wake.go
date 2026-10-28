// Cross-goroutine deadline and Close wake-up scenarios of the rust_stdlib_sys
// Go differential; built together with sys_oracle.go. Each scenario blocks a
// call (read, write, accept) on one goroutine, changes a deadline or closes
// the descriptor from another, and reports the error plus whether the blocked
// call returned promptly after the change.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

// wakeSubject is the blocked end of a wake scenario.
type wakeSubject struct {
	block    func() error
	setRead  func(time.Time) error
	setWrite func(time.Time) error
	setBoth  func(time.Time) error
	close    func() error
	// poke makes the blocked call able to return successfully.
	poke func()
	// cleanup releases the rest of the fixture.
	cleanup func()
	write   bool
}

type deadliner interface {
	SetDeadline(time.Time) error
}

func connSubject(c net.Conn, write bool, poke func(), cleanup func()) *wakeSubject {
	s := &wakeSubject{
		setRead: c.SetReadDeadline, setWrite: c.SetWriteDeadline, setBoth: c.SetDeadline,
		close: c.Close, poke: poke, cleanup: cleanup, write: write,
	}
	if write {
		s.block = func() error {
			buf := make([]byte, 1<<20)
			for {
				if _, err := c.Write(buf); err != nil {
					return err
				}
			}
		}
	} else {
		s.block = func() error {
			_, err := c.Read(make([]byte, 8))
			return err
		}
	}
	return s
}

func wakeSetup(kind string) *wakeSubject {
	switch kind {
	case "tcp_read", "tcp_write":
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		ch := make(chan net.Conn, 1)
		go func() {
			c, _ := ln.Accept()
			ch <- c
		}()
		c, _ := net.Dial("tcp", ln.Addr().String())
		srv := <-ch
		return connSubject(c, kind == "tcp_write", func() { srv.Write([]byte("x")) },
			func() { c.Close(); srv.Close(); ln.Close() })
	case "udp_read":
		pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
		addr := pc.LocalAddr().String()
		return &wakeSubject{
			block: func() error {
				_, _, err := pc.ReadFrom(make([]byte, 8))
				return err
			},
			setRead: pc.SetReadDeadline, setWrite: pc.SetWriteDeadline, setBoth: pc.SetDeadline,
			close: pc.Close,
			poke: func() {
				if c, err := net.Dial("udp", addr); err == nil {
					c.Write([]byte("x"))
					c.Close()
				}
			},
			cleanup: func() { pc.Close() },
		}
	case "unix_read", "unix_write":
		os.Remove("wk.sock")
		ln, _ := net.Listen("unix", "wk.sock")
		ch := make(chan net.Conn, 1)
		go func() {
			c, _ := ln.Accept()
			ch <- c
		}()
		c, _ := net.Dial("unix", "wk.sock")
		srv := <-ch
		return connSubject(c, kind == "unix_write", func() { srv.Write([]byte("x")) },
			func() { c.Close(); srv.Close(); ln.Close() })
	case "unixgram_read":
		os.Remove("wg.sock")
		pc, _ := net.ListenPacket("unixgram", "wg.sock")
		return &wakeSubject{
			block: func() error {
				_, _, err := pc.ReadFrom(make([]byte, 8))
				return err
			},
			setRead: pc.SetReadDeadline, setWrite: pc.SetWriteDeadline, setBoth: pc.SetDeadline,
			close: pc.Close,
			poke: func() {
				if c, err := net.Dial("unixgram", "wg.sock"); err == nil {
					c.Write([]byte("x"))
					c.Close()
				}
			},
			cleanup: func() { pc.Close() },
		}
	case "tcp_accept", "unix_accept":
		network, addr := "tcp", "127.0.0.1:0"
		if kind == "unix_accept" {
			os.Remove("wa.sock")
			network, addr = "unix", "wa.sock"
		}
		ln, _ := net.Listen(network, addr)
		target := ln.Addr().String()
		d := ln.(deadliner)
		return &wakeSubject{
			block: func() error {
				_, err := ln.Accept()
				return err
			},
			setRead: d.SetDeadline, setWrite: d.SetDeadline, setBoth: d.SetDeadline,
			close: ln.Close,
			poke: func() {
				if c, err := net.Dial(network, target); err == nil {
					time.Sleep(300 * time.Millisecond)
					c.Close()
				}
			},
			cleanup: func() { ln.Close() },
		}
	}
	return nil
}

func runWake(f []string) string {
	if f[0] != "wake" {
		return "unknown scenario " + f[0]
	}
	kind, how := f[1], f[2]
	s := wakeSetup(kind)
	if s == nil {
		return "no such kind " + kind
	}
	defer s.cleanup()
	set := s.setRead
	if s.write {
		set = s.setWrite
	}
	var action func()
	lo, hi := 0, 40
	switch how {
	case "now":
		action = func() { set(time.Now()) }
	case "both":
		action = func() { s.setBoth(time.Now()) }
	case "past":
		action = func() { set(time.Now().Add(-time.Hour)) }
	case "shorten":
		set(time.Now().Add(10 * time.Second))
		action = func() { set(time.Now().Add(20 * time.Millisecond)) }
		lo, hi = 15, 60
	case "close":
		action = func() { s.close() }
	case "extend", "clear":
		set(time.Now().Add(400 * time.Millisecond))
		action = func() {
			if how == "extend" {
				set(time.Now().Add(10 * time.Second))
			} else {
				set(time.Time{})
			}
		}
		go func() {
			time.Sleep(500 * time.Millisecond)
			s.poke()
		}()
	default:
		return "no such trigger " + how
	}
	t0c := make(chan time.Time, 1)
	go func() {
		if how == "extend" || how == "clear" {
			time.Sleep(15 * time.Millisecond)
		} else {
			time.Sleep(50 * time.Millisecond)
		}
		t0 := time.Now()
		action()
		t0c <- t0
	}()
	start := time.Now()
	err := s.block()
	t1 := time.Now()
	t0 := <-t0c
	out := errText(err)
	if how == "extend" || how == "clear" {
		// The call must outlive the original 400 ms deadline and end with the data.
		return out + fmt.Sprintf(" waited=%v", t1.Sub(start) >= 380*time.Millisecond)
	}
	el := t1.Sub(t0)
	out += fmt.Sprintf(" timely=%v", t1.After(t0) && el >= time.Duration(lo)*time.Millisecond && el < time.Duration(hi)*time.Millisecond)
	if how == "close" {
		out += " close2=" + errText(s.close())
		out += " after=" + errText(s.block())
		out += " setdl=" + errText(s.setBoth(time.Now().Add(time.Second)))
	}
	return out
}
