// Scenario oracle for tools/conn_check.py: live loopback TCP, UDP, Unix and
// net.Pipe scripts. Each input line is "<scenario> [args]"; the reply is one
// line of " ; "-separated observations (errors by class and exact text, with
// ephemeral ports normalised by the checker). Mirrors examples/conn_probe.rs.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func cls(err error) string {
	switch {
	case err == nil:
		return "nil"
	case errors.Is(err, net.ErrClosed):
		return "closed"
	case errors.Is(err, io.EOF):
		return "eof"
	case errors.Is(err, io.ErrClosedPipe):
		return "closedpipe"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	if strings.Contains(err.Error(), "connection refused") {
		return "refused"
	}
	return "other"
}

func ob(label string, err error) string {
	if err == nil {
		return label + "=nil"
	}
	return label + "=" + cls(err) + "(" + err.Error() + ")"
}

func obp(label string, err error, path string) string {
	return strings.ReplaceAll(ob(label, err), path, "PATH")
}

func addrs(prefix string, c net.Conn) []string {
	return []string{
		prefix + ".local=" + c.LocalAddr().Network() + " " + c.LocalAddr().String(),
		prefix + ".remote=" + c.RemoteAddr().Network() + " " + c.RemoteAddr().String(),
	}
}

func payload(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 3)
	}
	return b
}

func tcpEcho(n int) []string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return []string{ob("listen", err)}
	}
	defer ln.Close()
	tr := []string{"listener=" + ln.Addr().Network() + " " + ln.Addr().String()}
	srv := make(chan []string, 1)
	go func() {
		var t []string
		c, err := ln.Accept()
		if err != nil {
			srv <- []string{ob("accept", err)}
			return
		}
		defer c.Close()
		t = append(t, addrs("srv", c)...)
		buf := make([]byte, n)
		_, err = io.ReadFull(c, buf)
		t = append(t, ob("srv.readfull", err))
		_, err = c.Write(buf)
		t = append(t, ob("srv.write", err))
		k, err := c.Read(make([]byte, 8))
		t = append(t, "srv.read="+strconv.Itoa(k)+" "+cls(err))
		_, err = c.Write([]byte("bye"))
		t = append(t, ob("srv.bye", err))
		srv <- t
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return append(tr, ob("dial", err))
	}
	defer c.Close()
	tc := c.(*net.TCPConn)
	tr = append(tr, addrs("cli", c)...)
	w := payload(n)
	_, err = c.Write(w)
	tr = append(tr, ob("cli.write", err))
	got := make([]byte, n)
	_, err = io.ReadFull(c, got)
	tr = append(tr, ob("cli.readfull", err), "equal="+strconv.FormatBool(bytes.Equal(w, got)))
	tr = append(tr, ob("closewrite", tc.CloseWrite()))
	bye := make([]byte, 8)
	k, err := io.ReadFull(c, bye)
	tr = append(tr, "cli.bye="+string(bye[:k])+" "+cls(err))
	k, err = c.Read(bye)
	tr = append(tr, "cli.after="+strconv.Itoa(k)+" "+cls(err))
	tr = append(tr, ob("nodelay", tc.SetNoDelay(false)))
	return append(tr, <-srv...)
}

func tcpDeadline(ms int) []string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() { c, _ := ln.Accept(); acc <- c }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return []string{ob("dial", err)}
	}
	defer c.Close()
	s := <-acc
	defer s.Close()
	var tr []string
	start := time.Now()
	c.SetReadDeadline(start.Add(time.Duration(ms) * time.Millisecond))
	_, err = c.Read(make([]byte, 4))
	el := time.Since(start)
	tr = append(tr, ob("read1", err), "waited="+strconv.FormatBool(el >= time.Duration(ms)*time.Millisecond && el < time.Duration(ms+400)*time.Millisecond))
	_, err = c.Read(make([]byte, 4))
	tr = append(tr, ob("read2", err))
	c.SetReadDeadline(time.Time{})
	s.Write([]byte("hi"))
	b := make([]byte, 4)
	k, err := c.Read(b)
	tr = append(tr, "read3="+string(b[:k])+" "+cls(err))
	c.SetDeadline(time.Now().Add(-time.Second))
	_, err = c.Write([]byte("x"))
	tr = append(tr, ob("write-past", err))
	_, err = c.Read(b)
	tr = append(tr, ob("read-past", err))
	return tr
}

func tcpRefused() []string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	_, err := net.Dial("tcp", addr)
	tr := []string{ob("dial", err)}
	var oe *net.OpError
	if errors.As(err, &oe) {
		tr = append(tr, "op="+oe.Op, "net="+oe.Net, "addr="+oe.Addr.String(), "timeout="+strconv.FormatBool(oe.Timeout()))
	}
	_, err = net.DialTimeout("tcp", addr, time.Second)
	tr = append(tr, ob("dialtimeout", err))
	return tr
}

func tcpClosed() []string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { c, _ := ln.Accept(); if c != nil { defer c.Close(); io.Copy(io.Discard, c) } }()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return []string{ob("dial", err)}
	}
	tr := []string{ob("close1", c.Close())}
	_, err = c.Read(make([]byte, 1))
	tr = append(tr, ob("read", err))
	_, err = c.Write([]byte("x"))
	tr = append(tr, ob("write", err))
	tr = append(tr, ob("close2", c.Close()))
	tr = append(tr, ob("setdeadline", c.SetDeadline(time.Now())))
	tr = append(tr, ob("closeread", c.(*net.TCPConn).CloseRead()))
	return tr
}

func tcpAcceptClose() []string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	res := make(chan error, 1)
	go func() { _, err := ln.Accept(); res <- err }()
	time.Sleep(50 * time.Millisecond)
	tr := []string{ob("close", ln.Close())}
	tr = append(tr, ob("accept", <-res))
	tr = append(tr, ob("close2", ln.Close()))
	_, err := ln.Accept()
	tr = append(tr, ob("accept2", err))
	return tr
}

func tcpAcceptDeadline() []string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Millisecond))
	_, err := ln.Accept()
	tr := []string{ob("accept", err)}
	ln.(*net.TCPListener).SetDeadline(time.Time{})
	go func() { c, err := net.Dial("tcp", ln.Addr().String()); if err == nil { defer c.Close(); time.Sleep(100 * time.Millisecond) } }()
	c, err := ln.Accept()
	tr = append(tr, ob("accept2", err))
	if c != nil {
		c.Close()
	}
	return tr
}

func tcpReadClose() []string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { c, _ := ln.Accept(); if c != nil { defer c.Close(); time.Sleep(time.Second) } }()
	c, _ := net.Dial("tcp", ln.Addr().String())
	res := make(chan error, 1)
	go func() { _, err := c.Read(make([]byte, 1)); res <- err }()
	time.Sleep(50 * time.Millisecond)
	c.Close()
	tr := []string{ob("read", <-res)}
	// Deadline interrupt of a blocked read.
	c2, _ := net.Dial("tcp", ln.Addr().String())
	defer c2.Close()
	go func() { _, err := c2.Read(make([]byte, 1)); res <- err }()
	time.Sleep(50 * time.Millisecond)
	c2.SetReadDeadline(time.Now())
	tr = append(tr, ob("interrupted", <-res))
	return tr
}

// tcpWake blocks a read and an accept, then wakes each from another goroutine
// with a deadline change or Close; the harness asserts the calls return within
// a small bound of the change (the std-based Rust types poll every ~50 ms).
func tcpWake(how string) []string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { c, _ := ln.Accept(); if c != nil { defer c.Close(); time.Sleep(time.Second) } }()
	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln2.Close()
	tl := ln2.(*net.TCPListener)
	var tr []string
	wake := func(label string, set func(time.Time), closeFn func(), block func() error) {
		var t0 time.Time
		switch how {
		case "shorten":
			set(time.Now().Add(10 * time.Second))
		}
		done := make(chan struct{})
		go func() {
			time.Sleep(50 * time.Millisecond)
			t0 = time.Now()
			switch how {
			case "now":
				set(time.Now())
			case "shorten":
				set(time.Now().Add(20 * time.Millisecond))
			case "close":
				closeFn()
			}
			close(done)
		}()
		err := block()
		t1 := time.Now()
		<-done
		tr = append(tr, ob(label, err), fmt.Sprintf("%s-timely=%v", label, t1.After(t0) && t1.Sub(t0) < 250*time.Millisecond))
	}
	wake("read", func(t time.Time) { c.SetReadDeadline(t) }, func() { c.Close() },
		func() error { _, err := c.Read(make([]byte, 1)); return err })
	wake("accept", func(t time.Time) { tl.SetDeadline(t) }, func() { ln2.Close() },
		func() error { _, err := ln2.Accept(); return err })
	return tr
}

func tcpInUse() []string {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	_, err := net.Listen("tcp", ln.Addr().String())
	return []string{ob("listen2", err)}
}

func udpEcho(n int) []string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return []string{ob("listen", err)}
	}
	defer pc.Close()
	tr := []string{"local=" + pc.LocalAddr().Network() + " " + pc.LocalAddr().String()}
	go func() {
		buf := make([]byte, 2048)
		k, a, err := pc.ReadFrom(buf)
		if err == nil {
			pc.WriteTo(buf[:k], a)
		}
	}()
	c, err := net.Dial("udp", pc.LocalAddr().String())
	if err != nil {
		return append(tr, ob("dial", err))
	}
	defer c.Close()
	tr = append(tr, addrs("cli", c)...)
	w := payload(n)
	k, err := c.Write(w)
	tr = append(tr, "write="+strconv.Itoa(k)+" "+cls(err))
	buf := make([]byte, 2048)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	k, err = c.Read(buf)
	tr = append(tr, "read="+strconv.Itoa(k)+" "+cls(err), "equal="+strconv.FormatBool(bytes.Equal(w, buf[:k])))
	c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err = c.Read(buf)
	tr = append(tr, ob("read2", err))
	return tr
}

func udpConnected() []string {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	ra, _ := net.ResolveUDPAddr("udp", pc.LocalAddr().String())
	c, err := net.DialUDP("udp", nil, ra)
	if err != nil {
		return []string{ob("dial", err)}
	}
	defer c.Close()
	_, err = c.WriteTo([]byte("x"), ra)
	tr := []string{ob("writeto", err)}
	_, err = c.WriteToUDP([]byte("x"), ra)
	tr = append(tr, ob("writetoudp", err))
	_, err = c.WriteTo([]byte("x"), &net.TCPAddr{})
	tr = append(tr, ob("writeto-tcpaddr", err))
	u, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer u.Close()
	_, err = u.Write([]byte("x"))
	tr = append(tr, ob("write-unconnected", err))
	k, err := u.WriteToUDP([]byte("hello"), ra)
	tr = append(tr, "writetoudp-ok="+strconv.Itoa(k)+" "+cls(err))
	buf := make([]byte, 16)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	k, a, err := pc.ReadFrom(buf)
	tr = append(tr, "readfrom="+string(buf[:k])+" "+cls(err), "net="+a.Network())
	_, err = u.WriteToUDP([]byte("x"), nil)
	tr = append(tr, ob("writetoudp-nil", err))
	return tr
}

func unixPath() string {
	d, _ := os.MkdirTemp("", "cs")
	return filepath.Join(d, "s")
}

func unixEcho(n int) []string {
	path := unixPath()
	defer os.RemoveAll(filepath.Dir(path))
	ln, err := net.Listen("unix", path)
	if err != nil {
		return []string{ob("listen", err)}
	}
	tr := []string{"listener=" + ln.Addr().Network() + " " + strings.ReplaceAll(ln.Addr().String(), path, "PATH")}
	srv := make(chan []string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			srv <- []string{ob("accept", err)}
			return
		}
		defer c.Close()
		buf := make([]byte, n)
		_, err = io.ReadFull(c, buf)
		c.Write(buf)
		k, err2 := c.Read(make([]byte, 4))
		srv <- []string{ob("srv.readfull", err), "srv.read=" + strconv.Itoa(k) + " " + cls(err2),
			"srv.local=" + strings.ReplaceAll(c.LocalAddr().String(), path, "PATH"), "srv.remote=[" + c.RemoteAddr().String() + "]"}
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		return append(tr, ob("dial", err))
	}
	uc := c.(*net.UnixConn)
	tr = append(tr, "cli.local=["+c.LocalAddr().String()+"] "+c.LocalAddr().Network(),
		"cli.remote="+strings.ReplaceAll(c.RemoteAddr().String(), path, "PATH")+" "+c.RemoteAddr().Network())
	w := payload(n)
	c.Write(w)
	got := make([]byte, n)
	_, err = io.ReadFull(c, got)
	tr = append(tr, ob("cli.readfull", err), "equal="+strconv.FormatBool(bytes.Equal(w, got)))
	tr = append(tr, ob("closewrite", uc.CloseWrite()))
	tr = append(tr, <-srv...)
	c.Close()
	tr = append(tr, ob("lnclose", ln.Close()))
	_, serr := os.Stat(path)
	tr = append(tr, "unlinked="+strconv.FormatBool(os.IsNotExist(serr)))
	_, err = net.Dial("unix", path)
	tr = append(tr, obp("redial", err, path))
	return tr
}

func unixDgram() []string {
	path := unixPath()
	defer os.RemoveAll(filepath.Dir(path))
	pc, err := net.ListenPacket("unixgram", path)
	if err != nil {
		return []string{ob("listen", err)}
	}
	defer pc.Close()
	tr := []string{"local=" + pc.LocalAddr().Network() + " " + strings.ReplaceAll(pc.LocalAddr().String(), path, "PATH")}
	ra := &net.UnixAddr{Name: path, Net: "unixgram"}
	c, err := net.DialUnix("unixgram", nil, ra)
	if err != nil {
		return append(tr, ob("dial", err))
	}
	defer c.Close()
	k, err := c.Write([]byte("ping"))
	tr = append(tr, "write="+strconv.Itoa(k)+" "+cls(err))
	buf := make([]byte, 16)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	k, a, err := pc.ReadFrom(buf)
	if a == nil {
		tr = append(tr, "readfrom="+string(buf[:k])+" "+cls(err), "from=<nil>")
	} else {
		tr = append(tr, "readfrom="+string(buf[:k])+" "+cls(err), "from=["+a.String()+"] "+a.Network())
	}
	_, err = c.WriteTo([]byte("x"), ra)
	tr = append(tr, obp("writeto-connected", err, path))
	return tr
}

func pipeEcho(n int) []string {
	a, b := net.Pipe()
	tr := []string{"addr=" + a.LocalAddr().Network() + " " + a.LocalAddr().String() + " " + b.RemoteAddr().String()}
	done := make(chan []string, 1)
	go func() {
		buf := make([]byte, n)
		_, err := io.ReadFull(b, buf)
		_, werr := b.Write(buf)
		done <- []string{ob("srv.read", err), ob("srv.write", werr)}
	}()
	w := payload(n)
	_, err := a.Write(w)
	tr = append(tr, ob("write", err))
	got := make([]byte, n)
	_, err = io.ReadFull(a, got)
	tr = append(tr, ob("readfull", err), "equal="+strconv.FormatBool(bytes.Equal(w, got)))
	tr = append(tr, <-done...)
	tr = append(tr, ob("close-b", b.Close()))
	k, err := a.Read(make([]byte, 4))
	tr = append(tr, "read-after-remote-close="+strconv.Itoa(k)+" "+cls(err))
	_, err = a.Write([]byte("x"))
	tr = append(tr, ob("write-after-remote-close", err))
	_, err = b.Read(make([]byte, 1))
	tr = append(tr, ob("read-local-closed", err))
	tr = append(tr, ob("setdeadline-closed", a.SetDeadline(time.Now())))
	return tr
}

func pipeDeadline() []string {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	_, err := a.Read(make([]byte, 1))
	tr := []string{ob("read", err)}
	b.SetWriteDeadline(time.Now().Add(30 * time.Millisecond))
	k, err := b.Write([]byte("abc"))
	tr = append(tr, "write="+strconv.Itoa(k)+" "+cls(err)+" "+err.Error())
	a.SetReadDeadline(time.Time{})
	b.SetWriteDeadline(time.Time{})
	go func() { b.Write([]byte("hello")) }()
	buf := make([]byte, 2)
	k, err = a.Read(buf)
	tr = append(tr, "partial1="+string(buf[:k])+" "+cls(err))
	k, err = a.Read(buf)
	tr = append(tr, "partial2="+string(buf[:k])+" "+cls(err))
	k, err = a.Read(buf)
	tr = append(tr, "partial3="+string(buf[:k])+" "+cls(err))
	return tr
}

func addrErrors() []string {
	var tr []string
	for _, c := range [][2]string{{"tcp", ""}, {"foo", "x:1"}, {"tcp", "1.2.3.4"}, {"tcp", "a:b:c"}, {"tcp", "[::1]"},
		{"tcp4", "[::1]:80"}, {"tcp6", "127.0.0.1:80"}, {"udp", ":65536"}, {"ip", "127.0.0.1"}, {"unixpacket", ""}, {"tcp", "127.0.0.1:http-nope"}} {
		_, err := net.Dial(c[0], c[1])
		tr = append(tr, ob("dial("+c[0]+","+c[1]+")", err))
	}
	for _, c := range [][2]string{{"tcp", "bad:addr:x"}, {"foo", ":0"}, {"tcp", "127.0.0.1:99999"}, {"udp", "[::1"}, {"tcp4", "[::1]:0"}} {
		_, err := net.Listen(c[0], c[1])
		tr = append(tr, ob("listen("+c[0]+","+c[1]+")", err))
	}
	_, err := net.ListenPacket("tcp", ":0")
	tr = append(tr, ob("listenpacket(tcp)", err))
	return tr
}

func resolve() []string {
	var tr []string
	for _, c := range [][2]string{{"tcp", "127.0.0.1:80"}, {"tcp", "[::1]:http"}, {"tcp4", "[::1]:80"}, {"tcp", ":0"}, {"", "1.2.3.4:5"},
		{"tcp", "[fe80::1%eth0]:22"}, {"udp", "0.0.0.0:domain"}, {"udp6", "1.2.3.4:5"}, {"x", "1.2.3.4:5"}, {"tcp", "1.2.3.4:nosuchservice"},
		{"tcp", "1.2.3.4:-1"}, {"tcp", "1.2.3.4:70000"}, {"tcp", "localhost:80"}} {
		a, err := net.ResolveTCPAddr(c[0], c[1])
		if err != nil {
			tr = append(tr, ob("tcp("+c[0]+","+c[1]+")", err))
		} else {
			tr = append(tr, "tcp("+c[0]+","+c[1]+")="+a.String())
		}
		u, err := net.ResolveUDPAddr(c[0], c[1])
		if err != nil {
			tr = append(tr, ob("udp("+c[0]+","+c[1]+")", err))
		} else {
			tr = append(tr, "udp("+c[0]+","+c[1]+")="+u.String())
		}
	}
	for _, c := range [][2]string{{"ip", "1.2.3.4"}, {"ip4", "::1"}, {"ip6", "fe80::1%x"}, {"ip:1", "1.2.3.4"}, {"ip:nosuch", "1.2.3.4"}, {"", ""}} {
		a, err := net.ResolveIPAddr(c[0], c[1])
		if err != nil {
			tr = append(tr, ob("ip("+c[0]+","+c[1]+")", err))
		} else {
			tr = append(tr, "ip("+c[0]+","+c[1]+")="+a.String())
		}
	}
	for _, c := range [][2]string{{"unix", "/tmp/x"}, {"unixgram", "@a"}, {"tcp", "x"}} {
		a, err := net.ResolveUnixAddr(c[0], c[1])
		if err != nil {
			tr = append(tr, ob("unix("+c[0]+","+c[1]+")", err))
		} else {
			tr = append(tr, "unix("+c[0]+","+c[1]+")="+a.String()+" "+a.Network())
		}
	}
	for _, c := range [][2]string{{"tcp", "http"}, {"tcp", "80"}, {"udp", "domain"}, {"tcp", "nosuch"}, {"foo", "http"}, {"tcp", "70000"}, {"tcp", "-5"}, {"", "ssh"}, {"ip", "http"}, {"tcp", ""}, {"tcp", "+8"}} {
		p, err := net.LookupPort(c[0], c[1])
		if err != nil {
			tr = append(tr, ob("port("+c[0]+","+c[1]+")", err))
		} else {
			tr = append(tr, "port("+c[0]+","+c[1]+")="+strconv.Itoa(p))
		}
	}
	return tr
}

func handle(line string) []string {
	f := strings.Fields(line)
	arg := func() int {
		n, _ := strconv.Atoi(f[1])
		return n
	}
	switch f[0] {
	case "tcp_echo":
		return tcpEcho(arg())
	case "tcp_deadline":
		return tcpDeadline(arg())
	case "tcp_refused":
		return tcpRefused()
	case "tcp_closed":
		return tcpClosed()
	case "tcp_accept_close":
		return tcpAcceptClose()
	case "tcp_accept_deadline":
		return tcpAcceptDeadline()
	case "tcp_read_close":
		return tcpReadClose()
	case "tcp_wake":
		return tcpWake(f[1])
	case "tcp_in_use":
		return tcpInUse()
	case "udp_echo":
		return udpEcho(arg())
	case "udp_connected":
		return udpConnected()
	case "unix_echo":
		return unixEcho(arg())
	case "unix_dgram":
		return unixDgram()
	case "pipe_echo":
		return pipeEcho(arg())
	case "pipe_deadline":
		return pipeDeadline()
	case "addr_errors":
		return addrErrors()
	case "resolve":
		return resolve()
	}
	panic("unknown scenario " + f[0])
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, strings.Join(handle(in.Text()), " ; "))
		out.Flush()
	}
}
