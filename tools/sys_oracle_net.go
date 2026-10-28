// Network scenarios of the rust_stdlib_sys Go differential; built together
// with sys_oracle.go.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var tcpKeepIdle, tcpKeepIntvl, tcpKeepCnt = keepConsts()

// keepConsts: TCP_KEEPALIVE (idle), TCP_KEEPINTVL and TCP_KEEPCNT per OS.
func keepConsts() (int, int, int) {
	if runtime.GOOS == "darwin" {
		return 0x10, 0x101, 0x102
	}
	return 4, 5, 6
}

func ifaceLine(i net.Interface) string {
	return fmt.Sprintf("%s/%d/%d/%s/%s", i.Name, i.Index, i.MTU, i.Flags, i.HardwareAddr)
}

func addrStrings(addrs []net.Addr) string {
	out := make([]string, len(addrs))
	for i, a := range addrs {
		out[i] = a.String()
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func sockInt(c syscall.Conn, level, name int) string {
	rc, err := c.SyscallConn()
	if err != nil {
		return "err " + err.Error()
	}
	var v int
	var gerr error
	if err := rc.Control(func(fd uintptr) { v, gerr = syscall.GetsockoptInt(int(fd), level, name) }); err != nil {
		return "err " + err.Error()
	}
	if gerr != nil {
		return "err " + gerr.Error()
	}
	return strconv.Itoa(v)
}

// sockLinger reads SO_LINGER (struct linger, two native ints) through
// GetsockoptIPMreq, which reads eight bytes.
func sockLinger(c syscall.Conn) string {
	rc, _ := c.SyscallConn()
	var m *syscall.IPMreq
	var gerr error
	rc.Control(func(fd uintptr) { m, gerr = syscall.GetsockoptIPMreq(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER) })
	if gerr != nil {
		return "err " + gerr.Error()
	}
	le := func(b [4]byte) uint32 { return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24 }
	return fmt.Sprintf("%d,%d", le(m.Multiaddr), le(m.Interface))
}

func tcpState(c *net.TCPConn) string {
	return fmt.Sprintf("linger=%s rcvbuf=%s sndbuf=%s keepalive=%s idle=%s intvl=%s cnt=%s nodelay=%s",
		sockLinger(c),
		sockInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF), sockInt(c, syscall.SOL_SOCKET, syscall.SO_SNDBUF),
		sockInt(c, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE),
		sockInt(c, syscall.IPPROTO_TCP, tcpKeepIdle), sockInt(c, syscall.IPPROTO_TCP, tcpKeepIntvl),
		sockInt(c, syscall.IPPROTO_TCP, tcpKeepCnt), sockInt(c, syscall.IPPROTO_TCP, syscall.TCP_NODELAY))
}

func tcpPair() (client, server *net.TCPConn, ln *net.TCPListener, err error) {
	lc := net.ListenConfig{KeepAlive: -1}
	l, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, nil, err
	}
	ln = l.(*net.TCPListener)
	d := net.Dialer{KeepAlive: -1}
	c, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, nil, nil, err
	}
	s, err := ln.AcceptTCP()
	if err != nil {
		return nil, nil, nil, err
	}
	return c.(*net.TCPConn), s, ln, nil
}

func parseMs(s string) time.Duration {
	n, _ := strconv.Atoi(s)
	return time.Duration(n) * time.Millisecond
}

func runNet(f []string) string {
	switch f[0] {
	case "ifaces":
		ift, err := net.Interfaces()
		if err != nil {
			return errText(err)
		}
		var out []string
		for _, i := range ift {
			out = append(out, ifaceLine(i))
		}
		return "ifaces " + strings.Join(out, ";")
	case "ifaddrs":
		ift, err := net.Interfaces()
		if err != nil {
			return errText(err)
		}
		var out []string
		for _, i := range ift {
			a, err := i.Addrs()
			if err != nil {
				return errText(err)
			}
			m, err := i.MulticastAddrs()
			if err != nil {
				return errText(err)
			}
			out = append(out, fmt.Sprintf("%s=[%s]+[%s]", i.Name, addrStrings(a), addrStrings(m)))
		}
		all, err := net.InterfaceAddrs()
		if err != nil {
			return errText(err)
		}
		return "ifaddrs " + strings.Join(out, ";") + " all=" + addrStrings(all)
	case "iflookup":
		ift, _ := net.Interfaces()
		var out []string
		for _, i := range ift {
			byName, err1 := net.InterfaceByName(i.Name)
			byIndex, err2 := net.InterfaceByIndex(i.Index)
			out = append(out, fmt.Sprintf("%s:%v:%v:%v", i.Name, err1 == nil && ifaceLine(*byName) == ifaceLine(i),
				err2 == nil && ifaceLine(*byIndex) == ifaceLine(i), byName != nil && byIndex != nil))
		}
		for _, name := range []string{"", "nosuch0", "lo0lo0"} {
			_, err := net.InterfaceByName(name)
			out = append(out, errText(err))
		}
		for _, idx := range []int{0, -1, 99999} {
			_, err := net.InterfaceByIndex(idx)
			out = append(out, errText(err))
		}
		return "iflookup " + strings.Join(out, ";")
	case "tcpopts":
		c, s, ln, err := tcpPair()
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		defer s.Close()
		defer ln.Close()
		// macOS re-sizes a fresh connection's receive buffer to its autotuned
		// size (265408) a few milliseconds after connect, overriding a
		// SO_RCVBUF set in that window (about 1 in 1000 runs). Let the connection settle so the option results are stable.
		time.Sleep(50 * time.Millisecond)
		var out []string
		out = append(out, "base "+tcpState(c))
		for _, op := range strings.Fields(f[1]) {
			p := strings.Split(op, ":")
			var err error
			switch p[0] {
			case "linger":
				n, _ := strconv.Atoi(p[1])
				err = c.SetLinger(n)
			case "rcvbuf":
				n, _ := strconv.Atoi(p[1])
				err = c.SetReadBuffer(n)
			case "sndbuf":
				n, _ := strconv.Atoi(p[1])
				err = c.SetWriteBuffer(n)
			case "nodelay":
				err = c.SetNoDelay(p[1] == "1")
			case "keepalive":
				err = c.SetKeepAlive(p[1] == "1")
			case "period":
				err = c.SetKeepAlivePeriod(parseMs(p[1]))
			case "cfg":
				n, _ := strconv.Atoi(p[4])
				err = c.SetKeepAliveConfig(net.KeepAliveConfig{Enable: p[1] == "1", Idle: parseMs(p[2]), Interval: parseMs(p[3]), Count: n})
			}
			out = append(out, op+"="+errText(err)+" "+tcpState(c))
		}
		return strings.Join(out, " | ")
	case "udpopts":
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		var out []string
		for _, op := range strings.Fields(f[1]) {
			p := strings.Split(op, ":")
			n, _ := strconv.Atoi(p[1])
			if p[0] == "rcvbuf" {
				err = c.SetReadBuffer(n)
			} else {
				err = c.SetWriteBuffer(n)
			}
			out = append(out, fmt.Sprintf("%s=%s rcvbuf=%s sndbuf=%s", op, errText(err),
				sockInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF), sockInt(c, syscall.SOL_SOCKET, syscall.SO_SNDBUF)))
		}
		return strings.Join(out, " | ")
	case "unixopts":
		path := "u.sock"
		os.Remove(path)
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return errText(err)
		}
		defer ln.Close()
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		var out []string
		for _, op := range strings.Fields(f[1]) {
			p := strings.Split(op, ":")
			n, _ := strconv.Atoi(p[1])
			if p[0] == "rcvbuf" {
				err = c.SetReadBuffer(n)
			} else {
				err = c.SetWriteBuffer(n)
			}
			out = append(out, fmt.Sprintf("%s=%s rcvbuf=%s sndbuf=%s", op, errText(err),
				sockInt(c, syscall.SOL_SOCKET, syscall.SO_RCVBUF), sockInt(c, syscall.SOL_SOCKET, syscall.SO_SNDBUF)))
		}
		return strings.Join(out, " | ")
	case "rawconn":
		c, s, ln, err := tcpPair()
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		defer s.Close()
		defer ln.Close()
		go func() {
			time.Sleep(100 * time.Millisecond)
			s.Write([]byte("y"))
		}()
		var out []string
		out = append(out, "type="+sockInt(c, syscall.SOL_SOCKET, syscall.SO_TYPE))
		rc, _ := c.SyscallConn()
		calls := 0
		var got string
		err = rc.Read(func(fd uintptr) bool {
			calls++
			buf := make([]byte, 1)
			n, rerr := syscall.Read(int(fd), buf)
			if rerr == syscall.EAGAIN {
				return false
			}
			got = string(buf[:n])
			return true
		})
		out = append(out, fmt.Sprintf("read=%s calls=%d got=%q", errText(err), calls, got))
		calls = 0
		err = rc.Write(func(fd uintptr) bool { calls++; return true })
		out = append(out, fmt.Sprintf("write=%s calls=%d", errText(err), calls))
		lrc, _ := ln.SyscallConn()
		ctl := false
		err = lrc.Control(func(fd uintptr) { ctl = true })
		out = append(out, fmt.Sprintf("lctl=%s %v", errText(err), ctl))
		out = append(out, "lread="+errText(lrc.Read(func(fd uintptr) bool { return true })))
		out = append(out, "lwrite="+errText(lrc.Write(func(fd uintptr) bool { return true })))
		return strings.Join(out, " ")
	case "badfd":
		err := syscall.SetsockoptInt(999, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1)
		null, _ := os.Open("/dev/null")
		defer null.Close()
		err2 := syscall.SetsockoptInt(int(null.Fd()), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 1)
		return "badfd " + errText(err) + " | " + errText(err2)
	}
	return runMsg(f)
}
