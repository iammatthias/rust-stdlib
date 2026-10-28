// Dial and listen scenarios of the rust_stdlib_sys Go differential; built
// together with sys_oracle.go.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// tcpListener starts a loopback listener for the dial scenarios.
func tcpListener(network, addr string) (net.Listener, string) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, ""
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return ln, port
}

func echoOnce(ln net.Listener) {
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
}

func connState(c net.Conn) string {
	tc, ok := c.(*net.TCPConn)
	if !ok {
		return fmt.Sprintf("%T", c)
	}
	return fmt.Sprintf("keepalive=%s idle=%s intvl=%s cnt=%s nodelay=%s",
		sockInt(tc, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE),
		sockInt(tc, syscall.IPPROTO_TCP, tcpKeepIdle), sockInt(tc, syscall.IPPROTO_TCP, tcpKeepIntvl),
		sockInt(tc, syscall.IPPROTO_TCP, tcpKeepCnt), sockInt(tc, syscall.IPPROTO_TCP, syscall.TCP_NODELAY))
}

func roundTrip(c net.Conn) string {
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return "write " + err.Error()
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		return "read " + err.Error()
	}
	return "echo=" + string(buf)
}

func describeConn(c net.Conn) string {
	local := c.LocalAddr()
	remote := c.RemoteAddr()
	ls, rs := "<nil>", "<nil>"
	if local != nil {
		ls = local.Network() + "/" + local.String()
	}
	if remote != nil {
		rs = remote.Network() + "/" + remote.String()
	}
	return fmt.Sprintf("local=%s remote=%s", ls, rs)
}

func runDial(f []string) string {
	switch f[0] {
	case "dial_basic":
		// dial_basic network hostport (with {p} for the listener port) listenNet listenAddr
		ln, port := tcpListener(f[3], f[4])
		if ln == nil {
			return "listen failed"
		}
		defer ln.Close()
		echoOnce(ln)
		addr := strings.ReplaceAll(f[2], "{p}", port)
		c, err := net.Dial(f[1], addr)
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		return "ok " + describeConn(c) + " " + connState(c) + " " + roundTrip(c)
	case "dial_err":
		// dial_err network address
		start := time.Now()
		c, err := net.DialTimeout(f[1], f[2], 2*time.Second)
		if c != nil {
			c.Close()
		}
		_ = start
		return errText(err)
	case "dial_unix_refused":
		os.Remove("dead.sock")
		l, _ := net.Listen("unix", "dead.sock")
		l.(*net.UnixListener).SetUnlinkOnClose(false)
		l.Close()
		_, err := net.Dial("unix", "dead.sock")
		return errText(err)
	case "dial_local":
		// dial_local localSpec  (ip | ipport | udp | v6 | none)
		ln, port := tcpListener("tcp", "127.0.0.1:0")
		defer ln.Close()
		echoOnce(ln)
		d := net.Dialer{}
		switch f[1] {
		case "ip":
			d.LocalAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
		case "ipport":
			l2, p2 := tcpListener("tcp", "127.0.0.1:0")
			l2.Close()
			pn, _ := strconv.Atoi(p2)
			d.LocalAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: pn}
		case "udp":
			d.LocalAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
		case "v6":
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP("::1")}
		case "wild":
			d.LocalAddr = &net.TCPAddr{}
		}
		c, err := d.Dial("tcp", "127.0.0.1:"+port)
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		la := c.LocalAddr().(*net.TCPAddr)
		out := fmt.Sprintf("ok localip=%s remote=%s", la.IP, c.RemoteAddr())
		if f[1] == "ipport" {
			out += " keptport=" + fmt.Sprint(strconv.Itoa(la.Port) != "0")
		}
		return out
	case "dial_control":
		// dial_control mode: ok | error | ctx
		ln, port := tcpListener("tcp", "127.0.0.1:0")
		defer ln.Close()
		echoOnce(ln)
		var seen []string
		ctl := func(network, address string, c syscall.RawConn) error {
			seen = append(seen, network+"|"+address)
			var serr error
			c.Control(func(fd uintptr) {
				serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			})
			if f[1] == "error" {
				return errors.New("boom")
			}
			return serr
		}
		d := net.Dialer{}
		switch f[1] {
		case "ctx":
			d.Control = func(network, address string, c syscall.RawConn) error { seen = append(seen, "WRONG"); return nil }
			d.ControlContext = func(ctx context.Context, network, address string, c syscall.RawConn) error {
				seen = append(seen, "ctx:"+network+"|"+address)
				return nil
			}
		default:
			d.Control = ctl
		}
		c, err := d.Dial("tcp", "127.0.0.1:"+port)
		if err != nil {
			return errText(err) + " seen=" + strings.Join(seen, ",")
		}
		defer c.Close()
		reuse := sockInt(c.(*net.TCPConn), syscall.SOL_SOCKET, syscall.SO_REUSEADDR)
		return "ok seen=" + strings.Join(seen, ",") + " reuse=" + reuse
	case "dial_keepalive":
		// dial_keepalive keepAliveMs enable idleMs intervalMs count
		ln, port := tcpListener("tcp", "127.0.0.1:0")
		defer ln.Close()
		echoOnce(ln)
		ka, _ := strconv.Atoi(f[1])
		idle, _ := strconv.Atoi(f[3])
		intvl, _ := strconv.Atoi(f[4])
		cnt, _ := strconv.Atoi(f[5])
		d := net.Dialer{KeepAlive: time.Duration(ka) * time.Millisecond,
			KeepAliveConfig: net.KeepAliveConfig{Enable: f[2] == "1", Idle: time.Duration(idle) * time.Millisecond,
				Interval: time.Duration(intvl) * time.Millisecond, Count: cnt}}
		c, err := d.Dial("tcp", "127.0.0.1:"+port)
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		return "ok " + connState(c)
	case "listen_keepalive":
		// listen_keepalive keepAliveMs enable idleMs intervalMs count
		ka, _ := strconv.Atoi(f[1])
		idle, _ := strconv.Atoi(f[3])
		intvl, _ := strconv.Atoi(f[4])
		cnt, _ := strconv.Atoi(f[5])
		lc := net.ListenConfig{KeepAlive: time.Duration(ka) * time.Millisecond,
			KeepAliveConfig: net.KeepAliveConfig{Enable: f[2] == "1", Idle: time.Duration(idle) * time.Millisecond,
				Interval: time.Duration(intvl) * time.Millisecond, Count: cnt}}
		ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			return errText(err)
		}
		defer ln.Close()
		go func() {
			c, err := net.Dial("tcp", ln.Addr().String())
			if err == nil {
				time.Sleep(300 * time.Millisecond)
				c.Close()
			}
		}()
		c, err := ln.Accept()
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		return "ok " + connState(c)
	case "listen_accept_deadline":
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		tl := ln.(*net.TCPListener)
		start := time.Now()
		tl.SetDeadline(start.Add(100 * time.Millisecond))
		_, err := tl.Accept()
		out := errText(err) + fmt.Sprintf(" timely=%v", within(start, 95, 600))
		go func() {
			time.Sleep(100 * time.Millisecond)
			ln.Close()
		}()
		tl.SetDeadline(time.Time{})
		start = time.Now()
		_, err = tl.Accept()
		return out + " closed=" + errText(err) + fmt.Sprintf(" timely=%v", within(start, 95, 600))
	case "listen_unix":
		os.Remove("lu.sock")
		ln, err := net.Listen("unix", "lu.sock")
		if err != nil {
			return errText(err)
		}
		_, statErr := os.Stat("lu.sock")
		out := "created=" + fmt.Sprint(statErr == nil) + " addr=" + ln.Addr().Network() + "/" + ln.Addr().String()
		_, err2 := net.Listen("unix", "lu.sock")
		out += " again=" + errText(err2)
		go func() {
			c, err := net.Dial("unix", "lu.sock")
			if err == nil {
				c.Close()
			}
		}()
		c, err := ln.Accept()
		if err == nil {
			out += " accepted=" + fmt.Sprintf("%T", c) + " peer=" + fmt.Sprint(c.RemoteAddr() != nil)
			c.Close()
		} else {
			out += " accept=" + errText(err)
		}
		ln.Close()
		_, statErr = os.Stat("lu.sock")
		out += " afterclose=" + fmt.Sprint(statErr == nil)
		// SetUnlinkOnClose(false) keeps the file.
		ln2, _ := net.Listen("unix", "lu.sock")
		ln2.(*net.UnixListener).SetUnlinkOnClose(false)
		ln2.Close()
		_, statErr = os.Stat("lu.sock")
		out += " kept=" + fmt.Sprint(statErr == nil)
		os.Remove("lu.sock")
		return out
	case "listen_err":
		// listen_err network address
		l, err := net.Listen(f[1], f[2])
		if l != nil {
			l.Close()
		}
		return errText(err)
	case "listenpacket_err":
		c, err := net.ListenPacket(f[1], f[2])
		if c != nil {
			c.Close()
		}
		return errText(err)
	case "listenpacket_udp":
		c, err := net.ListenPacket(f[1], f[2])
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		cl, err := net.Dial("udp", c.LocalAddr().String())
		if err != nil {
			return errText(err)
		}
		defer cl.Close()
		cl.Write([]byte("dgram"))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		n, from, err := c.ReadFrom(buf)
		return fmt.Sprintf("ok %T local=%s got=%q from=%v %s", c, c.LocalAddr().Network(), buf[:n], from != nil, errText(err))
	case "listenpacket_unixgram":
		os.Remove("lg.sock")
		c, err := net.ListenPacket("unixgram", "lg.sock")
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		defer os.Remove("lg.sock")
		cl, err := net.Dial("unixgram", "lg.sock")
		if err != nil {
			return "dial " + errText(err)
		}
		defer cl.Close()
		cl.Write([]byte("ug"))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		n, _, err := c.ReadFrom(buf)
		return fmt.Sprintf("ok %T got=%q %s", c, buf[:n], errText(err))
	case "dialunix":
		// dialunix network laddr raddr
		var la, ra *net.UnixAddr
		if f[2] != "-" {
			la = &net.UnixAddr{Name: f[2], Net: f[1]}
		}
		if f[3] != "-" {
			ra = &net.UnixAddr{Name: f[3], Net: f[1]}
		}
		c, err := net.DialUnix(f[1], la, ra)
		if c != nil {
			c.Close()
		}
		return errText(err)
	case "listenunix":
		var la *net.UnixAddr
		if f[2] != "-" {
			la = &net.UnixAddr{Name: f[2], Net: f[1]}
		}
		l, err := net.ListenUnix(f[1], la)
		if l != nil {
			l.Close()
		}
		return errText(err)
	case "dialip":
		var la, ra *net.IPAddr
		if f[2] != "-" {
			la = &net.IPAddr{IP: net.ParseIP(f[2])}
		}
		if f[3] != "-" {
			ra = &net.IPAddr{IP: net.ParseIP(f[3])}
		}
		c, err := net.DialIP(f[1], la, ra)
		if c != nil {
			c.Close()
		}
		return errText(err)
	case "listenip":
		var la *net.IPAddr
		if f[2] != "-" {
			la = &net.IPAddr{IP: net.ParseIP(f[2])}
		}
		c, err := net.ListenIP(f[1], la)
		if c != nil {
			c.Close()
		}
		return errText(err)
	case "dialtcp":
		var la, ra *net.TCPAddr
		if f[2] != "-" {
			la = &net.TCPAddr{IP: net.ParseIP(f[2])}
		}
		if f[3] != "-" {
			ra = &net.TCPAddr{IP: net.ParseIP(f[3]), Port: 1}
		}
		c, err := net.DialTCP(f[1], la, ra)
		if c != nil {
			c.Close()
		}
		return errText(err)
	case "multicast":
		// multicast network ifname group:port
		var ifi *net.Interface
		if f[2] != "-" {
			ifi, _ = net.InterfaceByName(f[2])
		}
		host, port, _ := net.SplitHostPort(f[3])
		pn, _ := strconv.Atoi(port)
		var gaddr *net.UDPAddr
		if host != "-" {
			gaddr = &net.UDPAddr{IP: net.ParseIP(host), Port: pn}
		}
		c, err := net.ListenMulticastUDP(f[1], ifi, gaddr)
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		return "ok local=" + c.LocalAddr().String()
	case "fileconn":
		out := []string{}
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		defer ln.Close()
		echoOnce(ln)
		c, _ := net.Dial("tcp", ln.Addr().String())
		defer c.Close()
		file, _ := c.(*net.TCPConn).File()
		defer file.Close()
		fc, err := net.FileConn(file)
		if err != nil {
			out = append(out, "conn="+errText(err))
		} else {
			out = append(out, fmt.Sprintf("conn=%T %s", fc, describeConn(fc)), roundTrip(fc))
			fc.Close()
		}
		lf, _ := ln.(*net.TCPListener).File()
		defer lf.Close()
		fl, err := net.FileListener(lf)
		if err != nil {
			out = append(out, "listener="+errText(err))
		} else {
			out = append(out, fmt.Sprintf("listener=%T %s", fl, fl.Addr()))
			fl.Close()
		}
		uc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		defer uc.Close()
		uf, _ := uc.File()
		defer uf.Close()
		pc, err := net.FilePacketConn(uf)
		if err != nil {
			out = append(out, "packet="+errText(err))
		} else {
			out = append(out, fmt.Sprintf("packet=%T %s", pc, pc.LocalAddr()))
			pc.Close()
		}
		// A file that is not a socket.
		null, _ := os.Open("/dev/null")
		defer null.Close()
		_, err = net.FileConn(null)
		out = append(out, "notsock="+errText(err))
		_, err = net.FileListener(null)
		out = append(out, "notsock-listener="+errText(err))
		_, err = net.FilePacketConn(null)
		out = append(out, "notsock-packet="+errText(err))
		return strings.Join(out, " ")
	}
	return runWake(f)
}
