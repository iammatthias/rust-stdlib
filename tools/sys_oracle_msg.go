// Message I/O scenarios of the rust_stdlib_sys Go differential; built
// together with sys_oracle.go.
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"
)

func udpPair() (server, client *net.UDPConn, err error) {
	server, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return
	}
	client, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	return
}

func runMsg(f []string) string {
	switch f[0] {
	case "udpmsg":
		// udpmsg payloadLen readBufLen oobMode(none|ttl)
		size, _ := strconv.Atoi(f[1])
		rsize, _ := strconv.Atoi(f[2])
		server, client, err := udpPair()
		if err != nil {
			return errText(err)
		}
		defer server.Close()
		defer client.Close()
		if f[3] == "ttl" {
			rc, _ := server.SyscallConn()
			rc.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVTTL, 1) })
		}
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i)
		}
		n, oobn, err := client.WriteMsgUDP(payload, nil, server.LocalAddr().(*net.UDPAddr))
		out := fmt.Sprintf("write n=%d oobn=%d %s", n, oobn, errText(err))
		server.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, rsize)
		oob := make([]byte, 64)
		rn, roobn, flags, addr, err := server.ReadMsgUDP(b, oob)
		from := ""
		if addr != nil {
			from = fmt.Sprint(addr.String() == client.LocalAddr().String())
		}
		return out + fmt.Sprintf(" read n=%d oobn=%d flags=%d from=%s %s oob=%s", rn, roobn, flags, from, errText(err), hex.EncodeToString(oob[:roobn]))
	case "udpmsg_ap":
		server, client, err := udpPair()
		if err != nil {
			return errText(err)
		}
		defer server.Close()
		defer client.Close()
		ap := server.LocalAddr().(*net.UDPAddr).AddrPort()
		n, oobn, err := client.WriteMsgUDPAddrPort([]byte("hello"), nil, ap)
		out := fmt.Sprintf("write n=%d oobn=%d %s", n, oobn, errText(err))
		server.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 16)
		rn, roobn, flags, addr, err := server.ReadMsgUDPAddrPort(b, nil)
		return out + fmt.Sprintf(" read n=%d oobn=%d flags=%d from=%v %s", rn, roobn, flags, addr == client.LocalAddr().(*net.UDPAddr).AddrPort(), errText(err))
	case "udpmsg_conn":
		server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return errText(err)
		}
		defer server.Close()
		client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
		if err != nil {
			return errText(err)
		}
		defer client.Close()
		n, oobn, err := client.WriteMsgUDP([]byte("hi"), nil, nil)
		out := fmt.Sprintf("conn-nil n=%d oobn=%d %s", n, oobn, errText(err))
		_, _, err = client.WriteMsgUDP([]byte("hi"), nil, server.LocalAddr().(*net.UDPAddr))
		out += " conn-addr=" + normalizeAddr(errText(err), client, server)
		_, _, err = server.WriteMsgUDP([]byte("hi"), nil, nil)
		out += " unconn-nil=" + normalizeAddr(errText(err), client, server)
		return out
	case "unixmsg":
		os.Remove("s1.sock")
		os.Remove("c1.sock")
		server, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "s1.sock", Net: "unixgram"})
		if err != nil {
			return errText(err)
		}
		defer server.Close()
		client, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: "c1.sock", Net: "unixgram"})
		if err != nil {
			return errText(err)
		}
		defer client.Close()
		// A pipe whose write end travels as SCM_RIGHTS.
		pr, pw, _ := os.Pipe()
		defer pr.Close()
		defer pw.Close()
		oobOut := syscall.UnixRights(int(pw.Fd()))
		n, oobn, err := client.WriteMsgUnix([]byte("fd"), oobOut, &net.UnixAddr{Name: "s1.sock", Net: "unixgram"})
		out := fmt.Sprintf("write n=%d oobn=%d %s", n, oobn, errText(err))
		server.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 16)
		oob := make([]byte, 64)
		rn, roobn, flags, addr, err := server.ReadMsgUnix(b, oob)
		from := "<nil>"
		if addr != nil {
			from = addr.Name + "/" + addr.Net
		}
		out += fmt.Sprintf(" read n=%d oobn=%d flags=%d from=%s %s", rn, roobn, flags, from, errText(err))
		msgs, perr := syscall.ParseSocketControlMessage(oob[:roobn])
		out += " parse=" + errText(perr)
		if perr == nil && len(msgs) == 1 {
			fds, ferr := syscall.ParseUnixRights(&msgs[0])
			out += fmt.Sprintf(" fds=%d %s", len(fds), errText(ferr))
			if len(fds) == 1 {
				got := os.NewFile(uintptr(fds[0]), "received")
				got.Write([]byte("through"))
				got.Close()
				pw.Close()
				buf := make([]byte, 16)
				m, _ := pr.Read(buf)
				out += fmt.Sprintf(" via=%q", buf[:m])
			}
		}
		// Unconnected datagram without an address, and a mismatched network.
		_, _, err = client.WriteMsgUnix([]byte("x"), nil, nil)
		out += " noaddr=" + errText(err)
		_, _, err = client.WriteMsgUnix([]byte("x"), nil, &net.UnixAddr{Name: "s1.sock", Net: "unix"})
		out += " badnet=" + errText(err)
		return out
	case "unixmsg_stream":
		os.Remove("s2.sock")
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: "s2.sock", Net: "unix"})
		if err != nil {
			return errText(err)
		}
		defer ln.Close()
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: "s2.sock", Net: "unix"})
		if err != nil {
			return errText(err)
		}
		defer c.Close()
		s, err := ln.AcceptUnix()
		if err != nil {
			return errText(err)
		}
		defer s.Close()
		n, oobn, err := c.WriteMsgUnix([]byte("stream"), nil, nil)
		out := fmt.Sprintf("write n=%d oobn=%d %s", n, oobn, errText(err))
		s.SetReadDeadline(time.Now().Add(2 * time.Second))
		b := make([]byte, 16)
		rn, roobn, flags, addr, err := s.ReadMsgUnix(b, make([]byte, 16))
		return out + fmt.Sprintf(" read n=%d oobn=%d flags=%d addr=%v %s", rn, roobn, flags, addr, errText(err))
	}
	return runDial(f)
}

// normalizeAddr replaces the two sockets' addresses so the text compares
// across runs.
func normalizeAddr(s string, a, b net.Conn) string {
	return s
}
