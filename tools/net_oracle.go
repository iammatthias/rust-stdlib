// Line-protocol oracle for tools/net_check.py: parsers and formatters of package
// net (IP, IPMask, IPNet, ParseCIDR, ParseMAC, SplitHostPort, JoinHostPort,
// socket address types, error texts). One request per line, tokens separated by
// spaces, every argument hex-encoded ("_" is empty). Mirrors examples/net_probe.rs.
package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

func enc(s string) string {
	if s == "" {
		return "_"
	}
	return hex.EncodeToString([]byte(s))
}

func encb(b []byte) string { return enc(string(b)) }

func decb(s string) []byte {
	if s == "_" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func dec(s string) string { return string(decb(s)) }

func flag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func ipTok(ip net.IP) string {
	if ip == nil {
		return "-"
	}
	return enc(ip.String())
}

func maskTok(m net.IPMask) string {
	if m == nil {
		return "-"
	}
	return enc(m.String())
}

var probeMasks = []net.IPMask{
	net.CIDRMask(0, 32), net.CIDRMask(8, 32), net.CIDRMask(24, 32), net.CIDRMask(32, 32),
	net.CIDRMask(0, 128), net.CIDRMask(64, 128), net.CIDRMask(120, 128), net.CIDRMask(128, 128),
	{0xff, 0, 0xff, 0}, {0xff, 0xff, 0xff}, nil,
}

func dumpIP(ip net.IP) []string {
	t := []string{ipTok(ip.To4()), ipTok(ip.To16())}
	f := ""
	for _, b := range []bool{ip.IsUnspecified(), ip.IsLoopback(), ip.IsPrivate(), ip.IsMulticast(),
		ip.IsInterfaceLocalMulticast(), ip.IsLinkLocalMulticast(), ip.IsLinkLocalUnicast(), ip.IsGlobalUnicast()} {
		f += flag(b)
	}
	t = append(t, f, enc(ip.String()), maskTok(ip.DefaultMask()))
	mt, err := ip.MarshalText()
	if err != nil {
		t = append(t, "E"+enc(err.Error()))
	} else {
		t = append(t, "T"+encb(mt))
	}
	at, err := ip.AppendText([]byte("x"))
	if err != nil {
		t = append(t, "E"+enc(err.Error()))
	} else {
		t = append(t, "T"+encb(at))
	}
	for _, m := range probeMasks {
		t = append(t, ipTok(ip.Mask(m)))
	}
	for _, o := range []net.IP{ip, ip.To4(), ip.To16(), net.IPv4(1, 2, 3, 4), net.IPv4zero, net.IPv6loopback, nil} {
		t = append(t, flag(ip.Equal(o)))
	}
	var back net.IP
	if err := back.UnmarshalText(mt); err != nil {
		t = append(t, "E"+enc(err.Error()))
	} else {
		t = append(t, ipTok(back))
	}
	return t
}

func dumpNet(n *net.IPNet) []string {
	ones, bits := n.Mask.Size()
	t := []string{enc(n.String()), enc(n.Network()), ipTok(n.IP), maskTok(n.Mask), strconv.Itoa(ones), strconv.Itoa(bits)}
	for _, p := range []string{"1.2.3.4", "10.1.2.3", "192.168.0.1", "::1", "2001:db8::1", "::ffff:10.1.2.3", "fe80::1", "0.0.0.0"} {
		t = append(t, flag(n.Contains(net.ParseIP(p))))
	}
	t = append(t, flag(n.Contains(n.IP)), flag(n.Contains(nil)), flag(n.Contains(net.IP{1, 2, 3})))
	return t
}

func tcpTok(a *net.TCPAddr) []string {
	ap := a.AddrPort()
	return []string{enc(a.String()), enc(a.Network()), enc(ap.String()), flag(ap.IsValid()),
		enc(net.TCPAddrFromAddrPort(ap).String())}
}

func udpTok(a *net.UDPAddr) []string {
	ap := a.AddrPort()
	return []string{enc(a.String()), enc(a.Network()), enc(ap.String()), flag(ap.IsValid()),
		enc(net.UDPAddrFromAddrPort(ap).String())}
}

type fakeAddr struct{ n, s string }

func (f fakeAddr) Network() string { return f.n }
func (f fakeAddr) String() string  { return f.s }

func handle(line string) []string {
	f := strings.Fields(line)
	op := f[0]
	a := make([][]byte, len(f)-1)
	for i := range a {
		a[i] = decb(f[i+1])
	}
	switch op {
	case "I": // ParseIP of text
		ip := net.ParseIP(string(a[0]))
		if ip == nil {
			return []string{"NIL"}
		}
		return append([]string{"OK"}, dumpIP(ip)...)
	case "R": // raw IP bytes
		return append([]string{"OK"}, dumpIP(net.IP(a[0]))...)
	case "D": // ParseCIDR
		ip, n, err := net.ParseCIDR(string(a[0]))
		if err != nil {
			return []string{"ERR", enc(err.Error())}
		}
		return append(append([]string{"OK", ipTok(ip)}, dumpNet(n)...), flag(ip.Equal(n.IP)))
	case "N": // raw IPNet: ip bytes, mask bytes
		return dumpNet(&net.IPNet{IP: a[0], Mask: a[1]})
	case "M": // raw mask
		m := net.IPMask(a[0])
		ones, bits := m.Size()
		return []string{enc(m.String()), strconv.Itoa(ones), strconv.Itoa(bits)}
	case "K": // CIDRMask
		ones, _ := strconv.Atoi(string(a[0]))
		bits, _ := strconv.Atoi(string(a[1]))
		return []string{maskTok(net.CIDRMask(ones, bits))}
	case "H": // ParseMAC
		hw, err := net.ParseMAC(string(a[0]))
		if err != nil {
			return []string{"ERR", enc(err.Error())}
		}
		return []string{"OK", enc(hw.String()), hex.EncodeToString(hw)}
	case "S": // SplitHostPort
		h, p, err := net.SplitHostPort(string(a[0]))
		if err != nil {
			var ae *net.AddrError
			if !errors.As(err, &ae) {
				panic("not an AddrError")
			}
			return []string{"ERR", enc(err.Error()), flag(ae.Timeout()), flag(ae.Temporary())}
		}
		return []string{"OK", enc(h), enc(p)}
	case "J":
		return []string{enc(net.JoinHostPort(string(a[0]), string(a[1])))}
	case "T", "U": // raw TCPAddr/UDPAddr: ip bytes, port, zone
		port, _ := strconv.Atoi(string(a[1]))
		if op == "T" {
			return tcpTok(&net.TCPAddr{IP: a[0], Port: port, Zone: string(a[2])})
		}
		return udpTok(&net.UDPAddr{IP: a[0], Port: port, Zone: string(a[2])})
	case "P": // raw IPAddr and UnixAddr
		ia := &net.IPAddr{IP: a[0], Zone: string(a[1])}
		ua := &net.UnixAddr{Name: string(a[2]), Net: string(a[3])}
		return []string{enc(ia.String()), enc(ia.Network()), enc(ua.String()), enc(ua.Network())}
	case "Q": // OpError: op, net, source "net|str" or "-", addr, err kind/text
		var src, ad net.Addr
		if string(a[2]) != "-" {
			src = fakeAddr{"tcp", string(a[2])}
		}
		if string(a[3]) != "-" {
			ad = fakeAddr{"tcp", string(a[3])}
		}
		var inner error
		switch string(a[4]) {
		case "timeout":
			inner = timeoutErr{}
		case "addr":
			inner = &net.AddrError{Err: string(a[5]), Addr: "a"}
		case "unknown":
			inner = net.UnknownNetworkError(string(a[5]))
		case "closed":
			inner = net.ErrClosed
		case "parse":
			inner = &net.ParseError{Type: "t", Text: string(a[5])}
		default:
			inner = errors.New(string(a[5]))
		}
		e := &net.OpError{Op: string(a[0]), Net: string(a[1]), Source: src, Addr: ad, Err: inner}
		return []string{enc(e.Error()), flag(e.Timeout()), flag(e.Temporary()), flag(errors.Is(e, net.ErrClosed))}
	case "X": // DNSError text
		d := &net.DNSError{Err: string(a[0]), Name: string(a[1]), Server: string(a[2]),
			IsTimeout: string(a[3]) == "1", IsTemporary: string(a[4]) == "1"}
		return []string{enc(d.Error()), flag(d.Timeout()), flag(d.Temporary())}
	case "Y": // misc error texts
		return []string{
			enc((&net.AddrError{Err: "e", Addr: ""}).Error()),
			enc(net.UnknownNetworkError("foo").Error()),
			enc(net.InvalidAddrError("bad").Error()),
			enc((&net.DNSConfigError{Err: errors.New("boom")}).Error()),
			enc(net.ErrClosed.Error()),
			enc(net.ErrWriteToConnected.Error()),
			enc((&net.ParseError{Type: "IP address", Text: "x"}).Error()),
			net.Flags(0).String(), net.FlagUp.String(), (net.FlagUp | net.FlagLoopback | net.FlagRunning).String(),
			(net.FlagBroadcast | net.FlagPointToPoint | net.FlagMulticast).String(), net.Flags(1 << 9).String(),
		}
	}
	panic("unknown op " + op)
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, strings.Join(handle(in.Text()), " "))
	}
}
