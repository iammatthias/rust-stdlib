// Line-protocol oracle for tools/netip_check.py: one request per line, tokens
// separated by spaces, every argument hex-encoded ("_" is the empty string).
// Each reply is one line of tokens. Mirrors examples/netip_probe.rs.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
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

func dec(s string) string {
	if s == "_" {
		return ""
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func flag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

var prefixBits = []int{-1, 0, 1, 7, 8, 24, 31, 32, 33, 64, 96, 127, 128, 129}

func dumpAddr(ip netip.Addr) []string {
	t := []string{"OK", enc(ip.String()), enc(ip.StringExpanded()), enc(ip.Zone()), strconv.Itoa(ip.BitLen())}
	f := ""
	for _, b := range []bool{ip.Is4(), ip.Is4In6(), ip.Is6(), ip.IsLoopback(), ip.IsMulticast(),
		ip.IsInterfaceLocalMulticast(), ip.IsLinkLocalMulticast(), ip.IsLinkLocalUnicast(),
		ip.IsGlobalUnicast(), ip.IsPrivate(), ip.IsUnspecified(), ip.IsValid()} {
		f += flag(b)
	}
	t = append(t, f, enc(ip.Unmap().String()), enc(ip.Next().String()), enc(ip.Prev().String()),
		enc(ip.WithZone("z1").String()), enc(ip.WithZone("").String()), encb(ip.AsSlice()))
	mt, _ := ip.MarshalText()
	mb, _ := ip.MarshalBinary()
	at, _ := ip.AppendText([]byte("x"))
	ab, _ := ip.AppendBinary([]byte("y"))
	t = append(t, encb(mt), encb(mb), encb(at), encb(ab), encb(ip.AppendTo([]byte("z"))))
	var back netip.Addr
	if err := back.UnmarshalBinary(mb); err != nil {
		t = append(t, "E")
	} else {
		t = append(t, enc(back.String()), flag(back == ip))
	}
	var backT netip.Addr
	if err := backT.UnmarshalText(mt); err != nil {
		t = append(t, "E")
	} else {
		t = append(t, enc(backT.String()), flag(backT == ip))
	}
	if ip.Is4() || ip.Is4In6() {
		a := ip.As4()
		t = append(t, hex.EncodeToString(a[:]))
	} else {
		t = append(t, "-")
	}
	a16 := ip.As16()
	t = append(t, hex.EncodeToString(a16[:]))
	for _, b := range prefixBits {
		p, err := ip.Prefix(b)
		if err != nil {
			t = append(t, "E"+enc(err.Error()))
		} else {
			t = append(t, enc(p.String()), strconv.Itoa(p.Bits()), flag(p.IsValid()))
		}
		pf := netip.PrefixFrom(ip, b)
		t = append(t, enc(pf.String()), strconv.Itoa(pf.Bits()), enc(pf.Masked().String()), flag(pf.IsSingleIP()))
	}
	return t
}

func dumpPrefix(p netip.Prefix) []string {
	t := []string{"OK", enc(p.String()), strconv.Itoa(p.Bits()), enc(p.Addr().String()), flag(p.IsValid()),
		flag(p.IsSingleIP()), enc(p.Masked().String())}
	mt, _ := p.MarshalText()
	mb, _ := p.MarshalBinary()
	at, _ := p.AppendText([]byte("x"))
	ab, _ := p.AppendBinary([]byte("y"))
	t = append(t, encb(mt), encb(mb), encb(at), encb(ab), encb(p.AppendTo([]byte("z"))))
	var back netip.Prefix
	if err := back.UnmarshalBinary(mb); err != nil {
		t = append(t, "E")
	} else {
		t = append(t, enc(back.String()), flag(back == p))
	}
	var backT netip.Prefix
	if err := backT.UnmarshalText(mt); err != nil {
		t = append(t, "E")
	} else {
		t = append(t, enc(backT.String()), flag(backT == p))
	}
	return t
}

func dumpAddrPort(p netip.AddrPort) []string {
	t := []string{"OK", enc(p.String()), enc(p.Addr().String()), strconv.Itoa(int(p.Port())), flag(p.IsValid())}
	mt, _ := p.MarshalText()
	mb, _ := p.MarshalBinary()
	at, _ := p.AppendText([]byte("x"))
	ab, _ := p.AppendBinary([]byte("y"))
	t = append(t, encb(mt), encb(mb), encb(at), encb(ab), encb(p.AppendTo([]byte("z"))))
	var back netip.AddrPort
	if err := back.UnmarshalBinary(mb); err != nil {
		t = append(t, "E")
	} else {
		t = append(t, enc(back.String()), flag(back == p))
	}
	var backT netip.AddrPort
	if err := backT.UnmarshalText(mt); err != nil {
		t = append(t, "E")
	} else {
		t = append(t, enc(backT.String()), flag(backT == p))
	}
	return t
}

// parseAddr accepts "~" for the zero Addr.
func parseAddr(s string) (netip.Addr, string) {
	if s == "~" {
		return netip.Addr{}, ""
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return ip, err.Error()
	}
	return ip, ""
}

// parsePrefix accepts "~" (zero Prefix) and "!addr/bits" (PrefixFrom).
func parsePrefix(s string) netip.Prefix {
	if s == "~" {
		return netip.Prefix{}
	}
	if strings.HasPrefix(s, "!") {
		i := strings.LastIndex(s, "/")
		ip, _ := parseAddr(s[1:i])
		b, _ := strconv.Atoi(s[i+1:])
		return netip.PrefixFrom(ip, b)
	}
	p, _ := netip.ParsePrefix(s) // the zero Prefix on error
	return p
}

func unmarshalText(a string) []string {
	var t []string
	var ia netip.Addr
	if err := ia.UnmarshalText([]byte(a)); err != nil {
		t = append(t, "E"+enc(err.Error()))
	} else {
		t = append(t, enc(ia.String()))
	}
	var ip netip.AddrPort
	if err := ip.UnmarshalText([]byte(a)); err != nil {
		t = append(t, "E"+enc(err.Error()))
	} else {
		t = append(t, enc(ip.String()))
	}
	var ix netip.Prefix
	if err := ix.UnmarshalText([]byte(a)); err != nil {
		t = append(t, "E"+enc(err.Error()))
	} else {
		t = append(t, enc(ix.String()))
	}
	return t
}

func unmarshalBinary(b []byte) []string {
	var t []string
	if ip, ok := netip.AddrFromSlice(b); ok {
		t = append(t, enc(ip.String()))
	} else {
		t = append(t, "-")
	}
	var ia netip.Addr
	if err := ia.UnmarshalBinary(b); err != nil {
		t = append(t, "E"+enc(err.Error()))
	} else {
		t = append(t, enc(ia.String()))
	}
	var ip netip.AddrPort
	if err := ip.UnmarshalBinary(b); err != nil {
		t = append(t, "E"+enc(err.Error()))
	} else {
		t = append(t, enc(ip.String()))
	}
	var ix netip.Prefix
	if err := ix.UnmarshalBinary(b); err != nil {
		t = append(t, "E"+enc(err.Error()))
	} else {
		t = append(t, enc(ix.String()), strconv.Itoa(ix.Bits()))
	}
	return t
}

func handle(line string) []string {
	f := strings.Fields(line)
	op := f[0]
	if op == "B" {
		if f[1] == "_" {
			return unmarshalBinary(nil)
		}
		b, err := hex.DecodeString(f[1])
		if err != nil {
			panic(err)
		}
		return unmarshalBinary(b)
	}
	a := make([]string, len(f)-1)
	for i := range a {
		a[i] = dec(f[i+1])
	}
	switch op {
	case "A":
		ip, e := parseAddr(a[0])
		if e != "" {
			return []string{"ERR", enc(e)}
		}
		return dumpAddr(ip)
	case "P":
		p, err := netip.ParsePrefix(a[0])
		if err != nil {
			return []string{"ERR", enc(err.Error())}
		}
		return dumpPrefix(p)
	case "T":
		p, err := netip.ParseAddrPort(a[0])
		if err != nil {
			return []string{"ERR", enc(err.Error())}
		}
		return dumpAddrPort(p)
	case "C":
		x, _ := parseAddr(a[0])
		y, _ := parseAddr(a[1])
		return []string{strconv.Itoa(x.Compare(y)), flag(x.Less(y)), flag(x == y)}
	case "K":
		p := parsePrefix(a[0])
		x, _ := parseAddr(a[1])
		return []string{flag(p.Contains(x))}
	case "O":
		p, q := parsePrefix(a[0]), parsePrefix(a[1])
		return []string{flag(p.Overlaps(q)), flag(q.Overlaps(p)), strconv.Itoa(p.Compare(q)), flag(p == q)}
	case "N":
		x, _ := parseAddr(a[0])
		t := []string{}
		cur := x
		for i := 0; i < 3; i++ {
			cur = cur.Next()
			t = append(t, enc(cur.String()), flag(cur == netip.Addr{}))
		}
		cur = x
		for i := 0; i < 3; i++ {
			cur = cur.Prev()
			t = append(t, enc(cur.String()), flag(cur == netip.Addr{}))
		}
		return t
	case "U":
		return unmarshalText(a[0])
	case "S":
		t := []string{}
		for _, ip := range []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified(), netip.IPv6Loopback(),
			netip.IPv6LinkLocalAllNodes(), netip.IPv6LinkLocalAllRouters(), {}} {
			t = append(t, enc(ip.String()))
		}
		return t
	}
	panic("unknown op " + op)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, strings.Join(handle(in.Text()), " "))
	}
}
