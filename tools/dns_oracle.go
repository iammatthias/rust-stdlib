// DNS resolver oracle for tools/dns_check.py. Usage: dns_oracle <fake-server host:port>.
// It reads one lookup per line from stdin, resolves it with Go's pure resolver
// (Resolver{PreferGo: true}) whose Dial always connects to the fake server, and
// prints a normalised result line. Mirrors examples/dns_probe.rs.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

var fake string

func resolver(strict bool) *net.Resolver {
	return &net.Resolver{
		PreferGo:     true,
		StrictErrors: strict,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, fake)
		},
	}
}

func errTok(err error) string {
	s := "ERR " + strconv.Quote(err.Error())
	var de *net.DNSError
	if errors.As(err, &de) {
		s += fmt.Sprintf(" | name=%q server=%q timeout=%v temporary=%v notfound=%v unwrap=%v", de.Name, de.Server, de.Timeout(), de.Temporary(), de.IsNotFound, de.Unwrap() != nil)
	}
	return s
}

func result(list []string, err error) string {
	body := strings.Join(list, ",")
	if err != nil {
		if len(list) > 0 {
			return "PARTIAL " + body + " " + errTok(err)
		}
		return errTok(err)
	}
	return "OK " + body
}

func handle(line string) string {
	f := strings.Fields(line)
	strict := false
	if f[len(f)-1] == "strict" {
		strict = true
		f = f[:len(f)-1]
	}
	r := resolver(strict)
	ctx := context.Background()
	switch f[0] {
	case "host":
		l, err := r.LookupHost(ctx, f[1])
		return result(l, err)
	case "ip":
		ips, err := r.LookupIP(ctx, f[1], f[2])
		var l []string
		for _, ip := range ips {
			l = append(l, ip.String())
		}
		return result(l, err)
	case "ipaddr":
		a, err := r.LookupIPAddr(ctx, f[1])
		var l []string
		for _, ip := range a {
			l = append(l, ip.String())
		}
		return result(l, err)
	case "netip":
		a, err := r.LookupNetIP(ctx, f[1], f[2])
		var l []string
		for _, ip := range a {
			l = append(l, ip.String())
		}
		return result(l, err)
	case "cname":
		c, err := r.LookupCNAME(ctx, f[1])
		if err != nil {
			return errTok(err)
		}
		return "OK " + c
	case "mx":
		m, err := r.LookupMX(ctx, f[1])
		var l []string
		for _, x := range m {
			l = append(l, fmt.Sprintf("%s:%d", x.Host, x.Pref))
		}
		sort.Strings(l)
		return result(l, err)
	case "ns":
		m, err := r.LookupNS(ctx, f[1])
		var l []string
		for _, x := range m {
			l = append(l, x.Host)
		}
		return result(l, err)
	case "txt":
		l, err := r.LookupTXT(ctx, f[1])
		for i := range l {
			l[i] = strconv.Quote(l[i])
		}
		return result(l, err)
	case "srv":
		svc, proto := f[1], f[2]
		if svc == "-" {
			svc = ""
		}
		if proto == "-" {
			proto = ""
		}
		cname, s, err := r.LookupSRV(ctx, svc, proto, f[3])
		var l []string
		for _, x := range s {
			l = append(l, fmt.Sprintf("%s:%d:%d:%d", x.Target, x.Port, x.Priority, x.Weight))
		}
		sort.Strings(l)
		return "cname=" + cname + " " + result(l, err)
	case "addr":
		l, err := r.LookupAddr(ctx, f[1])
		return result(l, err)
	}
	panic("unknown op " + f[0])
}

func main() {
	fake = os.Args[1]
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, handle(in.Text()))
		out.Flush()
	}
}
