package main

// Go oracle for the cgo-resolver differential in tools/dns_check.py: LookupAddr
// and LookupCNAME with the default resolver (the C library where Go prefers it),
// and which resolver Go picks (read from GODEBUG=netdns=2 output on stderr).

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

func enc(s string) string { return hex.EncodeToString([]byte(s)) }

func errText(err error) string {
	if err == nil {
		return "-"
	}
	flags := ""
	var de *net.DNSError
	if errors.As(err, &de) {
		if de.IsTimeout {
			flags += "T"
		}
		if de.IsTemporary {
			flags += "t"
		}
		if de.IsNotFound {
			flags += "N"
		}
	}
	return enc(err.Error()) + ":" + flags
}

func main() {
	s := bufio.NewScanner(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		f := strings.SplitN(s.Text(), "\t", 4)
		ctx := context.Background()
		switch f[0] {
		case "addr":
			names, err := net.DefaultResolver.LookupAddr(ctx, f[1])
			fmt.Fprintf(w, "addr|%s|%s\n", enc(strings.Join(names, ",")), errText(err))
		case "cname":
			c, err := net.DefaultResolver.LookupCNAME(ctx, f[1])
			fmt.Fprintf(w, "cname|%s|%s\n", enc(c), errText(err))
		case "order":
			// order <preferGo 0|1> <addr|host> <name>
			r := &net.Resolver{PreferGo: f[1] == "1"}
			if f[2] == "addr" {
				r.LookupAddr(ctx, f[3])
			} else {
				r.LookupCNAME(ctx, f[3])
			}
			fmt.Fprintln(w, "order|")
		}
	}
}
