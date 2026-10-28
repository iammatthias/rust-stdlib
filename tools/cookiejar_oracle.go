// Line-oriented Go net/http/cookiejar oracle for tools/cookiejar_check.py.
//
// Each request line is one scenario, tab-separated:
//   - the first field is the public suffix list: "n" for none, "t" for the
//     fixed test list shared with examples/cookiejar_probe.rs;
//   - "S<hex url>" starts a SetCookies batch for that URL, and each following
//     "C<fields>" adds a cookie to it; the batch is applied when the next S or
//     G field starts or the line ends;
//   - "G<hex url>" calls Cookies and emits hex(name)=hex(value) pairs joined by
//     ";", or "urlerr" when the URL does not parse.
//
// A cookie's fields are comma-separated: hex name, hex value, hex path, hex
// domain, decimal MaxAge, hex Expires (IMF-fixdate, empty for none) and flags
// ("s" Secure, "h" HttpOnly, "-" none). Empty hex means the empty string.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// testList is the public suffix list shared with the Rust probe: the longest
// listed suffix of the domain, or "" when none matches.
var testList = []string{"com", "org", "uk", "co.uk", "k12.ma.us", "ma.us", "github.io"}

type psl struct{}

func (psl) PublicSuffix(domain string) string {
	best := ""
	for _, s := range testList {
		if (domain == s || strings.HasSuffix(domain, "."+s)) && len(s) > len(best) {
			best = s
		}
	}
	return best
}

func (psl) String() string { return "test-psl" }

func unhex(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func cookieFrom(field string) *http.Cookie {
	parts := strings.Split(field, ",")
	if len(parts) != 7 {
		panic("bad cookie field " + field)
	}
	c := &http.Cookie{
		Name:     unhex(parts[0]),
		Value:    unhex(parts[1]),
		Path:     unhex(parts[2]),
		Domain:   unhex(parts[3]),
		Secure:   parts[6] == "s",
		HttpOnly: parts[6] == "h",
		Quoted:   parts[6] == "q",
	}
	age, err := strconv.Atoi(parts[4])
	if err != nil {
		panic(err)
	}
	c.MaxAge = age
	if exp := unhex(parts[5]); exp != "" {
		if t, err := time.Parse(http.TimeFormat, exp); err == nil {
			c.Expires = t
		}
	}
	return c
}

func run(line string) string {
	fields := strings.Split(line, "\t")
	var jar *cookiejar.Jar
	var err error
	if fields[0] == "t" {
		jar, err = cookiejar.New(&cookiejar.Options{PublicSuffixList: psl{}})
	} else {
		jar, err = cookiejar.New(nil)
	}
	if err != nil {
		panic(err)
	}
	var batchURL *url.URL
	var batch []*http.Cookie
	flush := func() {
		if batchURL != nil && len(batch) > 0 {
			jar.SetCookies(batchURL, batch)
		}
		batchURL, batch = nil, nil
	}
	var out []string
	for _, f := range fields[1:] {
		if f == "" {
			continue
		}
		switch f[0] {
		case 'S':
			flush()
			u, err := url.Parse(unhex(f[1:]))
			if err == nil {
				batchURL = u
			}
		case 'C':
			if batchURL != nil {
				batch = append(batch, cookieFrom(f[1:]))
			}
		case 'G':
			flush()
			u, err := url.Parse(unhex(f[1:]))
			if err != nil {
				out = append(out, "urlerr")
				continue
			}
			pairs := []string{}
			for _, c := range jar.Cookies(u) {
				pair := hex.EncodeToString([]byte(c.Name)) + "=" + hex.EncodeToString([]byte(c.Value))
				if c.Quoted {
					pair += "q"
				}
				pairs = append(pairs, pair)
			}
			out = append(out, strings.Join(pairs, ";"))
		default:
			panic("unknown op " + f)
		}
	}
	flush()
	return strings.Join(out, "\t")
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 4096), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, run(in.Text()))
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
