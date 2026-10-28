// Go net/http/pprof oracle for tools/pprof_check.py. Requests, one per line:
//
//	P <endpoint> <method> <uri hex> <body hex>
//
// where <endpoint> is cmdline, index, symbol, profile, trace or
// handler:<name>. Output: "code=<n> hdr=<k:v,...> body=<hex>".
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/pprof"
	"os"
	"sort"
	"strings"
)

func unhex(s string) string {
	if s == "-" {
		return ""
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func handle(line string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Sprintf("panic %v", r)
		}
	}()
	f := strings.Fields(line)
	endpoint, method, uri, body := f[1], f[2], unhex(f[3]), unhex(f[4])
	req := httptest.NewRequest(method, uri, strings.NewReader(body))
	if method == "POST" && body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	rec := httptest.NewRecorder()
	switch {
	case endpoint == "cmdline":
		pprof.Cmdline(rec, req)
	case endpoint == "index":
		pprof.Index(rec, req)
	case endpoint == "symbol":
		pprof.Symbol(rec, req)
	case endpoint == "profile":
		pprof.Profile(rec, req)
	case endpoint == "trace":
		pprof.Trace(rec, req)
	case strings.HasPrefix(endpoint, "handler:"):
		pprof.Handler(strings.TrimPrefix(endpoint, "handler:")).ServeHTTP(rec, req)
	default:
		panic("bad endpoint " + endpoint)
	}
	var keys []string
	for k := range rec.Header() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var hs []string
	for _, k := range keys {
		hs = append(hs, k+":"+strings.Join(rec.Header()[k], "|"))
	}
	return fmt.Sprintf("code=%d hdr=%s body=%s", rec.Code, strings.Join(hs, ","), hex.EncodeToString(rec.Body.Bytes()))
}

var _ = http.StatusOK

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		if strings.TrimSpace(line) != "" {
			fmt.Fprintln(out, handle(strings.TrimSpace(line)))
			out.Flush()
		}
		if err != nil {
			return
		}
	}
}
