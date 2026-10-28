// Line-oriented Go net/http/httptrace oracle. One request per line:
//
//	T <port> <config> <request>;<request>;...
//
// <config> is a comma-separated list of "nokeepalive", "maxidle=<n>"
// (MaxIdleConnsPerHost), "maxidleconns=<n>" (MaxIdleConns), "h2c" (HTTP/2
// with prior knowledge over cleartext TCP) and "host=<name>" (connect to
// <name>:<port> instead of 127.0.0.1). A request is
// "<method>,<path>,<body hex or ->,<name:value hex>|<name:value hex>...,<flags>"
// with flags separated by "+": "expect" (Expect: 100-continue), "chunked"
// (unknown body length), "noread" (close the response body unread).
//
// Requests run one after the other on one Transport. Events are grouped,
// because the write loop and the read loop race in Go: "main" (GetConn, DNS,
// connect, TLS, GotConn), "write" (WroteHeaderField, WroteHeaders,
// Wait100Continue, WroteRequest) and "read" (GotFirstResponseByte,
// Got100Continue, Got1xxResponse, PutIdleConn). The output is one line:
// each request prints "<result> main[...] write[...] read[...]".
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var portRe = regexp.MustCompile(`127\.0\.0\.1:\d+|\[::1\]:\d+`)

func scrub(s string) string { return portRe.ReplaceAllString(s, "ADDR") }

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

type events struct {
	mu                sync.Mutex
	main, write, read []string
	wrote             bool // WroteRequest has fired
}

func (e *events) add(group *[]string, s string) {
	e.mu.Lock()
	*group = append(*group, scrub(s))
	e.mu.Unlock()
}

func errText(err error) string {
	if err == nil {
		return "nil"
	}
	return err.Error()
}

func header(h textproto.MIMEHeader) string {
	var keys []string
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+":"+strings.Join(h[k], "|"))
	}
	return strings.Join(parts, ",")
}

func newTrace(e *events) *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		GetConn: func(hostPort string) { e.add(&e.main, "GetConn "+hostPort) },
		GotConn: func(info httptrace.GotConnInfo) {
			e.add(&e.main, fmt.Sprintf("GotConn reused=%v idle=%v", info.Reused, info.WasIdle))
		},
		PutIdleConn:          func(err error) { e.add(&e.read, "PutIdleConn "+errText(err)) },
		GotFirstResponseByte: func() { e.add(&e.read, "GotFirstResponseByte") },
		Got100Continue:       func() { e.add(&e.read, "Got100Continue") },
		Got1xxResponse: func(code int, h textproto.MIMEHeader) error {
			e.add(&e.read, fmt.Sprintf("Got1xxResponse %d %s", code, header(h)))
			return nil
		},
		DNSStart: func(i httptrace.DNSStartInfo) { e.add(&e.main, "DNSStart "+i.Host) },
		DNSDone: func(i httptrace.DNSDoneInfo) {
			var addrs []string
			for _, a := range i.Addrs {
				if s := a.String(); s == "127.0.0.1" {
					addrs = append(addrs, s)
				}
			}
			e.add(&e.main, fmt.Sprintf("DNSDone has127=%v err=%s", len(addrs) > 0, errText(i.Err)))
		},
		ConnectStart: func(network, addr string) {
			if !strings.HasPrefix(addr, "[::1]") {
				e.add(&e.main, "ConnectStart "+network+" "+addr)
			}
		},
		ConnectDone: func(network, addr string, err error) {
			if !strings.HasPrefix(addr, "[::1]") {
				e.add(&e.main, "ConnectDone "+network+" "+addr+" "+errText(err))
			}
		},
		TLSHandshakeStart: func() { e.add(&e.main, "TLSHandshakeStart") },
		TLSHandshakeDone: func(cs tls.ConnectionState, err error) {
			e.add(&e.main, "TLSHandshakeDone "+errText(err))
		},
		WroteHeaderField: func(key string, value []string) {
			e.add(&e.write, "WroteHeaderField "+key+"="+strings.Join(value, "|"))
		},
		WroteHeaders:    func() { e.add(&e.write, "WroteHeaders") },
		Wait100Continue: func() { e.add(&e.write, "Wait100Continue") },
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			e.add(&e.write, "WroteRequest "+errText(i.Err))
			e.mu.Lock()
			e.wrote = true
			e.mu.Unlock()
		},
	}
}

func run(port, config, requests string) string {
	tr := &http.Transport{ExpectContinueTimeout: 300 * time.Millisecond}
	host := "127.0.0.1"
	for _, c := range strings.Split(config, ",") {
		switch {
		case c == "nokeepalive":
			tr.DisableKeepAlives = true
		case strings.HasPrefix(c, "maxidle="):
			tr.MaxIdleConnsPerHost, _ = strconv.Atoi(c[len("maxidle="):])
		case strings.HasPrefix(c, "maxidleconns="):
			tr.MaxIdleConns, _ = strconv.Atoi(c[len("maxidleconns="):])
		case c == "h2c":
			// HTTP/2 over cleartext TCP with prior knowledge (no HTTP/1).
			tr.Protocols = new(http.Protocols)
			tr.Protocols.SetUnencryptedHTTP2(true)
		case strings.HasPrefix(c, "ect="):
			// ExpectContinueTimeout in milliseconds.
			ms, _ := strconv.Atoi(c[len("ect="):])
			tr.ExpectContinueTimeout = time.Duration(ms) * time.Millisecond
		case strings.HasPrefix(c, "host="):
			host = c[len("host="):]
		}
	}
	defer tr.CloseIdleConnections()
	var out []string
	for _, spec := range strings.Split(requests, ";") {
		f := strings.Split(spec, ",")
		method, path, body := f[0], f[1], unhex(f[2])
		flags := map[string]bool{}
		for _, fl := range strings.Split(f[4], "+") {
			flags[fl] = true
		}
		var rdr io.Reader
		if body != "" {
			rdr = strings.NewReader(body)
			if flags["chunked"] {
				rdr = io.MultiReader(strings.NewReader(body)) // hides the length
			}
		}
		e := &events{}
		ctx := httptrace.WithClientTrace(context.Background(), newTrace(e))
		req, err := http.NewRequestWithContext(ctx, method, "http://"+host+":"+port+path, rdr)
		if err != nil {
			out = append(out, "newrequest "+err.Error())
			continue
		}
		if flags["chunked"] {
			req.ContentLength = -1
		}
		if f[3] != "-" {
			for _, kv := range strings.Split(f[3], "|") {
				k, v, _ := strings.Cut(unhex(kv), ":")
				req.Header.Add(k, v)
			}
		}
		if flags["expect"] {
			req.Header.Set("Expect", "100-continue")
		}
		resp, err := tr.RoundTrip(req)
		result := ""
		if err != nil {
			result = "err " + scrub(err.Error())
		} else {
			if flags["noread"] {
				resp.Body.Close()
				result = fmt.Sprintf("status %d noread", resp.StatusCode)
			} else {
				b, rerr := io.ReadAll(resp.Body)
				// An h2c server that answers without reading the request body
				// follows the response with RST_STREAM(NO_ERROR). Closing the
				// body first would make that the abort error of the pending
				// request body write ("response body closed") instead of the
				// peer's reset: both are valid Go outcomes, so wait for the
				// write to end (WroteRequest) before closing, on both clients.
				for i := 0; i < 5000; i++ {
					e.mu.Lock()
					w := e.wrote
					e.mu.Unlock()
					if w {
						break
					}
					time.Sleep(time.Millisecond)
				}
				resp.Body.Close()
				result = fmt.Sprintf("status %d body %d %s", resp.StatusCode, len(b), errText(rerr))
			}
		}
		// Let the write loop finish its trailing hooks.
		time.Sleep(20 * time.Millisecond)
		e.mu.Lock()
		out = append(out, fmt.Sprintf("%s main[%s] write[%s] read[%s]", result,
			strings.Join(e.main, "; "), strings.Join(e.write, "; "), strings.Join(e.read, "; ")))
		e.mu.Unlock()
	}
	return strings.Join(out, " || ")
}

func handle(line string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Sprintf("panic %v", r)
		}
	}()
	f := strings.SplitN(line, " ", 4)
	if f[0] != "T" {
		panic("bad request " + line)
	}
	return run(f[1], f[2], f[3])
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	for {
		line, err := in.ReadString('\n')
		if len(strings.TrimSpace(line)) > 0 {
			fmt.Fprintln(out, handle(strings.TrimSpace(line)))
			out.Flush()
		}
		if err != nil {
			break
		}
	}
}
