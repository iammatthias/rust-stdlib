// Cleartext HTTP/2 (prior knowledge) server for the h2c scenarios of
// tools/httptrace_check.py. It listens on 127.0.0.1:0, prints "PORT <n>" and
// then one line per request:
//
//	REQ <connection number> <method> <request URI> <headers> <body hex>
//
// The response is chosen by the request's X-Mode header: ok, empty, nocontent,
// notfound, big (70000 bytes), head (Content-Length without a body), info
// (102, 103 and 199 before the final response) or reset (the handler aborts,
// which resets the stream). X-Read: 1 makes the handler read the request body
// before answering, which makes Go's server send "100 Continue" for a request
// with "Expect: 100-continue".
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type connKey struct{}

func main() {
	var conns atomic.Int64
	var out sync.Mutex
	srv := &http.Server{
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, conns.Add(1))
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body []byte
			if r.Header.Get("X-Read") == "1" {
				body, _ = io.ReadAll(r.Body)
			}
			var keys []string
			for k := range r.Header {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var hs []string
			for _, k := range keys {
				hs = append(hs, k+":"+strings.Join(r.Header[k], "|"))
			}
			out.Lock()
			fmt.Printf("REQ %v %s %s %s %s\n", r.Context().Value(connKey{}), r.Method, r.RequestURI,
				strings.Join(hs, ","), hex.EncodeToString(body))
			os.Stdout.Sync()
			out.Unlock()
			w.Header().Set("Date", "Thu, 01 Jan 2026 00:00:00 GMT")
			switch r.Header.Get("X-Mode") {
			case "empty":
				w.WriteHeader(200)
			case "nocontent":
				w.WriteHeader(204)
			case "notfound":
				http.Error(w, "nope", 404)
			case "big":
				w.Write([]byte(strings.Repeat("x", 70000)))
			case "head":
				w.Header().Set("Content-Length", "11")
				w.WriteHeader(200)
			case "info":
				w.Header().Set("Link", "</style.css>; rel=preload")
				w.WriteHeader(102)
				w.WriteHeader(103)
				w.Header().Set("X-Odd", "1")
				w.WriteHeader(199)
				w.Header().Del("Link")
				w.Header().Del("X-Odd")
				w.Write([]byte("hello world"))
			case "reset":
				panic(http.ErrAbortHandler)
			default:
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte("hello world"))
			}
		}),
	}
	srv.Protocols = new(http.Protocols)
	srv.Protocols.SetUnencryptedHTTP2(true)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Printf("PORT %d\n", l.Addr().(*net.TCPAddr).Port)
	os.Stdout.Sync()
	srv.Serve(l)
}
