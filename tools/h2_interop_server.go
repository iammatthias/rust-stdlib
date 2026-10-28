// Go HTTP/2 server for the Rust client interop test (tools/h2_interop.py).
//
//	go run tools/h2_interop_server.go <h2c|tls> <addr> [cert.hex key.hex]
//
// It serves the same handlers as examples/h2_interop_server/handlers.rs.
// Prints "listening ADDRESS" and runs until stdin reaches end of file.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func fnv(data []byte, h uint64) uint64 {
	for _, b := range data {
		h ^= uint64(b)
		h *= 0x100000001b3
	}
	return h
}

func queryInt(r *http.Request, k string) int {
	n, _ := strconv.Atoi(r.URL.Query().Get(k))
	return n
}

func main() {
	mode, addr := os.Args[1], os.Args[2]
	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Hello", "world")
		io.WriteString(w, "hello")
	})
	mux.HandleFunc("/proto", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "proto=%s major=%d minor=%d tls=%v method=%s host=%s uri=%s remote=%v ua=%s",
			r.Proto, r.ProtoMajor, r.ProtoMinor, r.TLS != nil, r.Method, r.Host, r.RequestURI, r.RemoteAddr != "", r.Header.Get("User-Agent"))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-Length", strconv.FormatInt(r.ContentLength, 10))
		rc := http.NewResponseController(w)
		rc.EnableFullDuplex()
		buf := make([]byte, 8192)
		for {
			n, err := r.Body.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					return
				}
				rc.Flush()
			}
			if err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 65536)
		n, h := 0, uint64(0xcbf29ce484222325)
		for {
			k, err := r.Body.Read(buf)
			n += k
			h = fnv(buf[:k], h)
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintf(w, "error=%v", err)
				return
			}
		}
		fmt.Fprintf(w, "len=%d fnv=%016x", n, h)
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		total := queryInt(r, "n")
		chunk := make([]byte, 32<<10)
		for sent := 0; sent < total; {
			k := len(chunk)
			if total-sent < k {
				k = total - sent
			}
			for i := 0; i < k; i++ {
				chunk[i] = byte((sent + i) % 251)
			}
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			sent += k
		}
	})
	mux.HandleFunc("/trailers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "X-Checksum, X-Done")
		io.WriteString(w, "payload")
		w.Header().Set("X-Checksum", "abc123")
		w.Header().Set("X-Done", "yes")
		w.Header().Set(http.TrailerPrefix+"X-Late", "late")
	})
	mux.HandleFunc("/reqtrailers", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		out := "body=" + string(body)
		var keys []string
		for k := range r.Trailer {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			out += " " + k + "=" + strings.Join(r.Trailer[k], ",")
		}
		io.WriteString(w, out)
	})
	mux.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		var keys []string
		for k := range r.Header {
			if k == "User-Agent" || k == "Accept-Encoding" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "%s=%s\n", k, strings.Join(r.Header[k], "|"))
		}
	})
	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		code, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/status/"))
		if err != nil {
			code = 500
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(code)
		if code != 204 && code != 304 {
			fmt.Fprintf(w, "status %d", code)
		}
	})
	mux.HandleFunc("/panic", func(w http.ResponseWriter, r *http.Request) { panic("boom") })
	mux.HandleFunc("/abort", func(w http.ResponseWriter, r *http.Request) { panic(http.ErrAbortHandler) })
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			io.WriteString(w, "canceled")
		case <-time.After(4 * time.Second):
			io.WriteString(w, "finished")
		}
	})
	mux.HandleFunc("/flush", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "a")
		http.NewResponseController(w).Flush()
		time.Sleep(100 * time.Millisecond)
		io.WriteString(w, "b")
	})
	mux.HandleFunc("/close", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		io.WriteString(w, "closing")
	})
	mux.HandleFunc("/cookie", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Join(r.Header["Cookie"], "|"))
	})
	mux.HandleFunc("/push", func(w http.ResponseWriter, r *http.Request) {
		res := "no-pusher"
		if p, ok := w.(http.Pusher); ok {
			if err := p.Push("/pushed", nil); err != nil {
				res = "err:" + err.Error()
			} else {
				res = "ok"
			}
		}
		fmt.Fprintf(w, "push=%s", res)
	})
	mux.HandleFunc("/pushed", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "pushed content") })

	var mu sync.Mutex
	cond := sync.NewCond(&mu)
	count := 0
	mux.HandleFunc("/barrier", func(w http.ResponseWriter, r *http.Request) {
		want := queryInt(r, "n")
		start := time.Now()
		mu.Lock()
		count++
		cond.Broadcast()
		for count < want && time.Since(start) < 8*time.Second {
			mu.Unlock()
			time.Sleep(20 * time.Millisecond)
			mu.Lock()
		}
		reached := count >= want
		mu.Unlock()
		fmt.Fprintf(w, "barrier reached=%v", reached)
	})
	mux.HandleFunc("/barrier-reset", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count = 0
		mu.Unlock()
		io.WriteString(w, "reset")
	})

	srv := &http.Server{Handler: mux}
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetHTTP2(true)
	p.SetUnencryptedHTTP2(true)
	srv.Protocols = &p

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	fmt.Printf("listening %s\n", ln.Addr())
	go func() {
		if mode == "tls" {
			cert, err := hex.DecodeString(strings.TrimSpace(mustRead(os.Args[3])))
			if err != nil {
				panic(err)
			}
			keyDER, err := hex.DecodeString(strings.TrimSpace(mustRead(os.Args[4])))
			if err != nil {
				panic(err)
			}
			var key any
			if key, err = x509.ParsePKCS8PrivateKey(keyDER); err != nil {
				if key, err = x509.ParseECPrivateKey(keyDER); err != nil {
					if key, err = x509.ParsePKCS1PrivateKey(keyDER); err != nil {
						panic(err)
					}
				}
			}
			srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: key}}}
			srv.ServeTLS(ln, "", "")
		} else {
			srv.Serve(ln)
		}
	}()
	io.Copy(io.Discard, os.Stdin)
	srv.Close()
}

func mustRead(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		panic(err)
	}
	return string(b)
}
