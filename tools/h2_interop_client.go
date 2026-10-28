// Go HTTP/2 client for the Rust server interop test (tools/h2_interop.py).
//
//	go run tools/h2_interop_client.go <h2c|tls> <host:port> [ca.hex]
//
// Runs every scenario against the handlers in
// examples/h2_interop_server/handlers.rs and prints "ok NAME" or
// "FAIL NAME: reason" per scenario; the exit status is non-zero on failure.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	base   string
	client *http.Client
	dials  atomic.Int64
)

func fnv(data []byte, h uint64) uint64 {
	for _, b := range data {
		h ^= uint64(b)
		h *= 0x100000001b3
	}
	return h
}

func get(path string) (*http.Response, []byte, error) {
	resp, err := client.Get(base + path)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp, body, err
}

type scenario struct {
	name string
	run  func() error
}

func want(got, exp string) error {
	if got != exp {
		return fmt.Errorf("got %q, want %q", got, exp)
	}
	return nil
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func scenarios() []scenario {
	return []scenario{
		{"hello", func() error {
			resp, body, err := get("/hello")
			if err != nil {
				return err
			}
			if resp.ProtoMajor != 2 || resp.Proto != "HTTP/2.0" {
				return fmt.Errorf("proto %q", resp.Proto)
			}
			if resp.Header.Get("X-Hello") != "world" {
				return fmt.Errorf("header %v", resp.Header)
			}
			if resp.Header.Get("Date") == "" || resp.Header.Get("Content-Type") == "" {
				return fmt.Errorf("missing Date or Content-Type: %v", resp.Header)
			}
			if resp.Header.Get("Content-Length") != "5" {
				return fmt.Errorf("content-length %q", resp.Header.Get("Content-Length"))
			}
			return want(string(body), "hello")
		}},
		{"proto", func() error {
			_, body, err := get("/proto")
			if err != nil {
				return err
			}
			s := string(body)
			for _, frag := range []string{"proto=HTTP/2.0", "major=2", "minor=0", "method=GET", "uri=/proto", "remote=true", "ua=Go-http-client/2.0"} {
				if !strings.Contains(s, frag) {
					return fmt.Errorf("missing %q in %q", frag, s)
				}
			}
			return nil
		}},
		{"echo-small", func() error {
			resp, err := client.Post(base+"/echo", "text/plain", strings.NewReader("ping"))
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if resp.Header.Get("X-Seen-Length") != "4" {
				return fmt.Errorf("server saw length %q", resp.Header.Get("X-Seen-Length"))
			}
			return want(string(b), "ping")
		}},
		{"echo-large-known-length", func() error {
			data := pattern(3 << 20)
			resp, err := client.Post(base+"/echo", "application/octet-stream", bytes.NewReader(data))
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			if !bytes.Equal(b, data) {
				return fmt.Errorf("echo mismatch: got %d bytes", len(b))
			}
			return nil
		}},
		{"echo-unknown-length-duplex", func() error {
			pr, pw := io.Pipe()
			req, _ := http.NewRequest("POST", base+"/echo", pr)
			gotOne := make(chan struct{})
			go func() {
				pw.Write([]byte("one"))
				<-gotOne
				pw.Write([]byte("two"))
				pw.Close()
			}()
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.Header.Get("X-Seen-Length") != "-1" {
				return fmt.Errorf("server saw length %q", resp.Header.Get("X-Seen-Length"))
			}
			// Full duplex: the first chunk comes back before the request body ends.
			buf := make([]byte, 3)
			if _, err := io.ReadFull(resp.Body, buf); err != nil {
				return err
			}
			if string(buf) != "one" {
				return fmt.Errorf("got %q", buf)
			}
			close(gotOne)
			rest, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			return want(string(rest), "two")
		}},
		{"download-large", func() error {
			const n = 12 << 20
			resp, body, err := get(fmt.Sprintf("/big?n=%d", n))
			if err != nil {
				return err
			}
			if resp.StatusCode != 200 || len(body) != n || !bytes.Equal(body, pattern(n)) {
				return fmt.Errorf("status %d, %d bytes", resp.StatusCode, len(body))
			}
			return nil
		}},
		{"upload-large-flow-control", func() error {
			const n = 24 << 20
			data := pattern(n)
			resp, err := client.Post(base+"/upload", "application/octet-stream", bytes.NewReader(data))
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return want(string(b), fmt.Sprintf("len=%d fnv=%016x", n, fnv(data, 0xcbf29ce484222325)))
		}},
		{"response-trailers", func() error {
			resp, err := client.Get(base + "/trailers")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if string(b) != "payload" {
				return fmt.Errorf("body %q", b)
			}
			if resp.Trailer.Get("X-Checksum") != "abc123" || resp.Trailer.Get("X-Done") != "yes" || resp.Trailer.Get("X-Late") != "late" {
				return fmt.Errorf("trailers %v", resp.Trailer)
			}
			return nil
		}},
		{"request-trailers", func() error {
			req, _ := http.NewRequest("POST", base+"/reqtrailers", io.NopCloser(strings.NewReader("data")))
			req.ContentLength = -1
			req.Trailer = http.Header{"X-Req-A": nil, "X-Req-B": nil}
			req.Trailer.Set("X-Req-A", "1")
			req.Trailer.Set("X-Req-B", "2")
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			return want(string(b), "body=data X-Req-A=1 X-Req-B=2")
		}},
		{"headers-and-cookies", func() error {
			req, _ := http.NewRequest("GET", base+"/headers", nil)
			req.Header.Add("X-Multi", "a")
			req.Header.Add("X-Multi", "b")
			req.Header.Set("Connection", "keep-alive")
			resp, err := client.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(b), "X-Multi=a|b") {
				return fmt.Errorf("headers %q", b)
			}
			if strings.Contains(string(b), "Connection") {
				return fmt.Errorf("connection header leaked: %q", b)
			}
			req2, _ := http.NewRequest("GET", base+"/cookie", nil)
			req2.AddCookie(&http.Cookie{Name: "a", Value: "1"})
			req2.AddCookie(&http.Cookie{Name: "b", Value: "2"})
			resp2, err := client.Do(req2)
			if err != nil {
				return err
			}
			defer resp2.Body.Close()
			b2, _ := io.ReadAll(resp2.Body)
			return want(string(b2), "a=1; b=2")
		}},
		{"status-codes", func() error {
			for _, code := range []int{204, 404, 418, 500} {
				resp, body, err := get(fmt.Sprintf("/status/%d", code))
				if err != nil {
					return err
				}
				if resp.StatusCode != code {
					return fmt.Errorf("status %d != %d", resp.StatusCode, code)
				}
				if code != 204 && string(body) != fmt.Sprintf("status %d", code) {
					return fmt.Errorf("body %q", body)
				}
			}
			return nil
		}},
		{"handler-panic-rst", func() error {
			_, _, err := get("/panic")
			if err == nil || !strings.Contains(err.Error(), "INTERNAL_ERROR") {
				return fmt.Errorf("want INTERNAL_ERROR reset, got %v", err)
			}
			// The connection survives a stream reset.
			_, body, err := get("/hello")
			if err != nil {
				return err
			}
			return want(string(body), "hello")
		}},
		{"handler-abort", func() error {
			_, _, err := get("/abort")
			if err == nil || !strings.Contains(err.Error(), "INTERNAL_ERROR") {
				return fmt.Errorf("want INTERNAL_ERROR reset, got %v", err)
			}
			return nil
		}},
		{"client-cancel-rst-stream", func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, "GET", base+"/slow", nil)
			start := time.Now()
			_, err := client.Do(req)
			if err == nil || !errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("want deadline exceeded, got %v", err)
			}
			if time.Since(start) > 3*time.Second {
				return errors.New("cancel took too long")
			}
			// The connection is still usable after the RST_STREAM.
			_, body, err := get("/hello")
			if err != nil {
				return err
			}
			return want(string(body), "hello")
		}},
		{"streaming-flush", func() error {
			resp, err := client.Get(base + "/flush")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			start := time.Now()
			buf := make([]byte, 1)
			if _, err := io.ReadFull(resp.Body, buf); err != nil {
				return err
			}
			if time.Since(start) > 80*time.Millisecond || buf[0] != 'a' {
				return fmt.Errorf("first chunk after %v: %q", time.Since(start), buf)
			}
			rest, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			return want(string(rest), "b")
		}},
		{"concurrent-streams", func() error {
			if _, _, err := get("/barrier-reset"); err != nil {
				return err
			}
			const n = 40
			var wg sync.WaitGroup
			errs := make(chan error, n)
			before := dials.Load()
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, body, err := get(fmt.Sprintf("/barrier?n=%d", n))
					if err != nil {
						errs <- err
						return
					}
					if string(body) != "barrier reached=true" {
						errs <- fmt.Errorf("body %q", body)
					}
				}()
			}
			wg.Wait()
			close(errs)
			for e := range errs {
				return e
			}
			if d := dials.Load() - before; d > 3 {
				return fmt.Errorf("%d new connections for %d concurrent streams", d, n)
			}
			return nil
		}},
		{"connection-reuse", func() error {
			before := dials.Load()
			for i := 0; i < 30; i++ {
				if _, _, err := get("/hello"); err != nil {
					return err
				}
			}
			if d := dials.Load() - before; d > 1 {
				return fmt.Errorf("%d dials for 30 sequential requests", d)
			}
			return nil
		}},
		{"connection-close-goaway", func() error {
			_, body, err := get("/close")
			if err != nil {
				return err
			}
			if string(body) != "closing" {
				return fmt.Errorf("body %q", body)
			}
			time.Sleep(100 * time.Millisecond)
			before := dials.Load()
			_, body, err = get("/hello")
			if err != nil {
				return err
			}
			if dials.Load() == before {
				return errors.New("no new connection after GOAWAY")
			}
			return want(string(body), "hello")
		}},
		{"push-disabled-by-go-client", func() error {
			_, body, err := get("/push")
			if err != nil {
				return err
			}
			return want(string(body), "push=err:feature not supported")
		}},
		{"head", func() error {
			resp, err := client.Head(base + "/hello")
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			b, _ := io.ReadAll(resp.Body)
			if len(b) != 0 || resp.StatusCode != 200 {
				return fmt.Errorf("head: %d %q", resp.StatusCode, b)
			}
			return nil
		}},
	}
}

func main() {
	mode, addr := os.Args[1], os.Args[2]
	dialer := &net.Dialer{}
	dial := func(ctx context.Context, network, a string) (net.Conn, error) {
		dials.Add(1)
		return dialer.DialContext(ctx, network, a)
	}
	var tr *http.Transport
	switch mode {
	case "h2c":
		var p http.Protocols
		p.SetUnencryptedHTTP2(true)
		tr = &http.Transport{Protocols: &p, DialContext: dial}
		base = "http://" + addr
	case "tls":
		der, err := hex.DecodeString(strings.TrimSpace(mustRead(os.Args[3])))
		if err != nil {
			panic(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			panic(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		host, port, _ := net.SplitHostPort(addr)
		_ = host
		tr = &http.Transport{
			TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: "localhost"},
			ForceAttemptHTTP2: true,
			DialContext:       dial,
		}
		base = "https://localhost:" + port
	}
	client = &http.Client{Transport: tr, Timeout: 60 * time.Second}
	failed := 0
	only := os.Getenv("H2_ONLY")
	for _, s := range scenarios() {
		if only != "" && s.name != only {
			continue
		}
		if err := s.run(); err != nil {
			fmt.Printf("FAIL %s: %v\n", s.name, err)
			failed++
		} else {
			fmt.Printf("ok %s\n", s.name)
		}
	}
	if failed > 0 {
		os.Exit(1)
	}
}

func mustRead(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		panic(err)
	}
	return string(b)
}
