// Interoperation of the Go-shaped net/http API with Go's own net/http:
// Go's client against the Rust server (patterns, redirects, cookies, ranges,
// conditional requests, gzip, trailers, streaming), and the Rust client
// against a Go server (redirects with a cookie jar, gzip).
//
//	gohttp_interop RUST_SERVER_URL RUST_CLIENT_BINARY
//
// The server's document root holds a.txt containing "hello rust files\n".
package main

import (
	"compress/gzip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"time"
)

var passed int

func check(cond bool, format string, args ...any) {
	if !cond {
		fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
		os.Exit(1)
	}
	passed++
}

func get(c *http.Client, url string, hdr map[string]string) (*http.Response, string) {
	req, err := http.NewRequest("GET", url, nil)
	check(err == nil, "new request: %v", err)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	check(err == nil, "GET %s: %v", url, err)
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	check(err == nil, "read %s: %v", url, err)
	return resp, string(b)
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gohttp_interop RUST_SERVER_URL RUST_CLIENT_BINARY")
		os.Exit(2)
	}
	base := os.Args[1]
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Timeout: 10 * time.Second, Jar: jar}

	// Pattern routing, path values, 404 and 405.
	resp, body := get(c, base+"/hello/gopher", nil)
	check(resp.StatusCode == 200 && body == "Hello, gopher.\n", "hello: %d %q", resp.StatusCode, body)
	resp, _ = get(c, base+"/nowhere", nil)
	check(resp.StatusCode == 404, "404: %d", resp.StatusCode)
	r, err := c.Post(base+"/hello/x", "text/plain", strings.NewReader("x"))
	check(err == nil, "POST /hello: %v", err)
	r.Body.Close()
	check(r.StatusCode == 405 && r.Header.Get("Allow") == "GET, HEAD", "405: %d %q", r.StatusCode, r.Header.Get("Allow"))

	// Bodies, chunked requests and Expect: 100-continue.
	for _, b := range []io.Reader{strings.NewReader("sized body"), struct{ io.Reader }{strings.NewReader("chunked body")}} {
		resp, err := c.Post(base+"/echo", "text/x-test", b)
		check(err == nil, "echo: %v", err)
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		check(resp.StatusCode == 200 && (string(data) == "sized body" || string(data) == "chunked body"), "echo body %q", data)
		check(resp.Header.Get("Content-Type") == "text/x-test", "echo type %q", resp.Header.Get("Content-Type"))
	}
	req, _ := http.NewRequest("POST", base+"/echo", strings.NewReader(strings.Repeat("e", 3000)))
	req.Header.Set("Expect", "100-continue")
	tr := &http.Transport{ExpectContinueTimeout: time.Second}
	resp2, err := (&http.Client{Transport: tr}).Do(req)
	check(err == nil, "expect-continue: %v", err)
	data, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	check(len(data) == 3000, "expect-continue body %d", len(data))

	// Redirects and cookies.
	resp, body = get(c, base+"/old", nil)
	check(body == "Hello, redirected.\n", "redirect body %q", body)
	get(c, base+"/set-cookie", nil)
	_, body = get(c, base+"/whoami", nil)
	check(body == "rust-1\n", "cookie round trip %q", body)

	// File server: content, ranges, conditionals, directory listing.
	resp, body = get(c, base+"/files/a.txt", nil)
	check(resp.StatusCode == 200 && body == "hello rust files\n", "file: %d %q", resp.StatusCode, body)
	check(strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain"), "file type %q", resp.Header.Get("Content-Type"))
	check(resp.Header.Get("Accept-Ranges") == "bytes", "accept-ranges")
	resp, body = get(c, base+"/files/a.txt", map[string]string{"Range": "bytes=6-9"})
	check(resp.StatusCode == 206 && body == "rust" && resp.Header.Get("Content-Range") == "bytes 6-9/17", "range: %d %q %q", resp.StatusCode, body, resp.Header.Get("Content-Range"))
	lm := resp.Header.Get("Last-Modified")
	check(lm != "", "last-modified")
	resp, _ = get(c, base+"/files/a.txt", map[string]string{"If-Modified-Since": lm})
	check(resp.StatusCode == 304, "304: %d", resp.StatusCode)
	resp, body = get(c, base+"/files/", nil)
	check(resp.StatusCode == 200 && strings.Contains(body, `<a href="a.txt">a.txt</a>`), "listing %q", body)

	// Streaming, trailers, gzip.
	resp, body = get(c, base+"/stream", nil)
	check(body == "one,two\n" && resp.TransferEncoding[0] == "chunked", "stream %q %v", body, resp.TransferEncoding)
	resp, body = get(c, base+"/trailer", nil)
	check(body == "payload\n" && resp.Trailer.Get("X-Checksum") == "abc123", "trailer %q %v", body, resp.Trailer)
	resp, body = get(c, base+"/gzip", nil)
	check(body == "gzipped from rust\n" && resp.Uncompressed, "gzip %q uncompressed=%v", body, resp.Uncompressed)

	// Rust client against a Go server.
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		switch r.URL.Path {
		case "/start":
			http.SetCookie(w, &http.Cookie{Name: "go", Value: "cookie-1", Path: "/"})
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			ck, _ := r.Cookie("go")
			v := "none"
			if ck != nil {
				v = ck.Value
			}
			fmt.Fprintf(w, "final cookie=%s ua=%s", v, r.Header.Get("User-Agent"))
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			zw.Write([]byte("gzipped from go"))
			zw.Close()
		}
	}))
	defer srv.Close()
	run := func(path string) string {
		command := exec.Command(os.Args[2], srv.URL+path)
		var stderr bytes.Buffer
		command.Stderr = &stderr
		out, err := command.Output()
		check(err == nil, "rust client %s: %v: %s", path, err, stderr.String())
		return string(out)
	}
	out := run("/start")
	check(strings.HasPrefix(out, "200 final cookie=cookie-1 ua=Go-http-client/1.1"), "rust client redirect+jar %q", out)
	out = run("/gzip")
	check(out == "200 gzipped from go", "rust client gzip %q", out)
	fmt.Printf("%d Go/Rust Go-shaped net/http interop cases passed\n", passed)
}
