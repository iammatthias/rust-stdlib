// Go net/http/cgi and net/http/fcgi oracle for tools/cgi_check.py. The first
// argument selects the mode:
//
//	map    stdin lines "M <k=v hex>|<k=v hex>|..." run cgi.RequestFromMap
//	host   stdin lines "H <field>=<hex> ..." run a cgi.Handler against
//	       tools/cgi_fixture.py with a recording ResponseWriter
//	child  run as a CGI program: cgi.Serve(appHandler)
//	fcgi   listen on 127.0.0.1:0, print "PORT <n>" and run fcgi.Serve(appHandler)
//
// Output lines: map: "ok ..." or "err <text>"; host: "code=<n> hdr=<...>
// body=<hex> log=<hex>". The same appHandler is implemented in
// examples/cgi_probe.rs.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/fcgi"
	"os"
	"sort"
	"strconv"
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

func headerText(h http.Header) string {
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

func mapMode(line string) string {
	params := map[string]string{}
	if rest := strings.TrimSpace(strings.TrimPrefix(line, "M")); rest != "" && rest != "-" {
		for _, kv := range strings.Split(rest, "|") {
			k, v, _ := strings.Cut(unhex(kv), "=")
			params[k] = v
		}
	}
	r, err := cgi.RequestFromMap(params)
	if err != nil {
		return "err " + err.Error()
	}
	return fmt.Sprintf("ok method=%s proto=%s %d.%d host=%s url=%s clen=%d close=%v tls=%v remote=%s trailer=%v hdr=%s",
		r.Method, r.Proto, r.ProtoMajor, r.ProtoMinor, r.Host, r.URL.String(), r.ContentLength, r.Close,
		r.TLS != nil, r.RemoteAddr, r.Trailer != nil && len(r.Trailer) == 0, headerText(r.Header))
}

// recorder is a minimal http.ResponseWriter that snapshots the header when
// the status is written.
type recorder struct {
	code     int
	header   http.Header
	snapshot http.Header
	body     bytes.Buffer
	wrote    bool
}

func (r *recorder) Header() http.Header { return r.header }
func (r *recorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.wrote = true
	r.code = code
	r.snapshot = r.header.Clone()
}
func (r *recorder) Write(p []byte) (int, error) {
	if !r.wrote {
		r.WriteHeader(200)
	}
	return r.body.Write(p)
}

func hostMode(line string) string {
	f := map[string]string{}
	for _, kv := range strings.Fields(strings.TrimPrefix(line, "H")) {
		k, v, _ := strings.Cut(kv, "=")
		f[k] = v
	}
	var body io.Reader = strings.NewReader(unhex(f["body"]))
	req, err := http.NewRequest(unhex(f["method"]), "http://"+unhex(f["host"])+unhex(f["uri"]), body)
	if err != nil {
		return "newrequest " + err.Error()
	}
	req.Host = unhex(f["host"])
	req.RemoteAddr = unhex(f["remote"])
	if f["tls"] == "1" {
		req.TLS = &tls.ConnectionState{HandshakeComplete: true}
	}
	if f["hdr"] != "" && f["hdr"] != "-" {
		for _, kv := range strings.Split(f["hdr"], "|") {
			k, v, _ := strings.Cut(unhex(kv), ":")
			req.Header.Add(k, v)
		}
	}
	if f["te"] == "chunked" {
		req.TransferEncoding = []string{"chunked"}
	}
	var logbuf, errbuf bytes.Buffer
	h := &cgi.Handler{
		Path:   fixturePath(),
		Root:   unhex(f["root"]),
		Logger: log.New(&logbuf, "", 0),
		Stderr: &errbuf,
	}
	if f["path"] != "" {
		h.Path = unhex(f["path"])
	}
	if f["dir"] != "" && f["dir"] != "-" {
		h.Dir = unhex(f["dir"])
	}
	if f["envx"] != "" && f["envx"] != "-" {
		for _, e := range strings.Split(f["envx"], "|") {
			h.Env = append(h.Env, unhex(e))
		}
	}
	if f["inherit"] != "" && f["inherit"] != "-" {
		for _, e := range strings.Split(f["inherit"], "|") {
			h.InheritEnv = append(h.InheritEnv, unhex(e))
		}
	}
	if f["args"] != "" && f["args"] != "-" {
		for _, e := range strings.Split(f["args"], "|") {
			h.Args = append(h.Args, unhex(e))
		}
	}
	if f["loc"] == "1" {
		h.PathLocationHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "REDIRECT %s %s host=%s remote=%s tls=%v hdrs=%d", r.Method, r.URL.String(), r.Host, r.RemoteAddr, r.TLS != nil, len(r.Header))
		})
	}
	rec := &recorder{header: http.Header{}}
	h.ServeHTTP(rec, req)
	if !rec.wrote {
		rec.WriteHeader(200)
	}
	return fmt.Sprintf("code=%d hdr=%s body=%s log=%s stderr=%s", rec.code, headerText(rec.snapshot),
		hex.EncodeToString(rec.body.Bytes()), hex.EncodeToString(logbuf.Bytes()), hex.EncodeToString(errbuf.Bytes()))
}

func fixturePath() string {
	return os.Getenv("CGI_FIXTURE")
}

// appHandler is the handler served by both the CGI child and the FastCGI
// server; its behavior is selected by the "mode" query parameter.
func appHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Date", "Thu, 01 Jan 2026 00:00:00 GMT")
	q := r.URL.Query()
	switch q.Get("mode") {
	case "echo", "":
		body, err := io.ReadAll(r.Body)
		errText := "nil"
		if err != nil {
			errText = err.Error()
		}
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "method=%s\nurl=%s\nproto=%s %d.%d\nhost=%s\nremote=%s\ntls=%v\nclen=%d\nclose=%v\nhdr=%s\nbody=%s\nbodyerr=%s\n",
			r.Method, r.URL.String(), r.Proto, r.ProtoMajor, r.ProtoMinor, r.Host, r.RemoteAddr, r.TLS != nil,
			r.ContentLength, r.Close, headerText(r.Header), hex.EncodeToString(body), errText)
		env := fcgi.ProcessEnv(r)
		var keys []string
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(w, "env=%d\n", len(env))
		for _, k := range keys {
			fmt.Fprintf(w, "%s=%s\n", k, env[k])
		}
	case "status":
		code, _ := strconv.Atoi(q.Get("code"))
		if q.Get("ctype") != "" {
			w.Header().Set("Content-Type", q.Get("ctype"))
		}
		for _, h := range q["h"] {
			k, v, _ := strings.Cut(h, "=")
			w.Header().Add(k, v)
		}
		w.WriteHeader(code)
		if n, _ := strconv.Atoi(q.Get("n")); n > 0 {
			w.Write(bytes.Repeat([]byte("x"), n))
		}
	case "chunks":
		for _, c := range q["c"] {
			w.Write([]byte(c))
			if f, ok := w.(http.Flusher); ok && q.Get("flush") == "1" {
				f.Flush()
			}
		}
	case "big":
		n, _ := strconv.Atoi(q.Get("n"))
		w.Header().Set("Content-Type", "application/octet-stream")
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = byte('a' + i%26)
		}
		w.Write(buf)
	case "sniff":
		w.Write([]byte(unhex(q.Get("data"))))
	case "twice":
		w.WriteHeader(201)
		w.WriteHeader(202)
		w.Write([]byte("twice"))
	case "nothing":
	case "readn":
		n, _ := strconv.Atoi(q.Get("n"))
		buf := make([]byte, n)
		got, err := io.ReadFull(r.Body, buf)
		fmt.Fprintf(w, "got=%d err=%v", got, err)
	case "notmod":
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(304)
	}
}

func main() {
	mode := ""
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "map", "host":
		in := bufio.NewReaderSize(os.Stdin, 1<<20)
		out := bufio.NewWriter(os.Stdout)
		defer out.Flush()
		for {
			line, err := in.ReadString('\n')
			line = strings.TrimSpace(line)
			if line != "" {
				func() {
					defer func() {
						if r := recover(); r != nil {
							fmt.Fprintf(out, "panic %v\n", r)
						}
					}()
					if mode == "map" {
						fmt.Fprintln(out, mapMode(line))
					} else {
						fmt.Fprintln(out, hostMode(line))
					}
				}()
				out.Flush()
			}
			if err != nil {
				return
			}
		}
	case "child":
		if err := cgi.Serve(http.HandlerFunc(appHandler)); err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			os.Exit(1)
		}
	case "fcgi":
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		fmt.Printf("PORT %d\n", l.Addr().(*net.TCPAddr).Port)
		os.Stdout.Sync()
		fcgi.Serve(l, http.HandlerFunc(appHandler))
	case "fcgistdin":
		// fcgi.Serve(nil, ...) accepts on the listener inherited as standard input.
		fmt.Println("READY")
		os.Stdout.Sync()
		fmt.Println("ERR", fcgi.Serve(nil, http.HandlerFunc(appHandler)))
	default:
		fmt.Fprintln(os.Stderr, "usage: cgi_oracle map|host|child|fcgi|fcgistdin")
		os.Exit(2)
	}
}
