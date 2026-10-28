// Line-oriented Go net/http/httputil oracle. Requests are MODE:f1,f2,... with
// hex fields; responses are hex so CR, LF and binary bodies survive transport.
//
// Messages are modelled on the crate's types: header lists are
// "name\x00value" pairs joined by \x01, Host and Transfer-Encoding come from
// those fields, and values are trimmed of SP/HTAB as the crate's Headers do.
//
//	Q method,target,headers,body,flag  DumpRequest of the server request
//	O method,target,headers,body,flag  DumpRequestOut of http.NewRequest
//	R status,headers,body,flag         DumpResponse
//	C stream                           NewChunkedReader: data,error
//	W chunk...                         NewChunkedWriter writes then Close
//	S data                             http.DetectContentType
//	P mode,method,target,headers,remote,backend,respheaders
//	                                   ReverseProxy outbound request and
//	                                   response headers (no network)
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

type field struct{ name, value string }

func fields(raw []byte) []field {
	var out []field
	if len(raw) == 0 {
		return out
	}
	for _, item := range bytes.Split(raw, []byte{1}) {
		name, value, _ := bytes.Cut(item, []byte{0})
		out = append(out, field{string(name), strings.Trim(string(value), " \t")})
	}
	return out
}

// split separates Host and Transfer-Encoding from the remaining header map.
func split(list []field) (host string, hasHost bool, te []string, header http.Header) {
	header = http.Header{}
	for _, f := range list {
		switch strings.ToLower(f.name) {
		case "host":
			if !hasHost {
				host, hasHost = f.value, true
			}
		case "transfer-encoding":
			te = append(te, f.value)
		default:
			header.Add(f.name, f.value)
		}
	}
	return
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func dumpResult(b []byte, err error) string {
	if err != nil {
		return "ERR"
	}
	return hx(b)
}

func headerLines(h http.Header) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		if k == "User-Agent" && len(h[k]) == 1 && h[k][0] == "" {
			continue // Go's "do not send" sentinel; the crate omits the field
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var lines []string
	for _, k := range keys {
		for _, v := range h[k] {
			lines = append(lines, k+": "+v)
		}
	}
	return strings.Join(lines, "\n")
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func proxy(f [][]byte) string {
	mode, method, target := string(f[0]), string(f[1]), string(f[2])
	host, hasHost, te, header := split(fields(f[3]))
	remote, backend := string(f[4]), string(f[5])
	_, _, rte, respHeader := split(fields(f[6]))
	for _, v := range rte {
		respHeader.Add("Transfer-Encoding", v)
	}
	for _, v := range te {
		header.Add("Transfer-Encoding", v)
	}
	req := httptest.NewRequest(method, target, nil)
	req.Header = header
	req.Host = ""
	if hasHost {
		req.Host = host
	}
	req.RemoteAddr = remote
	targetURL, err := url.Parse(backend)
	if err != nil {
		return "BADTARGET"
	}
	var out *http.Request
	failed := false
	rp := &httputil.ReverseProxy{
		Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			out = r
			return &http.Response{StatusCode: 200, Header: respHeader.Clone(), Body: http.NoBody, Request: r}, nil
		}),
		ErrorHandler: func(http.ResponseWriter, *http.Request, error) { failed = true },
	}
	switch mode {
	case "director":
		rp.Director = httputil.NewSingleHostReverseProxy(targetURL).Director
	case "rewrite":
		rp.Rewrite = func(pr *httputil.ProxyRequest) { pr.SetURL(targetURL); pr.SetXForwarded() }
	case "rewrite-host":
		rp.Rewrite = func(pr *httputil.ProxyRequest) {
			pr.SetURL(targetURL)
			pr.Out.Host = pr.In.Host
		}
	case "rewrite-append":
		rp.Rewrite = func(pr *httputil.ProxyRequest) {
			pr.SetURL(targetURL)
			pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			pr.SetXForwarded()
		}
	}
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	if failed || out == nil {
		return "ERR"
	}
	// The crate's writer recomputes Content-Length from the buffered body.
	result := rec.Result().Header
	result.Del("Content-Length")
	parts := []string{out.Method, out.URL.Scheme, out.URL.Host, out.URL.RequestURI(), out.Host,
		headerLines(out.Header), headerLines(result)}
	return hx([]byte(strings.Join(parts, "|")))
}

func proto(f []byte) (int, int) {
	major, minor, _ := strings.Cut(string(f), ".")
	a, _ := strconv.Atoi(major)
	b, _ := strconv.Atoi(minor)
	return a, b
}

// clientRequest builds http.NewRequest(method, "http://"+host+target, body)
// with TransferEncoding from the fields; a close token sets Close.
func clientRequest(f [][]byte) *http.Request {
	host, _, te, header := split(fields(f[2]))
	req, err := http.NewRequest(string(f[0]), "http://"+host+string(f[1]), bytes.NewReader(f[3]))
	if err != nil {
		return nil
	}
	for k, v := range header {
		req.Header[k] = v
	}
	req.TransferEncoding = te
	for _, v := range header["Connection"] {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "close") {
				req.Close = true
			}
		}
	}
	return req
}

type fakeConn struct {
	r io.Reader
	w bytes.Buffer
}

func (c *fakeConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *fakeConn) Close() error                       { return nil }
func (c *fakeConn) LocalAddr() net.Addr                { return nil }
func (c *fakeConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func errClass(err error) string {
	switch {
	case err == nil:
		return "ok"
	case err == httputil.ErrPersistEOF:
		return "persist"
	case err == io.EOF:
		return "eof"
	}
	return "err"
}

func messageLines(h http.Header) string {
	var lines []string
	keys := make([]string, 0, len(h))
	for k := range h {
		if k != "Transfer-Encoding" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range h[k] {
			lines = append(lines, k+": "+v)
		}
	}
	return strings.Join(lines, "\n")
}

// serverConn reads pipelined requests and answers each with an echo.
func serverConn(data []byte) string {
	c := &fakeConn{r: bytes.NewReader(data)}
	sc := httputil.NewServerConn(c, nil)
	var parts []string
	for i := 0; i < 8; i++ {
		req, err := sc.Read()
		if req != nil {
			body, _ := io.ReadAll(req.Body)
			parts = append(parts, fmt.Sprintf("REQ %s %s host=%s %x body=%x", req.Method, req.RequestURI,
				req.Host, messageLines(req.Header), body))
			resp := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1,
				Header:        http.Header{"X-Echo": {req.Method + " " + req.RequestURI}},
				Body:          io.NopCloser(bytes.NewReader(body)),
				ContentLength: int64(len(body))}
			parts = append(parts, "W "+errClass(sc.Write(req, resp)))
		}
		parts = append(parts, fmt.Sprintf("E %s %d", errClass(err), sc.Pending()))
		if err != nil {
			break
		}
	}
	return hx([]byte(strings.Join(parts, "\n"))) + "," + hx(c.w.Bytes())
}

// clientConn sends the requests (method,target,headers,body groups) and
// reads responses from the final field.
func clientConn(f [][]byte) string {
	c := &fakeConn{r: bytes.NewReader(f[len(f)-1])}
	cc := httputil.NewClientConn(c, nil)
	var parts []string
	for i := 0; i+4 <= len(f)-1; i += 4 {
		req := clientRequest(f[i : i+4])
		resp, err := cc.Do(req)
		if resp != nil {
			body, berr := io.ReadAll(resp.Body)
			parts = append(parts, fmt.Sprintf("RESP %d %x body=%x %s", resp.StatusCode,
				messageLines(resp.Header), body, errClass(berr)))
		}
		parts = append(parts, fmt.Sprintf("E %s %d", errClass(err), cc.Pending()))
		if err != nil {
			break
		}
	}
	return hx([]byte(strings.Join(parts, "\n"))) + "," + hx(c.w.Bytes())
}

func chunked(data []byte) string {
	out, err := io.ReadAll(httputil.NewChunkedReader(bytes.NewReader(data)))
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	return hx(out) + "," + hx([]byte(msg))
}

func handle(mode string, f [][]byte) string {
	switch mode {
	case "Q":
		host, _, te, header := split(fields(f[2]))
		major, minor := proto(f[5])
		req := &http.Request{Method: string(f[0]), RequestURI: string(f[1]), URL: &url.URL{},
			ProtoMajor: major, ProtoMinor: minor, Host: host, Header: header, TransferEncoding: te,
			Body: io.NopCloser(bytes.NewReader(f[3]))}
		return dumpResult(httputil.DumpRequest(req, string(f[4]) == "1"))
	case "O":
		req := clientRequest(f)
		if req == nil {
			return "ERR"
		}
		return dumpResult(httputil.DumpRequestOut(req, string(f[4]) == "1"))
	case "X", "Y":
		req := clientRequest(f)
		if req == nil {
			return "ERR"
		}
		var buf bytes.Buffer
		var err error
		if mode == "X" {
			err = req.Write(&buf)
		} else {
			err = req.WriteProxy(&buf)
		}
		return dumpResult(buf.Bytes(), err)
	case "Z":
		return serverConn(f[0])
	case "K":
		return clientConn(f)
	case "R":
		status, _ := strconv.Atoi(string(f[0]))
		list := fields(f[1])
		_, _, te, header := split(list)
		for _, fl := range list {
			if strings.EqualFold(fl.name, "host") {
				header.Add(fl.name, fl.value)
			}
		}
		major, minor := proto(f[4])
		resp := &http.Response{StatusCode: status, ProtoMajor: major, ProtoMinor: minor, Header: header,
			TransferEncoding: te, Body: io.NopCloser(bytes.NewReader(f[2]))}
		if len(te) > 0 && te[0] == "chunked" {
			resp.ContentLength = -1
		} else if n, err := strconv.ParseUint(strings.Trim(header.Get("Content-Length"), " \t\r\n"), 10, 63); err == nil && header.Get("Content-Length") != "" {
			resp.ContentLength = int64(n)
		} else {
			resp.ContentLength = int64(len(f[2]))
		}
		return dumpResult(httputil.DumpResponse(resp, string(f[3]) == "1"))
	case "C":
		return chunked(f[0])
	case "W":
		var buf bytes.Buffer
		w := httputil.NewChunkedWriter(&buf)
		for _, chunk := range f {
			w.Write(chunk)
		}
		w.Close()
		return hx(buf.Bytes())
	case "S":
		return hx([]byte(http.DetectContentType(f[0])))
	case "P":
		return proxy(f)
	}
	return "BADMODE"
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<26)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		mode, rest, ok := strings.Cut(in.Text(), ":")
		if !ok {
			fmt.Fprintln(out, "BADLINE")
			continue
		}
		var f [][]byte
		for _, part := range strings.Split(rest, ",") {
			b, err := hex.DecodeString(part)
			if err != nil {
				fmt.Fprintln(out, errors.New("BADHEX"))
				continue
			}
			f = append(f, b)
		}
		fmt.Fprintln(out, handle(mode, f))
	}
}
