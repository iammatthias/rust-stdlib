// Line-oriented Go net/http oracle. Each input line is MODE:f1,f2,... with hex
// fields and each output line is one hex-encoded record whose fields are
// joined by NUL bytes.
//
//	M patterns,requests   ServeMux routing table: patterns are \x01-joined,
//	                      requests are \x01-joined "method\x00host\x00target"
//	K kind,args...        cookies: PC line | PS line | ST fields | RC lines,filter
//	Q raw                 ReadRequest then Write
//	P raw,method          ReadResponse then Write
//	D kind,args...        dates and versions: T text | V text
//	F ...                 FileServer / ServeContent transcripts
//	L ...                 client redirect-policy transcripts
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func record(fields ...string) string {
	return hex.EncodeToString([]byte(strings.Join(fields, "\x00")))
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	var lines []string
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		if line != "" {
			lines = append(lines, line)
		}
		if err != nil {
			break
		}
	}
	// Records are independent; run them on a worker pool, in order on output.
	results := make([]string, len(lines))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 48)
	for i, line := range lines {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			results[i] = handle(line)
			<-sem
		}()
	}
	wg.Wait()
	for _, r := range results {
		out.WriteString(r)
		out.WriteString("\n")
	}
}

func handle(line string) (result string) {
	mode, rest, _ := strings.Cut(line, ":")
	var f []string
	if rest != "" {
		f = strings.Split(rest, ",")
	}
	defer func() {
		if r := recover(); r != nil {
			result = "PANIC " + fmt.Sprint(r)
			if os.Getenv("HTTP_ORACLE_STACK") != "" {
				result += " " + strings.ReplaceAll(string(debug.Stack()), "\n", " | ")
			}
		}
	}()
	switch mode {
	case "M":
		return muxTable(f)
	case "K":
		return cookieOp(f)
	case "Q":
		return requestOp(f)
	case "P":
		return responseOp(f)
	case "D":
		return dateOp(f)
	case "V":
		return serverOp(f)
	case "F":
		return fileOp(f)
	case "Z":
		return connOp(f)
	case "Y":
		return proxyOp(f)
	case "X":
		return corsOp(f)
	case "L":
		return redirectOp(f)
	}
	return "UNKNOWN"
}

// ---------------------------------------------------------------- ServeMux

func wildcardNames(pattern string) []string {
	var names []string
	for {
		i := strings.IndexByte(pattern, '{')
		if i < 0 {
			return names
		}
		j := strings.IndexByte(pattern[i:], '}')
		if j < 0 {
			return names
		}
		name := strings.TrimSuffix(pattern[i+1:i+j], "...")
		if name != "$" && name != "" {
			names = append(names, name)
		}
		pattern = pattern[i+j+1:]
	}
}

func muxTable(f []string) string {
	mux := http.NewServeMux()
	var regs []string
	var patterns []string
	if len(f[0]) > 0 {
		for _, p := range bytes.Split(unhex(f[0]), []byte{1}) {
			patterns = append(patterns, string(p))
		}
	}
	for _, p := range patterns {
		pat := p
		func() {
			defer func() {
				if r := recover(); r != nil {
					regs = append(regs, "panic")
				}
			}()
			mux.HandleFunc(pat, func(w http.ResponseWriter, r *http.Request) {
				var vals []string
				for _, n := range wildcardNames(pat) {
					vals = append(vals, n+"="+r.PathValue(n))
				}
				w.Header().Set("X-Pattern", r.Pattern)
				fmt.Fprint(w, strings.Join(vals, "&"))
			})
			regs = append(regs, "ok")
		}()
	}
	var res []string
	res = append(res, strings.Join(regs, " "))
	if len(f) > 1 && len(f[1]) > 0 {
		for _, rq := range bytes.Split(unhex(f[1]), []byte{1}) {
			parts := strings.Split(string(rq), "\x00")
			method, host, target := parts[0], parts[1], parts[2]
			raw := method + " " + target + " HTTP/1.1\r\n"
			if host != "" {
				raw += "Host: " + host + "\r\n"
			}
			raw += "\r\n"
			req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
			if err != nil {
				res = append(res, hex.EncodeToString([]byte("parse-error")))
				continue
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, req)
			resp := w.Result()
			b, _ := io.ReadAll(resp.Body)
			res = append(res, hex.EncodeToString([]byte(strings.Join([]string{
				strconv.Itoa(resp.StatusCode), resp.Header.Get("Allow"), resp.Header.Get("Location"),
				resp.Header.Get("X-Pattern"), resp.Header.Get("Content-Type"), string(b), req.Pattern,
			}, "\x00"))))
		}
	}
	return strings.Join(res, " ")
}

// ----------------------------------------------------------------- cookies

func cookieFields(c *http.Cookie) string {
	exp := "0"
	if !c.Expires.IsZero() {
		exp = strconv.FormatInt(c.Expires.Unix(), 10)
	}
	return record(c.Name, c.Value, strconv.FormatBool(c.Quoted), c.Path, c.Domain, exp, c.RawExpires,
		strconv.Itoa(c.MaxAge), strconv.FormatBool(c.Secure), strconv.FormatBool(c.HttpOnly),
		strconv.Itoa(int(c.SameSite)), strconv.FormatBool(c.Partitioned), c.Raw, strings.Join(c.Unparsed, "\x01"))
}

func cookieOp(f []string) string {
	switch string(unhex(f[0])) {
	case "PC":
		cs, err := http.ParseCookie(string(unhex(f[1])))
		if err != nil {
			return "ERR " + hex.EncodeToString([]byte(err.Error()))
		}
		var out []string
		for _, c := range cs {
			out = append(out, cookieFields(c))
		}
		return "OK " + strings.Join(out, " ")
	case "PS":
		c, err := http.ParseSetCookie(string(unhex(f[1])))
		if err != nil {
			return "ERR " + hex.EncodeToString([]byte(err.Error()))
		}
		return "OK " + cookieFields(c)
	case "ST":
		c := &http.Cookie{Name: string(unhex(f[1])), Value: string(unhex(f[2])), Quoted: string(unhex(f[3])) == "1",
			Path: string(unhex(f[4])), Domain: string(unhex(f[5]))}
		if s := string(unhex(f[6])); s != "" {
			n, _ := strconv.ParseInt(s, 10, 64)
			c.Expires = time.Unix(n, 0)
		}
		c.MaxAge, _ = strconv.Atoi(string(unhex(f[7])))
		c.Secure = string(unhex(f[8])) == "1"
		c.HttpOnly = string(unhex(f[9])) == "1"
		ss, _ := strconv.Atoi(string(unhex(f[10])))
		c.SameSite = http.SameSite(ss)
		c.Partitioned = string(unhex(f[11])) == "1"
		verr := ""
		if err := c.Valid(); err != nil {
			verr = err.Error()
		}
		return record(c.String(), verr)
	case "RC":
		r := &http.Request{Header: http.Header{}}
		if len(f[1]) > 0 {
			for _, l := range bytes.Split(unhex(f[1]), []byte{1}) {
				r.Header.Add("Cookie", string(l))
			}
		}
		filter := string(unhex(f[2]))
		var cs []*http.Cookie
		if filter == "" {
			cs = r.Cookies()
		} else {
			cs = r.CookiesNamed(filter)
		}
		var out []string
		for _, c := range cs {
			out = append(out, record(c.Name, c.Value, strconv.FormatBool(c.Quoted)))
		}
		one, err := r.Cookie(filter)
		first := ""
		if err != nil {
			first = err.Error()
		} else {
			first = one.Name + "=" + one.Value
		}
		return "OK " + hex.EncodeToString([]byte(first)) + " " + strings.Join(out, " ")
	}
	return "UNKNOWN"
}

// ------------------------------------------------------- request / response

func headerText(h http.Header) string {
	var b bytes.Buffer
	h.Write(&b)
	return b.String()
}

func requestOp(f []string) string {
	raw := unhex(f[0])
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return "ERR " + hex.EncodeToString([]byte(err.Error()))
	}
	body, berr := io.ReadAll(req.Body)
	berrs := ""
	if berr != nil {
		berrs = berr.Error()
	}
	var trailer string
	if req.Trailer != nil {
		trailer = headerText(req.Trailer)
	}
	req2, _ := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	var wb bytes.Buffer
	werr := ""
	if err := req2.Write(&wb); err != nil {
		werr = err.Error()
	}
	var pb bytes.Buffer
	perr := ""
	req3, _ := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err := req3.WriteProxy(&pb); err != nil {
		perr = err.Error()
	}
	return "OK " + record(req.Method, req.RequestURI, req.Proto, strconv.Itoa(req.ProtoMajor), strconv.Itoa(req.ProtoMinor),
		req.URL.String(), req.Host, strconv.FormatInt(req.ContentLength, 10), strings.Join(req.TransferEncoding, ","),
		strconv.FormatBool(req.Close), headerText(req.Header), trailer, string(body), berrs,
		string(wb.Bytes()), werr, string(pb.Bytes()), perr)
}

func responseOp(f []string) string {
	raw := unhex(f[0])
	method := string(unhex(f[1]))
	var req *http.Request
	if method != "" {
		req = &http.Request{Method: method}
	}
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req)
	if err != nil {
		return "ERR " + hex.EncodeToString([]byte(err.Error()))
	}
	body, berr := io.ReadAll(resp.Body)
	berrs := ""
	if berr != nil {
		berrs = berr.Error()
	}
	var trailer string
	if resp.Trailer != nil {
		trailer = headerText(resp.Trailer)
	}
	resp2, _ := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), req)
	var wb bytes.Buffer
	werr := ""
	if err := resp2.Write(&wb); err != nil {
		werr = err.Error()
	}
	return "OK " + record(resp.Status, strconv.Itoa(resp.StatusCode), resp.Proto, strconv.Itoa(resp.ProtoMajor),
		strconv.Itoa(resp.ProtoMinor), strconv.FormatInt(resp.ContentLength, 10), strings.Join(resp.TransferEncoding, ","),
		strconv.FormatBool(resp.Close), strconv.FormatBool(resp.Uncompressed), headerText(resp.Header), trailer,
		string(body), berrs, string(wb.Bytes()), werr)
}

// ------------------------------------------------------------ dates, misc

func dateOp(f []string) string {
	switch string(unhex(f[0])) {
	case "T":
		t, err := http.ParseTime(string(unhex(f[1])))
		if err != nil {
			return "ERR"
		}
		return "OK " + strconv.FormatInt(t.UnixNano(), 10) + " " + hex.EncodeToString([]byte(t.UTC().Format(http.TimeFormat)))
	case "V":
		maj, min, ok := http.ParseHTTPVersion(string(unhex(f[1])))
		return fmt.Sprintf("%d %d %v", maj, min, ok)
	case "H":
		// canonical header key and Header ops: key, then values
		return hex.EncodeToString([]byte(http.CanonicalHeaderKey(string(unhex(f[1])))))
	case "S":
		code, _ := strconv.Atoi(string(unhex(f[1])))
		return hex.EncodeToString([]byte(http.StatusText(code)))
	}
	return "UNKNOWN"
}

func sortedKeys(m map[string][]string) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	sort.Strings(k)
	return k
}

// ----------------------------------------------------------------- server

// runScript interprets a handler script, one op per line, fields TAB-separated:
//
//	h NAME VALUE   Header().Set      a NAME VALUE   Header().Add
//	d NAME         Header().Del      c CODE         WriteHeader
//	w TEXT         Write             f              Flush
//	r              read the whole body and write it back
//	rn N           read at most N body bytes and write them back
//	t KEY VALUE    set a "Trailer:KEY" header      p   panic(ErrAbortHandler)
//	m NAME         write r.PathValue / r.Method / r.URL.Path / r.Host / r.RequestURI info
func runScript(script string, w http.ResponseWriter, r *http.Request) {
	for _, line := range strings.Split(script, "\n") {
		if line == "" {
			continue
		}
		p := strings.Split(line, "\t")
		switch p[0] {
		case "h":
			w.Header().Set(p[1], p[2])
		case "a":
			w.Header().Add(p[1], p[2])
		case "d":
			w.Header().Del(p[1])
		case "c":
			n, _ := strconv.Atoi(p[1])
			w.WriteHeader(n)
		case "w":
			io.WriteString(w, p[1])
		case "f":
			http.NewResponseController(w).Flush()
		case "r":
			b, err := io.ReadAll(r.Body)
			fmt.Fprintf(w, "body=%d:%s err=%v", len(b), b, err)
		case "rn":
			n, _ := strconv.Atoi(p[1])
			buf := make([]byte, n)
			k, err := io.ReadFull(r.Body, buf)
			fmt.Fprintf(w, "rn=%d:%s err=%v", k, buf[:k], err)
		case "t":
			w.Header().Set(http.TrailerPrefix+p[1], p[2])
		case "p":
			panic(http.ErrAbortHandler)
		case "m":
			fmt.Fprintf(w, "%s %s %s %s %q cl=%d", r.Method, r.URL.Path, r.Host, r.Proto, r.RequestURI, r.ContentLength)
		}
	}
}

var dateRe = regexp.MustCompile(`Date: [A-Za-z]{3}, \d\d [A-Za-z]{3} \d{4} \d\d:\d\d:\d\d GMT`)

func serverOp(f []string) string {
	script := string(unhex(f[0]))
	raw := unhex(f[1])
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runScript(script, w, r)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Start()
	defer srv.Close()
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		return "DIALERR"
	}
	defer conn.Close()
	conn.Write(raw)
	var out bytes.Buffer
	buf := make([]byte, 4096)
	wait := 1500 * time.Millisecond // the first byte may be slow on a loaded machine
	for {
		conn.SetReadDeadline(time.Now().Add(wait))
		wait = serverIdle
		n, err := conn.Read(buf)
		out.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return hex.EncodeToString(dateRe.ReplaceAll(out.Bytes(), []byte("Date: X")))
}

// serverIdle is how long serverOp waits for more response bytes after the
// first; tools/http_check.py raises it (HTTP_SERVER_IDLE_MS) to rerun a
// pipelined vector whose later response was slow on a loaded machine.
var serverIdle = func() time.Duration {
	if ms, err := strconv.Atoi(os.Getenv("HTTP_SERVER_IDLE_MS")); err == nil {
		return time.Duration(ms) * time.Millisecond
	}
	return 150 * time.Millisecond
}()

// -------------------------------------------------- FileServer / ServeContent

// fileOp runs handlers on generated trees without a network:
//
//	F:kind,spec,requests
//
// kind is "fs" (FileServer over Dir), "file:NAME" (ServeFile of NAME inside the
// tree) or "content:NAME" (ServeContent over a spec file). spec lines are
// "d\tPATH" or "f\tPATH\tHEXCONTENT\tMTIME". requests are \x01-joined raw HTTP
// requests (without the trailing blank line). Output: one hex record per
// request with status, sorted headers and body; the random multipart boundary
// is replaced by BOUNDARY.
func fileOp(f []string) string {
	kind := string(unhex(f[0]))
	spec := string(unhex(f[1]))
	root, err := os.MkdirTemp("", "httpfs")
	if err != nil {
		return "TMPERR"
	}
	defer os.RemoveAll(root)
	contents := map[string][]byte{}
	mtimes := map[string]int64{}
	for _, line := range strings.Split(spec, "\n") {
		if line == "" {
			continue
		}
		p := strings.Split(line, "\t")
		full := root + "/" + p[1]
		switch p[0] {
		case "d":
			os.MkdirAll(full, 0o755)
		case "f":
			os.MkdirAll(full[:strings.LastIndex(full, "/")], 0o755)
			data := unhex(p[2])
			os.WriteFile(full, data, 0o644)
			mt, _ := strconv.ParseInt(p[3], 10, 64)
			os.Chtimes(full, time.Unix(mt, 0), time.Unix(mt, 0))
			contents[p[1]] = data
			mtimes[p[1]] = mt
		}
	}
	// Directory times are part of listings: pin them.
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			defer os.Chtimes(p, time.Unix(1700000100, 0), time.Unix(1700000100, 0))
		}
		return nil
	})
	var handler http.Handler
	switch {
	case kind == "fs":
		handler = http.FileServer(http.Dir(root))
	case strings.HasPrefix(kind, "file:"):
		name := strings.TrimPrefix(kind, "file:")
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, root+"/"+name)
		})
	case strings.HasPrefix(kind, "content:"):
		name := strings.TrimPrefix(kind, "content:")
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if v := r.Header.Get("X-Set-ETag"); v != "" {
				w.Header().Set("ETag", v)
			}
			if v := r.Header.Get("X-Set-Type"); v != "" {
				w.Header().Set("Content-Type", v)
			}
			if v := r.Header.Get("X-Set-Encoding"); v != "" {
				w.Header().Set("Content-Encoding", v)
			}
			mt := time.Time{}
			if m, ok := mtimes[name]; ok && m != 0 {
				mt = time.Unix(m, 0)
			}
			http.ServeContent(w, r, name, mt, bytes.NewReader(contents[name]))
		})
	}
	var out []string
	boundaryRe := regexp.MustCompile(`[0-9a-f]{60}`)
	for _, raw := range bytes.Split(unhex(f[2]), []byte{1}) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(append(raw, "\r\n\r\n"...))))
		if err != nil {
			out = append(out, hex.EncodeToString([]byte("parse-error")))
			continue
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		resp := rec.Result()
		body, _ := io.ReadAll(resp.Body)
		var hb bytes.Buffer
		resp.Header.Write(&hb)
		text := boundaryRe.ReplaceAll([]byte(strconv.Itoa(resp.StatusCode)+"\x00"+hb.String()+"\x00"+string(body)), []byte("BOUNDARY"))
		out = append(out, hex.EncodeToString(text))
	}
	return strings.Join(out, " ")
}

// redirectOp runs a client against two scripted servers A (127.0.0.1) and B
// ([::1]) and returns the transcript of what the servers saw plus the
// client's result:
//
//	L:script,cfg,start
//
// script lines are "S\tPATH\tSTATUS\tHEADERS\tBODY" with S in {A,B}; HEADERS are
// "Name=Value" joined by \x02 and may use {A} and {B} for the server URLs. cfg
// lines are "jar", "check=none|err3", "method=M", "body=TEXT", "hdr=Name:Value".
func redirectOp(f []string) string {
	type spec struct {
		status  int
		headers [][2]string
		body    string
	}
	scripts := map[string]map[string]spec{"A": {}, "B": {}}
	for _, line := range strings.Split(string(unhex(f[0])), "\n") {
		if line == "" {
			continue
		}
		p := strings.Split(line, "\t")
		st, _ := strconv.Atoi(p[2])
		sp := spec{status: st, body: p[4]}
		if p[3] != "" {
			for _, h := range strings.Split(p[3], "\x02") {
				k, v, _ := strings.Cut(h, "=")
				sp.headers = append(sp.headers, [2]string{k, v})
			}
		}
		scripts[p[0]][p[1]] = sp
	}
	var mu sync.Mutex
	var log []string
	var baseA, baseB string
	subst := func(s string) string {
		return strings.NewReplacer("{A}", baseA, "{B}", baseB,
			"{PORTA}", baseA[strings.LastIndex(baseA, ":")+1:], "{PORTB}", baseB[strings.LastIndex(baseB, ":")+1:]).Replace(s)
	}
	norm := func(s string) string {
		return strings.NewReplacer(baseA[len("http://"):], "A", baseB[len("http://"):], "B").Replace(s)
	}
	mk := func(name, network, addr string) *httptest.Server {
		ln, err := net.Listen(network, addr)
		if err != nil {
			panic(err)
		}
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			var hb bytes.Buffer
			h := r.Header.Clone()
			h.Del("Accept-Encoding")
			h.Write(&hb)
			mu.Lock()
			log = append(log, fmt.Sprintf("%s %s %s host=%s body=%q hdr=%q", name, r.Method, r.RequestURI, r.Host, body, hb.String()))
			mu.Unlock()
			sp, ok := scripts[name][r.URL.Path]
			if !ok {
				sp = spec{status: 404, body: "nf"}
			}
			for _, kv := range sp.headers {
				w.Header().Add(kv[0], subst(kv[1]))
			}
			w.WriteHeader(sp.status)
			io.WriteString(w, sp.body)
		}))
		srv.Listener.Close()
		srv.Listener = ln
		srv.Start()
		return srv
	}
	a, b := mk("A", "tcp4", "127.0.0.1:0"), mk("B", "tcp6", "[::1]:0")
	defer a.Close()
	defer b.Close()
	baseA = a.URL
	baseB = b.URL
	client := &http.Client{}
	method := "GET"
	var reqBody io.Reader
	hdrs := http.Header{}
	for _, line := range strings.Split(string(unhex(f[1])), "\n") {
		switch {
		case line == "jar":
			client.Jar, _ = cookiejar.New(nil)
		case line == "check=none":
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		case line == "check=err3":
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return errors.New("custom stop")
				}
				return nil
			}
		case strings.HasPrefix(line, "method="):
			method = strings.TrimPrefix(line, "method=")
		case strings.HasPrefix(line, "body="):
			reqBody = strings.NewReader(strings.TrimPrefix(line, "body="))
		case strings.HasPrefix(line, "hdr="):
			k, v, _ := strings.Cut(strings.TrimPrefix(line, "hdr="), ":")
			hdrs.Add(k, v)
		}
	}
	req, err := http.NewRequest(method, subst(string(unhex(f[2]))), reqBody)
	if err != nil {
		return "NEWREQ " + err.Error()
	}
	for k, vv := range hdrs {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	resp, err := client.Do(req)
	result := ""
	if err != nil {
		result = "ERR " + norm(err.Error())
	} else {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		result = fmt.Sprintf("OK %d %q loc=%q", resp.StatusCode, body, norm(resp.Header.Get("Location")))
	}
	mu.Lock()
	defer mu.Unlock()
	return hex.EncodeToString([]byte(norm(strings.Join(log, "\n")) + "\n" + result))
}

// connOp drives httputil.ServerConn ("S") or ClientConn ("C") over loopback
// TCP. For "S" the peer sends the raw requests then half-closes, and the
// transcript is each Read result plus the response bytes the peer received;
// for "C" the peer answers with the raw responses, and the transcript is each
// Write/Read result plus the request bytes the peer received.
//
//	Z:kind,raw,nreq
func connOp(f []string) string {
	kind := string(unhex(f[0]))
	raw := unhex(f[1])
	nreq, _ := strconv.Atoi(string(unhex(f[2])))
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "LISTENERR"
	}
	defer ln.Close()
	peer, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		return "DIALERR"
	}
	defer peer.Close()
	conn, err := ln.Accept()
	if err != nil {
		return "ACCEPTERR"
	}
	var seen bytes.Buffer
	done := make(chan struct{})
	switch kind {
	case "S":
		go func() {
			peer.Write(raw)
			peer.(*net.TCPConn).CloseWrite()
		}()
		go func() { io.Copy(&seen, peer); close(done) }()
	default:
		go func() {
			peer.Write(raw)
			peer.(*net.TCPConn).CloseWrite()
		}()
		go func() { io.Copy(&seen, peer); close(done) }()
	}
	var log []string
	errs := func(err error) string {
		if err == nil {
			return "<nil>"
		}
		return err.Error()
	}
	if kind == "S" {
		sc := httputil.NewServerConn(conn, nil)
		for i := 0; i < nreq; i++ {
			req, err := sc.Read()
			if req != nil {
				b, _ := io.ReadAll(req.Body)
				log = append(log, fmt.Sprintf("R %s %s body=%q err=%s pending=%d", req.Method, req.RequestURI, b, errs(err), sc.Pending()))
				resp := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, Request: req,
					Body: io.NopCloser(strings.NewReader("ok")), ContentLength: 2, Header: http.Header{}}
				log = append(log, "W "+errs(sc.Write(req, resp)))
				if sc.Write(req, resp) != httputil.ErrPipeline {
					log = append(log, "W2 not pipeline")
				}
			} else {
				log = append(log, "R nil err="+errs(err))
			}
			if err != nil {
				break
			}
		}
		log = append(log, "close "+errs(sc.Close()))
	} else {
		cc := httputil.NewClientConn(conn, nil)
		var reqs []*http.Request
		for i := 0; i < nreq; i++ {
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://example.com/r%d", i), nil)
			err := cc.Write(req)
			log = append(log, "W "+errs(err))
			if err == nil {
				reqs = append(reqs, req)
			}
		}
		log = append(log, fmt.Sprintf("pending=%d", cc.Pending()))
		for _, req := range reqs {
			resp, err := cc.Read(req)
			if resp != nil {
				b, _ := io.ReadAll(resp.Body)
				log = append(log, fmt.Sprintf("R %d %q body=%q err=%s", resp.StatusCode, resp.Status, b, errs(err)))
			} else {
				log = append(log, "R nil err="+errs(err))
			}
		}
		log = append(log, "close "+errs(cc.Close()))
	}
	conn.Close()
	<-done
	return hex.EncodeToString([]byte(strings.Join(log, "\n") + "\n--\n" + seen.String()))
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// proxyOp runs ReverseProxy.ServeHTTP with a capturing RoundTripper:
//
//	Y:mode,request,remote,backend
//
// mode is "director" or "rewrite"; request is the raw inbound request;
// backend is "status\nHeader: v\n...\n\nbody\x01Trailer: v\n..." (header and
// trailer lines "Name: value"). The target is http://backend.example:8080/base?x=1.
func proxyOp(f []string) string {
	mode := string(unhex(f[0]))
	raw := unhex(f[1])
	remote := string(unhex(f[2]))
	spec := string(unhex(f[3]))
	parts := strings.SplitN(spec, "\x01", 2)
	head, body, _ := strings.Cut(parts[0], "\n\n")
	lines := strings.Split(head, "\n")
	status, _ := strconv.Atoi(lines[0])
	bh := http.Header{}
	for _, l := range lines[1:] {
		if k, v, ok := strings.Cut(l, ": "); ok {
			bh.Add(k, v)
		}
	}
	var trailer http.Header
	if len(parts) > 1 && parts[1] != "" {
		trailer = http.Header{}
		for _, l := range strings.Split(parts[1], "\n") {
			if k, v, ok := strings.Cut(l, ": "); ok {
				trailer.Add(k, v)
			}
		}
	}
	target, _ := url.Parse("http://backend.example:8080/base?x=1")
	var captured string
	rp := &httputil.ReverseProxy{
		ErrorLog: log.New(io.Discard, "", 0),
		Transport: rtFunc(func(r *http.Request) (*http.Response, error) {
			var hb bytes.Buffer
			r.Header.Write(&hb)
			b := []byte{}
			if r.Body != nil {
				b, _ = io.ReadAll(r.Body)
			}
			captured = fmt.Sprintf("%s %s host=%q cl=%d close=%v hdr=%q body=%q", r.Method, r.URL.String(), r.Host, r.ContentLength, r.Close, hb.String(), b)
			resp := &http.Response{StatusCode: status, Header: bh.Clone(), Body: io.NopCloser(strings.NewReader(body)),
				ContentLength: int64(len(body)), Trailer: trailer, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Request: r}
			if bh.Get("X-Unknown-Length") != "" {
				resp.ContentLength = -1
			}
			return resp, nil
		}),
	}
	switch mode {
	case "director":
		rp.Director = httputil.NewSingleHostReverseProxy(target).Director
	case "rewrite":
		rp.Rewrite = func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.SetXForwarded()
		}
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return "parse-error"
	}
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, req)
	res := rec.Result()
	rb, _ := io.ReadAll(res.Body)
	var rh, th bytes.Buffer
	res.Header.Write(&rh)
	if res.Trailer != nil {
		res.Trailer.Write(&th)
	}
	return hex.EncodeToString([]byte(captured + "\n" + strconv.Itoa(res.StatusCode) + "\n" + rh.String() + "\n" + string(rb) + "\n" + th.String()))
}

// corsOp runs CrossOriginProtection: config lines "t\tORIGIN" (AddTrustedOrigin),
// "b\tPATTERN" (AddInsecureBypassPattern) and "d" (custom deny handler), then
// \x01-joined raw requests through Handler.
func corsOp(f []string) string {
	cop := http.NewCrossOriginProtection()
	var res []string
	for _, line := range strings.Split(string(unhex(f[0])), "\n") {
		if line == "" {
			continue
		}
		p := strings.Split(line, "\t")
		switch p[0] {
		case "t":
			if err := cop.AddTrustedOrigin(p[1]); err != nil {
				res = append(res, hex.EncodeToString([]byte("trusted-err:"+err.Error())))
			}
		case "b":
			func() {
				defer func() {
					if recover() != nil {
						res = append(res, hex.EncodeToString([]byte("bypass-panic")))
					}
				}()
				cop.AddInsecureBypassPattern(p[1])
			}()
		case "d":
			cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTeapot)
			}))
		}
	}
	h := cop.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	for _, raw := range bytes.Split(unhex(f[1]), []byte{1}) {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(append(raw, "\r\n\r\n"...))))
		if err != nil {
			res = append(res, hex.EncodeToString([]byte("parse-error")))
			continue
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		res = append(res, hex.EncodeToString([]byte(strconv.Itoa(rec.Code)+"\x00"+rec.Body.String())))
	}
	return strings.Join(res, " ")
}
