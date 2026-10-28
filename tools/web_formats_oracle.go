package main

import (
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

func main() {
	for _, s := range []string{`Text/Plain; CHARSET=utf-8; title="a; b\"c"`, `text/plain; a=x; A=y`, `text/plain; x="unterminated`} {
		v, p, e := mime.ParseMediaType(s)
		fmt.Printf("mime %q => %q %v %v\n", s, v, p, e)
	}
	r := http.Request{Header: http.Header{"Cookie": []string{`a=1; a="2"; empty=`}}}
	for _, c := range r.Cookies() {
		fmt.Printf("cookie %q=%q\n", c.Name, c.Value)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	origin, _ := url.Parse("https://www.example.com/")
	target, _ := url.Parse("https://sub.example.com/")
	jar.SetCookies(origin, []*http.Cookie{{Name: "sid", Value: "bad", Domain: "..example.com"}})
	fmt.Printf("cookiejar repeated-leading-dot domain count=%d\n", len(jar.Cookies(target)))
	jar.SetCookies(origin, []*http.Cookie{{Name: "sid", Value: "ok", Domain: ".Example.COM"}})
	for _, c := range jar.Cookies(target) {
		fmt.Printf("cookiejar single-leading-dot domain %q=%q\n", c.Name, c.Value)
	}
	wire := "preamble\r\n--a \t\r\nContent-Disposition: form-data; name=field\r\n\r\nbody\r\n--a--\t\r\nepilogue"
	rdr := multipart.NewReader(strings.NewReader(wire), "a")
	p, e := rdr.NextPart()
	if e != nil {
		panic(e)
	}
	b, e := io.ReadAll(p)
	if e != nil {
		panic(e)
	}
	fmt.Printf("multipart name=%q payload=%q\n", p.FormName(), b)
	_, e = rdr.NextPart()
	fmt.Printf("multipart end %v\n", e)
}
