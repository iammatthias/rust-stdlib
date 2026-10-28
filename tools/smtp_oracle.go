// Line-oriented Go net/smtp oracle. Requests, one per line:
//
//	S <port> <action>|<action>|...   run actions against a scripted server
//	M <port> <auth> <from> <to,to> <msg hex>   SendMail
//
// A request may end in " @ <key>:<message>:<mac>,..." (hex): the HMAC-MD5
// results the Rust probe, which has no cryptography, answers CRAM-MD5 with.
//
// An action is a verb and hex-encoded arguments:
//
//	dial                      smtp.Dial("127.0.0.1:<port>")
//	newclient <host>          net.Dial then smtp.NewClient(conn, host)
//	hello <name>              Client.Hello
//	ext <name>                Client.Extension
//	auth plain <id>,<user>,<pass>,<host>   Client.Auth(PlainAuth(...))
//	auth cram <user>,<secret>              Client.Auth(CRAMMD5Auth(...))
//	auth script <proto>,<initial>,<next>,... Client.Auth with a scripted
//	                          mechanism: <next> is "nil" (finish), "err"
//	                          (fail) or the hex response to send
//	auth startfail            a mechanism whose Start fails
//	mail|rcpt|verify <addr>   Client.Mail|Rcpt|Verify
//	data <msg>                Client.Data, Write(msg), Close
//	datanoclose <msg>         Client.Data, Write(msg), then no Close
//	reset|noop|quit|close|starttls|tlsstate
//
// <auth> in M is "none", "plain" (PlainAuth("", "u", "p", "127.0.0.1")) or
// "cram". Each action prints "ok [detail]" or "err <text>"; a request prints
// its results joined by " | ". Port numbers in errors are scrubbed.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"regexp"
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

var portRe = regexp.MustCompile(`127\.0\.0\.1:\d+`)

func scrub(err error) string {
	return "err " + portRe.ReplaceAllString(err.Error(), "ADDR")
}

type scriptAuth struct {
	proto   string
	initial string
	next    []string
	failed  bool
	i       int
}

func (a *scriptAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	if a.failed {
		return "", nil, errors.New("scripted start failure")
	}
	return a.proto, []byte(a.initial), nil
}

func (a *scriptAuth) Next(from []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	if a.i >= len(a.next) {
		return nil, nil
	}
	n := a.next[a.i]
	a.i++
	switch n {
	case "nil":
		return nil, nil
	case "err":
		return nil, errors.New("scripted next failure")
	case "empty":
		return []byte{}, nil
	}
	return []byte(unhex(n)), nil
}

func parseAuth(f []string) smtp.Auth {
	switch f[0] {
	case "plain":
		p := strings.Split(f[1], ",")
		return smtp.PlainAuth(unhex(p[0]), unhex(p[1]), unhex(p[2]), unhex(p[3]))
	case "cram":
		p := strings.Split(f[1], ",")
		return smtp.CRAMMD5Auth(unhex(p[0]), unhex(p[1]))
	case "startfail":
		return &scriptAuth{failed: true}
	case "script":
		p := strings.Split(f[1], ",")
		return &scriptAuth{proto: unhex(p[0]), initial: unhex(p[1]), next: p[2:]}
	}
	panic("bad auth " + f[0])
}

func runActions(port string, actions string) string {
	// Go computes HMAC-MD5 itself; the " @ " suffix carries the table the
	// Rust probe uses instead.
	actions, _, _ = strings.Cut(actions, " @ ")
	var c *smtp.Client
	var results []string
	for _, action := range strings.Split(actions, "|") {
		f := strings.Fields(action)
		var err error
		detail := ""
		if f[0] != "dial" && f[0] != "newclient" && c == nil {
			results = append(results, "err no client")
			continue
		}
		switch f[0] {
		case "dial":
			c, err = smtp.Dial("127.0.0.1:" + port)
		case "newclient":
			var conn net.Conn
			conn, err = net.Dial("tcp", "127.0.0.1:"+port)
			if err == nil {
				c, err = smtp.NewClient(conn, unhex(f[1]))
				if err != nil {
					conn.Close()
				}
			}
		case "hello":
			err = c.Hello(unhex(f[1]))
		case "ext":
			ok, param := c.Extension(unhex(f[1]))
			detail = fmt.Sprintf(" %v %q", ok, param)
		case "auth":
			err = c.Auth(parseAuth(f[1:]))
		case "mail":
			err = c.Mail(unhex(f[1]))
		case "rcpt":
			err = c.Rcpt(unhex(f[1]))
		case "verify":
			err = c.Verify(unhex(f[1]))
		case "data", "datanoclose":
			var w interface {
				Write([]byte) (int, error)
				Close() error
			}
			w, err = c.Data()
			if err == nil {
				if _, err = w.Write([]byte(unhex(f[1]))); err == nil && f[0] == "data" {
					err = w.Close()
				}
			}
		case "reset":
			err = c.Reset()
		case "noop":
			err = c.Noop()
		case "quit":
			err = c.Quit()
		case "close":
			err = c.Close()
		case "starttls":
			err = c.StartTLS(&tls.Config{ServerName: "mail.example.com"})
		case "tlsstate":
			_, ok := c.TLSConnectionState()
			detail = fmt.Sprintf(" %v", ok)
		default:
			panic("bad action " + f[0])
		}
		if err != nil {
			results = append(results, scrub(err))
		} else {
			results = append(results, "ok"+detail)
		}
	}
	if c != nil {
		c.Close()
	}
	return strings.Join(results, " | ")
}

func sendMail(f []string) string {
	var a smtp.Auth
	switch f[1] {
	case "plain":
		a = smtp.PlainAuth("", "u", "p", "127.0.0.1")
	case "cram":
		a = smtp.CRAMMD5Auth("u", "p")
	}
	var to []string
	for _, t := range strings.Split(f[3], ",") {
		if t != "-" {
			to = append(to, unhex(t))
		}
	}
	err := smtp.SendMail("127.0.0.1:"+f[0], a, unhex(f[2]), to, []byte(unhex(f[4])))
	if err != nil {
		return scrub(err)
	}
	return "ok"
}

func handle(line string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Sprintf("panic %v", r)
		}
	}()
	f := strings.SplitN(line, " ", 3)
	switch f[0] {
	case "S":
		return runActions(f[1], f[2])
	case "M":
		line, _, _ = strings.Cut(line, " @ ")
		return sendMail(strings.Fields(line)[1:])
	}
	panic("bad request " + line)
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
