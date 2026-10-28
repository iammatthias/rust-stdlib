// Line-protocol oracle for tools/url_check.py: one request per line, tokens
// separated by spaces, every argument hex-encoded ("_" is the empty string).
// Each reply is one line of hex tokens, or "SKIP" when a decoded component
// other than the host and user info is not valid UTF-8 (the Rust port stores
// such components with U+FFFD; the host and user info keep their raw bytes,
// and Hostname and Port are compared in their lossy form).
package main

import (
	"bufio"
	"encoding"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"unicode/utf8"
)

var (
	_ encoding.BinaryMarshaler   = (*url.URL)(nil)
	_ encoding.BinaryUnmarshaler = (*url.URL)(nil)
)

var invalidOutput bool

func enc(s string) string {
	if !utf8.ValidString(s) {
		invalidOutput = true
	}
	if s == "" {
		return "_"
	}
	return hex.EncodeToString([]byte(s))
}

// encRaw hex-encodes s without flagging invalid UTF-8: the Rust port keeps the
// raw bytes of the host and user info.
func encRaw(s string) string {
	if s == "" {
		return "_"
	}
	return hex.EncodeToString([]byte(s))
}

// encLossy encodes s the way Rust's String::from_utf8_lossy renders it: each
// maximal invalid prefix of a sequence becomes one U+FFFD.
func encLossy(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r != utf8.RuneError || n != 1 {
			b.WriteRune(r)
			i += n
			continue
		}
		b.WriteRune(utf8.RuneError)
		i += invalidPrefixLen(s[i:])
	}
	return enc(b.String())
}

// invalidPrefixLen is the length of the longest prefix of s that could begin a
// valid UTF-8 sequence (at least 1), per the Unicode "maximal subpart" rule.
func invalidPrefixLen(s string) int {
	c := s[0]
	var need int
	lo, hi := byte(0x80), byte(0xBF)
	switch {
	case c >= 0xC2 && c <= 0xDF:
		need = 2
	case c == 0xE0:
		need, lo = 3, 0xA0
	case c >= 0xE1 && c <= 0xEC, c == 0xEE, c == 0xEF:
		need = 3
	case c == 0xED:
		need, hi = 3, 0x9F
	case c == 0xF0:
		need, lo = 4, 0x90
	case c >= 0xF1 && c <= 0xF3:
		need = 4
	case c == 0xF4:
		need, hi = 4, 0x8F
	default:
		return 1
	}
	n := 1
	for n < need && n < len(s) {
		if n == 1 {
			if s[1] < lo || s[1] > hi {
				break
			}
		} else if s[n] < 0x80 || s[n] > 0xBF {
			break
		}
		n++
	}
	return n
}

func dec(s string) string {
	if s == "_" {
		return ""
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func flag(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// decodedInvalid reports whether percent-decoding every %XX in s yields
// invalid UTF-8.
func decodedInvalid(s string) bool {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if b, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				out = append(out, b...)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return !utf8.Valid(out)
}

func dumpURL(u *url.URL) []string {
	if decodedInvalid(u.RawQuery) {
		invalidOutput = true // query values are lossy in the Rust port
	}
	t := []string{"OK", enc(u.Scheme), enc(u.Opaque)}
	if u.User != nil {
		pw, set := u.User.Password()
		t = append(t, "1", encRaw(u.User.Username()), encRaw(pw), flag(set))
	} else {
		t = append(t, "0", "_", "_", "0")
	}
	t = append(t, encRaw(u.Host), enc(u.Path), enc(u.RawPath), flag(u.OmitHost), flag(u.ForceQuery),
		enc(u.RawQuery), enc(u.Fragment), enc(u.RawFragment))
	t = append(t, enc(u.String()), enc(u.Redacted()), enc(u.EscapedPath()), enc(u.EscapedFragment()),
		encLossy(u.Hostname()), encLossy(u.Port()), flag(u.IsAbs()), enc(u.RequestURI()), enc(u.Query().Encode()))
	b, _ := u.MarshalBinary()
	t = append(t, enc(string(b)))
	var back url.URL
	if err := back.UnmarshalBinary(b); err != nil {
		t = append(t, "E", enc(err.Error()))
	} else {
		t = append(t, "B", enc(back.String()))
	}
	return t
}

func result(u *url.URL, err error) []string {
	if err != nil {
		return []string{"E", enc(err.Error())}
	}
	return dumpURL(u)
}

func dumpValues(v url.Values, err error) []string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t := []string{}
	if err != nil {
		t = append(t, "E", enc(err.Error()))
	} else {
		t = append(t, "OK")
	}
	t = append(t, fmt.Sprint(len(keys)))
	for _, k := range keys {
		t = append(t, enc(k), fmt.Sprint(len(v[k])))
		for _, x := range v[k] {
			t = append(t, enc(x))
		}
	}
	t = append(t, enc(v.Encode()))
	return t
}

func handle(f []string) []string {
	args := make([]string, len(f)-1)
	for i, a := range f[1:] {
		args[i] = dec(a)
	}
	switch f[0] {
	case "P":
		u, err := url.Parse(args[0])
		return result(u, err)
	case "R":
		u, err := url.ParseRequestURI(args[0])
		return result(u, err)
	case "X":
		base, err := url.Parse(args[0])
		if err != nil {
			return []string{"E1", enc(err.Error())}
		}
		ref, err := url.Parse(args[1])
		if err != nil {
			return []string{"E2", enc(err.Error())}
		}
		t := dumpURL(base.ResolveReference(ref))
		u2, err := base.Parse(args[1])
		return append(t, result(u2, err)...)
	case "J":
		out, err := url.JoinPath(args[0], args[1:]...)
		t := []string{}
		if err != nil {
			t = append(t, "E", enc(err.Error()))
		} else {
			t = append(t, "OK", enc(out))
		}
		if u, perr := url.Parse(args[0]); perr == nil {
			t = append(t, "U", enc(u.JoinPath(args[1:]...).String()))
		}
		return t
	case "QE":
		return []string{"OK", enc(url.QueryEscape(args[0])), enc(url.PathEscape(args[0]))}
	case "QU", "PU":
		var s string
		var err error
		if f[0] == "QU" {
			s, err = url.QueryUnescape(args[0])
		} else {
			s, err = url.PathUnescape(args[0])
		}
		if err != nil {
			return []string{"E", enc(err.Error())}
		}
		return []string{"OK", enc(s)}
	case "Q":
		v, err := url.ParseQuery(args[0])
		return dumpValues(v, err)
	case "H":
		u := &url.URL{Host: args[0]}
		return []string{"OK", enc(u.Hostname()), enc(u.Port())}
	}
	panic("unknown op " + f[0])
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		if line = strings.TrimSpace(line); line != "" {
			skip := false
			fields := strings.Fields(line)
			switch fields[0] {
			case "P", "R", "X", "J":
				// URL parsing keeps the raw host and user info bytes; any other
				// invalid component is flagged by enc.
			default:
				for _, a := range fields[1:] {
					if decodedInvalid(dec(a)) {
						skip = true
					}
				}
			}
			if skip {
				fmt.Fprintln(out, "SKIP")
			} else {
				invalidOutput = false
				reply := handle(fields)
				if invalidOutput {
					reply = []string{"SKIP"}
				}
				fmt.Fprintln(out, strings.Join(reply, " "))
			}
		}
		if err != nil {
			return
		}
	}
}
