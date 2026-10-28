// Line-oriented Go time-zone oracle for tools/tzif_check.py. Each request is
// MODE:hex(TZif):args and is answered with one line.
//
//	Z  args are comma-separated Unix seconds; each answer is
//	   offset,hex(abbreviation),isDST,zoneStart,zoneEnd from Zone, IsDST and
//	   ZoneBounds ("-" for an unbounded side).
//	S  args are sec.nsec pairs; each answer is hex(Time.In(loc).String()).
//	D  args are y.mo.d.h.mi.s civil fields; each answer is Date(...).Unix().
//	L  the hex field is a zone name for LoadLocation (ZONEINFO is set by the
//	   caller); the answer is ok, the location name and Z answers for args,
//	   or the error class invalid, unknown or other.
//
// Answers are joined with ';'. "err" means LoadLocationFromTZData failed.
// Abbreviations that are not valid UTF-8 (or contain U+FFFD) print as "?"
// because the Rust port decodes them lossily.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func name(s string) string {
	if !utf8.ValidString(s) || strings.ContainsRune(s, utf8.RuneError) {
		return "?"
	}
	return hex.EncodeToString([]byte(s))
}

func bound(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return strconv.FormatInt(t.Unix(), 10)
}

func ints(s string, sep string) []int64 {
	parts := strings.Split(s, sep)
	out := make([]int64, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			panic(err)
		}
		out[i] = v
	}
	return out
}

func load(name string) (*time.Location, string) {
	loc, err := time.LoadLocation(name)
	switch {
	case err == nil:
		return loc, ""
	case err.Error() == "time: invalid location name":
		return nil, "invalid"
	case strings.HasPrefix(err.Error(), "unknown time zone "):
		return nil, "unknown"
	}
	return nil, "other"
}

func handle(mode string, data []byte, args string) string {
	var loc *time.Location
	var err error
	prefix := "ok\t"
	if mode == "L" {
		var class string
		if loc, class = load(string(data)); loc == nil {
			return class
		}
		prefix += hex.EncodeToString([]byte(loc.String())) + "\t"
		mode = "Z"
	} else if loc, err = time.LoadLocationFromTZData("Zone", data); err != nil {
		return "err"
	}
	var out []string
	for _, arg := range strings.Split(args, ",") {
		if arg == "" {
			continue
		}
		switch mode {
		case "Z":
			t := time.Unix(ints(arg, ".")[0], 0).In(loc)
			abbr, offset := t.Zone()
			start, end := t.ZoneBounds()
			dst := 0
			if t.IsDST() {
				dst = 1
			}
			out = append(out, fmt.Sprintf("%d,%s,%d,%s,%s", offset, name(abbr), dst, bound(start), bound(end)))
		case "S":
			v := ints(arg, ".")
			t := time.Unix(v[0], v[1]).In(loc)
			abbr, _ := t.Zone()
			if name(abbr) == "?" {
				out = append(out, "?")
			} else {
				out = append(out, hex.EncodeToString([]byte(t.String())))
			}
		case "D":
			v := ints(arg, ".")
			t := time.Date(int(v[0]), time.Month(v[1]), int(v[2]), int(v[3]), int(v[4]), int(v[5]), 0, loc)
			out = append(out, strconv.FormatInt(t.Unix(), 10))
		}
	}
	return prefix + strings.Join(out, ";")
}

func main() {
	// Pin Local like the Rust side's TZ=UTC; Windows ignores TZ.
	time.Local = time.UTC
	in := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for {
		line, err := in.ReadString('\n')
		line = strings.TrimRight(line, "\n")
		if line != "" {
			parts := strings.SplitN(line, ":", 3)
			data, herr := hex.DecodeString(parts[1])
			if herr != nil {
				panic(herr)
			}
			fmt.Fprintln(w, handle(parts[0], data, parts[2]))
		}
		if err != nil {
			break
		}
	}
}
