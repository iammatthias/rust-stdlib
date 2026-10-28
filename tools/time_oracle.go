// Line-oriented Go time oracle for tools/time_check.py. Requests and
// responses are tab-separated; strings are hex. Zone specs: U (UTC), L
// (Local), F<offset>,<hexname> (FixedZone), Z<name> (LoadLocation; the
// caller points ZONEINFO at the checked-in zoneinfo.zip).
//
//	F  sec nsec zone layout          -> hex(t.Format(layout))
//	S  sec nsec zone                 -> String, GoString, Date, Clock, Weekday,
//	                                    ISOWeek, YearDay, Zone, IsDST, Unix*,
//	                                    MarshalBinary/JSON/Text
//	P  layout value                  -> Parse result or hex(err.Error())
//	I  layout value zone             -> ParseInLocation
//	D  y mo d h mi s ns zone         -> Date(...) Unix, Nanosecond, Zone
//	A  sec nsec zone y m d           -> AddDate
//	R  sec nsec zone dur             -> Round, Truncate, Add(d), Sub(t)
//	U  kind hex(data)                -> UnmarshalJSON/Text/Binary result
//	N  hex(s)                        -> ParseDuration and Duration methods
//	M  nanos m                       -> Duration.Round/Truncate/Abs and floats
//	O  month weekday                 -> Month.String, Weekday.String
//	T  hex(tzif) sec,sec,...         -> LoadLocationFromTZData, then the zone at each sec
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func unhex(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

func num(s string) int64 {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		panic(err)
	}
	return v
}

var zones = map[string]*time.Location{}

func zone(spec string) *time.Location {
	switch {
	case spec == "U":
		return time.UTC
	case spec == "L":
		return time.Local
	case spec[0] == 'F':
		off, name, _ := strings.Cut(spec[1:], ",")
		return time.FixedZone(unhex(name), int(num(off)))
	case spec[0] == 'Z':
		if l, ok := zones[spec]; ok {
			return l
		}
		l, err := time.LoadLocation(spec[1:])
		if err != nil {
			panic(err)
		}
		zones[spec] = l
		return l
	}
	panic("bad zone " + spec)
}

func errText(err error) string {
	if err == nil {
		return "nil"
	}
	return hx(err.Error())
}

func describe(t time.Time) string {
	name, off := t.Zone()
	return fmt.Sprintf("%d\t%d\t%s\t%d\t%s\t%s", t.Unix(), t.Nanosecond(), hx(name), off,
		hx(t.Location().String()), hx(t.String()))
}

func state(t time.Time) string {
	y, mo, d := t.Date()
	h, mi, s := t.Clock()
	iy, iw := t.ISOWeek()
	name, off := t.Zone()
	bin, berr := t.MarshalBinary()
	js, jerr := t.MarshalJSON()
	tx, terr := t.MarshalText()
	return strings.Join([]string{
		hx(t.String()), hx(t.GoString()),
		fmt.Sprintf("%d,%d,%d,%d,%d,%d,%d,%d,%d,%d", y, mo, d, h, mi, s, t.Weekday(), iy, iw, t.YearDay()),
		fmt.Sprintf("%s,%d,%t,%t", hx(name), off, t.IsDST(), t.IsZero()),
		fmt.Sprintf("%d,%d,%d,%d", t.Unix(), t.UnixMilli(), t.UnixMicro(), t.UnixNano()),
		hex.EncodeToString(bin) + "," + errText(berr),
		hex.EncodeToString(js) + "," + errText(jerr),
		hex.EncodeToString(tx) + "," + errText(terr),
	}, "\t")
}

func handle(f []string) string {
	switch f[0] {
	case "F":
		t := time.Unix(num(f[1]), num(f[2])).In(zone(f[3]))
		return hx(t.Format(unhex(f[4])))
	case "S":
		return state(time.Unix(num(f[1]), num(f[2])).In(zone(f[3])))
	case "P", "I":
		var t time.Time
		var err error
		if f[0] == "P" {
			t, err = time.Parse(unhex(f[1]), unhex(f[2]))
		} else {
			t, err = time.ParseInLocation(unhex(f[1]), unhex(f[2]), zone(f[3]))
		}
		if err != nil {
			pe := err.(*time.ParseError)
			// The Rust port decodes elements that split a UTF-8 sequence
			// lossily; both sides print "?" for those.
			if !utf8.ValidString(pe.LayoutElem) || !utf8.ValidString(pe.ValueElem) {
				return "err\t?"
			}
			return "err\t" + hx(err.Error()) + "\t" + strings.Join([]string{hx(pe.Layout), hx(pe.Value),
				hx(pe.LayoutElem), hx(pe.ValueElem), hx(pe.Message)}, ",")
		}
		return "ok\t" + describe(t)
	case "D":
		t := time.Date(int(num(f[1])), time.Month(num(f[2])), int(num(f[3])), int(num(f[4])),
			int(num(f[5])), int(num(f[6])), int(num(f[7])), zone(f[8]))
		return describe(t)
	case "A":
		t := time.Unix(num(f[1]), num(f[2])).In(zone(f[3]))
		return describe(t.AddDate(int(num(f[4])), int(num(f[5])), int(num(f[6]))))
	case "R":
		t := time.Unix(num(f[1]), num(f[2])).In(zone(f[3]))
		d := time.Duration(num(f[4]))
		u := time.Unix(num(f[5]), num(f[6]))
		return strings.Join([]string{describe(t.Round(d)), describe(t.Truncate(d)), describe(t.Add(d)),
			strconv.FormatInt(int64(t.Sub(u)), 10), strconv.Itoa(t.Compare(u)),
			strconv.FormatBool(t.Before(u)), strconv.FormatBool(t.After(u)), strconv.FormatBool(t.Equal(u))}, "\t")
	case "U":
		var t time.Time
		data, _ := hex.DecodeString(f[2])
		var err error
		switch f[1] {
		case "json":
			err = t.UnmarshalJSON(data)
		case "text":
			err = t.UnmarshalText(data)
		case "binary":
			err = t.UnmarshalBinary(data)
		}
		if err != nil {
			return "err\t" + hx(err.Error())
		}
		return "ok\t" + describe(t)
	case "N":
		d, err := time.ParseDuration(unhex(f[1]))
		if err != nil {
			return "err\t" + hx(err.Error())
		}
		return fmt.Sprintf("ok\t%d\t%s", int64(d), hx(d.String()))
	case "M":
		d := time.Duration(num(f[1]))
		m := time.Duration(num(f[2]))
		return fmt.Sprintf("%d\t%d\t%d\t%x\t%x\t%x\t%d\t%d\t%s", d.Round(m), d.Truncate(m), d.Abs(),
			math.Float64bits(d.Seconds()), math.Float64bits(d.Minutes()), math.Float64bits(d.Hours()),
			d.Milliseconds(), d.Microseconds(), hx(d.String()))
	case "T":
		loc, err := time.LoadLocationFromTZData("x", []byte(unhex(f[1])))
		if err != nil {
			return "err\t" + hx(err.Error())
		}
		out := []string{"ok"}
		for _, sec := range strings.Split(f[2], ",") {
			name, off := time.Unix(num(sec), 0).In(loc).Zone()
			if !utf8.ValidString(name) {
				return "skip"
			}
			out = append(out, hx(name)+","+strconv.Itoa(off))
		}
		return strings.Join(out, "\t")
	case "O":
		return hx(time.Month(num(f[1])).String()) + "\t" + hx(time.Weekday(num(f[2])).String())
	}
	panic("bad mode " + f[0])
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<24)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for in.Scan() {
		line := in.Text()
		if line == "" {
			continue
		}
		fmt.Fprintln(w, handle(strings.Split(line, "\t")))
	}
}
