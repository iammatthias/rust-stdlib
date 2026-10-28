// Line-oriented Go strconv oracle. Requests are tab-separated; byte strings
// travel as hex. See tools/strconv_check.py for the request catalogue.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

func unhex(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func enc(s string) string { return hex.EncodeToString([]byte(s)) }

func errStr(err error) string {
	if err == nil {
		return "-"
	}
	return enc(err.Error())
}

func fbits(f float64) string {
	if math.IsNaN(f) {
		return "nan"
	}
	return fmt.Sprintf("%016x", math.Float64bits(f))
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 4096), 16*1024*1024)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	for in.Scan() {
		f := strings.Split(in.Text(), "\t")
		switch f[0] {
		case "F": // bits, fmt, prec, bitSize
			var bits uint64
			fmt.Sscanf(f[1], "%x", &bits)
			v := math.Float64frombits(bits)
			bs := atoi(f[4])
			if bs == 32 {
				v = float64(math.Float32frombits(uint32(bits)))
			}
			fmt.Fprintln(out, strconv.FormatFloat(v, f[2][0], atoi(f[3]), bs))
		case "P": // hex string, bitSize
			v, err := strconv.ParseFloat(unhex(f[1]), atoi(f[2]))
			fmt.Fprintf(out, "%s %s\n", fbits(v), errStr(err))
		case "I", "U":
			s, base, bs := unhex(f[1]), atoi(f[2]), atoi(f[3])
			if f[0] == "I" {
				v, err := strconv.ParseInt(s, base, bs)
				fmt.Fprintf(out, "%d %s\n", v, errStr(err))
			} else {
				v, err := strconv.ParseUint(s, base, bs)
				fmt.Fprintf(out, "%d %s\n", v, errStr(err))
			}
		case "A":
			v, err := strconv.Atoi(unhex(f[1]))
			fmt.Fprintf(out, "%d %s\n", v, errStr(err))
		case "B":
			v, err := strconv.ParseBool(unhex(f[1]))
			fmt.Fprintf(out, "%v %s\n", v, errStr(err))
		case "FI": // int formatting: value, base
			v, base := int64(0), atoi(f[2])
			fmt.Sscanf(f[1], "%d", &v)
			fmt.Fprintf(out, "%s %s %s\n", strconv.FormatInt(v, base), strconv.FormatUint(uint64(v), base), string(strconv.AppendInt([]byte("x"), v, base)))
		case "C": // hex string, bitSize
			v, err := strconv.ParseComplex(unhex(f[1]), atoi(f[2]))
			fmt.Fprintf(out, "%s %s %s\n", fbits(real(v)), fbits(imag(v)), errStr(err))
		case "FC": // re bits, im bits, fmt, prec, bitSize
			var rb, ib uint64
			fmt.Sscanf(f[1], "%x", &rb)
			fmt.Sscanf(f[2], "%x", &ib)
			re, im := math.Float64frombits(rb), math.Float64frombits(ib)
			bs := atoi(f[5])
			if bs == 64 {
				re, im = float64(float32(re)), float64(float32(im))
			}
			fmt.Fprintln(out, strconv.FormatComplex(complex(re, im), f[3][0], atoi(f[4]), bs))
		case "Q": // variant, hex string
			s := unhex(f[2])
			var r string
			switch f[1] {
			case "0":
				r = strconv.Quote(s)
			case "1":
				r = strconv.QuoteToASCII(s)
			case "2":
				r = strconv.QuoteToGraphic(s)
			}
			fmt.Fprintf(out, "%s %s\n", enc(r), enc(string(strconv.AppendQuote([]byte("x"), s))))
		case "R": // variant, rune
			var r int32
			fmt.Sscanf(f[2], "%d", &r)
			var q string
			switch f[1] {
			case "0":
				q = strconv.QuoteRune(r)
			case "1":
				q = strconv.QuoteRuneToASCII(r)
			case "2":
				q = strconv.QuoteRuneToGraphic(r)
			}
			fmt.Fprintf(out, "%s %v %v\n", enc(q), strconv.IsPrint(r), strconv.IsGraphic(r))
		case "UQ":
			v, err := strconv.Unquote(unhex(f[1]))
			fmt.Fprintf(out, "%s %s\n", enc(v), errStr(err))
		case "QP":
			v, err := strconv.QuotedPrefix(unhex(f[1]))
			fmt.Fprintf(out, "%s %s\n", enc(v), errStr(err))
		case "UC": // hex string, quote byte
			q := byte(atoi(f[2]))
			v, mb, tail, err := strconv.UnquoteChar(unhex(f[1]), q)
			fmt.Fprintf(out, "%d %v %s %s\n", v, mb, enc(tail), errStr(err))
		case "CB":
			fmt.Fprintf(out, "%v\n", strconv.CanBackquote(unhex(f[1])))
		default:
			panic("unknown request " + f[0])
		}
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
