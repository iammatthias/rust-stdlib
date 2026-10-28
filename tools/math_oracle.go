// Line-oriented Go math and math/bits oracle used by tools/math_check.py.
// Each request is "<op> <arg>..."; floating-point arguments are 16 hex digits
// of IEEE 754 bits, integers are decimal. The answer is one line: results as
// 16 hex digits of bits (any NaN prints "nan") or decimal integers, or
// "panic" if Go panics. examples/math_probe.rs answers the same requests.
package main

import (
	"bufio"
	"fmt"
	"math"
	"math/bits"
	"os"
	"strconv"
	"strings"
)

func f(s string) float64 {
	u, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		panic(err)
	}
	return math.Float64frombits(u)
}

func i(s string) int {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		panic(err)
	}
	return int(v)
}

func u(s string) uint64 {
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		panic(err)
	}
	return v
}

func o(x float64) string {
	if math.IsNaN(x) {
		return "nan"
	}
	return fmt.Sprintf("%016x", math.Float64bits(x))
}

var unary = map[string]func(float64) float64{
	"abs": math.Abs, "acos": math.Acos, "acosh": math.Acosh, "asin": math.Asin,
	"asinh": math.Asinh, "atan": math.Atan, "atanh": math.Atanh, "cbrt": math.Cbrt,
	"ceil": math.Ceil, "cos": math.Cos, "cosh": math.Cosh, "erf": math.Erf,
	"erfc": math.Erfc, "erfinv": math.Erfinv, "erfcinv": math.Erfcinv, "exp": math.Exp,
	"exp2": math.Exp2, "expm1": math.Expm1, "floor": math.Floor, "gamma": math.Gamma,
	"j0": math.J0, "j1": math.J1, "log": math.Log, "log10": math.Log10,
	"log1p": math.Log1p, "log2": math.Log2, "logb": math.Logb, "round": math.Round,
	"roundtoeven": math.RoundToEven, "sin": math.Sin, "sinh": math.Sinh,
	"sqrt": math.Sqrt, "tan": math.Tan, "tanh": math.Tanh, "trunc": math.Trunc,
	"y0": math.Y0, "y1": math.Y1,
}

var binary = map[string]func(float64, float64) float64{
	"atan2": math.Atan2, "copysign": math.Copysign, "dim": math.Dim, "hypot": math.Hypot,
	"max": math.Max, "min": math.Min, "mod": math.Mod, "nextafter": math.Nextafter,
	"pow": math.Pow, "remainder": math.Remainder,
}

func b(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

func answer(line string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "panic"
		}
	}()
	a := strings.Fields(line)
	op, a := a[0], a[1:]
	if fn, ok := unary[op]; ok {
		return o(fn(f(a[0])))
	}
	if fn, ok := binary[op]; ok {
		return o(fn(f(a[0]), f(a[1])))
	}
	switch op {
	case "fma":
		return o(math.FMA(f(a[0]), f(a[1]), f(a[2])))
	case "frexp":
		fr, e := math.Frexp(f(a[0]))
		return o(fr) + " " + strconv.Itoa(e)
	case "ldexp":
		return o(math.Ldexp(f(a[0]), i(a[1])))
	case "modf":
		ip, fp := math.Modf(f(a[0]))
		return o(ip) + " " + o(fp)
	case "lgamma":
		l, s := math.Lgamma(f(a[0]))
		return o(l) + " " + strconv.Itoa(s)
	case "sincos":
		s, c := math.Sincos(f(a[0]))
		return o(s) + " " + o(c)
	case "jn":
		return o(math.Jn(i(a[0]), f(a[1])))
	case "yn":
		return o(math.Yn(i(a[0]), f(a[1])))
	case "ilogb":
		return strconv.Itoa(math.Ilogb(f(a[0])))
	case "pow10":
		return o(math.Pow10(i(a[0])))
	case "isinf":
		return b(math.IsInf(f(a[0]), i(a[1])))
	case "isnan":
		return b(math.IsNaN(f(a[0])))
	case "signbit":
		return b(math.Signbit(f(a[0])))
	case "inf":
		return o(math.Inf(i(a[0])))
	case "nan":
		return fmt.Sprintf("%016x", math.Float64bits(math.NaN()))
	case "f64bits":
		return fmt.Sprintf("%016x", math.Float64bits(f(a[0])))
	case "f32bits":
		return fmt.Sprintf("%08x", math.Float32bits(float32(f(a[0]))))
	case "f32from":
		v := math.Float32frombits(uint32(u(a[0])))
		if v != v {
			return "nan"
		}
		return fmt.Sprintf("%016x", math.Float64bits(float64(v)))
	case "nextafter32":
		x, y := float32(f(a[0])), float32(f(a[1]))
		r := math.Nextafter32(x, y)
		if r != r {
			return "nan"
		}
		return fmt.Sprintf("%08x", math.Float32bits(r))
	case "const":
		consts := []float64{math.E, math.Pi, math.Phi, math.Sqrt2, math.SqrtE, math.SqrtPi,
			math.SqrtPhi, math.Ln2, math.Log2E, math.Ln10, math.Log10E, math.MaxFloat32,
			math.SmallestNonzeroFloat32, math.MaxFloat64, math.SmallestNonzeroFloat64}
		var parts []string
		for _, c := range consts {
			parts = append(parts, o(c))
		}
		return strings.Join(parts, " ")
	case "intconst":
		return fmt.Sprint(math.MaxInt8, math.MinInt8, math.MaxInt16, math.MinInt16, math.MaxInt32,
			math.MinInt32, int64(math.MaxInt64), int64(math.MinInt64), math.MaxUint8, math.MaxUint16,
			uint32(math.MaxUint32), uint64(math.MaxUint64), math.MaxInt, math.MinInt, uint(math.MaxUint), bits.UintSize)
	// math/bits: operands are decimal unsigned integers.
	case "lz8":
		return strconv.Itoa(bits.LeadingZeros8(uint8(u(a[0]))))
	case "lz16":
		return strconv.Itoa(bits.LeadingZeros16(uint16(u(a[0]))))
	case "lz32":
		return strconv.Itoa(bits.LeadingZeros32(uint32(u(a[0]))))
	case "lz64":
		return strconv.Itoa(bits.LeadingZeros64(u(a[0])))
	case "lz":
		return strconv.Itoa(bits.LeadingZeros(uint(u(a[0]))))
	case "tz8":
		return strconv.Itoa(bits.TrailingZeros8(uint8(u(a[0]))))
	case "tz16":
		return strconv.Itoa(bits.TrailingZeros16(uint16(u(a[0]))))
	case "tz32":
		return strconv.Itoa(bits.TrailingZeros32(uint32(u(a[0]))))
	case "tz64":
		return strconv.Itoa(bits.TrailingZeros64(u(a[0])))
	case "tz":
		return strconv.Itoa(bits.TrailingZeros(uint(u(a[0]))))
	case "oc8":
		return strconv.Itoa(bits.OnesCount8(uint8(u(a[0]))))
	case "oc16":
		return strconv.Itoa(bits.OnesCount16(uint16(u(a[0]))))
	case "oc32":
		return strconv.Itoa(bits.OnesCount32(uint32(u(a[0]))))
	case "oc64":
		return strconv.Itoa(bits.OnesCount64(u(a[0])))
	case "oc":
		return strconv.Itoa(bits.OnesCount(uint(u(a[0]))))
	case "len8":
		return strconv.Itoa(bits.Len8(uint8(u(a[0]))))
	case "len16":
		return strconv.Itoa(bits.Len16(uint16(u(a[0]))))
	case "len32":
		return strconv.Itoa(bits.Len32(uint32(u(a[0]))))
	case "len64":
		return strconv.Itoa(bits.Len64(u(a[0])))
	case "len":
		return strconv.Itoa(bits.Len(uint(u(a[0]))))
	case "rev8":
		return fmt.Sprint(bits.Reverse8(uint8(u(a[0]))))
	case "rev16":
		return fmt.Sprint(bits.Reverse16(uint16(u(a[0]))))
	case "rev32":
		return fmt.Sprint(bits.Reverse32(uint32(u(a[0]))))
	case "rev64":
		return fmt.Sprint(bits.Reverse64(u(a[0])))
	case "rev":
		return fmt.Sprint(bits.Reverse(uint(u(a[0]))))
	case "revb16":
		return fmt.Sprint(bits.ReverseBytes16(uint16(u(a[0]))))
	case "revb32":
		return fmt.Sprint(bits.ReverseBytes32(uint32(u(a[0]))))
	case "revb64":
		return fmt.Sprint(bits.ReverseBytes64(u(a[0])))
	case "revb":
		return fmt.Sprint(bits.ReverseBytes(uint(u(a[0]))))
	case "rot8":
		return fmt.Sprint(bits.RotateLeft8(uint8(u(a[0])), i(a[1])))
	case "rot16":
		return fmt.Sprint(bits.RotateLeft16(uint16(u(a[0])), i(a[1])))
	case "rot32":
		return fmt.Sprint(bits.RotateLeft32(uint32(u(a[0])), i(a[1])))
	case "rot64":
		return fmt.Sprint(bits.RotateLeft64(u(a[0]), i(a[1])))
	case "rot":
		return fmt.Sprint(bits.RotateLeft(uint(u(a[0])), i(a[1])))
	case "add32":
		s, c := bits.Add32(uint32(u(a[0])), uint32(u(a[1])), uint32(u(a[2])))
		return fmt.Sprint(s, c)
	case "add64":
		s, c := bits.Add64(u(a[0]), u(a[1]), u(a[2]))
		return fmt.Sprint(s, c)
	case "add":
		s, c := bits.Add(uint(u(a[0])), uint(u(a[1])), uint(u(a[2])))
		return fmt.Sprint(s, c)
	case "sub32":
		s, c := bits.Sub32(uint32(u(a[0])), uint32(u(a[1])), uint32(u(a[2])))
		return fmt.Sprint(s, c)
	case "sub64":
		s, c := bits.Sub64(u(a[0]), u(a[1]), u(a[2]))
		return fmt.Sprint(s, c)
	case "sub":
		s, c := bits.Sub(uint(u(a[0])), uint(u(a[1])), uint(u(a[2])))
		return fmt.Sprint(s, c)
	case "mul32":
		h, l := bits.Mul32(uint32(u(a[0])), uint32(u(a[1])))
		return fmt.Sprint(h, l)
	case "mul64":
		h, l := bits.Mul64(u(a[0]), u(a[1]))
		return fmt.Sprint(h, l)
	case "mul":
		h, l := bits.Mul(uint(u(a[0])), uint(u(a[1])))
		return fmt.Sprint(h, l)
	case "div32":
		q, r := bits.Div32(uint32(u(a[0])), uint32(u(a[1])), uint32(u(a[2])))
		return fmt.Sprint(q, r)
	case "div64":
		q, r := bits.Div64(u(a[0]), u(a[1]), u(a[2]))
		return fmt.Sprint(q, r)
	case "div":
		q, r := bits.Div(uint(u(a[0])), uint(u(a[1])), uint(u(a[2])))
		return fmt.Sprint(q, r)
	case "rem32":
		return fmt.Sprint(bits.Rem32(uint32(u(a[0])), uint32(u(a[1])), uint32(u(a[2]))))
	case "rem64":
		return fmt.Sprint(bits.Rem64(u(a[0]), u(a[1]), u(a[2])))
	case "rem":
		return fmt.Sprint(bits.Rem(uint(u(a[0])), uint(u(a[1])), uint(u(a[2]))))
	}
	return "unknown op " + op
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, answer(in.Text()))
	}
}
