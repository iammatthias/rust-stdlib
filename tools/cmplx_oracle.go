// Line-oriented Go math/cmplx oracle used by tools/cmplx_check.py.
// Requests are "<op> <re> <im> [<re2> <im2>]" with 16 hex digits of IEEE bits
// per component; answers are components in the same encoding ("nan" for any
// NaN), or 0/1 for predicates. examples/cmplx_probe.rs answers the same.
package main

import (
	"bufio"
	"fmt"
	"math"
	"math/cmplx"
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

func o(x float64) string {
	if math.IsNaN(x) {
		return "nan"
	}
	return fmt.Sprintf("%016x", math.Float64bits(x))
}

func oc(z complex128) string { return o(real(z)) + " " + o(imag(z)) }

func b(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

var unary = map[string]func(complex128) complex128{
	"acos": cmplx.Acos, "acosh": cmplx.Acosh, "asin": cmplx.Asin, "asinh": cmplx.Asinh,
	"atan": cmplx.Atan, "atanh": cmplx.Atanh, "conj": cmplx.Conj, "cos": cmplx.Cos,
	"cosh": cmplx.Cosh, "cot": cmplx.Cot, "exp": cmplx.Exp, "log": cmplx.Log,
	"log10": cmplx.Log10, "sin": cmplx.Sin, "sinh": cmplx.Sinh, "sqrt": cmplx.Sqrt,
	"tan": cmplx.Tan, "tanh": cmplx.Tanh,
	"neg": func(z complex128) complex128 { return -z },
}

func answer(line string) string {
	a := strings.Fields(line)
	op, a := a[0], a[1:]
	switch op {
	case "inf":
		return oc(cmplx.Inf())
	case "nan":
		return oc(cmplx.NaN())
	case "rect":
		return oc(cmplx.Rect(f(a[0]), f(a[1])))
	}
	z := complex(f(a[0]), f(a[1]))
	if fn, ok := unary[op]; ok {
		return oc(fn(z))
	}
	switch op {
	case "abs":
		return o(cmplx.Abs(z))
	case "phase":
		return o(cmplx.Phase(z))
	case "polar":
		r, t := cmplx.Polar(z)
		return o(r) + " " + o(t)
	case "isinf":
		return b(cmplx.IsInf(z))
	case "isnan":
		return b(cmplx.IsNaN(z))
	}
	w := complex(f(a[2]), f(a[3]))
	switch op {
	case "pow":
		return oc(cmplx.Pow(z, w))
	case "add":
		return oc(z + w)
	case "sub":
		return oc(z - w)
	case "mul":
		return oc(z * w)
	case "div":
		return oc(z / w)
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
