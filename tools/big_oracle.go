// Line-oriented Go math/big oracle for tools/big_check.py.
//
// Each request line is "<op> <arg> <arg> ..." and produces one reply line of
// space-separated tokens (see examples/big_probe.rs, which implements the same
// protocol). Integers are passed in Go's base-0 syntax and returned as
// Text(16); arbitrary strings (inputs to parsers, fmt directives and their
// output) are hex-encoded. Floats are passed as "prec,mode,text" and built
// with ParseFloat(text, 0, prec, mode); results are returned as
// "Text('p', 0)/Acc". A panic is reported as the token "panic".
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"os"
	"strconv"
	"strings"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func atoi(s string) int { return must(strconv.Atoi(s)) }

func unhex(s string) string { return string(must(hex.DecodeString(strings.TrimPrefix(s, "h")))) }

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

func pint(s string) *big.Int {
	x, ok := new(big.Int).SetString(s, 0)
	if !ok {
		panic("bad int " + s)
	}
	return x
}

func prat(s string) *big.Rat {
	x, ok := new(big.Rat).SetString(s)
	if !ok {
		panic("bad rat " + s)
	}
	return x
}

func pfloat(s string) *big.Float {
	parts := strings.SplitN(s, ",", 3)
	f, _, err := big.ParseFloat(parts[2], 0, uint(atoi(parts[0])), big.RoundingMode(atoi(parts[1])))
	if err != nil {
		panic(err)
	}
	return f
}

func ih(x *big.Int) string {
	if x == nil {
		return "nil"
	}
	return x.Text(16)
}

func fr(x *big.Float) string {
	return x.Text('p', 0) + "/" + x.Acc().String()
}

func b2s(b bool) string { return strconv.FormatBool(b) }

// try runs f and reports a panic as the token "panic", so that one panicking
// operation does not hide the others in a reply.
func try(f func() string) (out string) {
	defer func() {
		if recover() != nil {
			out = "panic"
		}
	}()
	return f()
}

func gobHex(b []byte, err error) string {
	if err != nil {
		return "err"
	}
	return hex.EncodeToString(b)
}

func f64s(x float64) string { return fmt.Sprintf("%016x", math.Float64bits(x)) }
func f32s(x float32) string { return fmt.Sprintf("%08x", math.Float32bits(x)) }
func f64(x float64) string { return fmt.Sprintf("%016x", math.Float64bits(x)) }
func f32(x float32) string { return fmt.Sprintf("%08x", math.Float32bits(x)) }

func newZ(prec, mode string) *big.Float {
	return new(big.Float).SetPrec(uint(atoi(prec))).SetMode(big.RoundingMode(atoi(mode)))
}

var textPrecs = []int{-1, 0, 1, 2, 5, 10, 17, 25, 50}

func handle(f []string) (out []string) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(big.ErrNaN); ok {
				out = []string{"nan"}
				return
			}
			out = []string{"panic"}
		}
	}()
	switch f[0] {
	// --- Int ---
	case "i.add":
		return []string{ih(new(big.Int).Add(pint(f[1]), pint(f[2])))}
	case "i.sub":
		return []string{ih(new(big.Int).Sub(pint(f[1]), pint(f[2])))}
	case "i.mul":
		return []string{ih(new(big.Int).Mul(pint(f[1]), pint(f[2])))}
	case "i.quo":
		return []string{ih(new(big.Int).Quo(pint(f[1]), pint(f[2])))}
	case "i.rem":
		return []string{ih(new(big.Int).Rem(pint(f[1]), pint(f[2])))}
	case "i.div":
		return []string{ih(new(big.Int).Div(pint(f[1]), pint(f[2])))}
	case "i.mod":
		return []string{ih(new(big.Int).Mod(pint(f[1]), pint(f[2])))}
	case "i.quorem":
		q, r := new(big.Int).QuoRem(pint(f[1]), pint(f[2]), new(big.Int))
		return []string{ih(q), ih(r)}
	case "i.divmod":
		q, r := new(big.Int).DivMod(pint(f[1]), pint(f[2]), new(big.Int))
		return []string{ih(q), ih(r)}
	case "i.divide":
		q, r := new(big.Int).Divide(pint(f[1]), pint(f[2]), new(big.Int), big.RoundingMode(atoi(f[3])))
		return []string{ih(q), ih(r)}
	case "i.cmp":
		x, y := pint(f[1]), pint(f[2])
		return []string{strconv.Itoa(x.Cmp(y)), strconv.Itoa(x.CmpAbs(y))}
	case "i.and":
		return []string{ih(new(big.Int).And(pint(f[1]), pint(f[2])))}
	case "i.or":
		return []string{ih(new(big.Int).Or(pint(f[1]), pint(f[2])))}
	case "i.xor":
		return []string{ih(new(big.Int).Xor(pint(f[1]), pint(f[2])))}
	case "i.andnot":
		return []string{ih(new(big.Int).AndNot(pint(f[1]), pint(f[2])))}
	case "i.lsh":
		return []string{ih(new(big.Int).Lsh(pint(f[1]), uint(atoi(f[2]))))}
	case "i.rsh":
		return []string{ih(new(big.Int).Rsh(pint(f[1]), uint(atoi(f[2]))))}
	case "i.bit":
		x, i := pint(f[1]), atoi(f[2])
		return []string{strconv.Itoa(int(x.Bit(i))), ih(new(big.Int).SetBit(x, i, 0)), ih(new(big.Int).SetBit(x, i, 1))}
	case "i.misc":
		x := pint(f[1])
		fv, acc := x.Float64()
		sq := "panic"
		if x.Sign() >= 0 {
			sq = ih(new(big.Int).Sqrt(x))
		}
		bs := x.Bytes()
		return []string{strconv.Itoa(x.Sign()), strconv.Itoa(x.BitLen()), strconv.Itoa(int(x.TrailingZeroBits())),
			strconv.FormatInt(x.Int64(), 10), strconv.FormatUint(x.Uint64(), 10), b2s(x.IsInt64()), b2s(x.IsUint64()),
			f64(fv), acc.String(), ih(new(big.Int).Neg(x)), ih(new(big.Int).Abs(x)), ih(new(big.Int).Not(x)), sq,
			"b" + hex.EncodeToString(bs), x.String(), string(must(x.MarshalJSON())), string(must(x.MarshalText()))}
	case "i.exp":
		var m *big.Int
		if f[3] != "nil" {
			m = pint(f[3])
		}
		return []string{ih(new(big.Int).Exp(pint(f[1]), pint(f[2]), m))}
	case "i.gcd":
		a, b := pint(f[1]), pint(f[2])
		x, y := new(big.Int), new(big.Int)
		d := new(big.Int).GCD(x, y, a, b)
		d2 := new(big.Int).GCD(nil, nil, a, b)
		return []string{ih(d), ih(x), ih(y), ih(d2)}
	case "i.modinv":
		return []string{ih(new(big.Int).ModInverse(pint(f[1]), pint(f[2])))}
	case "i.modsqrt":
		return []string{ih(new(big.Int).ModSqrt(pint(f[1]), pint(f[2])))}
	case "i.jacobi":
		return []string{strconv.Itoa(big.Jacobi(pint(f[1]), pint(f[2])))}
	case "i.prime":
		return []string{b2s(pint(f[1]).ProbablyPrime(atoi(f[2])))}
	case "i.text":
		x := pint(f[1])
		out := make([]string, 0, 61)
		for base := 2; base <= 62; base++ {
			out = append(out, x.Text(base))
		}
		return out
	case "i.parse":
		x, ok := new(big.Int).SetString(unhex(f[1]), atoi(f[2]))
		if !ok {
			return []string{"fail"}
		}
		return []string{ih(x)}
	case "i.unmarshal":
		var x big.Int
		if err := x.UnmarshalText([]byte(unhex(f[1]))); err != nil {
			return []string{"err", hx(err.Error())}
		}
		return []string{ih(&x)}
	case "i.fmt":
		return []string{hx(fmt.Sprintf(unhex(f[1]), pint(f[2])))}
	case "i.mulrange":
		a, b := must(strconv.ParseInt(f[1], 10, 64)), must(strconv.ParseInt(f[2], 10, 64))
		return []string{ih(new(big.Int).MulRange(a, b))}
	case "i.binomial":
		a, b := must(strconv.ParseInt(f[1], 10, 64)), must(strconv.ParseInt(f[2], 10, 64))
		return []string{ih(new(big.Int).Binomial(a, b))}
	case "i.fill":
		return []string{hex.EncodeToString(pint(f[1]).FillBytes(make([]byte, atoi(f[2]))))}
	case "i.setbytes":
		return []string{ih(new(big.Int).SetBytes(must(hex.DecodeString(f[1]))))}
	case "i.rand":
		r := rand.New(rand.NewSource(must(strconv.ParseInt(f[1], 10, 64))))
		n := pint(f[2])
		return []string{ih(new(big.Int).Rand(r, n)), ih(new(big.Int).Rand(r, n))}
	case "i.scan":
		var x big.Int
		if _, err := fmt.Sscanf(unhex(f[2]), "%"+f[1], &x); err != nil {
			return []string{"err"}
		}
		return []string{ih(&x)}
	case "i.gobraw":
		// GobDecode of arbitrary bytes: what Go stores unvalidated (a negative zero) and
		// how that value behaves.
		var x big.Int
		if err := x.GobDecode(must(hex.DecodeString(f[1]))); err != nil {
			return []string{"err", hx(err.Error())}
		}
		z := new(big.Int)
		out := []string{"ok", gobHex(x.GobEncode()), strconv.Itoa(x.Sign()), strconv.Itoa(x.Cmp(z)),
			strconv.Itoa(z.Cmp(&x)), strconv.Itoa(x.CmpAbs(z)), x.String(), x.Text(16),
			strconv.FormatInt(x.Int64(), 10), b2s(x.IsInt64()), b2s(x.IsUint64()), strconv.Itoa(x.BitLen())}
		for _, op := range []func() *big.Int{
			func() *big.Int { return new(big.Int).Neg(&x) },
			func() *big.Int { return new(big.Int).Abs(&x) },
			func() *big.Int { return new(big.Int).Set(&x) },
			func() *big.Int { return new(big.Int).Add(&x, z) },
			func() *big.Int { return new(big.Int).Sub(&x, z) },
			func() *big.Int { return new(big.Int).Sub(z, &x) },
			func() *big.Int { return new(big.Int).Mul(&x, big.NewInt(3)) },
			func() *big.Int { return new(big.Int).Lsh(&x, 3) },
			func() *big.Int { return new(big.Int).Rsh(&x, 1) },
			func() *big.Int { return new(big.Int).Not(&x) },
			func() *big.Int { return new(big.Int).Quo(&x, big.NewInt(3)) },
			func() *big.Int { return new(big.Int).Add(&x, big.NewInt(-5)) },
		} {
			out = append(out, try(func() string { return gobHex(op().GobEncode()) }))
		}
		for _, format := range []string{"%d", "%v", "%x", "%+d", "%s", "%10d"} {
			out = append(out, hx(fmt.Sprintf(format, &x)))
		}
		return out
	case "q.gobraw":
		var x big.Rat
		if err := x.GobDecode(must(hex.DecodeString(f[1]))); err != nil {
			return []string{"err", hx(err.Error())}
		}
		z := new(big.Rat)
		f64, exact := x.Float64()
		f32, exact32 := x.Float32()
		out := []string{"ok", gobHex(x.GobEncode()), x.String(), x.RatString(), x.FloatString(3), b2s(x.IsInt()),
			x.Num().String(), x.Denom().String(), strconv.Itoa(x.Sign()), strconv.Itoa(x.Cmp(z)), strconv.Itoa(z.Cmp(&x)),
			strconv.Itoa(x.Cmp(big.NewRat(1, 2))), f64s(f64), b2s(exact), f32s(f32), b2s(exact32)}
		for _, op := range []func() *big.Rat{
			func() *big.Rat { return new(big.Rat).Neg(&x) },
			func() *big.Rat { return new(big.Rat).Abs(&x) },
			func() *big.Rat { return new(big.Rat).Set(&x) },
			func() *big.Rat { return new(big.Rat).Add(&x, z) },
			func() *big.Rat { return new(big.Rat).Add(&x, big.NewRat(1, 3)) },
			func() *big.Rat { return new(big.Rat).Sub(z, &x) },
			func() *big.Rat { return new(big.Rat).Mul(&x, big.NewRat(3, 2)) },
			func() *big.Rat { return new(big.Rat).Quo(&x, big.NewRat(3, 2)) },
			func() *big.Rat { return new(big.Rat).Inv(&x) },
		} {
			out = append(out, try(func() string {
				r := op()
				return gobHex(r.GobEncode()) + ":" + r.String()
			}))
		}
		return out
	case "f.gobraw":
		var x big.Float
		if err := x.GobDecode(must(hex.DecodeString(f[1]))); err != nil {
			return []string{"err", hx(err.Error())}
		}
		out := []string{"ok", gobHex(x.GobEncode()), x.Mode().String(), x.Acc().String(), strconv.Itoa(int(x.Prec())),
			strconv.Itoa(int(x.MinPrec())), strconv.Itoa(x.Sign()), b2s(x.IsInf()), b2s(x.IsInt()), b2s(x.Signbit())}
		for _, op := range []func() string{
			func() string { return x.Text('p', 0) },
			func() string { return x.Text('g', 10) },
			func() string { return x.String() },
			func() string { f, a := x.Float64(); return f64s(f) + "/" + a.String() },
			func() string { f, a := x.Float32(); return f32s(f) + "/" + a.String() },
			func() string { i, a := x.Int64(); return strconv.FormatInt(i, 10) + "/" + a.String() },
			func() string { return strconv.Itoa(x.Cmp(new(big.Float))) },
			func() string { return gobHex(new(big.Float).Neg(&x).GobEncode()) },
			func() string { return gobHex(new(big.Float).Abs(&x).GobEncode()) },
			func() string { return gobHex(new(big.Float).Set(&x).GobEncode()) },
			func() string { return gobHex(new(big.Float).Add(&x, big.NewFloat(1)).GobEncode()) },
			func() string { return gobHex(new(big.Float).SetPrec(10).Set(&x).GobEncode()) },
			func() string { return gobHex(new(big.Float).Mul(&x, big.NewFloat(3)).GobEncode()) },
		} {
			out = append(out, try(op))
		}
		return out
	case "i.gob":
		b := must(pint(f[1]).GobEncode())
		var x big.Int
		if err := x.GobDecode(b); err != nil {
			panic(err)
		}
		return []string{hex.EncodeToString(b), ih(&x)}

	// --- Rat ---
	case "q.add":
		return []string{new(big.Rat).Add(prat(f[1]), prat(f[2])).String()}
	case "q.sub":
		return []string{new(big.Rat).Sub(prat(f[1]), prat(f[2])).String()}
	case "q.mul":
		return []string{new(big.Rat).Mul(prat(f[1]), prat(f[2])).String()}
	case "q.quo":
		return []string{new(big.Rat).Quo(prat(f[1]), prat(f[2])).String()}
	case "q.cmp":
		return []string{strconv.Itoa(prat(f[1]).Cmp(prat(f[2])))}
	case "q.misc":
		x := prat(f[1])
		f6, e6 := x.Float64()
		f3, e3 := x.Float32()
		inv := "panic"
		if x.Sign() != 0 {
			inv = new(big.Rat).Inv(x).String()
		}
		n, exact := x.FloatPrec()
		return []string{f64(f6), b2s(e6), f32(f3), b2s(e3), x.RatString(), x.FloatString(0), x.FloatString(1),
			x.FloatString(3), x.FloatString(20), new(big.Rat).Neg(x).String(), new(big.Rat).Abs(x).String(), inv,
			strconv.Itoa(x.Sign()), b2s(x.IsInt()), x.Num().String(), x.Denom().String(), strconv.Itoa(n), b2s(exact),
			string(must(x.MarshalText()))}
	case "q.parse":
		x, ok := new(big.Rat).SetString(unhex(f[1]))
		if !ok {
			return []string{"fail"}
		}
		return []string{x.String()}
	case "q.scan":
		var x big.Rat
		if _, err := fmt.Sscanf(unhex(f[2]), "%"+f[1], &x); err != nil {
			return []string{"err"}
		}
		return []string{x.String()}
	case "q.setf64":
		x := new(big.Rat).SetFloat64(math.Float64frombits(must(strconv.ParseUint(f[1], 16, 64))))
		if x == nil {
			return []string{"nil"}
		}
		return []string{x.String()}

	// --- Float ---
	case "f.add", "f.sub", "f.mul", "f.quo":
		z := newZ(f[1], f[2])
		x, y := pfloat(f[3]), pfloat(f[4])
		switch f[0] {
		case "f.add":
			z.Add(x, y)
		case "f.sub":
			z.Sub(x, y)
		case "f.mul":
			z.Mul(x, y)
		case "f.quo":
			z.Quo(x, y)
		}
		return []string{fr(z), strconv.Itoa(int(z.Prec()))}
	case "f.sqrt":
		z := newZ(f[1], f[2])
		z.Sqrt(pfloat(f[3]))
		return []string{z.Text('p', 0), strconv.Itoa(int(z.Prec()))}
	case "f.cmp":
		return []string{strconv.Itoa(pfloat(f[1]).Cmp(pfloat(f[2])))}
	case "f.parse":
		z := newZ(f[1], f[2])
		_, b, err := z.Parse(unhex(f[4]), atoi(f[3]))
		if err != nil {
			return []string{"err", hx(err.Error())}
		}
		return []string{fr(z), strconv.Itoa(b), strconv.Itoa(int(z.Prec()))}
	case "f.conv":
		x := pfloat(f[1])
		i64, a1 := x.Int64()
		u64, a2 := x.Uint64()
		fl64, a3 := x.Float64()
		fl32, a4 := x.Float32()
		zi, a5 := x.Int(nil)
		zr, a6 := x.Rat(nil)
		rs := "nil"
		if zr != nil {
			rs = zr.String()
		}
		var mant big.Float
		exp := x.MantExp(&mant)
		return []string{strconv.FormatInt(i64, 10), a1.String(), strconv.FormatUint(u64, 10), a2.String(),
			f64(fl64), a3.String(), f32(fl32), a4.String(), ih(zi), a5.String(), rs, a6.String(),
			b2s(x.IsInt()), strconv.Itoa(int(x.MinPrec())), b2s(x.Signbit()), strconv.Itoa(x.Sign()),
			strconv.Itoa(exp), mant.Text('p', 0), b2s(x.IsInf()), x.String(), string(must(x.MarshalText()))}
	case "f.setprec":
		x := pfloat(f[1])
		x.SetPrec(uint(atoi(f[2])))
		return []string{fr(x)}
	case "f.setmantexp":
		z := newZ(f[1], f[2])
		z.SetMantExp(pfloat(f[3]), atoi(f[4]))
		return []string{fr(z)}
	case "f.setint":
		z := newZ(f[1], f[2])
		z.SetInt(pint(f[3]))
		return []string{fr(z), strconv.Itoa(int(z.Prec()))}
	case "f.setrat":
		z := newZ(f[1], f[2])
		z.SetRat(prat(f[3]))
		return []string{fr(z), strconv.Itoa(int(z.Prec()))}
	case "f.setf64":
		z := newZ(f[1], f[2])
		z.SetFloat64(math.Float64frombits(must(strconv.ParseUint(f[3], 16, 64))))
		return []string{fr(z), strconv.Itoa(int(z.Prec()))}
	case "f.text":
		x := pfloat(f[1])
		var out []string
		for _, format := range []byte("eEfgGbpx") {
			for _, p := range textPrecs {
				out = append(out, x.Text(format, p))
			}
		}
		return out
	case "f.fmt":
		return []string{hx(fmt.Sprintf(unhex(f[1]), pfloat(f[2])))}
	case "f.scan":
		z := newZ(f[1], f[2])
		if _, err := fmt.Sscan(unhex(f[3]), z); err != nil {
			return []string{"err"}
		}
		return []string{fr(z), strconv.Itoa(int(z.Prec()))}
	case "f.gob":
		x := pfloat(f[1])
		b := must(x.GobEncode())
		var y big.Float
		if err := y.GobDecode(b); err != nil {
			panic(err)
		}
		return []string{hex.EncodeToString(b), fr(&y)}
	}
	panic("unknown op " + f[0])
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<26)
	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	for in.Scan() {
		out.WriteString(strings.Join(handle(strings.Fields(in.Text())), " "))
		out.WriteByte('\n')
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
