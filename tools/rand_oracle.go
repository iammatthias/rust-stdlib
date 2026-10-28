// Line-oriented Go math/rand and math/rand/v2 oracle.
//
// Each request is "<generator> | <op> <op> ...", where the generator is
// "pcg <seed1> <seed2>", "chacha <64 hex seed>" or "v1 <seed>", and each op is
// "Name" or "Name:arg". The reply is one space-separated token per op: integers
// in decimal, floats as IEEE-754 bit patterns in hex, permutations joined by
// commas and byte strings in hex.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	randv1 "math/rand"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"time"
)

func f64(x float64) string { return fmt.Sprintf("%016x", math.Float64bits(x)) }
func f32(x float32) string { return fmt.Sprintf("%08x", math.Float32bits(x)) }

func ints(p []int) string {
	parts := make([]string, len(p))
	for i, v := range p {
		parts[i] = strconv.Itoa(v)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// zipfArgs parses "s:v:imax:count" for the Zipf op.
func zipfArgs(arg string) (float64, float64, uint64, int) {
	p := strings.Split(arg, ":")
	return must(strconv.ParseFloat(p[0], 64)), must(strconv.ParseFloat(p[1], 64)),
		u64(p[2]), int(i64(p[3]))
}

func u64(s string) uint64 { return must(strconv.ParseUint(s, 10, 64)) }
func i64(s string) int64  { return must(strconv.ParseInt(s, 10, 64)) }

func v2op(r *rand.Rand, pcg *rand.PCG, cc *rand.ChaCha8, name, arg string) string {
	switch name {
	case "Int64":
		return fmt.Sprint(r.Int64())
	case "Uint32":
		return fmt.Sprint(r.Uint32())
	case "Uint64":
		return fmt.Sprint(r.Uint64())
	case "Int32":
		return fmt.Sprint(r.Int32())
	case "Int":
		return fmt.Sprint(r.Int())
	case "Uint":
		return fmt.Sprint(r.Uint())
	case "Int64N":
		return fmt.Sprint(r.Int64N(i64(arg)))
	case "Uint64N":
		return fmt.Sprint(r.Uint64N(u64(arg)))
	case "Int32N":
		return fmt.Sprint(r.Int32N(int32(i64(arg))))
	case "Uint32N":
		return fmt.Sprint(r.Uint32N(uint32(u64(arg))))
	case "IntN":
		return fmt.Sprint(r.IntN(int(i64(arg))))
	case "UintN":
		return fmt.Sprint(r.UintN(uint(u64(arg))))
	case "NInt8": // Go 1.27 generic method Rand.N
		return fmt.Sprint(r.N(int8(i64(arg))))
	case "NUint16":
		return fmt.Sprint(r.N(uint16(u64(arg))))
	case "NInt64":
		return fmt.Sprint(r.N(i64(arg)))
	case "NDuration":
		return fmt.Sprint(int64(r.N(time.Duration(i64(arg)))))
	case "Float64":
		return f64(r.Float64())
	case "Float32":
		return f32(r.Float32())
	case "Perm":
		return ints(r.Perm(int(i64(arg))))
	case "Shuffle":
		p := make([]int, i64(arg))
		for i := range p {
			p[i] = i
		}
		r.Shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] })
		return ints(p)
	case "NormFloat64":
		return f64(r.NormFloat64())
	case "ExpFloat64":
		return f64(r.ExpFloat64())
	case "Zipf":
		s, v, imax, count := zipfArgs(arg)
		z := rand.NewZipf(r, s, v, imax)
		if z == nil {
			return "nil"
		}
		vals := make([]string, count)
		for i := range vals {
			vals[i] = fmt.Sprint(z.Uint64())
		}
		return strings.Join(vals, ",")
	case "Read":
		buf := make([]byte, i64(arg))
		if n := must(cc.Read(buf)); n != len(buf) {
			panic("short read")
		}
		return hex.EncodeToString(buf)
	case "Marshal":
		if pcg != nil {
			data := must(pcg.MarshalBinary())
			*pcg = rand.PCG{}
			if err := pcg.UnmarshalBinary(data); err != nil {
				panic(err)
			}
			return hex.EncodeToString(data)
		}
		data := must(cc.MarshalBinary())
		*cc = *rand.NewChaCha8([32]byte{})
		if err := cc.UnmarshalBinary(data); err != nil {
			panic(err)
		}
		return hex.EncodeToString(data)
	default:
		panic("unknown v2 op " + name)
	}
}

func v1op(r *randv1.Rand, name, arg string) string {
	switch name {
	case "Seed":
		r.Seed(i64(arg))
		return "-"
	case "Int63":
		return fmt.Sprint(r.Int63())
	case "Uint32":
		return fmt.Sprint(r.Uint32())
	case "Uint64":
		return fmt.Sprint(r.Uint64())
	case "Int31":
		return fmt.Sprint(r.Int31())
	case "Int":
		return fmt.Sprint(r.Int())
	case "Int63n":
		return fmt.Sprint(r.Int63n(i64(arg)))
	case "Int31n":
		return fmt.Sprint(r.Int31n(int32(i64(arg))))
	case "Intn":
		return fmt.Sprint(r.Intn(int(i64(arg))))
	case "Float64":
		return f64(r.Float64())
	case "Float32":
		return f32(r.Float32())
	case "Perm":
		return ints(r.Perm(int(i64(arg))))
	case "Shuffle":
		p := make([]int, i64(arg))
		for i := range p {
			p[i] = i
		}
		r.Shuffle(len(p), func(i, j int) { p[i], p[j] = p[j], p[i] })
		return ints(p)
	case "Read":
		buf := make([]byte, i64(arg))
		if n := must(r.Read(buf)); n != len(buf) {
			panic("short read")
		}
		return hex.EncodeToString(buf)
	case "NormFloat64":
		return f64(r.NormFloat64())
	case "ExpFloat64":
		return f64(r.ExpFloat64())
	case "Zipf":
		s, v, imax, count := zipfArgs(arg)
		z := randv1.NewZipf(r, s, v, imax)
		if z == nil {
			return "nil"
		}
		vals := make([]string, count)
		for i := range vals {
			vals[i] = fmt.Sprint(z.Uint64())
		}
		return strings.Join(vals, ",")
	}
	panic("unknown v1 op " + name)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 4096), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		head, body, ok := strings.Cut(in.Text(), " | ")
		if !ok {
			panic("bad request")
		}
		gen := strings.Fields(head)
		var reply []string
		ops := strings.Fields(body)
		switch gen[0] {
		case "pcg":
			p := rand.NewPCG(u64(gen[1]), u64(gen[2]))
			r := rand.New(p)
			for _, op := range ops {
				name, arg, _ := strings.Cut(op, ":")
				reply = append(reply, v2op(r, p, nil, name, arg))
			}
		case "chacha":
			seed := must(hex.DecodeString(gen[1]))
			c := rand.NewChaCha8([32]byte(seed))
			r := rand.New(c)
			for _, op := range ops {
				name, arg, _ := strings.Cut(op, ":")
				reply = append(reply, v2op(r, nil, c, name, arg))
			}
		case "v1":
			r := randv1.New(randv1.NewSource(i64(gen[1])))
			for _, op := range ops {
				name, arg, _ := strings.Cut(op, ":")
				reply = append(reply, v1op(r, name, arg))
			}
		default:
			panic("unknown generator " + gen[0])
		}
		fmt.Fprintln(out, strings.Join(reply, " "))
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
