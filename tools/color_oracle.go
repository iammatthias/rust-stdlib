// Hash-based differential oracle for image/color conversions. Each request line
// is "<op> <model>"; the response is one FNV-1a hash over every 32-bit output
// word, so exhaustive sweeps stay cheap. tools/color_check.py runs the same
// requests against examples/color_probe.rs.
package main

import (
	"bufio"
	"fmt"
	"image/color"
	"os"
	"strings"
)

type hash uint64

func newHash() hash { return 0xcbf29ce484222325 }

func (h *hash) add(words ...uint32) {
	for _, w := range words {
		*h ^= hash(w)
		*h *= 0x100000001b3
	}
}

// rng is the xorshift64 generator shared with color_probe.rs.
type rng uint64

func (x *rng) next() uint64 {
	v := uint64(*x)
	v ^= v << 13
	v ^= v >> 7
	v ^= v << 17
	*x = rng(v)
	return v
}

// randomColor draws one color of kind next()%11, in the order Rust's probe uses:
// Rgba, Rgba64, Nrgba, Nrgba64, Gray, Gray16, Alpha, Alpha16, YCbCr, NYCbCrA, CMYK.
func randomColor(x *rng) (int, color.Color) {
	kind := int(x.next() % 11)
	u8 := func() uint8 { return uint8(x.next()) }
	u16 := func() uint16 { return uint16(x.next()) }
	switch kind {
	case 0:
		return kind, color.RGBA{u8(), u8(), u8(), u8()}
	case 1:
		return kind, color.RGBA64{u16(), u16(), u16(), u16()}
	case 2:
		return kind, color.NRGBA{u8(), u8(), u8(), u8()}
	case 3:
		return kind, color.NRGBA64{u16(), u16(), u16(), u16()}
	case 4:
		return kind, color.Gray{u8()}
	case 5:
		return kind, color.Gray16{u16()}
	case 6:
		return kind, color.Alpha{u8()}
	case 7:
		return kind, color.Alpha16{u16()}
	case 8:
		return kind, color.YCbCr{Y: u8(), Cb: u8(), Cr: u8()}
	case 9:
		return kind, color.NYCbCrA{YCbCr: color.YCbCr{Y: u8(), Cb: u8(), Cr: u8()}, A: u8()}
	default:
		return kind, color.CMYK{C: u8(), M: u8(), Y: u8(), K: u8()}
	}
}

// addColor hashes the concrete type tag and the fields of c.
func (h *hash) addColor(c color.Color) {
	_, c2 := tagOf(c)
	switch c := c.(type) {
	case color.RGBA:
		h.add(uint32(c2), uint32(c.R), uint32(c.G), uint32(c.B), uint32(c.A))
	case color.RGBA64:
		h.add(uint32(c2), uint32(c.R), uint32(c.G), uint32(c.B), uint32(c.A))
	case color.NRGBA:
		h.add(uint32(c2), uint32(c.R), uint32(c.G), uint32(c.B), uint32(c.A))
	case color.NRGBA64:
		h.add(uint32(c2), uint32(c.R), uint32(c.G), uint32(c.B), uint32(c.A))
	case color.Gray:
		h.add(uint32(c2), uint32(c.Y))
	case color.Gray16:
		h.add(uint32(c2), uint32(c.Y))
	case color.Alpha:
		h.add(uint32(c2), uint32(c.A))
	case color.Alpha16:
		h.add(uint32(c2), uint32(c.A))
	case color.YCbCr:
		h.add(uint32(c2), uint32(c.Y), uint32(c.Cb), uint32(c.Cr))
	case color.NYCbCrA:
		h.add(uint32(c2), uint32(c.Y), uint32(c.Cb), uint32(c.Cr), uint32(c.A))
	case color.CMYK:
		h.add(uint32(c2), uint32(c.C), uint32(c.M), uint32(c.Y), uint32(c.K))
	default:
		panic(fmt.Sprintf("unexpected color %T", c))
	}
}

func tagOf(c color.Color) (string, int) {
	switch c.(type) {
	case color.RGBA:
		return "rgba", 0
	case color.RGBA64:
		return "rgba64", 1
	case color.NRGBA:
		return "nrgba", 2
	case color.NRGBA64:
		return "nrgba64", 3
	case color.Gray:
		return "gray", 4
	case color.Gray16:
		return "gray16", 5
	case color.Alpha:
		return "alpha", 6
	case color.Alpha16:
		return "alpha16", 7
	case color.YCbCr:
		return "ycbcr", 8
	case color.NYCbCrA:
		return "nycbcra", 9
	case color.CMYK:
		return "cmyk", 10
	}
	panic(fmt.Sprintf("unexpected color %T", c))
}

var models = map[string]color.Model{
	"rgba":    color.RGBAModel,
	"rgba64":  color.RGBA64Model,
	"nrgba":   color.NRGBAModel,
	"nrgba64": color.NRGBA64Model,
	"gray":    color.GrayModel,
	"gray16":  color.Gray16Model,
	"alpha":   color.AlphaModel,
	"alpha16": color.Alpha16Model,
	"ycbcr":   color.YCbCrModel,
	"nycbcra": color.NYCbCrAModel,
	"cmyk":    color.CMYKModel,
}

const samples = 1 << 22

func run(op, model string) string {
	h := newHash()
	seed := rng(0x9E3779B97F4A7C15)
	x := &seed
	switch op {
	case "rgb_to_ycbcr":
		for v := 0; v < 1<<24; v++ {
			y, cb, cr := color.RGBToYCbCr(uint8(v>>16), uint8(v>>8), uint8(v))
			h.add(uint32(y), uint32(cb), uint32(cr))
		}
	case "ycbcr_to_rgb":
		for v := 0; v < 1<<24; v++ {
			r, g, b := color.YCbCrToRGB(uint8(v>>16), uint8(v>>8), uint8(v))
			h.add(uint32(r), uint32(g), uint32(b))
		}
	case "rgb_to_cmyk":
		for v := 0; v < 1<<24; v++ {
			c, m, y, k := color.RGBToCMYK(uint8(v>>16), uint8(v>>8), uint8(v))
			h.add(uint32(c), uint32(m), uint32(y), uint32(k))
		}
	case "cmyk_to_rgb":
		for i := 0; i < samples; i++ {
			v := x.next()
			r, g, b := color.CMYKToRGB(uint8(v), uint8(v>>8), uint8(v>>16), uint8(v>>24))
			h.add(uint32(r), uint32(g), uint32(b))
		}
	case "ycbcr_rgba":
		for v := 0; v < 1<<24; v++ {
			r, g, b, a := color.YCbCr{Y: uint8(v >> 16), Cb: uint8(v >> 8), Cr: uint8(v)}.RGBA()
			h.add(r, g, b, a)
		}
	case "nycbcra_rgba":
		for i := 0; i < samples; i++ {
			c := color.NYCbCrA{YCbCr: color.YCbCr{Y: uint8(x.next()), Cb: uint8(x.next()), Cr: uint8(x.next())}, A: uint8(x.next())}
			r, g, b, a := c.RGBA()
			h.add(r, g, b, a)
		}
	case "cmyk_rgba":
		for i := 0; i < samples; i++ {
			c := color.CMYK{C: uint8(x.next()), M: uint8(x.next()), Y: uint8(x.next()), K: uint8(x.next())}
			r, g, b, a := c.RGBA()
			h.add(r, g, b, a)
		}
	case "color_rgba":
		for i := 0; i < samples/4; i++ {
			_, c := randomColor(x)
			r, g, b, a := c.RGBA()
			h.add(r, g, b, a)
		}
	case "model":
		m, ok := models[model]
		if !ok {
			return "unknown model"
		}
		for i := 0; i < samples/4; i++ {
			_, c := randomColor(x)
			h.addColor(m.Convert(c))
		}
	default:
		return "unknown op"
	}
	return fmt.Sprintf("%016x", uint64(h))
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fields := strings.Fields(in.Text())
		if len(fields) != 2 {
			panic("bad request")
		}
		fmt.Fprintln(out, run(fields[0], fields[1]))
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
