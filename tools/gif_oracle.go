// Line-oriented Go image/gif oracle. Requests:
//
//	A <gif hex>   DecodeAll
//	D <gif hex>   Decode
//	C <gif hex>   DecodeConfig
//	E <config> <background> <loop> <disposal> <frame>...   EncodeAll
//	S <image> <num colors> <quantizer> <drawer>             Encode
//
// <config> is "zero", "<w>;<h>;<palette>" or "<w>;<h>;model" (a non-palette
// color model). <disposal> is "nil" or comma-separated bytes. A frame is
// <x0,y0,x1,y1>;<stride>;<delay>;<palette>;<pix hex>, where the palette "G"
// is the global palette slice itself and "G:<n>" its first n entries (sharing
// memory, as Go code that reuses one palette does). Palettes are
// comma-separated <color type>:<hex>, or "-" for none. <image> uses the
// tools/draw_oracle.go syntax. The quantizer is "nil" or "first" (the first
// distinct colors in scan order, as color.RGBA); the drawer is "nil", "Src",
// "Over" or "FS".
//
// Decoded frames print as <rect>/<delay>/<disposal>/<palette>/<pix>, palettes
// as 8-bit RGBA hex. Encoders print the GIF in hex or "err".
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"os"
	"strconv"
	"strings"
)

// Decode budget shared with examples/gif_probe.rs: the logical screen
// bounds every frame.
const maxPixels = 1 << 20

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	must(err)
	return n
}

func parsePoint(s string) image.Point {
	f := strings.Split(s, ",")
	return image.Point{atoi(f[0]), atoi(f[1])}
}

func parseRect(s string) image.Rectangle {
	f := strings.Split(s, ",")
	return image.Rectangle{image.Point{atoi(f[0]), atoi(f[1])}, image.Point{atoi(f[2]), atoi(f[3])}}
}

func parseColor(s string) color.Color {
	tag, h, _ := strings.Cut(s, ":")
	b, err := hex.DecodeString(h)
	must(err)
	u := func(i int) uint16 { return binary.BigEndian.Uint16(b[i:]) }
	switch tag {
	case "RGBA":
		return color.RGBA{b[0], b[1], b[2], b[3]}
	case "NRGBA":
		return color.NRGBA{b[0], b[1], b[2], b[3]}
	case "RGBA64":
		return color.RGBA64{u(0), u(2), u(4), u(6)}
	case "NRGBA64":
		return color.NRGBA64{u(0), u(2), u(4), u(6)}
	case "Gray":
		return color.Gray{b[0]}
	case "Gray16":
		return color.Gray16{u(0)}
	case "Alpha":
		return color.Alpha{b[0]}
	case "Alpha16":
		return color.Alpha16{u(0)}
	}
	panic("unknown color " + tag)
}

func parsePalette(s string) color.Palette {
	p := color.Palette{}
	if s != "-" {
		for _, c := range strings.Split(s, ",") {
			p = append(p, parseColor(c))
		}
	}
	return p
}

func build(spec string) image.Image {
	f := strings.Split(spec, "/")
	switch f[0] {
	case "Uniform":
		return image.NewUniform(parseColor(f[3]))
	case "Rect":
		return parseRect(f[1])
	}
	r := parseRect(f[1])
	pix, err := hex.DecodeString(f[2])
	must(err)
	w := r.Dx()
	switch f[0] {
	case "RGBA":
		return &image.RGBA{Pix: pix, Stride: 4 * w, Rect: r}
	case "NRGBA":
		return &image.NRGBA{Pix: pix, Stride: 4 * w, Rect: r}
	case "RGBA64":
		return &image.RGBA64{Pix: pix, Stride: 8 * w, Rect: r}
	case "NRGBA64":
		return &image.NRGBA64{Pix: pix, Stride: 8 * w, Rect: r}
	case "Gray":
		return &image.Gray{Pix: pix, Stride: w, Rect: r}
	case "Gray16":
		return &image.Gray16{Pix: pix, Stride: 2 * w, Rect: r}
	case "Alpha":
		return &image.Alpha{Pix: pix, Stride: w, Rect: r}
	case "Alpha16":
		return &image.Alpha16{Pix: pix, Stride: 2 * w, Rect: r}
	case "Paletted":
		return &image.Paletted{Pix: pix, Stride: w, Rect: r, Palette: parsePalette(f[3])}
	}
	panic("unknown image " + f[0])
}

type firstQuantizer struct{}

func (firstQuantizer) Quantize(p color.Palette, m image.Image) color.Palette {
	b := m.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if len(p) == cap(p) {
				return p
			}
			c := color.RGBAModel.Convert(m.At(x, y))
			found := false
			for _, q := range p {
				if q == c {
					found = true
					break
				}
			}
			if !found {
				p = append(p, c)
			}
		}
	}
	return p
}

func paletteHex(p color.Palette) string {
	if len(p) == 0 {
		return "-"
	}
	var b []byte
	for _, c := range p {
		r, g, bl, a := c.RGBA()
		b = append(b, uint8(r>>8), uint8(g>>8), uint8(bl>>8), uint8(a>>8))
	}
	return hex.EncodeToString(b)
}

func frameText(m *image.Paletted, delay int, disposal byte) string {
	b := m.Rect
	return fmt.Sprintf("%d,%d,%d,%d/%d/%d/%s/%s", b.Min.X, b.Min.Y, b.Max.X, b.Max.Y, delay, disposal,
		paletteHex(m.Palette), hex.EncodeToString(m.Pix))
}

func encodeAll(f []string) string {
	g := &gif.GIF{}
	var global color.Palette
	if f[0] != "zero" {
		c := strings.Split(f[0], ";")
		g.Config.Width, g.Config.Height = atoi(c[0]), atoi(c[1])
		if c[2] == "model" {
			g.Config.ColorModel = color.RGBAModel
		} else {
			global = parsePalette(c[2])
			g.Config.ColorModel = global
		}
	}
	g.BackgroundIndex = byte(atoi(f[1]))
	g.LoopCount = atoi(f[2])
	if f[3] != "nil" {
		g.Disposal = []byte{}
		if f[3] != "-" {
			for _, d := range strings.Split(f[3], ",") {
				g.Disposal = append(g.Disposal, byte(atoi(d)))
			}
		}
	}
	for _, frame := range f[4:] {
		p := strings.Split(frame, ";")
		pix, err := hex.DecodeString(p[4])
		must(err)
		var pal color.Palette
		switch {
		case p[3] == "G":
			pal = global
		case strings.HasPrefix(p[3], "G:"):
			pal = global[:atoi(p[3][2:])]
		default:
			pal = parsePalette(p[3])
		}
		g.Image = append(g.Image, &image.Paletted{Pix: pix, Stride: atoi(p[1]), Rect: parseRect(p[0]), Palette: pal})
		g.Delay = append(g.Delay, atoi(p[2]))
	}
	var buf bytes.Buffer
	if err := gif.EncodeAll(&buf, g); err != nil {
		return "err"
	}
	return hex.EncodeToString(buf.Bytes())
}

func encode(f []string) string {
	o := &gif.Options{NumColors: atoi(f[1])}
	if f[2] == "first" {
		o.Quantizer = firstQuantizer{}
	}
	switch f[3] {
	case "Src":
		o.Drawer = draw.Src
	case "Over":
		o.Drawer = draw.Over
	case "FS":
		o.Drawer = draw.FloydSteinberg
	}
	var buf bytes.Buffer
	if err := gif.Encode(&buf, build(f[0]), o); err != nil {
		return "err"
	}
	return hex.EncodeToString(buf.Bytes())
}

func decode(kind string, data []byte) string {
	cfg, err := gif.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return "err"
	}
	pal := color.Palette(nil)
	if p, ok := cfg.ColorModel.(color.Palette); ok {
		pal = p
	}
	if kind == "C" {
		return fmt.Sprintf("ok %d %d %s", cfg.Width, cfg.Height, paletteHex(pal))
	}
	// Same budget as the Rust probe; Go itself would try to allocate.
	if cfg.Width*cfg.Height > maxPixels {
		return "err"
	}
	if kind == "D" {
		m, err := gif.Decode(bytes.NewReader(data))
		if err != nil {
			return "err"
		}
		return "ok " + frameText(m.(*image.Paletted), 0, 0)
	}
	g, err := gif.DecodeAll(bytes.NewReader(data))
	if err != nil {
		return "err"
	}
	gp := color.Palette(nil)
	if p, ok := g.Config.ColorModel.(color.Palette); ok {
		gp = p
	}
	out := fmt.Sprintf("ok %d %d %d %d %s %d", g.Config.Width, g.Config.Height, g.BackgroundIndex, g.LoopCount,
		paletteHex(gp), len(g.Image))
	for i, m := range g.Image {
		out += " " + frameText(m, g.Delay[i], g.Disposal[i])
	}
	return out
}

// guard reports a Go panic (for example a nil palette color) as "panic".
func guard(f func([]string) string, args []string) (out string) {
	defer func() {
		if recover() != nil {
			out = "panic"
		}
	}()
	return f(args)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<16), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		kind, arg, _ := strings.Cut(in.Text(), " ")
		switch kind {
		case "A", "D", "C":
			data, err := hex.DecodeString(arg)
			must(err)
			fmt.Fprintln(out, decode(kind, data))
		case "E":
			fmt.Fprintln(out, guard(encodeAll, strings.Fields(arg)))
		case "S":
			fmt.Fprintln(out, guard(encode, strings.Fields(arg)))
		default:
			panic("bad request " + kind)
		}
	}
	must(in.Err())
}
