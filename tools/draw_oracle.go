// Line-oriented Go image/draw oracle. Requests:
//
//	D <dst> <src or SELF> <mask or nil> <x0,y0,x1,y1> <sx,sy> <mx,my> <Over|Src>
//	F <dst> <src> <x0,y0,x1,y1> <sx,sy>
//	U <img> <x0,y0,x1,y1> <px,py> <color> <cx,cy> <color>
//
// U takes SubImage of the rectangle, sets a pixel through the parent and one
// through the child, and replies with the parent's Pix, the child's Pix, the
// child's Stride and Rect (pixel sharing in both directions).
//
// D is draw.DrawMask (SELF passes dst as its own source); F is
// draw.FloydSteinberg.Draw. Images are <type>/<x0,y0,x1,y1>/<pix hex>/<palette>
// with a comma-separated palette of <color type>:<hex> (or -), Uniform/-/-/<color>
// and Rect/<x0,y0,x1,y1>/-/-. The reply is the destination's Pix in hex, or
// "panic" when Go panics.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"os"
	"strconv"
	"strings"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func parsePoint(s string) image.Point {
	f := strings.Split(s, ",")
	x, err := strconv.Atoi(f[0])
	must(err)
	y, err := strconv.Atoi(f[1])
	must(err)
	return image.Point{x, y}
}

func parseRect(s string) image.Rectangle {
	f := strings.Split(s, ",")
	p := parsePoint(f[0] + "," + f[1])
	q := parsePoint(f[2] + "," + f[3])
	return image.Rectangle{p, q}
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

func pix(m image.Image) []byte {
	switch m := m.(type) {
	case *image.RGBA:
		return m.Pix
	case *image.NRGBA:
		return m.Pix
	case *image.RGBA64:
		return m.Pix
	case *image.NRGBA64:
		return m.Pix
	case *image.Gray:
		return m.Pix
	case *image.Gray16:
		return m.Pix
	case *image.Alpha:
		return m.Pix
	case *image.Alpha16:
		return m.Pix
	case *image.Paletted:
		return m.Pix
	}
	panic("not a destination")
}

func stride(m image.Image) int {
	switch m := m.(type) {
	case *image.RGBA:
		return m.Stride
	case *image.NRGBA:
		return m.Stride
	case *image.RGBA64:
		return m.Stride
	case *image.NRGBA64:
		return m.Stride
	case *image.Gray:
		return m.Stride
	case *image.Gray16:
		return m.Stride
	case *image.Alpha:
		return m.Stride
	case *image.Alpha16:
		return m.Stride
	case *image.Paletted:
		return m.Stride
	}
	panic("not a destination")
}

func subImage(f []string) string {
	parent := build(f[1]).(draw.Image)
	sub := parent.(interface {
		SubImage(image.Rectangle) image.Image
	}).SubImage(parseRect(f[2]))
	p := parsePoint(f[3])
	parent.Set(p.X, p.Y, parseColor(f[4]))
	c := parsePoint(f[5])
	sub.(draw.Image).Set(c.X, c.Y, parseColor(f[6]))
	b := sub.Bounds()
	return fmt.Sprintf("%s %s %d %d,%d,%d,%d", hex.EncodeToString(pix(parent)), hex.EncodeToString(pix(sub)),
		stride(sub), b.Min.X, b.Min.Y, b.Max.X, b.Max.Y)
}

func run(f []string) (out string) {
	defer func() {
		if recover() != nil {
			out = "panic"
		}
	}()
	if f[0] == "U" {
		return subImage(f)
	}
	dst := build(f[1]).(draw.Image)
	switch f[0] {
	case "D":
		var src image.Image = dst
		if f[2] != "SELF" {
			src = build(f[2])
		}
		var mask image.Image
		if f[3] != "nil" {
			mask = build(f[3])
		}
		op := draw.Over
		if f[7] == "Src" {
			op = draw.Src
		}
		draw.DrawMask(dst, parseRect(f[4]), src, parsePoint(f[5]), mask, parsePoint(f[6]), op)
	case "O":
		src := build(f[2])
		op := draw.Over
		if f[5] == "Src" {
			op = draw.Src
		}
		op.Draw(dst, parseRect(f[3]), src, parsePoint(f[4]))
	case "F":
		draw.FloydSteinberg.Draw(dst, parseRect(f[3]), build(f[2]), parsePoint(f[4]))
	default:
		panic("bad request")
	}
	return hex.EncodeToString(pix(dst))
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<16), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, run(strings.Fields(in.Text())))
	}
	must(in.Err())
}
