// Line-oriented Go image/png oracle. Requests:
//
//	E <type>;<x0,y0,x1,y1>;<level>;<pix hex>;<palette>;<sub rect or empty>
//	D <png hex>
//	C <png hex>
//	I <hex>
//	TD <png hex>   (also TC, TI for image.Decode, TJ for image.DecodeConfig)
//
// The T requests reply "ok" or "err <error text>", so truncated inputs must
// fail with the same error as Go, not just fail.
//
// E replies "err <bytes written before the error, hex>" when encoding fails
// and I replies with image.Decode's format name and whether it succeeded.
//
// Palettes are comma-separated <color type>:<hex>. Decoded pixels are printed
// as big-endian RGBA64At values in row-major order.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"image"
	"image/color"
	_ "image/gif"
	"image/png"
	"os"
	"strconv"
	"strings"
)

// Decode limits shared with examples/png_probe.rs.
const maxDim = 4096
const maxPixels = 1 << 20

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func parseRect(s string) image.Rectangle {
	var v [4]int
	for i, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(f)
		must(err)
		v[i] = n
	}
	return image.Rectangle{image.Point{v[0], v[1]}, image.Point{v[2], v[3]}}
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

type subImager interface {
	SubImage(image.Rectangle) image.Image
}

func build(spec string) (image.Image, png.CompressionLevel) {
	f := strings.Split(spec, ";")
	r := parseRect(f[1])
	level, err := strconv.Atoi(f[2])
	must(err)
	pix, err := hex.DecodeString(f[3])
	must(err)
	pal := make(color.Palette, 0)
	if f[4] != "" {
		for _, c := range strings.Split(f[4], ",") {
			pal = append(pal, parseColor(c))
		}
	}
	w := r.Dx()
	var m image.Image
	switch f[0] {
	case "RGBA":
		m = &image.RGBA{Pix: pix, Stride: 4 * w, Rect: r}
	case "NRGBA":
		m = &image.NRGBA{Pix: pix, Stride: 4 * w, Rect: r}
	case "RGBA64":
		m = &image.RGBA64{Pix: pix, Stride: 8 * w, Rect: r}
	case "NRGBA64":
		m = &image.NRGBA64{Pix: pix, Stride: 8 * w, Rect: r}
	case "Gray":
		m = &image.Gray{Pix: pix, Stride: w, Rect: r}
	case "Gray16":
		m = &image.Gray16{Pix: pix, Stride: 2 * w, Rect: r}
	case "Alpha":
		m = &image.Alpha{Pix: pix, Stride: w, Rect: r}
	case "Alpha16":
		m = &image.Alpha16{Pix: pix, Stride: 2 * w, Rect: r}
	case "Paletted":
		m = &image.Paletted{Pix: pix, Stride: w, Rect: r, Palette: pal}
	case "Rect":
		m = r
	default:
		panic("unknown image " + f[0])
	}
	if f[5] != "" {
		m = m.(subImager).SubImage(parseRect(f[5]))
	}
	return m, png.CompressionLevel(level)
}

func typeName(m image.Image) string {
	switch m.(type) {
	case *image.RGBA:
		return "RGBA"
	case *image.NRGBA:
		return "NRGBA"
	case *image.RGBA64:
		return "RGBA64"
	case *image.NRGBA64:
		return "NRGBA64"
	case *image.Gray:
		return "Gray"
	case *image.Gray16:
		return "Gray16"
	case *image.Paletted:
		return "Paletted"
	}
	return "other"
}

func modelName(m color.Model) string {
	switch m {
	case color.RGBAModel:
		return "RGBA"
	case color.NRGBAModel:
		return "NRGBA"
	case color.RGBA64Model:
		return "RGBA64"
	case color.NRGBA64Model:
		return "NRGBA64"
	case color.GrayModel:
		return "Gray"
	case color.Gray16Model:
		return "Gray16"
	}
	if _, ok := m.(color.Palette); ok {
		return "Palette"
	}
	return "other"
}

func paletteHex(p color.Palette) string {
	if p == nil {
		return "-"
	}
	var b []byte
	for _, c := range p {
		r, g, bl, a := c.RGBA()
		b = binary.BigEndian.AppendUint16(b, uint16(r))
		b = binary.BigEndian.AppendUint16(b, uint16(g))
		b = binary.BigEndian.AppendUint16(b, uint16(bl))
		b = binary.BigEndian.AppendUint16(b, uint16(a))
	}
	return hex.EncodeToString(b) + "/" + strconv.Itoa(len(p))
}

func describe(m image.Image) string {
	b := m.Bounds()
	rgba64 := m.(image.RGBA64Image)
	var px []byte
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			c := rgba64.RGBA64At(x, y)
			px = binary.BigEndian.AppendUint16(px, c.R)
			px = binary.BigEndian.AppendUint16(px, c.G)
			px = binary.BigEndian.AppendUint16(px, c.B)
			px = binary.BigEndian.AppendUint16(px, c.A)
		}
	}
	pal := "-"
	if p, ok := m.(*image.Paletted); ok {
		pal = paletteHex(p.Palette)
	}
	return fmt.Sprintf("ok %s %d,%d,%d,%d %s %s", typeName(m), b.Min.X, b.Min.Y, b.Max.X, b.Max.Y,
		hex.EncodeToString(px), pal)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<16), 64<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		kind, arg, _ := strings.Cut(in.Text(), " ")
		switch kind {
		case "E":
			m, level := build(arg)
			var buf bytes.Buffer
			enc := png.Encoder{CompressionLevel: level}
			if err := enc.Encode(&buf, m); err != nil {
				fmt.Fprintln(out, "err", hex.EncodeToString(buf.Bytes()))
			} else {
				fmt.Fprintln(out, hex.EncodeToString(buf.Bytes()))
			}
		case "I":
			data, err := hex.DecodeString(arg)
			must(err)
			// Header budgets as for D: Go itself would try to allocate.
			if cfg, _, cerr := image.DecodeConfig(bytes.NewReader(data)); cerr == nil &&
				(cfg.Width > maxDim || cfg.Height > maxDim || cfg.Width*cfg.Height > maxPixels) {
				fmt.Fprintln(out, "skip")
				continue
			}
			_, name, err := image.Decode(bytes.NewReader(data))
			status := "ok"
			if err != nil {
				status = "err"
			}
			fmt.Fprintf(out, "%s %q\n", status, name)
		case "D", "C":
			data, err := hex.DecodeString(arg)
			must(err)
			cfg, err := png.DecodeConfig(bytes.NewReader(data))
			if err != nil {
				fmt.Fprintln(out, "err")
				continue
			}
			if kind == "C" {
				pal := "-"
				if p, ok := cfg.ColorModel.(color.Palette); ok {
					pal = paletteHex(p)
				}
				fmt.Fprintf(out, "ok %d %d %s %s\n", cfg.Width, cfg.Height, modelName(cfg.ColorModel), pal)
				continue
			}
			// Same budgets as the Rust probe; Go itself would try to allocate.
			if cfg.Width > maxDim || cfg.Height > maxDim || cfg.Width*cfg.Height > maxPixels {
				fmt.Fprintln(out, "err")
				continue
			}
			m, err := png.Decode(bytes.NewReader(data))
			if err != nil {
				fmt.Fprintln(out, "err")
			} else {
				fmt.Fprintln(out, describe(m))
			}
		case "TD", "TC", "TI", "TJ":
			data, err := hex.DecodeString(arg)
			must(err)
			var rerr error
			switch kind {
			case "TD":
				// Same dimension budgets as D.
				if cfg, cerr := png.DecodeConfig(bytes.NewReader(data)); cerr == nil &&
					(cfg.Width > maxDim || cfg.Height > maxDim || cfg.Width*cfg.Height > maxPixels) {
					fmt.Fprintln(out, "skip")
					continue
				}
				_, rerr = png.Decode(bytes.NewReader(data))
			case "TC":
				_, rerr = png.DecodeConfig(bytes.NewReader(data))
			case "TI":
				if cfg, _, cerr := image.DecodeConfig(bytes.NewReader(data)); cerr == nil &&
					(cfg.Width > maxDim || cfg.Height > maxDim || cfg.Width*cfg.Height > maxPixels) {
					fmt.Fprintln(out, "skip")
					continue
				}
				_, _, rerr = image.Decode(bytes.NewReader(data))
			default:
				_, _, rerr = image.DecodeConfig(bytes.NewReader(data))
			}
			if rerr != nil {
				fmt.Fprintln(out, "err", rerr.Error())
			} else {
				fmt.Fprintln(out, "ok")
			}
		default:
			panic("bad request " + kind)
		}
	}
	must(in.Err())
}
