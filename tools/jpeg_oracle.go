// Line-oriented Go image/jpeg oracle. Requests:
//
//	D <jpeg hex>   Decode
//	C <jpeg hex>   DecodeConfig
//	R <jpeg hex>   image.Decode through the format registry (name and bounds)
//	E <kind> <rect> <quality> <hide> <extra> <hex>   Encode
//
// Decode prints "ok Gray|RGBA|CMYK <rect> <stride> <pix hex>" or
// "ok YCbCr <rect> <ratio> <ystride> <cstride> <Y hex> <Cb hex> <Cr hex>"
// (the complete planes, padding included, as length:FNV-1a hash unless the
// JPEG_FULL environment variable is set), or "err <class> <text>" where the
// class is format, unsupported, eof or other. DecodeConfig prints
// "ok <model> <w> <h>" or "err ...". Images whose DecodeConfig dimensions
// exceed the shared pixel budget print "skip" so neither side allocates them.
//
// Encode builds an image of <kind> (Gray, RGBA, NRGBA, RGBA64, Gray16, Alpha,
// CMYK, YCbCr, NYCbCrA, Paletted, Uniform) with bounds <rect> = x0,y0,x1,y1
// from the compact pixel data in <hex> (YCbCr and NYCbCrA: Y, Cb, Cr[, A]
// planes of image.NewYCbCr's layout; Paletted: <extra> is the palette as
// comma-separated RGBA hex; other kinds: <extra> is "-" unless it is the
// YCbCr ratio). <quality> is "nil" for a nil *Options. <hide> 1 wraps the
// image so that only the image.Image methods are visible, forcing Go's
// generic color path. It prints the JPEG in hex or "err <text>".
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"os"
	"strconv"
	"strings"
)

// Decode budget shared with examples/jpeg_probe.rs.
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

func unhex(s string) []byte {
	if s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	must(err)
	return b
}

func parseRect(s string) image.Rectangle {
	f := strings.Split(s, ",")
	return image.Rect(atoi(f[0]), atoi(f[1]), atoi(f[2]), atoi(f[3]))
}

func class(err error) string {
	var fe jpeg.FormatError
	var ue jpeg.UnsupportedError
	switch {
	case errors.As(err, &fe):
		return "format"
	case errors.As(err, &ue):
		return "unsupported"
	case errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	}
	return "other"
}

func fail(err error) string {
	return "err " + class(err) + " " + err.Error()
}

func model(m color.Model) string {
	switch m {
	case color.GrayModel:
		return "Gray"
	case color.YCbCrModel:
		return "YCbCr"
	case color.RGBAModel:
		return "RGBA"
	case color.CMYKModel:
		return "CMYK"
	}
	return "unknown"
}

func rect(r image.Rectangle) string {
	return fmt.Sprintf("%d,%d,%d,%d", r.Min.X, r.Min.Y, r.Max.X, r.Max.Y)
}

// plane prints a pixel plane as its length and FNV-1a hash, or in full when
// JPEG_FULL is set.
func plane(p []byte) string {
	if os.Getenv("JPEG_FULL") != "" {
		return fmt.Sprintf("%x", p)
	}
	h := fnv.New64a()
	h.Write(p)
	return fmt.Sprintf("%d:%016x", len(p), h.Sum64())
}

func describe(m image.Image) string {
	switch m := m.(type) {
	case *image.Gray:
		return fmt.Sprintf("ok Gray %s %d %s", rect(m.Rect), m.Stride, plane(m.Pix))
	case *image.RGBA:
		return fmt.Sprintf("ok RGBA %s %d %s", rect(m.Rect), m.Stride, plane(m.Pix))
	case *image.CMYK:
		return fmt.Sprintf("ok CMYK %s %d %s", rect(m.Rect), m.Stride, plane(m.Pix))
	case *image.YCbCr:
		return fmt.Sprintf("ok YCbCr %s %d %d %d %s %s %s", rect(m.Rect), int(m.SubsampleRatio),
			m.YStride, m.CStride, plane(m.Y), plane(m.Cb), plane(m.Cr))
	}
	return fmt.Sprintf("ok other %T", m)
}

func decodeConfigLine(data []byte) (image.Config, error) {
	return jpeg.DecodeConfig(bytes.NewReader(data))
}

func decodeLine(data []byte) string {
	if cfg, err := decodeConfigLine(data); err == nil && int64(cfg.Width)*int64(cfg.Height) > maxPixels {
		return "skip"
	}
	m, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		return fail(err)
	}
	return describe(m)
}

// hidden exposes only the image.Image methods of the wrapped image.
type hidden struct{ image.Image }

func encodeLine(f []string) string {
	kind, r := f[0], parseRect(f[1])
	var opts *jpeg.Options
	if f[2] != "nil" {
		opts = &jpeg.Options{Quality: atoi(f[2])}
	}
	hide := f[3] == "1"
	extra := f[4]
	data := unhex(f[5])
	w, h := r.Dx(), r.Dy()
	var m image.Image
	switch kind {
	case "Gray":
		m = &image.Gray{Pix: data, Stride: w, Rect: r}
	case "RGBA":
		m = &image.RGBA{Pix: data, Stride: 4 * w, Rect: r}
	case "NRGBA":
		m = &image.NRGBA{Pix: data, Stride: 4 * w, Rect: r}
	case "RGBA64":
		m = &image.RGBA64{Pix: data, Stride: 8 * w, Rect: r}
	case "Gray16":
		m = &image.Gray16{Pix: data, Stride: 2 * w, Rect: r}
	case "Alpha":
		m = &image.Alpha{Pix: data, Stride: w, Rect: r}
	case "CMYK":
		m = &image.CMYK{Pix: data, Stride: 4 * w, Rect: r}
	case "YCbCr", "NYCbCrA":
		img := image.NewYCbCr(r, image.YCbCrSubsampleRatio(atoi(extra)))
		n := copy(img.Y, data)
		data = data[n:]
		n = copy(img.Cb, data)
		data = data[n:]
		n = copy(img.Cr, data)
		data = data[n:]
		if kind == "NYCbCrA" {
			a := &image.NYCbCrA{YCbCr: *img, AStride: w, A: make([]uint8, w*h)}
			copy(a.A, data)
			m = a
		} else {
			m = img
		}
	case "Paletted":
		var pal color.Palette
		for _, c := range strings.Split(extra, ",") {
			b := unhex(c)
			pal = append(pal, color.RGBA{b[0], b[1], b[2], b[3]})
		}
		m = &image.Paletted{Pix: data, Stride: w, Rect: r, Palette: pal}
	case "Uniform":
		b := data
		m = image.NewUniform(color.RGBA{b[0], b[1], b[2], b[3]})
	default:
		panic("unknown kind " + kind)
	}
	if hide {
		m = hidden{m}
	}
	var out bytes.Buffer
	if err := jpeg.Encode(&out, m, opts); err != nil {
		return "err " + err.Error()
	}
	return fmt.Sprintf("%x", out.Bytes())
}

func handle(line string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "panic"
		}
	}()
	f := strings.Fields(line)
	switch f[0] {
	case "D":
		return decodeLine(unhex(f[1]))
	case "C":
		cfg, err := decodeConfigLine(unhex(f[1]))
		if err != nil {
			return fail(err)
		}
		return fmt.Sprintf("ok %s %d %d", model(cfg.ColorModel), cfg.Width, cfg.Height)
	case "R":
		data := unhex(f[1])
		cfg, err := decodeConfigLine(data)
		if err != nil {
			return fail(err)
		}
		if int64(cfg.Width)*int64(cfg.Height) > maxPixels {
			return "skip"
		}
		m, name, err := image.Decode(bytes.NewReader(data))
		if err != nil {
			return "err " + err.Error()
		}
		return fmt.Sprintf("ok %s %s", name, rect(m.Bounds()))
	case "E":
		return encodeLine(f[1:])
	}
	panic("bad request " + line)
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for {
		line, err := in.ReadString('\n')
		if len(strings.TrimSpace(line)) > 0 {
			fmt.Fprintln(out, handle(strings.TrimSpace(line)))
		}
		if err != nil {
			break
		}
	}
}
