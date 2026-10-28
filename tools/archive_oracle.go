// Go standard-library oracle for bounded compression/archive conformance.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"os"
)

func run() error {
	if len(os.Args) != 5 {
		return fmt.Errorf("usage: archive_oracle encode|decode format input output")
	}
	input, e := os.ReadFile(os.Args[3])
	if e != nil {
		return e
	}
	var output bytes.Buffer
	operation, format := os.Args[1], os.Args[2]
	if operation == "encode" {
		var w io.WriteCloser
		switch format {
		case "deflate":
			w, e = flate.NewWriter(&output, flate.DefaultCompression)
		case "gzip":
			w = gzip.NewWriter(&output)
		case "zlib":
			w = zlib.NewWriter(&output)
		case "tar":
			t := tar.NewWriter(&output)
			e = t.WriteHeader(&tar.Header{Name: "file.bin", Mode: 0644, Size: int64(len(input)), Format: tar.FormatUSTAR})
			if e == nil {
				_, e = t.Write(input)
			}
			if e == nil {
				e = t.Close()
			}
		case "zip":
			z := zip.NewWriter(&output)
			var f io.Writer
			f, e = z.Create("file.bin")
			if e == nil {
				_, e = f.Write(input)
			}
			if e == nil {
				e = z.Close()
			}
		default:
			return fmt.Errorf("unsupported format")
		}
		if e != nil {
			return e
		}
		if w != nil {
			if _, e = w.Write(input); e != nil {
				return e
			}
			if e = w.Close(); e != nil {
				return e
			}
		}
	} else if operation == "decode" {
		var r io.ReadCloser
		switch format {
		case "deflate":
			r = flate.NewReader(bytes.NewReader(input))
		case "gzip":
			r, e = gzip.NewReader(bytes.NewReader(input))
		case "zlib":
			r, e = zlib.NewReader(bytes.NewReader(input))
		case "tar":
			t := tar.NewReader(bytes.NewReader(input))
			var h *tar.Header
			h, e = t.Next()
			if e == nil && h.Name != "file.bin" {
				e = fmt.Errorf("unexpected name")
			}
			if e == nil {
				_, e = io.Copy(&output, t)
			}
		case "zip":
			var z *zip.Reader
			z, e = zip.NewReader(bytes.NewReader(input), int64(len(input)))
			if e == nil {
				if len(z.File) != 1 || z.File[0].Name != "file.bin" {
					return fmt.Errorf("unexpected entries")
				}
				r, e = z.File[0].Open()
			}
		default:
			return fmt.Errorf("unsupported format")
		}
		if e != nil {
			return e
		}
		if r != nil {
			_, e = io.Copy(&output, r)
			ce := r.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		}
	} else {
		return fmt.Errorf("unsupported operation")
	}
	return os.WriteFile(os.Args[4], output.Bytes(), 0600)
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
