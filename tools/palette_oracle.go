// Standalone image/color/palette oracle using Go's standard library.
//
// Prints one line per palette entry: "<table> <index> <rrggbbaa>", using the
// non-premultiplied 8-bit channels of each color.
package main

import (
	"bufio"
	"fmt"
	"image/color"
	"image/color/palette"
	"os"
)

func main() {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	tables := []struct {
		name string
		p    color.Palette
	}{
		{"plan9", palette.Plan9},
		{"websafe", palette.WebSafe},
	}
	for _, table := range tables {
		for i, c := range table.p {
			n := color.NRGBAModel.Convert(c).(color.NRGBA)
			fmt.Fprintf(w, "%s %d %02x%02x%02x%02x\n", table.name, i, n.R, n.G, n.B, n.A)
		}
	}
}
