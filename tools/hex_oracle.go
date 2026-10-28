// Line-oriented Go encoding/hex oracle. Each input line is an operation letter
// followed by the hex encoding of the payload; output is one tab-separated record.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"unicode/utf8"
)

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 4096), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		line := in.Text()
		payload, err := hex.DecodeString(line[1:])
		if err != nil {
			panic(err)
		}
		switch line[0] {
		case 'E':
			dst := make([]byte, hex.EncodedLen(len(payload)))
			n := hex.Encode(dst, payload)
			fmt.Fprintf(out, "%s\t%d\n", hex.EncodeToString(payload), n)
		case 'D':
			dst := make([]byte, hex.DecodedLen(len(payload)))
			n, err := hex.Decode(dst, payload)
			fmt.Fprintf(out, "%d\t%x\t%s\n", n, dst[:n], errText(err))
		case 'A':
			dst, err := hex.AppendDecode([]byte{0x7f}, payload)
			fmt.Fprintf(out, "%x\t%s\n", dst, errText(err))
		case 'S':
			if !utf8.Valid(payload) {
				fmt.Fprintln(out, "skip")
				continue
			}
			dec, err := hex.DecodeString(string(payload))
			if err != nil {
				fmt.Fprintf(out, "err\t%x\t%s\n", dec, err.Error())
			} else {
				fmt.Fprintf(out, "ok\t%x\n", dec)
			}
		case 'P':
			fmt.Fprintf(out, "%x\n", hex.Dump(payload))
		case 'W':
			var buf bytes.Buffer
			dumper := hex.Dumper(&buf)
			for i := 0; i < len(payload); i += 7 {
				end := min(i+7, len(payload))
				if _, err := dumper.Write(payload[i:end]); err != nil {
					panic(err)
				}
			}
			if err := dumper.Close(); err != nil {
				panic(err)
			}
			fmt.Fprintf(out, "%x\n", buf.Bytes())
		default:
			panic("unknown operation")
		}
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
