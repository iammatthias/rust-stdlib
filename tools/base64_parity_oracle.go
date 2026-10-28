// Standalone Go base64 oracle for tools/base64_parity_check.py.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 4096), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	encodings := []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding, base64.StdEncoding.Strict(), base64.StdEncoding.WithPadding(base64.NoPadding)}
	for in.Scan() {
		line := in.Text()
		if strings.HasPrefix(line, "N") {
			parts := strings.SplitN(line[1:], ":", 2)
			index, _ := strconv.Atoi(parts[0])
			n, _ := strconv.Atoi(parts[1])
			fmt.Fprintf(out, "%d\t%d\n", encodings[index].EncodedLen(n), encodings[index].DecodedLen(n))
			continue
		}
		if strings.HasPrefix(line, "P") {
			parts := strings.SplitN(line[1:], ":", 2)
			index, _ := strconv.Atoi(parts[0])
			input, err := hex.DecodeString(parts[1])
			if err != nil {
				panic(err)
			}
			dst := make([]byte, encodings[index].DecodedLen(len(input)))
			n, err := encodings[index].Decode(dst, input)
			status := "ok"
			if err != nil {
				corrupt, ok := err.(base64.CorruptInputError)
				if !ok {
					panic(err)
				}
				status = fmt.Sprintf("err:%d", int64(corrupt))
			}
			fmt.Fprintf(out, "%d:%x:%s\n", n, dst[:n], status)
			continue
		}
		if strings.HasPrefix(line, "Q") {
			// Q<padding hex>:<plain hex>: WithPadding(padding) encode and DecodeString round trip.
			parts := strings.SplitN(line[1:], ":", 2)
			pad, _ := strconv.ParseUint(parts[0], 16, 32)
			plain, _ := hex.DecodeString(parts[1])
			func() {
				defer func() {
					if recover() != nil {
						fmt.Fprintln(out, "panic")
					}
				}()
				enc := base64.StdEncoding.WithPadding(rune(pad))
				text := enc.EncodeToString(plain)
				decoded, err := enc.DecodeString(text)
				fmt.Fprintf(out, "%x\t%x\t%v\n", text, decoded, err)
			}()
			continue
		}
		if strings.HasPrefix(line, "D") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				panic("bad decode request")
			}
			index := int(parts[0][1] - '0')
			input, err := hex.DecodeString(parts[1])
			if err != nil {
				panic(err)
			}
			decoded, err := encodings[index].DecodeString(string(input))
			if err != nil {
				corrupt, ok := err.(base64.CorruptInputError)
				if !ok {
					panic(err)
				}
				fmt.Fprintf(out, "err:%d:%x\n", int64(corrupt), decoded)
			} else {
				fmt.Fprintf(out, "ok:%x\n", decoded)
			}
			continue
		}
		plain, err := hex.DecodeString(line)
		if err != nil {
			panic(err)
		}
		for i, enc := range encodings {
			if i > 0 {
				fmt.Fprint(out, "\t")
			}
			fmt.Fprint(out, enc.EncodeToString(plain))
		}
		fmt.Fprintln(out)
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
