// Small JSON-free line oracle used by ascii85_check.py. Input is tab-delimited
// operation, hexadecimal bytes, and (for decode) a 0/1 flush flag.
package main

import (
	"bufio"
	"bytes"
	"encoding/ascii85"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 1<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		var op, encoded, flush string
		line := s.Text()
		for i, field := range split(line) {
			switch i {
			case 0:
				op = field
			case 1:
				encoded = field
			case 2:
				flush = field
			}
		}
		input, err := hex.DecodeString(encoded)
		if err != nil {
			panic(err)
		}
		if op == "E" {
			out := make([]byte, ascii85.MaxEncodedLen(len(input)))
			n := ascii85.Encode(out, input)
			fmt.Fprintf(w, "E|%s\n", hex.EncodeToString(out[:n]))
			continue
		}
		if op == "S" {
			var buf bytes.Buffer
			enc := ascii85.NewEncoder(&buf)
			if _, err := enc.Write(input); err != nil {
				panic(err)
			}
			if err := enc.Close(); err != nil {
				panic(err)
			}
			fmt.Fprintf(w, "E|%s\n", hex.EncodeToString(buf.Bytes()))
			continue
		}
		if op == "R" {
			out, readErr := io.ReadAll(ascii85.NewDecoder(bytes.NewReader(input)))
			message := "-"
			if readErr != nil {
				message = readErr.Error()
			}
			fmt.Fprintf(w, "R|%s|%s\n", hex.EncodeToString(out), message)
			continue
		}
		if op != "D" {
			panic("unknown operation")
		}
		out := make([]byte, 1<<14)
		n, consumed, decodeErr := ascii85.Decode(out, input, flush == "1")
		errorOffset := "-"
		if decodeErr != nil {
			var corrupt ascii85.CorruptInputError
			if errors.As(decodeErr, &corrupt) {
				errorOffset = fmt.Sprint(int64(corrupt))
			} else {
				panic(decodeErr)
			}
		}
		message := "-"
		if decodeErr != nil {
			message = decodeErr.Error()
		}
		fmt.Fprintf(w, "D|%d|%d|%s|%s|%s\n", n, consumed, hex.EncodeToString(out[:n]), errorOffset, message)
	}
	if err := s.Err(); err != nil {
		panic(err)
	}
}

func split(line string) []string {
	fields := []string{"", "", ""}
	for i := 0; i < len(fields); i++ {
		if i == len(fields)-1 {
			fields[i] = line
			break
		}
		j := 0
		for j < len(line) && line[j] != '\t' {
			j++
		}
		fields[i], line = line[:j], line[min(j+1, len(line)):]
	}
	return fields
}
