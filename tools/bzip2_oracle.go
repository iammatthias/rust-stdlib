// Standalone compress/bzip2 decoding oracle using Go's standard library.
//
// Each input line is a hex-encoded compressed stream. Each output line is
// "ok <hex>" or "err <hex> <tail> <structural>". The hex output holds every
// byte Read returned, including those returned together with the error: on
// truncated input Go keeps decoding zero bits and returns those bytes with
// io.ErrUnexpectedEOF. <tail> counts them so tools/bzip2_check.py can report
// how often that happens. <structural> is hex for the bzip2.StructuralError
// message, or "-" when the error is not a StructuralError.
package main

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

func run(data []byte) string {
	reader := bzip2.NewReader(bytes.NewReader(data))
	var output []byte
	buffer := make([]byte, 4096)
	for {
		n, err := reader.Read(buffer)
		if err == io.EOF {
			output = append(output, buffer[:n]...)
			return "ok " + hex.EncodeToString(output)
		}
		if err != nil {
			structural := "-"
			var structuralErr bzip2.StructuralError
			if errors.As(err, &structuralErr) {
				structural = hex.EncodeToString([]byte(structuralErr.Error()))
			}
			// Go returns the bytes decoded from zero bits after a truncation together with the error.
			output = append(output, buffer[:n]...)
			return fmt.Sprintf("err %s %d %s", hex.EncodeToString(output), n, structural)
		}
		output = append(output, buffer[:n]...)
	}
}

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 64*1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		data, err := hex.DecodeString(s.Text())
		if err != nil {
			panic(err)
		}
		w.WriteString(run(data))
		w.WriteByte('\n')
	}
	if err := s.Err(); err != nil {
		panic(err)
	}
}
