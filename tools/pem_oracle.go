// Standalone encoding/pem differential oracle using Go's standard library.
package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"

	"encoding/pem"
)

type request struct {
	Op       string            `json:"op"`
	Input    string            `json:"input"`
	InputHex string            `json:"input_hex"`
	Type     string            `json:"type"`
	Headers  map[string]string `json:"headers"`
	Bytes    []int             `json:"bytes"`
}

type response struct {
	Type      string            `json:"type"`
	Headers   map[string]string `json:"headers"`
	Bytes     []int             `json:"bytes"`
	Remainder string            `json:"remainder"`
}

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 16*1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		var req request
		if err := json.Unmarshal(s.Bytes(), &req); err != nil {
			panic(err)
		}
		var result any
		if req.Op == "encode" {
			payload := make([]byte, len(req.Bytes))
			for i, b := range req.Bytes {
				payload[i] = byte(b)
			}
			block := &pem.Block{Type: req.Type, Headers: req.Headers, Bytes: payload}
			var written bytes.Buffer
			writerErr := pem.Encode(&written, block)
			encoded := pem.EncodeToMemory(block)
			if (writerErr == nil) != (encoded != nil) || !bytes.Equal(written.Bytes(), encoded) {
				panic("pem.Encode disagrees with pem.EncodeToMemory")
			}
			if encoded != nil {
				result = string(encoded)
			}
		} else if req.Op == "decode_raw" {
			input, err := hex.DecodeString(req.InputHex)
			if err != nil {
				panic(err)
			}
			block, rest := pem.Decode(input)
			if block != nil {
				decoded := make([]int, len(block.Bytes))
				for i, b := range block.Bytes {
					decoded[i] = int(b)
				}
				headers := map[string]string{}
				for k, v := range block.Headers {
					headers[hex.EncodeToString([]byte(k))] = hex.EncodeToString([]byte(v))
				}
				result = response{Type: hex.EncodeToString([]byte(block.Type)), Headers: headers, Bytes: decoded, Remainder: hex.EncodeToString(rest)}
			}
		} else {
			block, rest := pem.Decode([]byte(req.Input))
			if block != nil {
				decoded := make([]int, len(block.Bytes))
				for i, b := range block.Bytes {
					decoded[i] = int(b)
				}
				result = response{Type: block.Type, Headers: block.Headers, Bytes: decoded, Remainder: string(rest)}
			}
		}
		out, err := json.Marshal(result)
		if err != nil {
			panic(err)
		}
		w.Write(out)
		w.WriteByte('\n')
	}
	if err := s.Err(); err != nil {
		panic(err)
	}
}
