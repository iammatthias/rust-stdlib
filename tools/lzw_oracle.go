// Standalone LZW encode/decode differential oracle using Go's standard library.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"

	"compress/lzw"
)

type request struct {
	Op       string `json:"op"`
	Order    string `json:"order"`
	LitWidth int    `json:"lit_width"`
	Bytes    []int  `json:"bytes"`
}
type response struct {
	OK    bool  `json:"ok"`
	Bytes []int `json:"bytes"`
}

func run(req request) response {
	data := make([]byte, len(req.Bytes))
	for i, b := range req.Bytes {
		data[i] = byte(b)
	}
	order := lzw.LSB
	if req.Order == "MSB" {
		order = lzw.MSB
	} else if req.Order != "LSB" {
		return response{Bytes: []int{}}
	}
	if req.Op == "encode_close" {
		var out bytes.Buffer
		writer := lzw.NewWriter(&out, order, req.LitWidth)
		_, writeErr := writer.Write(data)
		closeErr := writer.Close()
		secondCloseErr := writer.Close()
		_, afterErr := writer.Write([]byte{0})
		return response{OK: writeErr == nil && closeErr == nil && secondCloseErr == nil && afterErr != nil, Bytes: toInts(out.Bytes())}
	}
	if req.Op == "encode_reset" {
		var out bytes.Buffer
		writer := lzw.NewWriter(&out, order, req.LitWidth).(*lzw.Writer)
		_, writeErr := writer.Write(data)
		closeErr := writer.Close()
		writer.Reset(&out, order, req.LitWidth)
		reversed := make([]byte, len(data))
		for i, b := range data {
			reversed[len(data)-1-i] = b
		}
		_, resetWriteErr := writer.Write(reversed)
		resetCloseErr := writer.Close()
		return response{OK: writeErr == nil && closeErr == nil && resetWriteErr == nil && resetCloseErr == nil, Bytes: toInts(out.Bytes())}
	}
	if req.Op == "decode_close" {
		reader := lzw.NewReader(bytes.NewReader(data), order, req.LitWidth)
		closeErr := reader.Close()
		decoded, err := ioReadAll(reader)
		return response{OK: closeErr == nil && err != nil, Bytes: toInts(decoded)}
	}
	if req.Op == "encode" {
		var out bytes.Buffer
		writer := lzw.NewWriter(&out, order, req.LitWidth)
		_, writeErr := writer.Write(data)
		closeErr := writer.Close()
		encoded := out.Bytes()
		result := make([]int, len(encoded))
		for i, b := range encoded {
			result[i] = int(b)
		}
		return response{OK: writeErr == nil && closeErr == nil, Bytes: result}
	}
	reader := lzw.NewReader(bytes.NewReader(data), order, req.LitWidth)
	decoded, err := ioReadAll(reader)
	result := make([]int, len(decoded))
	for i, b := range decoded {
		result[i] = int(b)
	}
	return response{OK: err == nil, Bytes: result}
}

func toInts(data []byte) []int {
	result := make([]int, len(data))
	for i, b := range data {
		result[i] = int(b)
	}
	return result
}

func ioReadAll(reader interface{ Read([]byte) (int, error) }) ([]byte, error) {
	var output []byte
	buffer := make([]byte, 4096)
	for {
		n, err := reader.Read(buffer)
		output = append(output, buffer[:n]...)
		if err != nil {
			if err.Error() == "EOF" {
				return output, nil
			}
			return output, err
		}
		if n == 0 {
			return output, nil
		}
	}
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
		out, err := json.Marshal(run(req))
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
