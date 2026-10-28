// Go reference implementation for tools/hash_check.py.
package main

import (
	"bufio"
	"encoding"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/adler32"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
	"os"
)

type stateHash interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024), 4*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		data, err := hex.DecodeString(in.Text())
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		values := []string{}
		states := []string{}
		add := func(h stateHash) {
			for start := 0; start < len(data); start += 7 {
				end := start + 7
				if end > len(data) {
					end = len(data)
				}
				_, _ = h.Write(data[start:end])
			}
			values = append(values, hex.EncodeToString(h.Sum(nil)))
			state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
			if err != nil {
				panic(err)
			}
			states = append(states, hex.EncodeToString(state))
		}
		add(fnv.New32())
		add(fnv.New32a())
		add(fnv.New64())
		add(fnv.New64a())
		add(fnv.New128())
		add(fnv.New128a())
		add(crc64.New(crc64.MakeTable(crc64.ISO)))
		add(crc64.New(crc64.MakeTable(crc64.ECMA)))
		add(crc64.New(crc64.MakeTable(0x95ac9329ac4bc9b5)))
		values = append(values, fmt.Sprintf("%016x", crc64.Update(0x123456789abcdef0, crc64.MakeTable(0x95ac9329ac4bc9b5), data)))
		for _, poly := range []uint32{crc32.IEEE, crc32.Castagnoli, crc32.Koopman, 0x741b8cd7} {
			add(crc32.New(crc32.MakeTable(poly)))
		}
		values = append(values, fmt.Sprintf("%08x", crc32.Update(0x89abcdef, crc32.MakeTable(0x741b8cd7), data)))
		add(adler32.New())
		arbitraryAdler := adler32.New()
		if err := arbitraryAdler.(encoding.BinaryUnmarshaler).UnmarshalBinary([]byte{'a', 'd', 'l', 1, 255, 255, 255, 255}); err != nil {
			panic(err)
		}
		_, _ = arbitraryAdler.Write(data)
		values = append(values, fmt.Sprintf("%08x", arbitraryAdler.Sum32()))
		values = append(values, fmt.Sprintf("%08x", adler32.Checksum(data)))
		values = append(values, fmt.Sprintf("%08x", crc32.ChecksumIEEE(data)))
		values = append(values, fmt.Sprintf("%08x", crc32.Checksum(data, crc32.IEEETable)))
		values = append(values, fmt.Sprintf("%08x", crc32.Checksum(data, crc32.MakeTable(0x741b8cd7))))
		values = append(values, fmt.Sprintf("%08x", crc32.Update(0, crc32.IEEETable, data)))
		values = append(values, fmt.Sprintf("%016x", crc64.Checksum(data, crc64.MakeTable(crc64.ISO))))
		arbitraryState, err := arbitraryAdler.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			panic(err)
		}
		states = append(states, hex.EncodeToString(arbitraryState))
		encoded, err := json.Marshal([][]string{values, states})
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(out, string(encoded))
	}
	if err := in.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}
