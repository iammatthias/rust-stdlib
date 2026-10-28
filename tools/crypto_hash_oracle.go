// Go reference implementation for tools/crypto_hash_check.py.
//
// Reads one case per line as space-separated key=value tokens (byte strings are
// hex) and writes one line of name=value tokens per case. The Rust probe in
// crates/crypto/examples/crypto_probe.rs implements the same protocol.
package main

import (
	"bufio"
	"crypto"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/md5"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/subtle"
	"encoding"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"sort"
	"strconv"
	"strings"
)

type named struct {
	name string
	new  func() hash.Hash
}

var hashes = []named{
	{"md5", md5.New},
	{"sha1", sha1.New},
	{"sha224", sha256.New224},
	{"sha256", sha256.New},
	{"sha384", sha512.New384},
	{"sha512", sha512.New},
	{"sha512_224", sha512.New512_224},
	{"sha512_256", sha512.New512_256},
	{"sha3_224", func() hash.Hash { return sha3.New224() }},
	{"sha3_256", func() hash.Hash { return sha3.New256() }},
	{"sha3_384", func() hash.Hash { return sha3.New384() }},
	{"sha3_512", func() hash.Hash { return sha3.New512() }},
}

func parse(line string) map[string]string {
	fields := map[string]string{}
	for _, token := range strings.Split(line, " ") {
		key, value, _ := strings.Cut(token, "=")
		fields[key] = value
	}
	return fields
}

func bytesOf(fields map[string]string, key string) []byte {
	b, err := hex.DecodeString(fields[key])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad hex for", key, err)
		os.Exit(2)
	}
	return b
}

func intOf(fields map[string]string, key string) int {
	n, err := strconv.Atoi(fields[key])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad integer for", key, err)
		os.Exit(2)
	}
	return n
}

func failure(err error) string {
	return "err:" + strings.ReplaceAll(err.Error(), " ", "_")
}

func result(b []byte, err error) string {
	if err != nil {
		return failure(err)
	}
	return hex.EncodeToString(b)
}

func writeChunks(h interface{ Write([]byte) (int, error) }, data []byte, chunk int) {
	for start := 0; start < len(data); start += chunk {
		end := min(start+chunk, len(data))
		h.Write(data[start:end])
	}
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1024), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fields := parse(in.Text())
		out.WriteString(strings.Join(run(fields), " ") + "\n")
	}
}

func run(fields map[string]string) []string {
	var results []string
	emit := func(name, value string) { results = append(results, name+"="+value) }

	if fields["static"] == "1" {
		for h := crypto.MD4; h <= crypto.MLDSAMu; h++ {
			emit(fmt.Sprintf("hash.%d", h), fmt.Sprintf("%s,%d,%t", strings.ReplaceAll(h.String(), " ", "_"), h.Size(), h.Available()))
		}
		return results
	}

	data, key, salt, info := bytesOf(fields, "data"), bytesOf(fields, "key"), bytesOf(fields, "salt"), bytesOf(fields, "info")
	split, chunk := min(intOf(fields, "split"), len(data)), intOf(fields, "chunk")
	keyLen, iter := intOf(fields, "klen"), intOf(fields, "iter")

	for _, h := range hashes {
		full := h.new()
		writeChunks(full, data, chunk)
		emit("sum."+h.name, hex.EncodeToString(full.Sum(nil)))
		emit("sizes."+h.name, fmt.Sprintf("%d,%d", full.Size(), full.BlockSize()))

		// Sum must not disturb the running state.
		full.Write([]byte{1})
		again := h.new()
		again.Write(data)
		again.Write([]byte{1})
		emit("sumagain."+h.name, hex.EncodeToString(full.Sum(nil))+","+hex.EncodeToString(again.Sum(nil)))

		prefix := h.new()
		writeChunks(prefix, data[:split], chunk)
		state, err := prefix.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			panic(err)
		}
		emit("state."+h.name, hex.EncodeToString(state))
		appended, _ := prefix.(encoding.BinaryAppender).AppendBinary([]byte{9, 9})
		emit("appended."+h.name, hex.EncodeToString(appended))

		resumed := h.new()
		if err := resumed.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
			panic(err)
		}
		resumed.Write(data[split:])
		emit("resumed."+h.name, hex.EncodeToString(resumed.Sum(nil)))

		clone, err := prefix.(hash.Cloner).Clone()
		if err != nil {
			panic(err)
		}
		clone.Write(data[split:])
		emit("clone."+h.name, hex.EncodeToString(clone.Sum(nil)))

		// Corrupt states: wrong identifier, wrong size, and (for the Merkle-Damgard
		// family) an empty input.
		bad := append([]byte(nil), state...)
		bad[0] ^= 0xff
		emit("badid."+h.name, failure(h.new().(encoding.BinaryUnmarshaler).UnmarshalBinary(bad)))
		emit("badsize."+h.name, failure(h.new().(encoding.BinaryUnmarshaler).UnmarshalBinary(state[:len(state)-1])))

		mac := hmac.New(h.new, key)
		mac.Write(data)
		emit("hmac."+h.name, hex.EncodeToString(mac.Sum(nil)))
		mac.Reset()
		mac.Write(data[:split])
		mac.Write(data[split:])
		emit("hmacreset."+h.name, hex.EncodeToString(mac.Sum(nil))+fmt.Sprintf(",%d,%d", mac.Size(), mac.BlockSize()))

		newHash := func() hash.Hash { return h.new() }
		prk, err := hkdf.Extract(newHash, key, salt)
		emit("hkdf_extract."+h.name, result(prk, err))
		okm, err := hkdf.Expand(newHash, key, string(info), keyLen)
		emit("hkdf_expand."+h.name, result(okm, err))
		okm, err = hkdf.Key(newHash, key, salt, string(info), keyLen)
		emit("hkdf_key."+h.name, result(okm, err))

		derived, err := pbkdf2.Key(newHash, string(key), salt, iter, keyLen)
		emit("pbkdf2."+h.name, result(derived, err))
	}

	// Extendable-output functions, read in two pieces.
	shakeLen := intOf(fields, "slen")
	cshakeName, cshakeCustom := bytesOf(fields, "cn"), bytesOf(fields, "cs")
	readTwice := func(read func([]byte) (int, error)) string {
		output := make([]byte, shakeLen)
		first := shakeLen / 3
		read(output[:first])
		read(output[first:])
		return hex.EncodeToString(output)
	}
	s128, s256 := sha3.NewSHAKE128(), sha3.NewSHAKE256()
	c128, c256 := sha3.NewCSHAKE128(cshakeName, cshakeCustom), sha3.NewCSHAKE256(cshakeName, cshakeCustom)
	for _, x := range []*sha3.SHAKE{s128, s256, c128, c256} {
		writeChunks(x, data, chunk)
	}
	emit("shake128", readTwice(s128.Read))
	emit("shake256", readTwice(s256.Read))
	emit("cshake128", readTwice(c128.Read))
	emit("cshake256", readTwice(c256.Read))
	emit("shakeblock", fmt.Sprintf("%d,%d,%d,%d", s128.BlockSize(), s256.BlockSize(), c128.BlockSize(), c256.BlockSize()))
	c128.Reset()
	c128.Write(data)
	emit("cshake128reset", hex.EncodeToString(func() []byte { b := make([]byte, shakeLen); c128.Read(b); return b }()))
	emit("sumshake128", hex.EncodeToString(sha3.SumSHAKE128(data, shakeLen)))
	emit("sumshake256", hex.EncodeToString(sha3.SumSHAKE256(data, shakeLen)))
	for _, sum := range []struct {
		name string
		out  []byte
	}{
		{"md5", func() []byte { s := md5.Sum(data); return s[:] }()},
		{"sha1", func() []byte { s := sha1.Sum(data); return s[:] }()},
		{"sha224", func() []byte { s := sha256.Sum224(data); return s[:] }()},
		{"sha256", func() []byte { s := sha256.Sum256(data); return s[:] }()},
		{"sha384", func() []byte { s := sha512.Sum384(data); return s[:] }()},
		{"sha512", func() []byte { s := sha512.Sum512(data); return s[:] }()},
		{"sha512_224", func() []byte { s := sha512.Sum512_224(data); return s[:] }()},
		{"sha512_256", func() []byte { s := sha512.Sum512_256(data); return s[:] }()},
		{"sha3_224", func() []byte { s := sha3.Sum224(data); return s[:] }()},
		{"sha3_256", func() []byte { s := sha3.Sum256(data); return s[:] }()},
		{"sha3_384", func() []byte { s := sha3.Sum384(data); return s[:] }()},
		{"sha3_512", func() []byte { s := sha3.Sum512(data); return s[:] }()},
	} {
		emit("oneshot."+sum.name, hex.EncodeToString(sum.out))
	}

	// crypto/subtle and hmac.Equal.
	x, y := int32(intOf(fields, "x")), int32(intOf(fields, "y"))
	v := intOf(fields, "v") & 1
	emit("compare", strconv.Itoa(subtle.ConstantTimeCompare(data, key)))
	emit("compare_same", strconv.Itoa(subtle.ConstantTimeCompare(data, append([]byte(nil), data...))))
	emit("hmacequal", fmt.Sprintf("%t,%t", hmac.Equal(data, key), hmac.Equal(data, data)))
	emit("select", strconv.Itoa(subtle.ConstantTimeSelect(v, int(x), int(y))))
	emit("byteeq", strconv.Itoa(subtle.ConstantTimeByteEq(uint8(x), uint8(y))))
	emit("eq", strconv.Itoa(int(subtle.ConstantTimeEq(x, y))))
	if x >= 0 && y >= 0 {
		emit("lesseq", strconv.Itoa(subtle.ConstantTimeLessOrEq(int(x), int(y))))
	}
	dst := make([]byte, min(len(data), len(key)))
	n := subtle.XORBytes(dst, data, key)
	emit("xor", fmt.Sprintf("%d,%s", n, hex.EncodeToString(dst)))
	target := append([]byte(nil), data...)
	if len(key) >= len(data) {
		subtle.ConstantTimeCopy(v, target, key[:len(data)])
	}
	emit("copy", hex.EncodeToString(target))

	sort.Strings(results)
	return results
}

