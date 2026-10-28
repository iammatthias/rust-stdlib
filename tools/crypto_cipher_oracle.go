// Go reference implementation for tools/crypto_cipher_check.py.
//
// Reads one case per line as space-separated key=value tokens (byte strings are
// hex, lists are comma-separated) and writes one line of name=value tokens per
// case. The Rust probe in crates/crypto/examples/crypto_cipher_probe.rs
// implements the same protocol. Go panics, which the Rust API reports as errors,
// are recovered and printed as err:MESSAGE (spaces become underscores).
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

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

func intsOf(fields map[string]string, key string) []int {
	if fields[key] == "" {
		return nil
	}
	var out []int
	for _, part := range strings.Split(fields[key], ",") {
		n, err := strconv.Atoi(part)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad integer list for", key, err)
			os.Exit(2)
		}
		out = append(out, n)
	}
	return out
}

func message(text string) string {
	return "err:" + strings.ReplaceAll(text, " ", "_")
}

// recovered turns a panic into the same err:MESSAGE form as a returned error.
// Runtime errors (index out of range) are all "runtime".
func recovered(r any) string {
	switch v := r.(type) {
	case runtime.Error:
		return "err:runtime"
	case error:
		return message(v.Error())
	case string:
		return message(v)
	}
	return message(fmt.Sprint(r))
}

// try runs f and returns "ok:HEX" of the bytes it yields, or err:MESSAGE.
func try(f func() ([]byte, error)) (result string) {
	defer func() {
		if r := recover(); r != nil {
			result = recovered(r)
		}
	}()
	out, err := f()
	if err != nil {
		return message(err.Error())
	}
	return "ok:" + hex.EncodeToString(out)
}

// customBlock is a trivial invertible Block of any size, defined identically
// in the Rust probe: it exercises the generic (non-AES) code paths.
type customBlock struct{ key []byte }

func (c customBlock) BlockSize() int { return len(c.key) }

func (c customBlock) Encrypt(dst, src []byte) {
	for i, k := range c.key {
		b := src[i]
		dst[i] = (b<<3 | b>>5) ^ k
	}
}

func (c customBlock) Decrypt(dst, src []byte) {
	for i, k := range c.key {
		b := src[i] ^ k
		dst[i] = b>>3 | b<<5
	}
}

func newBlock(kind string, key []byte) (cipher.Block, error) {
	switch kind {
	case "aes":
		return aes.NewCipher(key)
	case "des":
		return des.NewCipher(key)
	case "tdes":
		return des.NewTripleDESCipher(key)
	case "custom":
		return customBlock{key}, nil
	}
	panic("unknown cipher " + kind)
}

func blockCase(f map[string]string, out map[string]string) {
	block, err := newBlock(f["cipher"], bytesOf(f, "key"))
	if err != nil {
		out["ctor"] = message(err.Error())
		return
	}
	out["ctor"] = "ok"
	out["bs"] = strconv.Itoa(block.BlockSize())
	in := bytesOf(f, "data")
	dlen := intOf(f, "dlen")
	for _, dir := range []string{"enc", "dec"} {
		dst := make([]byte, dlen)
		out[dir] = try(func() ([]byte, error) {
			if dir == "enc" {
				block.Encrypt(dst, in)
			} else {
				block.Decrypt(dst, in)
			}
			return dst[:min(len(dst), block.BlockSize())], nil
		})
	}
}

// split cuts data into the chunk sizes in chunks; the last chunk takes the
// rest. xs holds, per chunk, how much longer (or shorter) dst is than src.
func chunked(data []byte, chunks, xs []int, each func(i int, src, dst []byte) string) string {
	var results []string
	rest := data
	for i := 0; i < len(chunks); i++ {
		n := min(chunks[i], len(rest))
		if i == len(chunks)-1 {
			n = len(rest)
		}
		src := rest[:n]
		rest = rest[n:]
		x := 0
		if i < len(xs) {
			x = xs[i]
		}
		dst := make([]byte, max(0, n+x))
		results = append(results, each(i, src, dst))
	}
	return strings.Join(results, ";")
}

func modeCase(f map[string]string, out map[string]string) {
	block, err := newBlock(f["cipher"], bytesOf(f, "key"))
	if err != nil {
		out["ctor"] = message(err.Error())
		return
	}
	iv := bytesOf(f, "iv")
	data := bytesOf(f, "data")
	chunks, xs := intsOf(f, "chunks"), intsOf(f, "xs")
	op := f["op"]
	var ctorErr string
	var blockMode cipher.BlockMode
	var stream cipher.Stream
	func() {
		defer func() {
			if r := recover(); r != nil {
				ctorErr = recovered(r)
			}
		}()
		switch op {
		case "cbce":
			blockMode = cipher.NewCBCEncrypter(block, iv)
		case "cbcd":
			blockMode = cipher.NewCBCDecrypter(block, iv)
		case "ctr":
			stream = cipher.NewCTR(block, iv)
		case "ofb":
			stream = cipher.NewOFB(block, iv)
		case "cfbe":
			stream = cipher.NewCFBEncrypter(block, iv)
		case "cfbd":
			stream = cipher.NewCFBDecrypter(block, iv)
		default:
			panic("unknown op " + op)
		}
	}()
	if ctorErr != "" {
		out["ctor"] = ctorErr
		return
	}
	out["ctor"] = "ok"
	if blockMode != nil {
		out["bs"] = strconv.Itoa(blockMode.BlockSize())
	}
	out["r"] = chunked(data, chunks, xs, func(i int, src, dst []byte) string {
		return try(func() ([]byte, error) {
			if blockMode != nil {
				blockMode.CryptBlocks(dst, src)
			} else {
				stream.XORKeyStream(dst, src)
			}
			return dst[:min(len(dst), len(src))], nil
		})
	})
}

func rc4Case(f map[string]string, out map[string]string) {
	c, err := rc4.NewCipher(bytesOf(f, "key"))
	if err != nil {
		out["ctor"] = message(err.Error())
		return
	}
	out["ctor"] = "ok"
	resetAt := intOf(f, "reset")
	data := bytesOf(f, "data")
	out["r"] = chunked(data, intsOf(f, "chunks"), intsOf(f, "xs"), func(i int, src, dst []byte) string {
		if i == resetAt {
			c.Reset()
		}
		return try(func() ([]byte, error) {
			c.XORKeyStream(dst, src)
			return dst[:min(len(dst), len(src))], nil
		})
	})
}

func sealed(aead cipher.AEAD, pre, nonce, pt, aad []byte) string {
	return try(func() ([]byte, error) {
		return aead.Seal(append([]byte(nil), pre...), nonce, pt, aad), nil
	})
}

func opened(aead cipher.AEAD, pre, nonce, ct, aad []byte) string {
	return try(func() ([]byte, error) {
		return aead.Open(append([]byte(nil), pre...), nonce, ct, aad)
	})
}

func flip(b []byte, at int) []byte {
	c := append([]byte(nil), b...)
	if len(c) > 0 {
		c[at%len(c)] ^= 0x21
	}
	return c
}

func gcmCase(f map[string]string, out map[string]string) {
	block, err := newBlock(f["cipher"], bytesOf(f, "key"))
	if err != nil {
		out["ctor"] = message(err.Error())
		return
	}
	var aead cipher.AEAD
	var ctorErr string
	func() {
		defer func() {
			if r := recover(); r != nil {
				ctorErr = recovered(r)
			}
		}()
		var err error
		switch f["variant"] {
		case "std":
			aead, err = cipher.NewGCM(block)
		case "nonce":
			aead, err = cipher.NewGCMWithNonceSize(block, intOf(f, "n"))
		case "tag":
			aead, err = cipher.NewGCMWithTagSize(block, intOf(f, "t"))
		case "random":
			aead, err = cipher.NewGCMWithRandomNonce(block)
		default:
			panic("unknown variant " + f["variant"])
		}
		if err != nil {
			ctorErr = message(err.Error())
		}
	}()
	if ctorErr != "" {
		out["ctor"] = ctorErr
		return
	}
	out["ctor"] = "ok"
	out["ns"] = strconv.Itoa(aead.NonceSize())
	out["ov"] = strconv.Itoa(aead.Overhead())
	pre, nonce, pt, aad := bytesOf(f, "pre"), bytesOf(f, "nonce"), bytesOf(f, "pt"), bytesOf(f, "aad")
	raw := bytesOf(f, "raw")
	// A ciphertext of this key, sealed with the right nonce size, for the
	// open-side checks; random-nonce AEADs seal with their own nonce.
	goodNonce := bytesOf(f, "goodnonce")
	if f["variant"] == "random" {
		goodNonce = nil
		ct := aead.Seal(nil, nil, pt, aad)
		out["rn_len"] = strconv.Itoa(len(ct))
		out["rn_ct"] = hex.EncodeToString(ct)
		out["rn_self"] = opened(aead, pre, nil, ct, aad)
		if st, ok := f["st.rn_ct"]; ok {
			stBytes, _ := hex.DecodeString(st)
			out["rn_other"] = opened(aead, pre, nil, stBytes, aad)
		}
		out["rn_tag"] = opened(aead, pre, nil, flip(ct, len(ct)-1), aad)
		out["rn_nonce"] = opened(aead, pre, nil, flip(ct, 0), aad)
		out["rn_aad"] = opened(aead, pre, nil, ct, flip(aad, 0))
		out["rn_short"] = opened(aead, pre, nil, ct[:min(len(ct), 27)], aad)
	} else {
		ct := aead.Seal(nil, goodNonce, pt, aad)
		out["seal"] = sealed(aead, pre, nonce, pt, aad)
		out["self"] = opened(aead, pre, goodNonce, ct, aad)
		out["tag"] = opened(aead, pre, goodNonce, flip(ct, len(ct)-1), aad)
		out["body"] = opened(aead, pre, goodNonce, flip(ct, 0), aad)
		out["aad"] = opened(aead, pre, goodNonce, ct, flip(aad, 3))
		out["nonce"] = opened(aead, pre, flip(goodNonce, 1), ct, aad)
		out["trunc"] = opened(aead, pre, goodNonce, ct[:len(ct)-1], aad)
		out["raw"] = opened(aead, pre, nonce, raw, aad)
	}
	out["badnonce"] = sealed(aead, pre, nonce, pt, aad)
	out["badopen"] = opened(aead, pre, nonce, raw, aad)
}

func main() {
	reader := bufio.NewReaderSize(os.Stdin, 1<<20)
	writer := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer writer.Flush()
	for {
		line, err := reader.ReadString('\n')
		if line = strings.TrimRight(line, "\n"); line != "" {
			fields := parse(line)
			out := map[string]string{}
			switch fields["op"] {
			case "block":
				blockCase(fields, out)
			case "rc4":
				rc4Case(fields, out)
			case "gcm":
				gcmCase(fields, out)
			default:
				modeCase(fields, out)
			}
			var names []string
			for name := range out {
				names = append(names, name)
			}
			sortStrings(names)
			var parts []string
			for _, name := range names {
				parts = append(parts, name+"="+out[name])
			}
			fmt.Fprintln(writer, strings.Join(parts, " "))
		}
		if err != nil {
			break
		}
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
