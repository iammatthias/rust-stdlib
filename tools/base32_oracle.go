// Line-oriented Go base32 oracle used by tools/base32_check.py. Requests:
//
//	E<c>:<hex>            Encode and EncodeToString, then EncodedLen/DecodedLen
//	L<c>:<n>              EncodedLen(n) and DecodedLen(n)
//	A<c>:<hex>            AppendDecode(nil, src)
//	B<c>:<hex>            Decode(dst, src) with len(dst) == len(src)
//	S<c>:<hex>            DecodeString(src)
//	W<c>:<hex>            NewEncoder, written in 3-byte chunks, then Close
//	R<c>:<hex>            NewDecoder read to the end with io.ReadAll
//	C<c>:<read>,<chunk>|<hex>  NewDecoder over a reader that returns at most
//	                      <chunk> bytes per Read, read with <read>-byte buffers
//	N:<alphabet hex>|<p>  NewEncoding(alphabet).WithPadding(p)
//
// <c> selects one of the configurations in configs(), shared with
// examples/base32_probe.rs. A panic from the constructors is reported as "panic".
package main

import (
	"bufio"
	"bytes"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

func bytesRange(from byte, count int) string {
	out := make([]byte, count)
	for i := range out {
		out[i] = from + byte(i)
	}
	return string(out)
}

func configs() []*base32.Encoding {
	lower :="abcdefghijklmnopqrstuvwxyz234567"
	reversed := "ZYXWVUTSRQPONMLKJIHGFEDCBA765432"
	return []*base32.Encoding{
		base32.StdEncoding,
		base32.HexEncoding,
		base32.StdEncoding.WithPadding(base32.NoPadding),
		base32.HexEncoding.WithPadding(base32.NoPadding),
		base32.NewEncoding(lower).WithPadding('-'),
		base32.NewEncoding(bytesRange(0x80, 32)).WithPadding(0xff),
		base32.NewEncoding(bytesRange(0xe0, 32)).WithPadding(base32.NoPadding),
		base32.NewEncoding(reversed),
	}
}

func mustHex(text string) []byte {
	b, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return b
}

func configure(alphabet []byte, padding int) (out string) {
	defer func() {
		if recover() != nil {
			out = "panic"
		}
	}()
	enc := base32.NewEncoding(string(alphabet)).WithPadding(rune(padding))
	return "ok:" + hex.EncodeToString([]byte(enc.EncodeToString([]byte("foobar"))))
}

// chunkReader returns at most chunk bytes per Read.
type chunkReader struct {
	data  []byte
	chunk int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(p), r.chunk, len(r.data))
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

// readSchedule reads d with read-byte buffers and describes every read that
// returned data, then the final status. Go's (n > 0, err) pair is split into
// the data and the error, which is how a Rust io::Read reports it.
func readSchedule(d io.Reader, read int) string {
	var parts []string
	p := make([]byte, read)
	for i := 0; ; i++ {
		if i > 100000 {
			return strings.Join(parts, ";") + ";stall"
		}
		n, err := d.Read(p)
		if n > 0 {
			parts = append(parts, hex.EncodeToString(p[:n]))
		}
		if err != nil {
			status := err.Error()
			switch e := err.(type) {
			case base32.CorruptInputError:
				status = fmt.Sprintf("corrupt:%d", int64(e))
			default:
				if err == io.EOF {
					status = "EOF"
				} else if err == io.ErrUnexpectedEOF {
					status = "UEOF"
				}
			}
			return strings.Join(parts, ";") + "|" + status
		}
	}
}

func errorOffset(err error) int64 {
	return int64(err.(base32.CorruptInputError))
}

func handle(line string, cs []*base32.Encoding) string {
	if strings.HasPrefix(line, "C") {
		head, payload, _ := strings.Cut(line[1:], ":")
		c, _ := strconv.Atoi(head)
		sizes, data, _ := strings.Cut(payload, "|")
		read, chunk, _ := strings.Cut(sizes, ",")
		r, _ := strconv.Atoi(read)
		k, _ := strconv.Atoi(chunk)
		d := base32.NewDecoder(cs[c], &chunkReader{data: mustHex(data), chunk: k})
		return readSchedule(d, r)
	}
	if strings.HasPrefix(line, "N:") {
		alphabet, padding, _ := strings.Cut(line[2:], "|")
		p, err := strconv.Atoi(padding)
		if err != nil {
			panic(err)
		}
		return configure(mustHex(alphabet), p)
	}
	index, payload, ok := strings.Cut(line[1:], ":")
	if !ok {
		panic("bad request: " + line)
	}
	c, err := strconv.Atoi(index)
	if err != nil {
		panic(err)
	}
	enc := cs[c]
	switch line[0] {
	case 'L':
		n, err := strconv.Atoi(payload)
		if err != nil {
			panic(err)
		}
		return fmt.Sprintf("%d %d", enc.EncodedLen(n), enc.DecodedLen(n))
	case 'E':
		plain := mustHex(payload)
		dst := make([]byte, enc.EncodedLen(len(plain)))
		enc.Encode(dst, plain)
		if string(dst) != enc.EncodeToString(plain) {
			panic("Encode disagrees with EncodeToString")
		}
		return hex.EncodeToString(dst)
	case 'A':
		out, err := enc.AppendDecode(nil, mustHex(payload))
		if err != nil {
			return fmt.Sprintf("err:%d:%s", errorOffset(err), hex.EncodeToString(out))
		}
		return "ok:" + hex.EncodeToString(out)
	case 'B':
		src := mustHex(payload)
		dst := make([]byte, len(src))
		n, err := enc.Decode(dst, src)
		if err != nil {
			return fmt.Sprintf("err:%d:%d:%s", n, errorOffset(err), hex.EncodeToString(dst[:n]))
		}
		return fmt.Sprintf("ok:%d:%s", n, hex.EncodeToString(dst[:n]))
	case 'S':
		out, err := enc.DecodeString(string(mustHex(payload)))
		if err != nil {
			return fmt.Sprintf("err:%d:%s", errorOffset(err), hex.EncodeToString(out))
		}
		return "ok:" + hex.EncodeToString(out)
	case 'W':
		plain := mustHex(payload)
		var buf bytes.Buffer
		w := base32.NewEncoder(enc, &buf)
		for i := 0; i < len(plain); i += 3 {
			end := min(i+3, len(plain))
			if _, err := w.Write(plain[i:end]); err != nil {
				panic(err)
			}
		}
		if err := w.Close(); err != nil {
			panic(err)
		}
		return hex.EncodeToString(buf.Bytes())
	case 'R':
		out, err := io.ReadAll(base32.NewDecoder(enc, bytes.NewReader(mustHex(payload))))
		// Streaming output before an error depends on read chunking, so only the outcome is compared.
		if err != nil {
			return "err"
		}
		return "ok:" + hex.EncodeToString(out)
	}
	panic("unknown op: " + line)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 4096), 16*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	cs := configs()
	for in.Scan() {
		fmt.Fprintln(out, handle(in.Text(), cs))
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
