// Go standard-library oracle for the shared compatibility corpus.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
)

type input struct {
	Op      string `json:"op"`
	Input   string `json:"input"`
	Variant string `json:"variant"`
}

func run(v input) (string, error) {
	switch v.Op {
	case "hex":
		b, err := hex.DecodeString(v.Input)
		return hex.EncodeToString(b), err
	case "base64", "base64-decode":
		var enc *base64.Encoding
		switch v.Variant {
		case "standard":
			enc = base64.StdEncoding.Strict()
		case "url":
			enc = base64.URLEncoding.Strict()
		case "raw-standard":
			enc = base64.RawStdEncoding.Strict()
		case "raw-url":
			enc = base64.RawURLEncoding.Strict()
		default:
			return "", fmt.Errorf("invalid variant")
		}
		if v.Op == "base64" {
			b, err := hex.DecodeString(v.Input)
			return enc.EncodeToString(b), err
		}
		b, err := enc.DecodeString(v.Input)
		return hex.EncodeToString(b), err
	case "query-escape":
		return url.QueryEscape(v.Input), nil
	case "json":
		dec := json.NewDecoder(strings.NewReader(v.Input))
		dec.UseNumber()
		var object any
		if err := dec.Decode(&object); err != nil {
			return "", err
		}
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF {
			return "", fmt.Errorf("trailing JSON data")
		}
		var out bytes.Buffer
		enc := json.NewEncoder(&out)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(object); err != nil {
			return "", err
		}
		return strings.TrimSuffix(out.String(), "\n"), nil
	default:
		return "", fmt.Errorf("unknown operation: %s", v.Op)
	}
}
func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 2*1024*1024)
	out := json.NewEncoder(os.Stdout)
	out.SetEscapeHTML(false)
	for scanner.Scan() {
		var v input
		err := json.Unmarshal(scanner.Bytes(), &v)
		var result string
		if err == nil {
			result, err = run(v)
		}
		record := map[string]string{"ok": result}
		if err != nil {
			record = map[string]string{"error": err.Error()}
		}
		if err := out.Encode(record); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
