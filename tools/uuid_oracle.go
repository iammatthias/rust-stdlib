// Line-oriented Go uuid oracle used by tools/uuid_check.py. Each request line is
//
//	U:<hex text>                     UnmarshalText on the bytes: the UUID bytes in hex, or "err"
//	M:<hex uuid>                     String, MarshalText and AppendText("pre:"), in one line
//	C:<hex uuid>:<hex uuid>          Compare, as -1, 0 or 1
//	P:<hex text>                     MustParse: the String of the UUID, or "panic"
//	G4:<n>, G7:<n>                   n values of NewV4 or NewV7, as hex, comma-separated
//
// Generated values are random, so tools/uuid_check.py checks their properties
// rather than comparing them.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"uuid"
)

func decode(text string) []byte {
	b, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return b
}

func toUUID(text string) uuid.UUID {
	var u uuid.UUID
	copy(u[:], decode(text))
	return u
}

func process(line string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = "panic"
		}
	}()
	parts := strings.Split(line, ":")
	switch parts[0] {
	case "U":
		var u uuid.UUID
		if err := u.UnmarshalText(decode(parts[1])); err != nil {
			return "err"
		}
		return hex.EncodeToString(u[:])
	case "M":
		u := toUUID(parts[1])
		m, _ := u.MarshalText()
		a, _ := u.AppendText([]byte("pre:"))
		return fmt.Sprintf("s:%s|m:%s|a:%s", u.String(), hex.EncodeToString(m), hex.EncodeToString(a))
	case "C":
		return strconv.Itoa(toUUID(parts[1]).Compare(toUUID(parts[2])))
	case "P":
		return uuid.MustParse(string(decode(parts[1]))).String()
	case "G4", "G7":
		n, _ := strconv.Atoi(parts[1])
		items := make([]string, n)
		for i := range items {
			if parts[0] == "G4" {
				u := uuid.NewV4()
				items[i] = hex.EncodeToString(u[:])
			} else {
				u := uuid.NewV7()
				items[i] = hex.EncodeToString(u[:])
			}
		}
		return strings.Join(items, ",")
	}
	panic("bad request " + line)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, process(in.Text()))
	}
	if err := in.Err(); err != nil {
		panic(err)
	}
}
