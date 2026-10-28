package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func enc(s string) string { return hex.EncodeToString([]byte(s)) }

func dec(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return "err:" + enc(err.Error())
}

func encList(l []string) string {
	out := make([]string, len(l))
	for i, s := range l {
		out[i] = enc(s)
	}
	return strings.Join(out, ",")
}

var errBoom = errors.New("boom")

func kind(m fs.FileMode) string {
	switch {
	case m&fs.ModeSymlink != 0:
		return "L"
	case m.IsDir():
		return "D"
	default:
		return "F"
	}
}

// policy returns the error a walk callback gives for a visited path.
func policy(path string, isDir bool) error {
	base := filepath.Base(path)
	switch {
	case strings.HasPrefix(base, "skip") && isDir:
		return filepath.SkipDir
	case base == "skipfile":
		return filepath.SkipDir
	case base == "stop":
		return filepath.SkipAll
	case base == "boom":
		return errBoom
	}
	return nil
}

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 4096), 1<<20)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		f := strings.Split(s.Text(), "\t")
		get := func(i int) string {
			if i < len(f) {
				return dec(f[i])
			}
			return ""
		}
		op := f[0]
		a := get(1)
		var result string
		switch op {
		case "C":
			result = enc(filepath.Clean(a))
		case "S":
			d, file := filepath.Split(a)
			result = enc(d) + "|" + enc(file)
		case "B":
			result = enc(filepath.Base(a))
		case "D":
			result = enc(filepath.Dir(a))
		case "E":
			result = enc(filepath.Ext(a))
		case "A":
			result = fmt.Sprint(filepath.IsAbs(a))
		case "J":
			parts := make([]string, 0, len(f)-1)
			for i := 1; i < len(f); i++ {
				parts = append(parts, dec(f[i]))
			}
			result = enc(filepath.Join(parts...))
		case "M":
			m, err := filepath.Match(a, get(2))
			if err != nil {
				result = "error:" + enc(err.Error())
			} else {
				result = fmt.Sprint(m)
			}
		case "R":
			r, err := filepath.Rel(a, get(2))
			if err != nil {
				result = "error:" + enc(err.Error())
			} else {
				result = enc(r)
			}
		case "L":
			result = fmt.Sprint(filepath.IsLocal(a))
		case "Z":
			r, err := filepath.Localize(a)
			if err != nil {
				result = "error:" + enc(err.Error())
			} else {
				result = enc(r)
			}
		case "P":
			result = encList(filepath.SplitList(a))
		case "V":
			result = enc(filepath.VolumeName(a))
		case "T":
			result = enc(filepath.ToSlash(a))
		case "F":
			result = enc(filepath.FromSlash(a))
		case "H":
			result = fmt.Sprint(filepath.HasPrefix(a, get(2)))
		case "X":
			r, err := filepath.EvalSymlinks(a)
			if err != nil {
				result = "error:" + enc(err.Error())
			} else {
				result = enc(r)
			}
		case "Y":
			r, err := filepath.Abs(a)
			if err != nil {
				result = "error:" + enc(err.Error())
			} else {
				result = enc(r)
			}
		case "G":
			r, err := filepath.Glob(a)
			if err != nil {
				result = "error:" + enc(err.Error())
			} else {
				result = encList(r)
			}
		case "W", "K":
			var recs []string
			var err error
			if op == "W" {
				err = filepath.Walk(a, func(path string, info fs.FileInfo, err error) error {
					if err != nil {
						recs = append(recs, "E "+path+" "+err.Error())
						return nil
					}
					recs = append(recs, kind(info.Mode())+" "+path)
					return policy(path, info.IsDir())
				})
			} else {
				err = filepath.WalkDir(a, func(path string, d fs.DirEntry, err error) error {
					if err != nil {
						recs = append(recs, "E "+path+" "+err.Error())
						return nil
					}
					recs = append(recs, kind(d.Type())+" "+path)
					return policy(path, d.IsDir())
				})
			}
			result = encList(recs) + "|" + errText(err)
		default:
			panic("unknown operation " + op)
		}
		fmt.Fprintln(w, op+"|"+result)
	}
	if err := s.Err(); err != nil {
		panic(err)
	}
}
