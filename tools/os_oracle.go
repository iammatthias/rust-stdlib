package main

// Go oracle for the os differential (tools/os_check.py). It executes scripted
// operations, each in a fresh directory, and prints one result line per
// operation plus a dump of the resulting tree. Build with -tags osusergo is
// not needed here; os/user has its own oracle.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func enc(s string) string { return hex.EncodeToString([]byte(s)) }

func dec(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

var digits = regexp.MustCompile(`[0-9]{3,}`)

func norm(s string) string { return digits.ReplaceAllString(s, "#") }

func flags(err error) string {
	var b strings.Builder
	pred := func(c string, v bool) {
		if v {
			b.WriteString(c)
		}
	}
	pred("e", os.IsExist(err))
	pred("n", os.IsNotExist(err))
	pred("p", os.IsPermission(err))
	pred("t", os.IsTimeout(err))
	pred("E", errors.Is(err, fs.ErrExist))
	pred("N", errors.Is(err, fs.ErrNotExist))
	pred("P", errors.Is(err, fs.ErrPermission))
	pred("C", errors.Is(err, fs.ErrClosed))
	pred("I", errors.Is(err, fs.ErrInvalid))
	pred("F", err == io.EOF)
	return b.String()
}

func errStr(err error) string {
	return "err:" + flags(err) + ":" + enc(norm(err.Error()))
}

func parseMode(s string) os.FileMode {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		panic(err)
	}
	return os.FileMode(v)
}

func parseFlags(s string) int {
	f := 0
	switch {
	case strings.Contains(s, "RW"):
		f |= os.O_RDWR
	case strings.Contains(s, "W"):
		f |= os.O_WRONLY
	}
	if strings.Contains(s, "A") {
		f |= os.O_APPEND
	}
	if strings.Contains(s, "C") {
		f |= os.O_CREATE
	}
	if strings.Contains(s, "X") {
		f |= os.O_EXCL
	}
	if strings.Contains(s, "T") {
		f |= os.O_TRUNC
	}
	return f
}

func describe(fi fs.FileInfo) string {
	size := int64(-1)
	if fi.Mode().IsRegular() {
		size = fi.Size()
	}
	return fmt.Sprintf("%s|%s|%d|%t", enc(fi.Name()), fi.Mode().String(), size, fi.IsDir())
}

func typeOf(m fs.FileMode) string { return m.Type().String() }

var base string

func relWd() string {
	wd, err := os.Getwd()
	if err != nil {
		return errStr(err)
	}
	real, _ := filepath.EvalSymlinks(wd)
	r, err := filepath.Rel(base, real)
	if err != nil {
		return "outside"
	}
	return "ok:" + enc(r)
}

var curDir string

func dump() string {
	os.Chdir(curDir)
	var recs []string
	filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			recs = append(recs, "E "+norm(p))
			return nil
		}
		fi, err := os.Lstat(p)
		if err != nil {
			recs = append(recs, "E "+norm(p))
			return nil
		}
		rec := fmt.Sprintf("%s %s", norm(p), fi.Mode().String())
		switch {
		case fi.Mode().IsRegular():
			data, err := os.ReadFile(p)
			if err != nil {
				rec += " unreadable"
			} else {
				rec += fmt.Sprintf(" %d %x", fi.Size(), data)
			}
		case fi.Mode()&fs.ModeSymlink != 0:
			t, _ := os.Readlink(p)
			rec += " -> " + t
		}
		recs = append(recs, rec)
		return nil
	})
	sort.Strings(recs)
	return enc(strings.Join(recs, "\n"))
}

func fileOps(f *os.File, script string) string {
	var out []string
	for _, a := range strings.Split(script, ";") {
		if a == "" {
			continue
		}
		p := strings.Split(a, ":")
		var r string
		switch p[0] {
		case "w":
			n, err := f.Write([]byte(dec(p[1])))
			r = fmt.Sprintf("w%d", n)
			if err != nil {
				r += errStr(err)
			}
		case "ws":
			n, err := f.WriteString(dec(p[1]))
			r = fmt.Sprintf("ws%d", n)
			if err != nil {
				r += errStr(err)
			}
		case "r":
			n, _ := strconv.Atoi(p[1])
			buf := make([]byte, n)
			k, err := f.Read(buf)
			r = fmt.Sprintf("r%d:%x", k, buf[:k])
			if err != nil {
				r += errStr(err)
			}
		case "s":
			off, _ := strconv.ParseInt(p[1], 10, 64)
			wh, _ := strconv.Atoi(p[2])
			pos, err := f.Seek(off, wh)
			r = fmt.Sprintf("s%d", pos)
			if err != nil {
				r += errStr(err)
			}
		case "ra":
			off, _ := strconv.ParseInt(p[1], 10, 64)
			n, _ := strconv.Atoi(p[2])
			buf := make([]byte, n)
			k, err := f.ReadAt(buf, off)
			r = fmt.Sprintf("ra%d:%x", k, buf[:k])
			if err != nil {
				r += errStr(err)
			}
		case "wa":
			off, _ := strconv.ParseInt(p[1], 10, 64)
			n, err := f.WriteAt([]byte(dec(p[2])), off)
			r = fmt.Sprintf("wa%d", n)
			if err != nil {
				r += errStr(err)
			}
		case "tr":
			sz, _ := strconv.ParseInt(p[1], 10, 64)
			if err := f.Truncate(sz); err != nil {
				r = "tr" + errStr(err)
			} else {
				r = "tr-ok"
			}
		case "st":
			fi, err := f.Stat()
			if err != nil {
				r = "st" + errStr(err)
			} else {
				r = "st:" + describe(fi)
			}
		case "sync":
			if err := f.Sync(); err != nil {
				r = "sync" + errStr(err)
			} else {
				r = "sync-ok"
			}
		case "chmod":
			if err := f.Chmod(parseMode(p[1])); err != nil {
				r = "chmod" + errStr(err)
			} else {
				r = "chmod-ok"
			}
		case "rd", "rdn", "rdi":
			n, _ := strconv.Atoi(p[1])
			var names []string
			var err error
			switch p[0] {
			case "rd":
				var es []os.DirEntry
				es, err = f.ReadDir(n)
				for _, e := range es {
					names = append(names, e.Name()+"/"+e.Type().String())
				}
			case "rdn":
				names, err = f.Readdirnames(n)
			case "rdi":
				var is []fs.FileInfo
				is, err = f.Readdir(n)
				for _, i := range is {
					names = append(names, i.Name()+"/"+i.Mode().String())
				}
			}
			sort.Strings(names)
			r = fmt.Sprintf("%s%d:%s", p[0], len(names), enc(strings.Join(names, ",")))
			if err != nil {
				r += errStr(err)
			}
		case "c":
			if err := f.Close(); err != nil {
				r = "c" + errStr(err)
			} else {
				r = "c-ok"
			}
		case "name":
			r = "name:" + enc(f.Name())
		case "dl":
			err := f.SetDeadline(time.Now().Add(time.Second))
			if err != nil {
				r = "dl" + errStr(err)
			} else {
				r = "dl-ok"
			}
		case "rdl":
			err := f.SetReadDeadline(time.Time{})
			if err != nil {
				r = "rdl" + errStr(err)
			} else {
				r = "rdl-ok"
			}
		case "all":
			data, err := io.ReadAll(f)
			r = fmt.Sprintf("all%d:%x", len(data), data)
			if err != nil {
				r += errStr(err)
			}
		case "wt":
			var b bytes.Buffer
			n, err := f.WriteTo(&b)
			r = fmt.Sprintf("wt%d:%x", n, b.Bytes())
			if err != nil {
				r += errStr(err)
			}
		case "rf":
			n, err := f.ReadFrom(strings.NewReader(dec(p[1])))
			r = fmt.Sprintf("rf%d", n)
			if err != nil {
				r += errStr(err)
			}
		default:
			panic("unknown file op " + p[0])
		}
		out = append(out, r)
	}
	return strings.Join(out, ",")
}

var root *os.Root

func run(f []string) string {
	get := func(i int) string {
		if i < len(f) {
			return dec(f[i])
		}
		return ""
	}
	res := func(err error) string {
		if err != nil {
			return errStr(err)
		}
		return "ok"
	}
	switch f[0] {
	case "mkdir":
		return res(os.Mkdir(get(1), parseMode(get(2))))
	case "mkdirall":
		return res(os.MkdirAll(get(1), parseMode(get(2))))
	case "writefile":
		return res(os.WriteFile(get(1), []byte(get(2)), parseMode(get(3))))
	case "readfile":
		d, err := os.ReadFile(get(1))
		if err != nil {
			return errStr(err)
		}
		return "ok:" + hex.EncodeToString(d)
	case "remove":
		return res(os.Remove(get(1)))
	case "removeall":
		return res(os.RemoveAll(get(1)))
	case "rename":
		return res(os.Rename(get(1), get(2)))
	case "link":
		return res(os.Link(get(1), get(2)))
	case "symlink":
		return res(os.Symlink(get(1), get(2)))
	case "readlink":
		d, err := os.Readlink(get(1))
		if err != nil {
			return errStr(err)
		}
		return "ok:" + enc(d)
	case "stat", "lstat":
		var fi fs.FileInfo
		var err error
		if f[0] == "stat" {
			fi, err = os.Stat(get(1))
		} else {
			fi, err = os.Lstat(get(1))
		}
		if err != nil {
			return errStr(err)
		}
		return "ok:" + describe(fi)
	case "stattime":
		fi, err := os.Stat(get(1))
		if err != nil {
			return errStr(err)
		}
		return fmt.Sprintf("ok:%d", fi.ModTime().Unix())
	case "chmod":
		return res(os.Chmod(get(1), parseMode(get(2))))
	case "truncate":
		n, _ := strconv.ParseInt(get(2), 10, 64)
		return res(os.Truncate(get(1), n))
	case "chtimes":
		a, _ := strconv.ParseInt(get(2), 10, 64)
		m, _ := strconv.ParseInt(get(3), 10, 64)
		var at, mt time.Time
		if a != 0 {
			at = time.Unix(a, 0)
		}
		if m != 0 {
			mt = time.Unix(m, 0)
		}
		return res(os.Chtimes(get(1), at, mt))
	case "readdir":
		es, err := os.ReadDir(get(1))
		var names []string
		for _, e := range es {
			names = append(names, e.Name()+"/"+e.Type().String())
		}
		r := "ok:" + enc(strings.Join(names, ","))
		if err != nil {
			return errStr(err)
		}
		return r
	case "samefile":
		a, err := os.Stat(get(1))
		if err != nil {
			return errStr(err)
		}
		b, err := os.Stat(get(2))
		if err != nil {
			return errStr(err)
		}
		return fmt.Sprintf("ok:%t", os.SameFile(a, b))
	case "openw":
		fl := parseFlags(get(2))
		f, err := os.OpenFile(get(1), fl, parseMode(get(3)))
		if err != nil {
			return errStr(err)
		}
		n, werr := f.Write([]byte(get(4)))
		cerr := f.Close()
		r := fmt.Sprintf("ok:%d", n)
		if werr != nil {
			r += ":w" + errStr(werr)
		}
		if cerr != nil {
			r += ":c" + errStr(cerr)
		}
		return r
	case "file":
		f, err := os.OpenFile(get(1), parseFlags(get(2)), parseMode(get(3)))
		if err != nil {
			return errStr(err)
		}
		defer f.Close()
		return "ok:" + fileOps(f, get(4))
	case "createtemp":
		f, err := os.CreateTemp(get(1), get(2))
		if err != nil {
			return errStr(err)
		}
		name := f.Name()
		f.Close()
		return "ok:" + enc(norm(name))
	case "mkdirtemp":
		n, err := os.MkdirTemp(get(1), get(2))
		if err != nil {
			return errStr(err)
		}
		return "ok:" + enc(norm(n))
	case "chdir":
		return res(os.Chdir(get(1)))
	case "getwd":
		return relWd()
	case "copyfs":
		return res(os.CopyFS(get(2), os.DirFS(get(1))))
	case "dirfsread":
		d, err := fs.ReadFile(os.DirFS(get(1)), get(2))
		if err != nil {
			return errStr(err)
		}
		return "ok:" + hex.EncodeToString(d)
	case "dirfsstat":
		fi, err := fs.Stat(os.DirFS(get(1)), get(2))
		if err != nil {
			return errStr(err)
		}
		return "ok:" + describe(fi)
	case "dirfsreaddir":
		es, err := fs.ReadDir(os.DirFS(get(1)), get(2))
		if err != nil {
			return errStr(err)
		}
		var names []string
		for _, e := range es {
			names = append(names, e.Name()+"/"+e.Type().String())
		}
		return "ok:" + enc(strings.Join(names, ","))
	case "pipe":
		r, w, err := os.Pipe()
		if err != nil {
			return errStr(err)
		}
		w.Write([]byte(get(1)))
		w.Close()
		d, err := io.ReadAll(r)
		r.Close()
		return fmt.Sprintf("ok:%x", d)
	case "setenv":
		return res(os.Setenv(get(1), get(2)))
	case "unsetenv":
		return res(os.Unsetenv(get(1)))
	case "getenv":
		return "ok:" + enc(os.Getenv(get(1)))
	case "lookupenv":
		v, ok := os.LookupEnv(get(1))
		return fmt.Sprintf("ok:%t:%s", ok, enc(v))
	case "expand":
		return "ok:" + enc(os.Expand(get(1), func(k string) string { return "<" + k + ">" }))
	case "expandenv":
		return "ok:" + enc(os.ExpandEnv(get(1)))
	case "userdirs":
		h, e1 := os.UserHomeDir()
		c, e2 := os.UserCacheDir()
		cf, e3 := os.UserConfigDir()
		part := func(s string, e error) string {
			if e != nil {
				return "E" + enc(e.Error())
			}
			return enc(s)
		}
		return "ok:" + part(h, e1) + "," + part(c, e2) + "," + part(cf, e3) + "," + enc(os.TempDir())
	case "info":
		g, _ := os.Getgroups()
		sort.Ints(g)
		return fmt.Sprintf("ok:%d,%d,%d,%d,%d,%v", os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), os.Getpagesize(), g)
	case "consts":
		return fmt.Sprintf("ok:%c,%c,%s,%t,%t", os.PathSeparator, os.PathListSeparator, os.DevNull,
			os.IsPathSeparator('/'), os.IsPathSeparator('a'))
	case "modes":
		m, _ := strconv.ParseUint(get(1), 8, 32)
		var out []string
		for _, bits := range []uint32{0, uint32(os.ModeDir), uint32(os.ModeSymlink), uint32(os.ModeSetuid), uint32(os.ModeSticky),
			uint32(os.ModeNamedPipe), uint32(os.ModeSocket), uint32(os.ModeDevice | os.ModeCharDevice), uint32(os.ModeAppend | os.ModeExclusive | os.ModeTemporary), uint32(os.ModeIrregular), uint32(os.ModeSetgid)} {
			out = append(out, os.FileMode(bits|uint32(m)).String())
		}
		return "ok:" + enc(strings.Join(out, ","))
	// ---- Root ----
	case "rootopen":
		r, err := os.OpenRoot(get(1))
		if err != nil {
			return errStr(err)
		}
		root = r
		return "ok:" + enc(r.Name())
	case "rootclose":
		return res(root.Close())
	case "rsub":
		r, err := root.OpenRoot(get(1))
		if err != nil {
			return errStr(err)
		}
		defer r.Close()
		return "ok:" + enc(r.Name())
	case "rread":
		d, err := root.ReadFile(get(1))
		if err != nil {
			return errStr(err)
		}
		return "ok:" + hex.EncodeToString(d)
	case "rwrite":
		return res(root.WriteFile(get(1), []byte(get(2)), parseMode(get(3))))
	case "rfile":
		f, err := root.OpenFile(get(1), parseFlags(get(2)), parseMode(get(3)))
		if err != nil {
			return errStr(err)
		}
		defer f.Close()
		return "ok:" + enc(f.Name()) + ":" + fileOps(f, get(4))
	case "rcreate":
		f, err := root.Create(get(1))
		if err != nil {
			return errStr(err)
		}
		f.Close()
		return "ok"
	case "rmkdir":
		return res(root.Mkdir(get(1), parseMode(get(2))))
	case "rmkdirall":
		return res(root.MkdirAll(get(1), parseMode(get(2))))
	case "rstat", "rlstat":
		var fi fs.FileInfo
		var err error
		if f[0] == "rstat" {
			fi, err = root.Stat(get(1))
		} else {
			fi, err = root.Lstat(get(1))
		}
		if err != nil {
			return errStr(err)
		}
		return "ok:" + describe(fi)
	case "rreadlink":
		d, err := root.Readlink(get(1))
		if err != nil {
			return errStr(err)
		}
		return "ok:" + enc(d)
	case "rsymlink":
		return res(root.Symlink(get(1), get(2)))
	case "rlink":
		return res(root.Link(get(1), get(2)))
	case "rrename":
		return res(root.Rename(get(1), get(2)))
	case "rremove":
		return res(root.Remove(get(1)))
	case "rremoveall":
		return res(root.RemoveAll(get(1)))
	case "rchmod":
		return res(root.Chmod(get(1), parseMode(get(2))))
	case "rfsread":
		d, err := fs.ReadFile(root.FS(), get(1))
		if err != nil {
			return errStr(err)
		}
		return "ok:" + hex.EncodeToString(d)
	case "rfsreaddir":
		es, err := fs.ReadDir(root.FS(), get(1))
		if err != nil {
			return errStr(err)
		}
		var names []string
		for _, e := range es {
			names = append(names, e.Name()+"/"+e.Type().String())
		}
		return "ok:" + enc(strings.Join(names, ","))
	case "inroot":
		f, err := os.OpenInRoot(get(1), get(2))
		if err != nil {
			return errStr(err)
		}
		defer f.Close()
		d, _ := io.ReadAll(f)
		return fmt.Sprintf("ok:%x", d)
	}
	panic("unknown op " + f[0])
}

func main() {
	var err error
	base, err = os.Getwd()
	if err != nil {
		panic(err)
	}
	base, _ = filepath.EvalSymlinks(base)
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 1<<16), 1<<24)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	n := 0
	for s.Scan() {
		f := strings.Split(s.Text(), "\t")
		if f[0] == "NEW" {
			if n > 0 {
				fmt.Fprintln(w, "TREE|"+dump())
			}
			os.Chdir(base)
			if root != nil {
				root.Close()
				root = nil
			}
			dir := fmt.Sprintf("s%d", n)
			n++
			if err := os.Mkdir(dir, 0o755); err != nil {
				panic(err)
			}
			os.Chdir(dir)
			curDir = filepath.Join(base, dir)
			continue
		}
		fmt.Fprintln(w, f[0]+"|"+run(f))
	}
	if n > 0 {
		fmt.Fprintln(w, "TREE|"+dump())
	}
}
