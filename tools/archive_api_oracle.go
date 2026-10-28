// Go oracle for the archive/tar and archive/zip API differential
// (tools/check_archive_api.py). It reads or writes archives and prints a
// canonical, line-oriented description that examples/archive_api_probe.rs
// reproduces byte for byte.
//
//	archive_api_oracle tar-read FILE
//	archive_api_oracle tar-write MANIFEST OUT
//	archive_api_oracle zip-read FILE
//	archive_api_oracle zip-write MANIFEST OUT
package main

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const contentCap = 8 << 20

func hx(s string) string { return hex.EncodeToString([]byte(s)) }

func tm(t time.Time) string {
	if t.IsZero() {
		return "zero"
	}
	return fmt.Sprintf("%d.%d", t.Unix(), t.Nanosecond())
}

func fnv64(b []byte, h uint64) uint64 {
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func kvs(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, hx(k)+":"+hx(m[k]))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, ",")
}

// digest reads r up to contentCap bytes and describes the content.
func digest(r io.Reader) string {
	h := uint64(14695981039346656037)
	total := 0
	buf := make([]byte, 32<<10)
	failed := 0
	trunc := 0
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if total+n > contentCap {
				n = contentCap - total
				trunc = 1
			}
			h = fnv64(buf[:n], h)
			total += n
		}
		if trunc == 1 {
			break
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			failed = 1
			break
		}
	}
	return fmt.Sprintf("D len=%d fnv=%016x trunc=%d err=%d", total, h, trunc, failed)
}

func nonUTF8(ss ...string) bool {
	for _, s := range ss {
		if !utf8.ValidString(s) {
			return true
		}
	}
	return false
}

func tarRead(path string, out *bufio.Writer) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			fmt.Fprintln(out, "END ok")
			return nil
		}
		if err != nil {
			fmt.Fprintln(out, "END err")
			return nil
		}
		bad := nonUTF8(h.Name, h.Linkname, h.Uname, h.Gname)
		for k, v := range h.PAXRecords {
			bad = bad || nonUTF8(k, v)
		}
		for k, v := range h.Xattrs {
			bad = bad || nonUTF8(k, v)
		}
		fmt.Fprintf(out, "H type=%d name=%s link=%s size=%d mode=%d uid=%d gid=%d uname=%s gname=%s mtime=%s atime=%s ctime=%s dmaj=%d dmin=%d fmt=%d xattr=%s pax=%s local=%d nonutf8=%d\n",
			h.Typeflag, hx(h.Name), hx(h.Linkname), h.Size, h.Mode, h.Uid, h.Gid, hx(h.Uname), hx(h.Gname),
			tm(h.ModTime), tm(h.AccessTime), tm(h.ChangeTime), h.Devmajor, h.Devminor, int(h.Format),
			kvs(h.Xattrs), kvs(h.PAXRecords), b2i(filepath.IsLocal(h.Name)), b2i(bad))
		fmt.Fprintln(out, digest(tr))
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// manifest lines are space separated key=value pairs; strings are hex.
type fields map[string]string

func parseLine(line string) fields {
	f := fields{}
	for _, kv := range strings.Fields(line) {
		k, v, _ := strings.Cut(kv, "=")
		f[k] = v
	}
	return f
}

func (f fields) str(k string) string {
	b, _ := hex.DecodeString(f[k])
	return string(b)
}

func (f fields) num(k string) int64 {
	n, _ := strconv.ParseInt(f[k], 10, 64)
	return n
}

func (f fields) time(k string) time.Time {
	v, ok := f[k]
	if !ok || v == "zero" {
		return time.Time{}
	}
	s, ns, _ := strings.Cut(v, ".")
	a, _ := strconv.ParseInt(s, 10, 64)
	b, _ := strconv.ParseInt(ns, 10, 64)
	return time.Unix(a, b).UTC()
}

func (f fields) kv(k string) map[string]string {
	v, ok := f[k]
	if !ok || v == "-" {
		return nil
	}
	m := map[string]string{}
	for _, p := range strings.Split(v, ",") {
		a, b, _ := strings.Cut(p, ":")
		ka, _ := hex.DecodeString(a)
		vb, _ := hex.DecodeString(b)
		m[string(ka)] = string(vb)
	}
	return m
}

func (f fields) data() []byte {
	b, _ := hex.DecodeString(f["data"])
	return b
}

func manifestLines(path string) ([]fields, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []fields
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, parseLine(line))
	}
	return out, nil
}

func status(err error) string {
	if err != nil {
		return "err"
	}
	return "ok"
}

func tarWrite(manifest, outPath string) error {
	lines, err := manifestLines(manifest)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for _, f := range lines {
		h := &tar.Header{
			Typeflag: byte(f.num("type")),
			Name:     f.str("name"),
			Linkname: f.str("link"),
			Size:     f.num("size"),
			Mode:     f.num("mode"),
			Uid:      int(f.num("uid")),
			Gid:      int(f.num("gid")),
			Uname:    f.str("uname"),
			Gname:    f.str("gname"),
			ModTime:  f.time("mtime"),
			Devmajor: f.num("dmaj"),
			Devminor: f.num("dmin"),
			Xattrs:   f.kv("xattr"),
			Format:   tar.Format(f.num("fmt")),
		}
		h.AccessTime = f.time("atime")
		h.ChangeTime = f.time("ctime")
		h.PAXRecords = f.kv("pax")
		err := tw.WriteHeader(h)
		fmt.Fprintf(out, "W %s\n", status(err))
		if err != nil {
			continue
		}
		if d := f.data(); len(d) > 0 {
			_, err = tw.Write(d)
			fmt.Fprintf(out, "D %s\n", status(err))
		}
	}
	err = tw.Close()
	fmt.Fprintf(out, "CLOSE %s\n", status(err))
	return os.WriteFile(outPath, buf.Bytes(), 0o600)
}

// sparseAt serves a .zsparse golden (gzip of: u64 size, u32 spans, then
// u64 offset, u32 len, bytes per span) as an io.ReaderAt over a large,
// mostly zero archive.
type sparseAt struct {
	size  int64
	spans []sparseSpan
}

type sparseSpan struct {
	off  int64
	data []byte
}

func (f *sparseAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset")
	}
	if off >= f.size {
		return 0, io.EOF
	}
	end := min(off+int64(len(p)), f.size)
	n := int(end - off)
	clear(p[:n])
	for _, s := range f.spans {
		sEnd := s.off + int64(len(s.data))
		if sEnd <= off || s.off >= end {
			continue
		}
		from, to := max(s.off, off), min(sEnd, end)
		copy(p[from-off:to-off], s.data[from-s.off:to-s.off])
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func openArchive(path string) (io.ReaderAt, int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	if !strings.HasSuffix(path, ".zsparse") {
		return bytes.NewReader(data), int64(len(data)), nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	raw, err := io.ReadAll(gz)
	if err != nil {
		return nil, 0, err
	}
	f := &sparseAt{size: int64(binary.LittleEndian.Uint64(raw))}
	n := int(binary.LittleEndian.Uint32(raw[8:]))
	raw = raw[12:]
	for i := 0; i < n; i++ {
		off := int64(binary.LittleEndian.Uint64(raw))
		l := int(binary.LittleEndian.Uint32(raw[8:]))
		f.spans = append(f.spans, sparseSpan{off, raw[12 : 12+l]})
		raw = raw[12+l:]
	}
	return f, f.size, nil
}

func zipRead(path string, out *bufio.Writer) error {
	ra, size, err := openArchive(path)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		fmt.Fprintln(out, "END err")
		return nil
	}
	fmt.Fprintf(out, "Z comment=%s count=%d\n", hx(zr.Comment), len(zr.File))
	for _, f := range zr.File {
		off, offErr := f.DataOffset()
		fmt.Fprintf(out, "F name=%s comment=%s nonutf8=%d creator=%d reader=%d flags=%d method=%d mtime=%d mdate=%d modified=%s crc=%d csize=%d usize=%d csize64=%d usize64=%d extra=%s attrs=%d mode=%d offset=%d offerr=%d\n",
			hx(f.Name), hx(f.Comment), b2i(f.NonUTF8), f.CreatorVersion, f.ReaderVersion, f.Flags, f.Method,
			f.ModifiedTime, f.ModifiedDate, tm(f.Modified), f.CRC32, f.CompressedSize, f.UncompressedSize,
			f.CompressedSize64, f.UncompressedSize64, hex.EncodeToString(f.Extra), f.ExternalAttrs, uint32(f.Mode()), off, b2i(offErr != nil))
		rc, err := f.Open()
		if err != nil {
			fmt.Fprintf(out, "D open=err\n")
			continue
		}
		fmt.Fprintln(out, digest(rc))
		rc.Close()
		raw, err := f.OpenRaw()
		if err != nil {
			fmt.Fprintln(out, "R err")
		} else {
			fmt.Fprintln(out, strings.Replace(digest(raw), "D ", "R ", 1))
		}
	}
	// The fs.FS view.
	var names []string
	werr := fs.WalkDir(zr, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			names = append(names, "walkerr:"+hx(name))
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			names = append(names, "infoerr:"+hx(name))
			return nil
		}
		line := fmt.Sprintf("%s:dir=%d:size=%d:mode=%d", hx(name), b2i(d.IsDir()), info.Size(), uint32(info.Mode()))
		if !d.IsDir() {
			if f, oerr := zr.Open(name); oerr == nil {
				line += ":" + strings.Replace(digest(f), " ", ",", -1)
				f.Close()
			} else {
				line += ":openerr"
			}
		}
		names = append(names, line)
		return nil
	})
	_ = werr
	fmt.Fprintf(out, "FS %s\n", strings.Join(names, " "))
	fmt.Fprintln(out, "END ok")
	return nil
}

func zipWrite(manifest, outPath string) error {
	lines, err := manifestLines(manifest)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	var created []*zip.FileHeader
	for _, f := range lines {
		switch f["op"] {
		case "comment":
			err := zw.SetComment(f.str("comment"))
			fmt.Fprintf(out, "C %s\n", status(err))
			continue
		case "offset":
			zw.SetOffset(f.num("offset"))
			continue
		}
		name, comment := f.str("name"), f.str("comment")
		if v, ok := f["rawname"]; ok {
			b, _ := hex.DecodeString(v)
			name = string(b)
		}
		if v, ok := f["rawcomment"]; ok {
			b, _ := hex.DecodeString(v)
			comment = string(b)
		}
		h := &zip.FileHeader{
			Name:    name,
			Comment: comment,
			Method:  uint16(f.num("method")),
			NonUTF8: f["nonutf8"] == "1",
			Extra:   f.rawExtra(),
			Flags:   uint16(f.num("flags")),
		}
		if v, ok := f["modified"]; ok && v != "zero" {
			h.Modified = f.time("modified")
		}
		if v, ok := f["mode"]; ok {
			n, _ := strconv.ParseUint(v, 10, 32)
			h.SetMode(fs.FileMode(n))
		}
		var w io.Writer
		var err error
		switch f["op"] {
		case "raw":
			h.CRC32 = uint32(f.num("crc"))
			h.CompressedSize64 = uint64(f.num("csize64"))
			h.UncompressedSize64 = uint64(f.num("usize64"))
			w, err = zw.CreateRaw(h)
		default:
			w, err = zw.CreateHeader(h)
		}
		fmt.Fprintf(out, "W %s\n", status(err))
		if err != nil {
			continue
		}
		created = append(created, h)
		if d := f.data(); len(d) > 0 {
			_, err = w.Write(d)
			fmt.Fprintf(out, "D %s\n", status(err))
		}
	}
	err = zw.Close()
	fmt.Fprintf(out, "CLOSE %s\n", status(err))
	// CreateHeader updates the headers it is given: print them as Rust's Writer::headers.
	for _, h := range created {
		sizes := "-"
		if h.Method == zip.Store {
			sizes = fmt.Sprintf("%d,%d,%d,%d", h.CompressedSize, h.UncompressedSize, h.CompressedSize64, h.UncompressedSize64)
		}
		fmt.Fprintf(out, "HD name=%s creator=%d reader=%d flags=%d method=%d mtime=%d mdate=%d crc=%d sizes=%s usize64=%d extra=%s\n",
			hx(h.Name), h.CreatorVersion, h.ReaderVersion, h.Flags, h.Method, h.ModifiedTime, h.ModifiedDate,
			h.CRC32, sizes, h.UncompressedSize64, hex.EncodeToString(h.Extra))
	}
	return os.WriteFile(outPath, buf.Bytes(), 0o600)
}

func (f fields) rawExtra() []byte {
	b, _ := hex.DecodeString(f["extra"])
	return b
}

// tarFileInfo prints FileInfoHeader of os.Lstat(path) for each path, with
// Uname and Gname from the user database as Go looks them up.
func tarFileInfo(paths []string, out *bufio.Writer) {
	for _, path := range paths {
		fi, err := os.Lstat(path)
		if err != nil {
			fmt.Fprintf(out, "FI %s lstat-err\n", hx(path))
			continue
		}
		link := ""
		if fi.Mode()&fs.ModeSymlink != 0 {
			link, _ = os.Readlink(path)
		}
		h, err := tar.FileInfoHeader(fi, link)
		if err != nil {
			fmt.Fprintf(out, "FI %s err\n", hx(path))
			continue
		}
		fmt.Fprintf(out, "FI %s type=%d name=%s link=%s size=%d mode=%d uid=%d gid=%d uname=%s gname=%s mtime=%s atime=%s ctime=%s dmaj=%d dmin=%d\n",
			hx(path), h.Typeflag, hx(h.Name), hx(h.Linkname), h.Size, h.Mode, h.Uid, h.Gid, hx(h.Uname), hx(h.Gname),
			tm(h.ModTime), tm(h.AccessTime), tm(h.ChangeTime), h.Devmajor, h.Devminor)
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: archive_api_oracle tar-read|zip-read FILE... | tar-write|zip-write MANIFEST OUT")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "tar-read", "zip-read":
		out := bufio.NewWriter(os.Stdout)
		for _, path := range os.Args[2:] {
			fmt.Fprintf(out, "@@ %s\n", path)
			if os.Args[1] == "tar-read" {
				err = tarRead(path, out)
			} else {
				err = zipRead(path, out)
			}
			if err != nil {
				break
			}
		}
		out.Flush()
	case "tar-fileinfo":
		out := bufio.NewWriter(os.Stdout)
		tarFileInfo(os.Args[2:], out)
		out.Flush()
	case "tar-write":
		err = tarWrite(os.Args[2], os.Args[3])
	case "zip-write":
		err = zipWrite(os.Args[2], os.Args[3])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
