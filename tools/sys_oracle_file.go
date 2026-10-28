// File deadline scenarios of the rust_stdlib_sys Go differential; built
// together with sys_oracle.go.
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

func within(start time.Time, lo, hi int) bool {
	el := time.Since(start)
	return el >= time.Duration(lo)*time.Millisecond && el < time.Duration(hi)*time.Millisecond
}

func runFile(f []string) string {
	switch f[0] {
	case "fdl_timeout":
		ms, _ := strconv.Atoi(f[1])
		r, w, _ := os.Pipe()
		defer r.Close()
		defer w.Close()
		start := time.Now()
		r.SetReadDeadline(start.Add(time.Duration(ms) * time.Millisecond))
		n, err := r.Read(make([]byte, 8))
		return fmt.Sprintf("n=%d %s timely=%v", n, errText(err), within(start, ms-5, ms+500))
	case "fdl_past":
		r, w, _ := os.Pipe()
		defer r.Close()
		defer w.Close()
		w.Write([]byte("x"))
		e1 := r.SetReadDeadline(time.Now().Add(-time.Second))
		n, err := r.Read(make([]byte, 8))
		out := fmt.Sprintf("set=%s n=%d %s", errText(e1), n, errText(err))
		e2 := r.SetReadDeadline(time.Time{})
		n, err = r.Read(make([]byte, 8))
		return out + fmt.Sprintf(" cleared=%s n=%d %s", errText(e2), n, errText(err))
	case "fdl_extend":
		r, w, _ := os.Pipe()
		defer r.Close()
		defer w.Close()
		start := time.Now()
		r.SetReadDeadline(start.Add(3 * time.Second))
		go func() {
			time.Sleep(100 * time.Millisecond)
			r.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
		}()
		_, err := r.Read(make([]byte, 8))
		return errText(err) + fmt.Sprintf(" timely=%v", within(start, 140, 1000))
	case "fdl_shorten_now":
		r, w, _ := os.Pipe()
		defer r.Close()
		defer w.Close()
		start := time.Now()
		go func() {
			time.Sleep(100 * time.Millisecond)
			r.SetDeadline(time.Now().Add(-time.Second))
		}()
		_, err := r.Read(make([]byte, 8))
		return errText(err) + fmt.Sprintf(" timely=%v", within(start, 95, 1000))
	case "fdl_cancel":
		r, w, _ := os.Pipe()
		defer r.Close()
		defer w.Close()
		start := time.Now()
		r.SetReadDeadline(start.Add(250 * time.Millisecond))
		go func() {
			time.Sleep(100 * time.Millisecond)
			r.SetReadDeadline(time.Time{})
			time.Sleep(300 * time.Millisecond)
			w.Write([]byte("z"))
		}()
		n, err := r.Read(make([]byte, 8))
		return fmt.Sprintf("n=%d %s timely=%v", n, errText(err), within(start, 390, 1500))
	case "fdl_close":
		r, w, _ := os.Pipe()
		defer w.Close()
		start := time.Now()
		go func() {
			time.Sleep(100 * time.Millisecond)
			r.Close()
		}()
		_, err := r.Read(make([]byte, 8))
		out := errText(err) + fmt.Sprintf(" timely=%v", within(start, 95, 1000))
		out += " close2=" + errText(r.Close())
		_, err = r.Read(make([]byte, 8))
		out += " read=" + errText(err)
		out += " setdl=" + errText(r.SetDeadline(time.Now().Add(time.Second)))
		_, err = w.Write([]byte("x"))
		out += " wclosedpeer=" + errText(err)
		return out
	case "fdl_pipe_kind":
		// os.Pipe is a real pipe: a FIFO-type file, one direction per end.
		r, w, _ := os.Pipe()
		defer r.Close()
		defer w.Close()
		ri, _ := r.Stat()
		wi, _ := w.Stat()
		_, werr := r.Write([]byte("x"))
		_, rerr := w.Read(make([]byte, 1))
		return fmt.Sprintf("names=%s,%s rmode=%s wmode=%s named_pipe=%v,%v rwrite=%s wread=%s", r.Name(), w.Name(),
			ri.Mode(), wi.Mode(), ri.Mode()&os.ModeNamedPipe != 0, wi.Mode()&os.ModeNamedPipe != 0, errText(werr), errText(rerr))
	case "fdl_write":
		r, w, _ := os.Pipe()
		defer r.Close()
		defer w.Close()
		start := time.Now()
		w.SetWriteDeadline(start.Add(150 * time.Millisecond))
		chunk := make([]byte, 65536)
		var err error
		total := 0
		for err == nil && total < 64<<20 {
			var n int
			n, err = w.Write(chunk)
			total += n
		}
		return errText(err) + fmt.Sprintf(" wrote=%v timely=%v", total > 0, within(start, 145, 1500))
	case "fdl_files":
		var out []string
		for _, name := range []string{"f", "d", "/dev/null", "ff"} {
			file, err := os.OpenFile(name, os.O_RDWR, 0)
			if err != nil {
				file, err = os.Open(name)
			}
			if err != nil {
				out = append(out, name+":"+errText(err))
				continue
			}
			out = append(out, fmt.Sprintf("%s:%s,%s,%s", name,
				errText(file.SetDeadline(time.Now().Add(time.Second))),
				errText(file.SetReadDeadline(time.Now().Add(time.Second))),
				errText(file.SetWriteDeadline(time.Time{}))))
			file.Close()
		}
		return fmt.Sprint(out)
	case "fdl_rw":
		r, w, _ := os.Pipe()
		defer r.Close()
		defer w.Close()
		n, err := w.Write([]byte("hello"))
		out := fmt.Sprintf("w=%d %s", n, errText(err))
		buf := make([]byte, 3)
		n, err = r.Read(buf)
		out += fmt.Sprintf(" r=%d %s %q", n, errText(err), buf[:n])
		w.Close()
		n, err = r.Read(buf)
		out += fmt.Sprintf(" r2=%d %s", n, errText(err))
		n, err = r.Read(buf)
		out += fmt.Sprintf(" eof=%d %v", n, err)
		return out
	}
	return runNet(f)
}
