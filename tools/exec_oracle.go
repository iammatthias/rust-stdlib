package main

// Go oracle for the os/exec differential (tools/exec_check.py).

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"syscall"
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

func errText(err error) string {
	if err == nil {
		return "-"
	}
	return enc(err.Error())
}

// perr is a Process error with how errors.Is classifies it: D for
// os.ErrProcessDone, I for syscall.EINVAL, C for syscall.ECHILD.
func perr(err error) string {
	if err == nil {
		return "-"
	}
	flags := ""
	if errors.Is(err, os.ErrProcessDone) {
		flags += "D"
	}
	if errors.Is(err, syscall.EINVAL) {
		flags += "I"
	}
	if errors.Is(err, syscall.ECHILD) {
		flags += "C"
	}
	return enc(err.Error() + "/" + flags)
}

func withHandle(p *os.Process) string {
	if err := p.WithHandle(func(h uintptr) {}); err != nil {
		return err.Error()
	}
	return "ok"
}

func classes(err error) string {
	var b strings.Builder
	var ee *exec.ExitError
	var e *exec.Error
	if errors.As(err, &ee) {
		b.WriteString("X")
	}
	if errors.As(err, &e) {
		b.WriteString("E")
	}
	if errors.Is(err, exec.ErrNotFound) {
		b.WriteString("N")
	}
	if errors.Is(err, exec.ErrDot) {
		b.WriteString("D")
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		b.WriteString("W")
	}
	if errors.Is(err, os.ErrNotExist) {
		b.WriteString("n")
	}
	if errors.Is(err, os.ErrPermission) {
		b.WriteString("p")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		b.WriteString("T")
	}
	return b.String()
}

func state(c *exec.Cmd) string {
	if c.ProcessState == nil {
		return "-"
	}
	s := c.ProcessState
	return fmt.Sprintf("%s;%d;%t;%t", enc(s.String()), s.ExitCode(), s.Success(), s.Exited())
}

func main() {
	s := bufio.NewScanner(os.Stdin)
	s.Buffer(make([]byte, 1<<16), 1<<24)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		f := strings.Split(s.Text(), "\t")
		mode := f[0]
		get := func(i int) string {
			if i < len(f) {
				return dec(f[i])
			}
			return ""
		}
		switch mode {
		case "setenv":
			os.Setenv(get(1), get(2))
			fmt.Fprintln(w, "setenv|ok")
			continue
		case "chdir":
			err := os.Chdir(get(1))
			fmt.Fprintln(w, "chdir|"+errText(err))
			continue
		case "lookpath":
			p, err := exec.LookPath(get(1))
			fmt.Fprintf(w, "lookpath|%s|%s|%s\n", enc(p), errText(err), classes(err))
			continue
		}
		name := get(1)
		var args []string
		if a := get(2); a != "" {
			args = strings.Split(a, "\x1f")
		}
		var env []string
		envSet := f[3] != "NIL"
		if envSet {
			if e := get(3); e != "" {
				env = strings.Split(e, "\x1f")
			} else {
				env = []string{}
			}
		}
		dir := get(4)
		stdin := get(5)
		timeoutMs, _ := strconv.Atoi(get(6))
		waitDelayMs, _ := strconv.Atoi(get(7))

		if mode == "procattr" {
			// os.StartProcess with stdin from the null device, stdout and
			// stderr into one pipe, and the named files at descriptors 3, 4, ...
			// ("-" is a nil entry: closed in the child).
			null, _ := os.Open(os.DevNull)
			pr, pw, _ := os.Pipe()
			files := []*os.File{null, pw, pw}
			for _, n := range strings.Split(stdin, ",") {
				if n == "" {
					continue
				}
				if n == "-" {
					files = append(files, nil)
					continue
				}
				fh, err := os.Open(n)
				if err != nil {
					panic(err)
				}
				files = append(files, fh)
			}
			argv := append([]string{name}, args...)
			p, err := os.StartProcess(name, argv, &os.ProcAttr{Dir: dir, Env: []string{"PATH=/usr/bin:/bin"}, Files: files})
			if err != nil {
				pw.Close()
				fmt.Fprintf(w, "procattr||%s\n", enc(err.Error()))
				continue
			}
			pw.Close()
			data, _ := io.ReadAll(pr)
			st, werr := p.Wait()
			text := ""
			if werr != nil {
				text = werr.Error()
			} else {
				text = st.String()
			}
			fmt.Fprintf(w, "procattr|%s|%s\n", hex.EncodeToString(data), enc(text))
			continue
		}
		if mode == "handle" {
			argv := append([]string{name}, args...)
			p, err := os.StartProcess(name, argv, &os.ProcAttr{Env: []string{"PATH=/usr/bin:/bin"}, Files: []*os.File{nil, nil, nil}})
			if err != nil {
				panic(err)
			}
			seen := false
			before := "ok:true"
			if err := p.WithHandle(func(h uintptr) { seen = true }); err != nil {
				before = err.Error()
			} else if !seen {
				before = "ok:false"
			}
			p.Wait()
			after := withHandle(p)
			// Wait again, signal, then Release after Wait. Go's pidfd path
			// checks the status before the pid and its pid path the pid first.
			_, werr := p.Wait()
			sig := p.Signal(os.Kill)
			p.Release()
			sig2 := p.Signal(os.Kill)
			fmt.Fprintf(w, "handle|%s|%s|%s|%s|%s|%s\n", enc(before), enc(after), perr(werr), perr(sig), perr(sig2), enc(withHandle(p)))
			continue
		}
		if mode == "released" {
			// Release before Wait. Wait is the bare EINVAL, and Signal, Kill and
			// WithHandle report "already released". The child stays a zombie.
			argv := append([]string{name}, args...)
			p, err := os.StartProcess(name, argv, &os.ProcAttr{Env: []string{"PATH=/usr/bin:/bin"}, Files: []*os.File{nil, nil, nil}})
			if err != nil {
				panic(err)
			}
			p.Release()
			_, werr := p.Wait()
			fmt.Fprintf(w, "released|%s|%s|%s|%s\n", enc(withHandle(p)), perr(werr), perr(p.Signal(os.Kill)), perr(p.Kill()))
			continue
		}

		var cmd *exec.Cmd
		if timeoutMs > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
			defer cancel()
			cmd = exec.CommandContext(ctx, name, args...)
		} else {
			cmd = exec.Command(name, args...)
		}
		if envSet {
			cmd.Env = env
		}
		cmd.Dir = dir
		cmd.WaitDelay = time.Duration(waitDelayMs) * time.Millisecond
		var out, errb bytes.Buffer
		var stdout, stderr string
		var err error
		extra := "-"
		switch mode {
		case "run":
			if stdin != "" {
				cmd.Stdin = strings.NewReader(stdin)
			}
			cmd.Stdout = &out
			cmd.Stderr = &errb
			err = cmd.Run()
			stdout, stderr = hex.EncodeToString(out.Bytes()), hex.EncodeToString(errb.Bytes())
		case "extra":
			// ExtraFiles: the comma separated files become descriptors 3, 4, ...
			for _, n := range strings.Split(stdin, ",") {
				if n == "" {
					continue
				}
				fh, err := os.Open(n)
				if err != nil {
					panic(err)
				}
				cmd.ExtraFiles = append(cmd.ExtraFiles, fh)
			}
			cmd.Stdout = &out
			cmd.Stderr = &errb
			err = cmd.Run()
			stdout, stderr = hex.EncodeToString(out.Bytes()), hex.EncodeToString(errb.Bytes())
		case "output":
			if stdin != "" {
				cmd.Stdin = strings.NewReader(stdin)
			}
			var o []byte
			o, err = cmd.Output()
			stdout = hex.EncodeToString(o)
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				extra = hex.EncodeToString(ee.Stderr)
			}
		case "combined":
			if stdin != "" {
				cmd.Stdin = strings.NewReader(stdin)
			}
			var o []byte
			o, err = cmd.CombinedOutput()
			stdout = hex.EncodeToString(o)
		case "same":
			// Stdout and Stderr are the same writer.
			cmd.Stdout = &out
			cmd.Stderr = &out
			err = cmd.Run()
			stdout = hex.EncodeToString(out.Bytes())
		case "pipes":
			var so, se io.ReadCloser
			so, err = cmd.StdoutPipe()
			if err == nil {
				se, err = cmd.StderrPipe()
			}
			if err == nil {
				err = cmd.Start()
			}
			if err == nil {
				ob, _ := io.ReadAll(so)
				eb, _ := io.ReadAll(se)
				stdout, stderr = hex.EncodeToString(ob), hex.EncodeToString(eb)
				err = cmd.Wait()
			}
		case "pipesafter":
			// Wait closes the parent's pipe ends: later I/O reports a closed file.
			var wc io.WriteCloser
			var so, se io.ReadCloser
			wc, err = cmd.StdinPipe()
			if err == nil {
				so, err = cmd.StdoutPipe()
			}
			if err == nil {
				se, err = cmd.StderrPipe()
			}
			if err == nil {
				err = cmd.Start()
			}
			if err == nil {
				wc.Write([]byte(stdin))
				wc.Close()
				ob, _ := io.ReadAll(so)
				eb, _ := io.ReadAll(se)
				stdout, stderr = hex.EncodeToString(ob), hex.EncodeToString(eb)
				err = cmd.Wait()
				_, e1 := so.Read(make([]byte, 1))
				_, e2 := se.Read(make([]byte, 1))
				_, e3 := wc.Write([]byte("x"))
				e4 := wc.Close()
				e5 := so.Close()
				e6 := se.Close()
				extra = enc(strings.Join([]string{errText(e1), errText(e2), errText(e3), errText(e4), errText(e5), errText(e6)}, ";"))
			}
		case "stdinpipe":
			var wc io.WriteCloser
			wc, err = cmd.StdinPipe()
			if err == nil {
				cmd.Stdout = &out
				err = cmd.Start()
			}
			if err == nil {
				wc.Write([]byte(stdin))
				wc.Close()
				err = cmd.Wait()
			}
			stdout = hex.EncodeToString(out.Bytes())
		case "environ":
			e := cmd.Environ()
			var keep []string
			for _, kv := range e {
				if strings.HasPrefix(kv, "RS_") || strings.HasPrefix(kv, "PWD=") {
					keep = append(keep, kv)
				}
			}
			sort.Strings(keep)
			stdout = enc(strings.Join(keep, "\n"))
		case "twice":
			cmd.Stdout = &out
			err1 := cmd.Start()
			err2 := cmd.Start()
			err3 := cmd.Wait()
			err4 := cmd.Wait()
			err = fmt.Errorf("%s|%s|%s|%s", errText(err1), errText(err2), errText(err3), errText(err4))
			stdout = hex.EncodeToString(out.Bytes())
		case "waitfirst":
			err = cmd.Wait()
		case "string":
			stdout = enc(cmd.String())
		case "pathargs":
			stdout = enc(cmd.Path + "|" + strings.Join(cmd.Args, " ") + "|" + errText(cmd.Err))
		default:
			panic("unknown mode " + mode)
		}
		fmt.Fprintf(w, "%s|%s|%s|%s|%s|%s|%s|%s|%s\n", mode, stdout, stderr, errText(err), classes(err), state(cmd), enc(cmd.String()), extra, "")
	}
}
