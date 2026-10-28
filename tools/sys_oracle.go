// Go side of the rust_stdlib_sys differential (tools/sys_check.py). Reads one
// scenario per line from stdin and prints one observation line per scenario;
// crates/sys/examples/sys_probe.rs implements the same protocol.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return "err " + err.Error()
}

func atoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}

func timeOrZero(sec, nsec string) time.Time {
	if sec == "-" {
		return time.Time{}
	}
	return time.Unix(int64(atoi(sec)), int64(atoi(nsec)))
}

func stat(name string) string {
	fi, err := os.Stat(name)
	if err != nil {
		return errText(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	// Atimespec on macOS, Atim on Linux.
	atime := reflect.ValueOf(st).Elem().FieldByName("Atimespec")
	if !atime.IsValid() {
		atime = reflect.ValueOf(st).Elem().FieldByName("Atim")
	}
	return fmt.Sprintf("mtime=%d.%09d atime=%d.%09d nlink=%d", fi.ModTime().Unix(), fi.ModTime().Nanosecond(), atime.Field(0).Int(), atime.Field(1).Int(), st.Nlink)
}

func sigName(n int) string { return syscall.Signal(n).String() }

func run(f []string) string {
	switch f[0] {
	case "ids":
		return fmt.Sprintf("uid=%d euid=%d gid=%d egid=%d ppid=%d", os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid(), os.Getppid())
	case "groups":
		g, err := os.Getgroups()
		if err != nil {
			return errText(err)
		}
		sort.Ints(g)
		return fmt.Sprint("ok ", g)
	case "hostname":
		h, err := os.Hostname()
		if err != nil {
			return errText(err)
		}
		return "ok " + h
	case "errno":
		return "errno " + f[1] + " " + syscall.Errno(atoi(f[1])).Error()
	case "signal":
		return "signal " + f[1] + " " + sigName(atoi(f[1]))
	case "errnos":
		return fmt.Sprint(int(syscall.EPERM), int(syscall.ENOENT), int(syscall.ESRCH), int(syscall.EINTR), int(syscall.EIO),
			int(syscall.EBADF), int(syscall.EAGAIN), int(syscall.ENOMEM), int(syscall.EACCES), int(syscall.EEXIST), int(syscall.EXDEV),
			int(syscall.ENOTDIR), int(syscall.EISDIR), int(syscall.EINVAL), int(syscall.ENFILE), int(syscall.EMFILE), int(syscall.ENOTTY),
			int(syscall.EPIPE), int(syscall.ENOSYS), int(syscall.ELOOP), int(syscall.ENOTSOCK), int(syscall.EPROTONOSUPPORT),
			int(syscall.EOPNOTSUPP), int(syscall.EAFNOSUPPORT), int(syscall.EADDRINUSE), int(syscall.EADDRNOTAVAIL),
			int(syscall.ENETUNREACH), int(syscall.ECONNABORTED), int(syscall.ECONNRESET), int(syscall.ENOBUFS), int(syscall.EISCONN),
			int(syscall.ENOTCONN), int(syscall.ETIMEDOUT), int(syscall.ECONNREFUSED), int(syscall.EHOSTUNREACH),
			int(syscall.EINPROGRESS), int(syscall.ENOTEMPTY), int(syscall.ENOTSUP), int(syscall.EWOULDBLOCK), int(syscall.EDESTADDRREQ), int(syscall.EALREADY),
			int(syscall.SIGHUP), int(syscall.SIGINT), int(syscall.SIGQUIT), int(syscall.SIGABRT), int(syscall.SIGKILL),
			int(syscall.SIGUSR1), int(syscall.SIGSEGV), int(syscall.SIGUSR2), int(syscall.SIGPIPE), int(syscall.SIGALRM),
			int(syscall.SIGTERM), int(syscall.SIGCHLD), int(syscall.SIGCONT), int(syscall.SIGSTOP))
	case "errno_class":
		e := syscall.Errno(atoi(f[1]))
		return fmt.Sprintf("errno_class %s timeout=%v temporary=%v perm=%v exist=%v notexist=%v unsupported=%v", f[1],
			e.Timeout(), e.Temporary(), e.Is(os.ErrPermission), e.Is(os.ErrExist), e.Is(os.ErrNotExist), e.Is(errors.ErrUnsupported))
	case "chtimes":
		// chtimes name asec ansec msec mnsec ("-" leaves a time unchanged)
		err := os.Chtimes(f[1], timeOrZero(f[2], f[3]), timeOrZero(f[4], f[5]))
		return errText(err) + " " + stat(f[1])
	case "link":
		err := os.Link(f[1], f[2])
		links := ""
		if fi, serr := os.Stat(f[2]); serr == nil {
			links = strconv.Itoa(int(fi.Sys().(*syscall.Stat_t).Nlink))
		}
		return errText(err) + " nlink=" + links
	case "kill":
		var pid int
		switch f[1] {
		case "self":
			pid = os.Getpid()
		case "ppid":
			pid = os.Getppid()
		default:
			pid = atoi(f[1])
		}
		p, err := os.FindProcess(pid)
		if err != nil {
			return errText(err)
		}
		return errText(p.Signal(syscall.Signal(atoi(f[2]))))
	case "child":
		// child sig: start sleep, probe it with signal 0, signal it, wait, signal again.
		cmd := exec.Command("sleep", "30")
		if err := cmd.Start(); err != nil {
			return errText(err)
		}
		out := []string{"zero:" + errText(cmd.Process.Signal(syscall.Signal(0)))}
		out = append(out, "sig:"+errText(cmd.Process.Signal(syscall.Signal(atoi(f[1])))))
		// Signals that do not end the child would leave Wait sleeping.
		if sig := atoi(f[1]); sig != 15 && sig != 9 && sig != 2 {
			cmd.Process.Kill()
		}
		err := cmd.Wait()
		ws := cmd.ProcessState.Sys().(syscall.WaitStatus)
		out = append(out, fmt.Sprintf("signaled=%v signal=%d", ws.Signaled(), int(ws.Signal())))
		_ = err
		out = append(out, "after:"+errText(cmd.Process.Signal(syscall.Signal(0))))
		out = append(out, "kill:"+errText(cmd.Process.Kill()))
		return strings.Join(out, " ")
	}
	return runFile(f)
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	for in.Scan() {
		line := in.Text()
		if line == "" {
			continue
		}
		fmt.Println(run(strings.Split(line, "\t")))
	}
}
