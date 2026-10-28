package main

// Go oracle for the os/user differential. Build with cgo enabled: the
// libc-backed implementation (getpwuid_r, getgrouplist, ...).

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"os/user"
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

func errText(err error) string { return "err:" + enc(err.Error()) }

func u(u *user.User, err error) string {
	if err != nil {
		return errText(err)
	}
	return strings.Join([]string{enc(u.Uid), enc(u.Gid), enc(u.Username), enc(u.Name), enc(u.HomeDir)}, ",")
}

func main() {
	s := bufio.NewScanner(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for s.Scan() {
		f := strings.Split(s.Text(), "\t")
		arg := ""
		if len(f) > 1 {
			arg = dec(f[1])
		}
		var r string
		switch f[0] {
		case "lookup":
			r = u(user.Lookup(arg))
		case "lookupid":
			r = u(user.LookupId(arg))
		case "group":
			g, err := user.LookupGroup(arg)
			if err != nil {
				r = errText(err)
			} else {
				r = enc(g.Gid) + "," + enc(g.Name)
			}
		case "groupid":
			g, err := user.LookupGroupId(arg)
			if err != nil {
				r = errText(err)
			} else {
				r = enc(g.Gid) + "," + enc(g.Name)
			}
		case "groupids":
			us, err := user.Lookup(arg)
			if err != nil {
				r = errText(err)
				break
			}
			ids, err := us.GroupIds()
			if err != nil {
				r = errText(err)
			} else {
				r = enc(strings.Join(ids, ","))
			}
		case "current":
			r = u(user.Current())
		case "groupidsfor":
			// Synthetic user: name,gid.
			p := strings.SplitN(arg, ",", 2)
			us := &user.User{Username: p[0], Gid: p[1]}
			ids, err := us.GroupIds()
			if err != nil {
				r = errText(err)
			} else {
				r = enc(strings.Join(ids, ","))
			}
		default:
			panic("unknown op")
		}
		fmt.Fprintln(w, f[0]+"|"+r)
	}
}
