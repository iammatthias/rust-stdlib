// Line-oriented Go oracle for errors, sync, sync/atomic, hash/maphash, unique
// and weak, used by tools/stdsync_check.py. Each request is "<domain> <script>"
// where the script is a ';'-separated list of commands run in order on fresh
// objects; the answer is the space-separated results. Only deterministic,
// non-blocking single-goroutine scripts are used. Panics are reported as the
// token "panic:<message>". examples/stdsync_probe.rs answers the same requests.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"hash/maphash"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unique"
	"weak"
)

func b(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// ---- sync/atomic

type integer interface {
	int32 | int64 | uint32 | uint64 | uintptr
}

type atom[T integer] interface {
	Load() T
	Store(T)
	Swap(T) T
	CompareAndSwap(T, T) bool
	Add(T) T
	And(T) T
	Or(T) T
}

func parse[T integer](s string) T {
	if s[0] == '-' {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			panic(err)
		}
		return T(v)
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		panic(err)
	}
	return T(v)
}

func runAtom[T integer, A any, P interface {
	*A
	atom[T]
}](cmds [][]string) []string {
	var a A
	p := P(&a)
	var out []string
	for _, c := range cmds {
		switch c[0] {
		case "load":
			out = append(out, fmt.Sprint(p.Load()))
		case "store":
			p.Store(parse[T](c[1]))
			out = append(out, "-")
		case "swap":
			out = append(out, fmt.Sprint(p.Swap(parse[T](c[1]))))
		case "cas":
			out = append(out, b(p.CompareAndSwap(parse[T](c[1]), parse[T](c[2]))))
		case "add":
			out = append(out, fmt.Sprint(p.Add(parse[T](c[1]))))
		case "and":
			out = append(out, fmt.Sprint(p.And(parse[T](c[1]))))
		case "or":
			out = append(out, fmt.Sprint(p.Or(parse[T](c[1]))))
		}
	}
	return out
}

func runBool(cmds [][]string) []string {
	var a atomic.Bool
	var out []string
	for _, c := range cmds {
		switch c[0] {
		case "load":
			out = append(out, b(a.Load()))
		case "store":
			a.Store(c[1] == "1")
			out = append(out, "-")
		case "swap":
			out = append(out, b(a.Swap(c[1] == "1")))
		case "cas":
			out = append(out, b(a.CompareAndSwap(c[1] == "1", c[2] == "1")))
		}
	}
	return out
}

// Function forms over plain variables.
func runFuncs32(cmds [][]string) []string {
	var v int32
	var out []string
	for _, c := range cmds {
		switch c[0] {
		case "load":
			out = append(out, fmt.Sprint(atomic.LoadInt32(&v)))
		case "store":
			atomic.StoreInt32(&v, parse[int32](c[1]))
			out = append(out, "-")
		case "swap":
			out = append(out, fmt.Sprint(atomic.SwapInt32(&v, parse[int32](c[1]))))
		case "cas":
			out = append(out, b(atomic.CompareAndSwapInt32(&v, parse[int32](c[1]), parse[int32](c[2]))))
		case "add":
			out = append(out, fmt.Sprint(atomic.AddInt32(&v, parse[int32](c[1]))))
		case "and":
			out = append(out, fmt.Sprint(atomic.AndInt32(&v, parse[int32](c[1]))))
		case "or":
			out = append(out, fmt.Sprint(atomic.OrInt32(&v, parse[int32](c[1]))))
		}
	}
	return out
}

func runFuncs64(cmds [][]string) []string {
	var v uint64
	var out []string
	for _, c := range cmds {
		switch c[0] {
		case "load":
			out = append(out, fmt.Sprint(atomic.LoadUint64(&v)))
		case "store":
			atomic.StoreUint64(&v, parse[uint64](c[1]))
			out = append(out, "-")
		case "swap":
			out = append(out, fmt.Sprint(atomic.SwapUint64(&v, parse[uint64](c[1]))))
		case "cas":
			out = append(out, b(atomic.CompareAndSwapUint64(&v, parse[uint64](c[1]), parse[uint64](c[2]))))
		case "add":
			out = append(out, fmt.Sprint(atomic.AddUint64(&v, parse[uint64](c[1]))))
		case "and":
			out = append(out, fmt.Sprint(atomic.AndUint64(&v, parse[uint64](c[1]))))
		case "or":
			out = append(out, fmt.Sprint(atomic.OrUint64(&v, parse[uint64](c[1]))))
		}
	}
	return out
}

// Value holds ints ("i") or strings ("s").
func runValue(cmds [][]string) []string {
	var v atomic.Value
	var out []string
	val := func(kind, s string) any {
		if kind == "i" {
			n, _ := strconv.Atoi(s)
			return n
		}
		return s
	}
	for _, c := range cmds {
		func() {
			defer func() {
				if r := recover(); r != nil {
					out = append(out, "panic")
				}
			}()
			switch c[0] {
			case "load":
				if x := v.Load(); x == nil {
					out = append(out, "nil")
				} else {
					out = append(out, fmt.Sprint(x))
				}
			case "store":
				v.Store(val(c[1], c[2]))
				out = append(out, "-")
			case "swap":
				if x := v.Swap(val(c[1], c[2])); x == nil {
					out = append(out, "nil")
				} else {
					out = append(out, fmt.Sprint(x))
				}
			case "cas":
				var old any
				if c[1] != "n" {
					old = val(c[1], c[2])
				}
				out = append(out, b(v.CompareAndSwap(old, val(c[3], c[4]))))
			}
		}()
	}
	return out
}

func runPointer(cmds [][]string) []string {
	var p atomic.Pointer[int]
	objs := map[string]*int{}
	get := func(name string) *int {
		if name == "nil" {
			return nil
		}
		if objs[name] == nil {
			n := len(objs)
			objs[name] = &n
		}
		return objs[name]
	}
	show := func(x *int) string {
		if x == nil {
			return "nil"
		}
		for k, v := range objs {
			if v == x {
				return k
			}
		}
		return "?"
	}
	var out []string
	for _, c := range cmds {
		switch c[0] {
		case "load":
			out = append(out, show(p.Load()))
		case "store":
			p.Store(get(c[1]))
			out = append(out, "-")
		case "swap":
			out = append(out, show(p.Swap(get(c[1]))))
		case "cas":
			out = append(out, b(p.CompareAndSwap(get(c[1]), get(c[2]))))
		}
	}
	return out
}

// ---- sync

func catch(f func() string) (out string) {
	defer func() {
		if r := recover(); r != nil {
			out = fmt.Sprintf("panic:%v", r)
		}
	}()
	return f()
}

func runMutex(cmds [][]string) []string {
	var m sync.Mutex
	var rw sync.RWMutex
	var out []string
	for _, c := range cmds {
		switch c[0] {
		case "lock":
			m.Lock()
			out = append(out, "-")
		case "trylock":
			out = append(out, b(m.TryLock()))
		case "unlock":
			m.Unlock()
			out = append(out, "-")
		case "rwlock":
			rw.Lock()
			out = append(out, "-")
		case "rwtrylock":
			out = append(out, b(rw.TryLock()))
		case "rwunlock":
			rw.Unlock()
			out = append(out, "-")
		case "rlock":
			rw.RLock()
			out = append(out, "-")
		case "tryrlock":
			out = append(out, b(rw.TryRLock()))
		case "runlock":
			rw.RUnlock()
			out = append(out, "-")
		case "rlocker":
			l := rw.RLocker()
			l.Lock()
			out = append(out, b(!rw.TryLock()))
			l.Unlock()
			ok := rw.TryLock()
			out = append(out, b(ok))
			if ok {
				rw.Unlock()
			}
		}
	}
	return out
}

func runWaitGroup(cmds [][]string) []string {
	var wg sync.WaitGroup
	var out []string
	n := 0
	for _, c := range cmds {
		out = append(out, catch(func() string {
			switch c[0] {
			case "add":
				d, _ := strconv.Atoi(c[1])
				wg.Add(d)
				n += d
			case "done":
				wg.Done()
				n--
			case "wait":
				if n == 0 {
					wg.Wait()
				}
			case "go":
				ch := make(chan struct{})
				wg.Go(func() { <-ch })
				close(ch)
				wg.Wait()
			}
			return "-"
		}))
	}
	return out
}

func runOnce(cmds [][]string) []string {
	var once sync.Once
	count := 0
	var out []string
	for _, c := range cmds {
		out = append(out, catch(func() string {
			switch c[0] {
			case "do":
				once.Do(func() { count++ })
			case "dopanic":
				once.Do(func() { count++; panic("boom") })
			case "count":
				return strconv.Itoa(count)
			}
			return "-"
		}))
	}
	return out
}

func runOnceFuncs(cmds [][]string) []string {
	calls := 0
	f := sync.OnceFunc(func() { calls++ })
	v := sync.OnceValue(func() int { calls++; return calls * 10 })
	vs := sync.OnceValues(func() (int, string) { calls++; return calls, "x" })
	pf := sync.OnceFunc(func() { calls++; panic("pf") })
	pv := sync.OnceValue(func() int { calls++; panic("pv") })
	var out []string
	for _, c := range cmds {
		out = append(out, catch(func() string {
			switch c[0] {
			case "f":
				f()
			case "v":
				return strconv.Itoa(v())
			case "vs":
				a, s := vs()
				return fmt.Sprintf("%d %s", a, s)
			case "pf":
				pf()
			case "pv":
				return strconv.Itoa(pv())
			case "calls":
				return strconv.Itoa(calls)
			}
			return "-"
		}))
	}
	return out
}

func runMap(cmds [][]string) []string {
	var m sync.Map
	var out []string
	show := func(v any, ok bool) string {
		if !ok {
			return "none"
		}
		return fmt.Sprint(v)
	}
	for _, c := range cmds {
		switch c[0] {
		case "store":
			m.Store(c[1], c[2])
			out = append(out, "-")
		case "load":
			v, ok := m.Load(c[1])
			out = append(out, show(v, ok))
		case "loadorstore":
			v, loaded := m.LoadOrStore(c[1], c[2])
			out = append(out, fmt.Sprintf("%v %s", v, b(loaded)))
		case "loadanddelete":
			v, loaded := m.LoadAndDelete(c[1])
			out = append(out, show(v, loaded))
		case "delete":
			m.Delete(c[1])
			out = append(out, "-")
		case "swap":
			v, loaded := m.Swap(c[1], c[2])
			out = append(out, show(v, loaded))
		case "cas":
			out = append(out, b(m.CompareAndSwap(c[1], c[2], c[3])))
		case "cad":
			out = append(out, b(m.CompareAndDelete(c[1], c[2])))
		case "clear":
			m.Clear()
			out = append(out, "-")
		case "range":
			var items []string
			m.Range(func(k, v any) bool {
				items = append(items, fmt.Sprint(k, "=", v))
				return true
			})
			sort.Strings(items)
			out = append(out, "["+strings.Join(items, ",")+"]")
		case "rangestop":
			n := 0
			m.Range(func(k, v any) bool { n++; return false })
			out = append(out, strconv.Itoa(n))
		}
	}
	return out
}

func runPool(cmds [][]string) []string {
	n := 0
	withNew := sync.Pool{New: func() any { n++; return "new" + strconv.Itoa(n) }}
	var plain sync.Pool
	var out []string
	for _, c := range cmds {
		switch c[0] {
		case "put":
			withNew.Put(c[1])
			plain.Put(c[1])
			out = append(out, "-")
		case "get":
			out = append(out, fmt.Sprint(withNew.Get()))
		case "getplain":
			v := plain.Get()
			if v == nil {
				out = append(out, "nil")
			} else {
				out = append(out, fmt.Sprint(v))
			}
		}
	}
	return out
}

func runCond() []string {
	var mu sync.Mutex
	c := sync.NewCond(&mu)
	c.Signal()
	c.Broadcast()
	return []string{b(c.L == &mu)}
}

// ---- errors

type W struct {
	msg string
	err error
}

func (w *W) Error() string { return "w(" + w.msg + ")" }
func (w *W) Unwrap() error { return w.err }

type parser struct {
	s      string
	i      int
	leaves map[int]error
}

func (p *parser) expr() error {
	switch {
	case p.s[p.i] == 'N':
		p.i++
		return nil
	case p.s[p.i] == 'L':
		p.i++
		j := p.i
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
		}
		k, _ := strconv.Atoi(p.s[j:p.i])
		if p.leaves[k] == nil {
			p.leaves[k] = errors.New("e" + strconv.Itoa(k))
		}
		return p.leaves[k]
	case p.s[p.i] == 'W':
		p.i += 2
		e := p.expr()
		p.i++
		return &W{msg: fmt.Sprint(e), err: e}
	default: // J(a,b,...)
		p.i += 2
		var errs []error
		for {
			errs = append(errs, p.expr())
			if p.s[p.i] == ',' {
				p.i++
				continue
			}
			p.i++
			return errors.Join(errs...)
		}
	}
}

func runErrors(script string) []string {
	p := &parser{s: script, leaves: map[int]error{}}
	root := p.expr()
	var out []string
	if root == nil {
		out = append(out, "nil")
	} else {
		out = append(out, strings.ReplaceAll(root.Error(), "\n", "|"))
	}
	var ks []int
	for k := range p.leaves {
		ks = append(ks, k)
	}
	sort.Ints(ks)
	for _, k := range ks {
		out = append(out, b(errors.Is(root, p.leaves[k])))
	}
	other := errors.New("other")
	out = append(out, b(errors.Is(root, other)), b(errors.Is(root, nil)), b(errors.Is(nil, nil)))
	var w *W
	if errors.As(root, &w) {
		out = append(out, strings.ReplaceAll(w.Error(), "\n", "|"))
	} else {
		out = append(out, "noas")
	}
	if g, ok := errors.AsType[*W](root); ok {
		out = append(out, strings.ReplaceAll(g.Error(), "\n", "|"))
	} else {
		out = append(out, "noastype")
	}
	if u := errors.Unwrap(root); u == nil {
		out = append(out, "nounwrap")
	} else {
		out = append(out, strings.ReplaceAll(u.Error(), "\n", "|"))
	}
	out = append(out, b(errors.Is(errors.ErrUnsupported, errors.ErrUnsupported)), errors.ErrUnsupported.Error())
	return out
}

// ---- hash/maphash properties

func runMaphash(script string) []string {
	// script: hex bytes, then chunk sizes after ':'
	parts := strings.Split(script, ":")
	var data []byte
	for i := 0; i+1 < len(parts[0]); i += 2 {
		v, _ := strconv.ParseUint(parts[0][i:i+2], 16, 8)
		data = append(data, byte(v))
	}
	var chunks []int
	for _, f := range strings.Fields(parts[1]) {
		n, _ := strconv.Atoi(f)
		chunks = append(chunks, n)
	}
	seed := maphash.MakeSeed()
	seed2 := maphash.MakeSeed()
	var out []string
	var h maphash.Hash
	h.SetSeed(seed)
	h.Write(data)
	oneShot := h.Sum64()
	out = append(out, b(oneShot == maphash.Bytes(seed, data)))
	out = append(out, b(maphash.String(seed, string(data)) == maphash.Bytes(seed, data)))
	// chunked writes with a mix of Write, WriteString, WriteByte
	var h2 maphash.Hash
	h2.SetSeed(seed)
	rest := data
	for i, n := range chunks {
		if n > len(rest) {
			n = len(rest)
		}
		piece := rest[:n]
		rest = rest[n:]
		switch i % 3 {
		case 0:
			h2.Write(piece)
		case 1:
			h2.WriteString(string(piece))
		default:
			for _, c := range piece {
				h2.WriteByte(c)
			}
		}
	}
	h2.Write(rest)
	out = append(out, b(h2.Sum64() == oneShot))
	h2.Reset()
	h2.Write(data)
	out = append(out, b(h2.Sum64() == oneShot))
	out = append(out, b(h.Seed() == seed))
	prefix := []byte("pre")
	sum := h.Sum(prefix)
	var le uint64
	for i := 0; i < 8; i++ {
		le |= uint64(sum[3+i]) << (8 * i)
	}
	out = append(out, b(len(sum) == 11 && string(sum[:3]) == "pre" && le == oneShot))
	out = append(out, b(h.Size() == 8 && h.BlockSize() == 128))
	out = append(out, b(maphash.Bytes(seed2, data) != maphash.Bytes(seed, data)))
	out = append(out, b(maphash.Bytes(seed, append(append([]byte{}, data...), 0)) != oneShot))
	c := h
	out = append(out, b(c.Sum64() == oneShot))
	c.WriteString("more")
	out = append(out, b(c.Sum64() != oneShot && h.Sum64() == oneShot))
	// comparable
	n := len(data)
	var h3 maphash.Hash
	h3.SetSeed(seed)
	maphash.WriteComparable(&h3, n)
	out = append(out, b(maphash.Comparable(seed, n) == h3.Sum64() && maphash.Comparable(seed, n) == maphash.Comparable(seed, len(data))))
	s := string(data)
	out = append(out, b(maphash.Comparable(seed, s) == maphash.Comparable(seed, string(data))))
	out = append(out, catch(func() string {
		var z maphash.Hash
		z.SetSeed(maphash.Seed{})
		return "no"
	}))
	hasher := maphash.ComparableHasher[string]{}
	var h4 maphash.Hash
	h4.SetSeed(seed)
	hasher.Hash(&h4, s)
	var h5 maphash.Hash
	h5.SetSeed(seed)
	hasher.Hash(&h5, string(data))
	out = append(out, b(h4.Sum64() == h5.Sum64() && hasher.Equal(s, string(data)) && !hasher.Equal(s, s+"x")))
	return out
}

// ---- unique and weak

func runUnique(cmds [][]string) []string {
	var hs []unique.Handle[string]
	var is []unique.Handle[int]
	var out []string
	for _, c := range cmds {
		switch c[0] {
		case "s":
			hs = append(hs, unique.Make(c[1]))
		case "i":
			n, _ := strconv.Atoi(c[1])
			is = append(is, unique.Make(n))
		}
	}
	for i := range hs {
		out = append(out, hs[i].Value())
		for j := range hs {
			out = append(out, b(hs[i] == hs[j]))
		}
	}
	for i := range is {
		out = append(out, strconv.Itoa(is[i].Value()))
		for j := range is {
			out = append(out, b(is[i] == is[j]))
		}
	}
	return out
}

func runWeak() []string {
	x, y := new(int), new(int)
	*x, *y = 1, 2
	w1, w2, w3 := weak.Make(x), weak.Make(x), weak.Make(y)
	var nilw weak.Pointer[int]
	out := []string{b(w1 == w2), b(w1 == w3), b(w1.Value() == x), b(w3.Value() == y), b(nilw.Value() == nil),
		b(weak.Make[int](nil) == nilw)}
	return out
}

func cmdsOf(script string) [][]string {
	var cmds [][]string
	for _, c := range strings.Split(script, ";") {
		if f := strings.Fields(c); len(f) > 0 {
			cmds = append(cmds, f)
		}
	}
	return cmds
}

func answer(line string) string {
	domain, script, _ := strings.Cut(line, " ")
	cmds := cmdsOf(script)
	var out []string
	switch domain {
	case "i32":
		out = runAtom[int32, atomic.Int32](cmds)
	case "i64":
		out = runAtom[int64, atomic.Int64](cmds)
	case "u32":
		out = runAtom[uint32, atomic.Uint32](cmds)
	case "u64":
		out = runAtom[uint64, atomic.Uint64](cmds)
	case "up":
		out = runAtom[uintptr, atomic.Uintptr](cmds)
	case "bool":
		out = runBool(cmds)
	case "f32":
		out = runFuncs32(cmds)
	case "f64":
		out = runFuncs64(cmds)
	case "value":
		out = runValue(cmds)
	case "pointer":
		out = runPointer(cmds)
	case "mutex":
		out = runMutex(cmds)
	case "wg":
		out = runWaitGroup(cmds)
	case "once":
		out = runOnce(cmds)
	case "oncefunc":
		out = runOnceFuncs(cmds)
	case "map":
		out = runMap(cmds)
	case "pool":
		out = runPool(cmds)
	case "cond":
		out = runCond()
	case "errors":
		out = runErrors(script)
	case "maphash":
		out = runMaphash(script)
	case "unique":
		out = runUnique(cmds)
	case "weak":
		out = runWeak()
	default:
		return "unknown domain " + domain
	}
	return strings.Join(out, " ")
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<20)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		fmt.Fprintln(out, answer(in.Text()))
	}
}
