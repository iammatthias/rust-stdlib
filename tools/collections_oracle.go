// Go oracle for tools/collections_check.py: sort, slices, maps, cmp, iter and
// container/{heap,list,ring}. One request per stdin line, one response per line.
//go:build ignore

package main

import (
	"bufio"
	"cmp"
	"container/heap"
	"container/list"
	"container/ring"
	"fmt"
	"iter"
	"maps"
	"math"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
)

type rec struct{ k, id int }
type recs []rec

func (r recs) Len() int           { return len(r) }
func (r recs) Less(i, j int) bool { return r[i].k < r[j].k }
func (r recs) Swap(i, j int)      { r[i], r[j] = r[j], r[i] }

func ints(f []string) []int {
	out := []int{}
	for _, s := range f {
		v, err := strconv.Atoi(s)
		if err != nil {
			panic(err)
		}
		out = append(out, v)
	}
	return out
}

func floats(f []string) []float64 {
	out := []float64{}
	for _, s := range f {
		v, err := strconv.ParseUint(s, 16, 64)
		if err != nil {
			panic(err)
		}
		out = append(out, math.Float64frombits(v))
	}
	return out
}

func join[T any](v []T) string {
	p := make([]string, len(v))
	for i, x := range v {
		p[i] = fmt.Sprint(x)
	}
	return strings.Join(p, ",")
}

func b2s(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func doSort(f []string) string {
	algo := f[0]
	keys := ints(f[1:])
	rs := make(recs, len(keys))
	for i, k := range keys {
		rs[i] = rec{k, i}
	}
	pre := b2s(sort.IsSorted(rs)) + b2s(sort.SliceIsSorted(rs, func(i, j int) bool { return rs[i].k < rs[j].k })) +
		b2s(slices.IsSortedFunc(rs, func(a, b rec) int { return cmp.Compare(a.k, b.k) })) + b2s(slices.IsSorted(keys)) +
		b2s(sort.IntsAreSorted(keys))
	stable := false
	switch algo {
	case "sort":
		sort.Sort(rs)
	case "rsort":
		sort.Sort(sort.Reverse(rs))
	case "stable":
		sort.Stable(rs)
		stable = true
	case "rstable":
		sort.Stable(sort.Reverse(rs))
		stable = true
	case "slice":
		sort.Slice(rs, func(i, j int) bool { return rs[i].k < rs[j].k })
	case "slicestable":
		sort.SliceStable(rs, func(i, j int) bool { return rs[i].k < rs[j].k })
		stable = true
	case "sortfunc":
		slices.SortFunc(rs, func(a, b rec) int { return cmp.Compare(a.k, b.k) })
	case "sortstablefunc":
		slices.SortStableFunc(rs, func(a, b rec) int { return cmp.Compare(a.k, b.k) })
		stable = true
	case "sorted":
		out := slices.Sorted(slices.Values(keys))
		return pre + " " + join(out)
	case "ints":
		sort.Ints(keys)
		return pre + " " + join(keys)
	case "intslice":
		sort.IntSlice(keys).Sort()
		return pre + " " + join(keys)
	case "strings":
		ss := make([]string, len(keys))
		for i, k := range keys {
			ss[i] = fmt.Sprint(k)
		}
		sort.Strings(ss)
		a := slices.Clone(ss)
		sort.StringSlice(a).Sort()
		return pre + " " + join(ss) + " " + b2s(sort.StringsAreSorted(ss)) + b2s(slices.Equal(a, ss))
	}
	if stable {
		ids := make([]int, len(rs))
		for i, r := range rs {
			ids[i] = r.id
		}
		return pre + " " + join(ids)
	}
	ks := make([]int, len(rs))
	byID := make([]int, len(rs))
	for i, r := range rs {
		ks[i] = r.k
		byID[r.id] = r.k
	}
	return pre + " " + join(ks) + " " + join(byID)
}

func fnorm(f float64) string {
	if f != f {
		return "n"
	}
	if f == 0 {
		return "0"
	}
	return strconv.FormatUint(math.Float64bits(f), 16)
}

func doFSort(f []string) string {
	fs := floats(f)
	a := slices.Clone(fs)
	b := slices.Clone(fs)
	pre := b2s(slices.IsSorted(fs)) + b2s(sort.Float64sAreSorted(fs))
	slices.Sort(a)
	sort.Float64s(b)
	norm := func(v []float64) string {
		p := make([]string, len(v))
		for i, x := range v {
			p[i] = fnorm(x)
		}
		return strings.Join(p, ",")
	}
	raw := make([]uint64, len(a))
	for i, x := range a {
		raw[i] = math.Float64bits(x)
	}
	slices.Sort(raw)
	rp := make([]string, len(raw))
	for i, x := range raw {
		rp[i] = strconv.FormatUint(x, 16)
	}
	c := slices.Clone(fs)
	sort.Sort(sort.Float64Slice(c))
	d := slices.Clone(fs)
	sort.Float64Slice(d).Sort()
	return pre + " " + norm(a) + " " + norm(b) + " " + norm(c) + " " + norm(d) + " " + strings.Join(rp, ",")
}

func doFSearch(f []string) string {
	fs := floats(f)
	t, a := fs[0], fs[1:]
	i, found := slices.BinarySearch(a, t)
	j, found2 := slices.BinarySearchFunc(a, t, func(e, t float64) int { return cmp.Compare(e, t) })
	return fmt.Sprintf("%d,%s %d %d,%s %d", i, b2s(found), sort.SearchFloat64s(a, t), j, b2s(found2),
		sort.Float64Slice(a).Search(t))
}

func doISearch(f []string) string {
	v := ints(f)
	t, a := v[0], v[1:]
	i, found := slices.BinarySearch(a, t)
	k, kf := sort.Find(len(a), func(i int) int { return cmp.Compare(t, a[i]) })
	j, jf := slices.BinarySearchFunc(a, t, func(e, t int) int { return cmp.Compare(e, t) })
	s := make([]string, len(a))
	for i, x := range a {
		s[i] = fmt.Sprint(x)
	}
	ss := sort.SearchStrings(s, fmt.Sprint(t))
	return fmt.Sprintf("%d,%s %d %d,%s %d,%s %d %d", i, b2s(found), sort.SearchInts(a, t), k, b2s(kf), j, b2s(jf),
		sort.IntSlice(a).Search(t), ss) + fmt.Sprintf(" %d", sort.Search(len(a), func(i int) bool { return a[i] >= t }))
}

func doSL(line string) string {
	parts := strings.Split(line, ";")
	head := strings.Fields(parts[0])
	op := head[0]
	p := ints(head[1:])
	a := ints(strings.Fields(parts[1]))
	b := []int{}
	if len(parts) > 2 {
		b = ints(strings.Fields(parts[2]))
	}
	eq := func(x, y int) bool { return x-y <= 1 && y-x <= 1 }
	switch op {
	case "compact":
		return join(slices.Compact(a))
	case "compactfunc":
		return join(slices.CompactFunc(a, eq))
	case "delete":
		return join(slices.Delete(a, p[0], p[1]))
	case "deletefunc":
		n := 0
		r := slices.DeleteFunc(a, func(x int) bool { n++; return x%3 == 0 })
		return join(r) + " " + fmt.Sprint(n)
	case "insert":
		return join(slices.Insert(a, p[0], b...))
	case "replace":
		return join(slices.Replace(a, p[0], p[1], b...))
	case "reverse":
		slices.Reverse(a)
		return join(a)
	case "index":
		return fmt.Sprint(slices.Index(a, p[0]), slices.IndexFunc(a, func(x int) bool { return x > p[0] }),
			slices.Contains(a, p[0]), slices.ContainsFunc(a, func(x int) bool { return x > p[0] }))
	case "repeat":
		return join(slices.Repeat(a, p[0]))
	case "chunk":
		var out []string
		for c := range slices.Chunk(a, p[0]) {
			out = append(out, join(c))
		}
		return strings.Join(out, "|")
	case "compare":
		return fmt.Sprint(slices.Compare(a, b), slices.CompareFunc(a, b, func(x, y int) int { return cmp.Compare(y, x) }),
			slices.Equal(a, b), slices.EqualFunc(a, b, eq))
	case "concat":
		return join(slices.Concat(a, b, a))
	case "minmax":
		return fmt.Sprint(slices.Min(a), slices.Max(a),
			slices.MinFunc(a, func(x, y int) int { return cmp.Compare(x%5, y%5) }),
			slices.MaxFunc(a, func(x, y int) int { return cmp.Compare(x%5, y%5) }))
	case "backward":
		var out []string
		for i, v := range slices.Backward(a) {
			out = append(out, fmt.Sprintf("%d:%d", i, v))
		}
		return strings.Join(out, ",") + " " + join(slices.AppendSeq(b, slices.Values(a)))
	}
	panic("bad SL op " + op)
}

func doFMM(f []string) string {
	fs := floats(f)
	bits := func(f float64) string {
		if f != f {
			return "n" // NaN payloads are not preserved by min/max
		}
		return strconv.FormatUint(math.Float64bits(f), 16)
	}
	return bits(slices.Min(fs)) + " " + bits(slices.Max(fs))
}

func doCmp(f []string) string {
	v := floats(f)
	x, y := v[0], v[1]
	xi, yi := int(int8(math.Float64bits(x))), int(int8(math.Float64bits(y)))
	return fmt.Sprint(cmp.Compare(x, y), cmp.Less(x, y), cmp.Compare(xi, yi), cmp.Or(xi, yi, 7))
}

func mapStr(m map[int]int) string {
	ks := slices.Sorted(maps.Keys(m))
	p := make([]string, len(ks))
	for i, k := range ks {
		p[i] = fmt.Sprintf("%d:%d", k, m[k])
	}
	return strings.Join(p, ",")
}

func parseMap(s string) map[int]int {
	m := map[int]int{}
	for _, kv := range strings.Fields(s) {
		p := strings.Split(kv, ":")
		k, _ := strconv.Atoi(p[0])
		v, _ := strconv.Atoi(p[1])
		m[k] = v
	}
	return m
}

func doMap(line string) string {
	parts := strings.Split(line, ";")
	m1, m2 := parseMap(parts[0]), parseMap(parts[1])
	vs := slices.Sorted(maps.Values(m1))
	c := maps.Clone(m1)
	maps.Copy(c, m2)
	d := maps.Clone(m1)
	maps.DeleteFunc(d, func(k, v int) bool { return (k+v)%2 == 1 })
	e := maps.Collect(maps.All(m1))
	maps.Insert(e, maps.All(m2))
	return fmt.Sprint(maps.Equal(m1, m2), maps.EqualFunc(m1, m2, func(a, b int) bool { return a%3 == b%3 })) +
		" " + join(vs) + " " + mapStr(c) + " " + mapStr(d) + " " + mapStr(e) + " " + mapStr(m1)
}

func doPull(f []string) string {
	v := ints(f)
	stopAt := v[0]
	next, stop := iter.Pull(slices.Values(v[1:]))
	var out []string
	for i := 0; i < len(v)+1; i++ {
		if i == stopAt {
			stop()
			stop()
		}
		x, ok := next()
		out = append(out, fmt.Sprintf("%d%s", x, b2s(ok)))
	}
	n2, s2 := iter.Pull2(slices.All(v[1:]))
	defer s2()
	i, x, ok := n2()
	return strings.Join(out, ",") + fmt.Sprintf(" %d,%d,%s", i, x, b2s(ok))
}

// ---- heap ----

type hp struct{ r recs }

func (h *hp) Len() int           { return len(h.r) }
func (h *hp) Less(i, j int) bool { return h.r[i].k < h.r[j].k }
func (h *hp) Swap(i, j int)      { h.r[i], h.r[j] = h.r[j], h.r[i] }
func (h *hp) Push(x any)         { h.r = append(h.r, x.(rec)) }
func (h *hp) Pop() any {
	n := len(h.r) - 1
	x := h.r[n]
	h.r = h.r[:n]
	return x
}

func (h *hp) dump() string {
	p := make([]string, len(h.r))
	for i, r := range h.r {
		p[i] = fmt.Sprintf("%d.%d", r.k, r.id)
	}
	return strings.Join(p, ",")
}

func doHeap(line string) string {
	h := &hp{}
	next := 0
	var out []string
	for _, op := range strings.Split(line, ";") {
		f := strings.Fields(op)
		if len(f) == 0 {
			continue
		}
		v := ints(f[1:])
		res := ""
		switch f[0] {
		case "init":
			h.r = nil
			for _, k := range v {
				h.r = append(h.r, rec{k, next})
				next++
			}
			heap.Init(h)
		case "push":
			heap.Push(h, rec{v[0], next})
			next++
		case "pop":
			r := heap.Pop(h).(rec)
			res = fmt.Sprintf("=%d.%d", r.k, r.id)
		case "remove":
			r := heap.Remove(h, v[0]).(rec)
			res = fmt.Sprintf("=%d.%d", r.k, r.id)
		case "fix":
			h.r[v[0]].k = v[1]
			heap.Fix(h, v[0])
		}
		out = append(out, f[0]+res+"["+h.dump()+"]")
	}
	return strings.Join(out, " ")
}

// ---- list ----

func listStr(l *list.List) string {
	var f, b []string
	for e := l.Front(); e != nil; e = e.Next() {
		f = append(f, fmt.Sprint(e.Value))
	}
	for e := l.Back(); e != nil; e = e.Prev() {
		b = append(b, fmt.Sprint(e.Value))
	}
	return strings.Join(f, ",") + "/" + strings.Join(b, ",") + "#" + fmt.Sprint(l.Len())
}

func doList(line string) string {
	ls := map[string]*list.List{"A": list.New(), "B": list.New()}
	var hs []*list.Element
	var out []string
	for _, op := range strings.Split(line, ";") {
		f := strings.Fields(op)
		if len(f) == 0 {
			continue
		}
		l := ls[f[0]]
		v := ints(f[2:])
		res := ""
		add := func(e *list.Element) {
			if e == nil {
				res = "=nil"
				return
			}
			hs = append(hs, e)
			res = "=h"
		}
		switch f[1] {
		case "pb":
			add(l.PushBack(v[0]))
		case "pf":
			add(l.PushFront(v[0]))
		case "ib":
			add(l.InsertBefore(v[0], hs[v[1]]))
		case "ia":
			add(l.InsertAfter(v[0], hs[v[1]]))
		case "rm":
			n := l.Len()
			x := l.Remove(hs[v[0]])
			if l.Len() != n {
				res = fmt.Sprintf("=%v", x)
			} else {
				res = "=-"
			}
		case "mf":
			l.MoveToFront(hs[v[0]])
		case "mb":
			l.MoveToBack(hs[v[0]])
		case "mbf":
			l.MoveBefore(hs[v[0]], hs[v[1]])
		case "maf":
			l.MoveAfter(hs[v[0]], hs[v[1]])
		case "pbl":
			l.PushBackList(ls[map[string]string{"A": "B", "B": "A"}[f[0]]])
		case "pfl":
			l.PushFrontList(ls[map[string]string{"A": "B", "B": "A"}[f[0]]])
		case "sv":
			hs[v[0]].Value = v[1]
		case "nx":
			e := hs[v[0]].Next()
			if e == nil {
				res = "=nil"
			} else {
				res = fmt.Sprintf("=%v", e.Value)
			}
		case "pv":
			e := hs[v[0]].Prev()
			if e == nil {
				res = "=nil"
			} else {
				res = fmt.Sprintf("=%v", e.Value)
			}
		case "init":
			l.Init()
		}
		out = append(out, f[1]+res+" A:"+listStr(ls["A"])+" B:"+listStr(ls["B"]))
	}
	return strings.Join(out, " ")
}

// ---- ring ----

func ringStr(r *ring.Ring) string {
	if r == nil {
		return "nil"
	}
	var p []string
	r.Do(func(x any) { p = append(p, fmt.Sprint(x)) })
	return fmt.Sprint(r.Len()) + ":" + strings.Join(p, ",")
}

func doRing(line string) string {
	var rs [4]*ring.Ring
	ctr := 0
	var out []string
	for _, op := range strings.Split(line, ";") {
		f := strings.Fields(op)
		if len(f) == 0 {
			continue
		}
		v := ints(f[1:])
		switch f[0] {
		case "new":
			r := ring.New(v[1])
			rs[v[0]] = r
			for p := r; p != nil; {
				p.Value = ctr
				ctr++
				p = p.Next()
				if p == r {
					break
				}
			}
		case "mv":
			if rs[v[1]] != nil {
				rs[v[0]] = rs[v[1]].Move(v[2])
			}
		case "link":
			if rs[v[0]] != nil {
				rs[v[2]] = rs[v[0]].Link(rs[v[1]])
			}
		case "unlink":
			if rs[v[0]] != nil {
				rs[v[2]] = rs[v[0]].Unlink(v[1])
			}
		case "nx":
			if rs[v[1]] != nil {
				rs[v[0]] = rs[v[1]].Next()
			}
		case "pv":
			if rs[v[1]] != nil {
				rs[v[0]] = rs[v[1]].Prev()
			}
		case "sv":
			if rs[v[0]] != nil {
				rs[v[0]].Value = v[1]
			}
		}
		out = append(out, f[0]+" "+ringStr(rs[0])+" "+ringStr(rs[1])+" "+ringStr(rs[2])+" "+ringStr(rs[3]))
	}
	return strings.Join(out, " | ")
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		line := sc.Text()
		cmd, rest, _ := strings.Cut(line, " ")
		f := strings.Fields(rest)
		var r string
		switch cmd {
		case "SORT":
			r = doSort(f)
		case "FSORT":
			r = doFSort(f)
		case "FSEARCH":
			r = doFSearch(f)
		case "ISEARCH":
			r = doISearch(f)
		case "SL":
			r = doSL(rest)
		case "FMM":
			r = doFMM(f)
		case "CMP":
			r = doCmp(f)
		case "MAP":
			r = doMap(rest)
		case "PULL":
			r = doPull(f)
		case "HEAP":
			r = doHeap(rest)
		case "LIST":
			r = doList(rest)
		case "RING":
			r = doRing(rest)
		default:
			panic("bad command " + cmd)
		}
		fmt.Fprintln(w, r)
	}
}
