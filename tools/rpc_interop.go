// rpc_interop is the Go side of the net/rpc interop test (tools/rpc_check.py):
//
//	go run tools/rpc_interop.go server <gob|json|http> [debug]   prints "PORT n", serves until stdin closes
//	go run tools/rpc_interop.go client <gob|json|http> <port>    runs the scenario, printing one line per step
//
// tools/derive-check/examples/rpc_probe.rs has the same two modes with the
// same service; the scenario output must be identical whichever side is Rust.
package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Args struct{ A, B int }
type Reply struct{ C int }
type Quotient struct{ Quo, Rem int }

type Inner struct{ X int }

type Rich struct {
	S   string `json:"s"`
	F   float64
	B   []byte
	M   map[string]int
	P   *int
	L   []string `json:"l,omitempty"`
	N   int8
	In  Inner
	Any any
}

func (t *Arith) Echo(args *Rich, reply *Rich) error {
	*reply = *args
	return nil
}

type Arith struct {
	mu    sync.Mutex
	calls int
}

func (t *Arith) Add(args *Args, reply *Reply) error {
	t.mu.Lock()
	t.calls++
	t.mu.Unlock()
	reply.C = args.A + args.B
	return nil
}

func (t *Arith) Mul(args *Args, reply *Reply) error {
	reply.C = args.A * args.B
	return nil
}

func (t *Arith) Div(args *Args, q *Quotient) error {
	if args.B == 0 {
		return errors.New("divide by zero")
	}
	q.Quo, q.Rem = args.A/args.B, args.A%args.B
	return nil
}

func (t *Arith) Error(args *Args, reply *Reply) error { return errors.New("ERROR") }

func (t *Arith) Count(args *Args, reply *int) error {
	t.mu.Lock()
	*reply = t.calls
	t.mu.Unlock()
	return nil
}

func (t *Arith) Names(args *Args, reply *map[string]int) error {
	(*reply)["x"] = 1
	return nil
}

func (t *Arith) Sleep(args *Args, reply *Reply) error {
	time.Sleep(time.Duration(args.A) * time.Millisecond)
	reply.C = args.A
	return nil
}

// Money is a dollar amount on the wire as "$d.cc": the value receiver
// marshals it and the pointer receiver unmarshals it.
type Money struct{ Cents int }

func (m Money) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"$%d.%02d"`, m.Cents/100, m.Cents%100)), nil
}

func (m *Money) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) < 4 || s[0] != '"' || s[1] != '$' || s[len(s)-1] != '"' {
		return fmt.Errorf("bad money %s", s)
	}
	d, c, ok := strings.Cut(s[2:len(s)-1], ".")
	dollars, err1 := strconv.Atoi(d)
	cents, err2 := strconv.Atoi(c)
	if !ok || err1 != nil || err2 != nil {
		return fmt.Errorf("bad money %s", s)
	}
	m.Cents = dollars*100 + cents
	return nil
}

// Stamp marshals and unmarshals through pointer receivers.
type Stamp struct{ N int }

func (s *Stamp) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"stamp-%d"`, s.N)), nil
}

func (s *Stamp) UnmarshalJSON(b []byte) error {
	body, ok1 := strings.CutPrefix(string(b), `"stamp-`)
	body, ok2 := strings.CutSuffix(body, `"`)
	n, err := strconv.Atoi(body)
	if !ok1 || !ok2 || err != nil {
		return fmt.Errorf("bad stamp %s", b)
	}
	s.N = n
	return nil
}

// Sealed marshals through a pointer receiver and has no UnmarshalJSON.
type Sealed struct{ N int }

func (s *Sealed) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"sealed-%d"`, s.N)), nil
}

// Verbatim keeps the JSON text it was decoded from; "null" when it has none.
type Verbatim struct{ Text string }

func (v *Verbatim) UnmarshalJSON(b []byte) error {
	v.Text = string(b)
	return nil
}

func (v Verbatim) MarshalJSON() ([]byte, error) {
	if v.Text == "" {
		return []byte("null"), nil
	}
	return []byte(v.Text), nil
}

// Faulty fails to marshal with an error; Broken marshals invalid JSON.
type Faulty struct{ Code int }

func (Faulty) MarshalJSON() ([]byte, error) { return nil, errors.New("boom") }

type Broken struct{ Code int }

func (Broken) MarshalJSON() ([]byte, error) { return []byte("{"), nil }

// Tier is an int on the wire as "tier-N" (0 to 3): MarshalText takes a value
// receiver and UnmarshalText a pointer receiver.
type Tier int

func (t Tier) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("tier-%d", int(t))), nil
}

func (t *Tier) UnmarshalText(b []byte) error {
	n, ok := strings.CutPrefix(string(b), "tier-")
	v, err := strconv.Atoi(n)
	if !ok || err != nil || v < 0 || v > 3 {
		return fmt.Errorf("bad tier %s", b)
	}
	*t = Tier(v)
	return nil
}

// Region is a string on the wire as "r:NAME", both as a value and as a map key.
type Region string

func (r Region) MarshalText() ([]byte, error) { return []byte("r:" + string(r)), nil }

func (r *Region) UnmarshalText(b []byte) error {
	name, ok := strings.CutPrefix(string(b), "r:")
	if !ok {
		return fmt.Errorf("bad region %s", b)
	}
	*r = Region(name)
	return nil
}

// Code marshals and unmarshals through pointer receivers: a Code that is not
// addressable is an object.
type Code struct{ N int }

func (c *Code) MarshalText() ([]byte, error) { return []byte(fmt.Sprintf("code-%d", c.N)), nil }

func (c *Code) UnmarshalText(b []byte) error {
	n, ok := strings.CutPrefix(string(b), "code-")
	v, err := strconv.Atoi(n)
	if !ok || err != nil {
		return fmt.Errorf("bad code %s", b)
	}
	c.N = v
	return nil
}

// Mixed marshals as JSON through a pointer receiver and as text through a value
// receiver: the JSON method applies where the value is addressable (slice
// elements), and the text elsewhere (map values).
type Mixed struct{ N int }

func (m *Mixed) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`{"mixed":%d}`, m.N)), nil
}

func (m Mixed) MarshalText() ([]byte, error) { return []byte(fmt.Sprintf("mixed-%d", m.N)), nil }

// Torn fails to marshal as text when N is negative, as a value or as a map key.
type Torn struct{ N int }

func (t Torn) MarshalText() ([]byte, error) {
	if t.N < 0 {
		return nil, fmt.Errorf("torn %d", t.N)
	}
	return []byte(fmt.Sprintf("torn-%d", t.N)), nil
}

func (t *Torn) UnmarshalText(b []byte) error {
	n, ok := strings.CutPrefix(string(b), "torn-")
	v, err := strconv.Atoi(n)
	if !ok || err != nil {
		return fmt.Errorf("bad torn %s", b)
	}
	t.N = v
	return nil
}

type Torns struct {
	One  Torn
	Keys map[Torn]int
}

type Labels struct {
	Tier     Tier
	TierPtr  *Tier
	Tiers    []Tier
	ByTier   map[Tier]string
	ByRegion map[Region]int
	Code     Code
	Codes    []Code
	Mixed    []Mixed
	MixedMap map[string]Mixed
}

// PKey has MarshalText and UnmarshalText on its pointer only: as a map key it
// passes encoding/json's type check and fails when the name is written.
type PKey struct{ N int }

func (p *PKey) MarshalText() ([]byte, error) { return []byte(fmt.Sprintf("pk-%d", p.N)), nil }

func (p *PKey) UnmarshalText(b []byte) error {
	n, ok := strings.CutPrefix(string(b), "pk-")
	v, err := strconv.Atoi(n)
	if !ok || err != nil {
		return fmt.Errorf("bad pkey %s", b)
	}
	p.N = v
	return nil
}

type PKeys struct {
	Pad  int
	M    map[PKey]int
	Deep []PKeysDeep
}

type PKeysDeep struct{ M map[PKey]int }

// JKey is a string with both UnmarshalJSON and UnmarshalText: as a map key only
// the text method is used, with the unquoted name.
type JKey string

func (k JKey) MarshalText() ([]byte, error)  { return []byte(k), nil }
func (k *JKey) UnmarshalJSON(b []byte) error { *k = JKey("J" + string(b)); return nil }
func (k *JKey) UnmarshalText(b []byte) error { *k = JKey("T" + string(b)); return nil }

type JKeys struct{ M map[JKey]int }

// The byte kinds below carry one method each; a slice or array of them is
// base64 or an array depending on the methods.
type MJV byte

func (b MJV) MarshalJSON() ([]byte, error) { return []byte("7"), nil }

type MJP byte

func (b *MJP) MarshalJSON() ([]byte, error) { return []byte("7"), nil }

type MTV byte

func (b MTV) MarshalText() ([]byte, error) { return []byte("t"), nil }

type MTP byte

func (b *MTP) MarshalText() ([]byte, error) { return []byte("t"), nil }

type UJP byte

func (b *UJP) UnmarshalJSON(t []byte) error { *b = UJP(len(t)); return nil }

type UTP byte

func (b *UTP) UnmarshalText(t []byte) error { *b = UTP(len(t)); return nil }

type Octets struct {
	A []MJV
	B []MJP
	C []MTV
	D []MTP
	E []UJP
	F []UTP
	G [2]MJP
	H [2]UTP
}

// Quoted has text-typed fields with the ,string option, which does not apply to them.
type Quoted struct {
	A Region `json:",string"`
	B Tier   `json:",string"`
	C *Tier  `json:",string"`
	D []Tier `json:",string"`
	F int    `json:",string"`
	G []int  `json:",string"`
	H *Code  `json:",string"`
}

type Entry struct {
	Amount Money
	Ptr    *Money
	List   []Money
	Map    map[string]Money
	Raw    Verbatim
	Stamp  *Stamp
	Hidden Stamp
	Sealed map[string]Sealed
}

type Ledger struct{}

func (t *Ledger) Post(args *Entry, reply *Entry) error {
	*reply = *args
	return nil
}

func (t *Ledger) Faulty(args *Faulty, reply *Faulty) error {
	*reply = *args
	return nil
}

func (t *Ledger) Broken(args *Broken, reply *Broken) error {
	*reply = *args
	return nil
}

func (t *Ledger) Labels(args *Labels, reply *Labels) error {
	*reply = *args
	return nil
}

func (t *Ledger) Torns(args *Torns, reply *Torns) error {
	*reply = *args
	return nil
}

func (t *Ledger) PKeys(args *PKeys, reply *PKeys) error {
	*reply = *args
	return nil
}

func (t *Ledger) JKeys(args *JKeys, reply *JKeys) error {
	*reply = *args
	return nil
}

func (t *Ledger) Octets(args *Octets, reply *Octets) error {
	*reply = *args
	return nil
}

func (t *Ledger) Quoted(args *Quoted, reply *Quoted) error {
	*reply = *args
	return nil
}

func serve(mode string, debug bool) {
	srv := rpc.NewServer()
	if err := srv.Register(new(Arith)); err != nil {
		panic(err)
	}
	if err := srv.Register(new(Ledger)); err != nil {
		panic(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Printf("PORT %d\n", l.Addr().(*net.TCPAddr).Port)
	os.Stdout.Sync()
	go func() {
		switch mode {
		case "http":
			srv.HandleHTTP(rpc.DefaultRPCPath, rpc.DefaultDebugPath)
			http.Serve(l, nil)
		case "json":
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go srv.ServeCodec(jsonrpc.NewServerCodec(c))
			}
		default:
			srv.Accept(l)
		}
	}()
	io.Copy(io.Discard, os.Stdin)
}

func report(name string, v any, err error) {
	var se rpc.ServerError
	switch {
	case err == nil:
		fmt.Printf("%s: ok %v\n", name, v)
	case errors.As(err, &se):
		fmt.Printf("%s: servererror %q\n", name, string(se))
	default:
		fmt.Printf("%s: error %q\n", name, err.Error())
	}
}

func client(mode, port string) {
	addr := "127.0.0.1:" + port
	var c *rpc.Client
	var err error
	switch mode {
	case "http":
		c, err = rpc.DialHTTP("tcp", addr)
	case "json":
		c, err = jsonrpc.Dial("tcp", addr)
	default:
		c, err = rpc.Dial("tcp", addr)
	}
	if err != nil {
		fmt.Println("dial error:", err)
		os.Exit(1)
	}
	var r Reply
	err = c.Call("Arith.Add", &Args{7, 8}, &r)
	report("add", r.C, err)
	err = c.Call("Arith.Mul", &Args{7, 8}, &r)
	report("mul", r.C, err)
	var q Quotient
	err = c.Call("Arith.Div", &Args{7, 2}, &q)
	report("div", q, err)
	err = c.Call("Arith.Div", &Args{7, 0}, &q)
	report("div0", nil, err)
	err = c.Call("Arith.Error", &Args{}, &r)
	report("error", nil, err)
	err = c.Call("Arith.Add", &Args{1, 2}, &r)
	report("after-error", r.C, err)
	err = c.Call("Arith.Unknown", &Args{}, &r)
	report("unknown-method", nil, err)
	err = c.Call("Nope.Add", &Args{}, &r)
	report("unknown-service", nil, err)
	err = c.Call("Add", &Args{}, &r)
	report("ill-formed", nil, err)
	var m map[string]int
	err = c.Call("Arith.Names", &Args{}, &m)
	report("names", m, err)
	var n int
	err = c.Call("Arith.Count", &Args{}, &n)
	report("count", n, err)
	post := &Entry{Amount: Money{150}, Ptr: &Money{205}, List: []Money{{1}}, Map: map[string]Money{"a": {300}}, Raw: Verbatim{Text: `{"x": [1, 2]}`}, Stamp: &Stamp{4}, Hidden: Stamp{9}}
	var pr Entry
	err = c.Call("Ledger.Post", post, &pr)
	report("post", pr.Amount.Cents, err)
	ptr, first, stamp := -1, -1, -1
	if pr.Ptr != nil {
		ptr = pr.Ptr.Cents
	}
	if len(pr.List) > 0 {
		first = pr.List[0].Cents
	}
	if pr.Stamp != nil {
		stamp = pr.Stamp.N
	}
	fmt.Printf("post-fields: ptr=%d list=%d map=%d raw=%q stamp=%d hidden=%d\n", ptr, first, pr.Map["a"].Cents, pr.Raw.Text, stamp, pr.Hidden.N)
	var fa Faulty
	err = c.Call("Ledger.Faulty", Faulty{Code: 1}, &fa)
	report("faulty", fa.Code, err)
	var br Broken
	err = c.Call("Ledger.Broken", Broken{Code: 2}, &br)
	report("broken", br.Code, err)
	tier3 := Tier(3)
	labels := &Labels{Tier: 2, TierPtr: &tier3, Tiers: []Tier{0, 1}, ByTier: map[Tier]string{3: "three", 1: "one<&>"},
		ByRegion: map[Region]int{"north": 1, "south": 2}, Code: Code{N: 4}, Codes: []Code{{5}},
		Mixed: []Mixed{{7}}, MixedMap: map[string]Mixed{}}
	var lb Labels
	err = c.Call("Ledger.Labels", labels, &lb)
	report("labels", nil, err)
	if err == nil {
		ptr := -1
		if lb.TierPtr != nil {
			ptr = int(*lb.TierPtr)
		}
		fmt.Printf("labels-fields: tier=%d ptr=%d tiers=%d,%d bytier=%d %q %q region=%d,%d code=%d codes=%d mixed=%d mixedmap=%d\n",
			lb.Tier, ptr, lb.Tiers[0], lb.Tiers[1], len(lb.ByTier), lb.ByTier[3], lb.ByTier[1], lb.ByRegion["north"], lb.ByRegion["south"],
			lb.Code.N, lb.Codes[0].N, len(lb.Mixed), len(lb.MixedMap))
	}
	var tn Torns
	err = c.Call("Ledger.Torns", &Torns{One: Torn{-1}, Keys: map[Torn]int{}}, &tn)
	report("torn-value", nil, err)
	err = c.Call("Ledger.Torns", &Torns{One: Torn{1}, Keys: map[Torn]int{{-2}: 1}}, &tn)
	report("torn-key", nil, err)
	err = c.Call("Ledger.Torns", &Torns{One: Torn{1}, Keys: map[Torn]int{{2}: 3}}, &tn)
	report("torns", nil, err)
	if err == nil {
		fmt.Printf("torns-fields: one=%d key2=%d keys=%d\n", tn.One.N, tn.Keys[Torn{2}], len(tn.Keys))
	}

	if mode == "json" {
		// A pointer-only MarshalText key fails when the request is written,
		// with the offset and path of jsontext's error.
		var pk PKeys
		err = c.Call("Ledger.PKeys", &PKeys{Pad: 1, M: map[PKey]int{{1}: 2}}, &pk)
		report("pkeys", nil, err)
		err = c.Call("Ledger.PKeys", &PKeys{M: map[PKey]int{}, Deep: []PKeysDeep{{M: map[PKey]int{}}, {M: map[PKey]int{{1}: 2}}}}, &pk)
		report("pkeys-deep", nil, err)
		err = c.Call("Ledger.PKeys", &PKeys{M: map[PKey]int{}}, &pk)
		report("pkeys-empty", nil, err)
	}

	var wg sync.WaitGroup
	results := make([]int, 20)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var rr Reply
			if err := c.Call("Arith.Mul", &Args{i, 3}, &rr); err == nil {
				results[i] = rr.C
			} else {
				results[i] = -1
			}
		}(i)
	}
	wg.Wait()
	fmt.Println("concurrent:", results)

	t0 := time.Now()
	var r1, r2 Reply
	d1 := c.Go("Arith.Sleep", &Args{150, 0}, &r1, nil)
	d2 := c.Go("Arith.Sleep", &Args{150, 0}, &r2, nil)
	<-d1.Done
	<-d2.Done
	fmt.Println("async:", r1.C, r2.C, d1.Error, d2.Error, time.Since(t0) < 280*time.Millisecond)

	fmt.Println("close:", c.Close())
	fmt.Println("close-again:", c.Close())
	err = c.Call("Arith.Add", &Args{1, 2}, &r)
	report("after-close", nil, err)
}

func main() {
	switch os.Args[1] {
	case "server":
		serve(os.Args[2], len(os.Args) > 3)
	case "client":
		client(os.Args[2], os.Args[3])
	case "debug":
		// debug <port>: print the /debug/rpc page.
		resp, err := http.Get("http://127.0.0.1:" + os.Args[2] + "/debug/rpc")
		if err != nil {
			panic(err)
		}
		b, _ := io.ReadAll(resp.Body)
		fmt.Print(string(b))
	}
}
