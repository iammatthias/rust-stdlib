//go:build ignore

// Go side of the crypto/tls differential (tools/gotls_check.py).
//
//	gotls_oracle certs <dir>             write the test PKI as PEM files
//	gotls_oracle tables                  print the String/name tables
//	gotls_oracle session                 re-encode SessionState vectors from stdin
//	gotls_oracle server <dir> k=v...     TLS server, one JSON line per connection
//	gotls_oracle client <dir> <addr> k=v...  TLS client, one JSON line per connection
//
// Options (shared with backends/tls/examples/gotls_probe.rs): cert, certs, min,
// max, suites, alpn, sni, clientauth, clientcert, roots, skipverify, conns,
// sessions, now, curves, getcert. Output field names are the contract.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// ------------------------------------------------------------------ PKI

type party struct {
	cert *x509.Certificate
	key  any
	der  []byte
}

var serial int64 = 100

func newKey(kind string) (any, any) {
	switch kind {
	case "rsa":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		return k, &k.PublicKey
	case "ed25519":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		must(err)
		return priv, pub
	default:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		return k, &k.PublicKey
	}
}

func issue(tmpl *x509.Certificate, parent *party, kind string) *party {
	serial++
	tmpl.SerialNumber = big.NewInt(serial)
	key, pub := newKey(kind)
	signer, parentCert := key, tmpl
	if parent != nil {
		signer, parentCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, pub, signer)
	must(err)
	c, err := x509.ParseCertificate(der)
	must(err)
	return &party{c, key, der}
}

var (
	start = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	end   = time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)
)

func caTemplate(cn string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: cn}, NotBefore: start, NotAfter: end,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
}

func leafTemplate(cn string, dns []string, ips []string, usage x509.ExtKeyUsage) *x509.Certificate {
	t := &x509.Certificate{Subject: pkix.Name{CommonName: cn}, NotBefore: start, NotAfter: end,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}, DNSNames: dns}
	for _, ip := range ips {
		t.IPAddresses = append(t.IPAddresses, net.ParseIP(ip))
	}
	return t
}

func writePEM(path, typ string, der []byte) {
	must(os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644))
}

func writeParty(dir, name string, p *party, chain ...*party) {
	var certPEM []byte
	certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.der})...)
	for _, c := range chain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})...)
	}
	must(os.WriteFile(filepath.Join(dir, name+".pem"), certPEM, 0o644))
	var keyDER []byte
	var typ string
	switch k := p.key.(type) {
	case *rsa.PrivateKey:
		keyDER, typ = x509.MarshalPKCS1PrivateKey(k), "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		d, err := x509.MarshalECPrivateKey(k)
		must(err)
		keyDER, typ = d, "EC PRIVATE KEY"
	default:
		d, err := x509.MarshalPKCS8PrivateKey(k)
		must(err)
		keyDER, typ = d, "PRIVATE KEY"
	}
	writePEM(filepath.Join(dir, name+"-key.pem"), typ, keyDER)
}

func certs(dir string) {
	must(os.MkdirAll(dir, 0o755))
	ca := issue(caTemplate("gotls test CA"), nil, "ecdsa")
	writePEM(filepath.Join(dir, "ca.pem"), "CERTIFICATE", ca.der)
	other := issue(caTemplate("gotls other CA"), nil, "ecdsa")
	writePEM(filepath.Join(dir, "other-ca.pem"), "CERTIFICATE", other.der)
	inter := issue(caTemplate("gotls intermediate"), ca, "ecdsa")
	// The intermediate issues the ECDSA server leaf: chain length three.
	ecdsaLeaf := issue(leafTemplate("ecdsa.test", []string{"localhost", "ecdsa.test"}, []string{"127.0.0.1"}, x509.ExtKeyUsageServerAuth), inter, "ecdsa")
	writeParty(dir, "ecdsa", ecdsaLeaf, inter)
	rsaLeaf := issue(leafTemplate("rsa.test", []string{"localhost", "rsa.test"}, []string{"127.0.0.1"}, x509.ExtKeyUsageServerAuth), ca, "rsa")
	writeParty(dir, "rsa", rsaLeaf)
	edLeaf := issue(leafTemplate("ed25519.test", []string{"localhost", "ed25519.test"}, []string{"127.0.0.1"}, x509.ExtKeyUsageServerAuth), ca, "ed25519")
	writeParty(dir, "ed25519", edLeaf)
	expired := leafTemplate("expired.test", []string{"localhost"}, []string{"127.0.0.1"}, x509.ExtKeyUsageServerAuth)
	expired.NotBefore, expired.NotAfter = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	writeParty(dir, "expired", issue(expired, ca, "ecdsa"))
	notyet := leafTemplate("notyet.test", []string{"localhost"}, []string{"127.0.0.1"}, x509.ExtKeyUsageServerAuth)
	notyet.NotBefore, notyet.NotAfter = time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2095, 1, 1, 0, 0, 0, 0, time.UTC)
	writeParty(dir, "notyet", issue(notyet, ca, "ecdsa"))
	writeParty(dir, "wronghost", issue(leafTemplate("wronghost.test", []string{"other.test", "second.test"}, nil, x509.ExtKeyUsageServerAuth), ca, "ecdsa"))
	writeParty(dir, "untrusted", issue(leafTemplate("untrusted.test", []string{"localhost"}, []string{"127.0.0.1"}, x509.ExtKeyUsageServerAuth), other, "ecdsa"))
	writeParty(dir, "client-ecdsa", issue(leafTemplate("client.test", nil, nil, x509.ExtKeyUsageClientAuth), ca, "ecdsa"))
	writeParty(dir, "client-untrusted", issue(leafTemplate("client-untrusted.test", nil, nil, x509.ExtKeyUsageClientAuth), other, "ecdsa"))
}

// -------------------------------------------------------------- tables

func tables() {
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	dump := func(kind string, list []*tls.CipherSuite) {
		for _, c := range list {
			fmt.Fprintf(w, "%s %04x %s %v %v\n", kind, c.ID, c.Name, c.SupportedVersions, c.Insecure)
		}
	}
	dump("secure", tls.CipherSuites())
	dump("insecure", tls.InsecureCipherSuites())
	for i := 0; i < 65536; i++ {
		fmt.Fprintf(w, "n %04x %s|%s|%s|%s\n", i, tls.CipherSuiteName(uint16(i)), tls.VersionName(uint16(i)),
			tls.CurveID(i).String(), tls.SignatureScheme(i).String())
	}
	for i := -3; i < 9; i++ {
		fmt.Fprintf(w, "auth %d %s\n", i, tls.ClientAuthType(i).String())
	}
	fmt.Fprintf(w, "alert %s|%s|%s|%s\n", tls.AlertError(42).Error(), tls.AlertError(0).Error(), tls.AlertError(121).Error(), tls.AlertError(200).Error())
	fmt.Fprintf(w, "errors %s|%s|%s\n", (&tls.CertificateVerificationError{Err: fmt.Errorf("boom")}).Error(),
		tls.RecordHeaderError{Msg: "bad"}.Error(), (&tls.ECHRejectionError{}).Error())
	for i := 0; i < 5; i++ {
		fmt.Fprintf(w, "quic %d %s\n", i, tls.QUICEncryptionLevel(i).String())
	}
}

// ------------------------------------------------------------- sessions

// session reads hex SessionState encodings, one per line, and prints either
// "err <message>" or the re-encoded hex and the Extra / EarlyData fields.
func session() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		raw, err := hex.DecodeString(strings.TrimSpace(sc.Text()))
		if err != nil {
			fmt.Println("badhex")
			continue
		}
		ss, err := tls.ParseSessionState(raw)
		if err != nil {
			fmt.Println("err", err)
			continue
		}
		b, err := ss.Bytes()
		if err != nil {
			fmt.Println("encerr", err)
			continue
		}
		var extra []string
		for _, e := range ss.Extra {
			extra = append(extra, hex.EncodeToString(e))
		}
		fmt.Printf("ok %s %v %s\n", hex.EncodeToString(b), ss.EarlyData, strings.Join(extra, ","))
	}
}

// -------------------------------------------------------- connections

type opts map[string]string

func parseOpts(args []string) opts {
	o := opts{}
	for _, a := range args {
		k, v, _ := strings.Cut(a, "=")
		o[k] = v
	}
	return o
}

func version(s string) uint16 {
	switch s {
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	}
	return 0
}

func loadPool(dir, name string) *x509.CertPool {
	pool := x509.NewCertPool()
	b, err := os.ReadFile(filepath.Join(dir, name+".pem"))
	must(err)
	if !pool.AppendCertsFromPEM(b) {
		panic("bad CA " + name)
	}
	return pool
}

func loadPair(dir, name string) tls.Certificate {
	c, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem"))
	must(err)
	return c
}

func baseConfig(dir string, o opts) *tls.Config {
	c := &tls.Config{MinVersion: version(o["min"]), MaxVersion: version(o["max"])}
	if s := o["suites"]; s != "" {
		for _, id := range strings.Split(s, ",") {
			v, err := strconv.ParseUint(id, 0, 16)
			must(err)
			c.CipherSuites = append(c.CipherSuites, uint16(v))
		}
	}
	if s := o["alpn"]; s != "" {
		c.NextProtos = strings.Split(s, ",")
	}
	if s := o["curves"]; s != "" {
		for _, id := range strings.Split(s, ",") {
			v, err := strconv.ParseUint(id, 0, 16)
			must(err)
			c.CurvePreferences = append(c.CurvePreferences, tls.CurveID(v))
		}
	}
	return c
}

func hexs(b []byte, err error) string {
	if err != nil {
		return "err:" + err.Error()
	}
	return hex.EncodeToString(b)
}

func cns(chain []*x509.Certificate) []string {
	var r []string
	for _, c := range chain {
		r = append(r, c.Subject.CommonName)
	}
	return r
}

func report(c *tls.Conn, extra map[string]any) map[string]any {
	st := c.ConnectionState()
	r := map[string]any{
		"version":  tls.VersionName(st.Version),
		"cipher":   tls.CipherSuiteName(st.CipherSuite),
		"curve":    st.CurveID.String(),
		"alpn":     st.NegotiatedProtocol,
		"sni":      st.ServerName,
		"resumed":  st.DidResume,
		"hrr":      st.HelloRetryRequest,
		"complete": st.HandshakeComplete,
		"peers":    len(st.PeerCertificates),
	}
	if len(st.PeerCertificates) > 0 {
		r["peer_cn"] = st.PeerCertificates[0].Subject.CommonName
	}
	var chains [][]string
	for _, ch := range st.VerifiedChains {
		chains = append(chains, cns(ch))
	}
	r["chains"] = chains
	r["ekm"] = hexs(st.ExportKeyingMaterial("EXPERIMENT gotls", nil, 32))
	r["ekm_ctx"] = hexs(st.ExportKeyingMaterial("EXPERIMENT gotls", []byte("ctx"), 32))
	r["ekm_empty"] = hexs(st.ExportKeyingMaterial("EXPERIMENT gotls", []byte{}, 32))
	for k, v := range extra {
		r[k] = v
	}
	return r
}

func emit(r map[string]any) {
	b, err := json.Marshal(r)
	must(err)
	fmt.Println(string(b))
}

func serverMain(dir string, o opts) {
	cfg := baseConfig(dir, o)
	for _, name := range strings.Split(o["certs"], ",") {
		if name != "" {
			cfg.Certificates = append(cfg.Certificates, loadPair(dir, name))
		}
	}
	if o["getcert"] == "1" {
		all := map[string]tls.Certificate{}
		for _, n := range []string{"ecdsa", "rsa", "ed25519"} {
			all[n] = loadPair(dir, n)
		}
		cfg.Certificates = nil
		cfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := all["ecdsa"]
			switch h.ServerName {
			case "rsa.test":
				c = all["rsa"]
			case "ed25519.test":
				c = all["ed25519"]
			}
			return &c, nil
		}
	}
	auth := map[string]tls.ClientAuthType{"": tls.NoClientCert, "NoClientCert": tls.NoClientCert,
		"RequestClientCert": tls.RequestClientCert, "RequireAnyClientCert": tls.RequireAnyClientCert,
		"VerifyClientCertIfGiven": tls.VerifyClientCertIfGiven, "RequireAndVerifyClientCert": tls.RequireAndVerifyClientCert}
	cfg.ClientAuth = auth[o["clientauth"]]
	// clientcas=system leaves ClientCAs nil: Go verifies against the system roots.
	if cfg.ClientAuth >= tls.VerifyClientCertIfGiven && o["clientcas"] != "system" {
		cfg.ClientCAs = loadPool(dir, "ca")
	}
	cfg.SessionTicketsDisabled = o["tickets"] == "0"
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	must(err)
	fmt.Println("listening", ln.Addr().String())
	os.Stdout.Sync()
	go func() {
		bufio.NewReader(os.Stdin).ReadByte()
		os.Exit(0)
	}()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			tc := c.(*tls.Conn)
			c.SetDeadline(time.Now().Add(20 * time.Second))
			if err := tc.Handshake(); err != nil {
				emit(map[string]any{"role": "server", "error": err.Error()})
				return
			}
			line, err := bufio.NewReader(tc).ReadString('\n')
			if err != nil {
				emit(map[string]any{"role": "server", "error": err.Error(), "stage": "read"})
				return
			}
			tc.Write([]byte("echo:" + line))
			emit(report(tc, map[string]any{"role": "server"}))
			// Wait for the client to close so tickets/alerts are delivered.
			buf := make([]byte, 16)
			tc.Read(buf)
		}(raw)
	}
}

func clientMain(dir, addr string, o opts) {
	cfg := baseConfig(dir, o)
	cfg.ServerName = o["sni"]
	if cfg.ServerName == "" {
		cfg.ServerName = "localhost"
	}
	switch o["roots"] {
	case "other":
		cfg.RootCAs = loadPool(dir, "other-ca")
	case "system":
		cfg.RootCAs = nil
	default:
		cfg.RootCAs = loadPool(dir, "ca")
	}
	cfg.InsecureSkipVerify = o["skipverify"] == "1"
	if n := o["clientcert"]; n != "" && n != "none" {
		pair := loadPair(dir, "client-"+n)
		cfg.Certificates = []tls.Certificate{pair}
		if o["forcecert"] == "1" {
			// Send the certificate even when the server's CA list excludes it.
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &pair, nil }
		}
	}
	if o["now"] != "" {
		t, err := time.Parse(time.RFC3339, o["now"])
		must(err)
		cfg.Time = func() time.Time { return t }
	}
	if o["sessions"] == "1" {
		cfg.ClientSessionCache = tls.NewLRUClientSessionCache(8)
	}
	conns := 1
	if o["conns"] != "" {
		conns, _ = strconv.Atoi(o["conns"])
	}
	for i := 0; i < conns; i++ {
		d := &net.Dialer{Timeout: 10 * time.Second}
		raw, err := d.DialContext(context.Background(), "tcp", addr)
		must(err)
		raw.SetDeadline(time.Now().Add(20 * time.Second))
		c := tls.Client(raw, cfg)
		stage := "handshake"
		err = c.Handshake()
		if err == nil {
			stage = "write"
			_, err = c.Write([]byte("hello\n"))
		}
		var line string
		if err == nil {
			stage = "read"
			line, err = bufio.NewReader(c).ReadString('\n')
		}
		if err != nil {
			emit(map[string]any{"role": "client", "error": err.Error(), "stage": stage})
		} else {
			emit(report(c, map[string]any{"role": "client", "echo": strings.TrimSpace(line)}))
		}
		c.Close()
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: gotls_oracle certs|tables|session|server|client")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "certs":
		certs(os.Args[2])
	case "tables":
		tables()
	case "session":
		session()
	case "server":
		serverMain(os.Args[2], parseOpts(os.Args[3:]))
	case "client":
		clientMain(os.Args[2], os.Args[3], parseOpts(os.Args[4:]))
	default:
		os.Exit(2)
	}
}
