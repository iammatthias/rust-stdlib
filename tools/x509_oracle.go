// Go reference implementation for tools/x509_check.py.
//
// Reads one case per line as space-separated key=value tokens (byte strings
// are hex) and writes one line per case: "dump=<hex of a text dump>" or
// "err=<hex of the error message>". The Rust probe in
// crates/crypto/examples/x509_probe.rs implements the same protocol and the
// same dump format, so equal lines mean every field matched.
package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type fields map[string]string

func parse(line string) fields {
	f := fields{}
	for _, token := range strings.Split(line, " ") {
		key, value, _ := strings.Cut(token, "=")
		f[key] = value
	}
	return f
}

func (f fields) b(key string) []byte {
	out, err := hex.DecodeString(f[key])
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad hex for", key, err)
		os.Exit(2)
	}
	return out
}

func (f fields) list(key string) [][]byte {
	if f[key] == "" {
		return nil
	}
	var out [][]byte
	for _, item := range strings.Split(f[key], ",") {
		b, err := hex.DecodeString(item)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad hex in", key, err)
			os.Exit(2)
		}
		out = append(out, b)
	}
	return out
}

type dump struct{ strings.Builder }

func (d *dump) w(k string, v any) { fmt.Fprintf(d, "%s=%v\n", k, v) }
func (d *dump) h(k string, v []byte) {
	fmt.Fprintf(d, "%s=%s\n", k, hex.EncodeToString(v))
}
func (d *dump) strs(k string, v []string) {
	d.w(k+".len", len(v))
	for i, s := range v {
		d.h(fmt.Sprintf("%s[%d]", k, i), []byte(s))
	}
}

func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func oids(v []asn1.ObjectIdentifier) string {
	var parts []string
	for _, o := range v {
		parts = append(parts, o.String())
	}
	return strings.Join(parts, ",")
}

func valDump(v any) string {
	switch v := v.(type) {
	case nil:
		return "nil"
	case string:
		return "s:" + hex.EncodeToString([]byte(v))
	case int64:
		return "i:" + strconv.FormatInt(v, 10)
	case int:
		return "i:" + strconv.Itoa(v)
	case bool:
		return "b:" + strconv.FormatBool(v)
	case []byte:
		return "o:" + hex.EncodeToString(v)
	case asn1.BitString:
		return fmt.Sprintf("bs:%s/%d", hex.EncodeToString(v.Bytes), v.BitLength)
	case asn1.ObjectIdentifier:
		return "oid:" + v.String()
	case time.Time:
		return "t:" + fmtTime(v)
	case asn1.RawValue:
		return fmt.Sprintf("raw:%d,%d,%v,%s,%s", v.Class, v.Tag, v.IsCompound, hex.EncodeToString(v.Bytes), hex.EncodeToString(v.FullBytes))
	}
	return fmt.Sprintf("?:%T", v)
}

func dumpName(d *dump, p string, n pkix.Name) {
	d.w(p+".string", hex.EncodeToString([]byte(n.String())))
	d.strs(p+".country", n.Country)
	d.strs(p+".organization", n.Organization)
	d.strs(p+".ou", n.OrganizationalUnit)
	d.strs(p+".locality", n.Locality)
	d.strs(p+".province", n.Province)
	d.strs(p+".street", n.StreetAddress)
	d.strs(p+".postal", n.PostalCode)
	d.h(p+".serial", []byte(n.SerialNumber))
	d.h(p+".cn", []byte(n.CommonName))
	d.w(p+".names.len", len(n.Names))
	for i, a := range n.Names {
		d.w(fmt.Sprintf("%s.names[%d]", p, i), a.Type.String()+"|"+valDump(a.Value))
	}
	rs := n.ToRDNSequence()
	b, err := asn1.Marshal(rs)
	if err != nil {
		d.w(p+".rdn", "err")
	} else {
		d.h(p+".rdn", b)
	}
}

func dumpExts(d *dump, p string, exts []pkix.Extension) {
	d.w(p+".len", len(exts))
	for i, e := range exts {
		d.w(fmt.Sprintf("%s[%d]", p, i), fmt.Sprintf("%s|%v|%s", e.Id, e.Critical, hex.EncodeToString(e.Value)))
	}
}

func ips(v []net.IP) string {
	var parts []string
	for _, ip := range v {
		parts = append(parts, hex.EncodeToString(ip))
	}
	return strings.Join(parts, ",")
}

func ipnets(v []*net.IPNet) string {
	var parts []string
	for _, n := range v {
		parts = append(parts, hex.EncodeToString(n.IP)+"/"+hex.EncodeToString(n.Mask))
	}
	return strings.Join(parts, ",")
}

func urls(v []*url.URL) string {
	var parts []string
	for _, u := range v {
		parts = append(parts, hex.EncodeToString([]byte(u.String())))
	}
	return strings.Join(parts, ",")
}

func dumpPublicKey(d *dump, p string, k any) {
	if k == nil {
		d.w(p, "nil")
		return
	}
	d.w(p+".type", fmt.Sprintf("%T", k))
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		d.h(p+".pkix_err", []byte(err.Error()))
	} else {
		d.h(p+".pkix", b)
	}
	if rk, ok := k.(*rsa.PublicKey); ok {
		d.h(p+".pkcs1", x509.MarshalPKCS1PublicKey(rk))
	}
}

func sigAlgs(a x509.SignatureAlgorithm) string { return fmt.Sprintf("%d:%s", int(a), a.String()) }

func dumpCert(c *x509.Certificate) string {
	var d dump
	d.h("raw", c.Raw)
	d.h("raw_tbs", c.RawTBSCertificate)
	d.h("raw_spki", c.RawSubjectPublicKeyInfo)
	d.h("raw_subject", c.RawSubject)
	d.h("raw_issuer", c.RawIssuer)
	d.h("raw_sigalg", c.RawSignatureAlgorithm)
	d.h("signature", c.Signature)
	d.w("sigalg", sigAlgs(c.SignatureAlgorithm))
	d.w("pkalg", fmt.Sprintf("%d:%s", int(c.PublicKeyAlgorithm), c.PublicKeyAlgorithm))
	dumpPublicKey(&d, "pk", c.PublicKey)
	d.w("version", c.Version)
	d.w("serial", c.SerialNumber)
	dumpName(&d, "issuer", c.Issuer)
	dumpName(&d, "subject", c.Subject)
	d.w("not_before", fmtTime(c.NotBefore))
	d.w("not_after", fmtTime(c.NotAfter))
	d.w("key_usage", int(c.KeyUsage))
	dumpExts(&d, "ext", c.Extensions)
	d.w("unhandled", oids(c.UnhandledCriticalExtensions))
	var ekus []string
	for _, e := range c.ExtKeyUsage {
		ekus = append(ekus, fmt.Sprintf("%d:%s", int(e), e))
	}
	d.w("eku", strings.Join(ekus, ","))
	d.w("unknown_eku", oids(c.UnknownExtKeyUsage))
	d.w("bc", fmt.Sprintf("%v|%v|%d|%v", c.BasicConstraintsValid, c.IsCA, c.MaxPathLen, c.MaxPathLenZero))
	d.h("skid", c.SubjectKeyId)
	d.h("akid", c.AuthorityKeyId)
	d.strs("ocsp", c.OCSPServer)
	d.strs("issuing", c.IssuingCertificateURL)
	d.strs("dns", c.DNSNames)
	d.strs("email", c.EmailAddresses)
	d.w("ips", ips(c.IPAddresses))
	d.w("uris", urls(c.URIs))
	d.w("pdc", c.PermittedDNSDomainsCritical)
	d.strs("pdns", c.PermittedDNSDomains)
	d.strs("edns", c.ExcludedDNSDomains)
	d.w("pip", ipnets(c.PermittedIPRanges))
	d.w("eip", ipnets(c.ExcludedIPRanges))
	d.strs("pemail", c.PermittedEmailAddresses)
	d.strs("eemail", c.ExcludedEmailAddresses)
	d.strs("puri", c.PermittedURIDomains)
	d.strs("euri", c.ExcludedURIDomains)
	d.strs("crldp", c.CRLDistributionPoints)
	d.w("policy_ids", oids(c.PolicyIdentifiers))
	var pols []string
	for _, p := range c.Policies {
		pols = append(pols, p.String())
	}
	d.w("policies", strings.Join(pols, ","))
	d.w("inhibit_any", fmt.Sprintf("%d|%v", c.InhibitAnyPolicy, c.InhibitAnyPolicyZero))
	d.w("inhibit_map", fmt.Sprintf("%d|%v", c.InhibitPolicyMapping, c.InhibitPolicyMappingZero))
	d.w("require_explicit", fmt.Sprintf("%d|%v", c.RequireExplicitPolicy, c.RequireExplicitPolicyZero))
	var maps []string
	for _, m := range c.PolicyMappings {
		maps = append(maps, m.IssuerDomainPolicy.String()+">"+m.SubjectDomainPolicy.String())
	}
	d.w("policy_mappings", strings.Join(maps, ","))
	// Self-signature check: the result must agree too.
	if err := c.CheckSignatureFrom(c); err != nil {
		d.h("selfsig", []byte(err.Error()))
	} else {
		d.w("selfsig", "ok")
	}
	if err := c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature); err != nil {
		d.h("sigcheck", []byte(err.Error()))
	} else {
		d.w("sigcheck", "ok")
	}
	return d.String()
}

func dumpCSR(c *x509.CertificateRequest) string {
	var d dump
	d.h("raw", c.Raw)
	d.h("raw_tbs", c.RawTBSCertificateRequest)
	d.h("raw_spki", c.RawSubjectPublicKeyInfo)
	d.h("raw_subject", c.RawSubject)
	d.h("raw_sigalg", c.RawSignatureAlgorithm)
	d.w("version", c.Version)
	d.h("signature", c.Signature)
	d.w("sigalg", sigAlgs(c.SignatureAlgorithm))
	d.w("pkalg", fmt.Sprintf("%d:%s", int(c.PublicKeyAlgorithm), c.PublicKeyAlgorithm))
	dumpPublicKey(&d, "pk", c.PublicKey)
	dumpName(&d, "subject", c.Subject)
	d.w("attrs.len", len(c.Attributes))
	for i, a := range c.Attributes {
		var vs []string
		for _, set := range a.Value {
			var items []string
			for _, atv := range set {
				items = append(items, atv.Type.String()+"="+valDump(atv.Value))
			}
			vs = append(vs, strings.Join(items, ";"))
		}
		d.w(fmt.Sprintf("attr[%d]", i), a.Type.String()+"|"+strings.Join(vs, "/"))
	}
	dumpExts(&d, "ext", c.Extensions)
	d.strs("dns", c.DNSNames)
	d.strs("email", c.EmailAddresses)
	d.w("ips", ips(c.IPAddresses))
	d.w("uris", urls(c.URIs))
	if err := c.CheckSignature(); err != nil {
		d.h("sigcheck", []byte(err.Error()))
	} else {
		d.w("sigcheck", "ok")
	}
	return d.String()
}

func dumpRL(rl *x509.RevocationList) string {
	var d dump
	d.h("raw", rl.Raw)
	d.h("raw_tbs", rl.RawTBSRevocationList)
	d.h("raw_issuer", rl.RawIssuer)
	d.h("raw_sigalg", rl.RawSignatureAlgorithm)
	dumpName(&d, "issuer", rl.Issuer)
	d.h("akid", rl.AuthorityKeyId)
	d.h("signature", rl.Signature)
	d.w("sigalg", sigAlgs(rl.SignatureAlgorithm))
	d.w("number", rl.Number)
	d.w("this_update", fmtTime(rl.ThisUpdate))
	d.w("next_update", fmtTime(rl.NextUpdate))
	d.w("entries.len", len(rl.RevokedCertificateEntries))
	for i, e := range rl.RevokedCertificateEntries {
		d.w(fmt.Sprintf("entry[%d]", i), fmt.Sprintf("%s|%s|%d|%s", e.SerialNumber, fmtTime(e.RevocationTime), e.ReasonCode, hex.EncodeToString(e.Raw)))
		dumpExts(&d, fmt.Sprintf("entry[%d].ext", i), e.Extensions)
	}
	d.w("revoked.len", len(rl.RevokedCertificates))
	for i, e := range rl.RevokedCertificates {
		d.w(fmt.Sprintf("revoked[%d]", i), fmt.Sprintf("%s|%s", e.SerialNumber, fmtTime(e.RevocationTime)))
	}
	dumpExts(&d, "ext", rl.Extensions)
	return d.String()
}

func dumpCertList(cl *pkix.CertificateList) string {
	var d dump
	t := cl.TBSCertList
	d.h("raw", t.Raw)
	d.w("version", t.Version)
	d.w("sigalg", t.Signature.Algorithm.String())
	d.h("sigparams", t.Signature.Parameters.FullBytes)
	d.w("issuer", hex.EncodeToString([]byte(t.Issuer.String())))
	d.w("this_update", fmtTime(t.ThisUpdate))
	d.w("next_update", fmtTime(t.NextUpdate))
	d.w("revoked.len", len(t.RevokedCertificates))
	for i, e := range t.RevokedCertificates {
		d.w(fmt.Sprintf("revoked[%d]", i), fmt.Sprintf("%s|%s", e.SerialNumber, fmtTime(e.RevocationTime)))
		dumpExts(&d, fmt.Sprintf("revoked[%d].ext", i), e.Extensions)
	}
	dumpExts(&d, "ext", t.Extensions)
	d.w("outer_sigalg", cl.SignatureAlgorithm.Algorithm.String())
	d.h("sigvalue", cl.SignatureValue.RightAlign())
	return d.String()
}

func keyType(k any) string { return fmt.Sprintf("%T", k) }

func dumpPrivate(k any) string {
	var d dump
	d.w("type", keyType(k))
	var pub crypto.PublicKey
	switch k := k.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
		d.h("pkcs1", x509.MarshalPKCS1PrivateKey(k))
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
		if b, err := x509.MarshalECPrivateKey(k); err == nil {
			d.h("sec1", b)
		} else {
			d.h("sec1_err", []byte(err.Error()))
		}
	case ed25519.PrivateKey:
		pub = k.Public()
	case *mldsa.PrivateKey:
		pub = k.PublicKey()
	case *ecdh.PrivateKey:
		pub = k.PublicKey()
	}
	if b, err := x509.MarshalPKCS8PrivateKey(k); err == nil {
		d.h("pkcs8", b)
	} else {
		d.h("pkcs8_err", []byte(err.Error()))
	}
	dumpPublicKey(&d, "pub", pub)
	return d.String()
}

func run(f fields) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	switch f["op"] {
	case "parse_cert":
		c, err := x509.ParseCertificate(f.b("der"))
		if err != nil {
			return "", err
		}
		return dumpCert(c), nil
	case "parse_certs":
		cs, err := x509.ParseCertificates(f.b("der"))
		if err != nil {
			return "", err
		}
		var d dump
		d.w("count", len(cs))
		for i, c := range cs {
			d.h(fmt.Sprintf("raw[%d]", i), c.Raw)
		}
		return d.String(), nil
	case "parse_csr":
		c, err := x509.ParseCertificateRequest(f.b("der"))
		if err != nil {
			return "", err
		}
		return dumpCSR(c), nil
	case "parse_crl":
		rl, err := x509.ParseRevocationList(f.b("der"))
		if err != nil {
			return "", err
		}
		return dumpRL(rl), nil
	case "parse_der_crl":
		cl, err := x509.ParseDERCRL(f.b("der"))
		if err != nil {
			return "", err
		}
		return dumpCertList(cl), nil
	case "parse_crl_any":
		cl, err := x509.ParseCRL(f.b("der"))
		if err != nil {
			return "", err
		}
		return dumpCertList(cl), nil
	case "parse_key":
		der := f.b("der")
		var k any
		var err error
		switch f["kind"] {
		case "pkcs1":
			k, err = x509.ParsePKCS1PrivateKey(der)
		case "pkcs8":
			k, err = x509.ParsePKCS8PrivateKey(der)
		case "ec":
			k, err = x509.ParseECPrivateKey(der)
		case "pkix":
			pk, err := x509.ParsePKIXPublicKey(der)
			if err != nil {
				return "", err
			}
			var d dump
			dumpPublicKey(&d, "pub", pk)
			return d.String(), nil
		case "pkcs1pub":
			pk, err := x509.ParsePKCS1PublicKey(der)
			if err != nil {
				return "", err
			}
			var d dump
			dumpPublicKey(&d, "pub", pk)
			return d.String(), nil
		}
		if err != nil {
			return "", err
		}
		return dumpPrivate(k), nil
	case "oid":
		o, err := x509.ParseOID(string(f.b("text")))
		if err != nil {
			return "", err
		}
		var d dump
		d.w("string", o.String())
		b, _ := o.MarshalBinary()
		d.h("binary", b)
		t, _ := o.MarshalText()
		d.h("text", t)
		a, ok := asn1OID(o)
		d.w("asn1", fmt.Sprintf("%v|%v", a, ok))
		return d.String(), nil
	case "oid_der":
		var o x509.OID
		if err := o.UnmarshalBinary(f.b("der")); err != nil {
			return "", err
		}
		var d dump
		d.w("string", o.String())
		a, ok := asn1OID(o)
		d.w("asn1", fmt.Sprintf("%v|%v", a, ok))
		d.w("eq_asn1", o.EqualASN1OID(a))
		return d.String(), nil
	case "oid_ints":
		var ints []uint64
		for _, p := range strings.Split(f["ints"], ",") {
			v, _ := strconv.ParseUint(p, 10, 64)
			ints = append(ints, v)
		}
		o, err := x509.OIDFromInts(ints)
		if err != nil {
			return "", err
		}
		var d dump
		d.w("string", o.String())
		b, _ := o.MarshalBinary()
		d.h("binary", b)
		return d.String(), nil
	case "name":
		return nameOp(f)
	case "pem_certs":
		pool := x509.NewCertPool()
		ok := pool.AppendCertsFromPEM(f.b("pem"))
		var d dump
		d.w("ok", ok)
		subs := pool.Subjects()
		d.w("subjects.len", len(subs))
		for i, s := range subs {
			d.h(fmt.Sprintf("subject[%d]", i), s)
		}
		return d.String(), nil
	case "verify":
		return verifyOp(f)
	case "hostname":
		c, err := x509.ParseCertificate(f.b("der"))
		if err != nil {
			return "", err
		}
		var d dump
		for i, h := range f.list("hosts") {
			if err := c.VerifyHostname(string(h)); err != nil {
				d.w(fmt.Sprintf("host[%d]", i), "err:"+hex.EncodeToString([]byte(err.Error())))
			} else {
				d.w(fmt.Sprintf("host[%d]", i), "ok")
			}
		}
		return d.String(), nil
	case "create":
		return createOp(f)
	case "genkey":
		var k any
		var err error
		switch f["kind"] {
		case "p224":
			k, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case "p256":
			k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "p384":
			k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "p521":
			k, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		case "ed25519":
			_, k, err = ed25519.GenerateKey(rand.Reader)
		case "rsa2048":
			k, err = rsa.GenerateKey(rand.Reader, 2048)
		case "rsa3072":
			k, err = rsa.GenerateKey(rand.Reader, 3072)
		case "mldsa44":
			k, err = mldsa.GenerateKey(mldsa.MLDSA44())
		case "mldsa65":
			k, err = mldsa.GenerateKey(mldsa.MLDSA65())
		case "mldsa87":
			k, err = mldsa.GenerateKey(mldsa.MLDSA87())
		case "x25519":
			k, err = ecdh.X25519().GenerateKey(rand.Reader)
		case "p256ecdh":
			k, err = ecdh.P256().GenerateKey(rand.Reader)
		default:
			return "", fmt.Errorf("unknown key kind %q", f["kind"])
		}
		if err != nil {
			return "", err
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return "", err
		}
		var d dump
		d.h("key", der)
		if ek, ok := k.(*ecdsa.PrivateKey); ok {
			if b, err := x509.MarshalECPrivateKey(ek); err == nil {
				d.h("sec1", b)
			}
		}
		if rk, ok := k.(*rsa.PrivateKey); ok {
			d.h("pkcs1", x509.MarshalPKCS1PrivateKey(rk))
		}
		return d.String(), nil
	}
	return "", fmt.Errorf("unknown op %q", f["op"])
}

func asn1OID(o x509.OID) (asn1.ObjectIdentifier, bool) {
	var parsed asn1.ObjectIdentifier
	var ints []int
	s := o.String()
	for _, p := range strings.Split(s, ".") {
		v, err := strconv.Atoi(p)
		if err != nil || v > 1<<31-1 {
			return nil, false
		}
		ints = append(ints, v)
	}
	parsed = ints
	return parsed, true
}

// ---- names ---------------------------------------------------------------

func (f fields) i(key string) int64 {
	v, _ := strconv.ParseInt(f[key], 10, 64)
	return v
}

func (f fields) strs(key string) []string {
	var out []string
	for _, b := range f.list(key) {
		out = append(out, string(b))
	}
	return out
}

func (f fields) text(key string) string { return string(f.b(key)) }

// parseATV parses "oid:kind:hex".
func parseATV(s string) (pkix.AttributeTypeAndValue, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 {
		return pkix.AttributeTypeAndValue{}, fmt.Errorf("bad atv %q", s)
	}
	var oid asn1.ObjectIdentifier
	for _, p := range strings.Split(parts[0], ".") {
		v, _ := strconv.Atoi(p)
		oid = append(oid, v)
	}
	data, _ := hex.DecodeString(parts[2])
	atv := pkix.AttributeTypeAndValue{Type: oid}
	switch parts[1] {
	case "s":
		atv.Value = string(data)
	case "i":
		v, _ := strconv.ParseInt(string(data), 10, 64)
		atv.Value = v
	case "b":
		atv.Value = string(data) == "true"
	case "o":
		atv.Value = data
	case "n":
		atv.Value = nil
	case "oid":
		var o asn1.ObjectIdentifier
		for _, p := range strings.Split(string(data), ".") {
			v, _ := strconv.Atoi(p)
			o = append(o, v)
		}
		atv.Value = o
	case "bs":
		atv.Value = asn1.BitString{Bytes: data[1:], BitLength: int(data[0])}
	case "t":
		v, _ := strconv.ParseInt(string(data), 10, 64)
		atv.Value = time.Unix(v, 0).UTC()
	case "raw":
		atv.Value = asn1.RawValue{FullBytes: data}
	}
	return atv, nil
}

func parseRDNs(spec string) (pkix.RDNSequence, error) {
	var seq pkix.RDNSequence
	if spec == "" {
		return seq, nil
	}
	for _, set := range strings.Split(spec, ";") {
		var rdn pkix.RelativeDistinguishedNameSET
		if set != "-" {
			for _, a := range strings.Split(set, "|") {
				atv, err := parseATV(a)
				if err != nil {
					return nil, err
				}
				rdn = append(rdn, atv)
			}
		}
		seq = append(seq, rdn)
	}
	return seq, nil
}

func nameOp(f fields) (string, error) {
	seq, err := parseRDNs(f["rdns"])
	if err != nil {
		return "", err
	}
	var d dump
	d.h("seq.string", []byte(seq.String()))
	if b, err := asn1.Marshal(seq); err != nil {
		d.w("seq.marshal", "err")
	} else {
		d.h("seq.marshal", b)
	}
	var n pkix.Name
	n.FillFromRDNSequence(&seq)
	dumpName(&d, "filled", n)
	// ExtraNames: every ATV as its own RDN.
	var extra []pkix.AttributeTypeAndValue
	for _, rdn := range seq {
		extra = append(extra, rdn...)
	}
	en := pkix.Name{CommonName: "cn", Country: []string{"US"}, Organization: []string{"o1", "o2"}, ExtraNames: extra}
	if f["noextra"] == "1" {
		en.ExtraNames = nil
	}
	if f["empty_extra"] == "1" {
		en.ExtraNames = []pkix.AttributeTypeAndValue{}
	}
	dumpName(&d, "extra", en)
	return d.String(), nil
}

// ---- keys ----------------------------------------------------------------

func signerFrom(f fields, key string) (crypto.Signer, error) {
	k, err := x509.ParsePKCS8PrivateKey(f.b(key))
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("not a signer: %T", k)
	}
	return s, nil
}

func ipList(items [][]byte) []net.IP {
	var out []net.IP
	for _, b := range items {
		out = append(out, net.IP(b))
	}
	return out
}

func ipNetList(f fields, key string) []*net.IPNet {
	var out []*net.IPNet
	if f[key] == "" {
		return nil
	}
	for _, item := range strings.Split(f[key], ",") {
		ip, mask, _ := strings.Cut(item, "/")
		ipb, _ := hex.DecodeString(ip)
		mb, _ := hex.DecodeString(mask)
		out = append(out, &net.IPNet{IP: ipb, Mask: mb})
	}
	return out
}

func dotted(s string) asn1.ObjectIdentifier {
	var o asn1.ObjectIdentifier
	for _, p := range strings.Split(s, ".") {
		v, _ := strconv.Atoi(p)
		o = append(o, v)
	}
	return o
}

func dottedList(f fields, key string) []asn1.ObjectIdentifier {
	if f[key] == "" {
		return nil
	}
	var out []asn1.ObjectIdentifier
	for _, p := range strings.Split(f[key], ",") {
		out = append(out, dotted(p))
	}
	return out
}

func extList(f fields, key string) []pkix.Extension {
	if f[key] == "" {
		return nil
	}
	var out []pkix.Extension
	for _, item := range strings.Split(f[key], ",") {
		parts := strings.SplitN(item, "|", 3)
		v, _ := hex.DecodeString(parts[2])
		out = append(out, pkix.Extension{Id: dotted(parts[0]), Critical: parts[1] == "true", Value: v})
	}
	return out
}

func urlList(f fields, key string) []*url.URL {
	var out []*url.URL
	for _, s := range f.strs(key) {
		u, err := url.Parse(s)
		if err != nil {
			panic(err)
		}
		out = append(out, u)
	}
	return out
}

func subjectFromSpec(f fields) pkix.Name {
	n := pkix.Name{
		CommonName:         f.text("cn"),
		SerialNumber:       f.text("sn"),
		Country:            f.strs("c"),
		Organization:       f.strs("o"),
		OrganizationalUnit: f.strs("ou"),
		Locality:           f.strs("l"),
		Province:           f.strs("st"),
		StreetAddress:      f.strs("street"),
		PostalCode:         f.strs("postal"),
	}
	if f["xnames"] != "" {
		for _, a := range strings.Split(f["xnames"], "|") {
			atv, _ := parseATV(a)
			n.ExtraNames = append(n.ExtraNames, atv)
		}
	}
	return n
}

func templateFromSpec(f fields) *x509.Certificate {
	t := &x509.Certificate{}
	if f["serial"] != "" {
		t.SerialNumber, _ = new(big.Int).SetString(f["serial"], 10)
	}
	t.NotBefore = time.Unix(f.i("nb"), 0)
	t.NotAfter = time.Unix(f.i("na"), 0)
	t.Subject = subjectFromSpec(f)
	if f["rawsubject"] != "" {
		t.RawSubject = f.b("rawsubject")
	}
	t.KeyUsage = x509.KeyUsage(f.i("ku"))
	if f["eku"] != "" {
		for _, p := range strings.Split(f["eku"], ",") {
			v, _ := strconv.Atoi(p)
			t.ExtKeyUsage = append(t.ExtKeyUsage, x509.ExtKeyUsage(v))
		}
	}
	t.UnknownExtKeyUsage = dottedList(f, "ueku")
	if f["bc"] != "" {
		p := strings.Split(f["bc"], ":")
		t.BasicConstraintsValid = p[0] == "true"
		t.IsCA = p[1] == "true"
		t.MaxPathLen, _ = strconv.Atoi(p[2])
		t.MaxPathLenZero = p[3] == "true"
	}
	t.SubjectKeyId = f.b("skid")
	t.AuthorityKeyId = f.b("akid")
	t.OCSPServer = f.strs("ocsp")
	t.IssuingCertificateURL = f.strs("issuing")
	t.DNSNames = f.strs("dns")
	t.EmailAddresses = f.strs("email")
	t.IPAddresses = ipList(f.list("ip"))
	t.URIs = urlList(f, "uri")
	t.PermittedDNSDomainsCritical = f["pdc"] == "true"
	t.PermittedDNSDomains = f.strs("pdns")
	t.ExcludedDNSDomains = f.strs("edns")
	t.PermittedIPRanges = ipNetList(f, "pip")
	t.ExcludedIPRanges = ipNetList(f, "eip")
	t.PermittedEmailAddresses = f.strs("pemail")
	t.ExcludedEmailAddresses = f.strs("eemail")
	t.PermittedURIDomains = f.strs("puri")
	t.ExcludedURIDomains = f.strs("euri")
	t.CRLDistributionPoints = f.strs("crldp")
	t.PolicyIdentifiers = dottedList(f, "polids")
	for _, p := range strings.Split(f["pols"], ",") {
		if p == "" {
			continue
		}
		o, err := x509.ParseOID(p)
		if err != nil {
			panic(err)
		}
		t.Policies = append(t.Policies, o)
	}
	t.ExtraExtensions = extList(f, "extra")
	t.SignatureAlgorithm = x509.SignatureAlgorithm(f.i("sigalg"))
	return t
}

func createOp(f fields) (string, error) {
	switch f["what"] {
	case "cert":
		signer, err := signerFrom(f, "key")
		if err != nil {
			return "", err
		}
		tmpl := templateFromSpec(f)
		parent := tmpl
		if f["parent"] != "" {
			parent, err = x509.ParseCertificate(f.b("parent"))
			if err != nil {
				return "", err
			}
		}
		var pub any = signer.Public()
		if f["pub"] != "" {
			pub, err = x509.ParsePKIXPublicKey(f.b("pub"))
			if err != nil {
				return "", err
			}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			return "", err
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", fmt.Errorf("created certificate does not parse: %v", err)
		}
		var d dump
		d.h("der", der)
		d.h("tbs", c.RawTBSCertificate)
		return d.String(), nil
	case "csr":
		signer, err := signerFrom(f, "key")
		if err != nil {
			return "", err
		}
		t := &x509.CertificateRequest{
			Subject:            subjectFromSpec(f),
			DNSNames:           f.strs("dns"),
			EmailAddresses:     f.strs("email"),
			IPAddresses:        ipList(f.list("ip")),
			URIs:               urlList(f, "uri"),
			ExtraExtensions:    extList(f, "extra"),
			SignatureAlgorithm: x509.SignatureAlgorithm(f.i("sigalg")),
		}
		if f["rawsubject"] != "" {
			t.RawSubject = f.b("rawsubject")
		}
		if f["attrs"] != "" {
			// attrs=oid;set/set+oid;set where a set is atv|atv
			for _, a := range strings.Split(f["attrs"], "+") {
				oid, rest, _ := strings.Cut(a, ";")
				attr := pkix.AttributeTypeAndValueSET{Type: dotted(oid)}
				for _, set := range strings.Split(rest, "/") {
					var vs []pkix.AttributeTypeAndValue
					for _, x := range strings.Split(set, "|") {
						atv, _ := parseATV(x)
						vs = append(vs, atv)
					}
					attr.Value = append(attr.Value, vs)
				}
				t.Attributes = append(t.Attributes, attr)
			}
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, t, signer)
		if err != nil {
			return "", err
		}
		c, err := x509.ParseCertificateRequest(der)
		if err != nil {
			return "", fmt.Errorf("created request does not parse: %v", err)
		}
		var d dump
		d.h("der", der)
		d.h("tbs", c.RawTBSCertificateRequest)
		return d.String(), nil
	case "crl":
		signer, err := signerFrom(f, "key")
		if err != nil {
			return "", err
		}
		issuer, err := x509.ParseCertificate(f.b("issuer"))
		if err != nil {
			return "", err
		}
		n, _ := new(big.Int).SetString(f["number"], 10)
		t := &x509.RevocationList{
			Number:             n,
			ThisUpdate:         time.Unix(f.i("this"), 0),
			NextUpdate:         time.Unix(f.i("next"), 0),
			ExtraExtensions:    extList(f, "extra"),
			SignatureAlgorithm: x509.SignatureAlgorithm(f.i("sigalg")),
		}
		if f["entries"] != "" {
			for _, e := range strings.Split(f["entries"], ",") {
				p := strings.Split(e, ":")
				sn, _ := new(big.Int).SetString(p[0], 10)
				ts, _ := strconv.ParseInt(p[1], 10, 64)
				rc, _ := strconv.Atoi(p[2])
				t.RevokedCertificateEntries = append(t.RevokedCertificateEntries, x509.RevocationListEntry{
					SerialNumber: sn, RevocationTime: time.Unix(ts, 0), ReasonCode: rc,
				})
			}
		}
		if f["dep"] == "1" {
			for _, e := range t.RevokedCertificateEntries {
				t.RevokedCertificates = append(t.RevokedCertificates, pkix.RevokedCertificate{SerialNumber: e.SerialNumber, RevocationTime: e.RevocationTime})
			}
			t.RevokedCertificateEntries = nil
		}
		der, err := x509.CreateRevocationList(rand.Reader, t, issuer, signer)
		if err != nil {
			return "", err
		}
		rl, err := x509.ParseRevocationList(der)
		if err != nil {
			return "", fmt.Errorf("created list does not parse: %v", err)
		}
		var d dump
		d.h("der", der)
		d.h("tbs", rl.RawTBSRevocationList)
		d.w("sigcheck", rl.CheckSignatureFrom(issuer) == nil)
		return d.String(), nil
	case "old_crl":
		signer, err := signerFrom(f, "key")
		if err != nil {
			return "", err
		}
		issuer, err := x509.ParseCertificate(f.b("issuer"))
		if err != nil {
			return "", err
		}
		var revoked []pkix.RevokedCertificate
		if f["entries"] != "" {
			for _, e := range strings.Split(f["entries"], ",") {
				p := strings.Split(e, ":")
				sn, _ := new(big.Int).SetString(p[0], 10)
				ts, _ := strconv.ParseInt(p[1], 10, 64)
				revoked = append(revoked, pkix.RevokedCertificate{SerialNumber: sn, RevocationTime: time.Unix(ts, 0)})
			}
		}
		der, err := issuer.CreateCRL(rand.Reader, signer, revoked, time.Unix(f.i("this"), 0), time.Unix(f.i("next"), 0))
		if err != nil {
			return "", err
		}
		cl, err := x509.ParseDERCRL(der)
		if err != nil {
			return "", fmt.Errorf("created old list does not parse: %v", err)
		}
		var d dump
		d.h("der", der)
		d.h("tbs", cl.TBSCertList.Raw)
		return d.String(), nil
	case "key":
		// Re-marshal a key in every form.
		k, err := x509.ParsePKCS8PrivateKey(f.b("key"))
		if err != nil {
			return "", err
		}
		return dumpPrivate(k), nil
	}
	return "", fmt.Errorf("unknown create target %q", f["what"])
}

// ---- verification --------------------------------------------------------

func verifyOp(f fields) (string, error) {
	leaf, err := x509.ParseCertificate(f.b("leaf"))
	if err != nil {
		return "", err
	}
	inters := x509.NewCertPool()
	var all [][]byte
	all = append(all, leaf.Raw)
	for _, der := range f.list("inter") {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", err
		}
		inters.AddCert(c)
		all = append(all, c.Raw)
	}
	roots := x509.NewCertPool()
	for _, der := range f.list("roots") {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return "", err
		}
		roots.AddCert(c)
		all = append(all, c.Raw)
	}
	opts := x509.VerifyOptions{
		DNSName:       f.text("dns"),
		Intermediates: inters,
		Roots:         roots,
		CurrentTime:   time.Unix(f.i("time"), 0).UTC(),
	}
	if f["ekus"] != "" {
		for _, p := range strings.Split(f["ekus"], ",") {
			v, _ := strconv.Atoi(p)
			opts.KeyUsages = append(opts.KeyUsages, x509.ExtKeyUsage(v))
		}
	}
	for _, p := range strings.Split(f["policies"], ",") {
		if p == "" {
			continue
		}
		o, err := x509.ParseOID(p)
		if err != nil {
			return "", err
		}
		opts.CertificatePolicies = append(opts.CertificatePolicies, o)
	}
	chains, err := leaf.Verify(opts)
	var d dump
	if err != nil {
		d.h("err", []byte(err.Error()))
		et := fmt.Sprintf("%T", err)
		if !strings.HasPrefix(et, "x509.") {
			et = "other"
		}
		d.w("errtype", et)
		return d.String(), nil
	}
	d.w("chains", len(chains))
	for i, chain := range chains {
		var idx []string
		for _, c := range chain {
			n := -1
			for j, raw := range all {
				if bytes.Equal(raw, c.Raw) {
					n = j
					break
				}
			}
			idx = append(idx, strconv.Itoa(n))
		}
		d.w(fmt.Sprintf("chain[%d]", i), strings.Join(idx, ","))
	}
	return d.String(), nil
}

var _ = bytes.Equal
var _ = elliptic.P256
var _ = big.NewInt
var _ = pem.Decode

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 1<<28)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		f := parse(in.Text())
		res, err := run(f)
		if err != nil {
			fmt.Fprintf(out, "err=%s\n", hex.EncodeToString([]byte(err.Error())))
		} else {
			fmt.Fprintf(out, "dump=%s\n", hex.EncodeToString([]byte(res)))
		}
	}
}
