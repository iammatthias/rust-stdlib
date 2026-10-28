// Go reference implementation for tools/crypto_asym_check.py.
//
// Reads one case per line as space-separated key=value tokens (byte strings are
// hex) and writes one line of name=value tokens per case: the op's outputs, or
// err=1 when Go returns an error or panics. The Rust probe in
// crates/crypto/examples/crypto_asym_probe.rs implements the same protocol.
package main

import (
	"bufio"
	"crypto"
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"hash"
	"math/big"
	"os"
	"strings"
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

func (f fields) n(key string) *big.Int {
	v, ok := new(big.Int).SetString(f[key], 16)
	if !ok {
		return new(big.Int)
	}
	return v
}

func (f fields) i(key string) int {
	var v int
	fmt.Sscanf(f[key], "%d", &v)
	return v
}

type out map[string]string

func x(b []byte) string { return hex.EncodeToString(b) }

func bn(v *big.Int) string { return x(v.Bytes()) }

func hashOf(name string) crypto.Hash {
	switch name {
	case "sha1":
		return crypto.SHA1
	case "sha224":
		return crypto.SHA224
	case "sha256":
		return crypto.SHA256
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	case "sha512_256":
		return crypto.SHA512_256
	case "sha3_256":
		return crypto.SHA3_256
	}
	panic("hash " + name)
}

func digest(name string, msg []byte) []byte {
	var h hash.Hash
	switch name {
	case "sha1":
		h = sha1.New()
	case "sha224":
		h = sha256.New224()
	case "sha256":
		h = sha256.New()
	case "sha384":
		h = sha512.New384()
	case "sha512":
		h = sha512.New()
	case "sha512_256":
		h = sha512.New512_256()
	case "sha3_256":
		h = sha3.New256()
	default:
		panic("hash " + name)
	}
	h.Write(msg)
	return h.Sum(nil)
}

func curveOf(name string) elliptic.Curve {
	switch name {
	case "p224":
		return elliptic.P224()
	case "p256":
		return elliptic.P256()
	case "p384":
		return elliptic.P384()
	case "p521":
		return elliptic.P521()
	}
	panic("curve " + name)
}

func ecdhCurve(name string) ecdh.Curve {
	switch name {
	case "p256":
		return ecdh.P256()
	case "p384":
		return ecdh.P384()
	case "p521":
		return ecdh.P521()
	case "x25519":
		return ecdh.X25519()
	}
	panic("curve " + name)
}

func rsaKey(f fields) *rsa.PrivateKey {
	k, err := x509.ParsePKCS1PrivateKey(f.b("key"))
	if err != nil {
		panic(err)
	}
	return k
}

func okOf(ok bool) string {
	if ok {
		return "1"
	}
	return "0"
}

func mlkemDecaps(param string, seed, ct []byte) ([]byte, error) {
	if param == "768" {
		dk, err := mlkem.NewDecapsulationKey768(seed)
		if err != nil {
			return nil, err
		}
		return dk.Decapsulate(ct)
	}
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, err
	}
	return dk.Decapsulate(ct)
}

func mldsaParams(p string) mldsa.Parameters {
	switch p {
	case "44":
		return mldsa.MLDSA44()
	case "65":
		return mldsa.MLDSA65()
	}
	return mldsa.MLDSA87()
}

func dsaKey(f fields) *dsa.PrivateKey {
	return &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{Parameters: dsa.Parameters{P: f.n("p"), Q: f.n("q"), G: f.n("g")}, Y: f.n("y")},
		X:         f.n("x"),
	}
}

func hpkeSuite(f fields) (hpke.KEM, hpke.KDF, hpke.AEAD) {
	var kem hpke.KEM
	switch f["kem"] {
	case "p256":
		kem = hpke.DHKEM(ecdh.P256())
	case "p384":
		kem = hpke.DHKEM(ecdh.P384())
	case "p521":
		kem = hpke.DHKEM(ecdh.P521())
	default:
		kem = hpke.DHKEM(ecdh.X25519())
	}
	kdf, err := hpke.NewKDF(uint16(f.i("kdf")))
	if err != nil {
		panic(err)
	}
	aead, err := hpke.NewAEAD(uint16(f.i("aead")))
	if err != nil {
		panic(err)
	}
	return kem, kdf, aead
}

func run(f fields) out {
	o := out{}
	switch f["op"] {
	case "ed_keygen":
		k := ed25519.NewKeyFromSeed(f.b("seed"))
		o["pub"] = x(k.Public().(ed25519.PublicKey))
		o["priv"] = x(k)
	case "ed_sign":
		k := ed25519.NewKeyFromSeed(f.b("seed"))
		msg := f.b("msg")
		opts := &ed25519.Options{Context: string(f.b("ctx"))}
		if f["mode"] == "ph" {
			opts.Hash = crypto.SHA512
			h := sha512.Sum512(msg)
			msg = h[:]
		}
		sig, err := k.Sign(nil, msg, opts)
		if err != nil {
			panic(err)
		}
		o["sig"] = x(sig)
	case "ed_verify":
		msg := f.b("msg")
		opts := &ed25519.Options{Context: string(f.b("ctx"))}
		if f["mode"] == "ph" {
			opts.Hash = crypto.SHA512
			h := sha512.Sum512(msg)
			msg = h[:]
		}
		err := ed25519.VerifyWithOptions(ed25519.PublicKey(f.b("pub")), msg, f.b("sig"), opts)
		o["ok"] = okOf(err == nil)
	case "ecdh":
		c := ecdhCurve(f["curve"])
		priv, err := c.NewPrivateKey(f.b("priv"))
		if err != nil {
			panic(err)
		}
		o["pub"] = x(priv.PublicKey().Bytes())
		pub, err := c.NewPublicKey(f.b("peer"))
		if err != nil {
			panic(err)
		}
		shared, err := priv.ECDH(pub)
		if err != nil {
			panic(err)
		}
		o["shared"] = x(shared)
	case "ecdh_pub":
		priv, err := ecdhCurve(f["curve"]).NewPrivateKey(f.b("priv"))
		if err != nil {
			panic(err)
		}
		o["pub"] = x(priv.PublicKey().Bytes())
	case "ec_pub":
		c := curveOf(f["curve"])
		d := f.b("d")
		px, py := c.ScalarBaseMult(d)
		o["x"], o["y"] = bn(px), bn(py)
		priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: px, Y: py}, D: new(big.Int).SetBytes(d)}
		bytes, err := priv.Bytes()
		if err != nil {
			panic(err)
		}
		o["raw"] = x(bytes)
	case "ec_det", "ec_sign":
		c := curveOf(f["curve"])
		d := new(big.Int).SetBytes(f.b("d"))
		px, py := c.ScalarBaseMult(d.Bytes())
		priv := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: c, X: px, Y: py}, D: d}
		dg := f.b("digest")
		var sig []byte
		var err error
		if f["op"] == "ec_det" {
			sig, err = priv.Sign(nil, dg, hashOf(f["hash"]))
		} else {
			sig, err = ecdsa.SignASN1(rand.Reader, priv, dg)
		}
		if err != nil {
			panic(err)
		}
		o["sig"] = x(sig)
		o["x"], o["y"] = bn(px), bn(py)
	case "ec_verify":
		c := curveOf(f["curve"])
		pub := &ecdsa.PublicKey{Curve: c, X: f.n("x"), Y: f.n("y")}
		o["ok"] = okOf(ecdsa.VerifyASN1(pub, f.b("digest"), f.b("sig")))
	case "el_basemult":
		c := curveOf(f["curve"])
		px, py := c.ScalarBaseMult(f.b("k"))
		o["x"], o["y"] = bn(px), bn(py)
	case "el_mult":
		c := curveOf(f["curve"])
		px, py := c.ScalarMult(f.n("x"), f.n("y"), f.b("k"))
		o["x"], o["y"] = bn(px), bn(py)
	case "el_add":
		c := curveOf(f["curve"])
		px, py := c.Add(f.n("x"), f.n("y"), f.n("x2"), f.n("y2"))
		o["x"], o["y"] = bn(px), bn(py)
	case "el_double":
		c := curveOf(f["curve"])
		px, py := c.Double(f.n("x"), f.n("y"))
		o["x"], o["y"] = bn(px), bn(py)
	case "el_unmarshal", "el_unmarshalc":
		c := curveOf(f["curve"])
		var px, py *big.Int
		if f["op"] == "el_unmarshal" {
			px, py = elliptic.Unmarshal(c, f.b("data"))
		} else {
			px, py = elliptic.UnmarshalCompressed(c, f.b("data"))
		}
		if px == nil {
			panic("invalid")
		}
		o["x"], o["y"] = bn(px), bn(py)
		o["m"] = x(elliptic.Marshal(c, px, py))
		o["mc"] = x(elliptic.MarshalCompressed(c, px, py))
	case "rsa_gen":
		k, err := rsa.GenerateKey(rand.Reader, f.i("bits"))
		if err != nil {
			panic(err)
		}
		o["key"] = x(x509.MarshalPKCS1PrivateKey(k))
	case "rsa_p1_sign":
		sig, err := rsa.SignPKCS1v15(nil, rsaKey(f), hashOf(f["hash"]), f.b("digest"))
		if err != nil {
			panic(err)
		}
		o["sig"] = x(sig)
	case "rsa_p1_verify":
		err := rsa.VerifyPKCS1v15(&rsaKey(f).PublicKey, hashOf(f["hash"]), f.b("digest"), f.b("sig"))
		o["ok"] = okOf(err == nil)
	case "rsa_pss_sign":
		sig, err := rsa.SignPSS(rand.Reader, rsaKey(f), hashOf(f["hash"]), f.b("digest"),
			&rsa.PSSOptions{SaltLength: f.i("salt")})
		if err != nil {
			panic(err)
		}
		o["sig"] = x(sig)
	case "rsa_pss_verify":
		err := rsa.VerifyPSS(&rsaKey(f).PublicKey, hashOf(f["hash"]), f.b("digest"), f.b("sig"),
			&rsa.PSSOptions{SaltLength: f.i("salt")})
		o["ok"] = okOf(err == nil)
	case "rsa_oaep_enc":
		ct, err := rsa.EncryptOAEPWithOptions(rand.Reader, &rsaKey(f).PublicKey, f.b("msg"),
			&rsa.OAEPOptions{Hash: hashOf(f["hash"]), MGFHash: hashOf(f["mgf"]), Label: f.b("label")})
		if err != nil {
			panic(err)
		}
		o["ct"] = x(ct)
	case "rsa_oaep_dec":
		pt, err := rsaKey(f).Decrypt(nil, f.b("ct"),
			&rsa.OAEPOptions{Hash: hashOf(f["hash"]), MGFHash: hashOf(f["mgf"]), Label: f.b("label")})
		if err != nil {
			panic(err)
		}
		o["msg"] = x(pt)
	case "rsa_p1_enc":
		ct, err := rsa.EncryptPKCS1v15(rand.Reader, &rsaKey(f).PublicKey, f.b("msg"))
		if err != nil {
			panic(err)
		}
		o["ct"] = x(ct)
	case "rsa_p1_dec":
		pt, err := rsa.DecryptPKCS1v15(nil, rsaKey(f), f.b("ct"))
		if err != nil {
			panic(err)
		}
		o["msg"] = x(pt)
	case "mk_ek":
		if f["param"] == "768" {
			dk, err := mlkem.NewDecapsulationKey768(f.b("seed"))
			if err != nil {
				panic(err)
			}
			o["ek"] = x(dk.EncapsulationKey().Bytes())
		} else {
			dk, err := mlkem.NewDecapsulationKey1024(f.b("seed"))
			if err != nil {
				panic(err)
			}
			o["ek"] = x(dk.EncapsulationKey().Bytes())
		}
	case "mk_dec":
		k, err := mlkemDecaps(f["param"], f.b("seed"), f.b("ct"))
		if err != nil {
			panic(err)
		}
		o["k"] = x(k)
	case "mk_enc":
		var k, c []byte
		var err error
		if f["param"] == "768" {
			ek, e := mlkem.NewEncapsulationKey768(f.b("ek"))
			if e != nil {
				panic(e)
			}
			k, c, err = mlkemtest.Encapsulate768(ek, f.b("m"))
		} else {
			ek, e := mlkem.NewEncapsulationKey1024(f.b("ek"))
			if e != nil {
				panic(e)
			}
			k, c, err = mlkemtest.Encapsulate1024(ek, f.b("m"))
		}
		if err != nil {
			panic(err)
		}
		o["k"], o["c"] = x(k), x(c)
	case "mk_encr":
		if f["param"] == "768" {
			ek, err := mlkem.NewEncapsulationKey768(f.b("ek"))
			if err != nil {
				panic(err)
			}
			k, c := ek.Encapsulate()
			o["k"], o["c"] = x(k), x(c)
		} else {
			ek, err := mlkem.NewEncapsulationKey1024(f.b("ek"))
			if err != nil {
				panic(err)
			}
			k, c := ek.Encapsulate()
			o["k"], o["c"] = x(k), x(c)
		}
	case "md_pub":
		k, err := mldsa.NewPrivateKey(mldsaParams(f["param"]), f.b("seed"))
		if err != nil {
			panic(err)
		}
		o["pub"] = x(k.PublicKey().Bytes())
	case "md_sign", "md_sign_rand":
		k, err := mldsa.NewPrivateKey(mldsaParams(f["param"]), f.b("seed"))
		if err != nil {
			panic(err)
		}
		opts := &mldsa.Options{Context: string(f.b("ctx"))}
		var sig []byte
		if f["op"] == "md_sign" {
			sig, err = k.SignDeterministic(f.b("msg"), opts)
		} else {
			sig, err = k.Sign(nil, f.b("msg"), opts)
		}
		if err != nil {
			panic(err)
		}
		o["sig"] = x(sig)
		o["pub"] = x(k.PublicKey().Bytes())
	case "md_verify":
		pk, err := mldsa.NewPublicKey(mldsaParams(f["param"]), f.b("pub"))
		if err != nil {
			panic(err)
		}
		err = mldsa.Verify(pk, f.b("msg"), f.b("sig"), &mldsa.Options{Context: string(f.b("ctx"))})
		o["ok"] = okOf(err == nil)
	case "dsa_sign":
		r, s, err := dsa.Sign(rand.Reader, dsaKey(f), f.b("digest"))
		if err != nil {
			panic(err)
		}
		o["r"], o["s"] = bn(r), bn(s)
	case "dsa_verify":
		k := dsaKey(f)
		o["ok"] = okOf(dsa.Verify(&k.PublicKey, f.b("digest"), f.n("r"), f.n("s")))
	case "hp_seal":
		kem, kdf, aead := hpkeSuite(f)
		var pk hpke.PublicKey
		var sk hpke.PrivateKey
		var err error
		if f["pub"] != "" {
			pk, err = kem.NewPublicKey(f.b("pub"))
		} else {
			sk, err = kem.GenerateKey()
			if err == nil {
				pk = sk.PublicKey()
				b, _ := sk.Bytes()
				o["sk"] = x(b)
				o["pub"] = x(pk.Bytes())
			}
		}
		if err != nil {
			panic(err)
		}
		enc, s, err := hpke.NewSender(pk, kdf, aead, f.b("info"))
		if err != nil {
			panic(err)
		}
		o["enc"] = x(enc)
		if f.i("aead") != 65535 {
			ct, err := s.Seal(f.b("aad"), f.b("pt"))
			if err != nil {
				panic(err)
			}
			o["ct"] = x(ct)
		}
		e, err := s.Export(string(f.b("ectx")), f.i("elen"))
		if err != nil {
			panic(err)
		}
		o["exp"] = x(e)
	case "hp_open":
		kem, kdf, aead := hpkeSuite(f)
		sk, err := kem.NewPrivateKey(f.b("sk"))
		if err != nil {
			panic(err)
		}
		r, err := hpke.NewRecipient(f.b("enc"), sk, kdf, aead, f.b("info"))
		if err != nil {
			panic(err)
		}
		if f.i("aead") != 65535 {
			pt, err := r.Open(f.b("aad"), f.b("ct"))
			if err != nil {
				panic(err)
			}
			o["pt"] = x(pt)
		}
		e, err := r.Export(string(f.b("ectx")), f.i("elen"))
		if err != nil {
			panic(err)
		}
		o["exp"] = x(e)
	default:
		panic("unknown op " + f["op"])
	}
	return o
}

func safe(f fields) (o out) {
	defer func() {
		if r := recover(); r != nil {
			o = out{"err": "1"}
		}
	}()
	return run(f)
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1<<20), 1<<26)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()
	for scanner.Scan() {
		o := safe(parse(scanner.Text()))
		keys := make([]string, 0, len(o))
		for k := range o {
			keys = append(keys, k)
		}
		// Stable order.
		for i := range keys {
			for j := i + 1; j < len(keys); j++ {
				if keys[j] < keys[i] {
					keys[i], keys[j] = keys[j], keys[i]
				}
			}
		}
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+o[k])
		}
		fmt.Fprintln(writer, strings.Join(parts, " "))
	}
}
