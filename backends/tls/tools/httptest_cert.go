// Regenerate the public, test-only certificate used by httptest TLS servers.
//
// Go's own httptest certificate (net/http/internal/testcert) is a CA
// certificate; rustls/webpki rejects a CA certificate used as an end
// entity, so this generates the equivalent self-signed end-entity
// certificate: SANs 127.0.0.1, ::1, example.com and *.example.com, valid
// from 1970-01-01 until 2084-01-29 16:00 UTC like Go's. Run from
// backends/tls:
//
//	go run tools/httptest_cert.go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"os"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Acme Co"}},
		NotBefore:             time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2084, 1, 29, 16, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              []string{"example.com", "*.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	must(err)
	must(os.WriteFile("src/httptest_cert.hex", []byte(hex.EncodeToString(der)+"\n"), 0o644))
	must(os.WriteFile("src/httptest_key.hex", []byte(hex.EncodeToString(pkcs8)+"\n"), 0o644))
}
