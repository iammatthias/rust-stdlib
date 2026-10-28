// Regenerate public, test-only certificate fixtures using Go's stdlib.
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
 "path/filepath"
 "time"
)
func must(err error) { if err!=nil { panic(err) } }
func save(name string, bytes []byte) { must(os.WriteFile(filepath.Join("tests/fixtures",name+".hex"),[]byte(hex.EncodeToString(bytes)+"\n"),0644)) }
func main() {
 must(os.MkdirAll("tests/fixtures",0755))
 caKey,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader); must(e)
 start:=time.Date(2020,1,1,0,0,0,0,time.UTC); end:=time.Date(2050,1,1,0,0,0,0,time.UTC)
 ca:=&x509.Certificate{SerialNumber:big.NewInt(1),Subject:pkix.Name{CommonName:"rust-stdlib TEST ONLY CA"},NotBefore:start,NotAfter:end,IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature}
 caDer,e:=x509.CreateCertificate(rand.Reader,ca,ca,&caKey.PublicKey,caKey); must(e); save("ca",caDer)
 ca,e=x509.ParseCertificate(caDer); must(e)
 for i,name:=range []string{"server","expired","wrong-host"} {
  key,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader); must(e)
  cert:=&x509.Certificate{SerialNumber:big.NewInt(int64(i+2)),Subject:pkix.Name{CommonName:"public test fixture"},NotBefore:start,NotAfter:end,KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},DNSNames:[]string{"localhost"},IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")}}
  if name=="expired" { cert.NotBefore=time.Date(2000,1,1,0,0,0,0,time.UTC); cert.NotAfter=time.Date(2001,1,1,0,0,0,0,time.UTC) }
  if name=="wrong-host" { cert.DNSNames=[]string{"example.invalid"}; cert.IPAddresses=nil }
  der,e:=x509.CreateCertificate(rand.Reader,cert,ca,&key.PublicKey,caKey); must(e); save(name,der)
  pkcs8,e:=x509.MarshalPKCS8PrivateKey(key); must(e); save(name+"-key",pkcs8)
 }
}
