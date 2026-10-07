// Command ctv-demo 在本地内存中构造根/中间/叶子证书、名称约束与吊销数据，
// 然后演示证书链校验、吊销判定与热更新。全程不访问网络、不读取真实凭据。
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"os"
	"time"

	ctv "github.com/lechandonga/certificate-trust-validator-go"
)

func main() {
	now := time.Now()
	root, rootKey := mustCA("Demo Root", nil, nil, now.Add(10*365*24*time.Hour))
	inter, interKey := mustCA("Demo Intermediate", root, rootKey, now.Add(5*365*24*time.Hour))
	leaf := mustLeaf("demo.local", inter, interKey, []string{"demo.local", "*.demo.local"}, now.Add(90*24*time.Hour))

	store := ctv.NewTrustStore()
	store.AddAnchor(root)
	store.AddIntermediate(inter)

	rev := ctv.NewMemoryRevocationSource()
	store.SetRevocationSources(rev)

	v := ctv.NewValidator(store, ctv.Config{
		EnableRevocation:  true,
		RequireRevocation: false,
		RevocationPolicy:  ctv.RevocationHardFail,
		ExtKeyUsage:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	run := func(host string) {
		res, err := v.Verify(ctv.VerifyOptions{Leaf: leaf, Hostname: host, Time: now})
		if err != nil {
			fmt.Printf("[%-18s] 拒绝: %v\n", host, err)
			return
		}
		fmt.Printf("[%-18s] 通过: 链长度=%d 信任库版本=%d\n", host, len(res.Chain.Certs), res.StoreVer)
	}

	fmt.Println("== 1. 基本校验与主机名 ==")
	run("demo.local")
	run("app.demo.local")
	run("a.b.demo.local") // 通配符不跨标签，拒绝
	run("other.example")

	fmt.Println("== 2. 吊销热更新 ==")
	run("demo.local")
	rev.Replace(map[string]map[string]ctv.RevocationEntry{
		inter.Subject.String(): {leaf.SerialNumber.Text(16): {Revoked: true}},
	})
	run("demo.local")

	fmt.Println("== 3. 信任锚热更新 ==")
	store.RemoveAnchor(root)
	run("demo.local")
	store.AddAnchor(root)
	run("demo.local")

	os.Exit(0)
}

func key() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func mustCA(cn string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	k := key()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	signerCert, signerKey := tmpl, k
	if issuer != nil {
		signerCert, signerKey = issuer, issuerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &k.PublicKey, signerKey)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c, k
}

func mustLeaf(cn string, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, dns []string, notAfter time.Time) *x509.Certificate {
	k := key()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &k.PublicKey, issuerKey)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}
