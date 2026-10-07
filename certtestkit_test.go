package ctv

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"time"
)

type testKey struct {
	priv *ecdsa.PrivateKey
}

func mustKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

var serialCounter int64

func nextSerial() *big.Int {
	serialCounter++
	return big.NewInt(serialCounter)
}

// certSpec 描述一张待签发证书的关键字段。
type certSpec struct {
	commonName       string
	org              string
	isCA             bool
	maxPathLen       int
	maxPathLenZero   bool
	dnsNames         []string
	ips              []net.IP
	emails           []string
	notBefore        time.Time
	notAfter         time.Time
	keyUsage         x509.KeyUsage
	extKeyUsage      []x509.ExtKeyUsage
	excludeDNS       []string
	permitDNS        []string
	excludeIP        []*net.IPNet
	permitIP         []*net.IPNet
	excludeEmail     []string
	permitEmail      []string
	unknownCritical  bool
	subjectKeyID     []byte
	serial           *big.Int
	basicConstraints bool // 是否包含 basic constraints 扩展
}

func defaultCA(spec *certSpec) {
	spec.isCA = true
	spec.basicConstraints = true
	spec.keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if spec.maxPathLen == 0 && !spec.maxPathLenZero {
		spec.maxPathLen = -1
	}
}

// issue 按 spec 构造证书并用 issuer 签发；issuer 为 nil 表示自签名根。
func issue(issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, spec certSpec) (*x509.Certificate, *ecdsa.PrivateKey) {
	key := mustKey()
	tmpl := &x509.Certificate{
		SerialNumber:                spec.serial,
		Subject:                     pkix.Name{CommonName: spec.commonName, Organization: []string{spec.org}},
		NotBefore:                   spec.notBefore,
		NotAfter:                    spec.notAfter,
		KeyUsage:                    spec.keyUsage,
		ExtKeyUsage:                 spec.extKeyUsage,
		BasicConstraintsValid:       spec.basicConstraints,
		IsCA:                        spec.isCA,
		MaxPathLen:                  spec.maxPathLen,
		MaxPathLenZero:              spec.maxPathLenZero,
		DNSNames:                    spec.dnsNames,
		IPAddresses:                 spec.ips,
		EmailAddresses:              spec.emails,
		PermittedDNSDomainsCritical: false,
		PermittedDNSDomains:         spec.permitDNS,
		ExcludedDNSDomains:          spec.excludeDNS,
		PermittedIPRanges:           spec.permitIP,
		ExcludedIPRanges:            spec.excludeIP,
		PermittedEmailAddresses:     spec.permitEmail,
		ExcludedEmailAddresses:      spec.excludeEmail,
	}
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = nextSerial()
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	}
	if spec.unknownCritical {
		// 1.2.3.4.5.6.7 是验证器不认识的 OID；标记为 critical。
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:       asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7},
			Critical: true,
			Value:    []byte{0x04, 0x01, 0x00},
		})
	}
	signerCert := issuer
	signerKey := issuerKey
	if issuer == nil {
		signerCert = tmpl
		signerKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c, key
}

func rootSpec(cn string) certSpec {
	s := certSpec{commonName: cn, notBefore: time.Now().Add(-time.Hour),
		notAfter: time.Now().Add(10 * 365 * 24 * time.Hour)}
	defaultCA(&s)
	return s
}

func caSpec(cn string) certSpec {
	s := certSpec{commonName: cn, notBefore: time.Now().Add(-time.Hour),
		notAfter: time.Now().Add(5 * 365 * 24 * time.Hour)}
	defaultCA(&s)
	return s
}

func leafSpec(cn string, dns ...string) certSpec {
	return certSpec{
		commonName:  cn,
		dnsNames:    dns,
		keyUsage:    x509.KeyUsageDigitalSignature,
		extKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		notBefore:   time.Now().Add(-time.Hour),
		notAfter:    time.Now().Add(90 * 24 * time.Hour),
	}
}

// issueCRL 用 CA 私钥生成包含 revokedSerials 的 DER CRL。
func issueCRL(ca *x509.Certificate, caKey *ecdsa.PrivateKey, revokedSerials []*big.Int,
	thisUpdate, nextUpdate time.Time) []byte {
	var revoked []pkix.RevokedCertificate
	for _, s := range revokedSerials {
		revoked = append(revoked, pkix.RevokedCertificate{SerialNumber: s, RevocationTime: thisUpdate})
	}
	tmpl := &x509.RevocationList{
		Issuer:              ca.Subject,
		ThisUpdate:          thisUpdate,
		NextUpdate:          nextUpdate,
		RevokedCertificates: revoked,
		Number:              big.NewInt(1),
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
	if err != nil {
		panic(err)
	}
	return der
}

// issueWithKey 使用调用方给定的主体密钥签发证书，用于构造交叉签名
// （同主体/同公钥、不同颁发者）场景。
func issueWithKey(issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey,
	subjectKey *ecdsa.PrivateKey, spec certSpec) *x509.Certificate {
	tmpl := &x509.Certificate{
		SerialNumber:            nextSerial(),
		Subject:                 pkix.Name{CommonName: spec.commonName, Organization: []string{spec.org}},
		NotBefore:               spec.notBefore,
		NotAfter:                spec.notAfter,
		KeyUsage:                spec.keyUsage,
		ExtKeyUsage:             spec.extKeyUsage,
		BasicConstraintsValid:   true,
		IsCA:                    spec.isCA,
		MaxPathLen:              spec.maxPathLen,
		MaxPathLenZero:          spec.maxPathLenZero,
		DNSNames:                spec.dnsNames,
		IPAddresses:             spec.ips,
		EmailAddresses:          spec.emails,
		PermittedDNSDomains:     spec.permitDNS,
		ExcludedDNSDomains:      spec.excludeDNS,
		PermittedIPRanges:       spec.permitIP,
		ExcludedIPRanges:        spec.excludeIP,
		PermittedEmailAddresses: spec.permitEmail,
		ExcludedEmailAddresses:  spec.excludeEmail,
		SubjectKeyId:            spec.subjectKeyID,
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(365 * 24 * time.Hour)
	}
	if spec.unknownCritical {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}, Critical: true,
			Value: []byte{0x04, 0x01, 0x00},
		})
	}
	signerCert, signerKey := issuer, issuerKey
	if issuer == nil {
		signerCert, signerKey = tmpl, subjectKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &subjectKey.PublicKey, signerKey)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

func caSpecAt(cn string, at time.Time) certSpec {
	s := caSpec(cn)
	s.notBefore = at.Add(-time.Hour)
	s.notAfter = at.Add(24 * time.Hour)
	return s
}

func leafSpecAt(cn, dns string, at time.Time) certSpec {
	s := leafSpec(cn, dns)
	s.notBefore = at.Add(-time.Hour)
	s.notAfter = at.Add(24 * time.Hour)
	return s
}

func bigFromCert(c *x509.Certificate) *big.Int { return c.SerialNumber }
