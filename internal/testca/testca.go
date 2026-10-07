// Package testca builds X.509 test material entirely in memory. No file, no
// network and no real credentials are involved; every private key is a fresh
// in-process ECDSA P-256 key.
package testca

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

// CA bundles a generated certificate with its private key so it can sign
// further certificates.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// Leaf is an end-entity certificate plus its key.
type Leaf struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NameConstraintSpec describes permitted/excluded name spaces for a CA
// certificate. It maps directly onto x509.Certificate fields while keeping
// test definitions compact.
type NameConstraintSpec struct {
	PermittedDNS    []string
	ExcludedDNS     []string
	PermittedIPs    []string // CIDRs
	ExcludedIPs     []string
	PermittedEmails []string
	ExcludedEmails  []string
}

func applyNameConstraints(tmpl *x509.Certificate, spec *NameConstraintSpec) {
	if spec == nil {
		return
	}
	tmpl.PermittedDNSDomains = spec.PermittedDNS
	tmpl.ExcludedDNSDomains = spec.ExcludedDNS
	tmpl.PermittedEmailAddresses = spec.PermittedEmails
	tmpl.ExcludedEmailAddresses = spec.ExcludedEmails
	for _, cidr := range spec.PermittedIPs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		tmpl.PermittedIPRanges = append(tmpl.PermittedIPRanges, n)
	}
	for _, cidr := range spec.ExcludedIPs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		tmpl.ExcludedIPRanges = append(tmpl.ExcludedIPRanges, n)
	}
}

func newKey() *ecdsa.PrivateKey {
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

// RootSpec configures a self-signed root.
type RootSpec struct {
	CommonName string
	Serial     *big.Int
	NotBefore  time.Time
	NotAfter   time.Time
}

// NewRoot creates a self-signed root CA.
func NewRoot(spec RootSpec) *CA {
	key := newKey()
	tmpl := &x509.Certificate{
		SerialNumber:          serialOr(spec.Serial),
		Subject:               pkix.Name{CommonName: spec.CommonName},
		NotBefore:             spec.NotBefore,
		NotAfter:              spec.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            10,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &CA{Cert: c, Key: key}
}

// ICAConfig configures an intermediate CA.
type ICAConfig struct {
	CommonName  string
	Serial      *big.Int
	NotBefore   time.Time
	NotAfter    time.Time
	Issuer      *CA
	SelfKey     *ecdsa.PrivateKey // key to certify (for cross-signs)
	KeyUsage    x509.KeyUsage
	MaxPathLen  int // 0 = default(5); positive N sets pathLen=N; -1 encodes pathLen 0
	NameConst   *NameConstraintSpec
	EKU         []x509.ExtKeyUsage
	UnknownCrit []asn1.ObjectIdentifier // critical OIDs we intentionally do not implement
}

// NewIntermediate issues an intermediate certificate from Issuer.
func NewIntermediate(cfg ICAConfig) *CA {
	key := cfg.SelfKey
	if key == nil {
		key = newKey()
	}
	ku := cfg.KeyUsage
	if ku == 0 {
		ku = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	pl := cfg.MaxPathLen
	if pl == 0 {
		pl = 5
	}
	plZero := false
	if cfg.MaxPathLen == -1 {
		pl, plZero = 0, true
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serialOr(cfg.Serial),
		Subject:               pkix.Name{CommonName: cfg.CommonName},
		NotBefore:             cfg.NotBefore,
		NotAfter:              cfg.NotAfter,
		KeyUsage:              ku,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            pl,
		MaxPathLenZero:        plZero,
		ExtKeyUsage:           cfg.EKU,
	}
	applyNameConstraints(tmpl, cfg.NameConst)

	for _, oid := range cfg.UnknownCrit {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oid, Critical: true, Value: []byte{0x04, 0x00}})
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, cfg.Issuer.Cert, &key.PublicKey, cfg.Issuer.Key)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &CA{Cert: c, Key: key}
}

// LeafConfig configures an end-entity certificate.
type LeafConfig struct {
	CommonName  string
	DNSNames    []string
	IPAddrs     []net.IP
	Emails      []string
	Serial      *big.Int
	NotBefore   time.Time
	NotAfter    time.Time
	Issuer      *CA
	KeyUsage    x509.KeyUsage
	EKU         []x509.ExtKeyUsage
	NameConst   *NameConstraintSpec
	UnknownCrit []asn1.ObjectIdentifier
}

// NewLeaf issues a terminal certificate from Issuer.
func NewLeaf(cfg LeafConfig) *Leaf {
	key := newKey()
	ku := cfg.KeyUsage
	if ku == 0 {
		ku = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	eku := cfg.EKU
	if eku == nil {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serialOr(cfg.Serial),
		Subject:               pkix.Name{CommonName: cfg.CommonName},
		DNSNames:              cfg.DNSNames,
		IPAddresses:           cfg.IPAddrs,
		EmailAddresses:        cfg.Emails,
		NotBefore:             cfg.NotBefore,
		NotAfter:              cfg.NotAfter,
		KeyUsage:              ku,
		BasicConstraintsValid: true,
		IsCA:                  false,
		ExtKeyUsage:           eku,
	}
	applyNameConstraints(tmpl, cfg.NameConst)
	for _, oid := range cfg.UnknownCrit {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: oid, Critical: true, Value: []byte{0x04, 0x00}})
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, cfg.Issuer.Cert, &key.PublicKey, cfg.Issuer.Key)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return &Leaf{Cert: c, Key: key}
}

// CorruptSignature flips a byte in the signature bytes of the DER, producing
// a certificate whose signature cannot validate.
func CorruptSignature(cert *x509.Certificate) *x509.Certificate {
	der := append([]byte(nil), cert.Raw...)
	// Flip a byte inside the signature BIT STRING (near the end of DER).
	idx := len(der) - 8
	der[idx] ^= 0xFF
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}

func serialOr(s *big.Int) *big.Int {
	if s != nil {
		return s
	}
	return nextSerial()
}
