// Package trust implements locally constructed trust anchors, intermediate
// certificates and an immutable, versioned trust snapshot.
//
// All data lives in memory: there is no network access and no dependency on
// the operating system trust store. A Snapshot is an atomic view of the trust
// material; replacing a snapshot in the engine makes a new configuration
// visible to validators immediately and consistently.
package trust

import (
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sort"
)

// Anchor is a trusted root certificate.
type Anchor struct {
	Cert *x509.Certificate
}

// Store is a named collection of trust anchors and trusted intermediates.
// Cross-signed certificates are simply added as intermediates; path building
// discovers every reachable chain deterministically.
type Store struct {
	ID       string
	anchors  []*x509.Certificate
	inters   []*x509.Certificate
	anchorID map[string]bool
}

// NewStore creates an empty, named trust store.
func NewStore(id string) *Store {
	return &Store{ID: id, anchorID: map[string]bool{}}
}

// AddAnchor registers a certificate as a trust anchor. Adding the same
// certificate twice has no effect.
func (s *Store) AddAnchor(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("trust: nil anchor certificate")
	}
	if !cert.IsCA {
		return fmt.Errorf("trust: certificate %s is not a CA and cannot be an anchor", cert.Subject.String())
	}
	key := Fingerprint(cert)
	if s.anchorID[key] {
		return nil
	}
	s.anchorID[key] = true
	s.anchors = append(s.anchors, cert)
	return nil
}

// AddIntermediate registers an intermediate CA certificate that may be used
// when building a path. Duplicates are ignored.
func (s *Store) AddIntermediate(cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("trust: nil intermediate certificate")
	}
	if !cert.IsCA {
		return fmt.Errorf("trust: certificate %s is not a CA", cert.Subject.String())
	}
	for _, c := range s.inters {
		if Fingerprint(c) == Fingerprint(cert) {
			return nil
		}
	}
	s.inters = append(s.inters, cert)
	return nil
}

// Anchors returns the trust anchors in stable (insertion) order.
func (s *Store) Anchors() []*x509.Certificate {
	out := make([]*x509.Certificate, len(s.anchors))
	copy(out, s.anchors)
	return out
}

// Intermediates returns the trusted intermediates.
func (s *Store) Intermediates() []*x509.Certificate {
	out := make([]*x509.Certificate, len(s.inters))
	copy(out, s.inters)
	return out
}

// Snapshot is an immutable versioned view of one trust store. Snapshots are
// never mutated in place; every update produces a new snapshot with a new
// version, which guarantees that concurrent validators observe either the
// complete old state or the complete new state, never a mixture.
type Snapshot struct {
	StoreID          string
	Version          uint64
	anchors          []*x509.Certificate
	intermediates    []*x509.Certificate
	anchorsBySubject map[string][]*x509.Certificate
	intersBySubject  map[string][]*x509.Certificate
}

// BuildSnapshot returns an immutable snapshot of the store. The version is
// supplied by the caller (normally the engine) so versions are monotonic per
// store id.
func (s *Store) BuildSnapshot(version uint64) *Snapshot {
	snap := &Snapshot{
		StoreID:          s.ID,
		Version:          version,
		anchors:          s.Anchors(),
		intermediates:    s.Intermediates(),
		anchorsBySubject: map[string][]*x509.Certificate{},
		intersBySubject:  map[string][]*x509.Certificate{},
	}
	for _, c := range snap.anchors {
		k := c.Subject.String()
		snap.anchorsBySubject[k] = append(snap.anchorsBySubject[k], c)
	}
	for _, c := range snap.intermediates {
		k := c.Subject.String()
		snap.intersBySubject[k] = append(snap.intersBySubject[k], c)
	}
	// Deterministic ordering within every bucket: by serial number then
	// fingerprint. This makes path selection reproducible even when several
	// certificates share a subject (cross-signs / re-keys).
	for _, m := range []map[string][]*x509.Certificate{snap.anchorsBySubject, snap.intersBySubject} {
		for k := range m {
			sort.Slice(m[k], func(i, j int) bool {
				return lessCert(m[k][i], m[k][j])
			})
		}
	}
	return snap
}

// AnchorsByIssuer returns anchors whose subject matches the given issuer.
func (s *Snapshot) AnchorsByIssuer(issuer *x509.Certificate) []*x509.Certificate {
	return s.anchorsBySubject[issuer.Issuer.String()]
}

// IntersBySubject returns intermediates with the given subject.
func (s *Snapshot) IntersBySubject(subject string) []*x509.Certificate {
	return s.intersBySubject[subject]
}

// AnchorByFingerprint reports whether cert is a trust anchor, returning the
// stored anchor instance.
func (s *Snapshot) AnchorByFingerprint(fp string) (*x509.Certificate, bool) {
	for _, a := range s.anchors {
		if Fingerprint(a) == fp {
			return a, true
		}
	}
	return nil, false
}

// Fingerprint returns a stable SHA-256 fingerprint of the DER encoding.
func Fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum)
}

// lessCert gives a total, reproducible order over certificates with the same
// subject: serial number first, then full DER fingerprint.
func lessCert(a, b *x509.Certificate) bool {
	if cmp := a.SerialNumber.Cmp(b.SerialNumber); cmp != 0 {
		return cmp < 0
	}
	return Fingerprint(a) < Fingerprint(b)
}
