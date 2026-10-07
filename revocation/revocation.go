// Package revocation implements local, CRL-like revocation data and an
// explicit, configurable failure policy.
//
// Revocation data is constructed/loaded entirely in memory. Every data set
// (IssuerList) has its own thisUpdate/nextUpdate window: a stale or missing
// list is treated as "unavailable", and whether unavailability opens or closes
// the connection is decided solely by Policy.
package revocation

import (
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"
)

// Reason is the revocation reason of a single entry (mirrors CRL reason codes
// that matter for TLS).
type Reason int

const (
	ReasonUnspecified Reason = iota
	ReasonKeyCompromise
	ReasonCACompromise
	ReasonAffiliationChanged
	ReasonSuperseded
	ReasonCessationOfOperation
	ReasonCertificateHold
	ReasonRemoveFromCRL
	ReasonPrivilegeWithdrawn
	ReasonAACompromise
)

// IssuerList is the revocation list published by one CA.
type IssuerList struct {
	IssuerName string
	ThisUpdate time.Time
	NextUpdate time.Time
	Entries    map[string]Reason // serial decimal -> reason
	revokedAt  map[string]time.Time
}

// NewIssuerList builds a revocation list for the CA named issuerName.
// A zero nextUpdate means the list never expires (handy for fixed tests).
func NewIssuerList(issuerName string, thisUpdate, nextUpdate time.Time) *IssuerList {
	return &IssuerList{
		IssuerName: issuerName,
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
		Entries:    map[string]Reason{},
		revokedAt:  map[string]time.Time{},
	}
}

// Add marks a serial as revoked.
func (l *IssuerList) Add(serial *big.Int, reason Reason, at time.Time) error {
	if serial == nil {
		return errors.New("revocation: nil serial")
	}
	k := serial.String()
	l.Entries[k] = reason
	l.revokedAt[k] = at
	return nil
}

// Remove deletes a serial, e.g. to simulate delta CRLs between hot updates.
func (l *IssuerList) Remove(serial *big.Int) {
	if serial == nil {
		return
	}
	delete(l.Entries, serial.String())
	delete(l.revokedAt, serial.String())
}

// FreshAt reports whether the list is within its validity window at t.
func (l *IssuerList) FreshAt(t time.Time) bool {
	if !l.ThisUpdate.IsZero() && t.Before(l.ThisUpdate) {
		return false
	}
	if !l.NextUpdate.IsZero() && !t.Before(l.NextUpdate) {
		return false
	}
	return true
}

// Status is the per-certificate revocation verdict.
type Status int

const (
	StatusGood Status = iota
	StatusRevoked
	StatusUnavailable // no fresh list for the issuing CA
)

// Result carries a status plus the distinguishing reason.
type Result struct {
	Status      Status
	Reason      Reason
	RevokedAt   time.Time
	Unavailable string // human-readable explanation when StatusUnavailable
}

// Data is an immutable, versioned collection of per-issuer revocation lists.
// Lookups happen against the snapshot captured for the whole validation, so
// concurrent updates can never produce a torn view across certificates.
type Data struct {
	Version uint64
	lists   map[string]*IssuerList
}

// NewData creates empty revocation data.
func NewData() *Data {
	return &Data{lists: map[string]*IssuerList{}}
}

// AddList registers (or replaces) the list for its issuer.
func (d *Data) AddList(l *IssuerList) {
	d.lists[l.IssuerName] = l
}

// Lookup returns the revocation status of cert at time now.
func (d *Data) Lookup(cert *x509.Certificate, now time.Time) Result {
	l, ok := d.lists[cert.Issuer.String()]
	if !ok {
		return Result{Status: StatusUnavailable, Unavailable: fmt.Sprintf("no revocation list for issuer %q", cert.Issuer.String())}
	}
	if !l.FreshAt(now) {
		return Result{Status: StatusUnavailable, Unavailable: fmt.Sprintf("revocation list for issuer %q is stale (nextUpdate %s)", l.IssuerName, l.NextUpdate.Format(time.RFC3339))}
	}
	if reason, revoked := l.Entries[cert.SerialNumber.String()]; revoked {
		return Result{Status: StatusRevoked, Reason: reason, RevokedAt: l.revokedAt[cert.SerialNumber.String()]}
	}
	return Result{Status: StatusGood}
}

// IssuerNames returns covered issuer names, sorted.
func (d *Data) IssuerNames() []string {
	out := make([]string, 0, len(d.lists))
	for k := range d.lists {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Policy decides what happens when fresh revocation information is
// unavailable (missing or expired). It is an explicit, stable configuration:
// there is no implicit default mixed into the verification logic.
type Policy int

const (
	// PolicyFailClosed rejects the chain whenever fresh revocation data is
	// unavailable for any certificate on the path.
	PolicyFailClosed Policy = iota
	// PolicyFailOpen accepts a chain when revocation data is unavailable;
	// actually revoked certificates are always rejected.
	PolicyFailOpen
)

// Source is the concurrency-safe holder of the current revocation data.
// Replace swaps the whole pointer atomically.
type Source struct {
	mu      sync.RWMutex
	current *Data
}

// NewSource creates a source with initial data (may be nil).
func NewSource(initial *Data) *Source {
	return &Source{current: initial}
}

// Replace atomically installs new revocation data; subsequent validations see
// it immediately. Running validations keep using the snapshot they captured.
func (s *Source) Replace(d *Data) {
	s.mu.Lock()
	s.current = d
	s.mu.Unlock()
}

// Current returns the installed revocation data (may be nil).
func (s *Source) Current() *Data {
	s.mu.RLock()
	d := s.current
	s.mu.RUnlock()
	return d
}
