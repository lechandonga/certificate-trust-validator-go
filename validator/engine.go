// Package validator performs local X.509 path building and validation with
// deterministic multi-path selection, name constraints, hostname matching and
// policy-driven revocation decisions.
//
// All inputs are in memory. The Engine holds versioned trust and revocation
// snapshots; every Validate call captures one atomic (trust, revocation)
// view, so concurrent calls see only an old or a new complete state and
// caches are keyed per trust store / version.
package validator

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"sync"
	"time"

	"github.com/lechandonga/certificate-trust-validator-go/revocation"
	"github.com/lechandonga/certificate-trust-validator-go/trust"
)

// Clock lets tests freeze or advance time deterministically.
type Clock func() time.Time

// Options configures an Engine.
type Options struct {
	RevocationPolicy revocation.Policy
	Clock            Clock
	// CacheResults enables memoization of validation outcomes within one
	// trust/revocation version. Caches are never shared across stores or
	// versions.
	CacheResults bool
}

// Engine is the concurrency-safe entry point.
type Engine struct {
	mu sync.RWMutex

	trustStores map[string]*trust.Store
	trustVer    map[string]uint64
	trustSnap   map[string]*trust.Snapshot

	revSource *revocation.Source
	revVer    uint64

	opts Options

	// cache keyed by cacheKey -> *cacheEntry; entries are version-scoped.
	cacheMu sync.Mutex
	cache   map[string]*cacheEntry
}

type cacheEntry struct {
	done  chan struct{}
	chain candidateChain
	err   error
}

// NewEngine creates an engine.
func NewEngine(opts Options) *Engine {
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	return &Engine{
		trustStores: map[string]*trust.Store{},
		trustVer:    map[string]uint64{},
		trustSnap:   map[string]*trust.Snapshot{},
		revSource:   revocation.NewSource(nil),
		cache:       map[string]*cacheEntry{},
		opts:        opts,
	}
}

// AddStore registers a trust store and publishes its first snapshot.
func (e *Engine) AddStore(s *trust.Store) *trust.Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.trustStores[s.ID] = s
	e.trustVer[s.ID]++
	v := e.trustVer[s.ID]
	snap := s.BuildSnapshot(v)
	e.trustSnap[s.ID] = snap
	return snap
}

// UpdateTrust republishes the current contents of store id as a new snapshot.
// The change is visible immediately to the next Validate call.
func (e *Engine) UpdateTrust(id string) (*trust.Snapshot, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	s, ok := e.trustStores[id]
	if !ok {
		return nil, fmt.Errorf("validator: unknown trust store %q", id)
	}
	e.trustVer[id]++
	snap := s.BuildSnapshot(e.trustVer[id])
	e.trustSnap[id] = snap
	return snap, nil
}

// ReplaceStore atomically swaps the complete contents registered for id.
// The store id is reused but the version is incremented, so validators
// observe the new trust material as one indivisible unit.
func (e *Engine) ReplaceStore(id string, s *trust.Store) *trust.Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.trustStores[id] = s
	e.trustVer[id]++
	snap := s.BuildSnapshot(e.trustVer[id])
	e.trustSnap[id] = snap
	return snap
}

// ReplaceRevocation atomically installs new revocation data.
func (e *Engine) ReplaceRevocation(d *revocation.Data) {
	e.mu.Lock()
	e.revVer++
	rev := withVersion(d, e.revVer)
	e.mu.Unlock()
	e.revSource.Replace(rev)
}

func withVersion(d *revocation.Data, v uint64) *revocation.Data {
	if d == nil {
		return nil
	}
	d.Version = v
	return d
}

// View is the immutable state captured for one validation.
type View struct {
	Trust *trust.Snapshot
	Rev   *revocation.Data
}

// snapshot captures an atomic view under the read lock.
func (e *Engine) snapshot(storeID string) (View, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	snap, ok := e.trustSnap[storeID]
	if !ok {
		return View{}, fmt.Errorf("validator: unknown trust store %q", storeID)
	}
	return View{Trust: snap, Rev: e.revSource.Current()}, nil
}

// Request is a validation request.
type Request struct {
	StoreID string
	Leaf    *x509.Certificate
	// Intermediates presented alongside the leaf (e.g. by a TLS peer). They
	// are only used to connect the path; they never confer trust.
	Intermediates []*x509.Certificate
	// Hostname checks DNS/IP SAN. Email checks rfc822Name SAN. At least the
	// target identifier relevant to the caller should be set; empty fields
	// are simply not checked.
	Hostname string
	IP       string
	Email    string
}

// Result reports the selected path.
type Result struct {
	Chain        []*x509.Certificate
	StoreID      string
	TrustVersion uint64
	RevVersion   uint64
	FromCache    bool
}

// Validate builds and validates the path for req.
func (e *Engine) Validate(req Request) (*Result, error) {
	if req.Leaf == nil {
		return nil, &VerificationError{Code: CodeEmptyInput, CertIndex: -1, Message: "leaf certificate is nil"}
	}
	view, err := e.snapshot(req.StoreID)
	if err != nil {
		return nil, err
	}

	key := e.cacheKey(req, view)
	if e.opts.CacheResults {
		if entry := e.getCache(key); entry != nil {
			<-entry.done
			if entry.err != nil {
				return nil, entry.err
			}
			return e.toResult(entry.chain, view, true), nil
		}
	}

	chain, err := e.validateUncached(req, view)
	if e.opts.CacheResults {
		e.finishCache(key, chain, err)
	}
	if err != nil {
		return nil, err
	}
	return e.toResult(chain, view, false), nil
}

func (e *Engine) validateUncached(req Request, view View) (candidateChain, error) {
	now := e.opts.Clock()

	built := buildChains(req.Leaf, view.Trust, req.Intermediates)
	if len(built.chains) == 0 {
		if built.cycleDetected {
			return nil, &VerificationError{Code: CodeCycle, CertIndex: -1, Message: fmt.Sprintf("issuer graph from %s contains a cycle and never reaches an anchor", req.Leaf.Subject.String())}
		}
		if built.tooDeep {
			return nil, &VerificationError{Code: CodePathTooLong, CertIndex: -1, Message: fmt.Sprintf("path search exceeded max depth %d without reaching an anchor", maxChainDepth)}
		}
		return nil, &VerificationError{Code: CodeNoPath, CertIndex: -1, Message: fmt.Sprintf("no path from %s to an anchor in store %q", req.Leaf.Subject.String(), req.StoreID)}
	}

	// Chains are already in deterministic preference order. Validate each;
	// remember the error of the highest-priority candidate if all fail.
	var firstErr *VerificationError
	for _, chain := range built.chains {
		if err := verifyChain(chain, view.Rev, e.opts.RevocationPolicy, now); err != nil {
			if firstErr == nil {
				firstErr = err.(*VerificationError)
			}
			continue
		}
		if err := checkIdentifiers(req, chain[0]); err != nil {
			return nil, err
		}
		return chain, nil
	}
	return nil, firstErr
}

func checkIdentifiers(req Request, leaf *x509.Certificate) error {
	if req.Hostname != "" {
		if err := MatchHostname(leaf, req.Hostname); err != nil {
			return err
		}
	}
	if req.IP != "" {
		if err := MatchIP(leaf, req.IP); err != nil {
			return err
		}
	}
	if req.Email != "" {
		if err := MatchEmail(leaf, req.Email); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) toResult(chain candidateChain, view View, fromCache bool) *Result {
	rv := uint64(0)
	if view.Rev != nil {
		rv = view.Rev.Version
	}
	out := make([]*x509.Certificate, len(chain))
	copy(out, chain)
	return &Result{Chain: out, StoreID: view.Trust.StoreID, TrustVersion: view.Trust.Version, RevVersion: rv, FromCache: fromCache}
}

type cacheKey struct {
	store    string
	trustVer uint64
	revVer   uint64
	policy   int
	leafFP   string
	extrasFP string
	host     string
	ip       string
	email    string
}

func (e *Engine) cacheKey(req Request, view View) string {
	rv := uint64(0)
	if view.Rev != nil {
		rv = view.Rev.Version
	}
	h := sha256.New()
	for _, c := range req.Intermediates {
		h.Write(c.Raw)
	}
	k := cacheKey{
		store:    view.Trust.StoreID,
		trustVer: view.Trust.Version,
		revVer:   rv,
		policy:   int(e.opts.RevocationPolicy),
		leafFP:   trust.Fingerprint(req.Leaf),
		extrasFP: fmt.Sprintf("%x", h.Sum(nil)),
		host:     req.Hostname,
		ip:       req.IP,
		email:    req.Email,
	}
	return fmt.Sprintf("%+v", k)
}

// getCache returns an in-flight or finished entry, or registers a new one.
func (e *Engine) getCache(key string) *cacheEntry {
	e.cacheMu.Lock()
	defer e.cacheMu.Unlock()
	// Opportunistically drop entries for versions far behind: version is in
	// the key, so stale entries are never reused across updates; bounded map
	// growth is prevented by pruning on size.
	if len(e.cache) > 4096 {
		e.cache = map[string]*cacheEntry{}
	}
	if entry, ok := e.cache[key]; ok {
		return entry
	}
	entry := &cacheEntry{done: make(chan struct{})}
	e.cache[key] = entry
	return nil
}

func (e *Engine) finishCache(key string, chain candidateChain, err error) {
	e.cacheMu.Lock()
	entry, ok := e.cache[key]
	e.cacheMu.Unlock()
	if !ok {
		return
	}
	entry.chain = chain
	entry.err = err
	close(entry.done)
}
