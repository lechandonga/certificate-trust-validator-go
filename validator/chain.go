package validator

import (
	"crypto/x509"

	"github.com/lechandonga/certificate-trust-validator-go/trust"
)

// maxChainDepth bounds path search to defeat any pathological graph and to
// reject chains longer than the configured path length.
const maxChainDepth = 20

// candidateChain is leaf -> ... -> anchor.
type candidateChain []*x509.Certificate

// buildResult carries the enumerated chains plus structural observations
// collected while walking the issuer graph.
type buildResult struct {
	chains        []candidateChain
	cycleDetected bool
	tooDeep       bool
}

// buildChains enumerates every syntactically reachable chain from the leaf to
// a trust anchor using anchors and intermediates in snap, optionally
// augmented by extra (e.g. TLS presented) intermediates.
//
// Determinism guarantees:
//   - issuers for a subject are visited in trust.Snapshot bucket order
//     (serial, then fingerprint);
//   - extra intermediates are consulted after store intermediates in their
//     given order;
//   - the returned slice is sorted by the canonical chain ordering
//     (fewer intermediates first, then lexicographic certificate fingerprints
//     leaf-first). The first valid chain in that order is the answer, which
//     is reproducible across runs regardless of map iteration.
func buildChains(leaf *x509.Certificate, snap *trust.Snapshot, extra []*x509.Certificate) buildResult {
	res := buildResult{}

	// onPath fingerprints detect cycles.
	onPath := map[string]bool{}

	var dfs func(current *x509.Certificate, chain candidateChain)
	dfs = func(current *x509.Certificate, chain candidateChain) {
		fp := trust.Fingerprint(current)
		if onPath[fp] {
			res.cycleDetected = true
			return
		}
		if len(chain) > maxChainDepth {
			res.tooDeep = true
			return
		}
		onPath[fp] = true
		defer delete(onPath, fp)

		// Trust-anchor endpoint: the current certificate is itself an anchor.
		if _, ok := snap.AnchorByFingerprint(fp); ok {
			out := make(candidateChain, len(chain))
			copy(out, chain)
			res.chains = append(res.chains, out)
			return
		}

		parents := issuerCandidates(current, snap, extra)
		for _, parent := range parents {
			pfp := trust.Fingerprint(parent)
			extended := append(chain, parent)
			if pfp == fp || onPath[pfp] {
				res.cycleDetected = true
				continue
			}
			if isSelfSigned(parent) {
				if _, ok := snap.AnchorByFingerprint(pfp); ok {
					out := make(candidateChain, len(extended))
					copy(out, extended)
					res.chains = append(res.chains, out)
				}
				continue
			}
			dfs(parent, extended)
		}
	}

	dfs(leaf, candidateChain{leaf})

	sortChains(res.chains)
	return res
}

// issuerCandidates returns possible issuers for child in deterministic order:
// store intermediates with matching subject, then extra intermediates, then
// anchors with matching subject.
func issuerCandidates(child *x509.Certificate, snap *trust.Snapshot, extra []*x509.Certificate) []*x509.Certificate {
	seen := map[string]bool{}
	var out []*x509.Certificate
	add := func(c *x509.Certificate) {
		if c == nil {
			return
		}
		fp := trust.Fingerprint(c)
		if seen[fp] {
			return
		}
		seen[fp] = true
		out = append(out, c)
	}
	for _, c := range snap.IntersBySubject(child.Issuer.String()) {
		add(c)
	}
	for _, c := range extra {
		if c.Subject.String() == child.Issuer.String() {
			add(c)
		}
	}
	for _, c := range snap.AnchorsByIssuer(child) {
		add(c)
	}
	return out
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.Subject.String() == c.Issuer.String()
}

// sortChains orders candidates so path selection is total and reproducible.
// Preference: (1) fewer certificates (shorter path), (2) lexicographically
// smaller fingerprints from the leaf upward.
func sortChains(chains []candidateChain) {
	for i := 1; i < len(chains); i++ {
		for j := i; j > 0 && chainLess(chains[j], chains[j-1]); j-- {
			chains[j], chains[j-1] = chains[j-1], chains[j]
		}
	}
}

func chainLess(a, b candidateChain) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	for i := range a {
		fa, fb := trust.Fingerprint(a[i]), trust.Fingerprint(b[i])
		if fa != fb {
			return fa < fb
		}
	}
	return false
}
