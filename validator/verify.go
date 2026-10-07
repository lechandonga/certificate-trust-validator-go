package validator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/lechandonga/certificate-trust-validator-go/revocation"
)

// verifyChain fully validates one leaf->anchor chain at time now. Every
// failure gets a precise Code and certificate index.
func verifyChain(chain candidateChain, rev *revocation.Data, policy revocation.Policy, now time.Time) error {
	// 1. Per-certificate checks, leaf to anchor.
	for i, cert := range chain {
		isAnchor := i == len(chain)-1

		if err := checkValidity(cert, i, now); err != nil {
			return err
		}
		if err := checkCriticalExtensions(cert, i); err != nil {
			return err
		}
		if i == 0 {
			if cert.IsCA {
				return certErr(CodeBasicConstraints, i, cert, "terminal certificate has cA=true")
			}
			if err := checkLeafKeyUsage(cert, i); err != nil {
				return err
			}
		} else {
			if err := checkCAProperties(cert, i); err != nil {
				return err
			}
		}
		// Path length: count non-self-issued intermediate CAs below cert.
		if i >= 1 {
			if err := checkPathLen(chain, i); err != nil {
				return err
			}
		}
		// Signature by issuer (the next cert up).
		if i < len(chain)-1 {
			parent := chain[i+1]
			if err := checkSignature(cert, parent, i); err != nil {
				return err
			}
		} else if isAnchor {
			// Anchor: self-signature must verify (defends against tampered
			// anchor bytes loaded into the trust store).
			if err := checkSignature(cert, cert, i); err != nil {
				return err
			}
		}
	}

	// 2. EKU chaining: the leaf asserts serverAuth and every CA must allow it.
	if err := checkEKUChain(chain); err != nil {
		return err
	}

	// 3. Name constraints, accumulated root-first and applied to each cert
	// below the asserting CA.
	var cs constraintsSet
	for i := len(chain) - 1; i >= 1; i-- {
		ca := chain[i]
		if err := cs.merge(ca); err != nil {
			return err
		}
		if err := cs.checkCertificate(chain[i-1], i-1); err != nil {
			return err
		}
	}

	// 4. Revocation for every non-anchor certificate. All lookups use the
	// same immutable data snapshot captured by the caller.
	for i := 0; i < len(chain)-1; i++ {
		cert := chain[i]
		if rev == nil {
			if policy == revocation.PolicyFailClosed {
				return certErr(CodeRevocationUnavailable, i, cert, "no revocation data installed (fail-closed)")
			}
			continue
		}
		res := rev.Lookup(cert, now)
		switch res.Status {
		case revocation.StatusRevoked:
			return certErr(CodeRevoked, i, cert, "certificate revoked (reason %d) at %s", res.Reason, res.RevokedAt.Format(time.RFC3339))
		case revocation.StatusUnavailable:
			if policy == revocation.PolicyFailClosed {
				return certErr(CodeRevocationUnavailable, i, cert, "%s (fail-closed)", res.Unavailable)
			}
		}
	}
	return nil
}

func checkValidity(cert *x509.Certificate, idx int, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return certErr(CodeNotYetValid, idx, cert, "not valid before %s", cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return certErr(CodeExpired, idx, cert, "expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func checkCriticalExtensions(cert *x509.Certificate, idx int) error {
	for _, oid := range cert.UnhandledCriticalExtensions {
		return certErr(CodeUnknownCriticalExt, idx, cert, "unrecognized critical extension %s", oid.String())
	}
	return nil
}

func checkCAProperties(cert *x509.Certificate, idx int) error {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return certErr(CodeNotCA, idx, cert, "issuer certificate is not a CA (basicConstraints absent or cA=false)")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return certErr(CodeKeyUsage, idx, cert, "CA certificate lacks keyCertSign")
	}
	return nil
}

func checkLeafKeyUsage(cert *x509.Certificate, idx int) error {
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return certErr(CodeKeyUsage, idx, cert, "leaf certificate lacks digitalSignature key usage")
	}
	return nil
}

func checkPathLen(chain candidateChain, idx int) error {
	ca := chain[idx]
	max := ca.MaxPathLen
	if max < 0 {
		return nil
	}
	// Number of CA certificates below this one (excluding leaf and the CA
	// itself): indexes 1..idx-1. Self-issued intermediates do not consume
	// pathLen budget.
	count := 0
	for j := 1; j < idx; j++ {
		if chain[j].Subject.String() != chain[j].Issuer.String() {
			count++
		}
	}
	if count > max {
		return certErr(CodePathTooLong, idx, ca, "pathLenConstraint %d exceeded: %d non-self-issued CA(s) below", max, count)
	}
	return nil
}

func checkEKUChain(chain candidateChain) error {
	if !hasServerAuth(chain[0]) {
		return certErr(CodeExtKeyUsage, 0, chain[0], "leaf certificate does not assert serverAuth")
	}
	for i := 1; i < len(chain); i++ {
		cert := chain[i]
		if len(cert.ExtKeyUsage) == 0 {
			continue // no EKU extension means any purpose
		}
		if !hasServerAuth(cert) {
			return certErr(CodeExtKeyUsage, i, cert, "CA does not permit serverAuth")
		}
	}
	return nil
}

func hasServerAuth(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth || eku == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

func checkSignature(child, parent *x509.Certificate, childIdx int) error {
	var hash crypto.Hash
	switch child.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.SHA256WithRSAPSS:
		hash = crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		hash = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		hash = crypto.SHA512
	}

	var valid bool
	switch pub := parent.PublicKey.(type) {
	case *ecdsa.PublicKey:
		h := hash.New()
		h.Write(child.RawTBSCertificate)
		valid = ecdsa.VerifyASN1(pub, h.Sum(nil), child.Signature)
	case *rsa.PublicKey:
		if hash == 0 {
			break
		}
		h := hash.New()
		h.Write(child.RawTBSCertificate)
		if child.SignatureAlgorithm == x509.SHA256WithRSAPSS ||
			child.SignatureAlgorithm == x509.SHA384WithRSAPSS ||
			child.SignatureAlgorithm == x509.SHA512WithRSAPSS {
			valid = rsa.VerifyPSS(pub, hash, h.Sum(nil), child.Signature, nil) == nil
		} else {
			valid = rsa.VerifyPKCS1v15(pub, hash, h.Sum(nil), child.Signature) == nil
		}
	case ed25519.PublicKey:
		valid = ed25519.Verify(pub, child.RawTBSCertificate, child.Signature)
	default:
		return certErr(CodeInvalidSignature, childIdx, child, "unsupported issuer public key type")
	}
	if !valid {
		return certErr(CodeInvalidSignature, childIdx, child, "signature does not verify against issuer %s", parent.Subject.String())
	}
	return nil
}
