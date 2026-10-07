package validator

import (
	"crypto/x509"
	"fmt"
)

// Code is a stable, distinguishable failure category. Two different reject
// reasons never share a code, so callers (and tests) can branch on the exact
// cause instead of string matching.
type Code string

const (
	CodeNoPath                Code = "NO_VALID_PATH"          // no chain reaches a trust anchor
	CodeCycle                 Code = "PATH_CYCLE"             // chain contains a repeated certificate
	CodePathTooLong           Code = "PATH_TOO_LONG"          // exceeds MaxPathLen / search depth
	CodeExpired               Code = "CERT_EXPIRED"           // NotAfter in the past
	CodeNotYetValid           Code = "CERT_NOT_YET_VALID"     // NotBefore in the future
	CodeInvalidSignature      Code = "INVALID_SIGNATURE"      // signature does not verify
	CodeNotCA                 Code = "NOT_A_CA"               // issuer cert is not a CA
	CodeBasicConstraints      Code = "BASIC_CONSTRAINTS"      // cA/basicConstraints problem
	CodeKeyUsage              Code = "KEY_USAGE_MISMATCH"     // required key usage bit missing
	CodeExtKeyUsage           Code = "EXT_KEY_USAGE_MISMATCH" // required EKU (serverAuth) missing
	CodeUnknownCriticalExt    Code = "UNKNOWN_CRITICAL_EXT"   // unrecognized critical extension
	CodeNameConstraints       Code = "NAME_CONSTRAINT_VIOLATION"
	CodeHostnameMismatch      Code = "HOSTNAME_MISMATCH"
	CodeRevoked               Code = "CERT_REVOKED"
	CodeRevocationUnavailable Code = "REVOCATION_UNAVAILABLE"
	CodeEmptyInput            Code = "EMPTY_INPUT"
)

// VerificationError describes exactly why verification failed and, when
// applicable, which certificate on the candidate path caused it.
type VerificationError struct {
	Code    Code
	Message string
	// CertIndex is the index in the candidate chain (0 = leaf), -1 when the
	// failure is not tied to a specific certificate.
	CertIndex int
	// CertSubject is a stable rendering of the offending certificate subject.
	CertSubject string
}

func (e *VerificationError) Error() string {
	if e.CertSubject != "" {
		return fmt.Sprintf("%s: %s [cert#%d %s]", e.Code, e.Message, e.CertIndex, e.CertSubject)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func certErr(code Code, idx int, cert *x509.Certificate, format string, args ...any) *VerificationError {
	e := &VerificationError{Code: code, CertIndex: idx, Message: fmt.Sprintf(format, args...)}
	if cert != nil {
		e.CertSubject = cert.Subject.String()
	}
	return e
}

// AsVerificationError unwraps a VerificationError if present.
func AsVerificationError(err error) (*VerificationError, bool) {
	ve, ok := err.(*VerificationError)
	return ve, ok
}
