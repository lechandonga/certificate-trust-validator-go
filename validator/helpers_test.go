package validator_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	bigpkg "math/big"
	"testing"
	"time"

	"github.com/lechandonga/certificate-trust-validator-go/revocation"
	"github.com/lechandonga/certificate-trust-validator-go/trust"
	"github.com/lechandonga/certificate-trust-validator-go/validator"
)

var (
	t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 = t0.Add(10 * 365 * 24 * time.Hour)
	tn = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
)

func big(n int64) *bigpkg.Int { return bigpkg.NewInt(n) }

func newECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func fixedClock() validator.Options {
	return validator.Options{Clock: func() time.Time { return tn }, CacheResults: true, RevocationPolicy: revocation.PolicyFailOpen}
}

func engineWith(t *testing.T, id string, anchor *x509.Certificate, inters ...*x509.Certificate) (*validator.Engine, *trust.Store) {
	t.Helper()
	e := validator.NewEngine(fixedClock())
	s := trust.NewStore(id)
	if err := s.AddAnchor(anchor); err != nil {
		t.Fatal(err)
	}
	for _, c := range inters {
		if err := s.AddIntermediate(c); err != nil {
			t.Fatal(err)
		}
	}
	e.AddStore(s)
	return e, s
}

func assertCode(t *testing.T, err error, want validator.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error code %s, got nil", want)
	}
	ve, ok := validator.AsVerificationError(err)
	if !ok {
		t.Fatalf("expected *VerificationError, got %T: %v", err, err)
	}
	if ve.Code != want {
		t.Fatalf("expected code %s, got %s (%v)", want, ve.Code, err)
	}
}

func logCase(t *testing.T, business, setup, expectation string) {
	t.Helper()
	t.Logf("[业务] %-22s | 用例: %-28s | 预期: %s", business, setup, expectation)
}

func logPass(t *testing.T, business string) {
	t.Helper()
	t.Logf("[结果] %-22s | PASS", business)
}

func chainSubjects(res *validator.Result) []string {
	out := make([]string, len(res.Chain))
	for i, c := range res.Chain {
		out[i] = fmt.Sprintf("%s#%s", c.Subject.CommonName, c.SerialNumber)
	}
	return out
}
