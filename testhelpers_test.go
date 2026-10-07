package ctv

import (
	"crypto/x509"
	"testing"
)

func mustPass(t *testing.T, msg string, err error, res *VerifyResult) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: 意外失败: %v", msg, err)
	}
	if res == nil || len(res.Chain.Certs) == 0 {
		t.Fatalf("%s: 通过但链为空", msg)
	}
}

func mustReason(t *testing.T, msg string, err error, allowed ...ReasonCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: 预期失败却通过", msg)
	}
	got := reasonOf(err)
	for _, a := range allowed {
		if got == a {
			return
		}
	}
	t.Fatalf("%s: 原因为 %s，不在允许集合 %v 内", msg, got, allowed)
}

func reasonOf(err error) ReasonCode {
	if ve, ok := err.(*VerifyError); ok {
		return ve.Reason
	}
	return ReasonCode(err.Error())
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}

func reverseCerts(certs ...*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, len(certs))
	for i, c := range certs {
		out[len(certs)-1-i] = c
	}
	return out
}
