package validator_test

import (
	"encoding/asn1"
	"net"
	"testing"

	"github.com/lechandonga/certificate-trust-validator-go/internal/testca"
	"github.com/lechandonga/certificate-trust-validator-go/validator"
)

func TestSignatureAndCriticalExt(t *testing.T) {
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	ica := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root, NotBefore: t0, NotAfter: t1})

	logCase(t, "签名被篡改", "翻转 leaf 签名字节", "INVALID_SIGNATURE")
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"x.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	corrupt := testca.CorruptSignature(leaf.Cert)
	e, _ := engineWith(t, "sig", root.Cert, ica.Cert)
	_, err := e.Validate(validator.Request{StoreID: "sig", Leaf: corrupt})
	assertCode(t, err, validator.CodeInvalidSignature)
	logPass(t, "签名被篡改")

	logCase(t, "未知关键扩展", "leaf 携带不支持的 critical OID 1.2.3.4.5.6.7", "UNKNOWN_CRITICAL_EXT")
	critOID := asn1.ObjectIdentifier{1, 2, 3, 4, 5, 6, 7}
	leaf2 := testca.NewLeaf(testca.LeafConfig{CommonName: "y", DNSNames: []string{"y.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1, UnknownCrit: []asn1.ObjectIdentifier{critOID}})
	_, err = e.Validate(validator.Request{StoreID: "sig", Leaf: leaf2.Cert})
	assertCode(t, err, validator.CodeUnknownCriticalExt)
	logPass(t, "未知关键扩展")

	logCase(t, "中间证书被篡改", "翻转 ICA 签名字节", "INVALID_SIGNATURE index=1")
	badICA := testca.CorruptSignature(ica.Cert)
	e2, _ := engineWith(t, "sig2", root.Cert, badICA)
	leaf3 := testca.NewLeaf(testca.LeafConfig{CommonName: "z", DNSNames: []string{"z.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	// leaf3 is signed by the original ica key; CorruptSignature keeps TBS the
	// same, so leaf's signature still verifies against ica's key — but ica's
	// own signature vs root fails.
	_, err = e2.Validate(validator.Request{StoreID: "sig2", Leaf: leaf3.Cert})
	ve, ok := validator.AsVerificationError(err)
	if !ok || ve.Code != validator.CodeInvalidSignature || ve.CertIndex != 1 {
		t.Fatalf("expected INVALID_SIGNATURE at index 1, got %v", err)
	}
	logPass(t, "中间证书被篡改")
}

func TestLeafIsCARejected(t *testing.T) {
	logCase(t, "终端证书 cA=true", "用 IsCA 模板签发终端证书", "BASIC_CONSTRAINTS")
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	caLike := testca.NewIntermediate(testca.ICAConfig{CommonName: "FakeCA", Issuer: root, NotBefore: t0, NotAfter: t1})
	e, _ := engineWith(t, "caleaf", root.Cert, caLike.Cert)
	_, err := e.Validate(validator.Request{StoreID: "caleaf", Leaf: caLike.Cert})
	assertCode(t, err, validator.CodeBasicConstraints)
	logPass(t, "终端证书 cA=true")
}

func TestEmptyAndUnknownStore(t *testing.T) {
	logCase(t, "空 leaf", "请求未带证书", "EMPTY_INPUT")
	e := validator.NewEngine(fixedClock())
	if _, err := e.Validate(validator.Request{StoreID: "x"}); err == nil {
		t.Fatal("expected EMPTY_INPUT")
	} else {
		assertCode(t, err, validator.CodeEmptyInput)
	}
	logPass(t, "空 leaf")

	logCase(t, "未知信任库", "StoreID 未注册", "明确报错")
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	ica := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root, NotBefore: t0, NotAfter: t1})
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"x.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	if _, err := e.Validate(validator.Request{StoreID: "nope", Leaf: leaf.Cert}); err == nil {
		t.Fatal("expected unknown store error")
	}
	logPass(t, "未知信任库")
}

func TestHostnameMatching(t *testing.T) {
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	ica := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root, NotBefore: t0, NotAfter: t1})

	logCase(t, "DNS 精确匹配", "SAN example.com, 访问 example.com", "通过")
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "cn-ignored", DNSNames: []string{"example.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	e, _ := engineWith(t, "host", root.Cert, ica.Cert)
	if _, err := e.Validate(validator.Request{StoreID: "host", Leaf: leaf.Cert, Hostname: "example.com"}); err != nil {
		t.Fatalf("exact match should pass: %v", err)
	}
	logPass(t, "DNS 精确匹配")

	logCase(t, "通配符仅限左侧单标签", "SAN *.example.com", "a.example.com 通过; a.b.example.com/evil.com 拒绝")
	wild := testca.NewLeaf(testca.LeafConfig{CommonName: "w", DNSNames: []string{"*.example.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	if _, err := e.Validate(validator.Request{StoreID: "host", Leaf: wild.Cert, Hostname: "a.example.com"}); err != nil {
		t.Fatalf("wildcard one label: %v", err)
	}
	if _, err := e.Validate(validator.Request{StoreID: "host", Leaf: wild.Cert, Hostname: "a.b.example.com"}); err == nil {
		t.Fatal("wildcard must not match multiple labels")
	}
	logPass(t, "通配符仅限左侧单标签")

	logCase(t, "标识不匹配", "SAN example.com 访问 evil.com", "HOSTNAME_MISMATCH")
	if _, err := e.Validate(validator.Request{StoreID: "host", Leaf: leaf.Cert, Hostname: "evil.com"}); err == nil {
		t.Fatal("expected hostname mismatch")
	}
	logPass(t, "标识不匹配")

	logCase(t, "CN 不得作为别名绕过", "SAN=example.com 且 CN=trusted-ca.example, 访问 CN", "HOSTNAME_MISMATCH (只信 SAN)")
	if _, err := e.Validate(validator.Request{StoreID: "host", Leaf: leaf.Cert, Hostname: "cn-ignored"}); err == nil {
		t.Fatal("CN must not be accepted when SAN present and mismatched")
	}
	logPass(t, "CN 不得作为别名绕过")

	logCase(t, "IP 字面量匹配", "SAN IP 10.0.0.1", "通过; 其他 IP 拒绝")
	ipLeaf := testca.NewLeaf(testca.LeafConfig{CommonName: "ip", IPAddrs: []net.IP{net.ParseIP("10.0.0.1")}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	if _, err := e.Validate(validator.Request{StoreID: "host", Leaf: ipLeaf.Cert, IP: "10.0.0.1"}); err != nil {
		t.Fatalf("ip match: %v", err)
	}
	if _, err := e.Validate(validator.Request{StoreID: "host", Leaf: ipLeaf.Cert, IP: "10.0.0.2"}); err == nil {
		t.Fatal("expected ip mismatch")
	}
	logPass(t, "IP 字面量匹配")

	logCase(t, "邮箱 SAN 匹配", "SAN alice@example.com / .example.com", "精确与域匹配通过; 其他拒绝")
	mailLeaf := testca.NewLeaf(testca.LeafConfig{CommonName: "m", Emails: []string{"alice@example.com", ".example.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	for _, ok := range []string{"alice@example.com", "bob@sub.example.com"} {
		if _, err := e.Validate(validator.Request{StoreID: "host", Leaf: mailLeaf.Cert, Email: ok}); err != nil {
			t.Fatalf("email %s should pass: %v", ok, err)
		}
	}
	if _, err := e.Validate(validator.Request{StoreID: "host", Leaf: mailLeaf.Cert, Email: "bob@evil.org"}); err == nil {
		t.Fatal("expected email mismatch")
	}
	logPass(t, "邮箱 SAN 匹配")
}
