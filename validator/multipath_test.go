package validator_test

import (
	"crypto/x509"
	"testing"

	"github.com/lechandonga/certificate-trust-validator-go/internal/testca"
	"github.com/lechandonga/certificate-trust-validator-go/trust"
	"github.com/lechandonga/certificate-trust-validator-go/validator"
)

func TestCrossSignDeterministic(t *testing.T) {
	logCase(t, "交叉签名-双合法", "共享 ICA 密钥被 Root1/Root2 同时签发", "多次校验稳定选中同一锚点")
	root1 := testca.NewRoot(testca.RootSpec{CommonName: "Root1", Serial: big(1), NotBefore: t0, NotAfter: t1})
	root2 := testca.NewRoot(testca.RootSpec{CommonName: "Root2", Serial: big(2), NotBefore: t0, NotAfter: t1})
	icaKey := newECKey(t)
	ica1 := testca.NewIntermediate(testca.ICAConfig{CommonName: "Shared-ICA", SelfKey: icaKey, Issuer: root1, Serial: big(10), NotBefore: t0, NotAfter: t1})
	ica2 := testca.NewIntermediate(testca.ICAConfig{CommonName: "Shared-ICA", SelfKey: icaKey, Issuer: root2, Serial: big(11), NotBefore: t0, NotAfter: t1})
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"example.com"}, Issuer: ica1, NotBefore: t0, NotAfter: t1})

	s := trust.NewStore("multi")
	_ = s.AddAnchor(root1.Cert)
	_ = s.AddAnchor(root2.Cert)
	_ = s.AddIntermediate(ica1.Cert)
	_ = s.AddIntermediate(ica2.Cert)
	e := validator.NewEngine(fixedClock())
	e.AddStore(s)

	var picked string
	for i := 0; i < 8; i++ {
		res, err := e.Validate(validator.Request{StoreID: "multi", Leaf: leaf.Cert})
		if err != nil {
			t.Fatal(err)
		}
		anchor := res.Chain[len(res.Chain)-1].Subject.CommonName
		if i == 0 {
			picked = anchor
			t.Logf("确定性路径选择: %v", chainSubjects(res))
		} else if anchor != picked {
			t.Fatalf("non-deterministic: %s vs %s", picked, anchor)
		}
	}
	logPass(t, "交叉签名-双合法")

	logCase(t, "交叉签名-首选非法回退", "serial 较小路径的 ICA 过期, 另一路径合法", "稳定回退到 Root2 路径")
	expired := testca.NewIntermediate(testca.ICAConfig{CommonName: "Shared-ICA", SelfKey: icaKey, Issuer: root1, Serial: big(10), NotBefore: t0, NotAfter: tn.Add(-timeHour)})
	s2 := trust.NewStore("multi2")
	_ = s2.AddAnchor(root1.Cert)
	_ = s2.AddAnchor(root2.Cert)
	_ = s2.AddIntermediate(expired.Cert)
	_ = s2.AddIntermediate(ica2.Cert)
	e2 := validator.NewEngine(fixedClock())
	e2.AddStore(s2)
	res, err := e2.Validate(validator.Request{StoreID: "multi2", Leaf: leaf.Cert})
	if err != nil {
		t.Fatalf("expected deterministic fallback: %v", err)
	}
	if res.Chain[len(res.Chain)-1].Subject.CommonName != "Root2" {
		t.Fatalf("expected Root2 fallback, got %s", res.Chain[len(res.Chain)-1].Subject)
	}
	logPass(t, "交叉签名-首选非法回退")

	logCase(t, "多条等长路径不同中间层", "两个独立根各有 ICA, leaf 被两个 ICA 同主体密钥签发", "可复现选择")
	rootA := testca.NewRoot(testca.RootSpec{CommonName: "RootA", Serial: big(101), NotBefore: t0, NotAfter: t1})
	rootB := testca.NewRoot(testca.RootSpec{CommonName: "RootB", Serial: big(102), NotBefore: t0, NotAfter: t1})
	icaKey2 := newECKey(t)
	icaA := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA-X", SelfKey: icaKey2, Issuer: rootA, Serial: big(201), NotBefore: t0, NotAfter: t1})
	icaB := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA-X", SelfKey: icaKey2, Issuer: rootB, Serial: big(202), NotBefore: t0, NotAfter: t1})
	leaf2 := testca.NewLeaf(testca.LeafConfig{CommonName: "h", DNSNames: []string{"h.com"}, Issuer: icaA, Serial: big(300), NotBefore: t0, NotAfter: t1})
	s3 := trust.NewStore("multi3")
	_ = s3.AddAnchor(rootB.Cert)
	_ = s3.AddAnchor(rootA.Cert)
	_ = s3.AddIntermediate(icaB.Cert)
	_ = s3.AddIntermediate(icaA.Cert)
	e3 := validator.NewEngine(fixedClock())
	e3.AddStore(s3)
	var p1, p2 string
	for i := 0; i < 4; i++ {
		r1, _ := e3.Validate(validator.Request{StoreID: "multi3", Leaf: leaf2.Cert})
		r2, _ := e3.Validate(validator.Request{StoreID: "multi3", Leaf: leaf2.Cert})
		p1, p2 = r1.Chain[2].Subject.CommonName, r2.Chain[2].Subject.CommonName
		if p1 != p2 {
			t.Fatalf("runs diverged: %s vs %s", p1, p2)
		}
	}
	t.Logf("双 ICA 等长路径稳定选择锚点 %s", p1)
	logPass(t, "多条等长路径不同中间层")
}

const timeHour = 60 * 60 * 1_000_000_000 // time.Hour without importing time again

func TestValidityWindow(t *testing.T) {
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	ica := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root, NotBefore: t0, NotAfter: t1})

	logCase(t, "过期", "leaf NotAfter 早于当前时间", "CERT_EXPIRED")
	expired := testca.NewLeaf(testca.LeafConfig{CommonName: "e", DNSNames: []string{"e.com"}, Issuer: ica, NotBefore: t0, NotAfter: tn.Add(-24 * timeHour)})
	e, _ := engineWith(t, "v", root.Cert, ica.Cert)
	_, err := e.Validate(validator.Request{StoreID: "v", Leaf: expired.Cert})
	assertCode(t, err, validator.CodeExpired)
	logPass(t, "过期")

	logCase(t, "未生效", "leaf NotBefore 晚于当前时间", "CERT_NOT_YET_VALID")
	future := testca.NewLeaf(testca.LeafConfig{CommonName: "f", DNSNames: []string{"f.com"}, Issuer: ica, NotBefore: tn.Add(24 * timeHour), NotAfter: t1})
	_, err = e.Validate(validator.Request{StoreID: "v", Leaf: future.Cert})
	assertCode(t, err, validator.CodeNotYetValid)
	logPass(t, "未生效")

	logCase(t, "中间证书过期", "ICA 已过期但 leaf 有效", "CERT_EXPIRED 且 CertIndex=1")
	oldICA := testca.NewIntermediate(testca.ICAConfig{CommonName: "OldICA", Issuer: root, NotBefore: t0, NotAfter: tn.Add(-24 * timeHour)})
	leaf2 := testca.NewLeaf(testca.LeafConfig{CommonName: "g", DNSNames: []string{"g.com"}, Issuer: oldICA, NotBefore: t0, NotAfter: t1})
	e2, _ := engineWith(t, "v2", root.Cert, oldICA.Cert)
	_, err = e2.Validate(validator.Request{StoreID: "v2", Leaf: leaf2.Cert})
	ve, ok := validator.AsVerificationError(err)
	if !ok || ve.Code != validator.CodeExpired || ve.CertIndex != 1 {
		t.Fatalf("expected CERT_EXPIRED at index 1, got %v", err)
	}
	logPass(t, "中间证书过期")
}

func TestKeyUsageAndEKU(t *testing.T) {
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})

	logCase(t, "ICA 缺少 keyCertSign", "中间 CA keyUsage 仅 digitalSignature", "KEY_USAGE_MISMATCH")
	badICA := testca.NewIntermediate(testca.ICAConfig{CommonName: "BadICA", Issuer: root, NotBefore: t0, NotAfter: t1, KeyUsage: x509.KeyUsageDigitalSignature})
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"x.com"}, Issuer: badICA, NotBefore: t0, NotAfter: t1})
	e, _ := engineWith(t, "ku", root.Cert, badICA.Cert)
	_, err := e.Validate(validator.Request{StoreID: "ku", Leaf: leaf.Cert})
	assertCode(t, err, validator.CodeKeyUsage)
	logPass(t, "ICA 缺少 keyCertSign")

	logCase(t, "leaf 无 serverAuth", "EKU 仅 clientAuth", "EXT_KEY_USAGE_MISMATCH")
	ica := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root, NotBefore: t0, NotAfter: t1})
	leaf2 := testca.NewLeaf(testca.LeafConfig{CommonName: "y", DNSNames: []string{"y.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1, EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	e2, _ := engineWith(t, "ku2", root.Cert, ica.Cert)
	_, err = e2.Validate(validator.Request{StoreID: "ku2", Leaf: leaf2.Cert})
	assertCode(t, err, validator.CodeExtKeyUsage)
	logPass(t, "leaf 无 serverAuth")

	logCase(t, "CA EKU 不含 serverAuth", "中间 CA 仅允许 clientAuth", "EXT_KEY_USAGE_MISMATCH")
	restrictedICA := testca.NewIntermediate(testca.ICAConfig{CommonName: "RICA", Issuer: root, NotBefore: t0, NotAfter: t1, EKU: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	leaf3 := testca.NewLeaf(testca.LeafConfig{CommonName: "z", DNSNames: []string{"z.com"}, Issuer: restrictedICA, NotBefore: t0, NotAfter: t1})
	e3, _ := engineWith(t, "ku3", root.Cert, restrictedICA.Cert)
	_, err = e3.Validate(validator.Request{StoreID: "ku3", Leaf: leaf3.Cert})
	assertCode(t, err, validator.CodeExtKeyUsage)
	logPass(t, "CA EKU 不含 serverAuth")
}
