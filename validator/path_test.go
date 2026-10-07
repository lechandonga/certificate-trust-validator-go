package validator_test

import (
	"crypto/x509"
	"testing"

	"github.com/lechandonga/certificate-trust-validator-go/internal/testca"
	"github.com/lechandonga/certificate-trust-validator-go/trust"
	"github.com/lechandonga/certificate-trust-validator-go/validator"
)

func TestValidBasicChain(t *testing.T) {
	logCase(t, "基础合法链", "leaf/ica/root 正常签发且在有效期", "通过, 链长 3")
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	ica := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root, NotBefore: t0, NotAfter: t1})
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "example", DNSNames: []string{"example.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})

	e, _ := engineWith(t, "prod", root.Cert, ica.Cert)
	res, err := e.Validate(validator.Request{StoreID: "prod", Leaf: leaf.Cert, Hostname: "example.com"})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if len(res.Chain) != 3 {
		t.Fatalf("expected chain length 3, got %d", len(res.Chain))
	}
	logPass(t, "基础合法链")
}

func TestBrokenChain(t *testing.T) {
	logCase(t, "断链", "签发 ICA 未装入信任库也未随链提供", "NO_VALID_PATH")
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	ica := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root, NotBefore: t0, NotAfter: t1})
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"x.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})

	e, _ := engineWith(t, "broken", root.Cert)
	_, err := e.Validate(validator.Request{StoreID: "broken", Leaf: leaf.Cert})
	assertCode(t, err, validator.CodeNoPath)
	logPass(t, "断链")

	logCase(t, "随链提供中间证书", "对端把 ICA 放在 Intermediates 中", "通过; 随链证书不赋予信任")
	e2 := validator.NewEngine(fixedClock())
	s2 := trust.NewStore("broken2")
	_ = s2.AddAnchor(root.Cert)
	e2.AddStore(s2)
	if _, err := e2.Validate(validator.Request{StoreID: "broken2", Leaf: leaf.Cert, Intermediates: []*x509.Certificate{ica.Cert}}); err != nil {
		t.Fatalf("presented intermediate should build path: %v", err)
	}

	logCase(t, "随链中间证书无锚点", "只有 ICA 没有任何根", "NO_VALID_PATH")
	s3 := trust.NewStore("broken3")
	e3 := validator.NewEngine(fixedClock())
	e3.AddStore(s3)
	_, err = e3.Validate(validator.Request{StoreID: "broken3", Leaf: leaf.Cert, Intermediates: []*x509.Certificate{ica.Cert}})
	assertCode(t, err, validator.CodeNoPath)
	logPass(t, "随链中间证书无锚点")
}

func TestCycleChain(t *testing.T) {
	logCase(t, "成环", "A/B 互相交叉签名, 环内证书无法到达锚点", "PATH_CYCLE")
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	a := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA-A", Issuer: root, NotBefore: t0, NotAfter: t1})
	b := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA-B", Issuer: root, NotBefore: t0, NotAfter: t1})
	crossA := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA-A", SelfKey: a.Key, Issuer: b, NotBefore: t0, NotAfter: t1})
	crossB := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA-B", SelfKey: b.Key, Issuer: a, NotBefore: t0, NotAfter: t1})
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"x.com"}, Issuer: crossA, NotBefore: t0, NotAfter: t1})

	// 只放交叉证书: leaf->crossA->crossB->crossA ... 环, 原始 a/b(可达 root) 缺席。
	e, _ := engineWith(t, "loopy", root.Cert, crossA.Cert, crossB.Cert)
	_, err := e.Validate(validator.Request{StoreID: "loopy", Leaf: leaf.Cert})
	assertCode(t, err, validator.CodeCycle)
	logPass(t, "成环")

	logCase(t, "环旁存在合法路径", "同时放入原始 a(可直达 root)", "确定性选中合法路径而非环")
	s := trust.NewStore("loopy2")
	_ = s.AddAnchor(root.Cert)
	_ = s.AddIntermediate(crossA.Cert)
	_ = s.AddIntermediate(crossB.Cert)
	_ = s.AddIntermediate(a.Cert)
	_ = s.AddIntermediate(b.Cert)
	e2 := validator.NewEngine(fixedClock())
	e2.AddStore(s)
	res, err := e2.Validate(validator.Request{StoreID: "loopy2", Leaf: leaf.Cert})
	if err != nil {
		t.Fatalf("valid path beside a cycle must pass: %v", err)
	}
	if res.Chain[len(res.Chain)-1].Subject.CommonName != "Root" {
		t.Fatalf("unexpected anchor: %s", res.Chain[len(res.Chain)-1].Subject)
	}
	logPass(t, "环旁存在合法路径")
}
