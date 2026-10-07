package validator_test

import (
	"net"
	"testing"

	"github.com/lechandonga/certificate-trust-validator-go/internal/testca"
	"github.com/lechandonga/certificate-trust-validator-go/validator"
)

func constrainedChain(t *testing.T, nc *testca.NameConstraintSpec, leafCfg testca.LeafConfig) (*validator.Engine, string, testca.LeafConfig) {
	t.Helper()
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	ica := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root, NotBefore: t0, NotAfter: t1, NameConst: nc})
	e, _ := engineWith(t, "nc", root.Cert, ica.Cert)
	leafCfg.Issuer = ica
	leafCfg.NotBefore, leafCfg.NotAfter = t0, t1
	return e, "nc", leafCfg
}

func TestNameConstraintsDNS(t *testing.T) {
	logCase(t, "permitted 包含目标", "permitted=.example.com, leaf SAN a.example.com", "通过")
	e, id, cfg := constrainedChain(t,
		&testca.NameConstraintSpec{PermittedDNS: []string{".example.com"}},
		testca.LeafConfig{CommonName: "a", DNSNames: []string{"a.example.com"}})
	leaf := testca.NewLeaf(cfg)
	if _, err := e.Validate(validator.Request{StoreID: id, Leaf: leaf.Cert, Hostname: "a.example.com"}); err != nil {
		t.Fatalf("permitted match: %v", err)
	}
	logPass(t, "permitted 包含目标")

	logCase(t, "permitted 不包含目标", "permitted=.example.com, leaf SAN a.evil.com", "NAME_CONSTRAINT_VIOLATION")
	e2b, id2b, cfg2 := constrainedChain(t,
		&testca.NameConstraintSpec{PermittedDNS: []string{".example.com"}},
		testca.LeafConfig{CommonName: "b", DNSNames: []string{"a.evil.com"}})
	leaf2 := testca.NewLeaf(cfg2)
	if _, err := e2b.Validate(validator.Request{StoreID: id2b, Leaf: leaf2.Cert}); err == nil {
		t.Fatal("expected name constraint violation")
	} else {
		assertCode(t, err, validator.CodeNameConstraints)
	}
	logPass(t, "permitted 不包含目标")

	logCase(t, "excluded 命中", "excluded=.evil.com", "NAME_CONSTRAINT_VIOLATION")
	e3, id3, cfg3 := func() (*validator.Engine, string, testca.LeafConfig) {
		return constrainedChain(t,
			&testca.NameConstraintSpec{ExcludedDNS: []string{".evil.com"}},
			testca.LeafConfig{CommonName: "c", DNSNames: []string{"x.evil.com"}})
	}()
	leaf3 := testca.NewLeaf(cfg3)
	_, err := e3.Validate(validator.Request{StoreID: id3, Leaf: leaf3.Cert})
	assertCode(t, err, validator.CodeNameConstraints)
	logPass(t, "excluded 命中")
}

func TestNameConstraintsHierarchyConflict(t *testing.T) {
	logCase(t, "上下级 permitted 冲突", "root 限 .a.com, ICA 限 .b.com", "leaf 无论如何都违反某一级 -> 拒绝")
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	// 两级累积: ICA1(permitted .a.com) -> ICA2(permitted .b.com) 形成冲突。
	ncRoot := &testca.NameConstraintSpec{PermittedDNS: []string{".a.com"}}
	ica1 := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA1", Issuer: root, NotBefore: t0, NotAfter: t1, NameConst: ncRoot})
	ica2 := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA2", Issuer: ica1, NotBefore: t0, NotAfter: t1,
		NameConst: &testca.NameConstraintSpec{PermittedDNS: []string{".b.com"}}})
	leafA := testca.NewLeaf(testca.LeafConfig{CommonName: "la", DNSNames: []string{"host.a.com"}, Issuer: ica2, NotBefore: t0, NotAfter: t1})
	leafB := testca.NewLeaf(testca.LeafConfig{CommonName: "lb", DNSNames: []string{"host.b.com"}, Issuer: ica2, NotBefore: t0, NotAfter: t1})

	e, _ := engineWith(t, "hier", root.Cert, ica1.Cert, ica2.Cert)
	if _, err := e.Validate(validator.Request{StoreID: "hier", Leaf: leafA.Cert}); err == nil {
		t.Fatal("host.a.com violates ICA2 permitted .b.com")
	} else {
		assertCode(t, err, validator.CodeNameConstraints)
	}
	if _, err := e.Validate(validator.Request{StoreID: "hier", Leaf: leafB.Cert}); err == nil {
		t.Fatal("host.b.com violates root-level permitted .a.com")
	} else {
		assertCode(t, err, validator.CodeNameConstraints)
	}

	logCase(t, "交集内通过", "leaf 同时满足两级 (用逐级包含的域)", "通过")
	ncRoot2 := &testca.NameConstraintSpec{PermittedDNS: []string{".example.com"}}
	ica3 := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA3", Issuer: root, NotBefore: t0, NotAfter: t1, NameConst: ncRoot2})
	ica4 := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA4", Issuer: ica3, NotBefore: t0, NotAfter: t1,
		NameConst: &testca.NameConstraintSpec{PermittedDNS: []string{"api.example.com"}}})
	leafOK := testca.NewLeaf(testca.LeafConfig{CommonName: "ok", DNSNames: []string{"api.example.com"}, Issuer: ica4, NotBefore: t0, NotAfter: t1})
	e2, _ := engineWith(t, "hier2", root.Cert, ica3.Cert, ica4.Cert)
	if _, err := e2.Validate(validator.Request{StoreID: "hier2", Leaf: leafOK.Cert}); err != nil {
		t.Fatalf("intersection name should pass: %v", err)
	}
	logPass(t, "交集内通过")

	logCase(t, "excluded 与下层 permitted 冲突", "上层 exclude .example.com, 下层 permit .example.com", "excluded 优先 -> 拒绝")
	ica5 := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA5", Issuer: root, NotBefore: t0, NotAfter: t1,
		NameConst: &testca.NameConstraintSpec{ExcludedDNS: []string{".example.com"}}})
	leafX := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"api.example.com"}, Issuer: ica5, NotBefore: t0, NotAfter: t1})
	e3, _ := engineWith(t, "hier3", root.Cert, ica5.Cert)
	_, err := e3.Validate(validator.Request{StoreID: "hier3", Leaf: leafX.Cert})
	assertCode(t, err, validator.CodeNameConstraints)
	logPass(t, "excluded 与下层 permitted 冲突")
}

func TestNameConstraintsIPAndMail(t *testing.T) {
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	ica := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root, NotBefore: t0, NotAfter: t1,
		NameConst: &testca.NameConstraintSpec{
			PermittedIPs:    []string{"10.1.0.0/16"},
			ExcludedIPs:     []string{"10.1.2.0/24"},
			PermittedEmails: []string{".example.com"},
			ExcludedEmails:  []string{"bad@example.com"},
		}})
	e, _ := engineWith(t, "ncip", root.Cert, ica.Cert)

	logCase(t, "IP 在 permitted 段内", "10.1.5.6 ∈ 10.1.0.0/16", "通过")
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "i", IPAddrs: []net.IP{net.ParseIP("10.1.5.6")}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	if _, err := e.Validate(validator.Request{StoreID: "ncip", Leaf: leaf.Cert, IP: "10.1.5.6"}); err != nil {
		t.Fatalf("permitted cidr: %v", err)
	}
	logPass(t, "IP 在 permitted 段内")

	logCase(t, "IP 在 excluded 子段", "10.1.2.3 被排除", "NAME_CONSTRAINT_VIOLATION")
	leaf2 := testca.NewLeaf(testca.LeafConfig{CommonName: "i2", IPAddrs: []net.IP{net.ParseIP("10.1.2.3")}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	_, err := e.Validate(validator.Request{StoreID: "ncip", Leaf: leaf2.Cert})
	assertCode(t, err, validator.CodeNameConstraints)
	logPass(t, "IP 在 excluded 子段")

	logCase(t, "IP 在 permitted 段外", "192.168.0.1", "NAME_CONSTRAINT_VIOLATION")
	leaf3 := testca.NewLeaf(testca.LeafConfig{CommonName: "i3", IPAddrs: []net.IP{net.ParseIP("192.168.0.1")}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	_, err = e.Validate(validator.Request{StoreID: "ncip", Leaf: leaf3.Cert})
	assertCode(t, err, validator.CodeNameConstraints)
	logPass(t, "IP 在 permitted 段外")

	logCase(t, "邮箱 permitted/excluded", "good@example.com 通过, bad@example.com 与 x@evil.com 拒绝", "分类正确")
	leafM := testca.NewLeaf(testca.LeafConfig{CommonName: "m", Emails: []string{"good@example.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	if _, err := e.Validate(validator.Request{StoreID: "ncip", Leaf: leafM.Cert, Email: "good@example.com"}); err != nil {
		t.Fatalf("good mail: %v", err)
	}
	leafM2 := testca.NewLeaf(testca.LeafConfig{CommonName: "m2", Emails: []string{"bad@example.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	_, err = e.Validate(validator.Request{StoreID: "ncip", Leaf: leafM2.Cert, Email: "bad@example.com"})
	assertCode(t, err, validator.CodeNameConstraints)
	leafM3 := testca.NewLeaf(testca.LeafConfig{CommonName: "m3", Emails: []string{"x@evil.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	_, err = e.Validate(validator.Request{StoreID: "ncip", Leaf: leafM3.Cert, Email: "x@evil.com"})
	assertCode(t, err, validator.CodeNameConstraints)
	logPass(t, "邮箱 permitted/excluded")
}
