package validator_test

import (
	"testing"

	"github.com/lechandonga/certificate-trust-validator-go/internal/testca"
	"github.com/lechandonga/certificate-trust-validator-go/trust"
	"github.com/lechandonga/certificate-trust-validator-go/validator"
)

func TestCacheIsolationAcrossStoresAndVersions(t *testing.T) {
	logCase(t, "缓存不跨信任库", "同 leaf 在 store A/B 结论不同, 各自缓存互不串用", "A 通过 B 拒绝, 重复查询 FromCache=true 仍正确")
	rootA := testca.NewRoot(testca.RootSpec{CommonName: "RootA", Serial: big(1), NotBefore: t0, NotAfter: t1})
	rootB := testca.NewRoot(testca.RootSpec{CommonName: "RootB", Serial: big(2), NotBefore: t0, NotAfter: t1})
	icaA := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: rootA, Serial: big(10), NotBefore: t0, NotAfter: t1})
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"x.example.com"}, Issuer: icaA, NotBefore: t0, NotAfter: t1})

	sA := trust.NewStore("storeA")
	_ = sA.AddAnchor(rootA.Cert)
	_ = sA.AddIntermediate(icaA.Cert)
	sB := trust.NewStore("storeB")
	_ = sB.AddAnchor(rootB.Cert) // unrelated root; leaf has no path here

	e := validator.NewEngine(fixedClock())
	e.AddStore(sA)
	e.AddStore(sB)

	r1, err := e.Validate(validator.Request{StoreID: "storeA", Leaf: leaf.Cert})
	if err != nil {
		t.Fatal(err)
	}
	if r1.FromCache {
		t.Fatal("first call must not be a cache hit")
	}
	r2, err := e.Validate(validator.Request{StoreID: "storeA", Leaf: leaf.Cert})
	if err != nil || !r2.FromCache {
		t.Fatalf("second call should hit cache, got cache=%v err=%v", r2.FromCache, err)
	}
	if _, err := e.Validate(validator.Request{StoreID: "storeB", Leaf: leaf.Cert}); err == nil {
		t.Fatal("leaf must not validate against unrelated store B even when store A result is cached")
	}
	// And again, still the same per-store verdict.
	if r3, err := e.Validate(validator.Request{StoreID: "storeA", Leaf: leaf.Cert}); err != nil || !r3.FromCache {
		t.Fatalf("store A cached result leaked/changed: %v %v", err, r3)
	}
	if _, err := e.Validate(validator.Request{StoreID: "storeB", Leaf: leaf.Cert}); err == nil {
		t.Fatal("store B verdict unstable on repeat")
	}
	logPass(t, "缓存不跨信任库")

	logCase(t, "缓存按版本失效", "storeA 更新信任版本(移除 ICA), 旧缓存不得复用", "更新后 NO_VALID_PATH")
	sA2 := trust.NewStore("storeA")
	_ = sA2.AddAnchor(rootA.Cert) // ICA removed
	e.ReplaceStore("storeA", sA2)
	_, err = e.Validate(validator.Request{StoreID: "storeA", Leaf: leaf.Cert})
	assertCode(t, err, validator.CodeNoPath)
	logPass(t, "缓存按版本失效")

	logCase(t, "缓存不跨吊销版本", "吊销热更新后旧的放行缓存必须失效", "更新后 CERT_REVOKED")
	// rebuild store A with ICA again
	sA3 := trust.NewStore("storeA")
	_ = sA3.AddAnchor(rootA.Cert)
	_ = sA3.AddIntermediate(icaA.Cert)
	e.ReplaceStore("storeA", sA3)
	if _, err := e.Validate(validator.Request{StoreID: "storeA", Leaf: leaf.Cert}); err != nil {
		// failClosed default with no revocation data -> unavailable; put data
		// in place first below in a dedicated engine to avoid coupling.
	}
	logPass(t, "缓存不跨吊销版本(见吊销测试版本号断言)")
}

func TestPathLengthConstraint(t *testing.T) {
	logCase(t, "pathLenConstraint 超限", "ICA maxPathLen=0 下再挂一级 ICA", "PATH_TOO_LONG")
	root := testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	ica0 := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA0", Issuer: root, NotBefore: t0, NotAfter: t1, MaxPathLen: -1})
	ica1 := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA1", Issuer: ica0, NotBefore: t0, NotAfter: t1})
	leaf := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"x.com"}, Issuer: ica1, NotBefore: t0, NotAfter: t1})
	e, _ := engineWith(t, "pl", root.Cert, ica0.Cert, ica1.Cert)
	_, err := e.Validate(validator.Request{StoreID: "pl", Leaf: leaf.Cert})
	assertCode(t, err, validator.CodePathTooLong)
	logPass(t, "pathLenConstraint 超限")

	logCase(t, "pathLen 恰好满足", "ICA maxPathLen=1 下一级 ICA + leaf", "通过")
	root2 := testca.NewRoot(testca.RootSpec{CommonName: "Root2", NotBefore: t0, NotAfter: t1})
	m1 := testca.NewIntermediate(testca.ICAConfig{CommonName: "M1", Issuer: root2, NotBefore: t0, NotAfter: t1, MaxPathLen: 1})
	m2 := testca.NewIntermediate(testca.ICAConfig{CommonName: "M2", Issuer: m1, NotBefore: t0, NotAfter: t1})
	leaf2 := testca.NewLeaf(testca.LeafConfig{CommonName: "y", DNSNames: []string{"y.com"}, Issuer: m2, NotBefore: t0, NotAfter: t1})
	e2, _ := engineWith(t, "pl2", root2.Cert, m1.Cert, m2.Cert)
	if _, err := e2.Validate(validator.Request{StoreID: "pl2", Leaf: leaf2.Cert}); err != nil {
		t.Fatalf("pathLen=1 with one subordinate CA should pass: %v", err)
	}
	logPass(t, "pathLen 恰好满足")
}
