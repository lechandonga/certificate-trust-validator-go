package validator_test

import (
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/certificate-trust-validator-go/internal/testca"
	"github.com/lechandonga/certificate-trust-validator-go/revocation"
	"github.com/lechandonga/certificate-trust-validator-go/trust"
	"github.com/lechandonga/certificate-trust-validator-go/validator"
)

func buildRevPKI() (root *testca.CA, ica *testca.CA, leaf *testca.Leaf) {
	root = testca.NewRoot(testca.RootSpec{CommonName: "Root", NotBefore: t0, NotAfter: t1})
	ica = testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root, NotBefore: t0, NotAfter: t1})
	leaf = testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"x.example.com"}, Issuer: ica, NotBefore: t0, NotAfter: t1})
	return
}

func newRevEngine(policy revocation.Policy, root *testca.CA, ica *testca.CA) (*validator.Engine, string) {
	e := validator.NewEngine(validator.Options{
		Clock:            func() time.Time { return tn },
		RevocationPolicy: policy,
	})
	s := trust.NewStore("rev")
	_ = s.AddAnchor(root.Cert)
	_ = s.AddIntermediate(ica.Cert)
	e.AddStore(s)
	return e, "rev"
}

func issuerRevData(icaSubject string, rootSubject string) *revocation.Data {
	d := revocation.NewData()
	d.AddList(revocation.NewIssuerList(icaSubject, tn.Add(-time.Hour), tn.Add(time.Hour)))
	d.AddList(revocation.NewIssuerList(rootSubject, tn.Add(-time.Hour), tn.Add(time.Hour)))
	return d
}

func TestRevocationStates(t *testing.T) {
	root, ica, leaf := buildRevPKI()
	e, id := newRevEngine(revocation.PolicyFailClosed, root, ica)

	logCase(t, "吊销数据缺失-failClosed", "未安装任何吊销数据", "REVOCATION_UNAVAILABLE")
	_, err := e.Validate(validator.Request{StoreID: id, Leaf: leaf.Cert})
	assertCode(t, err, validator.CodeRevocationUnavailable)
	logPass(t, "吊销数据缺失-failClosed")

	logCase(t, "吊销数据缺失-failOpen", "同一证书, 显式 failOpen 配置", "通过")
	eOpen, idO := newRevEngine(revocation.PolicyFailOpen, root, ica)
	if _, err := eOpen.Validate(validator.Request{StoreID: idO, Leaf: leaf.Cert}); err != nil {
		t.Fatalf("failOpen on missing data: %v", err)
	}
	logPass(t, "吊销数据缺失-failOpen")

	logCase(t, "证书状态 good", "新鲜列表且不含 leaf 序列号", "通过")
	e.ReplaceRevocation(issuerRevData(ica.Cert.Subject.String(), root.Cert.Subject.String()))
	if _, err := e.Validate(validator.Request{StoreID: id, Leaf: leaf.Cert}); err != nil {
		t.Fatalf("good status: %v", err)
	}
	logPass(t, "证书状态 good")

	logCase(t, "证书已吊销", "把 leaf 序列号加入列表", "CERT_REVOKED")
	revoked := revocation.NewData()
	l := revocation.NewIssuerList(ica.Cert.Subject.String(), tn.Add(-time.Hour), tn.Add(time.Hour))
	if err := l.Add(leaf.Cert.SerialNumber, revocation.ReasonKeyCompromise, tn.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	revoked.AddList(l)
	revoked.AddList(revocation.NewIssuerList("CN=Root", tn.Add(-time.Hour), tn.Add(time.Hour)))
	e.ReplaceRevocation(revoked)
	_, err = e.Validate(validator.Request{StoreID: id, Leaf: leaf.Cert})
	assertCode(t, err, validator.CodeRevoked)
	logPass(t, "证书已吊销")

	logCase(t, "吊销列表过期-failClosed", "nextUpdate 已过", "REVOCATION_UNAVAILABLE")
	stale := revocation.NewData()
	stale.AddList(revocation.NewIssuerList(ica.Cert.Subject.String(), tn.Add(-2*time.Hour), tn.Add(-time.Minute)))
	stale.AddList(revocation.NewIssuerList("CN=Root", tn.Add(-2*time.Hour), tn.Add(-time.Minute)))
	e.ReplaceRevocation(stale)
	_, err = e.Validate(validator.Request{StoreID: id, Leaf: leaf.Cert})
	assertCode(t, err, validator.CodeRevocationUnavailable)
	logPass(t, "吊销列表过期-failClosed")

	logCase(t, "吊销列表过期-failOpen", "过期列表 + failOpen", "通过(即使 leaf 在过期列表里也放行? 否——过期数据不可信, 按策略放行)")
	eOpen.ReplaceRevocation(stale)
	if _, err := eOpen.Validate(validator.Request{StoreID: idO, Leaf: leaf.Cert}); err != nil {
		t.Fatalf("failOpen on stale data: %v", err)
	}
	logPass(t, "吊销列表过期-failOpen")

	logCase(t, "吊销列表未来-failClosed", "thisUpdate 在未来", "REVOCATION_UNAVAILABLE")
	future := revocation.NewData()
	future.AddList(revocation.NewIssuerList(ica.Cert.Subject.String(), tn.Add(time.Hour), tn.Add(2*time.Hour)))
	future.AddList(revocation.NewIssuerList("CN=Root", tn.Add(time.Hour), tn.Add(2*time.Hour)))
	e.ReplaceRevocation(future)
	_, err = e.Validate(validator.Request{StoreID: id, Leaf: leaf.Cert})
	assertCode(t, err, validator.CodeRevocationUnavailable)
	logPass(t, "吊销列表未来-failClosed")

	logCase(t, "failOpen 下实际吊销仍拒绝", "新鲜列表包含 leaf 序列号", "CERT_REVOKED")
	eOpen.ReplaceRevocation(revoked)
	// failOpen 只在数据不可用时放行; 新鲜数据明确吊销时仍必须拒绝。
	_, err = eOpen.Validate(validator.Request{StoreID: idO, Leaf: leaf.Cert})
	assertCode(t, err, validator.CodeRevoked)
	logPass(t, "failOpen 下实际吊销仍拒绝")
}

func TestRevocationHotUpdate(t *testing.T) {
	logCase(t, "吊销状态热更新立即生效", "good -> revoked -> removed", "三次校验结论依次为 通过/拒绝/通过, 版本号递增")
	root, ica, leaf := buildRevPKI()
	e, id := newRevEngine(revocation.PolicyFailClosed, root, ica)
	d1 := issuerRevData(ica.Cert.Subject.String(), root.Cert.Subject.String())
	e.ReplaceRevocation(d1)
	r1, err := e.Validate(validator.Request{StoreID: id, Leaf: leaf.Cert})
	if err != nil {
		t.Fatal(err)
	}
	if r1.RevVersion != 1 {
		t.Fatalf("expected rev version 1, got %d", r1.RevVersion)
	}

	d2 := revocation.NewData()
	l2 := revocation.NewIssuerList(ica.Cert.Subject.String(), tn.Add(-time.Hour), tn.Add(time.Hour))
	_ = l2.Add(leaf.Cert.SerialNumber, revocation.ReasonAffiliationChanged, tn.Add(-time.Minute))
	d2.AddList(l2)
	d2.AddList(revocation.NewIssuerList(root.Cert.Subject.String(), tn.Add(-time.Hour), tn.Add(time.Hour)))
	e.ReplaceRevocation(d2)
	_, err = e.Validate(validator.Request{StoreID: id, Leaf: leaf.Cert})
	assertCode(t, err, validator.CodeRevoked)

	e.ReplaceRevocation(issuerRevData(ica.Cert.Subject.String(), root.Cert.Subject.String()))
	r3, err := e.Validate(validator.Request{StoreID: id, Leaf: leaf.Cert})
	if err != nil {
		t.Fatalf("un-revoke should pass again: %v", err)
	}
	if r3.RevVersion != 3 {
		t.Fatalf("expected rev version 3, got %d", r3.RevVersion)
	}
	logPass(t, "吊销状态热更新立即生效")
}

func TestTrustHotUpdateConcurrency(t *testing.T) {
	logCase(t, "信任数据热更新+并发校验", "一批 goroutine 在校验中途把 Root 换成新根(旧根删除)", "每个结果只反映旧版或新版完整数据, 无混合态/崩溃")
	root1 := testca.NewRoot(testca.RootSpec{CommonName: "Root1", Serial: big(1), NotBefore: t0, NotAfter: t1})
	root2 := testca.NewRoot(testca.RootSpec{CommonName: "Root2", Serial: big(2), NotBefore: t0, NotAfter: t1})
	ica1 := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root1, Serial: big(10), NotBefore: t0, NotAfter: t1})
	ica2 := testca.NewIntermediate(testca.ICAConfig{CommonName: "ICA", Issuer: root2, Serial: big(11), NotBefore: t0, NotAfter: t1})
	leaf1 := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"x.example.com"}, Issuer: ica1, Serial: big(20), NotBefore: t0, NotAfter: t1})
	leaf2 := testca.NewLeaf(testca.LeafConfig{CommonName: "x", DNSNames: []string{"x.example.com"}, Issuer: ica2, Serial: big(21), NotBefore: t0, NotAfter: t1})

	store1 := trust.NewStore("live")
	_ = store1.AddAnchor(root1.Cert)
	_ = store1.AddIntermediate(ica1.Cert)

	e := validator.NewEngine(fixedClock()) // no revocation policy config -> need data?
	// Install fresh revocation data covering both ICA subjects (same subject
	// string "ICA") up front so policy is not exercised.
	d := revocation.NewData()
	d.AddList(revocation.NewIssuerList(ica1.Cert.Subject.String(), tn.Add(-time.Hour), tn.Add(time.Hour)))
	d.AddList(revocation.NewIssuerList("CN=Root1", tn.Add(-time.Hour), tn.Add(time.Hour)))
	d.AddList(revocation.NewIssuerList("CN=Root2", tn.Add(-time.Hour), tn.Add(time.Hour)))
	e.ReplaceRevocation(d)
	e.AddStore(store1)

	const goroutines = 32
	const iterations = 200
	var wg sync.WaitGroup
	var mu sync.Mutex
	var passOld, passNew, rejected int

	stop := make(chan struct{})
	go func() {
		useFirst := true
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Rebuild whole store snapshot atomically: version N = root1,
			// version N+1 = root2.
			s := trust.NewStore("live")
			if useFirst {
				_ = s.AddAnchor(root1.Cert)
				_ = s.AddIntermediate(ica1.Cert)
			} else {
				_ = s.AddAnchor(root2.Cert)
				_ = s.AddIntermediate(ica2.Cert)
			}
			e.ReplaceStore("live", s)
			useFirst = !useFirst
			time.Sleep(time.Microsecond * 50)
		}
	}()

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				leaf := leaf1.Cert
				if (g+i)%2 == 0 {
					leaf = leaf2.Cert
				}
				res, err := e.Validate(validator.Request{StoreID: "live", Leaf: leaf})
				mu.Lock()
				switch {
				case err == nil && res.Chain[2].Subject.CommonName == "Root1":
					passOld++
				case err == nil && res.Chain[2].Subject.CommonName == "Root2":
					passNew++
				default:
					rejected++
				}
				mu.Unlock()
			}
		}(g)
	}
	wg.Wait()
	close(stop)

	total := passOld + passNew + rejected
	t.Logf("并发结果: Root1通过=%d Root2通过=%d 拒绝=%d 总计=%d", passOld, passNew, rejected, total)
	if total != goroutines*iterations {
		t.Fatalf("lost validations: %d vs %d", total, goroutines*iterations)
	}
	if passOld == 0 || passNew == 0 {
		t.Fatalf("expected both snapshots to be observed: old=%d new=%d", passOld, passNew)
	}
	// Rejection is legitimate only when leaf doesn't match the active root;
	// every acceptance must be exactly one full version (asserted by chain
	// anchor identity above). There must be no panic/torn state.
	logPass(t, "信任数据热更新+并发校验")
}
