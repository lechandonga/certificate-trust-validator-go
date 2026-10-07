// Command ctvdemo builds a complete local PKI in memory and demonstrates
// deterministic chain validation and policy-driven revocation decisions.
// Nothing touches the network or the host trust store.
//
//	go run ./cmd/ctvdemo
package main

import (
	"fmt"
	"time"

	"github.com/lechandonga/certificate-trust-validator-go/internal/testca"
	"github.com/lechandonga/certificate-trust-validator-go/revocation"
	"github.com/lechandonga/certificate-trust-validator-go/trust"
	"github.com/lechandonga/certificate-trust-validator-go/validator"
)

func main() {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	start := now.Add(-365 * 24 * time.Hour)
	end := now.Add(365 * 24 * time.Hour)

	root := testca.NewRoot(testca.RootSpec{CommonName: "Demo Root", NotBefore: start, NotAfter: end})
	ica := testca.NewIntermediate(testca.ICAConfig{
		CommonName: "Demo ICA", Issuer: root, NotBefore: start, NotAfter: end,
		NameConst: &testca.NameConstraintSpec{PermittedDNS: []string{".demo.example"}},
	})
	leaf := testca.NewLeaf(testca.LeafConfig{
		CommonName: "app", DNSNames: []string{"app.demo.example"},
		Issuer: ica, NotBefore: start, NotAfter: end,
	})

	store := trust.NewStore("demo")
	must(store.AddAnchor(root.Cert))
	must(store.AddIntermediate(ica.Cert))

	engine := validator.NewEngine(validator.Options{
		Clock:            func() time.Time { return now },
		RevocationPolicy: revocation.PolicyFailClosed,
		CacheResults:     true,
	})
	engine.AddStore(store)

	// 1) fail-closed with no revocation data -> explicit refusal.
	run(engine, leaf, 1, "fail-closed, 无吊销数据")

	// 2) install fresh good lists for ICA (leaf issuer) and Root (ICA issuer).
	data := revocation.NewData()
	data.AddList(revocation.NewIssuerList(ica.Cert.Subject.String(), now.Add(-time.Hour), now.Add(time.Hour)))
	data.AddList(revocation.NewIssuerList(root.Cert.Subject.String(), now.Add(-time.Hour), now.Add(time.Hour)))
	engine.ReplaceRevocation(data)
	run(engine, leaf, 2, "新鲜 good 列表")

	// 3) hot update: revoke the leaf. Decision flips immediately.
	rev := revocation.NewData()
	l := revocation.NewIssuerList(ica.Cert.Subject.String(), now.Add(-time.Hour), now.Add(time.Hour))
	must(l.Add(leaf.Cert.SerialNumber, revocation.ReasonKeyCompromise, now.Add(-time.Minute)))
	rev.AddList(l)
	rev.AddList(revocation.NewIssuerList(root.Cert.Subject.String(), now.Add(-time.Hour), now.Add(time.Hour)))
	engine.ReplaceRevocation(rev)
	run(engine, leaf, 3, "热更新: leaf 被吊销")
}

func run(e *validator.Engine, leaf *testca.Leaf, step int, label string) {
	res, err := e.Validate(validator.Request{
		StoreID:  "demo",
		Leaf:     leaf.Cert,
		Hostname: "app.demo.example",
	})
	fmt.Printf("[%d] %s\n", step, label)
	if err != nil {
		fmt.Printf("    拒绝: %v\n", err)
		return
	}
	fmt.Printf("    通过: 链 = ")
	for i := len(res.Chain) - 1; i >= 0; i-- {
		if i < len(res.Chain)-1 {
			fmt.Print(" -> ")
		}
		fmt.Print(res.Chain[i].Subject.CommonName)
	}
	fmt.Printf("\n    版本: trust=%d revocation=%d cached=%v\n", res.TrustVersion, res.RevVersion, res.FromCache)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
