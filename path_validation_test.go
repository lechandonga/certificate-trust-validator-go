package ctv

import (
	"crypto/x509"
	"testing"
	"time"
)

// TestPathBuildingAndSelection 覆盖业务一：证书链路径构建与确定性选择。
func TestPathBuildingAndSelection(t *testing.T) {
	t.Log("业务1 路径构建：合法链 / 交叉签名多路径确定性 / 断链 / 成环 / 签名失败")
	now := time.Now()

	t.Run("合法直链_叶子到根", func(t *testing.T) {
		store := NewTrustStore()
		root, rootKey := issue(nil, nil, rootSpec("Root A"))
		inter, interKey := issue(root, rootKey, caSpec("Inter A"))
		leaf, _ := issue(inter, interKey, leafSpec("leaf", "app.example.com"))
		store.AddAnchor(root)
		store.AddIntermediate(inter)

		v := NewValidator(store, Config{})
		res, err := v.Verify(VerifyOptions{Leaf: leaf, Hostname: "app.example.com", Time: now})
		mustPass(t, "合法直链应通过", err, res)
		if len(res.Chain.Certs) != 3 {
			t.Fatalf("链长度应为3，实际=%d", len(res.Chain.Certs))
		}
		t.Logf("用例[合法直链] PASS: 链=%v", res.Chain.Subjects())
	})

	t.Run("交叉签名多路径_结果确定且可复现", func(t *testing.T) {
		store := NewTrustStore()
		r1, r1Key := issue(nil, nil, rootSpec("Root 1"))
		r2, r2Key := issue(nil, nil, rootSpec("Root 2"))
		iKey := mustKey()
		iByR1 := issueWithKey(r1, r1Key, iKey, caSpec("Inter X"))
		iByR2 := issueWithKey(r2, r2Key, iKey, caSpec("Inter X"))
		leaf, _ := issue(iByR1, iKey, leafSpec("leaf-x", "x.example.com"))

		store.AddAnchor(r1)
		store.AddAnchor(r2)
		store.AddIntermediate(iByR1)
		store.AddIntermediate(iByR2)
		v := NewValidator(store, Config{})

		var firstID string
		for n := 0; n < 10; n++ {
			res, err := v.Verify(VerifyOptions{
				Leaf:          leaf,
				Time:          now,
				Intermediates: reverseCerts(iByR2, iByR1),
			})
			mustPass(t, "交叉签名至少有一条合法路径", err, res)
			id := certID(res.Chain.Certs[len(res.Chain.Certs)-1])
			if firstID == "" {
				firstID = id
			} else if id != firstID {
				t.Fatalf("路径选择不可复现: %s vs %s", firstID, id)
			}
		}
		t.Logf("用例[交叉签名多路径] PASS: 10次稳定选择锚 %s", short(firstID))
	})

	t.Run("断链_NO_VALID_PATH", func(t *testing.T) {
		root, rootKey := issue(nil, nil, rootSpec("Root B"))
		inter, interKey := issue(root, rootKey, caSpec("Inter B"))
		leaf, _ := issue(inter, interKey, leafSpec("leaf-b", "b.example.com"))
		store := NewTrustStore()
		store.AddIntermediate(inter) // 故意不加锚
		v := NewValidator(store, Config{})
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Time: now})
		mustReason(t, "断链必须报 NO_VALID_PATH", err, ReasonNoPath)
		t.Log("用例[断链] PASS")
	})

	t.Run("锚名称不符_必须拒绝", func(t *testing.T) {
		root, rootKey := issue(nil, nil, rootSpec("Root Real"))
		other, _ := issue(nil, nil, rootSpec("Root Other"))
		leaf, _ := issue(root, rootKey, leafSpec("leaf", "c.example.com"))
		store := NewTrustStore()
		store.AddAnchor(other) // 信任的是另一张根
		v := NewValidator(store, Config{})
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Time: now})
		if err == nil {
			t.Fatal("锚名称不符时必须拒绝")
		}
		t.Logf("用例[锚名称不符] PASS: reason=%s", reasonOf(err))
	})

	t.Run("成环_绝不通过", func(t *testing.T) {
		aKey := mustKey()
		bKey := mustKey()
		nowT := time.Now()
		// A 先自签仅用于得到一个 *x509.Certificate 模板承载主体信息；
		// 随后构造 A<->B 互相签发，无任何自签名信任锚。
		aSelf := issueWithKey(nil, nil, aKey, caSpecAt("CA-A", nowT))
		bCert := issueWithKey(aSelf, aKey, bKey, caSpecAt("CA-B", nowT))
		aByB := issueWithKey(bCert, bKey, aKey, caSpecAt("CA-A", nowT))
		leaf, _ := issue(aByB, aKey, leafSpecAt("leaf-cycle", "cyc.example.com", nowT))

		store := NewTrustStore()
		store.AddIntermediate(aByB)
		store.AddIntermediate(bCert)
		v := NewValidator(store, Config{})
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Time: nowT})
		if err == nil {
			t.Fatal("成环路径必须拒绝")
		}
		t.Logf("用例[成环] PASS: reason=%s", reasonOf(err))
	})

	t.Run("签名校验失败", func(t *testing.T) {
		root, rootKey := issue(nil, nil, rootSpec("Root S"))
		inter, _ := issue(root, rootKey, caSpec("Inter S"))
		// 构造同名但不同密钥的"影子中间证书"，并复制真实中间证书的 SKI，
		// 使叶子按 AKI/DN 索引到真实中间证书，但用其公钥验签必然失败。
		rogueKey := mustKey()
		rogueSpec := caSpec("Inter S")
		rogueSpec.subjectKeyID = inter.SubjectKeyId
		rogueInter := issueWithKey(nil, nil, rogueKey, rogueSpec)
		leaf, _ := issue(rogueInter, rogueKey, leafSpec("leaf", "s.example.com"))
		store := NewTrustStore()
		store.AddAnchor(root)
		store.AddIntermediate(inter)
		v := NewValidator(store, Config{})
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Time: now})
		if err == nil {
			t.Fatal("签名不匹配必须拒绝")
		}
		t.Logf("用例[签名失败] PASS: reason=%s", reasonOf(err))
	})

	t.Run("过期与未生效", func(t *testing.T) {
		root, rootKey := issue(nil, nil, rootSpec("Root E"))
		inter, interKey := issue(root, rootKey, caSpec("Inter E"))
		spec := leafSpec("leaf-e", "e.example.com")
		spec.notBefore = now.Add(48 * time.Hour)
		spec.notAfter = now.Add(72 * time.Hour)
		leaf, _ := issue(inter, interKey, spec)
		store := NewTrustStore()
		store.AddAnchor(root)
		store.AddIntermediate(inter)
		v := NewValidator(store, Config{})
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Time: now})
		mustReason(t, "未生效证书必须报过期类原因", err, ReasonExpired)
		t.Log("用例[未生效] PASS")
	})

	t.Run("非CA证书充当中间", func(t *testing.T) {
		root, rootKey := issue(nil, nil, rootSpec("Root NCA"))
		fakeCA, fakeCAKey := issue(root, rootKey, leafSpec("not-ca", "noc.example.com"))
		leaf, _ := issue(fakeCA, fakeCAKey, leafSpec("leaf", "d.example.com"))
		store := NewTrustStore()
		store.AddAnchor(root)
		store.AddIntermediate(fakeCA)
		v := NewValidator(store, Config{})
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Time: now})
		mustReason(t, "非CA做中间必须拒绝", err, ReasonNotCA, ReasonNoPath, ReasonSignature)
		t.Logf("用例[非CA中间] PASS: reason=%s", reasonOf(err))
	})

	t.Run("pathLen违反", func(t *testing.T) {
		root, rootKey := issue(nil, nil, rootSpec("Root PL"))
		interSpec := caSpec("Inter PL0")
		interSpec.maxPathLen = 0
		interSpec.maxPathLenZero = true
		inter, interKey := issue(root, rootKey, interSpec)
		sub, subKey := issue(inter, interKey, caSpec("Sub PL"))
		leaf, _ := issue(sub, subKey, leafSpec("leaf", "pl.example.com"))
		store := NewTrustStore()
		store.AddAnchor(root)
		store.AddIntermediate(inter)
		store.AddIntermediate(sub)
		v := NewValidator(store, Config{})
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Time: now})
		mustReason(t, "pathLen=0 下再挂中间必须拒绝", err, ReasonPathLenExceeded)
		t.Log("用例[pathLen] PASS")
	})

	t.Run("未知关键扩展", func(t *testing.T) {
		root, rootKey := issue(nil, nil, rootSpec("Root U"))
		inter, interKey := issue(root, rootKey, caSpec("Inter U"))
		spec := leafSpec("leaf-u", "u.example.com")
		spec.unknownCritical = true
		leaf, _ := issue(inter, interKey, spec)
		store := NewTrustStore()
		store.AddAnchor(root)
		store.AddIntermediate(inter)
		v := NewValidator(store, Config{})
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Time: now})
		mustReason(t, "未知关键扩展必须拒绝", err, ReasonUnknownCriticalExt)
		t.Log("用例[未知关键扩展] PASS")
	})

	t.Run("EKU用途不符", func(t *testing.T) {
		root, rootKey := issue(nil, nil, rootSpec("Root KU"))
		inter, interKey := issue(root, rootKey, caSpec("Inter KU"))
		spec := leafSpec("leaf-ku", "ku.example.com")
		spec.extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection}
		leaf, _ := issue(inter, interKey, spec)
		store := NewTrustStore()
		store.AddAnchor(root)
		store.AddIntermediate(inter)
		v := NewValidator(store, Config{ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Time: now})
		mustReason(t, "EKU不含serverAuth必须拒绝", err, ReasonKeyUsage)
		t.Log("用例[EKU不符] PASS")
	})
}
