package ctv

import (
	"crypto/ecdsa"
	"crypto/x509"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type revFixture struct {
	store       *TrustStore
	root, inter *x509.Certificate
	leaf        *x509.Certificate
	rootKey     *ecdsa.PrivateKey
	interKey    *ecdsa.PrivateKey
	issuerDN    string // 中间证书主体 DN，吊销叶子时用作颁发者键
	leafSerial  string
	interIssuer string // 根主体 DN，吊销中间时用
	interSerial string
	leafSpec    func() // 占位，保持结构可读（未使用）
}

func newRevFixture(t *testing.T) *revFixture {
	t.Helper()
	root, rk := issue(nil, nil, rootSpec("Root Rev"))
	inter, ik := issue(root, rk, caSpec("Inter Rev"))
	leaf, _ := issue(inter, ik, leafSpec("leaf-rev", "rev.example.com"))
	store := NewTrustStore()
	store.AddAnchor(root)
	store.AddIntermediate(inter)
	return &revFixture{
		store: store, root: root, inter: inter, leaf: leaf,
		rootKey: rk, interKey: ik,
		issuerDN:    issuerNameKey(inter),
		leafSerial:  serialKey(leaf),
		interIssuer: issuerNameKey(root),
		interSerial: serialKey(inter),
	}
}

func verifyCfg(policy UnavailablePolicy, require bool) Config {
	return Config{
		EnableRevocation:  true,
		RevocationPolicy:  policy,
		RequireRevocation: require,
	}
}

// TestRevocation 覆盖业务三：吊销判定、状态变化与吊销源不可用策略。
func TestRevocation(t *testing.T) {
	t.Log("业务3 吊销判定：未吊销通过 / 吊销拒绝 / 状态热变 / 源过期 / 源缺失软硬失败")
	now := time.Now()

	t.Run("无吊销记录_不要求吊销时通过", func(t *testing.T) {
		f := newRevFixture(t)
		src := NewMemoryRevocationSource()
		f.store.SetRevocationSources(src)
		v := NewValidator(f.store, verifyCfg(RevocationHardFail, false))
		res, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
		mustPass(t, "RequireRevocation=false 时数据缺失应放行", err, res)
		t.Log("用例[吊销缺失_默认放行] PASS")
	})

	t.Run("要求吊销但源缺失_HardFail拒绝", func(t *testing.T) {
		f := newRevFixture(t)
		src := NewMemoryRevocationSource()
		f.store.SetRevocationSources(src)
		v := NewValidator(f.store, verifyCfg(RevocationHardFail, true))
		_, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
		mustReason(t, "硬失败下无吊销数据必须拒绝", err, ReasonRevocationUnavailable)
		t.Log("用例[吊销缺失_硬失败] PASS")
	})

	t.Run("要求吊销但源缺失_SoftFail放行", func(t *testing.T) {
		f := newRevFixture(t)
		src := NewMemoryRevocationSource()
		f.store.SetRevocationSources(src)
		v := NewValidator(f.store, verifyCfg(RevocationSoftFail, true))
		res, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
		mustPass(t, "软失败下无吊销数据应放行", err, res)
		t.Log("用例[吊销缺失_软失败] PASS")
	})

	t.Run("数据过期_HardFail拒绝_SoftFail放行", func(t *testing.T) {
		f := newRevFixture(t)
		src := NewMemoryRevocationSource()
		// 覆盖该颁发者但新鲜度窗口已过。
		src.SetFreshnessWindow(now.Add(-2*time.Hour), now.Add(-time.Hour))
		src.Replace(map[string]map[string]RevocationEntry{
			f.issuerDN: {}, // 空表也代表"覆盖此颁发者"
		})
		f.store.SetRevocationSources(src)

		vHard := NewValidator(f.store, verifyCfg(RevocationHardFail, true))
		_, err := vHard.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
		mustReason(t, "过期吊销数据+硬失败必须拒绝", err,
			ReasonRevocationDataExpired, ReasonRevocationUnavailable)
		t.Logf("用例[吊销数据过期_硬失败] PASS: reason=%s", reasonOf(err))

		vSoft := NewValidator(f.store, verifyCfg(RevocationSoftFail, true))
		res, err := vSoft.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
		mustPass(t, "过期吊销数据+软失败应放行", err, res)
		t.Log("用例[吊销数据过期_软失败] PASS")
	})

	t.Run("叶子被吊销_拒绝", func(t *testing.T) {
		f := newRevFixture(t)
		src := NewMemoryRevocationSource()
		src.Replace(map[string]map[string]RevocationEntry{
			f.issuerDN: {f.leafSerial: {Revoked: true, RevocationTime: now.Add(-time.Minute)}},
		})
		f.store.SetRevocationSources(src)
		v := NewValidator(f.store, verifyCfg(RevocationSoftFail, true))
		_, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
		mustReason(t, "显式吊销在软失败下也必须拒绝", err, ReasonRevoked)
		t.Log("用例[叶子吊销] PASS")
	})

	t.Run("中间证书被吊销_拒绝", func(t *testing.T) {
		f := newRevFixture(t)
		src := NewMemoryRevocationSource()
		src.Replace(map[string]map[string]RevocationEntry{
			f.interIssuer: {f.interSerial: {Revoked: true}},
		})
		f.store.SetRevocationSources(src)
		v := NewValidator(f.store, verifyCfg(RevocationSoftFail, true))
		_, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
		mustReason(t, "中间被吊销必须拒绝", err, ReasonRevoked)
		t.Log("用例[中间吊销] PASS")
	})

	t.Run("吊销状态热变_同一叶子先过后拒再过", func(t *testing.T) {
		f := newRevFixture(t)
		src := NewMemoryRevocationSource()
		f.store.SetRevocationSources(src)
		v := NewValidator(f.store, verifyCfg(RevocationSoftFail, false))

		// 初始：未吊销 => 过
		if _, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now}); err != nil {
			t.Fatalf("初始状态应通过: %v", err)
		}
		// 更新为吊销 => 立即拒绝（缓存必须按吊销版本失效）
		src.Replace(map[string]map[string]RevocationEntry{
			f.issuerDN: {f.leafSerial: {Revoked: true}},
		})
		if _, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now}); err == nil {
			t.Fatal("吊销热更新后必须立即拒绝，缓存不得返回旧结果")
		}
		// 再更新回未吊销（空表）=> 通过
		src.Replace(map[string]map[string]RevocationEntry{f.issuerDN: {}})
		if _, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now}); err != nil {
			t.Fatalf("解除吊销后应恢复通过: %v", err)
		}
		t.Log("用例[吊销状态热变] PASS: 过->拒->过 立即生效")
	})

	t.Run("本地CRL文件_加载与吊销", func(t *testing.T) {
		f := newRevFixture(t)
		dir := t.TempDir()
		path := filepath.Join(dir, "inter.crl")
		der := issueCRL(f.inter, f.interKey,
			[]*big.Int{f.leaf.SerialNumber}, now.Add(-time.Hour), now.Add(24*time.Hour))
		if err := os.WriteFile(path, der, 0o600); err != nil {
			t.Fatal(err)
		}
		src, err := NewCRLFileRevocationSource(path)
		if err != nil {
			t.Fatal(err)
		}
		f.store.SetRevocationSources(src)
		v := NewValidator(f.store, verifyCfg(RevocationSoftFail, true))
		_, verr := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
		mustReason(t, "CRL 列出的序列号必须判为吊销", verr, ReasonRevoked)
		t.Log("用例[本地CRL吊销] PASS")
	})
}

// TestHotUpdateConcurrency 覆盖业务四：信任数据/吊销热更新下的并发校验，
// 每次校验只能观察到完整旧版或完整新版数据。
func TestHotUpdateConcurrency(t *testing.T) {
	t.Log("业务4 热更新并发：更新锚/吊销与并发校验同时进行，结论只能是完整旧版或新版")
	now := time.Now()
	f := newRevFixture(t)
	src := NewMemoryRevocationSource()
	f.store.SetRevocationSources(src)
	v := NewValidator(f.store, verifyCfg(RevocationHardFail, true))

	const goroutines = 32
	const iterations = 200

	var wg sync.WaitGroup
	var badInconsistent atomic.Int64
	var revokedRejections atomic.Int64
	var unavailableRejections atomic.Int64
	var passes atomic.Int64

	start := make(chan struct{})
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < iterations; i++ {
				_, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
				switch {
				case err == nil:
					passes.Add(1)
				case reasonOf(err) == ReasonRevoked:
					revokedRejections.Add(1)
				case reasonOf(err) == ReasonRevocationUnavailable ||
					reasonOf(err) == ReasonRevocationDataExpired:
					unavailableRejections.Add(1)
				default:
					// 其它原因（链/名称等）在该夹具下不应出现 => 视为观察到
					// 不一致的中间状态。
					badInconsistent.Add(1)
				}
			}
		}()
	}

	// 更新方交替发布"吊销表（覆盖颁发者、未吊销）"与"吊销叶子"两个完整版本。
	go func() {
		close(start)
		for i := 0; i < iterations; i++ {
			if i%2 == 0 {
				src.Replace(map[string]map[string]RevocationEntry{
					f.issuerDN:    {f.leafSerial: {Revoked: true}},
					f.interIssuer: {}, // 同时覆盖中间证书的颁发者（根）
				})
			} else {
				src.Replace(map[string]map[string]RevocationEntry{
					f.issuerDN:    {},
					f.interIssuer: {},
				})
			}
		}
	}()
	wg.Wait()

	total := passes.Load() + revokedRejections.Load() + unavailableRejections.Load()
	if badInconsistent.Load() != 0 {
		t.Fatalf("观察到 %d 次非预期失败，怀疑读到了半更新数据", badInconsistent.Load())
	}
	if total != goroutines*iterations {
		t.Fatalf("校验次数不一致 total=%d want=%d", total, goroutines*iterations)
	}
	t.Logf("用例[吊销热更新并发] PASS: 通过=%d 吊销拒绝=%d 不可用拒绝=%d，无非预期结果",
		passes.Load(), revokedRejections.Load(), unavailableRejections.Load())

	// 信任锚热更新：移除锚后立即不可用，恢复后立即可用。
	f.store.RemoveAnchor(f.root)
	_, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
	mustReason(t, "锚移除后必须立即拒绝", err, ReasonNoPath, ReasonAnchorNotFound)
	t.Logf("用例[锚移除立即生效] PASS: reason=%s", reasonOf(err))

	f.store.AddAnchor(f.root)
	if _, err := v.Verify(VerifyOptions{Leaf: f.leaf, Time: now}); err != nil {
		t.Fatalf("锚恢复后应可重新建链（吊销结论不受影响）: %v", err)
	}
	t.Log("用例[锚恢复立即生效] PASS")
}

// TestCacheIsolationBetweenStores 验证缓存不会在不同信任库之间串用：
// 同一叶子在信任库 A 合法、信任库 B 无锚，二者 Validator 独立，
// 任何调用顺序下 B 都必须拒绝。
func TestCacheIsolationBetweenStores(t *testing.T) {
	t.Log("业务4 缓存隔离：不同信任库的结果缓存不得串用")
	now := time.Now()
	f := newRevFixture(t)
	vA := NewValidator(f.store, Config{})
	storeB := NewTrustStore() // 空信任库，仅有叶子可能面对的中间证书，无锚
	storeB.AddIntermediate(f.inter)
	vB := NewValidator(storeB, Config{})

	// 交错调用并反转顺序两次，确保缓存预热方向不影响结论。
	for round := 0; round < 2; round++ {
		if round == 0 {
			if _, err := vA.Verify(VerifyOptions{Leaf: f.leaf, Time: now}); err != nil {
				t.Fatalf("信任库A应通过: %v", err)
			}
			_, err := vB.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
			mustReason(t, "信任库B不得复用A的缓存通过", err, ReasonNoPath)
		} else {
			_, errB := vB.Verify(VerifyOptions{Leaf: f.leaf, Time: now})
			mustReason(t, "信任库B始终拒绝", errB, ReasonNoPath)
			if _, err := vA.Verify(VerifyOptions{Leaf: f.leaf, Time: now}); err != nil {
				t.Fatalf("信任库A应通过: %v", err)
			}
		}
	}
	t.Log("用例[跨信任库缓存隔离] PASS")
}
