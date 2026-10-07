package ctv

import (
	"crypto/x509"
	"sort"
	"strings"
	"time"
)

// VerifyOptions 是一次校验请求的输入。
type VerifyOptions struct {
	// Leaf 终端证书（必填）。
	Leaf *x509.Certificate
	// Intermediates 调用方针对本次请求额外提供的中间证书（如 TLS 对端下发），
	// 与信任库内登记的中间证书取并集。
	Intermediates []*x509.Certificate
	// Hostname 期望匹配的 DNS/IP 名称；为空则跳过主机名校验。
	Hostname string
	// Time 校验时刻；零值使用系统当前时间。
	Time time.Time
}

// VerifyResult 是成功校验的结果。
type VerifyResult struct {
	Chain       Chain
	StoreVer    uint64
	RevVersions []uint64 // 本次校验实际看到的各吊销源版本
}

// Validator 绑定一个 TrustStore 与一份显式策略 Config。
// 一个 Validator 可被任意多 goroutine 并发使用。每个 TrustStore 使用独立
// Validator，结果缓存按信任库版本隔离，不会在不同信任库之间串用。
type Validator struct {
	store  *TrustStore
	config Config
	cache  *resultCache
}

// NewValidator 创建校验器。
func NewValidator(store *TrustStore, cfg Config) *Validator {
	return &Validator{store: store, config: cfg, cache: newResultCache()}
}

// Verify 执行"路径构建 -> 逐路径校验 -> 吊销判定"，返回确定且可复现的
// 第一条合法路径；全部失败时返回携带最高优先级原因的 *VerifyError。
func (v *Validator) Verify(opts VerifyOptions) (*VerifyResult, error) {
	when := opts.Time
	if when.IsZero() {
		when = time.Now()
	}
	if opts.Leaf == nil {
		return nil, newVerifyError(ReasonNoCertificate, -1, "", "leaf certificate is required")
	}

	snap := v.store.load()

	// 吊销视图在校验开始时一次性抓取，整次校验复用，保证热更新原子可见。
	var revViews []RevocationView
	if v.config.EnableRevocation {
		revViews = make([]RevocationView, 0, len(snap.revSources))
		for _, src := range snap.revSources {
			if view := src.Current(); view != nil {
				revViews = append(revViews, view)
			}
		}
	}

	cacheKey := buildCacheKey(snap, revViews, opts, when)
	if cached, ok := v.cache.get(cacheKey); ok {
		return cached, nil
	}

	// 1) 枚举所有以信任锚结尾的结构路径。
	paths, buildErr := v.buildPaths(snap, opts.Leaf, opts.Intermediates)
	if len(paths) == 0 {
		return nil, buildErr
	}

	// 2) 确定性排序：优先链更长的路径（含显式登记的交叉中间证书），
	//    其次按链上证书 ID 序列字典序。任何输入顺序下结论一致。
	sort.Slice(paths, func(i, j int) bool { return chainLess(paths[i], paths[j]) })

	// 3) 逐条校验，记录"最好"的失败原因用于最终报告。
	var bestErr *VerifyError
	for _, chain := range paths {
		if err := v.validateChain(chain, opts.Hostname, when); err != nil {
			if bestErr == nil || failurePriority(err, bestErr) {
				bestErr = err
			}
			continue
		}
		if err := v.checkRevocation(chain, revViews, when); err != nil {
			if bestErr == nil || failurePriority(err, bestErr) {
				bestErr = err
			}
			continue
		}
		res := &VerifyResult{
			Chain:       chain,
			StoreVer:    snap.version,
			RevVersions: viewVersions(revViews),
		}
		v.cache.put(cacheKey, res)
		return res, nil
	}
	return nil, bestErr
}

// failurePriority 决定报告哪个失败：内容性拒绝（吊销/名称/有效期等）优先
// 于策略性/结构性原因，避免最终错误被路径选择顺序偶然影响。
func failurePriority(a, b *VerifyError) bool {
	return reasonRank(a.Reason) > reasonRank(b.Reason)
}

func reasonRank(r ReasonCode) int {
	switch r {
	case ReasonRevoked:
		return 100
	case ReasonNameConstraint, ReasonHostMismatch:
		return 90
	case ReasonExpired:
		return 80
	case ReasonKeyUsage:
		return 70
	case ReasonNotCA, ReasonPathLenExceeded:
		return 60
	case ReasonUnknownCriticalExt:
		return 50
	case ReasonSignature:
		return 40
	case ReasonRevocationUnavailable, ReasonRevocationDataExpired:
		return 30
	default:
		return 10
	}
}

func viewVersions(views []RevocationView) []uint64 {
	out := make([]uint64, 0, len(views))
	for _, view := range views {
		out = append(out, view.Version())
	}
	return out
}

func chainLess(a, b Chain) bool {
	if len(a.Certs) != len(b.Certs) {
		return len(a.Certs) > len(b.Certs) // 更长的链排前面
	}
	for i := range a.Certs {
		ia, ib := certID(a.Certs[i]), certID(b.Certs[i])
		if ia != ib {
			return ia < ib
		}
	}
	return false
}

// buildPaths 以叶子为起点向上做 DFS，枚举所有以信任锚结尾的路径。
// onPath 记录已在当前路径上的证书 ID，重复使用同一证书即判定成环。
func (v *Validator) buildPaths(snap *snapshot, leaf *x509.Certificate,
	extra []*x509.Certificate) ([]Chain, *VerifyError) {

	extraByAK := map[string][]*x509.Certificate{}
	for _, c := range extra {
		extraByAK[subjectKeyID(c)] = insertSortedCert(extraByAK[subjectKeyID(c)], c)
	}

	var sawCycle, sawAnchorNameMismatch, sawSigFailure bool
	var longestPartial []*x509.Certificate
	var result []Chain

	var dfs func(current *x509.Certificate, path []*x509.Certificate, onPath map[string]bool)
	dfs = func(current *x509.Certificate, path []*x509.Certificate, onPath map[string]bool) {
		if len(path) > len(longestPartial) {
			longestPartial = append([]*x509.Certificate(nil), path...)
		}

		// 终止条件 1：当前证书由某个信任锚直接签发。
		for _, anchor := range snap.anchorsByAK[authorityKeyID(current)] {
			if !issuerMatches(current, anchor) {
				sawAnchorNameMismatch = true
				continue
			}
			if err := current.CheckSignatureFrom(anchor); err != nil {
				continue
			}
			chain := append(append([]*x509.Certificate{}, path...), anchor)
			result = append(result, Chain{Certs: chain})
		}

		// 终止条件 2：当前证书自身就是信任锚。
		if _, isAnchor := snap.anchors[certID(current)]; isAnchor {
			chain := append([]*x509.Certificate{}, path...)
			if !containsChain(result, chain) {
				result = append(result, Chain{Certs: chain})
			}
			return
		}

		// 向上枚举中间签发者：信任库中间证书 + 请求自带中间证书。
		candidates := map[string]*x509.Certificate{}
		for _, c := range snap.intermediatesByAK[authorityKeyID(current)] {
			candidates[certID(c)] = c
		}
		for _, c := range extraByAK[authorityKeyID(current)] {
			candidates[certID(c)] = c
		}
		ids := make([]string, 0, len(candidates))
		for id := range candidates {
			ids = append(ids, id)
		}
		sort.Strings(ids)

		for _, id := range ids {
			parent := candidates[id]
			if !issuerMatches(current, parent) {
				continue
			}
			if err := current.CheckSignatureFrom(parent); err != nil {
				sawSigFailure = true
				continue
			}
			if onPath[id] {
				sawCycle = true
				continue
			}
			onPath[id] = true
			dfs(parent, append(path, parent), onPath)
			delete(onPath, id)
		}
	}

	onPath := map[string]bool{certID(leaf): true}
	dfs(leaf, []*x509.Certificate{leaf}, onPath)

	if len(result) > 0 {
		return result, nil
	}
	switch {
	case sawCycle:
		return nil, newVerifyError(ReasonPathCycle, -1, certName(leaf),
			"certificate path contains a cycle and cannot reach a trust anchor")
	case sawSigFailure:
		return nil, newVerifyError(ReasonSignature, len(longestPartial)-1,
			certName(longestPartial[len(longestPartial)-1]),
			"a certificate with matching issuer name/key id exists but its signature does not verify")
	case sawAnchorNameMismatch:
		idx := len(longestPartial) - 1
		return nil, newVerifyError(ReasonAnchorNotFound, idx, certName(longestPartial[idx]),
			"issuer name matches no trust anchor (or anchor signature does not verify)")
	default:
		idx := len(longestPartial) - 1
		name := ""
		if idx >= 0 {
			name = certName(longestPartial[idx])
		}
		return nil, newVerifyError(ReasonNoPath, idx, name,
			"no certificate path can be built from the leaf to any trust anchor")
	}
}

func containsChain(chains []Chain, chain []*x509.Certificate) bool {
	for _, c := range chains {
		if len(c.Certs) != len(chain) {
			continue
		}
		same := true
		for i := range chain {
			if certID(c.Certs[i]) != certID(chain[i]) {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

// authorityKeyID 返回索引父候选所用键：优先 AKI 扩展，缺失时退化为
// 颁发者 DN（与 subjectKeyID 的退化规则对称）。
func authorityKeyID(c *x509.Certificate) string {
	if len(c.AuthorityKeyId) > 0 {
		return "sk:" + bytesHex(c.AuthorityKeyId)
	}
	return "dn:" + strings.TrimSpace(c.Issuer.String())
}

// issuerMatches 要求子证书 Issuer DN 与父证书 Subject DN 严格一致，
// 防止仅凭密钥/名称相似性把证书挂到错误的颁发者上。
func issuerMatches(child, parent *x509.Certificate) bool {
	return strings.TrimSpace(child.Issuer.String()) == strings.TrimSpace(parent.Subject.String())
}

func bytesHex(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexd[v>>4]
		out[i*2+1] = hexd[v&0x0f]
	}
	return string(out)
}
