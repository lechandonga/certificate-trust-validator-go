package ctv

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// resultCache 缓存成功校验结果。缓存键包含：
//   - 信任库快照版本（锚/中间证书/吊销源集合变化 => 版本递增 => 键失效）；
//   - 每个吊销视图版本（吊销数据热更新 => 键失效，立即看到新判定）；
//   - 叶子指纹、额外中间证书指纹集合、主机名与校验时刻（秒级）。
//
// cache 实例从属于单个 Validator/TrustStore，因此不同信任库之间绝不串用。
type resultCache struct {
	mu sync.Mutex
	m  map[string]*VerifyResult
}

func newResultCache() *resultCache {
	return &resultCache{m: make(map[string]*VerifyResult)}
}

func (c *resultCache) get(key string) (*VerifyResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.m[key]
	return r, ok
}

func (c *resultCache) put(key string, r *VerifyResult) {
	c.mu.Lock()
	c.m[key] = r
	c.mu.Unlock()
}

func buildCacheKey(snap *snapshot, views []RevocationView, opts VerifyOptions, when time.Time) string {
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte{0}) }

	write("store")
	write(strconv.FormatUint(snap.version, 10))
	write("leaf")
	write(certID(opts.Leaf))
	write("host")
	write(strings.ToLower(opts.Hostname))
	write("time")
	write(strconv.FormatInt(when.Unix(), 10))

	ids := make([]string, 0, len(opts.Intermediates))
	for _, c := range opts.Intermediates {
		ids = append(ids, certID(c))
	}
	sort.Strings(ids) // 额外中间证书传入顺序不影响缓存命中
	for _, id := range ids {
		write("extra")
		write(id)
	}
	for i, view := range views {
		write("rev")
		write(strconv.Itoa(i))
		write(strconv.FormatUint(view.Version(), 10))
	}
	return hex.EncodeToString(h.Sum(nil))
}
