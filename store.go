package ctv

import (
	"crypto/x509"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
)

// Config 是一次校验的显式策略配置。所有字段都必须显式给出，
// 组件不提供会悄悄改变安全语义的隐式默认。
type Config struct {
	// RevocationPolicy 吊销数据缺失/过期/不可用时 fail-open 还是 fail-closed。
	RevocationPolicy UnavailablePolicy
	// RequireRevocation 为 true 时，链上每张非锚证书都必须至少被一个
	// 吊销源覆盖（否则按 RevocationPolicy 处理）。
	RequireRevocation bool
	// EnableRevocation 为 false 时完全不做吊销判定（纯链校验模式）。
	EnableRevocation bool
	// ExtKeyUsage 终端证书必须具备的扩展密钥用途；nil 表示不要求。
	ExtKeyUsage []x509.ExtKeyUsage
}

// snapshot 是某一时刻信任数据的不可变视图。Validator 在单次校验内
// 只读取一个 snapshot，因此更新进行中不会看到半新半旧的数据。
type snapshot struct {
	version uint64

	anchors           map[string]*x509.Certificate // key: certID
	anchorsByAK       map[string][]*x509.Certificate
	intermediates     map[string]*x509.Certificate
	intermediatesByAK map[string][]*x509.Certificate
	revSources        []RevocationSource
}

// TrustStore 持有信任锚、可选中间证书与吊销来源。
// 所有写操作（Add/Update*/Replace）都以 copy-on-write 方式生成新快照并
// 原子发布，支持并发读与热更新。
type TrustStore struct {
	mu  sync.Mutex
	cur atomic.Pointer[snapshot]
}

// NewTrustStore 创建空信任库。
func NewTrustStore() *TrustStore {
	s := &TrustStore{}
	s.cur.Store(&snapshot{
		anchors:           map[string]*x509.Certificate{},
		anchorsByAK:       map[string][]*x509.Certificate{},
		intermediates:     map[string]*x509.Certificate{},
		intermediatesByAK: map[string][]*x509.Certificate{},
	})
	return s
}

func (s *TrustStore) load() *snapshot { return s.cur.Load() }

// cloneLocked 复制当前快照以便 copy-on-write 修改。
func (s *TrustStore) cloneLocked() *snapshot {
	cur := s.cur.Load()
	next := &snapshot{
		version:           cur.version + 1,
		anchors:           make(map[string]*x509.Certificate, len(cur.anchors)),
		anchorsByAK:       cloneAKIndex(cur.anchorsByAK),
		intermediates:     make(map[string]*x509.Certificate, len(cur.intermediates)),
		intermediatesByAK: cloneAKIndex(cur.intermediatesByAK),
		revSources:        append([]RevocationSource(nil), cur.revSources...),
	}
	for k, v := range cur.anchors {
		next.anchors[k] = v
	}
	for k, v := range cur.intermediates {
		next.intermediates[k] = v
	}
	return next
}

func cloneAKIndex(in map[string][]*x509.Certificate) map[string][]*x509.Certificate {
	out := make(map[string][]*x509.Certificate, len(in))
	for k, v := range in {
		cp := make([]*x509.Certificate, len(v))
		copy(cp, v)
		out[k] = cp
	}
	return out
}

// AddAnchor 原子地加入一个信任锚。
func (s *TrustStore) AddAnchor(c *x509.Certificate) {
	s.mu.Lock()
	next := s.cloneLocked()
	id := certID(c)
	if _, exists := next.anchors[id]; exists {
		s.mu.Unlock()
		return
	}
	next.anchors[id] = c
	next.anchorsByAK[subjectKeyID(c)] = insertSortedCert(next.anchorsByAK[subjectKeyID(c)], c)
	s.cur.Store(next)
	s.mu.Unlock()
}

// AddIntermediate 原子地加入一张中间证书（可用于补链）。
func (s *TrustStore) AddIntermediate(c *x509.Certificate) {
	s.mu.Lock()
	next := s.cloneLocked()
	id := certID(c)
	if _, exists := next.intermediates[id]; !exists {
		next.intermediates[id] = c
		next.intermediatesByAK[subjectKeyID(c)] = insertSortedCert(next.intermediatesByAK[subjectKeyID(c)], c)
		s.cur.Store(next)
	}
	s.mu.Unlock()
}

// RemoveAnchor 原子地移除信任锚（热更新信任数据）。
func (s *TrustStore) RemoveAnchor(c *x509.Certificate) {
	s.mu.Lock()
	next := s.cloneLocked()
	id := certID(c)
	if _, ok := next.anchors[id]; ok {
		delete(next.anchors, id)
		next.anchorsByAK = cloneAKIndex(next.anchorsByAK)
		ak := subjectKeyID(c)
		list := next.anchorsByAK[ak]
		for i, cand := range list {
			if certID(cand) == id {
				next.anchorsByAK[ak] = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(next.anchorsByAK[ak]) == 0 {
			delete(next.anchorsByAK, ak)
		}
		s.cur.Store(next)
	}
	s.mu.Unlock()
}

// SetRevocationSources 原子替换整组吊销来源。
func (s *TrustStore) SetRevocationSources(srcs ...RevocationSource) {
	s.mu.Lock()
	next := s.cloneLocked()
	next.revSources = append([]RevocationSource(nil), srcs...)
	s.cur.Store(next)
	s.mu.Unlock()
}

// Version 返回当前信任数据版本，每次原子更新单调递增。
func (s *TrustStore) Version() uint64 { return s.cur.Load().version }

func subjectKeyID(c *x509.Certificate) string {
	if len(c.SubjectKeyId) > 0 {
		return "sk:" + fmt.Sprintf("%x", c.SubjectKeyId)
	}
	return "dn:" + c.Subject.String()
}

// insertSortedCert 按证书 ID 字典序插入，保证同一候选集合在任意
// 添加顺序下都有确定的遍历顺序（路径选择可复现的基础）。
func insertSortedCert(list []*x509.Certificate, c *x509.Certificate) []*x509.Certificate {
	id := certID(c)
	for _, cand := range list {
		if certID(cand) == id {
			return list
		}
	}
	idx := 0
	for idx < len(list) && certID(list[idx]) < id {
		idx++
	}
	list = append(list, nil)
	copy(list[idx+1:], list[idx:])
	list[idx] = c
	return list
}

// serialKey 以十六进制序列号文本作为吊销查询键，与 CRL 的编码一致。
func serialKey(c *x509.Certificate) string {
	return new(big.Int).Set(c.SerialNumber).Text(16)
}

// issuerNameKey 返回吊销查询使用的颁发者标识（主体 DN 字符串）。
func issuerNameKey(c *x509.Certificate) string {
	return strings.TrimSpace(c.Subject.String())
}
