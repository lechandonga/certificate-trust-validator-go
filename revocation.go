package ctv

import (
	"crypto/x509"
	"os"
	"sync/atomic"
	"time"
)

// RevocationStatus 是单张证书的吊销判定结果。
type RevocationStatus int

const (
	// RevStatusUnknown 吊销源中没有该证书的条目（数据缺失）。
	RevStatusUnknown RevocationStatus = iota
	// RevStatusGood 吊销源显式声明证书有效（CRL 中未列入即视为 good）。
	RevStatusGood
	// RevStatusRevoked 吊销源显式声明证书已吊销。
	RevStatusRevoked
)

// UnavailablePolicy 决定吊销数据过期/缺失/不可用时的放行策略。
// 必须由调用方显式选择，不存在隐式默认。
type UnavailablePolicy int

const (
	// RevocationHardFail 吊销状态不可用时拒绝校验（fail-closed）。
	RevocationHardFail UnavailablePolicy = iota
	// RevocationSoftFail 吊销状态不可用时继续放行（fail-open）。
	RevocationSoftFail
)

// RevocationEntry 是某个序列号的一条吊销记录。
type RevocationEntry struct {
	// Revoked 为 true 表示吊销；false 表示显式登记为有效。
	Revoked bool
	// RevocationTime 仅用于结果展示。
	RevocationTime time.Time
}

// RevocationView 是某一时刻吊销数据的不可变视图。单次校验只会持有
// 一个视图，因此吊销数据热更新时，并发校验要么看到完整旧版，
// 要么看到完整新版，绝不会看到中间状态。
type RevocationView interface {
	// Lookup 按"颁发者主体 DN + 序列号(hex)"查询；ok=false 表示无条目。
	Lookup(issuerDN, serialHex string) (entry RevocationEntry, ok bool)
	// FreshAt 返回该视图是否覆盖此颁发者，以及数据在 at 时刻是否新鲜
	// （CRL 的 nextUpdate 语义）。
	FreshAt(issuerDN string, at time.Time) (covered, fresh bool)
	// Version 数据版本，更新后单调递增。
	Version() uint64
}

// RevocationSource 是可热更新的吊销来源。Current 返回当前不可变视图。
type RevocationSource interface {
	Current() RevocationView
}

// MemoryRevocationSource 是纯内存吊销源，适合本地构造数据与热更新测试。
// 内部状态以 atomic.Pointer 保存不可变 memView；Replace 原子切换整份数据。
type MemoryRevocationSource struct {
	cur atomic.Pointer[memView]
}

type memView struct {
	version      uint64
	data         map[string]map[string]RevocationEntry // issuerDN -> serialHex -> entry
	thisUpdate   time.Time
	nextUpdate   time.Time
	hasFreshness bool
}

// NewMemoryRevocationSource 创建一个不带新鲜度窗口的内存吊销源
// （数据不会随时间过期，只反映登记内容）。
func NewMemoryRevocationSource() *MemoryRevocationSource {
	m := &MemoryRevocationSource{}
	m.cur.Store(&memView{data: map[string]map[string]RevocationEntry{}})
	return m
}

// SetFreshnessWindow 显式设置数据的 thisUpdate/nextUpdate 窗口，
// 用于模拟"吊销源数据过期"。
func (m *MemoryRevocationSource) SetFreshnessWindow(thisUpdate, nextUpdate time.Time) *MemoryRevocationSource {
	cur := m.cur.Load()
	m.cur.Store(&memView{
		version:      cur.version + 1,
		data:         cur.data,
		thisUpdate:   thisUpdate,
		nextUpdate:   nextUpdate,
		hasFreshness: true,
	})
	return m
}

// Replace 以全新数据原子替换全部吊销记录并递增版本号。
// 进行中的并发校验要么看到替换前的完整数据，要么看到替换后的完整数据。
func (m *MemoryRevocationSource) Replace(data map[string]map[string]RevocationEntry) {
	cloned := make(map[string]map[string]RevocationEntry, len(data))
	for issuer, serials := range data {
		inner := make(map[string]RevocationEntry, len(serials))
		for serial, entry := range serials {
			inner[serial] = entry
		}
		cloned[issuer] = inner
	}
	cur := m.cur.Load()
	m.cur.Store(&memView{
		version:      cur.version + 1,
		data:         cloned,
		thisUpdate:   cur.thisUpdate,
		nextUpdate:   cur.nextUpdate,
		hasFreshness: cur.hasFreshness,
	})
}

// Touch 在不改变数据的情况下递增版本并可刷新新鲜度窗口，
// 模拟"重新拉取到同样数据"或"吊销数据续期"。
func (m *MemoryRevocationSource) Touch(thisUpdate, nextUpdate time.Time) {
	cur := m.cur.Load()
	nv := &memView{
		version:      cur.version + 1,
		data:         cur.data,
		thisUpdate:   cur.thisUpdate,
		nextUpdate:   cur.nextUpdate,
		hasFreshness: cur.hasFreshness,
	}
	if !thisUpdate.IsZero() {
		nv.thisUpdate = thisUpdate
	}
	if !nextUpdate.IsZero() {
		nv.nextUpdate = nextUpdate
	}
	nv.hasFreshness = true
	m.cur.Store(nv)
}

func (m *MemoryRevocationSource) Current() RevocationView { return m.cur.Load() }

func (v *memView) Lookup(issuerDN, serial string) (RevocationEntry, bool) {
	serials, ok := v.data[issuerDN]
	if !ok {
		return RevocationEntry{}, false
	}
	entry, ok := serials[serial]
	return entry, ok
}

func (v *memView) FreshAt(issuerDN string, at time.Time) (bool, bool) {
	if _, covered := v.data[issuerDN]; !covered {
		return false, false
	}
	if !v.hasFreshness {
		return true, true
	}
	return true, !at.After(v.nextUpdate)
}

func (v *memView) Version() uint64 { return v.version }

// CRLFileRevocationSource 从本地 CRL 文件（DER 或 PEM）加载吊销列表，
// 不访问任何网络。Reload 重新读盘并原子替换，版本号递增。
type CRLFileRevocationSource struct {
	path string
	cur  atomic.Pointer[crlView]
}

type parsedCRL struct {
	rl         *x509.RevocationList
	issuerName string
	revoked    map[string]RevocationEntry // key: 序列号的十六进制串
}

type crlView struct {
	version uint64
	lists   []parsedCRL
}

// NewCRLFileRevocationSource 创建本地 CRL 来源并立即加载一次。
func NewCRLFileRevocationSource(path string) (*CRLFileRevocationSource, error) {
	s := &CRLFileRevocationSource{path: path}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload 重新读取并解析本地 CRL 文件，成功后原子生效。
func (s *CRLFileRevocationSource) Reload() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var rl *x509.RevocationList
	if p := pemBlock(raw); p != nil {
		rl, err = x509.ParseRevocationList(p.Bytes)
	} else {
		rl, err = x509.ParseRevocationList(raw)
	}
	if err != nil {
		return err
	}
	parsed := parsedCRL{
		rl:         rl,
		issuerName: rl.Issuer.String(),
		revoked:    make(map[string]RevocationEntry, len(rl.RevokedCertificates)),
	}
	for _, rc := range rl.RevokedCertificates {
		parsed.revoked[rc.SerialNumber.Text(16)] = RevocationEntry{
			Revoked:        true,
			RevocationTime: rc.RevocationTime,
		}
	}
	cur := s.cur.Load()
	var ver uint64
	if cur != nil {
		ver = cur.version
	}
	s.cur.Store(&crlView{version: ver + 1, lists: []parsedCRL{parsed}})
	return nil
}

func (s *CRLFileRevocationSource) Current() RevocationView { return s.cur.Load() }

func (v *crlView) Lookup(issuerDN, serial string) (RevocationEntry, bool) {
	for i := range v.lists {
		if v.lists[i].issuerName != issuerDN {
			continue
		}
		// 被列入 CRL => revoked；CRL 覆盖该颁发者但未列入 => 显式 good。
		if entry, ok := v.lists[i].revoked[serial]; ok {
			return entry, true
		}
		return RevocationEntry{Revoked: false}, true
	}
	return RevocationEntry{}, false
}

func (v *crlView) FreshAt(issuerDN string, at time.Time) (bool, bool) {
	for i := range v.lists {
		if v.lists[i].issuerName != issuerDN {
			continue
		}
		if v.lists[i].rl.NextUpdate.IsZero() {
			return true, true
		}
		return true, !at.After(v.lists[i].rl.NextUpdate)
	}
	return false, false
}

func (v *crlView) Version() uint64 { return v.version }
