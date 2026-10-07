package ctv

import (
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// TestNameConstraintsAndHostname 覆盖业务二：逐级名称约束与主机名匹配。
func TestNameConstraintsAndHostname(t *testing.T) {
	t.Log("业务2 名称约束：permitted/excluded 逐级累积、上下级冲突拒绝；主机名严格匹配")
	now := time.Now()

	buildConstrained := func(t *testing.T,
		rootPermitDNS, rootExcludeDNS, rootPermitEmail, rootExcludeEmail,
		interPermitDNS, interExcludeDNS, interPermitEmail, interExcludeEmail []string,
		leafDNS, leafEmail string, leafIPs []net.IP) (*Validator, *x509.Certificate) {
		rs := rootSpec("Root NC")
		rs.permitDNS = rootPermitDNS
		rs.excludeDNS = rootExcludeDNS
		rs.permitEmail = rootPermitEmail
		rs.excludeEmail = rootExcludeEmail
		root, rk := issue(nil, nil, rs)
		is := caSpec("Inter NC")
		is.permitDNS = interPermitDNS
		is.excludeDNS = interExcludeDNS
		is.permitEmail = interPermitEmail
		is.excludeEmail = interExcludeEmail
		inter, ik := issue(root, rk, is)
		ls := leafSpec("leaf-nc", leafDNS)
		if leafEmail != "" {
			ls.emails = []string{leafEmail}
		}
		ls.ips = leafIPs
		leaf, _ := issue(inter, ik, ls)
		store := NewTrustStore()
		store.AddAnchor(root)
		store.AddIntermediate(inter)
		return NewValidator(store, Config{}), leaf
	}

	build := func(t *testing.T, rootPermitDNS, rootExcludeDNS, interPermitDNS, interExcludeDNS []string,
		leafDNS, leafEmail string, leafIPs []net.IP) (*Validator, *x509.Certificate) {
		return buildConstrained(t, rootPermitDNS, rootExcludeDNS, nil, nil,
			interPermitDNS, interExcludeDNS, nil, nil,
			leafDNS, leafEmail, leafIPs)
	}

	t.Run("命中permitted_通过", func(t *testing.T) {
		v, leaf := build(t, []string{".example.com"}, nil, nil, nil, "app.example.com", "", nil)
		res, err := v.Verify(VerifyOptions{Leaf: leaf, Hostname: "app.example.com", Time: now})
		mustPass(t, "permitted .example.com 下应通过", err, res)
		t.Log("用例[permitted命中] PASS")
	})

	t.Run("permitted不允许的兄弟域_拒绝", func(t *testing.T) {
		v, leaf := build(t, []string{".example.com"}, nil, nil, nil, "app.evil.org", "", nil)
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Hostname: "app.evil.org", Time: now})
		mustReason(t, "兄弟域必须被 permitted 拒绝", err, ReasonNameConstraint)
		t.Log("用例[permitted不命中] PASS")
	})

	t.Run("excluded子域_拒绝", func(t *testing.T) {
		v, leaf := build(t, nil, []string{"blocked.example.com"}, nil, nil, "host.blocked.example.com", "", nil)
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Hostname: "host.blocked.example.com", Time: now})
		mustReason(t, "excluded 子域必须拒绝", err, ReasonNameConstraint)
		t.Log("用例[excluded命中] PASS")
	})

	t.Run("上下级约束冲突_取交集为空_拒绝", func(t *testing.T) {
		// 根 permit .example.com；中间 exclude foo.example.com；
		// 叶子在 foo.example.com => 交集为空，必须拒绝，且不能被中间"放行"绕过。
		v, leaf := build(t,
			[]string{".example.com"}, nil,
			nil, []string{"foo.example.com"},
			"api.foo.example.com", "", nil)
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Hostname: "api.foo.example.com", Time: now})
		mustReason(t, "上下级冲突必须拒绝", err, ReasonNameConstraint)
		t.Log("用例[上下级约束冲突] PASS")
	})

	t.Run("IP约束_允许网段外拒绝", func(t *testing.T) {
		_, ipnet, _ := net.ParseCIDR("10.0.0.0/8")
		rs := rootSpec("Root IP")
		rs.permitIP = []*net.IPNet{ipnet}
		root, rk := issue(nil, nil, rs)
		inter, ik := issue(root, rk, caSpec("Inter IP"))
		ls := leafSpec("leaf-ip")
		ls.ips = []net.IP{net.ParseIP("192.168.1.1")}
		leaf, _ := issue(inter, ik, ls)
		store := NewTrustStore()
		store.AddAnchor(root)
		store.AddIntermediate(inter)
		v := NewValidator(store, Config{})
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Hostname: "192.168.1.1", Time: now})
		mustReason(t, "网段外 IP 必须拒绝", err, ReasonNameConstraint, ReasonHostMismatch)
		t.Logf("用例[IP约束] PASS: reason=%s", reasonOf(err))
	})

	t.Run("邮箱约束_excluded拒绝", func(t *testing.T) {
		v, leaf := buildConstrained(t,
			nil, nil, nil, nil,
			nil, nil, nil, []string{"mail.example.com"},
			"web.example.com", "user@mail.example.com", nil)
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Time: now})
		mustReason(t, "excluded 邮箱域必须拒绝", err, ReasonNameConstraint)
		t.Log("用例[邮箱excluded] PASS")
	})

	t.Run("主机名不匹配SAN_拒绝", func(t *testing.T) {
		v, leaf := build(t, nil, nil, nil, nil, "real.example.com", "", nil)
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Hostname: "impostor.example.com", Time: now})
		mustReason(t, "主机名与SAN不符必须拒绝", err, ReasonHostMismatch)
		t.Log("用例[主机名不匹配] PASS")
	})

	t.Run("通配符匹配与别名绕过", func(t *testing.T) {
		v, leaf := build(t, nil, nil, nil, nil, "*.example.com", "", nil)
		// 单层通配：a.example.com 通过；a.b.example.com 不通过。
		if _, err := v.Verify(VerifyOptions{Leaf: leaf, Hostname: "a.example.com", Time: now}); err != nil {
			t.Fatalf("单层通配应通过: %v", err)
		}
		_, err := v.Verify(VerifyOptions{Leaf: leaf, Hostname: "a.b.example.com", Time: now})
		mustReason(t, "通配符不得跨标签匹配", err, ReasonHostMismatch)
		t.Log("用例[通配符边界] PASS")
	})
}
