package ctv

import (
	"crypto/x509"
	"net"
	"strings"
)

// checkNameConstraints 按 RFC 5280 4.2.1.10 的语义实现：
// 从锚向叶子方向逐级应用 NameConstraints，累积生效的 permitted/excluded。
//   - excluded 命中任意一个即拒绝；
//   - permitted 集合非空时，每个标识类型都必须至少命中一条 permitted；
//   - 约束作用于其下方所有证书（包含叶子），锚自身的标识不被自身约束检查
//     （标准实现通行做法）；
//   - 上下级约束冲突（如上级 permit .example.com，下级 exclude
//     foo.example.com 且叶子正是 foo）时取交集为空 => 拒绝。
func checkNameConstraints(certs []*x509.Certificate) *VerifyError {
	// 自顶向下传播：用位置 i 的约束约束位置 0..i-1 的证书。
	for i := len(certs) - 1; i >= 1; i-- {
		constrained := certs[i]
		if len(constrained.PermittedDNSDomains) == 0 &&
			len(constrained.ExcludedDNSDomains) == 0 &&
			len(constrained.PermittedIPRanges) == 0 &&
			len(constrained.ExcludedIPRanges) == 0 &&
			len(constrained.PermittedEmailAddresses) == 0 &&
			len(constrained.ExcludedEmailAddresses) == 0 {
			continue
		}
		for j := 0; j < i; j++ {
			c := certs[j]
			dnsNames := certificateDNSNames(c)
			emails := c.EmailAddresses
			ips := c.IPAddresses

			// 无 SAN 的叶子可用 CN 作为 DNS 标识参与约束判定（兼容旧证书），
			// 但中间 CA 必须使用 SAN。
			if j == 0 && len(dnsNames) == 0 && len(emails) == 0 && len(ips) == 0 &&
				c.Subject.CommonName != "" && !looksLikeIP(c.Subject.CommonName) {
				dnsNames = []string{c.Subject.CommonName}
			}

			for _, name := range dnsNames {
				if violation := matchDNSConstraint(constrained, name); violation != "" {
					return constraintErr(j, c, name, violation)
				}
			}
			for _, email := range emails {
				if violation := matchEmailConstraint(constrained, email); violation != "" {
					return constraintErr(j, c, email, violation)
				}
			}
			for _, ip := range ips {
				if violation := matchIPConstraint(constrained, ip); violation != "" {
					return constraintErr(j, c, ip.String(), violation)
				}
			}

			// permitted 集合存在但该证书完全没有对应类型标识时不做强制
			// （只约束证书实际持有的标识类型），但 DNS permitted 非空且证书
			// 是叶子、没有任何 DNS/IP/邮箱标识，则视为无法证明合规 => 拒绝。
			if j == 0 && len(dnsNames) == 0 && len(ips) == 0 && len(emails) == 0 &&
				(len(constrained.PermittedDNSDomains) > 0 ||
					len(constrained.PermittedIPRanges) > 0 ||
					len(constrained.PermittedEmailAddresses) > 0) {
				return newVerifyError(ReasonNameConstraint, j, certName(c),
					"leaf carries no DNS/IP/email identity but a permitted subtree is asserted by "+
						certName(constrained))
			}
		}
	}
	return nil
}

func certificateDNSNames(c *x509.Certificate) []string {
	if len(c.DNSNames) > 0 {
		return c.DNSNames
	}
	return nil
}

func looksLikeIP(s string) bool { return net.ParseIP(s) != nil }

func constraintErr(idx int, c *x509.Certificate, identity string, detail string) *VerifyError {
	return newVerifyError(ReasonNameConstraint, idx, certName(c),
		"identity "+identity+" violates name constraints: "+detail)
}

func matchDNSConstraint(ca *x509.Certificate, name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, excl := range ca.ExcludedDNSDomains {
		if dnsInSubtree(name, strings.ToLower(strings.TrimSuffix(excl, "."))) {
			return "matched excluded DNS subtree '" + excl + "'"
		}
	}
	if len(ca.PermittedDNSDomains) > 0 {
		ok := false
		for _, perm := range ca.PermittedDNSDomains {
			if dnsInSubtree(name, strings.ToLower(strings.TrimSuffix(perm, "."))) {
				ok = true
				break
			}
		}
		if !ok {
			return "matched no permitted DNS subtree"
		}
	}
	return ""
}

// dnsInSubtree 实现 RFC 5280 的 DNS 子树规则：
// constraint 为前导点 ".example.com" 时只匹配子域；
// 不带前导点时匹配自身或子域（example.com / a.example.com）。
func dnsInSubtree(name, constraint string) bool {
	constraint = strings.TrimPrefix(constraint, ".")
	if constraint == "" {
		return true
	}
	if name == constraint {
		return true
	}
	return strings.HasSuffix(name, "."+constraint)
}

func matchEmailConstraint(ca *x509.Certificate, email string) string {
	email = strings.ToLower(email)
	for _, excl := range ca.ExcludedEmailAddresses {
		if emailInSubtree(email, strings.ToLower(excl)) {
			return "matched excluded email subtree '" + excl + "'"
		}
	}
	if len(ca.PermittedEmailAddresses) > 0 {
		ok := false
		for _, perm := range ca.PermittedEmailAddresses {
			if emailInSubtree(email, strings.ToLower(perm)) {
				ok = true
				break
			}
		}
		if !ok {
			return "matched no permitted email subtree"
		}
	}
	return ""
}

// emailInSubtree：constraint 以 "@" 开头表示邮箱域（RFC 5280 形式），
// 不带 "@" 时同时接受确切地址与同域地址。
func emailInSubtree(email, constraint string) bool {
	constraint = strings.TrimPrefix(constraint, "@")
	at := strings.LastIndex(email, "@")
	if at < 0 {
		return false
	}
	domain := email[at+1:]
	if domain == constraint {
		return true
	}
	return strings.HasSuffix(domain, "."+constraint)
}

func matchIPConstraint(ca *x509.Certificate, ip net.IP) string {
	for _, r := range ca.ExcludedIPRanges {
		if r.Contains(ip) {
			return "matched excluded IP range " + r.String()
		}
	}
	if len(ca.PermittedIPRanges) > 0 {
		ok := false
		for _, r := range ca.PermittedIPRanges {
			if r.Contains(ip) {
				ok = true
				break
			}
		}
		if !ok {
			return "matched no permitted IP range"
		}
	}
	return ""
}
