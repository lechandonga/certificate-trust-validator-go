package ctv

import (
	"crypto/x509"
	"encoding/asn1"
	"net"
	"strings"
	"time"
)

// validateChain 对一条已经通过签名与 DN 拼接检查的结构路径做完整内容校验。
// 链顺序：chain.Certs[0] 叶子 -> ... -> 最后一个信任锚。
func (v *Validator) validateChain(chain Chain, hostname string, when time.Time) *VerifyError {
	certs := chain.Certs
	n := len(certs)

	// --- 逐张证书：有效期、未知关键扩展 ---
	for i, c := range certs {
		if when.Before(c.NotBefore) {
			return newVerifyError(ReasonExpired, i, certName(c),
				"certificate is not valid before "+c.NotBefore.UTC().Format(time.RFC3339))
		}
		if when.After(c.NotAfter) {
			return newVerifyError(ReasonExpired, i, certName(c),
				"certificate expired at "+c.NotAfter.UTC().Format(time.RFC3339))
		}
		if len(c.UnhandledCriticalExtensions) > 0 {
			return newVerifyError(ReasonUnknownCriticalExt, i, certName(c),
				"unrecognized critical extension(s) present: "+joinOIDs(c.UnhandledCriticalExtensions))
		}
	}

	// --- CA 基本约束与 pathLen ---
	// 除叶子外，每张证书都必须是 CA 且 KeyCertUsage 包含 CertSign。
	for i := 1; i < n; i++ {
		c := certs[i]
		if !c.BasicConstraintsValid || !c.IsCA {
			return newVerifyError(ReasonNotCA, i, certName(c),
				"certificate used as CA but cA basic constraint is false or absent")
		}
		if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {
			return newVerifyError(ReasonKeyUsage, i, certName(c),
				"CA certificate keyUsage does not include keyCertSign")
		}
	}
	// pathLen：certs[i] 下方允许的中间 CA 数量 = n-1-i-? 对位置 i（非叶子、非锚
	// 不特殊处理锚，锚也必须满足），其与叶子之间的证书数为 i-1，
	// 这些都是"由它签发的路径上的非自颁发中间 CA"。
	for i := 1; i < n; i++ {
		c := certs[i]
		if c.MaxPathLen >= 0 {
			belowIntermediates := i - 1
			effective := c.MaxPathLen
			if c.MaxPathLenZero {
				effective = 0
			}
			if belowIntermediates > effective {
				return newVerifyError(ReasonPathLenExceeded, i, certName(c),
					"pathLenConstraint violated: intermediates below = "+itoa(belowIntermediates)+
						", allowed = "+itoa(effective))
			}
		}
	}

	// --- 叶子密钥用途 ---
	leaf := certs[0]
	if leaf.KeyUsage != 0 &&
		leaf.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement) == 0 {
		return newVerifyError(ReasonKeyUsage, 0, certName(leaf),
			"leaf keyUsage permits neither digitalSignature nor keyAgreement")
	}
	if len(v.config.ExtKeyUsage) > 0 {
		for _, required := range v.config.ExtKeyUsage {
			if !ekuAllowed(leaf, required) {
				return newVerifyError(ReasonKeyUsage, 0, certName(leaf),
					"leaf extended key usage does not include required usage "+ekuName(required))
			}
		}
	}

	// --- 名称约束：自上而下累积 permitted/excluded，逐级生效 ---
	if err := checkNameConstraints(certs); err != nil {
		return err
	}

	// --- 主机名与叶子标识匹配 ---
	if hostname != "" {
		if err := leaf.VerifyHostname(hostname); err != nil {
			return newVerifyError(ReasonHostMismatch, 0, certName(leaf),
				"hostname "+hostname+" does not match leaf identities: "+sanSummary(leaf))
		}
		// 额外确保匹配不是被 IP/名称别名"擦边"绕过：
		// VerifyHostname 已严格区分 IP 与 DNS，这里再做一次显式归类校验。
		if ip := net.ParseIP(hostname); ip != nil {
			if !leafHasIP(leaf, ip) {
				return newVerifyError(ReasonHostMismatch, 0, certName(leaf),
					"IP "+hostname+" is absent from leaf IP SANs")
			}
		} else if !leafHasDNS(leaf, hostname) {
			return newVerifyError(ReasonHostMismatch, 0, certName(leaf),
				"DNS name "+hostname+" matches no leaf DNS SAN / common name")
		}
	}

	return nil
}

func ekuAllowed(leaf *x509.Certificate, required x509.ExtKeyUsage) bool {
	if len(leaf.ExtKeyUsage) == 0 {
		return true // 未限制 EKU 时允许任意用途
	}
	for _, u := range leaf.ExtKeyUsage {
		if u == required {
			return true
		}
	}
	return false
}

func ekuName(u x509.ExtKeyUsage) string {
	switch u {
	case x509.ExtKeyUsageServerAuth:
		return "serverAuth"
	case x509.ExtKeyUsageClientAuth:
		return "clientAuth"
	case x509.ExtKeyUsageEmailProtection:
		return "emailProtection"
	default:
		return "usage(" + itoa(int(u)) + ")"
	}
}

func joinOIDs(oids []asn1.ObjectIdentifier) string {
	parts := make([]string, len(oids))
	for i, o := range oids {
		parts[i] = o.String()
	}
	return strings.Join(parts, ",")
}

func sanSummary(c *x509.Certificate) string {
	var parts []string
	parts = append(parts, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		parts = append(parts, ip.String())
	}
	parts = append(parts, c.EmailAddresses...)
	if len(parts) == 0 && c.Subject.CommonName != "" {
		parts = append(parts, "CN="+c.Subject.CommonName)
	}
	return strings.Join(parts, ",")
}

func leafHasIP(leaf *x509.Certificate, ip net.IP) bool {
	for _, candidate := range leaf.IPAddresses {
		if candidate.Equal(ip) {
			return true
		}
	}
	return false
}

func leafHasDNS(leaf *x509.Certificate, hostname string) bool {
	host := strings.ToLower(strings.TrimSuffix(hostname, "."))
	for _, name := range leaf.DNSNames {
		if matchDNS(strings.ToLower(strings.TrimSuffix(name, ".")), host) {
			return true
		}
	}
	if len(leaf.DNSNames) == 0 && strings.EqualFold(strings.TrimSuffix(leaf.Subject.CommonName, "."), host) {
		return true
	}
	return false
}

// matchDNS 实现标准通配符规则：仅最左侧标签可为 "*"，且 "*" 只匹配一个标签。
func matchDNS(pattern, host string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == host
	}
	plabels := strings.Split(pattern, ".")
	hlabels := strings.Split(host, ".")
	if len(plabels) != len(hlabels) || len(plabels) < 2 {
		return false
	}
	for i, p := range plabels {
		if i == 0 && strings.HasPrefix(p, "*") {
			// "*" 或 "a*" 形式：x509 的规则是整标签为 "*"，这里同样只接受整星。
			if p != "*" {
				return false
			}
			if hlabels[i] == "" {
				return false
			}
			continue
		}
		if p != hlabels[i] {
			return false
		}
	}
	return true
}
