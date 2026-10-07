package ctv

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

// certID 以证书 DER 的 SHA-256 摘要作为证书的稳定身份。
// 交叉签名场景下同主体/同公钥的不同证书拥有不同 ID，
// 因此可以被当作独立节点参与确定性的路径选择。
func certID(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func certName(c *x509.Certificate) string {
	if c == nil {
		return "<nil>"
	}
	if c.Subject.String() != "" {
		return c.Subject.String()
	}
	sum := sha256.Sum256(c.Raw)
	return "cert:" + hex.EncodeToString(sum[:8])
}

// Chain 表示一条校验路径：Chains[0] 为终端证书，
// 其后依次是中间证书，最后一个元素为信任锚（自签名）。
type Chain struct {
	Certs []*x509.Certificate
}

func (c Chain) leaf() *x509.Certificate { return c.Certs[0] }

// Subjects 返回链上每个证书的主题，仅用于日志与结果展示。
func (c Chain) Subjects() []string {
	out := make([]string, len(c.Certs))
	for i, cert := range c.Certs {
		out[i] = certName(cert)
	}
	return out
}
