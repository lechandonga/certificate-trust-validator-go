package ctv

// ReasonCode 是证书链校验与吊销判定的可区分失败原因码。
// 所有失败路径都会返回携带 ReasonCode 的 *VerifyError，
// 调用方可以稳定地按码分支处理，而不必解析错误文本。
type ReasonCode string

const (
	// ReasonOK 表示校验通过。
	ReasonOK ReasonCode = "OK"

	// ReasonNoCertificate 未提供终端证书。
	ReasonNoCertificate ReasonCode = "NO_CERTIFICATE"
	// ReasonExpired 证书的 NotBefore/NotAfter 与校验时刻不符（过期或未生效）。
	ReasonExpired ReasonCode = "CERT_EXPIRED_OR_NOT_YET_VALID"
	// ReasonNotCA 链中承担 CA 角色的证书缺失 CA 基本约束。
	ReasonNotCA ReasonCode = "NOT_A_CERTIFICATE_AUTHORITY"
	// ReasonPathLenExceeded 基本约束 pathLenConstraint 被违反。
	ReasonPathLenExceeded ReasonCode = "PATH_LEN_CONSTRAINT_EXCEEDED"
	// ReasonKeyUsage 证书密钥用途（KeyUsage/ExtKeyUsage）不满足所需用途。
	ReasonKeyUsage ReasonCode = "KEY_USAGE_MISMATCH"
	// ReasonUnknownCriticalExt 证书包含验证器无法识别的关键扩展。
	ReasonUnknownCriticalExt ReasonCode = "UNKNOWN_CRITICAL_EXTENSION"
	// ReasonSignature 证书签名无法用其颁发者公钥验证。
	ReasonSignature ReasonCode = "SIGNATURE_INVALID"
	// ReasonNameConstraint 名称约束（permitted/excluded，DNS/IP/邮箱）被违反。
	ReasonNameConstraint ReasonCode = "NAME_CONSTRAINT_VIOLATION"
	// ReasonHostMismatch 目标主机名与终端证书 SAN 不匹配。
	ReasonHostMismatch ReasonCode = "HOSTNAME_MISMATCH"
	// ReasonNoPath 找不到任何通往信任锚的合法结构路径（断链）。
	ReasonNoPath ReasonCode = "NO_VALID_PATH"
	// ReasonPathCycle 构造路径时检测到证书成环。
	ReasonPathCycle ReasonCode = "PATH_CYCLE"
	// ReasonAnchorNotFound 链最终指向的签发者不在信任锚集合中。
	ReasonAnchorNotFound ReasonCode = "TRUST_ANCHOR_NOT_FOUND"
	// ReasonRevoked 证书已被吊销（CRL 明确给出 revoked 状态）。
	ReasonRevoked ReasonCode = "CERT_REVOKED"
	// ReasonRevocationUnavailable 吊销数据缺失/过期/不可用，且策略为硬失败。
	ReasonRevocationUnavailable ReasonCode = "REVOCATION_STATUS_UNAVAILABLE"
	// ReasonRevocationDataExpired 吊销数据本身已过 nextUpdate，按策略归类。
	ReasonRevocationDataExpired ReasonCode = "REVOCATION_DATA_EXPIRED"
	// ReasonInternal 不应发生的内部错误（编码/解析异常等）。
	ReasonInternal ReasonCode = "INTERNAL_ERROR"
)

// VerifyError 携带确定性原因码、出错证书在链中的下标（-1 表示不适用）
// 以及人类可读明细。CertIndex 按 [叶子, 中间..., 锚] 编号。
type VerifyError struct {
	Reason    ReasonCode
	CertIndex int
	Subject   string
	Detail    string
}

func (e *VerifyError) Error() string {
	if e.Subject != "" {
		return string(e.Reason) + ": " + e.Detail +
			" (cert index=" + itoa(e.CertIndex) + ", subject=" + e.Subject + ")"
	}
	return string(e.Reason) + ": " + e.Detail
}

func newVerifyError(reason ReasonCode, idx int, subject, detail string) *VerifyError {
	return &VerifyError{Reason: reason, CertIndex: idx, Subject: subject, Detail: detail}
}

func itoa(i int) string {
	if i < 0 {
		return "-"
	}
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
