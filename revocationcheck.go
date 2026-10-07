package ctv

import (
	"time"
)

// checkRevocation 对链上每张非锚证书做吊销判定。
// 规则（确定性，不依赖任何外部服务）：
//  1. 任一吊销视图显式给出 revoked => ReasonRevoked；
//  2. 否则，若任一覆盖该颁发者的视图数据已过期：
//     HardFail => ReasonRevocationDataExpired；SoftFail => 放行；
//  3. 否则，没有任何视图覆盖该颁发者（缺失/不可用）：
//     RequireRevocation 时按 Hard/Soft 分别拒绝或放行；否则放行。
//
// 所有视图来自同一次 Current() 抓取，单次校验看到的是一致版本集合。
func (v *Validator) checkRevocation(chain Chain, views []RevocationView, when time.Time) *VerifyError {
	if !v.config.EnableRevocation {
		return nil
	}
	certs := chain.Certs
	// 证书 i 由其颁发者 certs[i+1] 吊销；锚自身不检查。
	for i := 0; i < len(certs)-1; i++ {
		c := certs[i]
		issuer := certs[i+1]
		issuerDN := issuerNameKey(issuer)
		serial := serialKey(c)

		covered := false
		stale := false
		for _, view := range views {
			if entry, ok := view.Lookup(issuerDN, serial); ok {
				covered = true
				if entry.Revoked {
					detail := "serial " + serial + " is listed as revoked by '" + issuerDN + "'"
					if !entry.RevocationTime.IsZero() {
						detail += " at " + entry.RevocationTime.UTC().Format(time.RFC3339)
					}
					return newVerifyError(ReasonRevoked, i, certName(c), detail)
				}
			}
			has, fresh := view.FreshAt(issuerDN, when)
			if has {
				covered = true
				if !fresh {
					stale = true
				}
			}
		}

		if stale {
			if v.config.RevocationPolicy == RevocationHardFail {
				return newVerifyError(ReasonRevocationDataExpired, i, certName(c),
					"revocation data for issuer '"+issuerDN+"' is past its nextUpdate")
			}
			continue // soft fail：数据过期但未显式吊销 => 放行
		}
		if !covered && v.config.RequireRevocation {
			if v.config.RevocationPolicy == RevocationHardFail {
				return newVerifyError(ReasonRevocationUnavailable, i, certName(c),
					"no usable revocation data for issuer '"+issuerDN+"' (hard-fail)")
			}
			// soft fail：显式放行。
		}
	}
	return nil
}
