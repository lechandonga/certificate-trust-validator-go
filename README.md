# certificate-trust-validator-go

一个**纯本地、零外部依赖**（仅 Go 标准库）的证书链校验与吊销判定组件。
证书、信任锚、名称约束与吊销数据全部在本地构造或从本地文件加载，
不访问网络、不使用真实凭据。

## 能力概览

- 从终端证书确定性地构建通往信任锚的校验路径；交叉签名 / 多路径时
  结论可复现；断链、成环、锚缺失、签名失败、过期、非 CA、pathLen 违反、
  KeyUsage/EKU 不符、未知关键扩展均明确拒绝并给出可区分原因码；
- 名称约束（DNS/IP/邮箱，permitted/excluded 逐级累积、上下级冲突拒绝）
  与主机名校验（SAN 严格匹配、通配符不跨标签、IP 与 DNS 不可互相冒充）；
- 吊销判定：内存吊销源与本地 CRL 文件源；数据缺失/过期时 fail-open 或
  fail-closed 由显式配置决定；吊销数据与信任锚更新立即生效；
- 并发安全：信任数据与吊销数据以不可变快照 + `atomic.Pointer` 发布，
  单次校验只能看到完整旧版或新版；结果缓存按信任库与数据版本隔离，
  不跨信任库串用。

## 快速开始

```go
store := ctv.NewTrustStore()
store.AddAnchor(rootCert)
store.AddIntermediate(interCert)

rev := ctv.NewMemoryRevocationSource()
store.SetRevocationSources(rev)

v := ctv.NewValidator(store, ctv.Config{
    EnableRevocation:  true,
    RequireRevocation: true,
    RevocationPolicy:  ctv.RevocationHardFail, // 吊销不可用时拒绝
    ExtKeyUsage:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
})

res, err := v.Verify(ctv.VerifyOptions{
    Leaf: leafCert, Hostname: "app.example.com",
})
if err != nil {
    ve := err.(*ctv.VerifyError)
    log.Fatalf("拒绝 reason=%s detail=%s", ve.Reason, ve.Detail)
}
fmt.Println(res.Chain.Subjects())
```

## 运行测试与演示

```bash
CGO_ENABLED=1 go test -race -v ./...   # 竞态检测 + 详细业务日志
go test ./...                          # 普通模式
go run ./cmd/ctv-demo                  # 本地端到端演示
```

## 文档

- [设计与规则说明](doc/DESIGN.md)：信任模型、确定性路径选择、名称约束、
  吊销判定、失败原因分类、热更新与并发可见性。
