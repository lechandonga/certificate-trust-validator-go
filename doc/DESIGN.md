# 证书链校验与吊销判定组件 — 设计说明

包路径：`github.com/lechandonga/certificate-trust-validator-go`（包名 `ctv`）。
仅使用 Go 标准库（`crypto/x509`、`crypto/ecdsa`、`encoding/asn1` 等），不访问网络、
不依赖真实凭据。所有信任数据在本地构造或从本地文件加载。

## 1. 信任模型

- 信任的起点是 **信任锚（Trust Anchor）**：显式登记进 `TrustStore` 的自签名根证书。
  锚不会因为"名字像"或"密钥像"就被信任，必须被显式登记。
- 终端证书（叶子）本身不被直接信任；必须能构造出
  `叶子 -> 中间 CA* -> 信任锚` 的完整路径。
- 中间证书可以来自两处：`TrustStore` 中预先登记的集合，或每次校验请求
  （`VerifyOptions.Intermediates`）随附的集合（模拟 TLS 对端下发链）。两者取并集。
- 每张非叶子证书都必须通过基本约束 `cA=TRUE` 检查且 `keyUsage` 含
  `keyCertSign`；叶子与 CA 的角色不可互换。

## 2. 路径构建与确定性选择

路径构建在 `validator.go` 的 `buildPaths` 中完成：

1. 从叶子开始做 DFS，用 AKI（无 AKI 时退化为颁发者 DN）索引候选父证书；
2. 对每个候选严格校验：
   - 子证书 `Issuer` DN 与父证书 `Subject` DN 完全一致；
   - `cert.CheckSignatureFrom(parent)` 签名验证通过；
3. 候选集合按证书 DER 的 SHA-256（`certID`）字典序排序，保证遍历顺序
   与证书被加入信任库的顺序无关；
4. 用 `onPath` 集合记录当前路径已使用的证书；再次遇到同一证书即判
   `PATH_CYCLE`，该延伸被丢弃；
5. DFS 结束条件：当前证书由某个信任锚直接签发，或当前证书自身就是锚。

**多路径时的确定性排序规则**（`chainLess`）：

1. 链更长的优先（显式包含交叉签名中间证书的路径优先于"锚直签"路径）；
2. 等长时按链上证书 `certID` 序列做字典序比较。

因此同一张证书在存在多条交叉签名可达路径时，任何调用顺序、任何并发时序下
选出的路径都完全一致、可复现。

## 3. 链内容校验

对每条结构路径执行（`chaincheck.go` / `nameconstraints.go`）：

- **有效期**：`NotBefore <= now <= NotAfter`，过期或未生效均拒绝；
- **未知关键扩展**：利用 `x509.Certificate.UnhandledCriticalExtensions`，
  只要存在验证器不认识且标记 critical 的扩展即拒绝；
- **CA 基本约束 / pathLen**：非叶子证书必须 `IsCA`；逐张检查
  `pathLenConstraint`，锚本身也参与约束计算；
- **密钥用途**：CA 需要 `keyCertSign`；叶子需要
  `digitalSignature` 或 `keyAgreement`；可配置必需 EKU（如 serverAuth）；
- **签名**：路径构建阶段已逐跳验证；
- **名称约束**：自锚向叶子方向逐级累积生效，见第 4 节；
- **主机名**：优先使用叶子 SAN，严格区分 DNS 与 IP；通配符只匹配一个
  标签且只能出现在最左侧标签（`*.example.com` 不匹配 `a.b.example.com`）。

当全部候选路径都失败时，返回"最高优先级"失败原因（`reasonRank`）：
显式吊销 > 名称/主机名 > 有效期 > KeyUsage > CA/pathLen > 未知关键扩展 >
签名 > 吊销不可用 > 其它。这样失败结论不会被路径枚举顺序偶然性影响。

## 4. 名称约束规则

按 RFC 5280 4.2.1.10 语义实现，对位置 `i` 上的 CA 证书，其
`Permitted*/Excluded*` 约束作用于链上其下方的所有证书 `0..i-1`：

- DNS：`example.com` 匹配自身与所有子域；`.example.com` 仅匹配子域；
- IP：基于 `PermittedIPRanges/ExcludedIPRanges` 网段包含判定；
- 邮箱：支持域形式（`example.com`）与 `@example.com` 形式；
- 每个证书的每一类标识（DNS/IP/邮箱）：
  - 命中任一 `excludedSubtrees` => 拒绝；
  - 当 `permittedSubtrees` 非空时，必须命中至少一条 permitted；
- 上下级约束按交集传播：上级 permit 某域、下级 exclude 其子域，则
  落在该子域内的叶子无法同时满足，必然被拒绝，中间 CA 无法"放行"绕过。

## 5. 吊销判定规则

抽象接口（`revocation.go`）：

- `RevocationSource`：可热更新的来源，`Current()` 返回不可变快照视图
  `RevocationView`；
- 内置实现：`MemoryRevocationSource`（测试/本地构造）与
  `CRLFileRevocationSource`（本地 DER/PEM CRL 文件，`Reload` 重新读盘）。

`Validator.Verify` 在开始时对每个来源抓取 **一次** `Current()`，整次校验
只使用这一组视图。单次校验看到的要么是旧版完整数据，要么是新版完整数据。

对链上每张非锚证书（以其直接颁发者 DN + 自身序列号查询）：

1. 任一视图显式 `Revoked=true` => `CERT_REVOKED`（硬结论，任何策略都拒绝）；
2. 任一覆盖该颁发者的视图已过 `nextUpdate`（数据过期）：
   - `RevocationHardFail` => `REVOCATION_DATA_EXPIRED` 拒绝；
   - `RevocationSoftFail` => 放行；
3. 没有任何视图覆盖该颁发者（缺失/不可用）：
   - `Config.RequireRevocation=false` => 放行；
   - `RequireRevocation=true` 时按显式策略：HardFail 拒绝
     （`REVOCATION_STATUS_UNAVAILABLE`）/ SoftFail 放行。

硬失败（fail-closed）与软失败（fail-open）必须由调用方显式选择，组件不
提供会悄悄改变安全语义的隐式默认。

## 6. 热更新与并发可见性

- `TrustStore` 内部保存不可变 `snapshot`，所有写操作（增删锚、增中间证书、
  替换吊销源集合）均 copy-on-write 后通过 `atomic.Pointer` 发布，版本号
  单调递增；
- 吊销源同理以 `atomic.Pointer<view>` 发布不可变视图；
- 校验成功结果缓存（`cache.go`）的键包含：信任库快照版本、每个吊销视图
  版本、叶子与额外中间证书指纹集合、主机名、秒级校验时刻。吊销数据或
  信任数据一更新，对应缓存键立即失效，新判定立刻生效；
- 缓存实例从属于单个 `Validator`（即单个 `TrustStore`），不同信任库使用
  不同 `Validator`，缓存不可能跨库串用。

## 7. 失败原因分类

| ReasonCode | 含义 |
| --- | --- |
| `NO_CERTIFICATE` | 未提供叶子证书 |
| `CERT_EXPIRED_OR_NOT_YET_VALID` | 过期或尚未生效 |
| `NOT_A_CERTIFICATE_AUTHORITY` | 承担 CA 角色的证书 `cA=false` |
| `PATH_LEN_CONSTRAINT_EXCEEDED` | 违反 pathLenConstraint |
| `KEY_USAGE_MISMATCH` | KeyUsage/EKU 不满足所需用途 |
| `UNKNOWN_CRITICAL_EXTENSION` | 存在不认识的关键扩展 |
| `SIGNATURE_INVALID` | 签名无法用颁发者公钥验证 |
| `NAME_CONSTRAINT_VIOLATION` | 违反 permitted/excluded 名称约束 |
| `HOSTNAME_MISMATCH` | 目标主机名与叶子 SAN 不匹配 |
| `NO_VALID_PATH` | 找不到通往信任锚的路径（断链） |
| `PATH_CYCLE` | 路径中证书成环 |
| `TRUST_ANCHOR_NOT_FOUND` | 链顶颁发者与任何信任锚不匹配 |
| `CERT_REVOKED` | 证书被显式吊销 |
| `REVOCATION_STATUS_UNAVAILABLE` | 吊销数据缺失/不可用且硬失败 |
| `REVOCATION_DATA_EXPIRED` | 吊销数据已过 nextUpdate 且硬失败 |
| `INTERNAL_ERROR` | 不应发生的内部错误 |

错误统一为 `*ctv.VerifyError`，含 `Reason`、`CertIndex`（链下标）、
`Subject`、`Detail`，便于按码分支与排障。

## 8. 本地验证方法

```bash
# 全部单测（竞态检测）
CGO_ENABLED=1 go test -race -v ./...

# 不带竞态检测的环境
go test -v ./...

# 静态检查
go vet ./...

# 端到端演示（本地构造证书与吊销数据）
go run ./cmd/ctv-demo
```

测试证书全部在 `certtestkit_test.go` 中用 ECDSA P-256 即时生成，
不落盘、不含真实凭据。`go test -v` 的日志按"业务 N / 用例[...] PASS"
组织，可直接看出覆盖的业务与每个用例的结果。
