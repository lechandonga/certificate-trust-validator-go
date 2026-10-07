# certificate-trust-validator-go

一套完全本地运行的 X.509 证书链校验与吊销判定组件。证书、信任锚、中间证书和吊销数据全部在进程内构造或由调用方装入内存，**不访问网络、不读取系统信任库、不依赖真实凭据**，仅使用 Go 标准库。

## 模块划分

| 包 | 职责 |
| --- | --- |
| `trust` | 信任锚/中间 CA 的命名信任库、去重、指纹，以及不可变的版本化快照 |
| `revocation` | 本地 CRL 风格吊销数据（按签发者+序列号、thisUpdate/nextUpdate 窗口）、显式放行/拒绝策略、并发安全数据源 |
| `validator` | 路径构建、确定性路径选择、逐证书校验、名称约束累积、主机名/IP/邮箱标识匹配、吊销判定、版本化结果缓存与引擎 |
| `internal/testca` | 内存测试 PKI：ECDSA P-256 自签根、中间 CA（交叉签名/名称约束/KU/EKU/自定义关键扩展）、终端证书、签名篡改工具 |
| `cmd/ctvdemo` | 本地演示：构造 PKI → 缺吊销数据拒绝 → 装入新鲜数据通过 → 热更新吊销立即拒绝 |

## 信任模型

- 信任起点只有显式加入某个命名 `trust.Store` 的自签锚点；随链（`Request.Intermediates`）提供的证书只能帮助连接路径，**永远不赋予信任**。
- 一次 `Validate` 在校验开始时抓取一个不可变视图 `(trust.Snapshot, revocation.Data)`。校验过程无锁运行，因此并发的信任库/吊销更新绝不会让单次校验看到“半新半旧”的数据：它要么用旧版完整数据，要么用新版完整数据。
- 锚点自身的自签名也会被验证，防止装入被篡改的锚点字节。

## 路径构建与选择

从终端证书出发沿 issuer 关系做有界深度优先枚举（最大深度 20，用 DER 的 SHA-256 指纹在路径上检测重复以识别环），找到所有可达锚点的候选链，然后按**全序**排序：

1. 链上证书数少者优先；
2. 长度相同时，从 leaf 起逐证书比较指纹（DER SHA-256，字典序）。

同一主体有多个候选签发者（交叉签名、重签）时，桶内按“序列号 → 指纹”排序，保证枚举顺序与机器无关。校验按该顺序对候选链逐条完整验证，**第一条完全合法的链即最终结论**；全部非法时返回排序最靠前候选的具体错误。该规则在任何机器、任何运行次数下结果一致（见 `TestCrossSignDeterministic`，含 8 次重复与首选链过期后稳定回退）。

交叉签名通过“同一主体密钥的多份 CA 证书”表达：把不同锚点签发的交叉证书作为中间证书加入信任库即可，路径构建自然枚举所有路径。

### 单链校验内容（leaf → anchor）

- 有效期：`NotBefore/NotAfter` 相对校验时钟，区分 `CERT_NOT_YET_VALID` 与 `CERT_EXPIRED`；
- 基本约束：非锚点签发者必须 `basicConstraints cA=true`；终端证书 `cA=true` 拒绝；`pathLenConstraint` 按 RFC 5280 统计其下方非自签 CA 数量（自签中间证书不占额度）；
- 密钥用途：CA 必须有 `keyCertSign`；终端证书必须有 `digitalSignature`；
- 扩展密钥用途：终端证书必须含 `serverAuth`，链上任一显式设置 EKU 的 CA 必须允许 `serverAuth`（无 EKU 扩展视为不限制）；
- 签名：直接用父证书公钥对 `RawTBSCertificate` 与签名做验签（ECDSA/RSA-PKCS1v15/PSS/Ed25519），不依赖系统校验器；
- 未知关键扩展：出现在 `UnhandledCriticalExtensions` 中一律拒绝；
- 环、超长、断链在路径枚举阶段分别给出 `PATH_CYCLE`、`PATH_TOO_LONG`、`NO_VALID_PATH`。

## 名称约束与主机名校验

- 名称约束从根向下逐级合并并立即对下级证书生效：
  - **permitted 逐级取交集**：每个声明了 permitted 的层级都必须至少有一个子树命中，名称空间只能被下级收窄，不能被放宽；上下级 permitted 冲突（如上级 `.a.com`、下级 `.b.com`）必然拒绝；
  - **excluded 逐级取并集**：任一层排除即拒绝，且 excluded 优先于下层 permitted；
  - 支持 DNS 域（含前导点/裸域两种编码）、IP CIDR、rfc822Name（精确邮箱或域匹配）；
  - 证书不含某类 SAN 时，该类约束不对其生效（RFC 5280 4.2.1.10）。
- 目标标识匹配只看 SAN：
  - DNS/IP 复用标准库 `Certificate.VerifyHostname`（RFC 6125 通配符规则：`*` 只允许在最左侧且只匹配一个标签；IP 字面量精确比较）；
  - 邮箱按 rfc822Name SAN 匹配，支持精确地址与 `.domain`/裸域后缀；
  - **CN 永不作为 SAN 缺失时的别名**，中间证书或别名无法绕过标识校验。

## 吊销判定规则

`revocation.Data` 是不可变版本对象，包含按签发者 DN 组织的 `IssuerList`，每个列表有 `ThisUpdate/NextUpdate`：

- 列表缺失、当前时间早于 `ThisUpdate` 或不早于 `NextUpdate` → `StatusUnavailable`（不可用）；
- 列表新鲜且含证书序列号 → `StatusRevoked`（带 CRL reason 与吊销时间）；否则 `StatusGood`；
- 策略是每个引擎**显式配置**的，没有隐式默认：
  - `PolicyFailClosed`：链上任一非锚点证书缺少新鲜吊销数据即拒绝（`REVOCATION_UNAVAILABLE`）；
  - `PolicyFailOpen`：数据不可用时放行；但新鲜数据明确吊销时，两种策略都一律 `CERT_REVOKED`。
- `Engine.ReplaceRevocation` / `Engine.ReplaceStore` / `UpdateTrust` 原子发布新版本，下一次校验立即生效；正在执行的校验继续使用抓取的旧快照。
- 结果缓存（可选）键含信任库 ID、信任版本、吊销版本、策略、leaf 指纹、随链证书指纹与目标标识：不同信任库、任一数据版本、不同策略之间都不可能命中同一条缓存；版本更新后旧缓存自然失效（map 有界淘汰）。

## 失败原因分类

错误为 `*validator.VerificationError`，`Code` 可直接分支判断，`CertIndex` 给出链上位置（0=终端证书）：

| Code | 含义 |
| --- | --- |
| `NO_VALID_PATH` | 无法从终端证书构建到达任一锚点的路径（断链、锚点不匹配） |
| `PATH_CYCLE` | issuer 图中存在重复证书构成的环且无合法路径可到达锚点 |
| `PATH_TOO_LONG` | 超过路径搜索深度或违反某级 `pathLenConstraint` |
| `CERT_EXPIRED` / `CERT_NOT_YET_VALID` | 时间窗口外 |
| `INVALID_SIGNATURE` | 签名与签发者公钥不匹配（含被篡改的锚点自签） |
| `NOT_A_CA` / `BASIC_CONSTRAINTS` | 签发者不是 CA / 终端证书带 `cA=true` |
| `KEY_USAGE_MISMATCH` | CA 缺 `keyCertSign` 或终端缺 `digitalSignature` |
| `EXT_KEY_USAGE_MISMATCH` | 终端或 CA 不允许 `serverAuth` |
| `UNKNOWN_CRITICAL_EXT` | 出现实现不识别的关键扩展 |
| `NAME_CONSTRAINT_VIOLATION` | SAN 标识违反逐级累积的 permitted/excluded |
| `HOSTNAME_MISMATCH` | 目标主机名/IP/邮箱不被任何 SAN 覆盖 |
| `CERT_REVOKED` | 新鲜吊销数据明确包含该序列号 |
| `REVOCATION_UNAVAILABLE` | 吊销数据缺失/过期且策略为 fail-closed |
| `EMPTY_INPUT` | 未提供终端证书 |

## 本地验证方法

要求 Go 1.25+，全程离线：

```bash
# 全量单测（测试证书均在进程内即时生成，不落盘）
go test ./...

# 详细日志：每个测试打印 [业务]/用例/预期/[结果] PASS，覆盖范围一目了然
go test -v ./validator/

# 竞态检测 + 重复执行（热更新并发校验场景，需 cgo/gcc）
CGO_ENABLED=1 go test -race -count=5 ./...

# 静态检查
go vet ./...

# 本地演示
go run ./cmd/ctvdemo
```

测试覆盖的业务面：

- 多路径与非法路径：基础链、断链、随链中间证书无锚点、交叉签名双合法的确定性、首选链非法时稳定回退、多等长路径、成环及“环旁有合法路径”；
- 证书内容：过期/未生效（终端与中间）、KU/EKU 不符（终端与 CA）、签名篡改（终端与中间）、未知关键扩展、终端证书 `cA=true`、`pathLenConstraint` 超限与恰好满足；
- 名称与标识：通配符单标签限制、CN 不能绕过 SAN、IP 字面量、邮箱 SAN；permitted 命中/不命中、excluded 命中、上下级 permitted 交集为空、交集内通过、excluded 优先、IP CIDR 与邮箱域约束；
- 吊销：数据缺失/列表过期/列表未来在 fail-closed 与 fail-open 下的稳定差异、明确吊销在两种策略下都拒绝、good→revoked→good 热更新与版本号；
- 热更新与并发：32 goroutine × 200 次校验与信任库整体原子切换并发执行，断言每次接受都严格对应某一完整版本（按锚点身份归类），`-race` 下稳定；缓存不跨信任库、按信任版本与吊销版本失效。
