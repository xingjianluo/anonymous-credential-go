# 匿名凭证：本地签发 / 选择性披露 / 不可关联出示 / 撤销服务（Go）

单进程内用本地密钥与内存状态模拟三方，演示一套**可运行**的匿名凭证系统：

- **签发方（Issuer）**：按属性策略签发凭证、留存可核对但不含属性明文的记录、执行吊销；
  并为持有者的**每次出示**单独签发短命、与历史不可关联的出示封套与撤销断言；
- **持有者（Holder）**：保存凭证并按会话授权做选择性披露。支持两种出示方式：
  - **legacy**：直接出示签入长期 CredID 的凭证（已知可关联，仅在兼容窗口内接受）；
  - **v2（默认推荐）**：每次出示全新随机化，跨场景、跨凭证、跨验证方都拼不回同一人；
- **验证方（Verifier）**：维护受信版本库与一次性会话，校验签名、承诺、会话绑定、时效与
  撤销状态。v2 路径全程不接触任何长期标识。

所有随机源与时钟均可注入，测试在确定性种子与手工时钟下稳定运行，无需等待真实时间。

## 快速开始

```bash
go run ./cmd/demo        # 演示：签发 -> 选择性披露 -> 重放/撤销拒绝
                         #      -> 多次 v2 不可关联出示 -> 兼容窗口结束停用 legacy
go test ./...            # 单元测试
go test -race ./...      # 竞态检测（多验证方并发“校验 vs 吊销”一致性）
go test -cover ./...     # 覆盖率
```

演示输出形如：

```
decision 1: accepted=true disclosed=[level] predicates=[is_adult]
decision 2 (replay): code=proof_replay
decision 3 (after revoke): code=revoked_credential
v2 show 1: accepted=true mode=v2 show_id=f1babe... disclosed=[level]
v2 show 2: accepted=true mode=v2 show_id=a0ce62... disclosed=[level]
v2 show 3: accepted=true mode=v2 show_id=a55b18... disclosed=[level]
each v2 show uses a fresh show_id; nothing correlates them
legacy show after window: code=legacy_presentation_rejected (explicitly rejected)
v2 show after window: accepted=true (unlinkable mode unaffected)
```


审计日志（JSON，stderr）中仅打印**会话标识、披露名称集合与判定依据**，例如：

```json
{"event":"verify","accepted":true,"session_id":"68ca...","issuer":"driving-entitlement",
 "policy_version":1,"cred_id":"cd9b...","disclosed_attrs":["level"],
 "predicates":["is_adult"],"basis":"signature_ok|commitments_ok|session_bound|not_revoked"}
```

v2 验证日志没有 `cred_id`，改为不可复用的 `mode` 与一次性 `show_id`：

```json
{"event":"verify","mode":"v2","accepted":true,"session_id":"ab12...",
 "issuer":"driving-entitlement","policy_version":1,"show_id":"f1babe...",
 "disclosed_attrs":["level"],"predicates":["is_adult"],
 "basis":"signature_ok|commitments_ok|session_bound|not_revoked"}
```

## 信任模型

### 密钥与绑定

1. 每个**策略版本**拥有独立的 Ed25519 签发密钥；验证方只信任通过带外方式登记到
   `TrustRegistry` 的版本公钥。**未知版本一律拒绝，绝不静默接受。**
2. 持有者在申领前生成一次性 **Ed25519 出示密钥对**：公钥随属性一起提交并被签发方
   签入凭证，私钥只留在持有者钱包里。任何证明必须由该私钥签名，因此凭证即使被复制，
   非持有者也无法冒用。
3. 凭证内不含属性明文，只有对每个属性的盐化承诺：
   `commitment = SHA-256("anoncred:commit:v1" | attrName | salt | value)`，
   盐为每次签发的一次性随机数。

### 凭证里有什么 / 签发记录里有什么

| 数据 | 凭证（持有者保存） | 签发记录（签发方留存） |
|---|---|---|
| 属性明文 | 仅持有者本地保存 | **不保存** |
| 属性承诺（盐化哈希） | 保存 | 保存（可核对、可吊销） |
| 一次性盐 | 持有者保存 | 不保存（无法回推明文） |
| CredID | 每次签发独立随机 | 仅随机 ID，无属性关联 |
| 持有者化名 | 保存 | 保存（用于审计/吊销定位） |
| 撤销状态 | —— | 保存（含时间、原因） |

因此签发方“知道给谁、发过什么版本、是否已吊销”，但**不留存任何属性值**；
同一持有者重复申领得到的多个 CredID 互相独立、随机，签发记录之间不可据此关联属性。

### 模拟实现的已知限制（非生产级匿名）

- **legacy 出示方式**直接携带 CredID，验证方可在多次出示间关联同一凭证。
  该方式仅在声明的**兼容窗口**内接受，窗口结束后明确拒绝；新系统默认走 v2。
- v2 的不可关联性需要持有者在出示时与签发方做一次**在线私有交互**
  （`PrepareShow`）。签发方据此知道“某凭证正在申请出示”，但验证方与任何
  外部观察者都拿不到可串联的材料；威胁模型假设签发方不与验证方合谋。
  生产实现可用 BBS 签名 / 累加器成员证明做到无需该次交互。
- 谓词为有限集合（`>=`、`<=`、`=`），由签发方对“满足”预签名令牌，
  并非通用零知识范围证明；属性名集合（不含值）对验证方可见。
- 全部状态在内存中，进程退出即消失；无网络协议、无持久化。

## 每次出示不可关联（v2）

旧方式下，单张凭证重复出示会反复暴露同一组材料：长期 `CredID`、持有者化名、
固定一次性出示公钥、固定承诺，以及签在它们之上的内容。多个验证方只要把各自
看到的公开结果与日志拼起来，就能判断这些出示来自同一凭证、同一持有者。

v2 把“凭证”与“某一次出示”彻底分开。每次出示，持有者在一次性会话中：

1. 生成**当次独立**的出示密钥对与每个披露属性的**全新随机盐**；
2. 向签发方出示 `ShowRequest`（私下携带 CredID、原盐、新盐与明文，仅用于
   签发方核对并重签，**绝不进入对外证明**），并用凭证绑定的一次性出示私钥签名；
3. 签发方核对凭证未撤销/未过期、重算原承诺确认值未被篡改后，返回：
   - `ShowEnvelope`：当次随机 `ShowID`、当次出示公钥、只含本次披露属性的
     **新鲜盐化承诺**、绑定本会话随机数的短命时间窗，以及签发方签名；
   - 重新绑定到当次 `ShowID` 的谓词令牌（旧的 CredID 令牌不复用）；
   - 绑定本会话、不含任何标识的 `RevocationAssertion`（见下节）；
4. 持有者用当次私钥对封套/披露/谓词签名，组装 `Presentation`。

### 不可关联范围（v2 提供与不提供的保证）

**提供：**

- 同一持有者先后取得的**多张凭证**，分别在不同验证方、不同时间出示，
  对外证明里不存在任何跨出示稳定的字节（ShowID、出示公钥、承诺、所有签名、
  撤销断言全部每次独立重新生成），拼日志也无法判定同源；
- **单张凭证**在不同场景重复出示，每次的 `ShowID`、承诺、令牌签名、持有者
  证明都不同，没有可跨场景复用的公开线索；
- 证明与审计日志都**不含**长期 CredID、持有者化名、固定出示公钥；未披露
  属性的值/盐/存在性（封套只承诺本次实际披露的属性）同样不外泄；
- 会话一次性 + 封套绑定会话随机数：同一证明不能重复接受，也不能跨会话重放。

**不提供 / 边界：**

- 策略名、版本号、模式指纹、披露属性名集合、谓词名、粗略时间戳属于出示场景
  的固有信息，仍对验证方可见——两个完全相同的“披露画像”在语义上可能被猜测
  关联，但密码学材料层面没有可复用标识；
- 签发方在 `PrepareShow` 环节知道是哪张凭证在申请出示（这是它仍能核对/撤销
  的前提）；不可关联性针对的是**验证侧与验证侧之间**的拼接；
- 依赖一次在线签发方交互；离线出示请用累加器/BBS 方案。

## v2 撤销检查：即时生效且自身不可追踪

- 持有者申请出示时，签发方在同一把锁下原子读取“是否已撤销 + 当前撤销纪元”，
  据此出具绑定**本次会话随机数**的 `RevocationAssertion`。断言里没有 CredID。
- 验证方校验断言签名与寿命，并与一个**无标识的全局撤销纪元**比对：
  - 凭证已撤销 → 申请阶段（`PrepareShow`）直接拒绝，新出示不可能成功；
  - 断言出具后、验证窗口内纪元被推进（发生了任何并发吊销）→ 保守拒绝，
    保证“吊销-校验”结论可线性化，不会出现吊销已发生却陈旧接受；
  - 撤销前已完成的验证可以接受。
- 验证侧**只读取全局纪元**，从不需要、也不允许按长期 CredID 查询撤销，
  因此撤销检查这条通道本身无法把多次出示串起来（有测试用包装源断言
  by-id 查询次数为 0）。
- 吊销一张凭证不影响其他有效凭证在**新的干净窗口**内出示；仅与某次吊销并发
  交错、落在同一窗口内的证明会被保守拒绝，开新窗口即恢复。

## 选择性披露规则

1. 验证方在**会话**中显式给出 `AllowAttrs` 与 `AllowPredicates` 白名单。
2. 持有者只把被允许的属性（名称 + 值 + 盐）与谓词令牌放入 `Presentation`；
   未披露属性的值、盐**不出现在返回结构、序列化字节或日志中**（有测试断言）。
3. 凭证主签名载荷**不包含**谓词令牌集合，避免“令牌全集”本身泄露持有者满足了
   哪些未披露谓词；每个谓词令牌由签发方独立签名并绑定 CredID。
4. 验证时重算每个披露属性的承诺，与凭证内已签名承诺比对：
   **篡改值、篡改盐、替换为他人承诺都会失败**（`tampered_disclosure`）。
5. 披露了白名单之外的属性 / 谓词，分别返回 `disclosure_not_allowed` /
   `predicate_not_allowed`；携带完整谓词令牌集合返回 `undisclosed_leak`。
6. 持有者证明的签名摘要覆盖：会话随机数、CredID、凭证主签名、每个披露项与谓词令牌，
   因此任何字段被改动都会使证明失效。

### 会话绑定与防重放

- `NewSession` 生成 32 字节一次性随机数与唯一会话 ID，带 TTL。
- 会话**先消费、后判定**（在互斥锁内原子标记），因此：
  - 同一证明第二次提交 → `proof_replay`；
  - 跨会话重放（nonce 不一致）→ `proof_replay`；
  - 并发提交同一证明不可能出现两个“接受”。
- 会话过期 → `session_expired`；凭证超出 `[NotBefore, ExpiresAt]` →
  `expired_credential`。

## 撤销规则与并发一致性

- `Issuer.Revoke(credID, reason)` 在互斥锁内将记录标记为已吊销，记录原因与时间。
- 维护一个单调递增的**撤销纪元（epoch）**：每发生一次新的吊销动作 `+1`。
- **legacy** 验证方按 CredID 原子读取“已撤销 + 纪元”快照，并在密码学校验窗口
  **前后**各读取一次纪元；**v2** 则只读取无标识纪元并核验会话绑定的撤销断言
  （v2 的完整语义见上文“v2 撤销检查”一节）。两条路径都保证：
  - 快照显示已吊销 → `revoked_credential`；
  - 窗口内纪元被推进（说明与某次吊销并发交错）→ 保守拒绝 `revoked_credential`，
    从而“校验-吊销”结论**可线性化**，不会出现吊销已发生却返回陈旧接受。
- 吊销是单调、幂等的：重复吊销不会改变纪元；未知凭证吊销返回
  `no_such_credential`。吊销无关凭证不影响其他凭证在新窗口内的正常校验。

## 版本兼容、停用与重复发布

凭证主签名（legacy）与 v2 出示封套都包含版本号与模式指纹 `SchemaHash`
（策略名 + 属性规格 + 谓词规格的确定性 JSON 摘要）。规则：

1. **未知版本**：信任库中不存在 → 建立会话即被拒（`unknown_version`）。
2. **历史版本默认兼容**：只要版本仍在信任库中登记，旧凭证继续可验证
   （新旧版本可并存，各自独立密钥）。
3. **显式日落（拒绝）**：`TrustRegistry.RejectVersion(issuer, v)` 后，
   该版本既不能开新会话，已开会话提交旧凭证也返回 `version_rejected`。
4. **旧版出示方式的兼容窗口**：`TrustRegistry.SetLegacyWindow(issuer, v, t)`
   声明 legacy 可关联出示的接受终点。窗口内继续接受；到达后提交的 legacy
   证明一律返回 `legacy_presentation_rejected`，而 v2 不可关联出示不受影响、
   继续可用。不设置窗口（零值）时 legacy 长期接受，保持向后兼容默认值。
5. **参数不兼容**：版本号相同但模式指纹与受信参数不一致，或凭证/封套版本与
   会话版本不一致 → `incompatible_parameters`。谓词/当次令牌参数漂移同样拒绝。
6. **同版本重复发布不允许悄悄覆盖**：
   - 再次登记的版本参数（策略名、模式指纹、签发公钥）完全一致 → 幂等，
     返回既有公开材料，**不重新生成密钥、不覆盖任何状态**；
   - 版本号相同但参数不一致 → `version_conflict`。签发方
     `AddPolicyVersion` 与验证方 `TrustRegistry.Register` 都遵守此规则；
     确需轮换信任档案只能由管理员显式调用 `TrustRegistry.Replace`
     （替换一个从未登记的版本返回 `unknown_version`）。

## 并发与批量行为边界

- 会话“先消费、后判定”，因此同一会话的并发提交最多产生一个接受结论，
  重放/跨会话提交为 `proof_replay`。
- 撤销纪元窗口使并发“校验 vs 吊销”的结论构成某种线性化交错：撤销开始前
  完成的校验可接受，之后必为 `revoked_credential`，不会出现重复接受或
  “已吊销仍接受”。
- 撤销是按凭证隔离的：吊销 A 不会使 B 的凭证失效；B 仅当自身被吊销、或其
  校验窗口与某次吊销动作并发时才失败，且在新的干净窗口内恢复。
- 批量场景（测试覆盖连续准备/验证 1000 张凭证）：钱包与签发记录不丢状态，
  每次 ShowID 两两不同；在固定注入种子下两次运行的结论集合完全可复现。
- 确定性来自可注入的 `RNG` 与 `Clock`；`DeterministicRNG` 自身带锁，
  可被多 goroutine 安全共享。

## 可区分的错误类型

所有失败返回带稳定类型码的 `*anoncred.Error`，用 `anoncred.CodeOf(err)` 判定：

| 阶段 | 类型码 |
|---|---|
| 签发 | `missing_attribute`、`unknown_attribute`、`invalid_attribute_value`、`attribute_out_of_range`、`policy_mismatch` |
| 证明结构 | `malformed_presentation`、`bad_issuer_signature`、`bad_holder_proof`、`tampered_disclosure`、`disclosure_not_allowed`、`predicate_not_allowed`、`undisclosed_leak`、`bad_show_envelope` |
| 生命周期 | `revoked_credential`、`expired_credential`、`session_unknown`、`session_expired`、`proof_replay` |
| 版本 | `unknown_version`、`version_rejected`、`incompatible_parameters`、`version_conflict`、`legacy_presentation_rejected` |
| 管理 | `no_such_credential` |

## 代码结构

```
errors.go        可区分错误类型码
infra.go         可注入随机源（crypto/rand / 确定性）、时钟（系统 / Fake）
policy.go        属性与谓词规格、申请校验、模式哈希、谓词求值
credential.go    值类型、承诺、凭证/谓词令牌的规范签名载荷
issuer.go        策略版本密钥、签发、签发记录、吊销纪元、v2 出示封套与撤销断言
holder.go        钱包、一次性出示密钥、legacy 与 v2 证明构造
presentation.go  legacy 对外证明结构与持有者证明摘要
show.go          v2 不可关联出示类型：封套/当次令牌/撤销断言及其规范载荷
verifier.go      信任库、一次性会话、legacy 与 v2 完整校验链
logging.go       结构化审计日志（v2 不记录长期标识）
service.go       三方装配与端到端流程（Prove / ProveUnlinkable）
cmd/demo         可运行演示
*_test.go        伪造/篡改/重放/越权/撤销/版本/并发/批量/不可关联等测试
```

## 在代码中使用

```go
svc := anoncred.NewService(anoncred.ServiceConfig{Clock: anoncred.NewFakeClock(now)})
_ = svc.RegisterPolicy(policy)

credID, _ := svc.IssueAndHold(anoncred.IssueRequest{
    PolicyName: policy.Name, PolicyVersion: policy.Version,
    Attributes: map[string]anoncred.Value{ /* ... */ },
})

res, _ := svc.Prove(credID, anoncred.VerifyPolicy{
    AllowAttrs: []string{"level"}, AllowPredicates: []string{"is_adult"},
}, []string{"level"}, []string{"is_adult"})

d, err := svc.Check(res.SessionID, res.Presentation) // 验证（legacy）
_ = svc.Revoke(credID, "reason")                      // 吊销

// v2：每次出示不可关联（推荐）。返回的证明里没有任何跨出示稳定标识。
r2, _ := svc.ProveUnlinkable(credID, anoncred.VerifyPolicy{
    AllowAttrs: []string{"level"}, AllowPredicates: []string{"is_adult"},
}, []string{"level"}, []string{"is_adult"})
d2, _ := svc.Check(r2.SessionID, r2.Presentation) // d2.Mode == "v2", d2.CredID == ""

// 声明旧版出示方式的兼容窗口终点；之后 legacy 被明确拒绝，v2 不受影响。
_ = svc.Trust.SetLegacyWindow(policy.Name, policy.Version, now.Add(24*time.Hour))
```

## 本地验证新增场景

除端到端演示外，可用 `-run` 精确验证本轮新增行为（全部使用注入的确定性随机源
与 FakeClock，不依赖真实等待）：

```bash
# 多张凭证跨场景不可关联、单凭证重复出示不暴露线索
go test -run TestV2MultiCredentialCrossScenarioUnlinkable -v
go test -run TestV2SameCredentialRepeatedShowsUnlinkable -v
# 撤销检查不可追踪（验证侧 by-id 查询次数必须为 0）
go test -run TestV2RevocationCheckIsNotTrackable -v
go test -run TestV2Revocation -v
# 同版本重复发布：幂等 vs version_conflict
go test -run 'TestIssuerRepublish|TestServiceRegister|TestTrustRegistryRepublish' -v
# 兼容窗口结束 legacy 被停用、v2 继续可用
go test -run TestLegacy -v
# 多验证方并发验证与撤销交错（-race 下运行）
go test -race -run TestV2Concurrent -v
# 上千凭证批量状态一致性与可复现性
go test -run TestBatch -v
```

