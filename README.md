# 匿名凭证：本地签发 / 选择性披露 / 不可关联出示 / 撤销服务（Go）

单进程内用本地密钥与内存状态模拟三方，演示一套**可运行**的匿名凭证系统：

- **签发方（Issuer）**：按属性策略签发凭证、留存可核对但不含属性明文的记录、执行吊销，
  并为 v2 出示签发会话绑定的短期背书；
- **持有者（Holder）**：保存凭证并按会话授权做选择性披露；v2 出示每次刷新全部公开特征，
  证明“满足条件”而不暴露其余属性，也不留下可跨场景串联的线索；
- **验证方（Verifier）**：维护受信版本库与一次性会话，旧格式直接校验签名/承诺，
  v2 格式校验“签发方短期背书 + 一次性持有者证明”，并做时效与撤销纪元线性化检查。

所有随机源与时钟均可注入，测试在确定性种子与手工时钟下稳定运行，无需等待真实时间。

## 快速开始

```bash
go run ./cmd/demo        # 不可关联出示 -> 撤销即时生效 -> 兼容窗口结束 -> 重复发布冲突
go test ./...            # 单元测试
go test -v ./...         # 逐用例日志：可见各业务覆盖与通过情况
go test -race ./...      # 竞态检测（并发验证/撤销交错、并发重复发布）
go test -race -run Republish ./...   # 只跑并发重复发布用例（幂等/冲突/交错一致性）
go test -cover ./...     # 覆盖率
```

并发重复发布用例（`republish_concurrency_test.go`）使用注入的确定性随机源
（每次取随机数前让出调度以放大竞争窗口）与手工时钟，不依赖真实等待，覆盖：

- `TestConcurrentIdenticalRepublishIdempotent`：并发相同参数登记全部幂等成功，
  只保留首次发布的密钥，已签发凭证在任意轮重复发布后仍可验证；
- `TestConcurrentConflictingRepublishSingleWinner`：并发参数冲突只有一族成功，
  失败方全部得到 `version_conflict` 且已发布状态不被覆盖；
- `TestRepublishInterleavedWithIssueAndVerify`：发布与签发/验证交错时不出现
  “签发密钥 ≠ 信任密钥”，交错结束后新旧凭证均可验证。

演示输出形如：

```
issued two v2 credentials for the same holder
verifier1: accepted=true cred_id="" show_id=7c0bdc...
verifier1: accepted=true cred_id="" show_id=17f52f...
two scenes share no reusable show identifier; verifier decisions carry no cred id
after revoke cred1: code=revoked_credential (decision cred_id="")
cred2 still accepted after cred1 revoked: true
replay rejected: code=proof_replay
legacy credential accepted within compatibility window
legacy after window: code=compat_window_closed
identical republish: idempotent
conflicting republish: code=version_conflict
```

审计日志（JSON，stderr）中 v2 验证行的 `cred_id` 恒为空串，仅出现每次独立随机的
`show_id`，避免审计通道本身成为跨出示追踪渠道。

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

- 谓词为有限集合（`>=`、`<=`、`=`），由签发方对“满足”预签名令牌，
  并非通用零知识范围证明；属性名集合（不含值）对验证方可见。
- v2 出示中**被披露属性的明文值**按会话授权对验证方可见——两个验证方若看到
  完全相同的罕见披露值组合，理论上可据“内容本身”猜测关联；不可关联保证针对的是
  密码学标识层面（CredID/密钥/承诺/标签/盐），不隐藏被授权披露的内容。
- v2 的签发方在出示阶段是在线参与方（背书模型），且签发方天然知道“谁拿过哪张凭证”；
  不可关联针对的是**验证侧与验证侧之间**的拼合，签发方仍可按凭证核对与撤销。
- 全部状态在内存中，进程退出即消失；无网络协议、无持久化。

## 不可关联出示（v2）

默认签发的凭证采用 v2 格式。一次 v2 出示涉及两个结构：

- `ShowingEnvelope`（持有者 → 验证方 → 签发方）：携带每次全新随机的
  **ShowID、RouteTag、一次性 Ed25519 出示密钥**，以及按本次随机数派生的
  披露值标签（ValTag）。信封中**不含** CredID、化名、凭证级持有公钥、
  属性承诺集合、静态盐与路由秘密。
- `ShowingAttestation`（签发方 → 验证方）：签发方在内部完成路由定位、撤销/有效期
  核对、持有者授权校验、披露值标签与谓词令牌复查后签发的**会话绑定短期背书**。
  背书同样不含任何长期标识。

### 不可关联范围（有测试断言）

1. **多张凭证跨场景**：同一持有者的多张凭证在不同验证方、不同时间出示，
   ShowID/RouteTag/一次性出示密钥/持有者授权签名/证明/ValTag 两两不得相同；
   即使两个验证方合并全部公开结果与日志，也无法拼回同一持有者
   （`TestMultipleCredentialsAcrossScenesUnlinkable`）。
2. **单凭证重复出示**：同一张凭证多次出示，上述特征每次全部刷新，不存在跨场景
   可复用的公开线索（`TestSameCredentialRepeatedShowsNoReusableClue`）。
3. **撤销核对不可追踪**：v2 验证决策与审计日志的 `cred_id` 恒为空，只出现一次性
   `show_id`；路由标签由“每凭证路由秘密 + 本次 ShowID + 会话 nonce”散列，
   验证方既不知道秘密也无法枚举（`TestV2RevocationCheckIsNotTrackable`）。
4. **背书不可搬移**：背书逐字段绑定 ShowID/会话 nonce/一次性出示密钥/披露集合，
   为 A 信封取得的背书无法用于 B 信封（`TestV2AttestationCannotBeMoved`）。

### 路由标签如何工作

```
RouteTag = SHA-256("anoncred:route:v2" | routingSecret | showID | sessionNonce | issuer#version)
ValTag   = SHA-256("anoncred:valtag:v2" | salt | showID | sessionNonce | attrName | encode(value))
```

`routingSecret` 为每凭证独立随机、仅签发方与持有者知道；静态盐不进入信封。
签发方在背书时遍历自身记录重算标签定位凭证，验证方拿到的标签每次不同且无法离线枚举，
因而不能把多次核对串成轨迹。

### 验证链

```
结构完整性 → nonce 绑定 → 版本/信任 → 会话披露白名单 → 展示时效
→ 一次性持有者证明（防信封伪造/背书搬移）
→ 签发方背书（内部原子完成：路由定位/撤销/有效期/授权/披露/谓词）
→ 背书签名与逐字段绑定 → 撤销纪元窗口线性化
```

## 旧格式与兼容窗口

v1（旧格式）证明直接携带 CredID 与承诺集合，验证方可以在多次出示间关联同一凭证。
规则：

1. 旧格式凭证必须显式以 legacy 方式签发（`Issuer.UseLegacy(true)` 或
   `IssueRequest{Legacy: true}`），且**仅在受信版本声明的兼容窗口内可验证**。
2. 窗口通过 `Service.SetLegacyWindow(version, end)` 声明；零值 `end` 表示窗口无限。
3. 窗口结束后，旧格式证明被明确拒绝为 `compat_window_closed`（绝不静默放行，
   也不与签名失败等原因混淆）。v2 证明不受该窗口影响。
4. 旧格式凭证无法走 v2 背书路径（无路由秘密，背书时直接排除）。

## 选择性披露规则

1. 验证方在**会话**中显式给出 `AllowAttrs` 与 `AllowPredicates` 白名单。
2. 持有者只把被允许的属性（名称 + 值 + 盐）与谓词令牌放入 `Presentation`；
   未披露属性的值、盐**不出现在返回结构、序列化字节或日志中**（有测试断言）。
3. 凭证主签名载荷**不包含**谓词令牌集合，避免“令牌全集”本身泄露持有者满足了
   哪些未披露谓词；每个谓词令牌由签发方独立签名并绑定 CredID。
4. 验证时重算每个披露属性的承诺，与凭证内已签名承诺比对：
   **篡改值、篡改盐、替换为他人承诺都会失败**（`tampered_disclosure`）。
   v2 格式中静态盐不出信封，等价检查由签发方在背书时用一次性 ValTag 重算完成，
   失败结论同为 `tampered_disclosure`。
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
- **旧格式**：验证方在密码学校验窗口前后各读取一次纪元，快照显示已吊销或窗口内
  纪元推进 → `revoked_credential`（后者为与吊销并发交错时的保守拒绝）。
- **v2**：路由定位、撤销检查、有效期检查、纪元读取全部在签发方背书临界区内原子
  完成——撤销开始后到达的新出示一定拿不到背书；验证方再比较背书纪元与窗口前后的
  纪元，与任意吊销并发交错时同样保守拒绝。
- 撤销即时性语义：**撤销前完成的验证可以接受，撤销开始后新的出示必须失败**；
  撤销核对不向验证方暴露 CredID，核对过程不留可串联的长期标识。
- 吊销是单调、幂等的：重复吊销不改变纪元；未知凭证吊销返回 `no_such_credential`。
  吊销一张凭证不影响其他有效凭证（v2/旧格式均有专门测试）。
- **并发与批量边界**：会话在锁内先消费后判定，同一证明不可能被接受两次；
  与某次吊销并发的、针对其他凭证的验证可能因纪元推进被**保守拒绝**（安全侧倾斜，
  重试验证即可）。批量上千张凭证连续验证时结论按种子可复现
  （`TestBatchThousandCredentialsConsistent`）。

## 版本兼容策略

凭证的主签名载荷中包含签发时的**版本号与模式指纹 `SchemaHash`**
（策略名 + 属性规格 + 谓词规格的确定性 JSON 摘要）。规则：

1. **未知版本**：信任库中不存在 → 建立会话即被拒（`unknown_version`）。
2. **历史版本默认兼容**：只要版本仍在信任库中登记，旧凭证继续可验证
   （新旧版本可并存，各自独立密钥）。
3. **同版本重复发布不得被悄悄覆盖**（并发与串行语义一致）：
   - 参数完全一致的重复发布 → **幂等**，保留首次发布的密钥（既有凭证不失效）；
   - 版本号相同但策略参数/模式指纹或签发方公钥不一致 →
     `version_conflict`，签发方与信任库两侧都会拒绝，首次发布不受影响。

   并发边界（有专门竞态测试，见下文）：
   - “参数一致”按**模式指纹 `SchemaHash`** 判定（策略名 + 属性/谓词规格），
     与验证方“参数不兼容”的口径一致；`IssuedAt`/`Description` 等元数据不参与判定。
   - 签发方在**单个写锁临界区**内完成“复查既有发布 + 安装新版本”：多条初始化
     路径同时登记同一版本时只有**首个安装生效**，其余执行流要么幂等返回首次发布
     的材料，要么以 `version_conflict` 失败——绝不出现后发覆盖，也不会进入
     “签发密钥与验证方信任密钥不一致”的状态。
   - 冲突失败是**专属类型码** `version_conflict`，与 `bad_issuer_signature`
     （签名校验失败）、`incompatible_parameters`（参数不兼容）明确区分；
     失败方不改动任何已发布状态，密钥生成等中间步骤失败也不会留下半更新的版本。
   - 重复发布与签发/验证交错时：发布结束后新签发的凭证必可验证，已签发凭证
     继续有效（除非命中上述显式版本规则）。
   - 公开材料访问器（`AddPolicyVersion`/`ActivePublic`/`PublicOf`）均返回
     **深拷贝**，调用方无法经返回指针改动已发布状态。
4. **显式日落（拒绝）**：`TrustRegistry.RejectVersion(issuer, v)` 后，
   该版本既不能开新会话，已开会话提交证明（含 v2 背书）也返回 `version_rejected`。
   历史凭证的命运由此是**显式规则**，不是隐式行为。
5. **旧格式兼容窗口**：旧格式证明仅在 `SetLegacyWindow` 声明的窗口内可验；
   窗口结束 → `compat_window_closed`。
6. **参数不兼容**：版本号相同但模式指纹与受信参数不一致，或凭证/出示版本与会话版本
   不一致 → `incompatible_parameters`。谓词令牌参数（阈值等）与策略定义漂移同样拒绝。

## 可区分的错误类型

所有失败返回带稳定类型码的 `*anoncred.Error`，用 `anoncred.CodeOf(err)` 判定：

| 阶段 | 类型码 |
|---|---|
| 签发 | `missing_attribute`、`unknown_attribute`、`invalid_attribute_value`、`attribute_out_of_range`、`policy_mismatch` |
| 证明结构 | `malformed_presentation`、`bad_issuer_signature`、`bad_holder_proof`、`tampered_disclosure`、`disclosure_not_allowed`、`predicate_not_allowed`、`undisclosed_leak`、`showing_rejected` |
| 生命周期 | `revoked_credential`、`expired_credential`、`session_unknown`、`session_expired`、`proof_replay` |
| 版本 | `unknown_version`、`version_rejected`、`incompatible_parameters`、`version_conflict`、`compat_window_closed` |
| 管理 | `no_such_credential` |

## 代码结构

```
errors.go              可区分错误类型码
infra.go               可注入随机源（crypto/rand / 确定性）、时钟（系统 / Fake）
policy.go              属性与谓词规格、申请校验、模式哈希、谓词求值
credential.go          值类型、承诺、凭证/谓词令牌的规范签名载荷、签发记录
issuer.go              策略版本密钥（重复发布规则）、签发、签发记录、吊销与撤销纪元
showing.go             v2 不可关联出示：信封/背书类型、路由标签与值标签、规范编码
showing_authority.go   签发方对 v2 出示的原子背书核对（撤销/授权/披露/谓词）
holder.go              钱包、一次性出示密钥、legacy 与 v2 两种证明构造
presentation.go        对外证明结构（双格式）与持有者证明摘要
verifier.go            信任库（含兼容窗口）、一次性会话、旧格式校验链
verifier_v2.go         v2 背书校验链与背书-信封绑定检查
logging.go             结构化审计日志（v2 不记录 cred_id）
service.go             三方装配与端到端流程
cmd/demo               可运行演示
*_test.go              伪造/篡改/重放/越权/撤销/版本/并发/批量/不可关联等测试
```

## 在代码中使用

```go
svc := anoncred.NewService(anoncred.ServiceConfig{Clock: anoncred.NewFakeClock(now)})
_ = svc.RegisterPolicy(policy)            // 默认签发的即为 v2 不可关联凭证
// _ = svc.SetLegacyWindow(1, windowEnd)  // 仅迁移期需要接受旧格式时声明窗口

credID, _ := svc.IssueAndHold(anoncred.IssueRequest{
    PolicyName: policy.Name, PolicyVersion: policy.Version,
    Attributes: map[string]anoncred.Value{ /* ... */ },
})

res, _ := svc.Prove(credID, anoncred.VerifyPolicy{
    AllowAttrs: []string{"level"}, AllowPredicates: []string{"is_adult"},
}, []string{"level"}, []string{"is_adult"})

d, err := svc.Check(res.SessionID, res.Presentation) // 验证（d.CredID 为空，d.ShowID 一次性）
_ = svc.Revoke(credID, "reason")                      // 吊销：之后新出示立即失败
```

本地验证新增场景：

```bash
go test -run 'TestMultipleCredentialsAcrossScenesUnlinkable|TestSameCredentialRepeatedShowsNoReusableClue' .
go test -run 'TestV2Revocation' .                  # 撤销即时生效/不可追踪/不误伤
go test -run 'TestIssuerRepublish|TestTrustRegistryRepublish|TestLegacyCompatWindowEnd' .
go test -run 'TestBatchThousand|TestV2ConcurrentMulti' . -race
```
