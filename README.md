# 匿名凭证：本地签发 / 选择性披露 / 撤销服务（Go）

单进程内用本地密钥与内存状态模拟三方，演示一套**可运行**的匿名凭证系统：

- **签发方（Issuer）**：按属性策略签发凭证、留存可核对但不含属性明文的记录、执行吊销；
- **持有者（Holder）**：保存凭证并按会话授权做选择性披露，证明“满足条件”而不暴露其余属性；
- **验证方（Verifier）**：维护受信版本库与一次性会话，校验签名、承诺、会话绑定、时效与撤销状态。

所有随机源与时钟均可注入，测试在确定性种子与手工时钟下稳定运行，无需等待真实时间。

## 快速开始

```bash
go run ./cmd/demo        # 端到端演示：签发 -> 选择性披露 -> 重放拒绝 -> 撤销拒绝
go test ./...            # 单元测试
go test -race ./...      # 竞态检测（并发“校验 vs 吊销”一致性）
go test -cover ./...     # 覆盖率
```

演示输出形如：

```
issued credential: cd9b3b...
decision 1: accepted=true disclosed=[level] predicates=[is_adult]
decision 2 (replay): code=proof_replay
decision 3 (after revoke): code=revoked_credential
```

审计日志（JSON，stderr）中仅打印**会话标识、披露名称集合与判定依据**，例如：

```json
{"event":"verify","accepted":true,"session_id":"68ca...","issuer":"driving-entitlement",
 "policy_version":1,"cred_id":"cd9b...","disclosed_attrs":["level"],
 "predicates":["is_adult"],"basis":"signature_ok|commitments_ok|session_bound|not_revoked"}
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

- CredID 出现在出示证明中，验证方理论上可在**多次出示之间**关联同一凭证。
  生产实现应改用不可链接撤销机制（如 Merkle 累加器 / BBS 签名 + 成员资格证明）。
- 谓词为有限集合（`>=`、`<=`、`=`），由签发方对“满足”预签名令牌，
  并非通用零知识范围证明；属性名集合（不含值）对验证方可见。
- 全部状态在内存中，进程退出即消失；无网络协议、无持久化。

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
- 验证方在密码学校验窗口**前后**各读取一次纪元：
  - 快照显示已吊销 → `revoked_credential`；
  - 窗口内纪元被推进（说明与某次吊销并发交错）→ 保守拒绝 `revoked_credential`，
    从而“校验-吊销”结论**可线性化**，不会出现吊销已发生却返回陈旧接受。
- 吊销是单调、幂等的：重复吊销不会改变纪元；未知凭证吊销返回
  `no_such_credential`。吊销无关凭证不影响其他凭证在新窗口内的正常校验。

## 版本兼容策略

凭证的主签名载荷中包含签发时的**版本号与模式指纹 `SchemaHash`**
（策略名 + 属性规格 + 谓词规格的确定性 JSON 摘要）。规则：

1. **未知版本**：信任库中不存在 → 建立会话即被拒（`unknown_version`）。
2. **历史版本默认兼容**：只要版本仍在信任库中登记，旧凭证继续可验证
   （新旧版本可并存，各自独立密钥）。
3. **显式日落（拒绝）**：`TrustRegistry.RejectVersion(issuer, v)` 后，
   该版本既不能开新会话，已开会话提交旧凭证也返回 `version_rejected`。
   历史凭证的命运由此是**显式规则**，不是隐式行为。
4. **参数不兼容**：版本号相同但模式指纹与受信参数不一致，或凭证版本与会话版本
   不一致 → `incompatible_parameters`。谓词令牌参数（阈值等）与策略定义漂移同样拒绝。

## 可区分的错误类型

所有失败返回带稳定类型码的 `*anoncred.Error`，用 `anoncred.CodeOf(err)` 判定：

| 阶段 | 类型码 |
|---|---|
| 签发 | `missing_attribute`、`unknown_attribute`、`invalid_attribute_value`、`attribute_out_of_range`、`policy_mismatch` |
| 证明结构 | `malformed_presentation`、`bad_issuer_signature`、`bad_holder_proof`、`tampered_disclosure`、`disclosure_not_allowed`、`predicate_not_allowed`、`undisclosed_leak` |
| 生命周期 | `revoked_credential`、`expired_credential`、`session_unknown`、`session_expired`、`proof_replay` |
| 版本 | `unknown_version`、`version_rejected`、`incompatible_parameters` |
| 管理 | `no_such_credential` |

## 代码结构

```
errors.go        可区分错误类型码
infra.go         可注入随机源（crypto/rand / 确定性）、时钟（系统 / Fake）
policy.go        属性与谓词规格、申请校验、模式哈希、谓词求值
credential.go    值类型、承诺、凭证/谓词令牌的规范签名载荷
issuer.go        策略版本密钥、签发、签发记录、吊销与撤销纪元
holder.go        钱包、一次性出示密钥、选择性披露证明构造
presentation.go  对外证明结构与持有者证明摘要
verifier.go      信任库、一次性会话、完整校验链
logging.go       结构化审计日志（不含未披露值）
service.go       三方装配与端到端流程
cmd/demo         可运行演示
*_test.go        伪造/篡改/重放/越权/撤销/版本/并发等测试
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

d, err := svc.Check(res.SessionID, res.Presentation) // 验证
_ = svc.Revoke(credID, "reason")                      // 吊销
```
