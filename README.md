# 本地匿名凭证签发、选择性披露与撤销服务（Go）

一个完全在本地运行、无外部依赖（仅 Go 标准库）的匿名凭证系统模拟：
使用本地 Ed25519 密钥与内存状态扮演**签发方（Issuer）/持有者（Holder）/
验证方（Verifier）**三方，实现凭证签发、选择性披露、会话绑定防重放、
即时撤销与策略版本演进，并对每一次判定给出**可区分错误类型**与
**可解释日志**。

## 快速开始

```bash
go run ./cmd/anondemo        # 端到端演示（正常/拒绝/篡改/重放/撤销/版本）
go test ./...                # 全部单测（确定性随机源与步进时钟，无需等待）
go test -race ./...          # 并发线性一致性测试（竞态检测）
go vet ./...
```

演示与测试不访问网络、不读写磁盘；签发/撤销登记表只存在于内存。

## 包结构

| 包 | 职责 |
| --- | --- |
| `internal/errors` | 可区分错误类型（`Kind`）：缺失/越界/越权/撤销/篡改/重放/版本等 |
| `internal/sys` | 可注入时钟（`RealClock`/`StepClock`/`FixedClock`）与随机源（`crypto/rand`/种子确定性 ChaCha8） |
| `internal/canonical` | 长度前缀确定性编码 + 域分隔 SHA-256 |
| `internal/policy` | 属性模式（int/enum/string、范围、必填、可披露标记）、一致性规则、版本注册表 |
| `internal/commitment` | 固定槽位 Merkle 属性承诺与开放证明（含路径深度严格校验） |
| `internal/credential` | 凭证主体、Ed25519 签发/验签、随机凭证标识秘密与标识承诺 |
| `internal/registry` | 并发安全的签发记录/撤销登记表（**不存属性明文**）、挑战盲化撤销查询 |
| `internal/issuer` | 策略校验、盐与标识生成、签发、撤销、审计 |
| `internal/holder` | 钱包、选择性披露证明、谓词、会话盲标签与 nullifier |
| `internal/verifier` | 会话/挑战管理、全链路校验、nullifier 防重放、TTL、版本下界 |
| `internal/logging` | `key=value` 结构化日志（会话标识、披露集合、判定依据） |

## 信任模型

- **签发方被信任**：诚实执行签发策略、保管 Ed25519 私钥、维护撤销状态。
  验证方只信任签发方公钥。
- **持有者不可信但自我保护**：持有者持有凭证、属性盐与凭证标识秘密
  （CredID），自行决定披露哪些被允许的属性。
- **验证方不信任持有者**：对证明做全量独立校验（签名、Merkle 开放、
  谓词、撤销状态、会话新鲜度），任何一步不过即按对应 `Kind` 拒绝。
- **通道假设**：本地进程内调用模拟三方消息传递；生产部署需在信道上
  另行保证机密性/完整性（TLS），本层不重复实现。
- **这是教学/模拟级别的匿名性**：选择性披露由 Merkle 承诺 + 盐实现，
  不包含配对群上的零知识范围证明（对**未披露**属性的范围/不等式谓词
  因此被明确拒绝，见下）。

### 不可关联性

- 每次签发都独立生成随机 CredID、每属性随机盐；同一持有者重复申领
  得到的 CredID、标识承诺、签名两两不同（测试 `TestRepeatedIssuanceUnlinkable`）。
- 凭证主体不含 HolderID；签发日志只打 HolderID 的摘要前缀。
- 对外证明中的撤销标识是按**会话挑战**盲化的 HMAC 标签，nullifier
  也是 `H(CredID, challenge)`，跨会话不可关联。

## 签发规则与拒绝原因（可区分）

申请先经 `policy.Registry.ValidateIssuance`：

| 情形 | 错误 Kind |
| --- | --- |
| 缺少必填属性 | `missing_attribute` |
| int 越界 / enum 不在白名单 / string 超长或类型错 | `value_out_of_range` |
| 跨属性一致性规则失败（如 `level=premium` 须 `age>=18`）、出现策略未定义属性 | `policy_violation` |
| 策略版本不存在 | `unknown_policy_version` |
| 策略版本已 Deprecated 仍申请新签发 | `incompatible_version` |

签发后登记表只保存：CredID（撤销句柄）、标识承诺、策略版本、签发
时间戳、撤销标志。**不保存属性明文与盐**；审计接口（`Audit`）甚至
不回放 CredID。

## 选择性披露规则

- 每个属性在策略中有 `Disclosable` 标记（如 `ssn=false`）。持有者
  请求披露未授权属性时，在**证明构造阶段**即被拒绝
  （`unauthorized_disclosure`）；验证方对收到的证明再独立检查一遍。
- 凭证的全部属性（含值与盐）进入固定槽位 Merkle 承诺根，根被
  Ed25519 签名覆盖。披露某属性时给出值、盐与兄弟路径；未披露属性
  仅以哈希兄弟形式出现。
- 可选属性缺失时占用固定 `null leaf`，可证明“为空”而不泄露其他信息。
- 谓词只支持在**已披露**属性上的 `eq`（等值）与 `gte`（整数下界，
  含相等）。对未披露属性提谓词返回 `unauthorized_disclosure`；
  条件不成立返回 `proof_invalid`。
- 证明结构中只有 `Reveals` 里声明且排序去重的属性；夹带额外属性、
  两个证明占用同一 Merkle 位置、路径深度与槽位数不符都会被拒绝。

## 防篡改、防重放与会话绑定

验证方为每个会话生成随机挑战，证明绑定：`SessionID`、挑战、承诺根、
SchemaHash、策略版本、披露集合与签名。判定顺序见
`internal/verifier/verifier.go` 文档注释：

1. 会话存在、未过期（TTL）、未被消耗；
2. 证明的会话/挑战与当前会话一致——**跨会话重放** → `replay`；
3. nullifier 在本会话未用过——**同一证明重复使用/并发重放** → `replay`；
4. 版本与 SchemaHash 校验；
5. 每个开放证明校验——**改值/改盐/改路径** → `proof_tampered`；
6. 谓词在披露值上成立；
7. 凭证主体重算并验 Ed25519——**伪造/改签** → `proof_tampered`；
8. 在线撤销检查；
9. 在互斥区内原子地占用会话与 nullifier。

nullifier 与盲标签按挑战变化，因此**不会跨会话成为可关联 ID**。

## 撤销规则与并发一致性

- `Issuer.Revoke(credID)` 立即置位；登记表对每个记录维护修订版本号
  `Rev`（0=有效，1=已撤销）。
- 验证时持有者提交 `BlindedRevID = HMAC(CredID, sessionChallenge)`，
  登记表在同一把锁内匹配并在 `RWMutex` 读锁下给出状态——
  “撤销”与“校验”对该记录的状态读取在单一全序上线性一致：
  - 未知盲标签 → `unknown_credential`；
  - 已撤销 → `credential_revoked`，且后续任何新会话必然失败；
  - 应答中的标识承诺必须与证明中的 `IDCommitment` 一致，否则
    `proof_tampered`。
- 并发测试 `TestRevocationImmediateAndConcurrent` 在 60 个校验协程与
  1 个撤销协程竞争下，用“接受时观察到的修订版本必须 < 撤销版本”
  断言线性一致性；`go test -race` 下重复运行无竞态、无矛盾结论。

## 版本兼容策略

- 策略以单调递增的 `Version` 注册；`Status` 为 `Active` 或
  `Deprecated`。
- `Active`：可签发可验证；`Deprecated`：拒绝新签发
  （`incompatible_version`），历史凭证仍可验证。
- 每个策略的参数（属性集合、类型、范围、枚举、长度）派生出
  `SchemaHash`，写入被签名的凭证主体。校验时与注册表中**同版本**
  参数的当前哈希比对：参数被不兼容修改 → `incompatible_version`，
  绝不静默接受。
- 验证方配置 `MinAcceptedVersion` 下界；低于下界的历史凭证被明确
  拒绝（`incompatible_version`）；注册表中不存在的版本是
  `unknown_policy_version`。
- 新增大版本策略（演示中的 v2：扩枚举、放宽 ssn 长度）与旧凭证
  并存：旧 v1 凭证继续按 v1 参数验证，直到被废止或低于验证方下界。

## 日志与可解释性

每条验证/签发日志包含 `session=`、`disclosed=`（逗号分隔的披露
属性名）、`decision=accept|reject`、`basis=`（判定环节）与
`error=`（Kind）。**未披露属性的名称与值、HolderID 明文、CredID
都不会出现在日志中**；签发侧的 HolderID 仅以摘要前缀关联。
测试可注入 `bytes.Buffer` 断言日志内容（见
`TestLogsContainSessionDisclosedBasis`）。

## 确定性测试

- 随机源：`sys.NewSeededRandom(seed)`（ChaCha8 派生），密钥生成、
  盐、CredID、会话挑战全部可复现。
- 时钟：`sys.NewStepClock` 手动推进，TTL 过期用例零等待。
- 并发用例结果通过共享修订版本号断言，不依赖调度时序；在
  `-race -count=N` 下稳定。

## 已知局限（模拟范围之外）

- 未实现对隐藏属性的零知识范围/集合成员证明；谓词必须落在披露属性上。
- 撤销检查是登记表内的线性 HMAC 匹配（本地模拟），未使用加密
  累加器或 Merkle 撤销列表；登记表本身被假设诚实可用。
- 未实现签发方与持有者之间的盲签发（BlindCredentials）协议，
  签发方在签发瞬间可见申请属性，但不留存。
