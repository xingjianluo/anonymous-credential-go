package anoncred

import (
	"crypto/ed25519"
	"encoding/hex"
	"reflect"
	"sync"
	"time"
)

// IssuerPublic 是签发方某策略版本的公开材料，验证方据此校验。
type IssuerPublic struct {
	Policy       Policy
	VerifyingKey ed25519.PublicKey
	SchemaHash   []byte
}

// Issuer 是本地模拟的签发方：持有签名密钥、策略版本、签发记录与撤销状态。
type Issuer struct {
	mu sync.RWMutex

	rng   RNG
	clock Clock
	audit *AuditLogger

	name string

	// versions: 策略版本号 -> 公开材料（含校验公钥）
	versions map[int]*IssuerPublic
	// signKeys 与 versions 一一对应的私钥
	signKeys map[int]ed25519.PrivateKey
	// activeVersion 为当前签发使用的版本
	activeVersion int

	// legacyDefault 为 true 时，未显式指定格式的签发按旧格式生成（测试/迁移用）。
	legacyDefault bool

	// records: credID hex -> 签发记录
	records map[string]*IssuanceRecord

	// revEpoch 为单调递增的撤销纪元：每次发生一次新的吊销动作即 +1。
	// 验证方通过纪元判定自己的校验窗口内是否发生过并发撤销。
	revEpoch uint64
}

// NewIssuer 创建签发方（不预置任何策略版本）。
func NewIssuer(name string, rng RNG, clock Clock) *Issuer {
	if rng == nil {
		rng = SecureRNG{}
	}
	if clock == nil {
		clock = SystemClock{}
	}
	return &Issuer{
		name:     name,
		rng:      rng,
		clock:    clock,
		versions: map[int]*IssuerPublic{},
		signKeys: map[int]ed25519.PrivateKey{},
		records:  map[string]*IssuanceRecord{},
	}
}

// WithAudit 注入审计日志。
func (is *Issuer) WithAudit(a *AuditLogger) *Issuer {
	is.audit = a
	return is
}

// AddPolicyVersion 登记一个策略版本并为其生成独立签名密钥。
//
// 重复发布规则（同版本号不得被后一次悄悄覆盖）：
//   - 同一版本号再次登记且策略参数完全一致：幂等，保留首次发布的密钥与公开材料；
//   - 同一版本号但参数/模式不同：返回 CodeVersionConflict，绝不覆盖既有发布。
//
// 整个“检查—生成密钥—写入”过程在同一把互斥锁内原子完成，因此多个执行流
// 并发登记同一版本号时，行为与串行登记完全一致：只有第一个执行流会生成
// 密钥并发布，其余执行流要么拿到首次发布的同一份材料（参数一致），要么拿到
// CodeVersionConflict（参数不一致）。密钥生成不会在锁外进行，杜绝“检查通过
// 后、写入前被其他执行流抢先发布”的窗口。
//
// 首次登记策略时，签发方对外名称采用策略名（凭证中 PolicyName 与信任标识一致）。
func (is *Issuer) AddPolicyVersion(p Policy) (*IssuerPublic, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	if existing, ok := is.versions[p.Version]; ok {
		if !reflect.DeepEqual(existing.Policy, p) {
			return nil, FailDetail(CodeVersionConflict,
				"policy version was already published with different parameters",
				is.name+"#"+itoa(p.Version))
		}
		cp := *existing
		return &cp, nil
	}

	// 仍持锁：本版本确定由本次调用首次发布，生成密钥并一次性写入，
	// 任何并发调用都只会在上方的已发布分支里结束。
	pub, priv, err := ed25519.GenerateKey(asReader(is.rng))
	if err != nil {
		return nil, err
	}
	ip := &IssuerPublic{
		Policy:       p,
		VerifyingKey: pub,
		SchemaHash:   p.SchemaHash(),
	}
	if is.name == "" {
		is.name = p.Name
	}
	is.versions[p.Version] = ip
	is.signKeys[p.Version] = priv
	if is.activeVersion == 0 {
		is.activeVersion = p.Version
	}
	return ip, nil
}

// removeFreshVersion 仅在“本次刚首次发布、但跨组件登记随后失败”的回滚路径上
// 由同包的装配层调用：移除该版本的公开材料与签名密钥，使系统回到发布前状态，
// 绝不留下半更新的版本。调用方必须确认该版本确为本次首发、且没有其他版本
// 依赖它（回滚发生在跨组件登记仍在持锁进行时，签发尚不可见）。
func (is *Issuer) removeFreshVersion(v int) {
	is.mu.Lock()
	defer is.mu.Unlock()
	delete(is.versions, v)
	delete(is.signKeys, v)
	if is.activeVersion == v {
		is.activeVersion = 0
	}
	if len(is.versions) == 0 {
		is.name = ""
	}
}

// hasVersion 报告某版本是否已在签发方发布（不改状态）。
func (is *Issuer) hasVersion(v int) bool {
	is.mu.RLock()
	defer is.mu.RUnlock()
	_, ok := is.versions[v]
	return ok
}

// UseVersion 将当前签发版本切换为 v；未知版本返回 CodePolicyMismatch。
func (is *Issuer) UseVersion(v int) error {
	is.mu.RLock()
	_, ok := is.versions[v]
	is.mu.RUnlock()
	if !ok {
		return FailDetail(CodePolicyMismatch, "issuer has no such policy version",
			is.name+"#"+itoa(v))
	}
	is.mu.Lock()
	is.activeVersion = v
	is.mu.Unlock()
	return nil
}

// UseLegacy 设置后续签发是否默认采用旧格式（仅迁移期/测试使用）。
func (is *Issuer) UseLegacy(on bool) error {
	is.mu.Lock()
	defer is.mu.Unlock()
	is.legacyDefault = on
	return nil
}

// ActivePublic 返回当前签发版本的公开材料。
func (is *Issuer) ActivePublic() *IssuerPublic {
	is.mu.RLock()
	defer is.mu.RUnlock()
	return is.versions[is.activeVersion]
}

// PublicOf 返回指定版本的公开材料。
func (is *Issuer) PublicOf(version int) (*IssuerPublic, error) {
	is.mu.RLock()
	defer is.mu.RUnlock()
	ip, ok := is.versions[version]
	if !ok {
		return nil, FailDetail(CodePolicyMismatch, "unknown policy version", is.name+"#"+itoa(version))
	}
	return ip, nil
}

// IssueRequest 是一次凭证申领申请。
type IssueRequest struct {
	Pseudonym     string
	PolicyName    string // 必须与当前策略一致
	PolicyVersion int    // 必须等于当前签发版本
	Attributes    map[string]Value
	TTL           time.Duration

	// HolderVerifyKey 为持有者预先生成的一次性出示公钥；由签发方签入凭证。
	HolderVerifyKey ed25519.PublicKey
	// HolderSignKey 在 PrepareIssue 时由持有者生成并暂存，签发成功后入钱包。
	HolderSignKey ed25519.PrivateKey
	// Legacy=true 时按旧格式（CredID 上链）签发；默认签发 v2 不可关联凭证。
	// 旧格式凭证仅在验证方声明的兼容窗口内可验证。
	Legacy bool
}

// Issue 按当前策略版本校验申请并签发凭证；校验失败按错误类型码拒绝。
func (is *Issuer) Issue(req IssueRequest) (*Credential, error) {
	is.mu.RLock()
	pub := is.versions[is.activeVersion]
	priv := is.signKeys[is.activeVersion]
	legacy := req.Legacy || is.legacyDefault
	is.mu.RUnlock()
	if pub == nil {
		return nil, Fail(CodePolicyMismatch, "issuer has no active policy version")
	}
	pol := pub.Policy

	// 策略一致性：名称与版本必须匹配当前签发策略。
	if req.PolicyName != pol.Name {
		is.logIssuance(hex.EncodeToString(nil), CodePolicyMismatch, "policy name mismatch")
		return nil, Fail(CodePolicyMismatch, "request policy name does not match issuer policy")
	}
	if req.PolicyVersion != pol.Version {
		is.logIssuance(hex.EncodeToString(nil), CodePolicyMismatch, "policy version mismatch")
		return nil, FailDetail(CodePolicyMismatch, "request policy version does not match active version",
			"request="+itoa(req.PolicyVersion)+" active="+itoa(pol.Version))
	}

	// 属性约定校验（缺失/越界/枚举等原因可区分）。
	if err := pol.validateApplication(req.Attributes); err != nil {
		is.logIssuance("", CodeOf(err), "application rejected")
		return nil, err
	}

	// 每次签发独立随机 CredID 与每属性一次性盐：签发记录之间不可关联。
	credID, err := is.rng.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	// 路由秘密同样每凭证独立随机：仅用于派生 v2 出示时的一次性路由标签；
	// 旧格式凭证不需要（也不应携带）该秘密。
	var routingSecret []byte
	if !legacy {
		routingSecret, err = is.rng.RandomBytes(32)
		if err != nil {
			return nil, err
		}
	}
	now := is.clock.Now()
	ttl := req.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}

	commits := map[string][]byte{}
	salts := map[string][]byte{}
	for _, spec := range pol.Attributes {
		v, ok := req.Attributes[spec.Name]
		if !ok {
			continue // 可选属性未提供
		}
		salt, err := is.rng.RandomBytes(16)
		if err != nil {
			return nil, err
		}
		salts[spec.Name] = salt
		commits[spec.Name] = commitment(spec.Name, salt, v)
	}

	// 为所有“满足”的策略谓词预签发令牌。
	tokens := map[string]PredicateToken{}
	for _, ps := range pol.Predicates {
		v, ok := req.Attributes[ps.Attr]
		if !ok || !evalPredicate(ps, v) {
			continue
		}
		pl := predPayload(credID, ps.Name, ps.Attr, ps.Op, ps.Threshold, ps.StrValue)
		tokens[ps.Name] = PredicateToken{
			Name:      ps.Name,
			Attr:      ps.Attr,
			Op:        ps.Op,
			Threshold: ps.Threshold,
			StrValue:  ps.StrValue,
			Signature: ed25519.Sign(priv, pl),
		}
	}

	signed := SignedCredential{
		PolicyName:      pol.Name,
		PolicyVersion:   pol.Version,
		CredID:          credID,
		Pseudonym:       req.Pseudonym,
		HolderVerifyKey: append([]byte(nil), req.HolderVerifyKey...),
		SchemaHash:      append([]byte(nil), pub.SchemaHash...),
		Commitments:     commits,
		NotBefore:       now,
		ExpiresAt:       now.Add(ttl),
		PredTokens:      tokens,
	}
	signed.Signature = ed25519.Sign(priv, signed.signPayload())

	cred := &Credential{
		Signed:        signed,
		Salts:         salts,
		AttrValues:    req.Attributes,
		RoutingSecret: append([]byte(nil), routingSecret...),
		Legacy:        legacy,
	}

	// 留存记录：仅含承诺，不含属性明文；同一持有者的不同凭证 CredID 独立随机。
	rec := &IssuanceRecord{
		CredID:          append([]byte(nil), credID...),
		Pseudonym:       req.Pseudonym,
		PolicyName:      pol.Name,
		PolicyVersion:   pol.Version,
		Salts:           saltsCopy(salts),
		RoutingSecret:   append([]byte(nil), routingSecret...),
		PredTokens:      tokens,
		HolderVerifyKey: append([]byte(nil), req.HolderVerifyKey...),
		IssuedAt:        now,
		ExpiresAt:       signed.ExpiresAt,
		Legacy:          legacy,
	}
	recCommit := make(map[string][]byte, len(commits))
	for k, v := range commits {
		recCommit[k] = append([]byte(nil), v...)
	}
	rec.Commitments = recCommit

	is.mu.Lock()
	is.records[hex.EncodeToString(credID)] = rec
	is.mu.Unlock()

	is.logIssuance(hex.EncodeToString(credID), "", "issued")
	return cred, nil
}

// Revoke 吊销指定凭证；未知凭证返回 CodeNoSuchCredential。
func (is *Issuer) Revoke(credID []byte, reason string) error {
	key := hex.EncodeToString(credID)
	is.mu.Lock()
	rec, ok := is.records[key]
	if !ok {
		is.mu.Unlock()
		return FailDetail(CodeNoSuchCredential, "no issuance record for credential", key)
	}
	wasRevoked := rec.Revoked
	rec.Revoked = true
	rec.RevokedAt = is.clock.Now()
	rec.RevokeReason = reason
	if !wasRevoked {
		is.revEpoch++
	}
	is.mu.Unlock()
	if is.audit != nil {
		is.audit.LogRevocation(is.name, key, reason)
	}
	return nil
}

// IsRevoked 查询吊销状态；未知凭证返回 false。
func (is *Issuer) IsRevoked(credID []byte) bool {
	is.mu.RLock()
	defer is.mu.RUnlock()
	rec, ok := is.records[hex.EncodeToString(credID)]
	return ok && rec.Revoked
}

// LookupRecord 核对签发记录（不含属性明文）；未知凭证返回 nil。
func (is *Issuer) LookupRecord(credID []byte) *IssuanceRecord {
	is.mu.RLock()
	defer is.mu.RUnlock()
	rec, ok := is.records[hex.EncodeToString(credID)]
	if !ok {
		return nil
	}
	cp := *rec
	cp.CredID = append([]byte(nil), rec.CredID...)
	cp.RoutingSecret = append([]byte(nil), rec.RoutingSecret...)
	cp.HolderVerifyKey = append([]byte(nil), rec.HolderVerifyKey...)
	cp.Commitments = make(map[string][]byte, len(rec.Commitments))
	for k, v := range rec.Commitments {
		cp.Commitments[k] = append([]byte(nil), v...)
	}
	cp.Salts = make(map[string][]byte, len(rec.Salts))
	for k, v := range rec.Salts {
		cp.Salts[k] = append([]byte(nil), v...)
	}
	cp.PredTokens = copyPredTokens(rec.PredTokens)
	return &cp
}

func copyPredTokens(in map[string]PredicateToken) map[string]PredicateToken {
	if in == nil {
		return nil
	}
	out := make(map[string]PredicateToken, len(in))
	for k, t := range in {
		t.Signature = append([]byte(nil), t.Signature...)
		out[k] = t
	}
	return out
}

// Records 返回全部签发记录的快照（供核对/审计）。
func (is *Issuer) Records() []IssuanceRecord {
	is.mu.RLock()
	defer is.mu.RUnlock()
	out := make([]IssuanceRecord, 0, len(is.records))
	for _, rec := range is.records {
		cp := *rec
		cp.CredID = append([]byte(nil), rec.CredID...)
		cp.RoutingSecret = append([]byte(nil), rec.RoutingSecret...)
		cp.HolderVerifyKey = append([]byte(nil), rec.HolderVerifyKey...)
		cp.Commitments = make(map[string][]byte, len(rec.Commitments))
		for k, v := range rec.Commitments {
			cp.Commitments[k] = append([]byte(nil), v...)
		}
		cp.Salts = make(map[string][]byte, len(rec.Salts))
		for k, v := range rec.Salts {
			cp.Salts[k] = append([]byte(nil), v...)
		}
		cp.PredTokens = copyPredTokens(rec.PredTokens)
		out = append(out, cp)
	}
	return out
}

func (is *Issuer) logIssuance(credIDHex string, rejected Code, detail string) {
	if is.audit != nil {
		is.audit.LogIssuance(is.name, is.activeVersion, credIDHex, rejected, detail)
	}
}

// saltsCopy 深拷贝每属性盐表。
func saltsCopy(in map[string][]byte) map[string][]byte {
	out := make(map[string][]byte, len(in))
	for k, v := range in {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [24]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// RevocationState 是某次撤销状态快照。
type RevocationState struct {
	Revoked bool
	Epoch   uint64
}

// RevocationSnapshot 在同一把读锁下原子返回凭证是否已撤销与当前撤销纪元。
func (is *Issuer) RevocationSnapshot(credID []byte) RevocationState {
	is.mu.RLock()
	defer is.mu.RUnlock()
	rec, ok := is.records[hex.EncodeToString(credID)]
	return RevocationState{Revoked: ok && rec.Revoked, Epoch: is.revEpoch}
}

// RevocationEpoch 返回当前撤销纪元。
func (is *Issuer) RevocationEpoch() uint64 {
	is.mu.RLock()
	defer is.mu.RUnlock()
	return is.revEpoch
}
