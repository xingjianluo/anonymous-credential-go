package anoncred

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"sort"
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
// 首次登记策略时，签发方对外名称采用策略名（凭证中 PolicyName 与信任标识一致）。
//
// 同版本号重复发布规则：
//   - 参数（策略名、模式指纹、有效期语义）完全一致：幂等返回已登记的公开材料，
//     不重新生成、不覆盖既有签名密钥，保证同一版本永远只有一套密钥；
//   - 版本号相同但参数不一致：返回 CodeVersionConflict，绝不静默覆盖。
func (is *Issuer) AddPolicyVersion(p Policy) (*IssuerPublic, error) {
	sum := p.SchemaHash()
	is.mu.Lock()
	if is.name == "" {
		is.name = p.Name
	}
	if existing, ok := is.versions[p.Version]; ok {
		is.mu.Unlock()
		if existing.Policy.Name == p.Name && bytes.Equal(existing.SchemaHash, sum) {
			return existing, nil // 幂等重复发布：保持既有密钥与参数
		}
		return nil, FailDetail(CodeVersionConflict,
			"policy version is already registered with different parameters; republishing is rejected",
			is.name+"#"+itoa(p.Version))
	}
	is.mu.Unlock()

	pub, priv, err := ed25519.GenerateKey(asReader(is.rng))
	if err != nil {
		return nil, err
	}
	ip := &IssuerPublic{
		Policy:       p,
		VerifyingKey: pub,
		SchemaHash:   sum,
	}
	is.mu.Lock()
	// 双检：锁释放期间可能已有同版本登记（并发发布）。
	if existing, ok := is.versions[p.Version]; ok {
		is.mu.Unlock()
		if existing.Policy.Name == p.Name && bytes.Equal(existing.SchemaHash, sum) {
			return existing, nil
		}
		return nil, FailDetail(CodeVersionConflict,
			"policy version was concurrently registered with different parameters",
			is.name+"#"+itoa(p.Version))
	}
	is.versions[p.Version] = ip
	is.signKeys[p.Version] = priv
	if is.activeVersion == 0 {
		is.activeVersion = p.Version
	}
	is.mu.Unlock()
	return ip, nil
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
}

// Issue 按当前策略版本校验申请并签发凭证；校验失败按错误类型码拒绝。
func (is *Issuer) Issue(req IssueRequest) (*Credential, error) {
	is.mu.RLock()
	pub := is.versions[is.activeVersion]
	priv := is.signKeys[is.activeVersion]
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
		Signed:     signed,
		Salts:      salts,
		AttrValues: req.Attributes,
	}

	// 留存记录：仅含承诺，不含属性明文；同一持有者的不同凭证 CredID 独立随机。
	rec := &IssuanceRecord{
		CredID:          append([]byte(nil), credID...),
		Pseudonym:       req.Pseudonym,
		PolicyName:      pol.Name,
		PolicyVersion:   pol.Version,
		Commitments:     commits, // 与凭证共享同一 map 引用；见落库前复制
		HolderVerifyKey: append([]byte(nil), req.HolderVerifyKey...),
		IssuedAt:        now,
		NotBefore:       now,
		ExpiresAt:       signed.ExpiresAt,
	}
	predNames := make([]string, 0, len(tokens))
	for name := range tokens {
		predNames = append(predNames, name)
	}
	sort.Strings(predNames)
	rec.Predicates = predNames
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
	cp.Commitments = make(map[string][]byte, len(rec.Commitments))
	for k, v := range rec.Commitments {
		cp.Commitments[k] = append([]byte(nil), v...)
	}
	return &cp
}

// Records 返回全部签发记录的快照（供核对/审计）。
func (is *Issuer) Records() []IssuanceRecord {
	is.mu.RLock()
	defer is.mu.RUnlock()
	out := make([]IssuanceRecord, 0, len(is.records))
	for _, rec := range is.records {
		cp := *rec
		cp.CredID = append([]byte(nil), rec.CredID...)
		cp.Commitments = make(map[string][]byte, len(rec.Commitments))
		for k, v := range rec.Commitments {
			cp.Commitments[k] = append([]byte(nil), v...)
		}
		out = append(out, cp)
	}
	return out
}

func (is *Issuer) logIssuance(credIDHex string, rejected Code, detail string) {
	if is.audit != nil {
		is.audit.LogIssuance(is.name, is.activeVersion, credIDHex, rejected, detail)
	}
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

// 每次出示封套/撤销断言的寿命：默认 2 分钟，最长 10 分钟。
// 它远短于凭证有效期，且只服务于“这一次”出示。
const (
	defaultShowTTL = 2 * time.Minute
	maxShowTTL     = 10 * time.Minute
)

// PrepareShow 为“单次出示”签发一个短命、与历史不可关联的封套与撤销断言。
//
// 安全要点：
//   - 必须由凭证绑定的一次性出示密钥对请求签名（ShowAuth），凭证已撤销/过期/
//     未知一律拒绝；
//   - 对每个要求披露的属性，持有者同时给出原盐与新盐；签发方重算原承诺核对
//     后，用新盐重新计算承诺并签入封套——明文值只在该私有申请中出现；
//   - 谓词令牌重新签给当次随机 ShowID，旧令牌绝不复用；
//   - 返回材料不含 CredID、化名、长期出示公钥等任何跨出示稳定标识。
func (is *Issuer) PrepareShow(req ShowRequest) (*ShowPackage, error) {
	if len(req.SessionNonce) == 0 {
		return nil, Fail(CodeMalformedPresentation, "show request requires a session nonce")
	}
	if len(req.ShowVerifyKey) != ed25519.PublicKeySize {
		return nil, Fail(CodeMalformedPresentation, "show verify key has wrong size")
	}
	if len(req.CredID) == 0 {
		return nil, Fail(CodeNoSuchCredential, "show request lacks credential id")
	}
	key := hex.EncodeToString(req.CredID)

	// 在同一把读锁下原子取得记录快照与纪元，避免“已撤销却出具未撤销断言”。
	is.mu.RLock()
	rec, ok := is.records[key]
	if !ok {
		is.mu.RUnlock()
		return nil, FailDetail(CodeNoSuchCredential, "no issuance record for credential", key)
	}
	recCopy := rec.snapshot()
	epoch := is.revEpoch
	pub := is.versions[rec.PolicyVersion]
	priv := is.signKeys[rec.PolicyVersion]
	is.mu.RUnlock()
	if pub == nil {
		return nil, FailDetail(CodeUnknownVersion, "issuer no longer holds the credential policy version",
			rec.PolicyName+"#"+itoa(rec.PolicyVersion))
	}

	if recCopy.Revoked {
		return nil, Fail(CodeRevokedCredential, "cannot show a revoked credential")
	}
	now := is.clock.Now()
	if now.Before(recCopy.NotBefore) || now.After(recCopy.ExpiresAt) {
		return nil, Fail(CodeExpiredCredential, "credential is not within its validity window")
	}
	// 持有者鉴权：只有持有凭证绑定私钥的一方才能申请出示。
	if !ed25519.Verify(ed25519.PublicKey(recCopy.HolderVerifyKey), showAuthPayload(&req), req.ShowAuth) {
		return nil, Fail(CodeBadHolderProof, "show request is not signed by the credential holder key")
	}

	// 披露属性：重算原承诺核对，再以当次新盐生成全新承诺集合。
	newCommits := make(map[string][]byte, len(req.Revealed))
	for name, ra := range req.Revealed {
		oldWant, exists := recCopy.Commitments[name]
		if !exists {
			return nil, FailDetail(CodeDisclosureNotAllowed,
				"requested disclosure attribute is not part of the credential", name)
		}
		if got := commitment(name, ra.OldSalt, ra.Value); !bytes.Equal(got, oldWant) {
			return nil, FailDetail(CodeTamperedDisclosure,
				"revealed value or original salt does not match the issued commitment", name)
		}
		if len(ra.NewSalt) == 0 {
			return nil, Fail(CodeMalformedPresentation, "fresh salt is required for a show envelope")
		}
		newCommits[name] = commitment(name, ra.NewSalt, ra.Value)
	}

	// 谓词：必须是签发时确实满足的集合；参数从受信策略现取，避免漂移。
	satisfied := map[string]bool{}
	for _, n := range recCopy.Predicates {
		satisfied[n] = true
	}
	predSpecs := map[string]PredicateSpec{}
	for _, ps := range pub.Policy.Predicates {
		predSpecs[ps.Name] = ps
	}
	predList := append([]string(nil), req.DisclosePreds...)
	sort.Strings(predList)
	seenPred := map[string]bool{}
	for _, name := range predList {
		if !satisfied[name] {
			return nil, FailDetail(CodePredicateNotAllowed,
				"credential does not hold the requested predicate token", name)
		}
		if seenPred[name] {
			return nil, FailDetail(CodeMalformedPresentation, "duplicate predicate in show request", name)
		}
		seenPred[name] = true
		if _, ok := predSpecs[name]; !ok {
			return nil, FailDetail(CodePredicateNotAllowed, "predicate is not defined by policy", name)
		}
	}

	showID, err := is.rng.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = defaultShowTTL
	}
	if ttl > maxShowTTL {
		ttl = maxShowTTL
	}
	expires := now.Add(ttl)
	// 封套寿命不得超出凭证自身的有效期。
	if expires.After(recCopy.ExpiresAt) {
		expires = recCopy.ExpiresAt
	}

	env := &ShowEnvelope{
		PolicyName:    pub.Policy.Name,
		PolicyVersion: pub.Policy.Version,
		SchemaHash:    append([]byte(nil), pub.SchemaHash...),
		ShowID:        showID,
		SessionNonce:  append([]byte(nil), req.SessionNonce...),
		ShowVerifyKey: append([]byte(nil), req.ShowVerifyKey...),
		Commitments:   newCommits,
		NotBefore:     now,
		ExpiresAt:     expires,
	}
	env.Signature = ed25519.Sign(priv, env.signPayload())

	tokens := make(map[string]ShowToken, len(predList))
	for _, name := range predList {
		ps := predSpecs[name]
		tok := ShowToken{
			Name:      ps.Name,
			Attr:      ps.Attr,
			Op:        ps.Op,
			Threshold: ps.Threshold,
			StrValue:  ps.StrValue,
		}
		tok.Signature = ed25519.Sign(priv,
			showTokenPayload(showID, tok.Name, tok.Attr, tok.Op, tok.Threshold, tok.StrValue))
		tokens[name] = tok
	}

	assertion := &RevocationAssertion{
		IssuerName:    pub.Policy.Name,
		PolicyVersion: pub.Policy.Version,
		SessionNonce:  append([]byte(nil), req.SessionNonce...),
		Epoch:         epoch,
		IssuedAt:      now,
		ExpiresAt:     expires,
	}
	assertion.Signature = ed25519.Sign(priv, assertion.payload())

	return &ShowPackage{Envelope: env, Tokens: tokens, Assertion: assertion}, nil
}

// snapshot 返回签发记录的深拷贝（避免调用方持有锁内引用）。
func (r *IssuanceRecord) snapshot() IssuanceRecord {
	cp := *r
	cp.CredID = append([]byte(nil), r.CredID...)
	cp.HolderVerifyKey = append([]byte(nil), r.HolderVerifyKey...)
	cp.Commitments = make(map[string][]byte, len(r.Commitments))
	for k, v := range r.Commitments {
		cp.Commitments[k] = append([]byte(nil), v...)
	}
	cp.Predicates = append([]string(nil), r.Predicates...)
	return cp
}
