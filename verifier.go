package anoncred

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"sync"
	"time"
)

// RevocationSource 是验证方查询签发方撤销状态的抽象。
//
// Issuer 直接实现该接口。纪元（epoch）在每次新的吊销动作后单调递增，
// 验证方在校验窗口前后各取一次快照：窗口内发生过并发撤销则拒绝接受，
// 从而保证“校验-撤销”结论可线性化、不出现陈旧接受。
type RevocationSource interface {
	IsRevoked(credID []byte) bool
	RevocationSnapshot(credID []byte) RevocationState
	RevocationEpoch() uint64
}

// TrustProfile 是验证方对某签发方某策略版本的信任配置。
type TrustProfile struct {
	IssuerName string
	Public     IssuerPublic
	// Rejected=true 表示该历史版本按明确规则被拒绝（版本日落）。
	Rejected bool
	// LegacyAcceptUntil 为旧版（可关联的 legacy 出示方式）的兼容窗口终点：
	// 零值表示继续接受旧方式；非零时刻之后提交的 legacy 证明一律以
	// CodeLegacyRejected 明确拒绝。v2 不可关联证明不受此窗口影响。
	LegacyAcceptUntil time.Time
}

// TrustRegistry 登记受信签发方版本；未知版本一律拒绝。
type TrustRegistry struct {
	mu       sync.RWMutex
	profiles map[string]*TrustProfile
}

// NewTrustRegistry 创建空信任库。
func NewTrustRegistry() *TrustRegistry {
	return &TrustRegistry{profiles: map[string]*TrustProfile{}}
}

func trustKey(issuer string, version int) string {
	return issuer + "#" + itoa(version)
}

// Register 登记一个受信版本。
//
// 重复登记规则：版本公钥与模式指纹完全一致时幂等（不覆盖、不改变既有状态）；
// 同版本号但参数/公钥不一致时返回 CodeVersionConflict，绝不被后一次发布
// 悄悄覆盖。确需更换档案只能由管理员显式调用 Replace。
func (r *TrustRegistry) Register(tp TrustProfile) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := trustKey(tp.IssuerName, tp.Public.Policy.Version)
	if existing, ok := r.profiles[key]; ok {
		if bytes.Equal(existing.Public.VerifyingKey, tp.Public.VerifyingKey) &&
			bytes.Equal(existing.Public.SchemaHash, tp.Public.SchemaHash) &&
			existing.Public.Policy.Name == tp.Public.Policy.Name {
			return nil // 幂等重复发布
		}
		return FailDetail(CodeVersionConflict,
			"version is already trusted with different parameters; use Replace to rotate deliberately", key)
	}
	cp := tp
	r.profiles[key] = &cp
	return nil
}

// Replace 是管理员显式替换某版本信任档案的入口（例如轮换签发方公钥）。
// 未知版本返回 CodeUnknownVersion；新档案必须与版本号一致。
func (r *TrustRegistry) Replace(tp TrustProfile) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := trustKey(tp.IssuerName, tp.Public.Policy.Version)
	if _, ok := r.profiles[key]; !ok {
		return FailDetail(CodeUnknownVersion, "cannot replace a version that was never registered", key)
	}
	cp := tp
	r.profiles[key] = &cp
	return nil
}

// SetLegacyWindow 为某版本设置旧版出示方式的兼容窗口终点。
func (r *TrustRegistry) SetLegacyWindow(issuer string, version int, acceptUntil time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tp, ok := r.profiles[trustKey(issuer, version)]
	if !ok {
		return FailDetail(CodeUnknownVersion, "trust registry has no such version", trustKey(issuer, version))
	}
	tp.LegacyAcceptUntil = acceptUntil.UTC()
	return nil
}

// RejectVersion 将一个已登记版本标记为显式拒绝（历史版本日落规则）。
func (r *TrustRegistry) RejectVersion(issuer string, version int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	tp, ok := r.profiles[trustKey(issuer, version)]
	if !ok {
		return FailDetail(CodeUnknownVersion, "trust registry has no such version", trustKey(issuer, version))
	}
	tp.Rejected = true
	return nil
}

// Lookup 查询信任配置；未知版本返回 nil。
func (r *TrustRegistry) Lookup(issuer string, version int) *TrustProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tp, ok := r.profiles[trustKey(issuer, version)]
	if !ok {
		return nil
	}
	cp := *tp
	return &cp
}

// VerifyPolicy 定义一次验证的策略要求。
type VerifyPolicy struct {
	AllowAttrs      []string // 本会话允许披露的属性
	AllowPredicates []string // 本会话允许证明的谓词
	TTL             time.Duration
}

// Session 是验证方的一次性验证会话。
type Session struct {
	ID        string
	Nonce     []byte
	Issuer    string
	Version   int
	Policy    VerifyPolicy
	CreatedAt time.Time
	ExpiresAt time.Time
	consumed  bool
}

// Verifier 是本地模拟的验证方。
type Verifier struct {
	mu       sync.Mutex
	rng      RNG
	clock    Clock
	trust    *TrustRegistry
	revoke   RevocationSource
	audit    *AuditLogger
	sessions map[string]*Session
}

// NewVerifier 创建验证方。
func NewVerifier(clock Clock, rng RNG, trust *TrustRegistry) *Verifier {
	if rng == nil {
		rng = SecureRNG{}
	}
	if clock == nil {
		clock = SystemClock{}
	}
	if trust == nil {
		trust = NewTrustRegistry()
	}
	return &Verifier{
		rng:      rng,
		clock:    clock,
		trust:    trust,
		sessions: map[string]*Session{},
	}
}

// WithRevocationSource 注入撤销状态来源（通常为签发方）。
func (v *Verifier) WithRevocationSource(rs RevocationSource) *Verifier {
	v.revoke = rs
	return v
}

// WithAudit 注入审计日志。
func (v *Verifier) WithAudit(a *AuditLogger) *Verifier {
	v.audit = a
	return v
}

// NewSession 为受信版本创建一次性会话。
func (v *Verifier) NewSession(issuer string, version int, pol VerifyPolicy) (*Session, error) {
	tp := v.trust.Lookup(issuer, version)
	if tp == nil {
		return nil, FailDetail(CodeUnknownVersion, "cannot open session for untrusted version",
			trustKey(issuer, version))
	}
	if tp.Rejected {
		return nil, FailDetail(CodeVersionRejected, "policy version has been explicitly rejected",
			trustKey(issuer, version))
	}
	nonce, err := v.rng.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	idB, err := v.rng.RandomBytes(16)
	if err != nil {
		return nil, err
	}
	ttl := pol.TTL
	if ttl <= 0 {
		ttl = defaultTTL
	}
	now := v.clock.Now()
	s := &Session{
		ID:        hex.EncodeToString(idB),
		Nonce:     nonce,
		Issuer:    issuer,
		Version:   version,
		Policy:    pol,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	v.mu.Lock()
	v.sessions[s.ID] = s
	v.mu.Unlock()
	return s, nil
}

// Session 返回会话的拷贝（不判定有效期）。
func (v *Verifier) Session(id string) *Session {
	v.mu.Lock()
	defer v.mu.Unlock()
	s, ok := v.sessions[id]
	if !ok {
		return nil
	}
	cp := *s
	cp.Nonce = append([]byte(nil), s.Nonce...)
	return &cp
}

// Decision 是验证结论。
type Decision struct {
	Accepted      bool
	Reason        Code   // 拒绝时的类型码；接受时为空
	Mode          string // "v2"（不可关联出示）或 "legacy"（旧版出示）
	SessionID     string
	Issuer        string
	PolicyVersion int
	// CredID 仅在 legacy 模式出现（已知可关联限制）；v2 模式恒为空。
	CredID string
	// ShowID 为 v2 模式下当次出示的随机标识，跨出示不复现；仅用于本次日志。
	ShowID         string
	DisclosedAttrs []string
	Predicates     []string
	CheckedAt      time.Time
}

// Verify 校验一次出示证明。
//
// 会话是一次性的：第一个完成判定的证明会消费会话，任何重复使用或跨会话
// 重放都以 CodeProofReplay 拒绝。
func (v *Verifier) Verify(sessionID string, pres *Presentation) (dec *Decision, err error) {
	now := v.clock.Now()

	// 先消费会话（原子），保证并发重放不会产生两个“接受”结论。
	v.mu.Lock()
	sess, ok := v.sessions[sessionID]
	if !ok {
		v.mu.Unlock()
		e := FailDetail(CodeSessionUnknown, "verifier has no such session", sessionID)
		v.auditReject(sessionID, "", 0, nil, nil, CodeSessionUnknown)
		return nil, e
	}
	if sess.consumed {
		v.mu.Unlock()
		e := FailDetail(CodeProofReplay, "session nonce has already been consumed", sessionID)
		v.auditReject(sessionID, sess.Issuer, sess.Version, nil, nil, CodeProofReplay)
		return nil, e
	}
	sess.consumed = true
	v.mu.Unlock()
	// 会话已消费，不会被重置；后续所有拒绝均为重放安全的终态结论。

	if now.After(sess.ExpiresAt) {
		return nil, FailDetail(CodeSessionExpired, "session expired", sessionID)
	}
	if pres == nil {
		return nil, Fail(CodeMalformedPresentation, "nil presentation")
	}

	// 校验窗口起点的撤销纪元（v2 与 legacy 共用；v2 不做任何按长期标识的查询）。
	var epochBefore uint64
	if v.revoke != nil {
		epochBefore = v.revoke.RevocationEpoch()
	}

	// v2：不可关联的每次出示。Envelope 是判别字段。
	if pres.Envelope != nil {
		return v.verifyV2(sess, pres, now, epochBefore)
	}

	d := &Decision{
		Mode:           "legacy",
		SessionID:      sessionID,
		Issuer:         sess.Issuer,
		PolicyVersion:  sess.Version,
		CredID:         hex.EncodeToString(pres.Signed.CredID),
		DisclosedAttrs: pres.disclosedNames(),
		Predicates:     pres.predicateNames(),
		CheckedAt:      now,
	}
	fail := func(c Code, msg, detail string) (*Decision, error) {
		d.Reason = c
		v.logDecision(d, msg)
		return d, FailDetail(c, msg, detail)
	}

	sc := pres.Signed

	// 1) 版本/签发方一致性与信任。
	if sc.PolicyName != sess.Issuer {
		return fail(CodePolicyMismatch, "presentation issuer differs from session issuer",
			"got="+sc.PolicyName+" want="+sess.Issuer)
	}
	tp := v.trust.Lookup(sess.Issuer, sc.PolicyVersion)
	if tp == nil {
		return fail(CodeUnknownVersion, "credential version is not registered in trust store",
			trustKey(sess.Issuer, sc.PolicyVersion))
	}
	if tp.Rejected {
		return fail(CodeVersionRejected, "credential version has been explicitly rejected",
			trustKey(sess.Issuer, sc.PolicyVersion))
	}
	// 旧版可关联出示方式的兼容窗口：窗口结束后明确拒绝，而不是继续放任可关联性。
	if !tp.LegacyAcceptUntil.IsZero() && now.After(tp.LegacyAcceptUntil) {
		return fail(CodeLegacyRejected,
			"legacy linkable presentation is past its declared compatibility window",
			trustKey(sess.Issuer, sc.PolicyVersion))
	}
	if sc.PolicyVersion != sess.Version {
		return fail(CodeIncompatibleParameters,
			"credential version does not match the session version",
			"cred="+itoa(sc.PolicyVersion)+" session="+itoa(sess.Version))
	}
	// 模式指纹：信任档案自身必须自洽；凭证携带的签发时指纹必须与
	// 受信参数完全一致，同版本号但参数/模式漂移一律拒绝，绝不静默接受。
	if !bytes.Equal(tp.Public.SchemaHash, tp.Public.Policy.SchemaHash()) {
		return fail(CodeIncompatibleParameters, "trust registry schema hash is internally inconsistent", "")
	}
	if !bytes.Equal(sc.SchemaHash, tp.Public.SchemaHash) {
		return fail(CodeIncompatibleParameters,
			"credential schema hash does not match the trusted parameters for this version", "")
	}

	// 2) 凭证结构完整性：不得携带隐藏的谓词令牌集合（防未披露信息泄露）。
	if len(sc.PredTokens) != 0 {
		return fail(CodeUndisclosedLeak,
			"presentation carries the full predicate token set, which would leak undisclosed predicates", "")
	}
	if len(sc.CredID) == 0 || len(sc.Signature) == 0 || len(sc.HolderVerifyKey) != ed25519.PublicKeySize {
		return fail(CodeMalformedPresentation, "signed credential is missing required fields", "")
	}
	if !bytes.Equal(pres.SessionNonce, sess.Nonce) {
		return fail(CodeProofReplay, "presentation nonce does not match the single-use session nonce", "")
	}

	// 3) 有效期。
	if now.Before(sc.NotBefore) || now.After(sc.ExpiresAt) {
		return fail(CodeExpiredCredential, "credential is not currently valid (time window)", "")
	}

	// 4) 签发方主签名（伪造凭证 / 篡改承诺在此失败）。
	payload := sc.signPayload()
	if !ed25519.Verify(tp.Public.VerifyingKey, payload, sc.Signature) {
		return fail(CodeBadIssuerSignature, "credential issuer signature verification failed", "")
	}

	// 5) 披露字段必须在会话授权范围内（越权披露）。
	allowAttr := map[string]bool{}
	for _, a := range sess.Policy.AllowAttrs {
		allowAttr[a] = true
	}
	allowPred := map[string]bool{}
	for _, p := range sess.Policy.AllowPredicates {
		allowPred[p] = true
	}
	discSet := map[string]bool{}
	for _, da := range pres.Disclosed {
		if da.Name == "" || len(da.Salt) == 0 {
			return fail(CodeMalformedPresentation, "disclosed attribute missing name or salt", da.Name)
		}
		if !allowAttr[da.Name] {
			return fail(CodeDisclosureNotAllowed, "disclosed attribute is not allowed by session", da.Name)
		}
		if discSet[da.Name] {
			return fail(CodeMalformedPresentation, "duplicate disclosed attribute", da.Name)
		}
		discSet[da.Name] = true
	}
	predSet := map[string]bool{}
	for _, pp := range pres.Predicates {
		if pp.Token.Name == "" || len(pp.Token.Signature) == 0 {
			return fail(CodeMalformedPresentation, "predicate token missing name or signature", pp.Token.Name)
		}
		if !allowPred[pp.Token.Name] {
			return fail(CodePredicateNotAllowed, "presented predicate is not allowed by session", pp.Token.Name)
		}
		if predSet[pp.Token.Name] {
			return fail(CodeMalformedPresentation, "duplicate predicate", pp.Token.Name)
		}
		predSet[pp.Token.Name] = true
	}

	// 6) 披露字段必须与已签名承诺一致：重算承诺，任何篡改都失败。
	for _, da := range pres.Disclosed {
		want, ok := sc.Commitments[da.Name]
		if !ok {
			return fail(CodeTamperedDisclosure, "disclosed attribute has no signed commitment", da.Name)
		}
		got := commitment(da.Name, da.Salt, da.Value)
		if !bytes.Equal(got, want) {
			return fail(CodeTamperedDisclosure, "disclosed value or salt does not match signed commitment", da.Name)
		}
		// 额外按当前策略复查取值约定，防止披露值语义异常。
		if spec, ok := tp.Public.Policy.attrSpec(da.Name); ok {
			if err := validateOne(spec, da.Value); err != nil {
				return fail(CodeInvalidAttributeValue, "disclosed value violates policy constraints", da.Name)
			}
		}
	}

	// 7) 谓词令牌：必须由同一签发方签名、绑定本凭证、且与策略定义一致。
	for _, pp := range pres.Predicates {
		tok := pp.Token
		spec, ok := tp.Public.Policy.predSpec(tok.Name)
		if !ok {
			return fail(CodePredicateNotAllowed, "predicate is not defined by trusted policy", tok.Name)
		}
		if spec.Attr != tok.Attr || spec.Op != tok.Op ||
			spec.Threshold != tok.Threshold || spec.StrValue != tok.StrValue {
			return fail(CodeIncompatibleParameters, "predicate token parameters differ from policy", tok.Name)
		}
		pl := predPayload(sc.CredID, tok.Name, tok.Attr, tok.Op, tok.Threshold, tok.StrValue)
		if !ed25519.Verify(tp.Public.VerifyingKey, pl, tok.Signature) {
			return fail(CodeBadIssuerSignature, "predicate token issuer signature verification failed", tok.Name)
		}
	}

	// 8) 持有者证明：用签入凭证的一次性出示公钥校验，覆盖 nonce 与全部披露内容。
	if !ed25519.Verify(ed25519.PublicKey(sc.HolderVerifyKey),
		pres.holderProofPayload(), pres.HolderProof) {
		return fail(CodeBadHolderProof, "holder proof signature verification failed", "")
	}

	// 9) 撤销：取原子快照；并比对校验窗口内纪元是否推进。
	if v.revoke != nil {
		snap := v.revoke.RevocationSnapshot(sc.CredID)
		if snap.Revoked {
			return fail(CodeRevokedCredential, "credential has been revoked", "")
		}
		if snap.Epoch != epochBefore {
			// 窗口内发生了（针对任意凭证的）并发吊销动作。
			return fail(CodeRevokedCredential,
				"revocation registry changed during verification; refusing stale acceptance", "")
		}
	}

	d.Accepted = true
	d.Reason = ""
	v.logDecision(d, "accepted")
	return d, nil
}

// verifyV2 校验“每次出示不可关联”的 v2 证明。
//
// 与 legacy 路径的本质区别：全程不接触长期 CredID/化名/固定出示公钥/固定承诺，
// 撤销状态只通过绑定会话的撤销断言 + 无标识纪元比对确认。
func (v *Verifier) verifyV2(sess *Session, pres *Presentation, now time.Time, epochBefore uint64) (*Decision, error) {
	env := pres.Envelope

	// 结构混用防线：v2 证明不得携带任何 legacy 稳定字段。
	if len(pres.Signed.Signature) != 0 || len(pres.Signed.CredID) != 0 ||
		len(pres.Signed.HolderVerifyKey) != 0 || len(pres.Predicates) != 0 {
		d := v.newV2Decision(sess, pres, now)
		return v.failV2(d, CodeBadShowEnvelope, "v2 presentation must not carry legacy credential fields", "")
	}
	if pres.Assertion == nil {
		d := v.newV2Decision(sess, pres, now)
		return v.failV2(d, CodeMalformedPresentation, "v2 presentation is missing the revocation assertion", "")
	}

	d := v.newV2Decision(sess, pres, now)
	fail := func(c Code, msg, detail string) (*Decision, error) {
		return v.failV2(d, c, msg, detail)
	}

	// 1) 版本/签发方一致性与信任（同 legacy：未知/日落/参数漂移均明确拒绝）。
	if env.PolicyName != sess.Issuer {
		return fail(CodePolicyMismatch, "presentation issuer differs from session issuer",
			"got="+env.PolicyName+" want="+sess.Issuer)
	}
	tp := v.trust.Lookup(sess.Issuer, env.PolicyVersion)
	if tp == nil {
		return fail(CodeUnknownVersion, "show envelope version is not registered in trust store",
			trustKey(sess.Issuer, env.PolicyVersion))
	}
	if tp.Rejected {
		return fail(CodeVersionRejected, "policy version has been explicitly rejected",
			trustKey(sess.Issuer, env.PolicyVersion))
	}
	if env.PolicyVersion != sess.Version {
		return fail(CodeIncompatibleParameters,
			"show envelope version does not match the session version",
			"env="+itoa(env.PolicyVersion)+" session="+itoa(sess.Version))
	}
	if !bytes.Equal(tp.Public.SchemaHash, tp.Public.Policy.SchemaHash()) {
		return fail(CodeIncompatibleParameters, "trust registry schema hash is internally inconsistent", "")
	}
	if !bytes.Equal(env.SchemaHash, tp.Public.SchemaHash) {
		return fail(CodeIncompatibleParameters,
			"show envelope schema hash does not match the trusted parameters for this version", "")
	}

	// 2) 结构完整性与当次绑定。
	if len(env.ShowID) == 0 || len(env.Signature) == 0 ||
		len(env.ShowVerifyKey) != ed25519.PublicKeySize {
		return fail(CodeMalformedPresentation, "show envelope is missing required fields", "")
	}
	if !bytes.Equal(env.SessionNonce, sess.Nonce) {
		return fail(CodeProofReplay, "show envelope is not bound to the single-use session nonce", "")
	}
	if !bytes.Equal(pres.SessionNonce, sess.Nonce) {
		return fail(CodeProofReplay, "presentation nonce does not match the single-use session nonce", "")
	}

	// 3) 出示封套自身时效。
	if now.Before(env.NotBefore) || now.After(env.ExpiresAt) {
		return fail(CodeExpiredCredential, "show envelope is not currently valid (time window)", "")
	}

	// 4) 签发方对当次封套的签名。
	if !ed25519.Verify(tp.Public.VerifyingKey, env.signPayload(), env.Signature) {
		return fail(CodeBadShowEnvelope, "show envelope issuer signature verification failed", "")
	}

	// 5) 披露授权与承诺一致性。
	allowAttr := map[string]bool{}
	for _, a := range sess.Policy.AllowAttrs {
		allowAttr[a] = true
	}
	allowPred := map[string]bool{}
	for _, p := range sess.Policy.AllowPredicates {
		allowPred[p] = true
	}
	discSet := map[string]bool{}
	for _, da := range pres.Disclosed {
		if da.Name == "" || len(da.Salt) == 0 {
			return fail(CodeMalformedPresentation, "disclosed attribute missing name or salt", da.Name)
		}
		if !allowAttr[da.Name] {
			return fail(CodeDisclosureNotAllowed, "disclosed attribute is not allowed by session", da.Name)
		}
		if discSet[da.Name] {
			return fail(CodeMalformedPresentation, "duplicate disclosed attribute", da.Name)
		}
		discSet[da.Name] = true
		want, ok := env.Commitments[da.Name]
		if !ok {
			return fail(CodeTamperedDisclosure, "disclosed attribute has no show commitment", da.Name)
		}
		if got := commitment(da.Name, da.Salt, da.Value); !bytes.Equal(got, want) {
			return fail(CodeTamperedDisclosure, "disclosed value or salt does not match show commitment", da.Name)
		}
		if spec, ok := tp.Public.Policy.attrSpec(da.Name); ok {
			if err := validateOne(spec, da.Value); err != nil {
				return fail(CodeInvalidAttributeValue, "disclosed value violates policy constraints", da.Name)
			}
		}
	}
	// 封套里只能出现本次实际披露属性的承诺：任何多余承诺都会泄露未披露属性“存在性”。
	if len(env.Commitments) != len(pres.Disclosed) {
		return fail(CodeUndisclosedLeak,
			"show envelope carries commitments for undisclosed attributes", "")
	}

	// 6) 当次谓词令牌：由签发方签给当次 ShowID，且与策略定义一致。
	predSet := map[string]bool{}
	for _, pt := range pres.ShowTokens {
		tok := pt.Token
		if tok.Name == "" || len(tok.Signature) == 0 {
			return fail(CodeMalformedPresentation, "show token missing name or signature", tok.Name)
		}
		if !allowPred[tok.Name] {
			return fail(CodePredicateNotAllowed, "show predicate is not allowed by session", tok.Name)
		}
		if predSet[tok.Name] {
			return fail(CodeMalformedPresentation, "duplicate show predicate", tok.Name)
		}
		predSet[tok.Name] = true
		spec, ok := tp.Public.Policy.predSpec(tok.Name)
		if !ok {
			return fail(CodePredicateNotAllowed, "predicate is not defined by trusted policy", tok.Name)
		}
		if spec.Attr != tok.Attr || spec.Op != tok.Op ||
			spec.Threshold != tok.Threshold || spec.StrValue != tok.StrValue {
			return fail(CodeIncompatibleParameters, "show token parameters differ from policy", tok.Name)
		}
		if !ed25519.Verify(tp.Public.VerifyingKey,
			showTokenPayload(env.ShowID, tok.Name, tok.Attr, tok.Op, tok.Threshold, tok.StrValue),
			tok.Signature) {
			return fail(CodeBadShowEnvelope, "show token issuer signature verification failed", tok.Name)
		}
	}

	// 7) 撤销断言：绑定本会话、同一签发方/版本、在其寿命内、签名有效。
	asrt := pres.Assertion
	if asrt.IssuerName != sess.Issuer || asrt.PolicyVersion != sess.Version {
		return fail(CodeRevokedCredential, "revocation assertion does not match session issuer/version", "")
	}
	if !bytes.Equal(asrt.SessionNonce, sess.Nonce) {
		return fail(CodeProofReplay, "revocation assertion is not bound to this session", "")
	}
	if now.After(asrt.ExpiresAt) {
		return fail(CodeRevokedCredential, "revocation assertion is stale (past its validity window)", "")
	}
	if !ed25519.Verify(tp.Public.VerifyingKey, asrt.payload(), asrt.Signature) {
		return fail(CodeRevokedCredential, "revocation assertion signature verification failed", "")
	}

	// 8) 持有者当次证明：用封套里的当次公钥校验。
	if !ed25519.Verify(ed25519.PublicKey(env.ShowVerifyKey),
		pres.holderProofPayloadV2(), pres.HolderProof) {
		return fail(CodeBadHolderProof, "holder proof signature verification failed", "")
	}

	// 9) 撤销纪元窗口：只比对无标识的全局纪元，确认断言出具后没有发生吊销。
	//     全程没有也不需要长期 CredID，因此撤销检查无法把多次出示串起来。
	if v.revoke != nil {
		epochAfter := v.revoke.RevocationEpoch()
		if asrt.Epoch != epochBefore || epochAfter != epochBefore {
			return fail(CodeRevokedCredential,
				"revocation registry changed around this presentation; refusing stale acceptance", "")
		}
	}

	d.Accepted = true
	d.Reason = ""
	v.logDecision(d, "accepted")
	return d, nil
}

// newV2Decision 构造 v2 决策骨架；CredID 恒为空，只保留当次 ShowID。
func (v *Verifier) newV2Decision(sess *Session, pres *Presentation, now time.Time) *Decision {
	showID := ""
	if pres.Envelope != nil {
		showID = hex.EncodeToString(pres.Envelope.ShowID)
	}
	return &Decision{
		Mode:           "v2",
		SessionID:      sess.ID,
		Issuer:         sess.Issuer,
		PolicyVersion:  sess.Version,
		ShowID:         showID,
		DisclosedAttrs: pres.disclosedNames(),
		Predicates:     pres.predicateNames(),
		CheckedAt:      now,
	}
}

// failV2 记录并返回一个 v2 拒绝结论。
func (v *Verifier) failV2(d *Decision, c Code, msg, detail string) (*Decision, error) {
	d.Reason = c
	v.logDecision(d, msg)
	return d, FailDetail(c, msg, detail)
}
func (v *Verifier) auditReject(sessionID, issuer string, version int, attrs, preds []string, code Code) {
	if v.audit == nil {
		return
	}
	v.audit.LogDecision(&Decision{
		Accepted:       false,
		Reason:         code,
		SessionID:      sessionID,
		Issuer:         issuer,
		PolicyVersion:  version,
		DisclosedAttrs: emptyIfNil(attrs),
		Predicates:     emptyIfNil(preds),
		CheckedAt:      v.clock.Now(),
	})
}

func emptyIfNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (v *Verifier) logDecision(d *Decision, msg string) {
	if v.audit != nil {
		v.audit.LogDecision(d)
	}
}

// validateOne 按单个属性规格校验一个披露值。
func validateOne(spec AttributeSpec, v Value) error {
	switch spec.Type {
	case AttrString:
		if v.IsInt {
			return Fail(CodeInvalidAttributeValue, "type mismatch")
		}
		if spec.NonEmpty && v.Str == "" {
			return Fail(CodeInvalidAttributeValue, "empty value")
		}
		if len(spec.Allowed) > 0 {
			for _, a := range spec.Allowed {
				if a == v.Str {
					return nil
				}
			}
			return Fail(CodeInvalidAttributeValue, "enum mismatch")
		}
	case AttrInt:
		if !v.IsInt {
			return Fail(CodeInvalidAttributeValue, "type mismatch")
		}
		if v.Int < spec.Min || v.Int > spec.Max {
			return Fail(CodeAttributeOutOfRange, "out of range")
		}
	}
	return nil
}

// randomNonce 生成 32 字节随机会话随机数（供内部/测试复用）。
func (v *Verifier) randomNonce() ([]byte, error) {
	return v.rng.RandomBytes(32)
}
