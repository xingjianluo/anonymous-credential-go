package anoncred

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"sort"
	"sync"
)

// StoredCredential 是持有者钱包中的凭证条目。
type StoredCredential struct {
	Cred        Credential
	IssuerPub   *IssuerPublic
	HolderSignK ed25519.PrivateKey // 与 Signed.HolderVerifyKey 对应的私钥
}

// Holder 是本地模拟的凭证持有者（钱包）。
type Holder struct {
	mu sync.Mutex

	rng   RNG
	clock Clock

	pseudonym string
	stored    map[string]*StoredCredential // credID hex -> 凭证
}

// NewHolder 创建持有者钱包。
func NewHolder(pseudonym string, rng RNG) *Holder {
	if rng == nil {
		rng = SecureRNG{}
	}
	return &Holder{
		rng:       rng,
		clock:     SystemClock{},
		pseudonym: pseudonym,
		stored:    map[string]*StoredCredential{},
	}
}

// WithClock 注入时钟（证明生成时间）。
func (h *Holder) WithClock(c Clock) *Holder {
	h.clock = c
	return h
}

// Pseudonym 返回持有者化名。
func (h *Holder) Pseudonym() string { return h.pseudonym }

// PrepareIssue 生成一次性出示密钥对，并返回可直接交给签发方的申请。
// 属性、TTL 由调用方填入；PolicyName/Version 在调用方从签发方公开材料取得。
func (h *Holder) PrepareIssue(attributes map[string]Value, ttlReq *IssueRequest) (*IssueRequest, error) {
	pub, priv, err := ed25519.GenerateKey(asReader(h.rng))
	if err != nil {
		return nil, err
	}
	if ttlReq == nil {
		ttlReq = &IssueRequest{}
	}
	ttlReq.Pseudonym = h.pseudonym
	ttlReq.HolderVerifyKey = pub
	ttlReq.HolderSignKey = priv
	if ttlReq.Attributes == nil {
		ttlReq.Attributes = attributes
	}
	return ttlReq, nil
}

// Accept 接收并保存签发方返回的凭证；校验出示公钥与钱包密钥匹配。
func (h *Holder) Accept(c *Credential, pub *IssuerPublic, signKey ed25519.PrivateKey) error {
	if c == nil {
		return Fail(CodeMalformedPresentation, "nil credential")
	}
	if signKey == nil || !publicKeyEqual(signKey.Public().(ed25519.PublicKey), c.Signed.HolderVerifyKey) {
		return Fail(CodeBadHolderProof, "credential holder key does not match wallet key")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.stored[hex.EncodeToString(c.Signed.CredID)] = &StoredCredential{
		Cred:        *c,
		IssuerPub:   pub,
		HolderSignK: signKey,
	}
	return nil
}

// CredentialIDs 返回钱包中凭证 ID 的十六进制列表。
func (h *Holder) CredentialIDs() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ids := make([]string, 0, len(h.stored))
	for k := range h.stored {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	return ids
}

// PresentRequest 描述一次出示请求。
type PresentRequest struct {
	CredIDHex     string
	SessionNonce  []byte
	DiscloseAttrs []string // 仅这些属性允许以明文值出现
	DisclosePreds []string // 仅这些谓词允许被证明
}

// BuildPresentation 依据会话授权范围构造选择性披露证明。
//
// 持有者侧同样强制最小披露：未被 DiscloseAttrs/DisclosePreds 列出的属性/谓词
// 绝不会进入返回结构。
func (h *Holder) BuildPresentation(req PresentRequest) (*Presentation, error) {
	if len(req.SessionNonce) == 0 {
		return nil, Fail(CodeMalformedPresentation, "session nonce is required")
	}
	h.mu.Lock()
	st, ok := h.stored[req.CredIDHex]
	h.mu.Unlock()
	if !ok {
		return nil, FailDetail(CodeNoSuchCredential, "holder has no such credential", req.CredIDHex)
	}

	allowAttrs := map[string]bool{}
	for _, a := range req.DiscloseAttrs {
		allowAttrs[a] = true
	}
	allowPreds := map[string]bool{}
	for _, p := range req.DisclosePreds {
		allowPreds[p] = true
	}

	// 仅披露存在于凭证中且被明确授权的属性。
	disclosed := []PresentedAttribute{}
	attrNames := make([]string, 0, len(allowAttrs))
	for a := range allowAttrs {
		attrNames = append(attrNames, a)
	}
	sort.Strings(attrNames)
	for _, name := range attrNames {
		v, vok := st.Cred.AttrValues[name]
		salt, sok := st.Cred.Salts[name]
		if !vok || !sok {
			return nil, FailDetail(CodeDisclosureNotAllowed,
				"requested disclosure attribute is not present in credential", name)
		}
		disclosed = append(disclosed, PresentedAttribute{Name: name, Value: v, Salt: append([]byte(nil), salt...)})
	}

	// 仅出示存在于凭证令牌集中且被明确授权的谓词。
	preds := []PresentedPredicate{}
	predNames := make([]string, 0, len(allowPreds))
	for p := range allowPreds {
		predNames = append(predNames, p)
	}
	sort.Strings(predNames)
	for _, name := range predNames {
		tok, ok := st.Cred.Signed.PredTokens[name]
		if !ok {
			return nil, FailDetail(CodePredicateNotAllowed,
				"requested predicate token is not available in credential", name)
		}
		preds = append(preds, PresentedPredicate{Token: tok})
	}

	pres := &Presentation{
		Signed:       st.Cred.Signed,
		Disclosed:    disclosed,
		Predicates:   preds,
		SessionNonce: append([]byte(nil), req.SessionNonce...),
		GeneratedAt:  h.clock.Now(),
	}
	// 安全关键：对外证明中的凭证公开部分不得携带完整谓词令牌集合，
	// 否则会泄露持有者满足了哪些未被会话允许披露的谓词。
	pres.Signed.PredTokens = nil
	pres.Signed.Signature = append([]byte(nil), st.Cred.Signed.Signature...)
	pres.Signed.Commitments = st.Cred.Signed.Commitments
	pres.HolderProof = ed25519.Sign(st.HolderSignK, pres.holderProofPayload())
	return pres, nil
}

func publicKeyEqual(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// lookup 返回钱包中的凭证条目（内部使用）。
func (h *Holder) lookup(credIDHex string) *StoredCredential {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stored[credIDHex]
}

// ShowPrep 是持有者为一次 v2 出示准备的私有上下文。
//
// 它暂存当次一次性出示密钥对（ShowSignK）与每个披露属性的原盐/新盐/值；
// Request 可直接交给签发方 PrepareShow。ShowSignK 只留在持有者手中。
type ShowPrep struct {
	Request   ShowRequest
	ShowSignK ed25519.PrivateKey
	// 组装最终证明用：披露项（值+新盐），顺序按名称固定。
	disclosed []PresentedAttribute
}

// PrepareUnlinkableShow 为指定凭证的一次会话生成 v2 出示申请。
//
// 与 BuildPresentation 不同，这里不使用签入凭证的长期出示公钥，而是为
// “这一次出示”重新生成密钥；所有披露属性也各自取一把全新随机盐。
func (h *Holder) PrepareUnlinkableShow(credIDHex string, sessionNonce []byte,
	discloseAttrs, disclosePreds []string) (*ShowPrep, error) {
	if len(sessionNonce) == 0 {
		return nil, Fail(CodeMalformedPresentation, "session nonce is required")
	}
	h.mu.Lock()
	st, ok := h.stored[credIDHex]
	h.mu.Unlock()
	if !ok {
		return nil, FailDetail(CodeNoSuchCredential, "holder has no such credential", credIDHex)
	}

	showPub, showPriv, err := ed25519.GenerateKey(asReader(h.rng))
	if err != nil {
		return nil, err
	}

	allowAttrs := map[string]bool{}
	for _, a := range discloseAttrs {
		allowAttrs[a] = true
	}
	attrNames := make([]string, 0, len(allowAttrs))
	for a := range allowAttrs {
		attrNames = append(attrNames, a)
	}
	sort.Strings(attrNames)

	revealed := make(map[string]RevealedAttr, len(attrNames))
	disclosed := make([]PresentedAttribute, 0, len(attrNames))
	for _, name := range attrNames {
		v, vok := st.Cred.AttrValues[name]
		oldSalt, sok := st.Cred.Salts[name]
		if !vok || !sok {
			return nil, FailDetail(CodeDisclosureNotAllowed,
				"requested disclosure attribute is not present in credential", name)
		}
		newSalt, err := h.rng.RandomBytes(16)
		if err != nil {
			return nil, err
		}
		revealed[name] = RevealedAttr{
			Value:   v,
			OldSalt: append([]byte(nil), oldSalt...),
			NewSalt: append([]byte(nil), newSalt...),
		}
		disclosed = append(disclosed, PresentedAttribute{
			Name:  name,
			Value: v,
			Salt:  append([]byte(nil), newSalt...),
		})
	}

	allowPreds := map[string]bool{}
	predNames := make([]string, 0, len(disclosePreds))
	for _, p := range disclosePreds {
		if !allowPreds[p] {
			allowPreds[p] = true
			predNames = append(predNames, p)
		}
	}
	sort.Strings(predNames)
	for _, name := range predNames {
		if _, ok := st.Cred.Signed.PredTokens[name]; !ok {
			return nil, FailDetail(CodePredicateNotAllowed,
				"requested predicate token is not available in credential", name)
		}
	}

	credID := append([]byte(nil), st.Cred.Signed.CredID...)
	req := ShowRequest{
		CredID:        credID,
		SessionNonce:  append([]byte(nil), sessionNonce...),
		ShowVerifyKey: showPub,
		Revealed:      revealed,
		DisclosePreds: predNames,
	}
	// 用“凭证绑定的一次性出示私钥”给申请签名，签发方据此鉴权。
	req.ShowAuth = ed25519.Sign(st.HolderSignK, showAuthPayload(&req))

	return &ShowPrep{Request: req, ShowSignK: showPriv, disclosed: disclosed}, nil
}

// BuildUnlinkablePresentation 用签发方返回的一次性材料组装 v2 对外证明，
// 并用当次出示私钥签名。返回结构中不含任何长期凭证字段。
func (h *Holder) BuildUnlinkablePresentation(prep *ShowPrep, pkg *ShowPackage) (*Presentation, error) {
	if prep == nil || pkg == nil || pkg.Envelope == nil || pkg.Assertion == nil {
		return nil, Fail(CodeMalformedPresentation, "show preparation or package is incomplete")
	}
	env := pkg.Envelope
	if !bytes.Equal(env.SessionNonce, prep.Request.SessionNonce) ||
		!publicKeyEqual(prep.ShowSignK.Public().(ed25519.PublicKey), env.ShowVerifyKey) {
		return nil, Fail(CodeBadShowEnvelope, "show envelope is not bound to this preparation")
	}
	if len(env.Commitments) != len(prep.disclosed) {
		return nil, Fail(CodeBadShowEnvelope, "show envelope commitment set differs from disclosed set")
	}
	for _, d := range prep.disclosed {
		if _, ok := env.Commitments[d.Name]; !ok {
			return nil, FailDetail(CodeBadShowEnvelope, "show envelope is missing a disclosed commitment", d.Name)
		}
	}

	tokens := make([]PresentedShowToken, 0, len(prep.Request.DisclosePreds))
	for _, name := range prep.Request.DisclosePreds {
		tok, ok := pkg.Tokens[name]
		if !ok {
			return nil, FailDetail(CodeBadShowEnvelope, "show package missing requested predicate token", name)
		}
		tokens = append(tokens, PresentedShowToken{Token: tok})
	}

	pres := &Presentation{
		Envelope:     env,
		Disclosed:    prep.disclosed,
		ShowTokens:   tokens,
		SessionNonce: append([]byte(nil), prep.Request.SessionNonce...),
		Assertion:    pkg.Assertion,
		GeneratedAt:  h.clock.Now(),
	}
	// 显式保证：长期凭证公开部分与旧令牌集合绝不进入 v2 证明。
	pres.Signed = SignedCredential{}
	pres.Predicates = nil
	pres.HolderProof = ed25519.Sign(prep.ShowSignK, pres.holderProofPayloadV2())
	return pres, nil
}
