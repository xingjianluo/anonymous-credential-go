package anoncred

import (
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

	// 旧格式凭证：沿用 legacy 出示路径（仅兼容窗口内可验证）。
	if st.Cred.Legacy {
		return h.buildLegacyPresentation(st, req, allowAttrs, allowPreds)
	}
	return h.buildV2Showing(st, req, allowAttrs, allowPreds)
}

// buildV2Showing 构造“多次出示不可关联”的 v2 证明。
//
// 每次出示重新生成：ShowID、RouteTag、一次性 Ed25519 出示密钥对。
// 信封中不出现 CredID、化名、凭证级持有公钥、属性承诺集合、静态盐。
func (h *Holder) buildV2Showing(st *StoredCredential, req PresentRequest,
	allowAttrs, allowPreds map[string]bool) (*Presentation, error) {

	showID, err := h.rng.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	showPub, showPriv, err := ed25519.GenerateKey(asReader(h.rng))
	if err != nil {
		return nil, err
	}

	sc := st.Cred.Signed
	now := h.clock.Now()
	env := &ShowingEnvelope{
		FormatVersion: ShowingFormatV2,
		PolicyName:    sc.PolicyName,
		PolicyVersion: sc.PolicyVersion,
		ShowID:        showID,
		HolderShowKey: showPub,
		SessionNonce:  append([]byte(nil), req.SessionNonce...),
		NotBefore:     now,
		ExpiresAt:     sc.ExpiresAt,
		GeneratedAt:   now,
	}
	env.RouteTag = routeTag(st.Cred.RoutingSecret, env.ShowID, env.SessionNonce,
		sc.PolicyName, sc.PolicyVersion)

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
		env.Disclosed = append(env.Disclosed, ShownAttribute{
			Name:   name,
			Value:  v,
			ValTag: valTag(salt, env.ShowID, env.SessionNonce, name, v),
		})
	}

	predNames := make([]string, 0, len(allowPreds))
	for p := range allowPreds {
		predNames = append(predNames, p)
	}
	sort.Strings(predNames)
	for _, name := range predNames {
		if _, ok := st.Cred.Signed.PredTokens[name]; !ok {
			return nil, FailDetail(CodePredicateNotAllowed,
				"requested predicate token is not available in credential", name)
		}
		env.Predicates = append(env.Predicates, name)
	}

	// 凭证级持有密钥授权“本次一次性出示公钥+披露范围”。
	env.HolderAuth = ed25519.Sign(st.HolderSignK, env.holderAuthPayload())
	// 一次性出示密钥对信封签名：背书只能与本信封一起使用。
	env.HolderProof = ed25519.Sign(showPriv, showProofPayload(env))

	return &Presentation{
		Showing:      env,
		SessionNonce: append([]byte(nil), req.SessionNonce...),
		GeneratedAt:  now,
	}, nil
}

// buildLegacyPresentation 保留旧格式的选择性披露证明构造。
func (h *Holder) buildLegacyPresentation(st *StoredCredential, req PresentRequest,
	allowAttrs, allowPreds map[string]bool) (*Presentation, error) {
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
