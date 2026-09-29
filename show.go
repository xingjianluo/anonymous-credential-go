package anoncred

import (
	"sort"
	"time"
)

// 本文件实现“每次出示不可关联”（v2）所需的数据结构与规范签名载荷。
//
// 与旧版（legacy，见 presentation.go 中直接携带 SignedCredential 的方式）不同，
// v2 的对外证明中不出现任何跨出示稳定的材料：无长期 CredID、无持有者化名、
// 无固定一次性出示公钥、无固定承诺。签发方为“每次出示”重新签发一个短命的
// ShowEnvelope，并把谓词令牌重新绑定到当次随机 ShowID；撤销状态以绑定会话
// 随机数的撤销断言呈现，验证方全程拿不到长期标识。

// ShowEnvelope 是签发方对“单次出示”的短命签名封套。
//
// 其中所有字段（ShowID、ShowVerifyKey、承诺集合、时间窗）均为每次出示独立
// 生成，不出现在任何其他出示中；签发方私钥签名本身也是非确定性的，
// 因此两个验证方无法凭封套字节把出示串到同一凭证或同一持有者。
type ShowEnvelope struct {
	PolicyName    string            `json:"policy_name"`
	PolicyVersion int               `json:"policy_version"`
	SchemaHash    []byte            `json:"schema_hash"`
	ShowID        []byte            `json:"show_id"`         // 当次出示随机标识
	SessionNonce  []byte            `json:"session_nonce"`   // 绑定一次性会话
	ShowVerifyKey []byte            `json:"show_verify_key"` // 当次出示一次性公钥
	Commitments   map[string][]byte `json:"commitments"`     // 仅含本次披露属性的新鲜盐化承诺
	NotBefore     time.Time         `json:"not_before"`
	ExpiresAt     time.Time         `json:"expires_at"`
	Signature     []byte            `json:"signature"`
}

// signPayload 返回出示封套的规范摘要输入（版本化前缀，独立于旧凭证签名）。
func (e *ShowEnvelope) signPayload() []byte {
	var b []byte
	b = append(b, []byte("anoncred:show:v2")...)
	b = writeLengthPrefixed(b, []byte(e.PolicyName))
	b = appendInt64(b, int64(e.PolicyVersion))
	b = writeLengthPrefixed(b, e.SchemaHash)
	b = writeLengthPrefixed(b, e.ShowID)
	b = writeLengthPrefixed(b, e.SessionNonce)
	b = writeLengthPrefixed(b, e.ShowVerifyKey)
	b = appendTime(b, e.NotBefore)
	b = appendTime(b, e.ExpiresAt)
	for _, name := range sortedKeys(e.Commitments) {
		b = writeLengthPrefixed(b, []byte(name))
		b = writeLengthPrefixed(b, e.Commitments[name])
	}
	return b
}

// ShowToken 是绑定到当次 ShowID 的谓词令牌；旧凭证里绑定 CredID 的令牌
// 绝不能进入 v2 证明（否则 CredID 会成为跨出示线索）。
type ShowToken struct {
	Name      string      `json:"name"`
	Attr      string      `json:"attr"`
	Op        PredicateOp `json:"op"`
	Threshold int64       `json:"threshold,omitempty"`
	StrValue  string      `json:"str_value,omitempty"`
	Signature []byte      `json:"signature"`
}

// PresentedShowToken 包装一次被出示的当次谓词令牌。
type PresentedShowToken struct {
	Token ShowToken `json:"token"`
}

// showTokenPayload 返回当次谓词令牌签名的规范摘要输入。
func showTokenPayload(showID []byte, name, attr string, op PredicateOp, threshold int64, strValue string) []byte {
	var b []byte
	b = append(b, []byte("anoncred:showtoken:v1")...)
	b = writeLengthPrefixed(b, showID)
	b = writeLengthPrefixed(b, []byte(name))
	b = writeLengthPrefixed(b, []byte(attr))
	b = writeLengthPrefixed(b, []byte(string(op)))
	b = appendInt64(b, threshold)
	b = writeLengthPrefixed(b, []byte(strValue))
	return b
}

// RevocationAssertion 是签发方为某次会话出具的“当时未撤销”断言。
//
// 断言不含 CredID 或任何长期标识，只绑定：签发方/版本（定位校验公钥）、
// 会话随机数（一次性）、出具时刻的撤销纪元（供验证方与公开纪元比对）。
// 验证方无需也无法拿长期标识去查询撤销，因此撤销检查本身不可追踪。
type RevocationAssertion struct {
	IssuerName    string    `json:"issuer_name"`
	PolicyVersion int       `json:"policy_version"`
	SessionNonce  []byte    `json:"session_nonce"`
	Epoch         uint64    `json:"epoch"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	Signature     []byte    `json:"signature"`
}

// payload 返回撤销断言签名的规范摘要输入。
func (a *RevocationAssertion) payload() []byte {
	var b []byte
	b = append(b, []byte("anoncred:revassert:v1")...)
	b = writeLengthPrefixed(b, []byte(a.IssuerName))
	b = appendInt64(b, int64(a.PolicyVersion))
	b = writeLengthPrefixed(b, a.SessionNonce)
	b = appendInt64(b, int64(a.Epoch))
	b = appendTime(b, a.IssuedAt)
	b = appendTime(b, a.ExpiresAt)
	return b
}

// RevealedAttr 是持有者为签发方“核对后重签”而私下出示的单个披露属性：
// 明文值 + 原承诺盐（使签发方能重算原承诺核对）+ 本次出示的新盐。
// 这些材料只在持有者->签发方的私有通道上出现，绝不进入对外证明。
type RevealedAttr struct {
	Value   Value
	OldSalt []byte
	NewSalt []byte
}

// ShowRequest 是持有者向签发方申请一次性出示封套的请求。
type ShowRequest struct {
	CredID        []byte
	SessionNonce  []byte
	ShowVerifyKey []byte // 当次出示一次性公钥
	Revealed      map[string]RevealedAttr
	DisclosePreds []string
	TTL           time.Duration

	// ShowAuth 为凭证绑定的一次性出示私钥对本请求的签名，
	// 证明“凭证持有者本人在申请本次出示”；签名载荷见 showAuthPayload。
	ShowAuth []byte
}

// showAuthPayload 返回出示申请鉴权签名的规范摘要输入。
func showAuthPayload(r *ShowRequest) []byte {
	var b []byte
	b = append(b, []byte("anoncred:showreq:v1")...)
	b = writeLengthPrefixed(b, r.CredID)
	b = writeLengthPrefixed(b, r.SessionNonce)
	b = writeLengthPrefixed(b, r.ShowVerifyKey)
	for _, name := range sortedKeys(r.Revealed) {
		ra := r.Revealed[name]
		b = writeLengthPrefixed(b, []byte(name))
		b = writeLengthPrefixed(b, encodeValue(ra.Value))
		b = writeLengthPrefixed(b, ra.OldSalt)
		b = writeLengthPrefixed(b, ra.NewSalt)
	}
	preds := append([]string(nil), r.DisclosePreds...)
	sort.Strings(preds)
	for _, name := range preds {
		b = writeLengthPrefixed(b, []byte(name))
	}
	return b
}

// ShowPackage 是签发方返回的一次性出示材料（不含任何长期标识）。
type ShowPackage struct {
	Envelope  *ShowEnvelope
	Tokens    map[string]ShowToken
	Assertion *RevocationAssertion
}

// holderProofPayloadV2 返回 v2 持有者证明的规范摘要输入。
//
// 覆盖：会话随机数、当次 ShowID、封套签名、每个披露项、每个当次谓词令牌。
// 不包含、也不需要包含任何长期凭证字段。
func (p *Presentation) holderProofPayloadV2() []byte {
	var b []byte
	b = append(b, []byte("anoncred:presentation:v2")...)
	b = writeLengthPrefixed(b, p.SessionNonce)
	b = writeLengthPrefixed(b, p.Envelope.ShowID)
	b = writeLengthPrefixed(b, p.Envelope.Signature)

	disc := make([]PresentedAttribute, len(p.Disclosed))
	copy(disc, p.Disclosed)
	sort.Slice(disc, func(i, j int) bool { return disc[i].Name < disc[j].Name })
	for _, d := range disc {
		b = writeLengthPrefixed(b, []byte(d.Name))
		b = writeLengthPrefixed(b, encodeValue(d.Value))
		b = writeLengthPrefixed(b, d.Salt)
	}

	toks := make([]PresentedShowToken, len(p.ShowTokens))
	copy(toks, p.ShowTokens)
	sort.Slice(toks, func(i, j int) bool { return toks[i].Token.Name < toks[j].Token.Name })
	for _, pt := range toks {
		b = writeLengthPrefixed(b, []byte(pt.Token.Name))
		b = writeLengthPrefixed(b, pt.Token.Signature)
	}
	return b
}
