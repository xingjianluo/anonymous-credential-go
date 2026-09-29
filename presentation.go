package anoncred

import (
	"sort"
	"time"
)

// PresentedAttribute 是被披露的单个属性：名称、值与承诺盐。
type PresentedAttribute struct {
	Name  string `json:"name"`
	Value Value  `json:"value"`
	Salt  []byte `json:"salt"`
}

// PresentedPredicate 是被出示的谓词令牌（不含属性明文）。
type PresentedPredicate struct {
	Token PredicateToken `json:"token"`
}

// Presentation 是持有者对外出示的证明。
//
// 两种格式：
//   - 旧格式（兼容窗口）：Showing==nil，使用 Signed/Disclosed/Predicates，CredID 上链；
//   - v2 不可关联格式：Showing!=nil，长期标识（CredID/承诺集/凭证级公钥/化名）一律不出现，
//     Attestation 由签发方在验证阶段注入（持有者不直接持有）。
//
// 未被会话允许的属性值/谓词不得出现在任何字段中。
type Presentation struct {
	// 凭证公开部分（含签发方签名与承诺集合）——仅旧格式使用；v2 留空。
	Signed SignedCredential `json:"signed"`

	// 仅包含被允许披露的属性——仅旧格式使用。
	Disclosed []PresentedAttribute `json:"disclosed"`
	// 仅包含被允许出示的谓词——仅旧格式使用。
	Predicates []PresentedPredicate `json:"predicates"`

	// Showing 为 v2 不可关联出示信封；非 nil 时走 v2 验证路径。
	Showing *ShowingEnvelope `json:"showing,omitempty"`

	// 会话绑定：由持有者对 (会话随机数, 披露集合, 谓词集合, 凭证公开部分) 签名——旧格式。
	SessionNonce []byte `json:"session_nonce"`
	HolderProof  []byte `json:"holder_proof"`

	// 证明生成时间（持有者时钟，用于日志/调试；信任以签名与会话为准）
	GeneratedAt time.Time `json:"generated_at"`
}

// isV2 报告该证明是否为 v2 不可关联格式。
func (p *Presentation) isV2() bool { return p != nil && p.Showing != nil }

// holderProofPayload 返回持有者证明签名的规范摘要输入。
//
// 该摘要覆盖：会话随机数（防重放/跨会话）、CredID 与凭证主签名（绑定凭证）、
// 每个披露属性的名称/值/盐（防篡改披露字段）、每个谓词令牌（防替换）。
func (p *Presentation) holderProofPayload() []byte {
	var b []byte
	b = append(b, []byte("anoncred:presentation:v1")...)
	b = writeLengthPrefixed(b, p.SessionNonce)
	b = writeLengthPrefixed(b, p.Signed.CredID)
	b = writeLengthPrefixed(b, p.Signed.Signature)

	disc := make([]PresentedAttribute, len(p.Disclosed))
	copy(disc, p.Disclosed)
	sort.Slice(disc, func(i, j int) bool { return disc[i].Name < disc[j].Name })
	for _, d := range disc {
		b = writeLengthPrefixed(b, []byte(d.Name))
		b = writeLengthPrefixed(b, encodeValue(d.Value))
		b = writeLengthPrefixed(b, d.Salt)
	}

	preds := make([]PresentedPredicate, len(p.Predicates))
	copy(preds, p.Predicates)
	sort.Slice(preds, func(i, j int) bool { return preds[i].Token.Name < preds[j].Token.Name })
	for _, pr := range preds {
		b = writeLengthPrefixed(b, []byte(pr.Token.Name))
		b = writeLengthPrefixed(b, pr.Token.Signature)
	}
	return b
}

// disclosedNames 返回被披露属性名集合（排序后）。
func (p *Presentation) disclosedNames() []string {
	names := make([]string, 0, len(p.Disclosed))
	for _, d := range p.Disclosed {
		names = append(names, d.Name)
	}
	sort.Strings(names)
	return names
}

// predicateNames 返回被出示谓词名集合（排序后）。
func (p *Presentation) predicateNames() []string {
	names := make([]string, 0, len(p.Predicates))
	for _, pr := range p.Predicates {
		names = append(names, pr.Token.Name)
	}
	sort.Strings(names)
	return names
}
