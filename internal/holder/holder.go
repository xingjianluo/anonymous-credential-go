// Package holder 实现持有者钱包与选择性披露证明。
//
// 安全约束：
//   - 仅策略标记 Disclosable 的属性可被披露，未披露属性的值与盐
//     不会出现在 Presentation 的任何字段；
//   - 声明条件（谓词）只能针对已披露属性求值（本方案未实现对隐藏
//     属性的零知识范围证明，未披露属性上的谓词一律拒绝）；
//   - 证明绑定会话挑战；Nullifier 按 (凭证标识, 挑战) 计算，不同
//     会话间不可关联，同会话内可用于重放检测；
//   - BlindedRevID 按挑战盲化，供签发方在线应答撤销状态。
package holder

import (
	"sort"

	"github.com/xingjianluo/anonymous-credential-go/internal/canonical"
	"github.com/xingjianluo/anonymous-credential-go/internal/commitment"
	"github.com/xingjianluo/anonymous-credential-go/internal/credential"
	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
	"github.com/xingjianluo/anonymous-credential-go/internal/policy"
	"github.com/xingjianluo/anonymous-credential-go/internal/registry"
)

// Wallet 保存持有者的凭证包。
type Wallet struct {
	holderID string
	bundles  []*credential.Bundle
}

// NewWallet 创建钱包。
func NewWallet(holderID string) *Wallet {
	return &Wallet{holderID: holderID}
}

// HolderID 返回持有者标识（仅本地使用，不进入证明）。
func (w *Wallet) HolderID() string { return w.holderID }

// Add 存入凭证包。
func (w *Wallet) Add(b *credential.Bundle) { w.bundles = append(w.bundles, b) }

// Predicate 是声明条件。支持的 Op：
//
//	"eq"  字符串/整数等值
//	"gte" 整数下界（含相等）
type Predicate struct {
	Attr  string
	Op    string
	Value any
}

// PresentationRequest 描述一次证明会话的披露与声明要求。
type PresentationRequest struct {
	SessionID     string
	Challenge     []byte
	PolicyVersion uint32
	Disclose      []string
	Predicates    []Predicate
}

// RevealValue 是证明中单个被披露属性的值与开放路径。
type RevealValue struct {
	Value    any
	Salt     []byte
	Position int
	Siblings [][32]byte
}

// Presentation 是对外出示的选择性披露证明。
type Presentation struct {
	SessionID     string
	Challenge     []byte
	PolicyVersion uint32
	TotalSlots    int
	CommitRoot    [32]byte
	SchemaHash    [32]byte
	CredSignature []byte
	IssuedAtUnix  int64
	Reveals       map[string]RevealValue
	Predicates    []Predicate
	DiscloseOrder []string
	IDCommitment  [32]byte
	BlindedRevID  [32]byte
	Nullifier     [32]byte
}

// SelectBundle 按策略版本从钱包选择一个凭证。
func (w *Wallet) SelectBundle(policyVersion uint32) (*credential.Bundle, error) {
	for _, b := range w.bundles {
		if b.PolicyVersion == policyVersion {
			return b, nil
		}
	}
	return nil, cerr.New(cerr.KindUnknownCredential, "wallet holds no credential for policy version %d", policyVersion)
}

// Present 按请求生成证明。
func (w *Wallet) Present(polreg *policy.Registry, req *PresentationRequest) (*Presentation, error) {
	if req == nil {
		return nil, cerr.New(cerr.KindMalformed, "nil presentation request")
	}
	if len(req.Challenge) == 0 {
		return nil, cerr.New(cerr.KindMalformed, "presentation requires a non-empty session challenge")
	}
	// 先确认策略版本已知（未知版本必须显式失败，而非落到钱包错误）。
	pol, err := polreg.Get(req.PolicyVersion)
	if err != nil {
		return nil, err
	}
	b, err := w.SelectBundle(req.PolicyVersion)
	if err != nil {
		return nil, err
	}

	// 1. 去重并排序披露集合，保证证明编码确定，也防止同属性双槽。
	disclose := dedupSorted(req.Disclose)
	for _, name := range disclose {
		spec, ok := pol.Attrs[name]
		if !ok {
			return nil, cerr.New(cerr.KindUnauthorizedDisclosure, "attribute %q is not defined by policy v%d", name, pol.Version)
		}
		if !spec.Disclosable {
			return nil, cerr.New(cerr.KindUnauthorizedDisclosure, "attribute %q is not permitted for disclosure", name)
		}
	}

	// 2. 用凭证包里的盐重建 Merkle 树，生成开放路径。
	sattrs := make([]commitment.SaltedAttr, 0, len(b.SpecNames))
	for _, n := range b.SpecNames {
		if v, ok := b.Attrs[n]; ok {
			sattrs = append(sattrs, commitment.SaltedAttr{Name: n, Value: v, Salt: b.Salts[n]})
		} else {
			sattrs = append(sattrs, commitment.SaltedAttr{Name: n, Missing: true})
		}
	}
	tree, err := commitment.Build(b.SpecNames, sattrs)
	if err != nil {
		return nil, err
	}
	if root := tree.Root(); root != b.Credential.Body.CommitRoot {
		return nil, cerr.New(cerr.KindProofTampered, "rebuilt commitment root does not match credential")
	}

	reveals := make(map[string]RevealValue, len(disclose))
	for _, name := range disclose {
		if tree.IsMissing(name) {
			return nil, cerr.New(cerr.KindProofInvalid, "cannot disclose missing optional attribute %q", name)
		}
		rv, err := tree.Open(name)
		if err != nil {
			return nil, err
		}
		reveals[name] = RevealValue{
			Value:    rv.Value,
			Salt:     rv.Salt,
			Position: rv.Position,
			Siblings: rv.Siblings,
		}
	}

	// 3. 谓词只能针对已披露属性求值并须成立。
	preds := make([]Predicate, 0, len(req.Predicates))
	for _, p := range req.Predicates {
		if _, disclosed := reveals[p.Attr]; !disclosed {
			return nil, cerr.New(cerr.KindUnauthorizedDisclosure, "predicate on undisclosed attribute %q is not supported", p.Attr)
		}
		got, ok := b.Attrs[p.Attr]
		if !ok {
			return nil, cerr.New(cerr.KindProofInvalid, "predicate attribute %q has no value", p.Attr)
		}
		if err := evalPredicate(got, p); err != nil {
			return nil, err
		}
		preds = append(preds, p)
	}

	// 4. 计算会话绑定的撤销盲标签与 nullifier。
	blinded := registry.BlindedTag(b.ID, req.Challenge)
	nullifier := Nullifier(b.ID, req.Challenge)

	p := &Presentation{
		SessionID:     req.SessionID,
		Challenge:     append([]byte(nil), req.Challenge...),
		PolicyVersion: req.PolicyVersion,
		TotalSlots:    len(b.SpecNames),
		CommitRoot:    b.Credential.Body.CommitRoot,
		SchemaHash:    b.Credential.Body.SchemaHash,
		CredSignature: append([]byte(nil), b.Credential.Signature...),
		IssuedAtUnix:  b.Credential.Body.IssuedAt.Unix(),
		Reveals:       reveals,
		Predicates:    preds,
		DiscloseOrder: disclose,
		IDCommitment:  b.IDCommitment,
		BlindedRevID:  blinded,
		Nullifier:     nullifier,
	}
	return p, nil
}

// Nullifier 计算按会话挑战变化的一次性 nullifier。
func Nullifier(credID, challenge []byte) [32]byte {
	return canonical.Hash("presentation-nullifier-v1",
		canonical.EncodeBytes(credID), canonical.EncodeBytes(challenge))
}

func evalPredicate(got any, p Predicate) error {
	switch p.Op {
	case "eq":
		if !valueEqual(got, p.Value) {
			return cerr.New(cerr.KindProofInvalid, "predicate eq(%q) failed: %v != %v", p.Attr, got, p.Value)
		}
		return nil
	case "gte":
		gn, ok1 := asInt64(got)
		wn, ok2 := asInt64(p.Value)
		if !ok1 || !ok2 {
			return cerr.New(cerr.KindMalformed, "predicate gte(%q) requires integer operands", p.Attr)
		}
		if gn < wn {
			return cerr.New(cerr.KindProofInvalid, "predicate gte(%q) failed: %d < %d", p.Attr, gn, wn)
		}
		return nil
	default:
		return cerr.New(cerr.KindMalformed, "unsupported predicate op %q", p.Op)
	}
}

func valueEqual(a, b any) bool {
	an, aok := asInt64(a)
	bn, bok := asInt64(b)
	if aok && bok {
		return an == bn
	}
	as, aok := a.(string)
	bs, bok := b.(string)
	if aok && bok {
		return as == bs
	}
	return false
}

func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	default:
		return 0, false
	}
}

func dedupSorted(xs []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
