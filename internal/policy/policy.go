// Package policy 定义属性模式、签发策略与版本注册表。
//
// 版本语义（README 同步说明）：
//   - Active：允许新签发、允许验证；
//   - Deprecated：拒绝新签发，但按该版本历史签发的凭证仍可验证
//     （受验证方 MinAcceptedVersion 下界约束）；
//   - 注册表中不存在的版本对验证方属于未知版本，一律拒绝；
//   - 凭证体绑定 SchemaHash，策略参数（属性集合/范围）变更会改变
//     SchemaHash，旧凭证与新策略参数不兼容时拒绝而非静默接受。
package policy

import (
	"sort"
	"unicode/utf8"

	"github.com/xingjianluo/anonymous-credential-go/internal/canonical"
	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
)

// AttrType 属性值类型。
type AttrType int

const (
	AttrInt AttrType = iota
	AttrEnum
	AttrString
)

// AttrSpec 描述单个属性的取值约束。
type AttrSpec struct {
	// Name 属性名，同时是 Merkle 槽位标识。
	Name string
	// Type 值类型。
	Type AttrType
	// Required 为 true 时签发申请必须包含该属性。
	Required bool
	// Disclosable 为 false 时该属性永远不能进入对外证明。
	Disclosable bool
	// Min/Max 仅对 AttrInt 生效，闭区间。
	Min int64
	Max int64
	// EnumValues 仅对 AttrEnum 生效，取值必须在此集合内。
	EnumValues []string
	// MaxLength 仅对 AttrString 生效，按 Unicode 码点数计长；0 表示不限。
	MaxLength int
}

// Status 策略状态。
type Status int

const (
	StatusActive Status = iota
	StatusDeprecated
)

// ConsistencyRule 表达跨属性一致性约束，返回 TypedError 说明违规原因。
type ConsistencyRule func(attrs map[string]any) error

// PremiumAgeRule 是内置一致性规则示例：level=premium 时 age>=18。
func PremiumAgeRule(attrs map[string]any) error {
	lv, lok := attrs["level"].(string)
	if !lok || lv != "premium" {
		return nil
	}
	age, aok := attrs["age"]
	if !aok {
		return nil // age 缺失由必填校验负责
	}
	n, ok := asInt64(age)
	if !ok {
		return nil
	}
	if n < 18 {
		return cerr.New(cerr.KindPolicyViolation, "consistency rule: premium level requires age >= 18, got %d", n)
	}
	return nil
}

// Policy 是带版本号的签发/校验策略。
type Policy struct {
	Name    string
	Version uint32
	Status  Status
	Attrs   map[string]*AttrSpec
	Rules   []ConsistencyRule
}

// AttrNames 返回按字典序排列的属性名（即 Merkle 固定槽位顺序）。
func (p *Policy) AttrNames() []string {
	names := make([]string, 0, len(p.Attrs))
	for n := range p.Attrs {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// SchemaHash 是策略参数（属性集合与取值约束）的承诺摘要。
// 凭证体携带该值，校验时与注册表中同版本策略的当前值比对，
// 参数被改导致不一致即按 IncompatibleVersion 拒绝。
func (p *Policy) SchemaHash() [32]byte {
	names := p.AttrNames()
	parts := make([][]byte, 0, 1+len(names)*8)
	parts = append(parts, canonical.EncodeString(p.Name), canonical.EncodeInt64(int64(p.Version)))
	for _, n := range names {
		a := p.Attrs[n]
		parts = append(parts,
			canonical.EncodeString(a.Name),
			canonical.EncodeInt64(int64(a.Type)),
			canonical.EncodeInt64(boolByte(a.Required)),
			canonical.EncodeInt64(boolByte(a.Disclosable)),
			canonical.EncodeInt64(a.Min),
			canonical.EncodeInt64(a.Max),
			canonical.EncodeInt64(int64(a.MaxLength)),
		)
		ev := make([][]byte, 0, len(a.EnumValues))
		for _, e := range a.EnumValues {
			ev = append(ev, canonical.EncodeString(e))
		}
		parts = append(parts, canonical.Concat(ev...))
	}
	return canonical.Hash("policy-schema-v1", parts...)
}

func boolByte(b bool) int64 {
	if b {
		return 1
	}
	return 0
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

// EncodeValue 按策略类型规范化编码属性值，供承诺与校验复用。
func EncodeValue(t AttrType, v any) ([]byte, error) {
	switch t {
	case AttrInt:
		n, ok := asInt64(v)
		if !ok {
			return nil, cerr.New(cerr.KindMalformed, "integer attribute has non-integer value %T", v)
		}
		return canonical.EncodeInt64(n), nil
	case AttrEnum:
		s, ok := v.(string)
		if !ok {
			return nil, cerr.New(cerr.KindMalformed, "enum attribute has non-string value %T", v)
		}
		return canonical.EncodeString(s), nil
	case AttrString:
		s, ok := v.(string)
		if !ok {
			return nil, cerr.New(cerr.KindMalformed, "string attribute has non-string value %T", v)
		}
		return canonical.EncodeString(s), nil
	default:
		return nil, cerr.New(cerr.KindMalformed, "unknown attribute type %d", t)
	}
}

// checkValue 校验单个值的类型与取值范围。
func checkValue(a *AttrSpec, v any) error {
	switch a.Type {
	case AttrInt:
		n, ok := asInt64(v)
		if !ok {
			return cerr.New(cerr.KindValueOutOfRange, "attribute %q expects integer, got %T", a.Name, v)
		}
		if n < a.Min || n > a.Max {
			return cerr.New(cerr.KindValueOutOfRange, "attribute %q=%d out of range [%d,%d]", a.Name, n, a.Min, a.Max)
		}
	case AttrEnum:
		s, ok := v.(string)
		if !ok {
			return cerr.New(cerr.KindValueOutOfRange, "attribute %q expects enum string, got %T", a.Name, v)
		}
		if !contains(a.EnumValues, s) {
			return cerr.New(cerr.KindValueOutOfRange, "attribute %q=%q not in allowed enum set %v", a.Name, s, a.EnumValues)
		}
	case AttrString:
		s, ok := v.(string)
		if !ok {
			return cerr.New(cerr.KindValueOutOfRange, "attribute %q expects string, got %T", a.Name, v)
		}
		if a.MaxLength > 0 && int64(utf8.RuneCountInString(s)) > int64(a.MaxLength) {
			return cerr.New(cerr.KindValueOutOfRange, "attribute %q length %d exceeds max %d", a.Name, utf8.RuneCountInString(s), a.MaxLength)
		}
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// IssuanceRequest 是一次凭证申领。
type IssuanceRequest struct {
	// HolderID 仅用于申请鉴权上下文，签发记录不留存该标识。
	HolderID string
	PolicyV  uint32
	Attrs    map[string]any
}

// Registry 管理策略版本的注册与查询。
type Registry struct {
	policies map[uint32]*Policy
}

// NewRegistry 创建空策略注册表。
func NewRegistry() *Registry {
	return &Registry{policies: map[uint32]*Policy{}}
}

// Register 注册一个策略版本；版本重复或定义非法时返回错误。
func (r *Registry) Register(p *Policy) error {
	if p == nil {
		return cerr.New(cerr.KindMalformed, "nil policy")
	}
	if _, exists := r.policies[p.Version]; exists {
		return cerr.New(cerr.KindPolicyViolation, "policy version %d already registered", p.Version)
	}
	if len(p.Attrs) == 0 {
		return cerr.New(cerr.KindMalformed, "policy v%d has no attributes", p.Version)
	}
	for name, a := range p.Attrs {
		if a.Name != name {
			return cerr.New(cerr.KindMalformed, "policy v%d attr map key %q != spec name %q", p.Version, name, a.Name)
		}
		if a.Type == AttrEnum && len(a.EnumValues) == 0 {
			return cerr.New(cerr.KindMalformed, "enum attr %q requires EnumValues", name)
		}
	}
	cp := *p
	cp.Attrs = make(map[string]*AttrSpec, len(p.Attrs))
	for k, v := range p.Attrs {
		a := *v
		cp.Attrs[k] = &a
	}
	r.policies[p.Version] = &cp
	return nil
}

// Get 按版本获取策略副本。
func (r *Registry) Get(version uint32) (*Policy, error) {
	p, ok := r.policies[version]
	if !ok {
		return nil, cerr.New(cerr.KindUnknownPolicyVersion, "policy version %d is not registered", version)
	}
	return p, nil
}

// Latest 返回最高版本号策略。
func (r *Registry) Latest() (*Policy, error) {
	if len(r.policies) == 0 {
		return nil, cerr.New(cerr.KindUnknownPolicyVersion, "no policy registered")
	}
	var best uint32
	first := true
	for v := range r.policies {
		if first || v > best {
			best, first = v, false
		}
	}
	return r.policies[best], nil
}

// ValidateIssuance 校验申请：未知/废止版本、缺失属性、越界取值、
// 多余属性与跨属性一致性规则。失败返回带可区分 Kind 的错误。
func (r *Registry) ValidateIssuance(req *IssuanceRequest) (*Policy, error) {
	if req == nil {
		return nil, cerr.New(cerr.KindMalformed, "nil issuance request")
	}
	p, err := r.Get(req.PolicyV)
	if err != nil {
		return nil, err
	}
	if p.Status == StatusDeprecated {
		return nil, cerr.New(cerr.KindIncompatibleVersion, "policy v%d is deprecated and cannot be used for new issuance", p.Version)
	}
	for name, a := range p.Attrs {
		v, present := req.Attrs[name]
		if !present {
			if a.Required {
				return nil, cerr.New(cerr.KindMissingAttribute, "required attribute %q is missing", name)
			}
			continue
		}
		if err := checkValue(a, v); err != nil {
			return nil, err
		}
	}
	for name := range req.Attrs {
		if _, ok := p.Attrs[name]; !ok {
			return nil, cerr.New(cerr.KindPolicyViolation, "attribute %q is not defined by policy v%d", name, p.Version)
		}
	}
	for _, rule := range p.Rules {
		if err := rule(req.Attrs); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Deprecate 将已注册版本标记为废止（参数不变，仅状态变化）。
// 用于策略生命周期演进：废止后拒绝新签发，历史凭证仍可被验证。
func (r *Registry) Deprecate(version uint32) error {
	p, ok := r.policies[version]
	if !ok {
		return cerr.New(cerr.KindUnknownPolicyVersion, "cannot deprecate: policy version %d is not registered", version)
	}
	p.Status = StatusDeprecated
	return nil
}
