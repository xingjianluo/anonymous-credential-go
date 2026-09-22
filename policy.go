package anoncred

import (
	"crypto/sha256"
	"encoding/json"
	"sort"
	"strconv"
	"time"
)

// AttrType 为属性标量类型。
type AttrType string

const (
	AttrString AttrType = "string"
	AttrInt    AttrType = "int"
)

// AttributeSpec 描述单个属性的取值约定。
//
// 字符串属性：NonEmpty=true 时不接受空串；Allowed 非空时取值必须在枚举内。
// 整型属性：取值必须落在 [Min, Max] 闭区间内。
type AttributeSpec struct {
	Name     string   `json:"name"`
	Type     AttrType `json:"type"`
	Required bool     `json:"required"`
	NonEmpty bool     `json:"non_empty"`
	Allowed  []string `json:"allowed,omitempty"` // 仅对 string 生效；空表示任意字符串
	Min      int64    `json:"min,omitempty"`     // 仅对 int 生效
	Max      int64    `json:"max,omitempty"`     // 仅对 int 生效
}

// PredicateOp 为可被第三方验证的谓词算子。
type PredicateOp string

const (
	PredGreaterEqual PredicateOp = ">="
	PredLessEqual    PredicateOp = "<="
	PredEqual        PredicateOp = "="
)

// PredicateSpec 描述策略允许的谓词（避免证明泄露属性名以外的信息）。
type PredicateSpec struct {
	Name      string      `json:"name"`
	Attr      string      `json:"attr"`
	Op        PredicateOp `json:"op"`
	Threshold int64       `json:"threshold,omitempty"` // 整数属性比较阈值
	StrValue  string      `json:"str_value,omitempty"` // 字符串属性 "=" 比较值
}

// Policy 定义一个签发策略版本。
type Policy struct {
	Name        string          `json:"name"`
	Version     int             `json:"version"`
	IssuedAt    time.Time       `json:"issued_at"`
	Description string          `json:"description,omitempty"`
	Attributes  []AttributeSpec `json:"attributes"`
	Predicates  []PredicateSpec `json:"predicates"`
}

// attrKey 为属性名规范化使用（当前直接使用原名）。
type attrKey = string

// attrSpec 返回给定属性名的规格与是否存在。
func (p *Policy) attrSpec(name string) (AttributeSpec, bool) {
	for i := range p.Attributes {
		if p.Attributes[i].Name == name {
			return p.Attributes[i], true
		}
	}
	return AttributeSpec{}, false
}

// predSpec 返回给定谓词名的规格与是否存在。
func (p *Policy) predSpec(name string) (PredicateSpec, bool) {
	for i := range p.Predicates {
		if p.Predicates[i].Name == name {
			return p.Predicates[i], true
		}
	}
	return PredicateSpec{}, false
}

// SchemaHash 返回模式指纹：属性集合、谓词集合及取值约定参与摘要。
// 版本号相同但模式发生变化时，指纹会不同。
func (p *Policy) SchemaHash() []byte {
	// 以确定性 JSON（字段顺序固定、切片按名称排序）编码后取 SHA-256。
	attrs := make([]AttributeSpec, len(p.Attributes))
	copy(attrs, p.Attributes)
	sort.Slice(attrs, func(i, j int) bool { return attrs[i].Name < attrs[j].Name })
	preds := make([]PredicateSpec, len(p.Predicates))
	copy(preds, p.Predicates)
	sort.Slice(preds, func(i, j int) bool { return preds[i].Name < preds[j].Name })

	canonical := struct {
		Name       string          `json:"name"`
		Attributes []AttributeSpec `json:"attributes"`
		Predicates []PredicateSpec `json:"predicates"`
	}{Name: p.Name, Attributes: attrs, Predicates: preds}
	b, _ := json.Marshal(canonical)
	sum := sha256.Sum256(b)
	return sum[:]
}

// validateApplication 按属性约定校验申请。
//
// 拒绝原因通过错误类型码区分：
//   - CodeMissingAttribute：缺少必填属性
//   - CodeUnknownAttribute：出现策略未定义的属性
//   - CodeInvalidAttributeValue：类型不符/空串/非法枚举
//   - CodeAttributeOutOfRange：数值超出 [Min, Max]
func (p *Policy) validateApplication(attrs map[string]Value) error {
	// 未知属性：申请中出现策略未定义的字段。
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, ok := p.attrSpec(name); !ok {
			return FailDetail(CodeUnknownAttribute, "application contains attribute not defined by policy", name)
		}
	}

	// 必填属性缺失（按规格顺序产生稳定的错误信息）。
	for _, spec := range p.Attributes {
		if !spec.Required {
			continue
		}
		if _, ok := attrs[spec.Name]; !ok {
			return FailDetail(CodeMissingAttribute, "required attribute is missing", spec.Name)
		}
	}

	// 取值校验。
	for _, spec := range p.Attributes {
		v, ok := attrs[spec.Name]
		if !ok {
			continue
		}
		switch spec.Type {
		case AttrString:
			if v.IsInt {
				return FailDetail(CodeInvalidAttributeValue, "attribute expects string but got int", spec.Name)
			}
			if spec.NonEmpty && v.Str == "" {
				return FailDetail(CodeInvalidAttributeValue, "string attribute must not be empty", spec.Name)
			}
			if len(spec.Allowed) > 0 {
				allowed := false
				for _, a := range spec.Allowed {
					if a == v.Str {
						allowed = true
						break
					}
				}
				if !allowed {
					return FailDetail(CodeInvalidAttributeValue,
						"string value is not in the allowed enum", spec.Name+"="+v.Str)
				}
			}
		case AttrInt:
			if !v.IsInt {
				return FailDetail(CodeInvalidAttributeValue, "attribute expects int but got string", spec.Name)
			}
			if v.Int < spec.Min || v.Int > spec.Max {
				return FailDetail(CodeAttributeOutOfRange,
					"integer value out of allowed range",
					spec.Name+"="+strconv.FormatInt(v.Int, 10)+" not in ["+
						strconv.FormatInt(spec.Min, 10)+","+strconv.FormatInt(spec.Max, 10)+"]")
			}
		default:
			return FailDetail(CodeInvalidAttributeValue, "policy attribute has unknown type", spec.Name)
		}
	}
	return nil
}

// evalPredicate 判断给定属性取值是否满足谓词。
func evalPredicate(spec PredicateSpec, v Value) bool {
	switch spec.Op {
	case PredGreaterEqual:
		return v.IsInt && v.Int >= spec.Threshold
	case PredLessEqual:
		return v.IsInt && v.Int <= spec.Threshold
	case PredEqual:
		if v.IsInt {
			return v.Int == spec.Threshold
		}
		return v.Str == spec.StrValue
	default:
		return false
	}
}
