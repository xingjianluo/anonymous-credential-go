// Package errors 定义凭证系统中可区分的错误类型。
//
// 所有跨包返回的失败都使用 TypedError，调用方通过 KindOf 取得 Kind
// 做分支处理，而不要依赖错误字符串匹配。
package errors

import "fmt"

// Kind 表示错误类别，调用方按类型判定失败原因。
type Kind int

const (
	// KindUnknown 未分类错误。
	KindUnknown Kind = iota
	// KindMissingAttribute 申请缺少策略要求的必填属性。
	KindMissingAttribute
	// KindValueOutOfRange 属性值超出策略约定范围（含长度/枚举）。
	KindValueOutOfRange
	// KindPolicyViolation 与签发策略一致性规则冲突。
	KindPolicyViolation
	// KindUnknownPolicyVersion 策略注册表中不存在该版本。
	KindUnknownPolicyVersion
	// KindIncompatibleVersion 版本已废止或校验参数不兼容。
	KindIncompatibleVersion
	// KindUnauthorizedDisclosure 试图披露策略不允许对外披露的属性。
	KindUnauthorizedDisclosure
	// KindUnknownCredential 凭证标识未在签发登记中找到。
	KindUnknownCredential
	// KindCredentialRevoked 凭证已被撤销。
	KindCredentialRevoked
	// KindProofInvalid 证明结构非法或条件不满足（含开放路径错误）。
	KindProofInvalid
	// KindProofTampered 签名不匹配或证明绑定字段被篡改。
	KindProofTampered
	// KindReplay 证明被重复使用或跨会话重放。
	KindReplay
	// KindMalformed 输入结构缺失或编码非法。
	KindMalformed
)

func (k Kind) String() string {
	switch k {
	case KindMissingAttribute:
		return "missing_attribute"
	case KindValueOutOfRange:
		return "value_out_of_range"
	case KindPolicyViolation:
		return "policy_violation"
	case KindUnknownPolicyVersion:
		return "unknown_policy_version"
	case KindIncompatibleVersion:
		return "incompatible_version"
	case KindUnauthorizedDisclosure:
		return "unauthorized_disclosure"
	case KindUnknownCredential:
		return "unknown_credential"
	case KindCredentialRevoked:
		return "credential_revoked"
	case KindProofInvalid:
		return "proof_invalid"
	case KindProofTampered:
		return "proof_tampered"
	case KindReplay:
		return "replay"
	case KindMalformed:
		return "malformed"
	default:
		return "unknown"
	}
}

// TypedError 携带可机读的错误类别与可读原因。
type TypedError struct {
	Kind   Kind
	Reason string
}

func (e *TypedError) Error() string {
	if e == nil {
		return ""
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Reason)
}

// New 构造一个带类别与原因的错误。
func New(kind Kind, format string, args ...any) error {
	return &TypedError{Kind: kind, Reason: fmt.Sprintf(format, args...)}
}

// Wrap 在原因前附加上下文，保留原类别。
func Wrap(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	kind := KindUnknown
	if te, ok := err.(*TypedError); ok {
		kind = te.Kind
	}
	return &TypedError{Kind: kind, Reason: fmt.Sprintf("%s: %s", fmt.Sprintf(format, args...), err.Error())}
}

// KindOf 返回错误对应的类别，nil 视为成功（KindUnknown 仅用于非 nil）。
func KindOf(err error) Kind {
	if err == nil {
		return KindUnknown
	}
	if te, ok := err.(*TypedError); ok {
		return te.Kind
	}
	return KindUnknown
}
