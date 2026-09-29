package anoncred

import (
	"errors"
	"fmt"
)

// Code 是可区分的错误类型码，调用方应通过 Code 判定失败原因。
type Code string

const (
	// 签发阶段
	CodeMissingAttribute      Code = "missing_attribute"       // 缺少必填属性
	CodeUnknownAttribute      Code = "unknown_attribute"       // 申请中出现策略未定义的属性
	CodeInvalidAttributeValue Code = "invalid_attribute_value" // 类型错误/空值/非法枚举
	CodeAttributeOutOfRange   Code = "attribute_out_of_range"  // 数值超出约定范围
	CodePolicyMismatch        Code = "policy_mismatch"         // 申请与签发策略不一致（版本/策略名）

	// 凭证与证明结构
	CodeMalformedPresentation Code = "malformed_presentation" // 证明结构不完整
	CodeBadIssuerSignature    Code = "bad_issuer_signature"   // 签发方签名校验失败（伪造/篡改）
	CodeBadHolderProof        Code = "bad_holder_proof"       // 持有者证明签名校验失败
	CodeTamperedDisclosure    Code = "tampered_disclosure"    // 披露字段与已签名承诺不一致
	CodeDisclosureNotAllowed  Code = "disclosure_not_allowed" // 越权披露：会话未允许的属性
	CodePredicateNotAllowed   Code = "predicate_not_allowed"  // 越权披露：会话未允许的谓词
	CodeUndisclosedLeak       Code = "undisclosed_leak"       // 证明中混入了未授权的附加数据

	// 生命周期
	CodeRevokedCredential Code = "revoked_credential" // 凭证已被吊销
	CodeExpiredCredential Code = "expired_credential" // 凭证已过期
	CodeSessionUnknown    Code = "session_unknown"    // 会话不存在
	CodeSessionExpired    Code = "session_expired"    // 会话已过期
	CodeProofReplay       Code = "proof_replay"       // 同一证明重复使用/重放

	// 版本
	CodeUnknownVersion         Code = "unknown_version"         // 未知版本，拒绝
	CodeVersionRejected        Code = "version_rejected"        // 历史版本被显式停用（日落规则）
	CodeIncompatibleParameters Code = "incompatible_parameters" // 版本参数/模式哈希不兼容
	CodeVersionConflict        Code = "version_conflict"        // 同版本号重复发布但参数不一致
	CodeCompatWindowClosed     Code = "compat_window_closed"    // 旧格式凭证超过声明的兼容窗口

	// 不可关联出示
	CodeShowingRejected Code = "showing_rejected" // 出示背书被签发方拒绝（路由标签无匹配凭证）

	// 签发方管理
	CodeNoSuchCredential Code = "no_such_credential" // 吊销/核对时找不到签发记录
)

// Error 携带稳定的错误类型码，便于按类型区分失败原因。
type Error struct {
	Code    Code
	Message string
	Detail  string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Detail)
}

// Fail 构造一个带类型码的错误。
func Fail(code Code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// FailDetail 在 Fail 基础上附加细节（细节中禁止携带未披露属性值）。
func FailDetail(code Code, msg, detail string) *Error {
	return &Error{Code: code, Message: msg, Detail: detail}
}

// CodeOf 提取错误类型码；非本包错误返回空串。
func CodeOf(err error) Code {
	var ve *Error
	if errors.As(err, &ve) {
		return ve.Code
	}
	return ""
}
