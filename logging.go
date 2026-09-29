package anoncred

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// AuditLogger 在验证/撤销等关键动作发生时输出结构化日志。
//
// 日志仅包含会话标识、披露“名称”集合与判定依据（错误类型码），
// 绝不打印未披露属性的值，也不打印承诺盐。
type AuditLogger struct {
	l *slog.Logger
}

// NewAuditLogger 创建输出到 w 的 JSON 审计日志；w 为 nil 时使用 stderr。
func NewAuditLogger(w io.Writer) *AuditLogger {
	if w == nil {
		w = os.Stderr
	}
	return &AuditLogger{l: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))}
}

// LogDecision 记录一次验证结论。
//
// v2（不可关联）决策只记录 mode 与当次 show_id，绝不记录长期 CredID；
// legacy 决策保留 cred_id（旧版出示方式的已知可关联限制）。
func (a *AuditLogger) LogDecision(d *Decision) {
	if a == nil || d == nil {
		return
	}
	mode := d.Mode
	if mode == "" {
		mode = "legacy"
	}
	common := func(accepted bool, level slog.Level) {
		attrs := []slog.Attr{
			slog.String("event", "verify"),
			slog.String("mode", mode),
			slog.Bool("accepted", accepted),
			slog.String("session_id", d.SessionID),
			slog.String("issuer", d.Issuer),
			slog.Int("policy_version", d.PolicyVersion),
			slog.Any("disclosed_attrs", d.DisclosedAttrs),
			slog.Any("predicates", d.Predicates),
			slog.Time("checked_at", d.CheckedAt),
		}
		if mode == "v2" {
			// show_id 每次出示独立随机，无法跨出示串联。
			attrs = append(attrs, slog.String("show_id", d.ShowID))
		} else {
			attrs = append(attrs, slog.String("cred_id", d.CredID))
		}
		if accepted {
			attrs = append(attrs, slog.String("basis", "signature_ok|commitments_ok|session_bound|not_revoked"))
		} else {
			attrs = append(attrs, slog.String("basis", string(d.Reason)))
		}
		a.l.LogAttrs(context.Background(), level, "verify_decision", attrs...)
	}
	level := slog.LevelWarn
	if d.Accepted {
		level = slog.LevelInfo
	}
	common(d.Accepted, level)
}

// LogIssuance 记录一次签发动作（仅记录凭证标识与策略版本，无属性值）。
func (a *AuditLogger) LogIssuance(issuer string, version int, credIDHex string, rejected Code, detail string) {
	if a == nil {
		return
	}
	attrs := []slog.Attr{
		slog.String("event", "issue"),
		slog.String("issuer", issuer),
		slog.Int("policy_version", version),
		slog.String("cred_id", credIDHex),
	}
	if rejected != "" {
		attrs = append(attrs, slog.Bool("accepted", false), slog.String("basis", string(rejected)))
		if detail != "" {
			attrs = append(attrs, slog.String("reason", detail))
		}
		a.l.LogAttrs(context.Background(), slog.LevelWarn, "issue_decision", attrs...)
		return
	}
	attrs = append(attrs, slog.Bool("accepted", true), slog.String("basis", "policy_validated"))
	a.l.LogAttrs(context.Background(), slog.LevelInfo, "issue_decision", attrs...)
}

// LogRevocation 记录一次吊销动作。
func (a *AuditLogger) LogRevocation(issuer, credIDHex, reason string) {
	if a == nil {
		return
	}
	a.l.Info("revocation",
		slog.String("event", "revoke"),
		slog.String("issuer", issuer),
		slog.String("cred_id", credIDHex),
		slog.String("reason", reason),
	)
}

// Logger 返回底层 slog 记录器，便于签发方/验证方内部复用。
func (a *AuditLogger) Logger() *slog.Logger {
	if a == nil {
		return slog.Default()
	}
	return a.l
}
