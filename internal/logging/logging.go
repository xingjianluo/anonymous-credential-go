// Package logging 提供统一的可解释日志。
//
// 每条日志至少带会话标识；验证链路还会带披露集合（disclosed）与
// 判定依据（basis/decision）。注意：日志中只允许出现被披露属性的
// 名称或值，未披露属性一律不得进入 fields。
package logging

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Logger 记录验证与签发链路的判定依据。
type Logger interface {
	Log(sessionID string, fields map[string]string, msg string)
}

// stdLogger 以 key=value 形式写文本日志，并发安全。
type stdLogger struct {
	mu sync.Mutex
	w  io.Writer
}

// New 返回写标准错误的简单日志器。
func New() Logger { return NewWithWriter(os.Stderr) }

// NewWithWriter 返回写指定 Writer 的日志器（便于测试捕获）。
func NewWithWriter(w io.Writer) Logger { return &stdLogger{w: w} }

// Discard 返回丢弃所有输出的日志器。
func Discard() Logger { return NewWithWriter(io.Discard) }

func (l *stdLogger) Log(sessionID string, fields map[string]string, msg string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var sb strings.Builder
	sb.WriteString(time.Now().UTC().Format(time.RFC3339Nano))
	sb.WriteString(" session=")
	sb.WriteString(quote(sessionID))
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sb.WriteByte(' ')
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(quote(fields[k]))
	}
	sb.WriteString(" msg=\"")
	sb.WriteString(strings.ReplaceAll(msg, "\"", "'"))
	sb.WriteString("\"\n")
	fmt.Fprint(l.w, sb.String())
}

func quote(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"=") {
		return s
	}
	return "\"" + strings.ReplaceAll(s, "\"", "'") + "\""
}

// Session 绑定固定会话标识的日志辅助类型。
type Session struct {
	Logger    Logger
	SessionID string
}

// Log 以该会话标识输出一条日志。
func (s Session) Log(fields map[string]string, msg string) {
	if s.Logger == nil {
		return
	}
	s.Logger.Log(s.SessionID, fields, msg)
}
