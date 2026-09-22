package anoncred

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func decodeLogLines(t *testing.T, b []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line not json: %v: %q", err, line)
		}
		out = append(out, m)
	}
	return out
}

func TestAuditLogContent(t *testing.T) {
	f := newFixture(t, 800)
	id := f.issue(t, map[string]Value{
		"name":  StringValue("LogSecretName"),
		"level": StringValue("C1"),
		"age":   IntValue(29),
	})
	res := f.proveRaw(t, id, VerifyPolicy{
		AllowAttrs:      []string{"level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}, []string{"level"}, []string{"is_adult"})
	if _, err := f.svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatal(err)
	}

	lines := decodeLogLines(t, f.logs.Bytes())
	var verifyLine map[string]any
	for _, m := range lines {
		if m["event"] == "verify" && m["accepted"] == true {
			verifyLine = m
		}
	}
	if verifyLine == nil {
		t.Fatalf("no accepted verify log line: %s", f.logs.String())
	}
	for _, key := range []string{"session_id", "issuer", "disclosed_attrs", "predicates", "basis", "cred_id"} {
		if _, ok := verifyLine[key]; !ok {
			t.Errorf("verify log missing key %q: %v", key, verifyLine)
		}
	}
	if verifyLine["session_id"] != res.SessionID {
		t.Errorf("session_id mismatch: %v", verifyLine["session_id"])
	}
	raw := f.logs.String()
	if strings.Contains(raw, "LogSecretName") {
		t.Errorf("undisclosed name value leaked into logs: %s", raw)
	}
	// 仅允许出现被披露属性名 level，不得出现未披露属性名 name 的值。
	if strings.Contains(raw, "\"disclosed_attrs\":[\"name\"]") {
		t.Errorf("name appears in disclosed set")
	}
}

func TestAuditLogRejectedBasis(t *testing.T) {
	f := newFixture(t, 801)
	// 触发一次越界拒绝，再触发一次重放拒绝，日志 basis 必须携带可区分类型码。
	_, _ = f.svc.IssueAndHold(IssueRequest{
		PolicyName:    "driving-entitlement",
		PolicyVersion: 1,
		Attributes: map[string]Value{
			"name": StringValue("A"), "level": StringValue("C1"), "age": IntValue(999),
		},
	})
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, VerifyPolicy{AllowAttrs: []string{"level"}, TTL: time.Minute},
		[]string{"level"}, nil)
	if _, err := f.svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Check(res.SessionID, res.Presentation); err == nil {
		t.Fatal("replay must fail")
	}

	raw := f.logs.String()
	if !strings.Contains(raw, string(CodeAttributeOutOfRange)) {
		t.Errorf("log missing basis %s", CodeAttributeOutOfRange)
	}
	if !strings.Contains(raw, string(CodeProofReplay)) {
		t.Errorf("log missing basis %s", CodeProofReplay)
	}
}

// 确定性：相同种子下 CredID 必须可复现，测试无需等待真实时间。
func TestDeterministicRNGAndClock(t *testing.T) {
	mk := func() (*fixture, string) {
		f := newFixture(t, 900)
		id := f.issue(t, goodAttrs())
		return f, id
	}
	_, id1 := mk()
	_, id2 := mk()
	if id1 != id2 {
		t.Fatalf("deterministic seed should reproduce same cred id:\n%s\n%s", id1, id2)
	}
	// FakeClock 默认固定在 start；推进是显式的。
	f := newFixture(t, 901)
	if !f.clock.Now().Equal(f.start) {
		t.Fatalf("fake clock drift: %v", f.clock.Now())
	}
	f.clock.Advance(3 * time.Second)
	if !f.clock.Now().Equal(f.start.Add(3 * time.Second)) {
		t.Fatal("fake clock advance broken")
	}
}
