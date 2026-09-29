package anoncred

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// --- 测试夹具 ---------------------------------------------------------------

type fixture struct {
	svc   *Service
	clock *FakeClock
	logs  *bytes.Buffer
	start time.Time
}

func newFixture(t *testing.T, seed uint64) *fixture {
	t.Helper()
	start := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)
	svc := NewService(ServiceConfig{
		IssuerRNG:   NewDeterministicRNG(seed),
		HolderRNG:   NewDeterministicRNG(seed + 1),
		VerifierRNG: NewDeterministicRNG(seed + 2),
		Clock:       clock,
	})
	var logs bytes.Buffer
	svc.Audit = NewAuditLogger(&logs)
	svc.Issuer.WithAudit(svc.Audit)
	svc.Verifier.WithAudit(svc.Audit)

	// 现有夹具沿用旧格式语义：显式签发 legacy 凭证并开放无限兼容窗口，
	// 从而既有签发/披露/重放/篡改/撤销用例保持原行为；
	// v2 不可关联行为由 unlinkable_test.go 等新增用例覆盖。
	mustReg(t, svc, v1Policy(start))
	if err := svc.Issuer.UseLegacy(true); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetLegacyWindow(1, time.Time{}); err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, clock: clock, logs: &logs, start: start}
}

func mustReg(t *testing.T, svc *Service, p Policy) {
	t.Helper()
	if err := svc.RegisterPolicy(p); err != nil {
		t.Fatalf("register policy: %v", err)
	}
	// 既有测试沿用旧格式语义：默认开放无限兼容窗口；
	// 兼容窗口的收紧/结束由 version_test.go 的专门用例断言。
	if err := svc.SetLegacyWindow(p.Version, time.Time{}); err != nil {
		t.Fatalf("set legacy window: %v", err)
	}
}

// v1Policy: name 必填非空；level 枚举；age 0..150；可选 country；
// 谓词 is_adult(age>=18)。
func v1Policy(at time.Time) Policy {
	return Policy{
		Name:     "driving-entitlement",
		Version:  1,
		IssuedAt: at,
		Attributes: []AttributeSpec{
			{Name: "name", Type: AttrString, Required: true, NonEmpty: true},
			{Name: "level", Type: AttrString, Required: true, NonEmpty: true,
				Allowed: []string{"C1", "C2", "D"}},
			{Name: "age", Type: AttrInt, Required: true, Min: 0, Max: 150},
			{Name: "country", Type: AttrString, Required: false},
		},
		Predicates: []PredicateSpec{
			{Name: "is_adult", Attr: "age", Op: PredGreaterEqual, Threshold: 18},
		},
	}
}

func goodAttrs() map[string]Value {
	return map[string]Value{
		"name":  StringValue("Alice"),
		"level": StringValue("C1"),
		"age":   IntValue(29),
	}
}

func (f *fixture) issue(t *testing.T, attrs map[string]Value) string {
	t.Helper()
	id, err := f.svc.IssueAndHold(IssueRequest{
		PolicyName:    "driving-entitlement",
		PolicyVersion: 1,
		Attributes:    attrs,
		TTL:           time.Hour,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return id
}

// proveCheck 创建会话、生成证明并验证，返回结论与错误。
func (f *fixture) proveCheck(t *testing.T, credID string, pol VerifyPolicy, attrs, preds []string) (*Decision, error) {
	t.Helper()
	res, err := f.svc.Prove(credID, pol, attrs, preds)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	return f.svc.Check(res.SessionID, res.Presentation)
}

// proveRaw 返回会话与证明，便于调用方自行篡改后校验。
func (f *fixture) proveRaw(t *testing.T, credID string, pol VerifyPolicy, attrs, preds []string) *ProveResult {
	t.Helper()
	res, err := f.svc.Prove(credID, pol, attrs, preds)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	return res
}

// --- 签发拒绝：原因可区分 ----------------------------------------------------

func TestIssueRejections(t *testing.T) {
	f := newFixture(t, 1)

	cases := []struct {
		name  string
		attrs map[string]Value
		want  Code
	}{
		{"missing required", map[string]Value{
			"level": StringValue("C1"), "age": IntValue(29),
		}, CodeMissingAttribute},
		{"unknown attribute", map[string]Value{
			"name": StringValue("A"), "level": StringValue("C1"),
			"age": IntValue(29), "ssn": StringValue("X"),
		}, CodeUnknownAttribute},
		{"empty string", map[string]Value{
			"name": StringValue(""), "level": StringValue("C1"), "age": IntValue(29),
		}, CodeInvalidAttributeValue},
		{"bad enum", map[string]Value{
			"name": StringValue("A"), "level": StringValue("ZZ"), "age": IntValue(29),
		}, CodeInvalidAttributeValue},
		{"wrong type", map[string]Value{
			"name": StringValue("A"), "level": StringValue("C1"), "age": StringValue("29"),
		}, CodeInvalidAttributeValue},
		{"out of range high", map[string]Value{
			"name": StringValue("A"), "level": StringValue("C1"), "age": IntValue(200),
		}, CodeAttributeOutOfRange},
		{"out of range low", map[string]Value{
			"name": StringValue("A"), "level": StringValue("C1"), "age": IntValue(-1),
		}, CodeAttributeOutOfRange},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.svc.IssueAndHold(IssueRequest{
				PolicyName:    "driving-entitlement",
				PolicyVersion: 1,
				Attributes:    tc.attrs,
			})
			if CodeOf(err) != tc.want {
				t.Fatalf("want code %s, got %v", tc.want, err)
			}
		})
	}

	// 策略名 / 版本不一致。
	if _, err := f.svc.IssueAndHold(IssueRequest{
		PolicyName: "other", PolicyVersion: 1, Attributes: goodAttrs(),
	}); CodeOf(err) != CodePolicyMismatch {
		t.Fatalf("policy name mismatch: %v", err)
	}
	if _, err := f.svc.IssueAndHold(IssueRequest{
		PolicyName: "driving-entitlement", PolicyVersion: 9, Attributes: goodAttrs(),
	}); CodeOf(err) != CodePolicyMismatch {
		t.Fatalf("policy version mismatch: %v", err)
	}
}

// 避免未使用导入（后续用例将使用 json/sync）。
var _ = json.Marshal
var _ sync.Mutex
