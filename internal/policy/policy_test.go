package policy

import (
	"testing"

	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
)

func testPolicy(v uint32, status Status) *Policy {
	return &Policy{
		Name: "id", Version: v, Status: status,
		Attrs: map[string]*AttrSpec{
			"age":     {Name: "age", Type: AttrInt, Required: true, Disclosable: true, Min: 0, Max: 150},
			"level":   {Name: "level", Type: AttrEnum, Required: true, Disclosable: true, EnumValues: []string{"basic", "premium"}},
			"country": {Name: "country", Type: AttrEnum, Required: false, Disclosable: true, EnumValues: []string{"CN", "US"}},
			"ssn":     {Name: "ssn", Type: AttrString, Required: true, Disclosable: false, MaxLength: 4},
		},
		Rules: []ConsistencyRule{PremiumAgeRule},
	}
}

func TestValidateIssuanceRejectionKinds(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(testPolicy(1, StatusActive)); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		req  *IssuanceRequest
		want cerr.Kind
	}{
		{"missing required", &IssuanceRequest{PolicyV: 1, Attrs: map[string]any{"level": "basic", "ssn": "abc"}}, cerr.KindMissingAttribute},
		{"int out of range", &IssuanceRequest{PolicyV: 1, Attrs: map[string]any{"age": 999, "level": "basic", "ssn": "a"}}, cerr.KindValueOutOfRange},
		{"bad enum", &IssuanceRequest{PolicyV: 1, Attrs: map[string]any{"age": 1, "level": "gold", "ssn": "a"}}, cerr.KindValueOutOfRange},
		{"string too long", &IssuanceRequest{PolicyV: 1, Attrs: map[string]any{"age": 1, "level": "basic", "ssn": "abcde"}}, cerr.KindValueOutOfRange},
		{"unknown attr", &IssuanceRequest{PolicyV: 1, Attrs: map[string]any{"age": 1, "level": "basic", "ssn": "a", "x": 1}}, cerr.KindPolicyViolation},
		{"rule violation", &IssuanceRequest{PolicyV: 1, Attrs: map[string]any{"age": 10, "level": "premium", "ssn": "a"}}, cerr.KindPolicyViolation},
		{"unknown version", &IssuanceRequest{PolicyV: 42, Attrs: map[string]any{}}, cerr.KindUnknownPolicyVersion},
	}
	for _, c := range cases {
		_, err := r.ValidateIssuance(c.req)
		if cerr.KindOf(err) != c.want {
			t.Errorf("%s: got %v want %v", c.name, cerr.KindOf(err), c.want)
		}
	}
}

func TestDeprecatedPolicyRejectsIssuance(t *testing.T) {
	r := NewRegistry()
	if err := r.Register(testPolicy(1, StatusActive)); err != nil {
		t.Fatal(err)
	}
	if err := r.Deprecate(1); err != nil {
		t.Fatal(err)
	}
	_, err := r.ValidateIssuance(&IssuanceRequest{PolicyV: 1, Attrs: map[string]any{
		"age": 30, "level": "basic", "ssn": "a",
	}})
	if cerr.KindOf(err) != cerr.KindIncompatibleVersion {
		t.Fatalf("got %v", err)
	}
}

func TestSchemaHashChangesWithParams(t *testing.T) {
	p1 := testPolicy(1, StatusActive)
	p2 := testPolicy(2, StatusActive)
	p2.Attrs["age"].Max = 200
	if p1.SchemaHash() == p2.SchemaHash() {
		t.Fatal("schema hash must change when range changes")
	}
	// 同参数结构的两个策略实例哈希应稳定一致（与 map 顺序无关）。
	p1b := testPolicy(1, StatusActive)
	if p1.SchemaHash() != p1b.SchemaHash() {
		t.Fatal("schema hash should be deterministic for identical params")
	}
}

func TestOptionalAttributeAbsenceAccepted(t *testing.T) {
	r := NewRegistry()
	must0(t, r.Register(testPolicy(1, StatusActive)))
	if _, err := r.ValidateIssuance(&IssuanceRequest{PolicyV: 1, Attrs: map[string]any{
		"age": 30, "level": "basic", "ssn": "a",
	}}); err != nil {
		t.Fatalf("optional country may be absent: %v", err)
	}
}

func TestDuplicateRegisterRejected(t *testing.T) {
	r := NewRegistry()
	must0(t, r.Register(testPolicy(1, StatusActive)))
	if err := r.Register(testPolicy(1, StatusActive)); err == nil {
		t.Fatal("duplicate version must be rejected")
	}
}

func must0(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
