package issuer_test

import (
	"bytes"
	"testing"

	"github.com/xingjianluo/anonymous-credential-go/internal/credential"
	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
	"github.com/xingjianluo/anonymous-credential-go/internal/issuer"
	"github.com/xingjianluo/anonymous-credential-go/internal/logging"
	"github.com/xingjianluo/anonymous-credential-go/internal/policy"
	"github.com/xingjianluo/anonymous-credential-go/internal/registry"
	"github.com/xingjianluo/anonymous-credential-go/internal/sys"
)

func pol() *policy.Policy {
	return &policy.Policy{
		Name: "id", Version: 1, Status: policy.StatusActive,
		Attrs: map[string]*policy.AttrSpec{
			"age": {Name: "age", Type: policy.AttrInt, Required: true, Disclosable: true, Min: 0, Max: 150},
			"ssn": {Name: "ssn", Type: policy.AttrString, Required: true, Disclosable: false, MaxLength: 8},
		},
	}
}

func TestRegistryRecordContainsNoPlaintextAttrs(t *testing.T) {
	polreg := policy.NewRegistry()
	if err := polreg.Register(pol()); err != nil {
		t.Fatal(err)
	}
	reg := registry.New()
	var buf bytes.Buffer
	log := logging.NewWithWriter(&buf)
	key, err := credential.GenerateKey(sys.NewSeededRandom(1))
	if err != nil {
		t.Fatal(err)
	}
	iss := issuer.New(key, polreg, reg, sys.FixedClock{}, sys.NewSeededRandom(2), log)
	b, err := iss.Issue(&policy.IssuanceRequest{
		HolderID: "alice", PolicyV: 1,
		Attrs: map[string]any{"age": 33, "ssn": "SECRET9"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 登记审计视图中不得包含任何属性明文或盐。
	rec, err := reg.Audit(b.IDCommitment)
	if err != nil {
		t.Fatal(err)
	}
	blob := []byte(rec.CredID)
	_ = blob
	if bytes.Contains([]byte(rec.CredID), []byte("SECRET9")) {
		t.Fatal("secret value must never appear in issuance record")
	}
	if rec.PolicyVer != 1 {
		t.Fatalf("record policy version wrong: %d", rec.PolicyVer)
	}
	// 日志中不得出现未披露/秘密属性明文。
	if bytes.Contains(buf.Bytes(), []byte("SECRET9")) {
		t.Fatal("secret value must never appear in issuer logs")
	}
	if bytes.Contains(buf.Bytes(), []byte("alice")) {
		t.Fatal("holder id must not appear in plaintext logs")
	}
}

func TestIssuanceRejectionKindsPropagate(t *testing.T) {
	polreg := policy.NewRegistry()
	_ = polreg.Register(pol())
	reg := registry.New()
	key, _ := credential.GenerateKey(sys.NewSeededRandom(3))
	iss := issuer.New(key, polreg, reg, sys.FixedClock{}, sys.NewSeededRandom(4), logging.Discard())
	if _, err := iss.Issue(&policy.IssuanceRequest{PolicyV: 1, Attrs: map[string]any{"ssn": "x"}}); cerr.KindOf(err) != cerr.KindMissingAttribute {
		t.Fatalf("got %v", err)
	}
	if _, err := iss.Issue(&policy.IssuanceRequest{PolicyV: 1, Attrs: map[string]any{"age": 999, "ssn": "x"}}); cerr.KindOf(err) != cerr.KindValueOutOfRange {
		t.Fatalf("got %v", err)
	}
}

func TestRevokeUnknownFails(t *testing.T) {
	polreg := policy.NewRegistry()
	_ = polreg.Register(pol())
	reg := registry.New()
	key, _ := credential.GenerateKey(sys.NewSeededRandom(5))
	iss := issuer.New(key, polreg, reg, sys.FixedClock{}, sys.NewSeededRandom(6), logging.Discard())
	if err := iss.Revoke([]byte("ghost")); cerr.KindOf(err) != cerr.KindUnknownCredential {
		t.Fatalf("got %v", err)
	}
}
