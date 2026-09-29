package anoncred

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// 签发方：同版本重复发布，参数一致必须幂等（密钥不变、可再验证既有凭证），
// 参数漂移必须以 version_conflict 拒绝，绝不能被悄悄覆盖。
func TestIssuerRepublishSameVersion(t *testing.T) {
	f := newFixture(t, 2300)
	id := f.issue(t, goodAttrs())
	firstPub := f.svc.Issuer.ActivePublic()

	// 1) 完全一致地再发一次：返回同一份公开材料、同一校验公钥。
	pub2, err := f.svc.Issuer.AddPolicyVersion(v1Policy(f.start))
	if err != nil {
		t.Fatalf("identical republish should be idempotent: %v", err)
	}
	if !ed25519Equal(firstPub.VerifyingKey, pub2.VerifyingKey) {
		t.Fatal("identical republish silently rotated the issuer verifying key")
	}

	// 2) 版本号相同但模式漂移：拒绝。
	drift := v1Policy(f.start)
	drift.Attributes = append(drift.Attributes, AttributeSpec{
		Name: "extra", Type: AttrString, Required: true,
	})
	if _, err := f.svc.Issuer.AddPolicyVersion(drift); CodeOf(err) != CodeVersionConflict {
		t.Fatalf("want version_conflict, got %v", err)
	}

	// 3) 版本号相同但策略名漂移：同样拒绝。
	renamed := v1Policy(f.start)
	renamed.Name = "another-policy"
	if _, err := f.svc.Issuer.AddPolicyVersion(renamed); CodeOf(err) != CodeVersionConflict {
		t.Fatalf("renamed republish: %v", err)
	}

	// 4) 既有凭证仍可用原来的密钥验证（未被覆盖）。
	if _, err := f.proveCheck(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: time.Minute,
	}, nil, []string{"is_adult"}); err != nil {
		t.Fatalf("existing credential must remain verifiable: %v", err)
	}
}

// Service.RegisterPolicy 同样遵守幂等/冲突规则。
func TestServiceRegisterPolicyIdempotent(t *testing.T) {
	f := newFixture(t, 2301)
	if err := f.svc.RegisterPolicy(v1Policy(f.start)); err != nil {
		t.Fatalf("re-register identical policy: %v", err)
	}
	drift := v1Policy(f.start)
	drift.Attributes = append(drift.Attributes, AttributeSpec{
		Name: "extra", Type: AttrString, Required: true,
	})
	if err := f.svc.RegisterPolicy(drift); CodeOf(err) != CodeVersionConflict {
		t.Fatalf("conflicting registration: %v", err)
	}
}

// 信任库：相同档案重复登记幂等；不同公钥/模式冲突；未知版本不能 Replace。
func TestTrustRegistryRepublishRules(t *testing.T) {
	f := newFixture(t, 2302)
	pub := f.svc.Issuer.ActivePublic()
	profile := func(key ed25519.PublicKey, hash []byte, name string) TrustProfile {
		return TrustProfile{
			IssuerName: "driving-entitlement",
			Public: IssuerPublic{
				Policy:       v1Policy(f.start),
				VerifyingKey: key,
				SchemaHash:   hash,
			},
		}
	}
	tp := profile(pub.VerifyingKey, pub.SchemaHash, "")
	if err := f.svc.Trust.Register(tp); err != nil {
		t.Fatalf("identical re-register: %v", err)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if err := f.svc.Trust.Register(profile(other, pub.SchemaHash, "")); CodeOf(err) != CodeVersionConflict {
		t.Fatalf("different key must conflict: %v", err)
	}
	if err := f.svc.Trust.Replace(TrustProfile{
		IssuerName: "driving-entitlement",
		Public: IssuerPublic{
			Policy:       v1Policy(f.start),
			VerifyingKey: other,
			SchemaHash:   pub.SchemaHash,
		},
	}); err != nil {
		t.Fatalf("explicit replace should work: %v", err)
	}
	if !ed25519Equal(f.svc.Trust.Lookup("driving-entitlement", 1).Public.VerifyingKey, other) {
		t.Fatal("explicit replace did not take effect")
	}
	v2 := v2Policy(f.start)
	if err := f.svc.Trust.Replace(TrustProfile{
		IssuerName: "driving-entitlement",
		Public: IssuerPublic{
			Policy:       v2,
			VerifyingKey: other,
			SchemaHash:   v2.SchemaHash(),
		},
	}); CodeOf(err) != CodeUnknownVersion {
		t.Fatalf("replace of never-registered version 2: %v", err)
	}
}

func ed25519Equal(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
