package anoncred

import (
	"testing"
	"time"
)

// TestIssuerRepublishSameParametersIdempotent:
// 同版本号以完全相同参数重复发布必须幂等，且不更换签发密钥（既有凭证不失效）。
func TestIssuerRepublishSameParametersIdempotent(t *testing.T) {
	f := newV2Fixture(t, 2300)
	pub1 := f.svc.Issuer.ActivePublic()

	again := v1Policy(f.start)
	pub2, err := f.svc.Issuer.AddPolicyVersion(again)
	if err != nil {
		t.Fatalf("identical republish must be idempotent: %v", err)
	}
	if !publicKeyEqual(pub1.VerifyingKey, pub2.VerifyingKey) {
		t.Fatal("identical republish must not rotate the issuer signing key")
	}
	// 通过服务层重复登记同样幂等。
	if err := f.svc.RegisterPolicy(v1Policy(f.start)); err != nil {
		t.Fatalf("service republish: %v", err)
	}
}

// TestIssuerRepublishConflictingParametersRejected:
// 同版本号但参数不同的重复发布必须被明确拒绝（version_conflict），
// 且不得覆盖首次发布（首次发布的密钥与凭证继续有效）。
func TestIssuerRepublishConflictingParametersRejected(t *testing.T) {
	f := newV2Fixture(t, 2301)
	id := f.issueLongTTL(t, goodAttrs())
	pubBefore := f.svc.Issuer.ActivePublic()

	drift := v1Policy(f.start)
	drift.Attributes = append(drift.Attributes, AttributeSpec{
		Name: "region", Type: AttrString, Required: true,
	})
	if _, err := f.svc.Issuer.AddPolicyVersion(drift); CodeOf(err) != CodeVersionConflict {
		t.Fatalf("want version_conflict, got %v", err)
	}
	pubAfter := f.svc.Issuer.ActivePublic()
	if !publicKeyEqual(pubBefore.VerifyingKey, pubAfter.VerifyingKey) {
		t.Fatal("conflicting republish must not replace the original publication")
	}
	// 既有凭证仍可正常验证。
	if _, err := f.proveCheck(t, id,
		VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute},
		nil, []string{"is_adult"}); err != nil {
		t.Fatalf("credential under original publication must still verify: %v", err)
	}
}

// TestTrustRegistryRepublishConflict:
// 信任库对“同版本不同参数”同样必须给出 version_conflict，不静默覆盖。
func TestTrustRegistryRepublishConflict(t *testing.T) {
	f := newV2Fixture(t, 2302)
	pub := f.svc.Issuer.ActivePublic()

	// 一致参数 -> 幂等。
	if err := f.svc.Trust.Register(TrustProfile{
		IssuerName: f.svc.Issuer.name, Public: *pub,
	}); err != nil {
		t.Fatalf("identical trust register: %v", err)
	}
	// 不同模式指纹 -> 冲突。
	other := *pub
	other.SchemaHash = append([]byte(nil), pub.SchemaHash...)
	other.SchemaHash[0] ^= 0xFF
	if err := f.svc.Trust.Register(TrustProfile{
		IssuerName: f.svc.Issuer.name, Public: other,
	}); CodeOf(err) != CodeVersionConflict {
		t.Fatalf("want version_conflict, got %v", err)
	}
}

// TestLegacyCompatWindowEnd:
// 旧格式凭证在兼容窗口内继续可验证；窗口结束后必须被明确拒绝（compat_window_closed），
// 规则对新旧凭证混跑同样适用。
func TestLegacyCompatWindowEnd(t *testing.T) {
	// legacy 夹具：旧格式签发 + 有界兼容窗口。
	start := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)
	svc := NewService(ServiceConfig{
		IssuerRNG:   NewDeterministicRNG(2303),
		HolderRNG:   NewDeterministicRNG(2304),
		VerifierRNG: NewDeterministicRNG(2305),
		Clock:       clock,
	})
	if err := svc.RegisterPolicy(v1Policy(start)); err != nil {
		t.Fatal(err)
	}
	if err := svc.Issuer.UseLegacy(true); err != nil {
		t.Fatal(err)
	}
	windowEnd := start.Add(48 * time.Hour)
	if err := svc.SetLegacyWindow(1, windowEnd); err != nil {
		t.Fatal(err)
	}

	id, err := svc.IssueAndHold(IssueRequest{
		PolicyName:    "driving-entitlement",
		PolicyVersion: 1,
		Attributes:    goodAttrs(),
		TTL:           365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}

	// 窗口内：可验证。
	res, err := svc.Prove(id, pol, nil, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatalf("within window: %v", err)
	}

	// 越过窗口结束时刻：明确拒绝。
	clock.Set(windowEnd.Add(time.Second))
	res2, err := svc.Prove(id, pol, nil, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Check(res2.SessionID, res2.Presentation); CodeOf(err) != CodeCompatWindowClosed {
		t.Fatalf("want compat_window_closed, got %v", err)
	}
}

// TestNewV2NotSubjectToLegacyWindow: 兼容窗口只约束旧格式；v2 出示不受其影响。
func TestNewV2NotSubjectToLegacyWindow(t *testing.T) {
	f := newV2Fixture(t, 2304)
	// 即便把旧格式窗口关闭，v2 凭证照常验证。
	if err := f.svc.SetLegacyWindow(1, f.start.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	id := f.issueLongTTL(t, goodAttrs())
	if _, err := f.proveCheck(t, id,
		VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute},
		nil, []string{"is_adult"}); err != nil {
		t.Fatalf("v2 must verify regardless of legacy window: %v", err)
	}
}

// TestLegacyCredentialCannotUseV2Path: legacy 凭证无法通过 v2 背书路径冒充。
func TestLegacyCredentialCannotUseV2Path(t *testing.T) {
	f := newFixture(t, 2305)
	id := f.issue(t, goodAttrs()) // legacy 凭证
	st := f.svc.Holder.lookup(id)
	if !st.Cred.Legacy {
		t.Fatal("fixture credential should be legacy")
	}
	if st.Cred.RoutingSecret != nil {
		t.Fatal("legacy credential should carry no routing secret")
	}
	// legacy 凭证的 BuildPresentation 走旧路径，不存在 Showing 信封。
	res := f.proveRaw(t, id, VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute},
		nil, []string{"is_adult"})
	if res.Presentation.isV2() {
		t.Fatal("legacy presentation must not be v2")
	}
}
