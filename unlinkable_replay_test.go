package anoncred

import (
	"testing"
	"time"
)

// TestV2ReplaySameSession: 同一会话第二次提交 v2 证明必须按重放拒绝。
func TestV2ReplaySameSession(t *testing.T) {
	f := newV2Fixture(t, 2600)
	id := f.issueLongTTL(t, goodAttrs())
	res := f.proveRaw(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: time.Minute,
	}, nil, []string{"is_adult"})
	if _, err := f.svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatalf("first check: %v", err)
	}
	if _, err := f.svc.Check(res.SessionID, res.Presentation); CodeOf(err) != CodeProofReplay {
		t.Fatalf("want proof_replay, got %v", err)
	}
}

// TestV2ReplayCrossSession: 把 v2 证明提交给另一个会话（nonce 不同）必须拒绝。
func TestV2ReplayCrossSession(t *testing.T) {
	f := newV2Fixture(t, 2601)
	id := f.issueLongTTL(t, goodAttrs())
	pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}
	res := f.proveRaw(t, id, pol, nil, []string{"is_adult"})
	if _, err := f.svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatalf("first check: %v", err)
	}
	sess2, err := f.svc.Verifier.NewSession(f.svc.Issuer.name, 1, pol)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Check(sess2.ID, res.Presentation); CodeOf(err) != CodeProofReplay {
		t.Fatalf("want proof_replay across sessions, got %v", err)
	}
}

// TestV2AttestationCannotBeMoved: 为信封 A 取得的背书不能搬到信封 B。
func TestV2AttestationCannotBeMoved(t *testing.T) {
	f := newV2Fixture(t, 2602)
	idA := f.issueLongTTL(t, goodAttrs())
	idB := f.issueLongTTL(t, goodAttrs())
	pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}

	resA := f.proveRaw(t, idA, pol, nil, []string{"is_adult"})

	// 为 A 取得真实背书；包装后的背书来源对 B 的信封仍返回 A 的背书，
	// 验证方的背书-信封绑定检查必须拒绝（背书无法搬到另一个信封/会话）。
	attA, err := f.svc.Issuer.AttestShowing(resA.Presentation.Showing)
	if err != nil {
		t.Fatal(err)
	}
	mix := newMixedAuthority(f.svc.Issuer, attA)

	trust := NewTrustRegistry()
	pub := f.svc.Issuer.ActivePublic()
	if err := trust.Register(TrustProfile{
		IssuerName: f.svc.Issuer.name, Public: *pub,
	}); err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(f.clock, NewDeterministicRNG(2603), trust).
		WithRevocationSource(f.svc.Issuer).
		WithShowingAuthority(mix)
	sess, err := v.NewSession(f.svc.Issuer.name, 1, pol)
	if err != nil {
		t.Fatal(err)
	}
	// resB 的信封绑定 sessB 的 nonce，需重新为 sess 生成 B 的信封。
	presB, err := f.svc.Holder.BuildPresentation(PresentRequest{
		CredIDHex:     idB,
		SessionNonce:  sess.Nonce,
		DisclosePreds: []string{"is_adult"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(sess.ID, presB)
	if CodeOf(err) != CodeIncompatibleParameters && CodeOf(err) != CodeBadIssuerSignature {
		t.Fatalf("moved attestation must fail binding/signature check, got %v", err)
	}
}

// mixedAuthority 对任何请求都返回固定背书（用于测试背书搬移攻击）。
type mixedAuthority struct {
	fixed *ShowingAttestation
}

func newMixedAuthority(_ ShowingAuthority, fixed *ShowingAttestation) ShowingAuthority {
	return &mixedAuthority{fixed: fixed}
}

func (m *mixedAuthority) AttestShowing(_ *ShowingEnvelope) (*ShowingAttestation, error) {
	return m.fixed, nil
}

// TestV2UndisclosedValuesNeverLeak: 未披露属性值/盐不得出现在 v2 证明字节中。
func TestV2UndisclosedValuesNeverLeak(t *testing.T) {
	f := newV2Fixture(t, 2604)
	attrs := map[string]Value{
		"name":    StringValue("V2SecretName"),
		"level":   StringValue("C1"),
		"age":     IntValue(29),
		"country": StringValue("V2Atlantis"),
	}
	id, err := f.svc.IssueAndHold(IssueRequest{
		PolicyName: "driving-entitlement", PolicyVersion: 1,
		Attributes: attrs, TTL: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := f.proveRaw(t, id, VerifyPolicy{
		AllowAttrs:      []string{"level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}, []string{"level"}, []string{"is_adult"})
	if _, err := f.svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatal(err)
	}
	if err := assertNoLeak(res.Presentation, []string{"V2SecretName", "V2Atlantis"}); err != nil {
		t.Fatal(err)
	}
}
