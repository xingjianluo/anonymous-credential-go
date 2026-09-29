package anoncred

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// newV2Fixture 在不开启 legacy 默认签发的情况下创建夹具（默认即 v2）。
func newV2Fixture(t *testing.T, seed uint64) *fixture {
	t.Helper()
	start := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
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
	mustReg(t, svc, v1Policy(start))
	return &fixture{svc: svc, clock: clock, logs: &logs, start: start}
}

// TestV2Smoke: v2 凭证出示谓词与属性，验证通过且决策不含 CredID。
func TestV2Smoke(t *testing.T) {
	f := newV2Fixture(t, 2000)
	id := f.issueLongTTL(t, goodAttrs())

	d, err := f.proveCheck(t, id, VerifyPolicy{
		AllowAttrs:      []string{"level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}, []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatalf("v2 verify: %v", err)
	}
	if !d.Accepted {
		t.Fatalf("not accepted: %+v", d)
	}
	if d.CredID != "" {
		t.Fatalf("v2 decision must not carry cred id, got %q", d.CredID)
	}
	if d.ShowID == "" {
		t.Fatal("v2 decision must carry per-show id")
	}
	if !equalStrings(d.DisclosedAttrs, []string{"level"}) ||
		!equalStrings(d.Predicates, []string{"is_adult"}) {
		t.Fatalf("unexpected disclosure: %+v", d)
	}
}

// TestV2PresentationContainsNoLongTermIdentifier: v2 证明序列化字节中
// 不得出现 CredID、化名、凭证级持有公钥、承诺、静态盐。
func TestV2PresentationContainsNoLongTermIdentifier(t *testing.T) {
	f := newV2Fixture(t, 2001)
	id := f.issueLongTTL(t, goodAttrs())
	idB, _ := decodeHex(id)
	st := f.svc.Holder.lookup(id)

	res := f.proveRaw(t, id, VerifyPolicy{
		AllowAttrs:      []string{"level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}, []string{"level"}, []string{"is_adult"})

	raw, err := json.Marshal(res.Presentation)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, idB) {
		t.Fatal("cred id leaked into v2 presentation")
	}
	if bytes.Contains(raw, []byte("local-holder")) {
		t.Fatal("pseudonym leaked into v2 presentation")
	}
	if bytes.Contains(raw, st.Cred.Signed.HolderVerifyKey) {
		t.Fatal("credential-level holder verify key leaked")
	}
	for name, c := range st.Cred.Signed.Commitments {
		if bytes.Contains(raw, c) {
			t.Fatalf("commitment for %s leaked", name)
		}
	}
	for name, s := range st.Cred.Salts {
		if bytes.Contains(raw, s) {
			t.Fatalf("static salt for %s leaked", name)
		}
	}
	if bytes.Contains(raw, st.Cred.RoutingSecret) {
		t.Fatal("routing secret leaked")
	}
}

// extractArtifacts 汇总一次 v2 证明中验证方可观察到的全部公开字节特征。
func extractArtifacts(t *testing.T, p *Presentation) [][]byte {
	t.Helper()
	if !p.isV2() {
		t.Fatal("not a v2 presentation")
	}
	e := p.Showing
	out := [][]byte{
		e.ShowID, e.RouteTag, e.HolderShowKey, e.HolderAuth, e.HolderProof,
	}
	for _, d := range e.Disclosed {
		out = append(out, d.ValTag)
	}
	return out
}

func artifactsOverlap(a, b [][]byte) []byte {
	for _, x := range a {
		for _, y := range b {
			if bytes.Equal(x, y) {
				return x
			}
		}
	}
	return nil
}

// TestMultipleCredentialsAcrossScenesUnlinkable:
// 同一持有者的多张凭证，分别在不同验证方、不同时间出示，
// 即便两个验证方合并各自观察到的全部公开结果，也无法判断它们来自同一持有者。
func TestMultipleCredentialsAcrossScenesUnlinkable(t *testing.T) {
	f := newV2Fixture(t, 2100)

	// 同一持有者先后拿到 3 张凭证（属性相同更能说明问题：值相同仍不可关联）。
	var ids []string
	for i := 0; i < 3; i++ {
		ids = append(ids, f.issueLongTTL(t, goodAttrs()))
	}

	pol := VerifyPolicy{
		AllowAttrs:      []string{"level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}
	// 两个相互独立的验证方（各自会话），共享同一签发方背书来源。
	trust2 := NewTrustRegistry()
	pub := f.svc.Issuer.ActivePublic()
	if err := trust2.Register(TrustProfile{
		IssuerName: f.svc.Issuer.name, Public: *pub,
	}); err != nil {
		t.Fatal(err)
	}
	verifier2 := NewVerifier(f.clock, NewDeterministicRNG(999), trust2).
		WithRevocationSource(f.svc.Issuer).
		WithShowingAuthority(f.svc.Issuer)

	// 场景 A：验证方 1 依次验证凭证 0、1；场景 B：验证方 2 在更晚时间验证凭证 2，
	// 并再次验证凭证 0（同一凭证跨验证方重复出示）。
	var allArtifacts [][][]byte

	proveOn := func(svcVerifier *Verifier, id string) *Decision {
		res := f.proveRaw(t, id, pol, []string{"level"}, []string{"is_adult"})
		if svcVerifier == f.svc.Verifier {
			d, err := f.svc.Check(res.SessionID, res.Presentation)
			if err != nil {
				t.Fatalf("verifier1 check: %v", err)
			}
			allArtifacts = append(allArtifacts, extractArtifacts(t, res.Presentation))
			return d
		}
		sess, err := verifier2.NewSession(f.svc.Issuer.name, 1, pol)
		if err != nil {
			t.Fatal(err)
		}
		pres, err := f.svc.Holder.BuildPresentation(PresentRequest{
			CredIDHex:     id,
			SessionNonce:  sess.Nonce,
			DiscloseAttrs: []string{"level"},
			DisclosePreds: []string{"is_adult"},
		})
		if err != nil {
			t.Fatal(err)
		}
		d, err := verifier2.Verify(sess.ID, pres)
		if err != nil {
			t.Fatalf("verifier2 check: %v", err)
		}
		allArtifacts = append(allArtifacts, extractArtifacts(t, pres))
		return d
	}

	d1 := proveOn(f.svc.Verifier, ids[0])
	f.clock.Advance(2 * time.Hour)
	d2 := proveOn(f.svc.Verifier, ids[1])
	f.clock.Advance(24 * time.Hour)
	d3 := proveOn(verifier2, ids[2])
	d4 := proveOn(verifier2, ids[0])

	for i, d := range []*Decision{d1, d2, d3, d4} {
		if !d.Accepted {
			t.Fatalf("showing %d not accepted: %+v", i, d)
		}
		if d.CredID != "" {
			t.Fatalf("showing %d leaked cred id", i)
		}
	}

	// 合并所有验证方日志后：任意两次出示的公开特征（show id/route tag/show key/auth/proof/val tag）
	// 两两不得相同，否则就能把它们拼回同一持有者/同一凭证。
	for i := 0; i < len(allArtifacts); i++ {
		for j := i + 1; j < len(allArtifacts); j++ {
			if shared := artifactsOverlap(allArtifacts[i], allArtifacts[j]); shared != nil {
				t.Fatalf("scenes %d and %d share a stable artifact: %x", i, j, shared)
			}
		}
	}
}

// TestSameCredentialRepeatedShowsNoReusableClue:
// 同一张凭证在不同场景重复出示，所有公开特征必须每次刷新，不存在跨场景可复用线索。
func TestSameCredentialRepeatedShowsNoReusableClue(t *testing.T) {
	f := newV2Fixture(t, 2101)
	id := f.issueLongTTL(t, goodAttrs())
	pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}

	var prev [][]byte
	for i := 0; i < 5; i++ {
		f.clock.Advance(time.Hour)
		res := f.proveRaw(t, id, pol, nil, []string{"is_adult"})
		d, err := f.svc.Check(res.SessionID, res.Presentation)
		if err != nil {
			t.Fatalf("show %d: %v", i, err)
		}
		if !d.Accepted {
			t.Fatalf("show %d not accepted", i)
		}
		cur := extractArtifacts(t, res.Presentation)
		if i > 0 && artifactsOverlap(prev, cur) != nil {
			t.Fatalf("show %d reuses an artifact from the previous showing", i)
		}
		prev = cur
	}
}

// issueLongTTL 在 v2 夹具内签发长有效期凭证，便于跨多日场景测试。
func (f *fixture) issueLongTTL(t *testing.T, attrs map[string]Value) string {
	t.Helper()
	id, err := f.svc.IssueAndHold(IssueRequest{
		PolicyName:    "driving-entitlement",
		PolicyVersion: 1,
		Attributes:    attrs,
		TTL:           365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return id
}
