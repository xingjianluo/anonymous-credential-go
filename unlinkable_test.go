package anoncred

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func proveUnlinkable(t *testing.T, f *fixture, credID string, attrs, preds []string) *ProveResult {
	t.Helper()
	res, err := f.svc.ProveUnlinkable(credID, VerifyPolicy{
		AllowAttrs:      attrs,
		AllowPredicates: preds,
		TTL:             time.Minute,
	}, attrs, preds)
	if err != nil {
		t.Fatalf("prove unlinkable: %v", err)
	}
	return res
}

// showPol 与默认披露集。
func v2Pol() VerifyPolicy {
	return VerifyPolicy{
		AllowAttrs:      []string{"level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}
}

// TestV2HappyPath：v2 出示被接受，决策标记为 v2 且不含 CredID。
func TestV2HappyPath(t *testing.T) {
	f := newFixture(t, 2000)
	id := f.issue(t, goodAttrs())

	res, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	d, err := f.svc.Check(res.SessionID, res.Presentation)
	if err != nil || !d.Accepted {
		t.Fatalf("v2 verify should accept: d=%+v err=%v", d, err)
	}
	if d.Mode != "v2" {
		t.Fatalf("mode = %q, want v2", d.Mode)
	}
	if d.CredID != "" {
		t.Fatalf("v2 decision must not carry long-term cred id, got %s", d.CredID)
	}
	if d.ShowID == "" {
		t.Fatal("v2 decision should carry a one-time show id")
	}
	if !equalStrings(d.DisclosedAttrs, []string{"level"}) ||
		!equalStrings(d.Predicates, []string{"is_adult"}) {
		t.Fatalf("unexpected disclosed/predicates: %v %v", d.DisclosedAttrs, d.Predicates)
	}
}

// TestV2MultiCredentialCrossScenarioUnlinkable：
// 同一持有者多张凭证、在多个“验证方”多次出示，公开结果中没有任何可复用线索。
func TestV2MultiCredentialCrossScenarioUnlinkable(t *testing.T) {
	f := newFixture(t, 2001)
	const n = 4
	credIDs := make([]string, n)
	for i := range credIDs {
		attrs := goodAttrs()
		attrs["name"] = StringValue("UnlinkablePerson") // 不披露
		credIDs[i] = f.issue(t, attrs)
	}

	type snapshot struct {
		sessionID string
		showID    []byte
		verifyKey []byte
		envSig    []byte
		holderSig []byte
		commits   map[string][]byte
		tokenSigs map[string][]byte
		assertSig []byte
		nonce     []byte
		raw       []byte
	}
	snaps := make([]snapshot, 0, n*2)

	// 每张凭证在两个不同验证方（用不同 AllowAttrs 会话模拟场景）各出示一次。
	scenarios := []VerifyPolicy{
		{AllowAttrs: []string{"level"}, AllowPredicates: []string{"is_adult"}, TTL: time.Minute},
		{AllowPredicates: []string{"is_adult"}, TTL: time.Minute},
	}
	for _, id := range credIDs {
		for si, pol := range scenarios {
			attrs := pol.AllowAttrs
			res, err := f.svc.ProveUnlinkable(id, pol, attrs, []string{"is_adult"})
			if err != nil {
				t.Fatalf("prove: %v", err)
			}
			p := res.Presentation
			if p.Envelope == nil {
				t.Fatal("expected v2 envelope")
			}
			raw, _ := json.Marshal(p)
			sn := snapshot{
				sessionID: res.SessionID,
				showID:    p.Envelope.ShowID,
				verifyKey: p.Envelope.ShowVerifyKey,
				envSig:    p.Envelope.Signature,
				holderSig: p.HolderProof,
				commits:   p.Envelope.Commitments,
				tokenSigs: map[string][]byte{},
				assertSig: p.Assertion.Signature,
				nonce:     p.SessionNonce,
				raw:       raw,
			}
			for _, pt := range p.ShowTokens {
				sn.tokenSigs[pt.Token.Name] = pt.Token.Signature
			}
			snaps = append(snaps, sn)

			d, err := f.svc.Check(res.SessionID, p)
			if err != nil || !d.Accepted {
				t.Fatalf("scenario %d verify failed: %v", si, err)
			}
		}
	}

	// 1) 任意两次出示的所有“看似标识”的字段都必须两两不同。
	identityFields := func(s snapshot) [][]byte {
		out := [][]byte{s.showID, s.verifyKey, s.envSig, s.holderSig, s.assertSig}
		for _, c := range s.commits {
			out = append(out, c)
		}
		for _, sig := range s.tokenSigs {
			out = append(out, sig)
		}
		return out
	}
	for i := 0; i < len(snaps); i++ {
		for j := i + 1; j < len(snaps); j++ {
			a, b := identityFields(snaps[i]), identityFields(snaps[j])
			if len(a) != len(b) {
				// 两场景披露数量不同（1 vs 0 个属性），仅比较公共长度前缀无意义；
				// 直接比较所有组合。
			}
			for _, x := range a {
				for _, y := range b {
					if bytes.Equal(x, y) {
						t.Fatalf("repeatable correlation token across shows %d and %d: %x", i, j, x)
					}
				}
			}
			if snaps[i].sessionID == snaps[j].sessionID || bytes.Equal(snaps[i].nonce, snaps[j].nonce) {
				t.Fatalf("session correlated across shows %d and %d", i, j)
			}
		}
	}

	// 2) 长期标识与未披露值绝不能出现在任何 v2 证明的序列化字节中。
	longTerm := map[string][]byte{}
	for _, id := range credIDs {
		b, _ := hexDecode(id)
		longTerm["credID:"+id] = b
	}
	st0 := f.svc.Holder.lookup(credIDs[0])
	longTerm["holderVerifyKey"] = st0.Cred.Signed.HolderVerifyKey
	for _, sn := range snaps {
		for label, secret := range longTerm {
			if bytes.Contains(sn.raw, secret) {
				t.Fatalf("long-term marker %s leaked into a v2 presentation", label)
			}
		}
		if bytes.Contains(sn.raw, []byte("UnlinkablePerson")) {
			t.Fatal("undisclosed name value leaked into a v2 presentation")
		}
		if bytes.Contains(sn.raw, []byte(st0.Cred.Signed.Pseudonym)) {
			t.Fatal("holder pseudonym leaked into a v2 presentation")
		}
	}
}

// TestV2SameCredentialRepeatedShowsUnlinkable：单张凭证在不同场景重复出示，
// 每次公开材料全部换新。
func TestV2SameCredentialRepeatedShowsUnlinkable(t *testing.T) {
	f := newFixture(t, 2002)
	id := f.issue(t, goodAttrs())

	var shows [][]byte
	for i := 0; i < 5; i++ {
		res, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
		if err != nil {
			t.Fatal(err)
		}
		d, err := f.svc.Check(res.SessionID, res.Presentation)
		if err != nil || !d.Accepted {
			t.Fatalf("show %d: %v", i, err)
		}
		raw, _ := json.Marshal(res.Presentation)
		for _, prev := range shows {
			if bytes.Equal(prev, raw) {
				t.Fatalf("show %d serialized identically to a previous show", i)
			}
		}
		shows = append(shows, raw)
	}
}

// TestV2ReplayRejected：同一 v2 证明二次提交、以及跨会话重放，必须失败。
func TestV2ReplayRejected(t *testing.T) {
	f := newFixture(t, 2003)
	id := f.issue(t, goodAttrs())
	res, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if _, err := f.svc.Check(res.SessionID, res.Presentation); CodeOf(err) != CodeProofReplay {
		t.Fatalf("replay same session: %v", err)
	}
	other, err := f.svc.Verifier.NewSession("driving-entitlement", 1, v2Pol())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Check(other.ID, res.Presentation); CodeOf(err) != CodeProofReplay {
		t.Fatalf("cross-session replay: %v", err)
	}
}
