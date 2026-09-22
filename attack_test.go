package anoncred

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sessionPolicy() VerifyPolicy {
	return VerifyPolicy{
		AllowAttrs:      []string{"name", "level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}
}

// 篡改披露值：承诺校验必须失败。
func TestTamperedDisclosure(t *testing.T) {
	f := newFixture(t, 21)
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, sessionPolicy(), []string{"level"}, []string{"is_adult"})

	// 修改披露值（C1 -> C2），盐不变。
	pres := clonePresentation(t, res.Presentation)
	pres.Disclosed[0].Value = StringValue("C2")
	resignHolder(t, f, pres)

	_, err := f.svc.Check(res.SessionID, pres)
	if CodeOf(err) != CodeTamperedDisclosure {
		t.Fatalf("want tampered_disclosure, got %v", err)
	}
}

// 篡改盐同样必须失败。
func TestTamperedSalt(t *testing.T) {
	f := newFixture(t, 22)
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, sessionPolicy(), []string{"level"}, nil)
	pres := clonePresentation(t, res.Presentation)
	pres.Disclosed[0].Salt[0] ^= 0xFF
	resignHolder(t, f, pres)
	_, err := f.svc.Check(res.SessionID, pres)
	if CodeOf(err) != CodeTamperedDisclosure {
		t.Fatalf("want tampered_disclosure, got %v", err)
	}
}

// 篡改已签名字段（例如承诺）：签发方主签名失败。
func TestTamperedCommitment(t *testing.T) {
	f := newFixture(t, 23)
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, sessionPolicy(), []string{"level"}, nil)
	pres := clonePresentation(t, res.Presentation)
	for k := range pres.Signed.Commitments {
		pres.Signed.Commitments[k][0] ^= 0x01
	}
	resignHolder(t, f, pres)
	_, err := f.svc.Check(res.SessionID, pres)
	if CodeOf(err) != CodeBadIssuerSignature {
		t.Fatalf("want bad_issuer_signature, got %v", err)
	}
}

// 完全伪造的凭证：签发方公钥校验失败。
func TestForgedCredential(t *testing.T) {
	f := newFixture(t, 24)
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, sessionPolicy(), []string{"level"}, nil)
	pres := clonePresentation(t, res.Presentation)

	// 攻击者生成自己的密钥并替换凭证签名。
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	pres.Signed.Signature = ed25519.Sign(priv, pres.Signed.signPayload())
	resignHolder(t, f, pres)
	_, err := f.svc.Check(res.SessionID, pres)
	if CodeOf(err) != CodeBadIssuerSignature {
		t.Fatalf("want bad_issuer_signature, got %v", err)
	}
}

// 伪造持有者证明：用非凭证绑定密钥签名必须失败。
func TestForgedHolderProof(t *testing.T) {
	f := newFixture(t, 25)
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, sessionPolicy(), []string{"level"}, nil)
	pres := clonePresentation(t, res.Presentation)
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	pres.HolderProof = ed25519.Sign(attackerPriv, pres.holderProofPayload())
	_, err := f.svc.Check(res.SessionID, pres)
	if CodeOf(err) != CodeBadHolderProof {
		t.Fatalf("want bad_holder_proof, got %v", err)
	}
}

// 重放：同一证明第二次使用必须失败。
func TestReplaySameSession(t *testing.T) {
	f := newFixture(t, 26)
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, sessionPolicy(), []string{"level"}, nil)
	if _, err := f.svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err := f.svc.Check(res.SessionID, res.Presentation)
	if CodeOf(err) != CodeProofReplay {
		t.Fatalf("want proof_replay, got %v", err)
	}
}

// 跨会话重放：把证明发到另一个会话（nonce 不同）必须失败。
func TestReplayCrossSession(t *testing.T) {
	f := newFixture(t, 27)
	id := f.issue(t, goodAttrs())
	res1 := f.proveRaw(t, id, sessionPolicy(), []string{"level"}, nil)
	if _, err := f.svc.Check(res1.SessionID, res1.Presentation); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	// 第二个会话；构造一个绑定新 nonce 的会话，但沿用旧证明。
	sess2, err := f.svc.Verifier.NewSession(f.svc.Issuer.name, 1, sessionPolicy())
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.Check(sess2.ID, res1.Presentation)
	if CodeOf(err) != CodeProofReplay {
		t.Fatalf("want proof_replay for cross-session, got %v", err)
	}
}

// 越权披露：会话不允许的属性/谓词不能出现在证明中。
func TestUnauthorizedDisclosure(t *testing.T) {
	f := newFixture(t, 28)
	id := f.issue(t, goodAttrs())

	// 会话只允许 level；持有者尝试披露 name。
	res := f.proveRaw(t, id, VerifyPolicy{
		AllowAttrs: []string{"level"},
		TTL:        time.Minute,
	}, []string{"name"}, nil)
	_, err := f.svc.Check(res.SessionID, res.Presentation)
	if CodeOf(err) != CodeDisclosureNotAllowed {
		t.Fatalf("want disclosure_not_allowed, got %v", err)
	}

	// 会话只允许 level；持有者尝试出示谓词。
	res2 := f.proveRaw(t, id, VerifyPolicy{
		AllowAttrs: []string{"level"},
		TTL:        time.Minute,
	}, []string{"level"}, []string{"is_adult"})
	_, err = f.svc.Check(res2.SessionID, res2.Presentation)
	if CodeOf(err) != CodePredicateNotAllowed {
		t.Fatalf("want predicate_not_allowed, got %v", err)
	}
}

// 未披露属性值不得出现在对外证明的任何序列化字节中。
func TestUndisclosedValuesNeverLeak(t *testing.T) {
	f := newFixture(t, 29)
	attrs := map[string]Value{
		"name":    StringValue("SecretNameXYZ"),
		"level":   StringValue("C1"),
		"age":     IntValue(29),
		"country": StringValue("Atlantis"),
	}
	id := f.issue(t, attrs)
	res := f.proveRaw(t, id, VerifyPolicy{
		AllowAttrs:      []string{"level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}, []string{"level"}, []string{"is_adult"})

	raw, err := json.Marshal(res.Presentation)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"SecretNameXYZ", "Atlantis"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Fatalf("undisclosed value %q leaked into presentation: %s", leak, raw)
		}
	}
	// 年龄明文 29 也不得出现；年龄只以谓词阈值 18 暴露。
	if strings.Contains(string(raw), "\"Int\":29") {
		t.Fatalf("undisclosed age leaked: %s", raw)
	}
}

// 未知会话 / 会话过期。
func TestSessionLifecycle(t *testing.T) {
	f := newFixture(t, 30)
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, sessionPolicy(), []string{"level"}, nil)

	if _, err := f.svc.Check("deadbeef", res.Presentation); CodeOf(err) != CodeSessionUnknown {
		t.Fatalf("want session_unknown, got %v", err)
	}

	// 先创建短 TTL 会话并生成证明，再推进时钟：会话过期但凭证仍在有效期内。
	res2 := f.proveRaw(t, id, VerifyPolicy{
		AllowAttrs: []string{"level"},
		TTL:        time.Minute,
	}, []string{"level"}, nil)
	f.clock.Advance(2 * time.Minute)
	_, err := f.svc.Check(res2.SessionID, res2.Presentation)
	if CodeOf(err) != CodeSessionExpired {
		t.Fatalf("want session_expired, got %v", err)
	}
	// 时钟回位，避免影响后续（本测试为最后用例，无需回位）。
}

// --- helpers ----------------------------------------------------------------

// clonePresentation 深拷贝证明，便于篡改而不污染原对象。
func clonePresentation(t *testing.T, p *Presentation) *Presentation {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var cp Presentation
	if err := json.Unmarshal(raw, &cp); err != nil {
		t.Fatal(err)
	}
	return &cp
}

// resignHolder 用钱包中对应凭证的持有者私钥重签持有者证明。
// 篡改已签名字段（承诺/值）后，即便持有者证明合法，签发方主签名或承诺
// 校验仍必须失败；此助手让测试能深入到对应拒绝层。
func resignHolder(t *testing.T, f *fixture, p *Presentation) {
	t.Helper()
	credIDHex := hexEncode(p.Signed.CredID)
	st := f.svc.Holder.lookup(credIDHex)
	if st == nil {
		t.Fatalf("wallet missing credential %s", credIDHex)
	}
	p.HolderProof = ed25519.Sign(st.HolderSignK, p.holderProofPayload())
}
