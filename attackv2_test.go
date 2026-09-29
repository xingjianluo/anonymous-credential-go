package anoncred

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// 篡改 v2 披露值：与封套新鲜承诺不符 -> tampered_disclosure。
func TestV2TamperedDisclosure(t *testing.T) {
	f := newFixture(t, 2200)
	id := f.issue(t, goodAttrs())
	res, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	pres := clonePresentation(t, res.Presentation)
	pres.Disclosed[0].Value = StringValue("C2")
	st := f.svc.Holder.lookup(id)
	// 用当次出示私钥重签（模拟持有者篡改后自行重签）。
	pres.HolderProof = ed25519.Sign(st.HolderSignK, pres.holderProofPayloadV2())
	if _, err := f.svc.Check(res.SessionID, pres); CodeOf(err) != CodeTamperedDisclosure {
		t.Fatalf("want tampered_disclosure, got %v", err)
	}
}

// 完全伪造封套签名 -> bad_show_envelope。
func TestV2ForgedEnvelope(t *testing.T) {
	f := newFixture(t, 2201)
	id := f.issue(t, goodAttrs())
	res, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	pres := clonePresentation(t, res.Presentation)
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	pres.Envelope.Signature = ed25519.Sign(attackerPriv, pres.Envelope.signPayload())
	if _, err := f.svc.Check(res.SessionID, pres); CodeOf(err) != CodeBadShowEnvelope {
		t.Fatalf("want bad_show_envelope, got %v", err)
	}
}

// 伪造持有者当次证明 -> bad_holder_proof。
func TestV2ForgedHolderProof(t *testing.T) {
	f := newFixture(t, 2202)
	id := f.issue(t, goodAttrs())
	res, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	pres := clonePresentation(t, res.Presentation)
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	pres.HolderProof = ed25519.Sign(attackerPriv, pres.holderProofPayloadV2())
	if _, err := f.svc.Check(res.SessionID, pres); CodeOf(err) != CodeBadHolderProof {
		t.Fatalf("want bad_holder_proof, got %v", err)
	}
}

// 伪造撤销断言 -> 拒绝。
func TestV2ForgedAssertion(t *testing.T) {
	f := newFixture(t, 2203)
	id := f.issue(t, goodAttrs())
	res, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	pres := clonePresentation(t, res.Presentation)
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	pres.Assertion.Signature = ed25519.Sign(attackerPriv, pres.Assertion.payload())
	if _, err := f.svc.Check(res.SessionID, pres); CodeOf(err) != CodeRevokedCredential {
		t.Fatalf("forged assertion must be rejected as revoked/unsafe, got %v", err)
	}
}

// v2 证明中混入 legacy 字段（CredID/旧令牌）必须被结构混用防线拒绝。
func TestV2MustNotCarryLegacyFields(t *testing.T) {
	f := newFixture(t, 2204)
	id := f.issue(t, goodAttrs())
	res, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	pres := clonePresentation(t, res.Presentation)
	pres.Signed.CredID = []byte{1, 2, 3, 4}
	if _, err := f.svc.Check(res.SessionID, pres); CodeOf(err) != CodeBadShowEnvelope {
		t.Fatalf("mixed v2/legacy fields: %v", err)
	}
}

// 越权披露在 v2 下同样被拒（会话只允许谓词，却披露 level）。
func TestV2UnauthorizedDisclosure(t *testing.T) {
	f := newFixture(t, 2205)
	id := f.issue(t, goodAttrs())
	pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}
	res, err := f.svc.ProveUnlinkable(id, pol, []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Check(res.SessionID, res.Presentation); CodeOf(err) != CodeDisclosureNotAllowed {
		t.Fatalf("want disclosure_not_allowed, got %v", err)
	}
}

// 非持有者无法申请 v2 出示：申请鉴权签名用错密钥。
func TestV2ShowRequestAuthRequired(t *testing.T) {
	f := newFixture(t, 2206)
	id := f.issue(t, goodAttrs())
	sess, err := f.svc.Verifier.NewSession("driving-entitlement", 1, v2Pol())
	if err != nil {
		t.Fatal(err)
	}
	prep, err := f.svc.Holder.PrepareUnlinkableShow(id, sess.Nonce, []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, _ := edKeyForTest()
	bad := prep.Request
	bad.ShowAuth = ed25519.Sign(otherPriv, showAuthPayload(&bad))
	if _, err := f.svc.Issuer.PrepareShow(bad); CodeOf(err) != CodeBadHolderProof {
		t.Fatalf("want bad_holder_proof on forged show request, got %v", err)
	}
}
