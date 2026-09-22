package anoncred

import (
	"testing"
	"time"
)

// 未成年凭证不持有 is_adult 令牌；持有者无法出示该谓词。
func TestPredicateNotIssuedWhenUnsatisfied(t *testing.T) {
	f := newFixture(t, 1000)
	attrs := map[string]Value{
		"name": StringValue("Kid"), "level": StringValue("C1"), "age": IntValue(17),
	}
	id := f.issue(t, attrs)

	// 持有者构造阶段就应失败：钱包中不存在 is_adult 令牌。
	res, err := f.svc.Prove(id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: time.Minute,
	}, nil, []string{"is_adult"})
	if CodeOf(err) != CodePredicateNotAllowed {
		t.Fatalf("want predicate_not_allowed at build time, got res=%v err=%v", res, err)
	}
}

// 边界：age=18 满足 >=18。
func TestPredicateBoundary(t *testing.T) {
	f := newFixture(t, 1001)
	attrs := map[string]Value{
		"name": StringValue("Edge"), "level": StringValue("C1"), "age": IntValue(18),
	}
	id := f.issue(t, attrs)
	if _, err := f.proveCheck(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: time.Minute,
	}, nil, []string{"is_adult"}); err != nil {
		t.Fatalf("age=18 should satisfy: %v", err)
	}
}

// 可选属性缺省也可以签发。
func TestOptionalAttributeOmitted(t *testing.T) {
	f := newFixture(t, 1002)
	id := f.issue(t, goodAttrs()) // 不含 country
	st := f.svc.Holder.lookup(id)
	if _, ok := st.Cred.Signed.Commitments["country"]; ok {
		t.Fatal("optional attribute must be absent when omitted")
	}
}

// BuildPresentation 拒绝空 nonce 与未知凭证。
func TestHolderBuildValidation(t *testing.T) {
	f := newFixture(t, 1003)
	id := f.issue(t, goodAttrs())
	h := f.svc.Holder

	if _, err := h.BuildPresentation(PresentRequest{CredIDHex: id}); CodeOf(err) != CodeMalformedPresentation {
		t.Fatalf("empty nonce: %v", err)
	}
	if _, err := h.BuildPresentation(PresentRequest{
		CredIDHex: "nope", SessionNonce: []byte{1},
	}); CodeOf(err) != CodeNoSuchCredential {
		t.Fatalf("unknown cred: %v", err)
	}
	// 披露一个凭证中不存在的属性。
	if _, err := h.BuildPresentation(PresentRequest{
		CredIDHex: id, SessionNonce: []byte{1, 2, 3}, DiscloseAttrs: []string{"country"},
	}); CodeOf(err) != CodeDisclosureNotAllowed {
		t.Fatalf("missing optional attr disclosure: %v", err)
	}
}

// Accept 拒绝与私钥不匹配的凭证。
func TestHolderAcceptMismatchedKey(t *testing.T) {
	f := newFixture(t, 1004)
	prep, err := f.svc.Holder.PrepareIssue(goodAttrs(), &IssueRequest{
		PolicyName: "driving-entitlement", PolicyVersion: 1, TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := f.svc.Issuer.Issue(*prep)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := edKeyForTest()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Holder.Accept(cred, f.svc.Issuer.ActivePublic(), otherPriv); CodeOf(err) != CodeBadHolderProof {
		t.Fatalf("want bad_holder_proof, got %v", err)
	}
}

// 结构不完整证明被拒绝。
func TestMalformedPresentation(t *testing.T) {
	f := newFixture(t, 1005)
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, VerifyPolicy{AllowAttrs: []string{"level"}, TTL: time.Minute},
		[]string{"level"}, nil)
	pres := clonePresentation(t, res.Presentation)
	pres.Signed.CredID = nil
	// 结构完整性检查先于签名检查；无需重签持有者证明。
	_, err := f.svc.Check(res.SessionID, pres)
	if CodeOf(err) != CodeMalformedPresentation {
		t.Fatalf("want malformed_presentation, got %v", err)
	}
}

// 非本凭证承诺替换：把另一凭证的 level 承诺换到本证明。
func TestForeignCommitmentSwap(t *testing.T) {
	f := newFixture(t, 1006)
	id1 := f.issue(t, goodAttrs())
	attrs2 := goodAttrs()
	attrs2["name"] = StringValue("Carol")
	id2 := f.issue(t, attrs2)

	// 用 id2 的证明外壳，但把 id1 会话绑定并替换披露值/盐以匹配 id2 的 level 承诺。
	res1 := f.proveRaw(t, id1, VerifyPolicy{AllowAttrs: []string{"level"}, TTL: time.Minute},
		[]string{"level"}, nil)
	res2 := f.proveRaw(t, id2, VerifyPolicy{AllowAttrs: []string{"level"}, TTL: time.Minute},
		[]string{"level"}, nil)

	pres := clonePresentation(t, res2.Presentation)
	// 重放到 id1 的会话 nonce 上：nonce 不匹配 -> replay；
	// 更直接：把 res2 的承诺与披露保持原样、只换 holder key 为 id1。
	_ = res1
	st1 := f.svc.Holder.lookup(id1)
	pres.Signed.HolderVerifyKey = st1.Cred.Signed.HolderVerifyKey
	// 主签名现在已失效（HolderVerifyKey 在主签名内），且没有原签发方签名，
	pres.HolderProof = edSign(st1.HolderSignK, pres.holderProofPayload())
	_, err := f.svc.Check(res2.SessionID, pres)
	if CodeOf(err) != CodeBadIssuerSignature {
		t.Fatalf("foreign commitment swap must fail issuer signature, got %v", err)
	}
}

// 持有者/签发方简单 API 冒烟。
func TestSimpleAccessors(t *testing.T) {
	f := newFixture(t, 1007)
	if f.svc.Holder.Pseudonym() != "local-holder" {
		t.Fatal("pseudonym")
	}
	id := f.issue(t, goodAttrs())
	if len(f.svc.Holder.CredentialIDs()) != 1 || f.svc.Holder.CredentialIDs()[0] != id {
		t.Fatal("credential ids")
	}
	idB, _ := hexDecode(id)
	if f.svc.Issuer.IsRevoked(idB) {
		t.Fatal("fresh credential should not be revoked")
	}
	if f.svc.Verifier.Session("missing") != nil {
		t.Fatal("missing session should be nil")
	}
	if s := f.svc.Verifier.Session(f.proveRaw(t, id, VerifyPolicy{
		AllowAttrs: []string{"level"}, TTL: time.Minute,
	}, []string{"level"}, nil).SessionID); s == nil {
		t.Fatal("existing session lookup")
	}
}
