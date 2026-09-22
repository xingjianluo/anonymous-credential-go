package anoncred

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// v2Policy: 在 v1 基础上新增必填属性 region；模式哈希必然不同。
func v2Policy(at time.Time) Policy {
	p := v1Policy(at)
	p.Version = 2
	p.Attributes = append(p.Attributes, AttributeSpec{
		Name: "region", Type: AttrString, Required: true, NonEmpty: true,
	})
	p.Predicates = append(p.Predicates, PredicateSpec{
		Name: "is_senior", Attr: "age", Op: PredGreaterEqual, Threshold: 65,
	})
	return p
}

// 历史版本默认保持可验证（显式登记的受信版本）。
func TestBackwardCompatibleVersions(t *testing.T) {
	f := newFixture(t, 700)
	idV1 := f.issue(t, goodAttrs())

	// 登记 v2 并切换签发版本；v1 凭证仍然可验证。
	mustReg(t, f.svc, v2Policy(f.start))
	if err := f.svc.Issuer.UseVersion(2); err != nil {
		t.Fatal(err)
	}
	attrsV2 := goodAttrs()
	attrsV2["region"] = StringValue("North")
	idV2, err := f.svc.IssueAndHold(IssueRequest{
		PolicyName:    "driving-entitlement",
		PolicyVersion: 2,
		Attributes:    attrsV2,
		TTL:           time.Hour,
	})
	if err != nil {
		t.Fatalf("issue v2: %v", err)
	}

	pol1 := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}
	d1, err := f.proveCheck(t, idV1, pol1, nil, []string{"is_adult"})
	if err != nil || !d1.Accepted {
		t.Fatalf("v1 credential should still verify: %v", err)
	}
	if d1.PolicyVersion != 1 {
		t.Fatalf("v1 decision version = %d", d1.PolicyVersion)
	}

	d2, err := f.proveCheck(t, idV2, VerifyPolicy{
		AllowPredicates: []string{"is_adult", "is_senior"},
		TTL:             time.Minute,
	}, nil, []string{"is_adult"})
	if err != nil || !d2.Accepted {
		t.Fatalf("v2 credential should verify: %v", err)
	}
	if d2.PolicyVersion != 2 {
		t.Fatalf("v2 decision version = %d", d2.PolicyVersion)
	}
}

// 未知版本绝不能被静默接受：无法建立会话。
func TestUnknownVersionRejected(t *testing.T) {
	f := newFixture(t, 701)
	_, err := f.svc.Verifier.NewSession("driving-entitlement", 99, VerifyPolicy{TTL: time.Minute})
	if CodeOf(err) != CodeUnknownVersion {
		t.Fatalf("want unknown_version, got %v", err)
	}
}

// 版本日落：显式 RejectVersion 后，历史凭证按明确规则被拒绝。
func TestVersionSunsetRejection(t *testing.T) {
	f := newFixture(t, 702)
	idV1 := f.issue(t, goodAttrs())

	mustReg(t, f.svc, v2Policy(f.start))
	if err := f.svc.Trust.RejectVersion("driving-entitlement", 1); err != nil {
		t.Fatal(err)
	}

	// 已日落版本无法开新会话。
	if _, err := f.svc.Verifier.NewSession("driving-entitlement", 1,
		VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}); CodeOf(err) != CodeVersionRejected {
		t.Fatalf("session for sunset version: %v", err)
	}

	// 即使会话在日落前已创建，提交证明时同样必须按日落规则拒绝。
	res := f.sunsetProve(t, idV1)
	if err := f.svc.Trust.RejectVersion("driving-entitlement", 1); err != nil {
		t.Fatal(err)
	}
	_, err := f.svc.Check(res.SessionID, res.Presentation)
	if CodeOf(err) != CodeVersionRejected {
		t.Fatalf("want version_rejected, got %v", err)
	}
}

// sunsetProve 在（可能已日落的）v1 上手动建立会话与证明，绕过 NewSession 的早期拒绝。
func (f *fixture) sunsetProve(t *testing.T, id string) *ProveResult {
	t.Helper()
	nonce, err := f.svc.Verifier.randomNonce()
	if err != nil {
		t.Fatal(err)
	}
	pres, err := f.svc.Holder.BuildPresentation(PresentRequest{
		CredIDHex:     id,
		SessionNonce:  nonce,
		DisclosePreds: []string{"is_adult"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Verifier.mu.Lock()
	sess := &Session{
		ID:        hexEncode(nonce[:16]),
		Nonce:     nonce,
		Issuer:    "driving-entitlement",
		Version:   1,
		Policy:    VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute},
		CreatedAt: f.clock.Now(),
		ExpiresAt: f.clock.Now().Add(time.Minute),
	}
	f.svc.Verifier.sessions[sess.ID] = sess
	f.svc.Verifier.mu.Unlock()
	return &ProveResult{SessionID: sess.ID, Presentation: pres}
}

// 同版本参数不兼容：凭证模式指纹与受信参数不同时必须拒绝。
func TestIncompatibleParameters(t *testing.T) {
	f := newFixture(t, 703)
	id := f.issue(t, goodAttrs())

	// 用“版本号同为 1、但模式定义漂移”的档案覆盖信任登记。
	drift := v2Policy(f.start)
	drift.Version = 1
	// 保留原签发方公钥，使失败精确归因于参数不兼容而非签名伪造。
	origPub := f.svc.Issuer.ActivePublic()
	f.svc.Trust.Register(TrustProfile{
		IssuerName: "driving-entitlement",
		Public: IssuerPublic{
			Policy:       drift,
			VerifyingKey: origPub.VerifyingKey,
			SchemaHash:   drift.SchemaHash(),
		},
	})

	res := f.proveRaw(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: time.Minute,
	}, nil, []string{"is_adult"})
	_, err := f.svc.Check(res.SessionID, res.Presentation)
	if CodeOf(err) != CodeIncompatibleParameters {
		t.Fatalf("want incompatible_parameters, got %v", err)
	}
}

// 凭证版本与会话版本不匹配：v1 证明提交给 v2 会话。
func TestSessionCredentialVersionMismatch(t *testing.T) {
	f := newFixture(t, 704)
	idV1 := f.issue(t, goodAttrs())
	mustReg(t, f.svc, v2Policy(f.start))
	if err := f.svc.Issuer.UseVersion(2); err != nil {
		t.Fatal(err)
	}

	sess, err := f.svc.Verifier.NewSession("driving-entitlement", 2, VerifyPolicy{
		AllowPredicates: []string{"is_adult", "is_senior"}, TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	pres, err := f.svc.Holder.BuildPresentation(PresentRequest{
		CredIDHex:     idV1,
		SessionNonce:  sess.Nonce,
		DisclosePreds: []string{"is_adult"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.Check(sess.ID, pres)
	if CodeOf(err) != CodeIncompatibleParameters {
		t.Fatalf("want incompatible_parameters, got %v", err)
	}
}

// 谓词令牌参数被替换（例如把阈值 18 改成 0）必须失败。
func TestPredicateTokenTampering(t *testing.T) {
	f := newFixture(t, 705)
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: time.Minute,
	}, nil, []string{"is_adult"})
	pres := clonePresentation(t, res.Presentation)
	pres.Predicates[0].Token.Threshold = 0
	// 用伪造密钥给篡改后的令牌重签也不行：验证方只信任签发方公钥。
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	tok := pres.Predicates[0].Token
	tok.Signature = ed25519.Sign(priv, predPayload(
		pres.Signed.CredID, tok.Name, tok.Attr, tok.Op, tok.Threshold, tok.StrValue))
	pres.Predicates[0].Token = tok
	resignHolder(t, f, pres)

	_, err := f.svc.Check(res.SessionID, pres)
	// 参数先与策略定义不符 -> incompatible；即便绕过，签名也会失败。
	c := CodeOf(err)
	if c != CodeIncompatibleParameters && c != CodeBadIssuerSignature {
		t.Fatalf("want incompatible_parameters or bad_issuer_signature, got %v", err)
	}
}
