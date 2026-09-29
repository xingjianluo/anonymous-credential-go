package anoncred

import (
	"bytes"
	"testing"
	"time"
)

// TestV2RevocationImmediate: v2 凭证撤销前可验证；撤销开始后新出示必须立即失败。
func TestV2RevocationImmediate(t *testing.T) {
	f := newV2Fixture(t, 2200)
	id := f.issueLongTTL(t, goodAttrs())
	pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}

	if _, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"}); err != nil {
		t.Fatalf("before revoke: %v", err)
	}
	if err := f.svc.Revoke(id, "v2-revoke"); err != nil {
		t.Fatal(err)
	}
	_, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"})
	if CodeOf(err) != CodeRevokedCredential {
		t.Fatalf("want revoked_credential, got %v", err)
	}
}

// TestV2RevokingOneDoesNotAffectOtherCredentials:
// 一张 v2 凭证被撤销，不得误伤同一持有者其他仍然有效的凭证；
// 新窗口内其他凭证必须继续接受。
func TestV2RevokingOneDoesNotAffectOtherCredentials(t *testing.T) {
	f := newV2Fixture(t, 2201)
	a := f.issueLongTTL(t, goodAttrs())
	attrsB := goodAttrs()
	attrsB["name"] = StringValue("Bob")
	b := f.issueLongTTL(t, attrsB)
	c := f.issueLongTTL(t, goodAttrs())

	if err := f.svc.Revoke(b, "only-b"); err != nil {
		t.Fatal(err)
	}
	pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}
	if _, err := f.proveCheck(t, a, pol, nil, []string{"is_adult"}); err != nil {
		t.Fatalf("credential A must still verify: %v", err)
	}
	if _, err := f.proveCheck(t, c, pol, nil, []string{"is_adult"}); err != nil {
		t.Fatalf("credential C must still verify: %v", err)
	}
	if _, err := f.proveCheck(t, b, pol, nil, []string{"is_adult"}); CodeOf(err) != CodeRevokedCredential {
		t.Fatalf("B must be revoked, got %v", err)
	}
}

// TestV2RevocationCheckIsNotTrackable:
// 撤销核对本身不得把多次出示串起来——审计日志中 v2 行只能出现每次随机的 show_id，
// 绝不能出现 cred_id；多次撤销核对后的日志不包含可复用的长期标识。
func TestV2RevocationCheckIsNotTrackable(t *testing.T) {
	f := newV2Fixture(t, 2202)
	id := f.issueLongTTL(t, goodAttrs())
	pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}

	for i := 0; i < 3; i++ {
		if _, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"}); err != nil {
			t.Fatalf("show %d: %v", i, err)
		}
	}
	if err := f.svc.Revoke(id, "untraceable"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"}); CodeOf(err) != CodeRevokedCredential {
		t.Fatal("post-revoke show must fail")
	}

	// 撤销“事件”本身允许签发方记录 cred_id（用于管理审计）；
	// 但任何 verify 事件行都不得携带 cred_id——撤销核对不得成为追踪渠道。
	// 校验所有 verify 行：cred_id 必须是空串，show_id 每次不同。
	lines := decodeLogLines(t, f.logs.Bytes())
	var showIDs []string
	for _, m := range lines {
		if m["event"] != "verify" {
			continue
		}
		if m["cred_id"] != "" {
			t.Fatalf("v2 verify log must not carry cred_id: %v", m["cred_id"])
		}
		sid, _ := m["show_id"].(string)
		if sid == "" {
			t.Fatalf("v2 verify log missing show_id: %v", m)
		}
		for _, prev := range showIDs {
			if prev == sid {
				t.Fatalf("show_id repeated across revocation checks: %s", sid)
			}
		}
		showIDs = append(showIDs, sid)
	}
	if len(showIDs) != 4 {
		t.Fatalf("want 4 verify log lines, got %d", len(showIDs))
	}

}

// TestV2ForgedRouteTagRejected: 伪造路由标签（找不到对应凭证）必须拒绝，
// 且错误与“已撤销”可区分。
func TestV2ForgedRouteTagRejected(t *testing.T) {
	f := newV2Fixture(t, 2203)
	id := f.issueLongTTL(t, goodAttrs())
	// 构造一个结构完全合法、但路由标签与任何签发记录都不匹配的信封，
	// 直接请求签发方背书：持有者授权签名由真实凭证密钥完成，
	// 但签发方在记录集中找不到匹配 -> showing_rejected（与 revoked 可区分）。
	st := f.svc.Holder.lookup(id)
	showPub, showPriv, _ := edKeyForTest()
	_ = showPriv
	nonce := []byte("session-nonce-for-forged-route-test")
	showID := []byte("show-id-for-forged-route-test--")
	env := &ShowingEnvelope{
		FormatVersion: ShowingFormatV2,
		PolicyName:    "driving-entitlement",
		PolicyVersion: 1,
		ShowID:        showID,
		RouteTag:      bytes.Repeat([]byte{0xAB}, 32),
		HolderShowKey: showPub,
		SessionNonce:  nonce,
		Predicates:    []string{"is_adult"},
		NotBefore:     f.clock.Now(),
		ExpiresAt:     f.clock.Now().Add(time.Hour),
		GeneratedAt:   f.clock.Now(),
	}
	env.HolderAuth = edSign(st.HolderSignK, env.holderAuthPayload())
	_, err := f.svc.Issuer.AttestShowing(env)
	if CodeOf(err) != CodeShowingRejected {
		t.Fatalf("want showing_rejected, got %v", err)
	}
}
