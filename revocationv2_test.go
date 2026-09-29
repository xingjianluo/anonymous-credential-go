package anoncred

import (
	"testing"
	"time"
)

// trackingRevocationSource 包装真实撤销源，记录验证侧发起的调用。
type trackingRevocationSource struct {
	inner        RevocationSource
	epochCalls   int
	idQueryCalls int
}

func (t *trackingRevocationSource) IsRevoked(credID []byte) bool {
	t.idQueryCalls++
	return t.inner.IsRevoked(credID)
}

func (t *trackingRevocationSource) RevocationSnapshot(credID []byte) RevocationState {
	t.idQueryCalls++
	return t.inner.RevocationSnapshot(credID)
}

func (t *trackingRevocationSource) RevocationEpoch() uint64 {
	t.epochCalls++
	return t.inner.RevocationEpoch()
}

// TestV2RevocationCheckIsNotTrackable：v2 校验全程只能读取无标识的全局纪元，
// 绝不允许按长期 CredID 查询撤销状态——否则撤销检查本身就能串联多次出示。
func TestV2RevocationCheckIsNotTrackable(t *testing.T) {
	f := newFixture(t, 2100)
	id := f.issue(t, goodAttrs())

	tracker := &trackingRevocationSource{inner: f.svc.Issuer}
	f.svc.Verifier.WithRevocationSource(tracker)

	for i := 0; i < 3; i++ {
		res, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.Check(res.SessionID, res.Presentation); err != nil {
			t.Fatalf("show %d verify: %v", i, err)
		}
	}
	if tracker.idQueryCalls != 0 {
		t.Fatalf("v2 verification performed %d trackable by-id revocation queries", tracker.idQueryCalls)
	}
	if tracker.epochCalls == 0 {
		t.Fatal("v2 verification should still consult the identifier-free epoch")
	}
}

// TestV2RevocationImmediate：撤销前出具的证明在撤销开始后提交必须失败；
// 撤销之后的新出示（申请阶段）也必须失败。
func TestV2RevocationImmediate(t *testing.T) {
	f := newFixture(t, 2101)
	id := f.issue(t, goodAttrs())

	// 撤销前完成的一次验证可以接受。
	before, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Check(before.SessionID, before.Presentation); err != nil {
		t.Fatalf("pre-revoke verify: %v", err)
	}

	// 撤销前准备好、撤销后才提交的证明：断言纪元已过期 -> 拒绝。
	inflight, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Revoke(id, "compromised"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Check(inflight.SessionID, inflight.Presentation); CodeOf(err) != CodeRevokedCredential {
		t.Fatalf("in-flight presentation after revoke: %v", err)
	}

	// 撤销之后的任何新出示：在签发方申请阶段就被拒绝。
	if _, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"}); CodeOf(err) != CodeRevokedCredential {
		t.Fatalf("new show after revoke should be rejected at prepare time: %v", err)
	}
}

// TestV2RevocationDoesNotCollateralOthers：一张凭证被撤销不影响其他有效凭证
// 在新窗口内的 v2 出示（不同 ShowID、不同断言、独立纪元窗口）。
func TestV2RevocationDoesNotCollateralOthers(t *testing.T) {
	f := newFixture(t, 2102)
	a := f.issue(t, goodAttrs())
	attrsB := goodAttrs()
	attrsB["name"] = StringValue("Bob")
	b := f.issue(t, attrsB)

	if err := f.svc.Revoke(a, "a-only"); err != nil {
		t.Fatal(err)
	}
	// B 在 A 已撤销后新开会话出示：断言纪元已包含 A 的撤销，但前后一致，
	// 且 B 自身有效——必须接受。
	resB, err := f.svc.ProveUnlinkable(b, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatalf("prepare show for B: %v", err)
	}
	d, err := f.svc.Check(resB.SessionID, resB.Presentation)
	if err != nil || !d.Accepted {
		t.Fatalf("unrelated valid credential B must still verify: d=%+v err=%v", d, err)
	}

	// 而在 B 的校验窗口中若再撤销（与校验并发的另一次吊销），B 也应保守拒绝。
	inflightB, err := f.svc.ProveUnlinkable(b, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	// 再签发一张并撤销，制造“窗口内纪元推进但与 B 无关”的交错。
	c := f.issue(t, goodAttrs())
	if err := f.svc.Revoke(c, "during-window"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Check(inflightB.SessionID, inflightB.Presentation); CodeOf(err) != CodeRevokedCredential {
		t.Fatalf("unrelated epoch change within window must conservatively reject: %v", err)
	}
	// 再开一个全新窗口（无并发撤销）后 B 又恢复可验证。
	resB2, err := f.svc.ProveUnlinkable(b, v2Pol(), []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	if d, err := f.svc.Check(resB2.SessionID, resB2.Presentation); err != nil || !d.Accepted {
		t.Fatalf("B should verify again in a fresh clean window: d=%+v err=%v", d, err)
	}
}

// TestV2ShowEnvelopeExpiry：封套自身过期也必须拒绝（凭证仍有效）。
func TestV2ShowEnvelopeExpiry(t *testing.T) {
	f := newFixture(t, 2103)
	id := f.issue(t, goodAttrs())
	pol := v2Pol()
	pol.TTL = maxShowTTL + time.Minute // 会话寿命长于封套，隔离封套过期判定
	res, err := f.svc.ProveUnlinkable(id, pol, []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(defaultShowTTL + time.Second)
	if _, err := f.svc.Check(res.SessionID, res.Presentation); CodeOf(err) != CodeExpiredCredential {
		t.Fatalf("expired show envelope: %v", err)
	}
}
