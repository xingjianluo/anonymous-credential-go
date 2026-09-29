package anoncred

import (
	"testing"
	"time"
)

// 兼容窗口内：旧版（可关联）出示仍可验证。
func TestLegacyAcceptedWithinWindow(t *testing.T) {
	f := newFixture(t, 2400)
	id := f.issue(t, goodAttrs())
	cut := f.start.Add(time.Hour)
	if err := f.svc.Trust.SetLegacyWindow("driving-entitlement", 1, cut); err != nil {
		t.Fatal(err)
	}
	// 窗口内（现在 = start）。
	if _, err := f.proveCheck(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: time.Minute,
	}, nil, []string{"is_adult"}); err != nil {
		t.Fatalf("legacy within window: %v", err)
	}
	// v2 始终可用，不受窗口影响。
	if _, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"}); err != nil {
		t.Fatalf("v2 prepare within window: %v", err)
	}
}

// 兼容窗口结束：旧版出示被明确拒绝（legacy_presentation_rejected），
// 而 v2 不可关联出示继续可用。
func TestLegacyRejectedAfterWindow(t *testing.T) {
	f := newFixture(t, 2401)
	id := f.issue(t, goodAttrs())
	cut := f.start.Add(30 * time.Minute)
	if err := f.svc.Trust.SetLegacyWindow("driving-entitlement", 1, cut); err != nil {
		t.Fatal(err)
	}

	// 窗口结束前先备好一个旧版证明（会话也在此时创建）。
	res := f.proveRaw(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: time.Hour,
	}, nil, []string{"is_adult"})

	f.clock.Advance(31 * time.Minute) // 越过窗口终点，会话仍未过期

	if _, err := f.svc.Check(res.SessionID, res.Presentation); CodeOf(err) != CodeLegacyRejected {
		t.Fatalf("legacy after window: %v", err)
	}

	// 同一时刻、同一凭证的 v2 出示照常通过。
	d, err := func() (*Decision, error) {
		r, err := f.svc.ProveUnlinkable(id, VerifyPolicy{
			AllowPredicates: []string{"is_adult"}, TTL: time.Minute,
		}, nil, []string{"is_adult"})
		if err != nil {
			t.Fatal(err)
		}
		return f.svc.Check(r.SessionID, r.Presentation)
	}()
	if err != nil || !d.Accepted {
		t.Fatalf("v2 must remain accepted after legacy window: d=%+v err=%v", d, err)
	}
}

// 未设置窗口（零值）：旧版一直可验证，保持向后兼容默认行为。
func TestLegacyDefaultNoWindow(t *testing.T) {
	f := newFixture(t, 2402)
	id := f.issue(t, goodAttrs())
	f.clock.Advance(24 * time.Hour) // 凭证 TTL 仅 1h，会先过期，故换新凭证
	id2 := f.issue(t, goodAttrs())
	_ = id
	if _, err := f.proveCheck(t, id2, VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: time.Minute,
	}, nil, []string{"is_adult"}); err != nil {
		t.Fatalf("legacy should still be accepted with no window: %v", err)
	}
}
