package anoncred

import (
	"sync"
	"testing"
	"time"
)

// TestConcurrentVerifyAndRevokeLinearizable: 同一凭证上并发校验与一次吊销，
// 结论必须是“吊销前可接受 / 吊销后必拒绝”的某种线性化交错，
// 且重复运行、竞态检测下不出现矛盾结论。
func TestConcurrentVerifyAndRevokeLinearizable(t *testing.T) {
	const verifyN = 16
	for iter := 0; iter < 30; iter++ {
		f := newFixture(t, uint64(500+iter))
		id := f.issue(t, goodAttrs())

		pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}
		type res struct {
			accepted bool
			code     Code
		}
		out := make([]res, verifyN)
		ready := make([]*ProveResult, verifyN)
		for i := range ready {
			ready[i] = f.proveRaw(t, id, pol, nil, []string{"is_adult"})
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < verifyN; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				d, err := f.svc.Check(ready[i].SessionID, ready[i].Presentation)
				if err != nil {
					out[i] = res{code: CodeOf(err)}
				} else {
					out[i] = res{accepted: d.Accepted}
				}
			}(i)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = f.svc.Revoke(id, "race")
		}()
		close(start)
		wg.Wait()

		var accept, revoke, replay, other int
		for _, r := range out {
			switch {
			case r.accepted:
				accept++
			case r.code == CodeRevokedCredential:
				revoke++
			case r.code == CodeProofReplay:
				replay++
			default:
				other++
			}
		}
		if replay != 0 || other != 0 {
			t.Fatalf("iter %d: unexpected codes (accept=%d revoked=%d replay=%d other=%d)",
				iter, accept, revoke, replay, other)
		}
		if accept+revoke != verifyN {
			t.Fatalf("iter %d: results not partitioned: accept=%d revoked=%d", iter, accept, revoke)
		}
		// 最终状态：已吊销；此后任何新证明必须失败。
		if _, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"}); CodeOf(err) != CodeRevokedCredential {
			t.Fatalf("iter %d: post-race verification not rejected", iter)
		}
	}
}

// TestRevocationEpochDoesNotBreakOthers: 吊销 A 凭证不应影响 B 凭证后续校验，
// 但与吊销并发进行中的校验允许保守拒绝（纪元窗口规则）。
func TestRevocationEpochDoesNotBreakOthers(t *testing.T) {
	f := newFixture(t, 600)
	a := f.issue(t, goodAttrs())
	attrsB := goodAttrs()
	attrsB["name"] = StringValue("Bob")
	b := f.issue(t, attrsB)

	if err := f.svc.Revoke(a, "a-only"); err != nil {
		t.Fatal(err)
	}
	pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}
	d, err := f.proveCheck(t, b, pol, nil, []string{"is_adult"})
	if err != nil {
		t.Fatalf("unrelated credential B must still verify after A epoch change: %v", err)
	}
	if !d.Accepted {
		t.Fatal("B decision not accepted")
	}
}
