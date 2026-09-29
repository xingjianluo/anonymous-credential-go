package anoncred

import (
	"sync"
	"testing"
)

// 多个验证方对同一凭证的多张当次证明并发校验，期间穿插一次撤销：
// 结论必须是“撤销前接受 / 撤销开始后拒绝”的线性化划分，
// 每个会话最多接受一次，不串号、不丢状态。
func TestV2ConcurrentVerifiersRevokeInterleaved(t *testing.T) {
	const verifyN = 24
	for iter := 0; iter < 20; iter++ {
		f := newFixture(t, uint64(2500+iter))
		id := f.issue(t, goodAttrs())

		pol := v2Pol()
		ready := make([]*ProveResult, verifyN)
		for i := range ready {
			r, err := f.svc.ProveUnlinkable(id, pol, []string{"level"}, []string{"is_adult"})
			if err != nil {
				t.Fatal(err)
			}
			ready[i] = r
		}

		type out struct {
			accepted bool
			code     Code
		}
		results := make([]out, verifyN)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < verifyN; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				d, err := f.svc.Check(ready[i].SessionID, ready[i].Presentation)
				if err != nil {
					results[i] = out{code: CodeOf(err)}
				} else {
					results[i] = out{accepted: d.Accepted}
				}
			}(i)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = f.svc.Revoke(id, "race-v2")
		}()
		close(start)
		wg.Wait()

		var accept, revoked, other int
		for _, r := range results {
			switch {
			case r.accepted:
				accept++
			case r.code == CodeRevokedCredential:
				revoked++
			default:
				other++
			}
		}
		if other != 0 {
			t.Fatalf("iter %d: unexpected codes: accept=%d revoked=%d other=%d",
				iter, accept, revoked, other)
		}
		if accept+revoked != verifyN {
			t.Fatalf("iter %d: results not partitioned %d/%d", iter, accept, revoked)
		}
		// 撤销完成后新出示必须失败（申请阶段）。
		if _, err := f.svc.ProveUnlinkable(id, pol, []string{"level"}, []string{"is_adult"}); CodeOf(err) != CodeRevokedCredential {
			t.Fatalf("iter %d: post-revoke new show must fail", iter)
		}
	}
}

// 同一持有者持有多张凭证并发验证，撤销其中一张不得误伤其他凭证，
// 且各自的 ShowID/结论不能串号。
func TestV2ConcurrentManyCredentialsRevokeOne(t *testing.T) {
	const n = 32
	f := newFixture(t, 2550)
	ids := make([]string, n)
	for i := range ids {
		attrs := goodAttrs()
		ids[i] = f.issue(t, attrs)
	}

	// 为每张凭证准备一个 v2 证明。
	pol := v2Pol()
	ready := make([]*ProveResult, n)
	for i, id := range ids {
		r, err := f.svc.ProveUnlinkable(id, pol, []string{"level"}, []string{"is_adult"})
		if err != nil {
			t.Fatal(err)
		}
		ready[i] = r
	}

	// 撤销中间一张。
	victim := n / 2
	if err := f.svc.Revoke(ids[victim], "victim"); err != nil {
		t.Fatal(err)
	}

	type out struct {
		accepted bool
		code     Code
		showID   string
	}
	results := make([]out, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range ready {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// 被撤销者的在途证明应保守拒绝/撤销拒绝；其余凭证断言是在撤销之后
			// 新窗口出具的吗？这里 ready 都在撤销前备好，因此撤销会使所有在途
			// 证明的纪元窗口失效。为精确隔离，未受害凭证改为撤销后重新出示。
			if i == victim {
				d, err := f.svc.Check(ready[i].SessionID, ready[i].Presentation)
				if err != nil {
					results[i] = out{code: CodeOf(err)}
				} else {
					results[i] = out{accepted: d.Accepted, showID: d.ShowID}
				}
				return
			}
			r, err := f.svc.ProveUnlinkable(ids[i], pol, []string{"level"}, []string{"is_adult"})
			if err != nil {
				results[i] = out{code: CodeOf(err)}
				return
			}
			d, err := f.svc.Check(r.SessionID, r.Presentation)
			if err != nil {
				results[i] = out{code: CodeOf(err)}
			} else {
				results[i] = out{accepted: d.Accepted, showID: d.ShowID}
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if results[victim].accepted || results[victim].code != CodeRevokedCredential {
		t.Fatalf("victim must be rejected: %+v", results[victim])
	}
	seenShow := map[string]bool{}
	for i, r := range results {
		if i == victim {
			continue
		}
		if !r.accepted {
			t.Fatalf("unrelated credential %d must still be accepted fresh: code=%s", i, r.code)
		}
		if r.showID == "" {
			t.Fatalf("credential %d decision missing show id", i)
		}
		if seenShow[r.showID] {
			t.Fatalf("duplicate show id across credentials: %s", r.showID)
		}
		seenShow[r.showID] = true
	}
}
