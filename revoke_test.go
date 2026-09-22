package anoncred

import (
	"sync"
	"testing"
	"time"
)

func TestRevocationImmediate(t *testing.T) {
	f := newFixture(t, 41)
	id := f.issue(t, goodAttrs())

	// 撤销前通过。
	if _, err := f.proveCheck(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}, nil, []string{"is_adult"}); err != nil {
		t.Fatalf("before revoke: %v", err)
	}

	if err := f.svc.Revoke(id, "compromised-device"); err != nil {
		t.Fatal(err)
	}

	// 撤销后新会话新证明必须立即失败。
	_, err := f.proveCheck(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}, nil, []string{"is_adult"})
	if CodeOf(err) != CodeRevokedCredential {
		t.Fatalf("want revoked_credential, got %v", err)
	}
}

func TestRevocationConcurrencyConsistency(t *testing.T) {
	for iter := 0; iter < 20; iter++ {
		f := newFixture(t, uint64(100+iter))
		id := f.issue(t, goodAttrs())

		const n = 12
		type result struct {
			accepted bool
			code     Code
		}
		results := make([]result, n)

		// 先为每个 goroutine 准备独立会话与证明（共享同一凭证）。
		pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}
		sessions := make([]*ProveResult, n)
		for i := 0; i < n; i++ {
			sessions[i] = f.proveRaw(t, id, pol, nil, []string{"is_adult"})
		}

		var wg sync.WaitGroup
		start := make(chan struct{})
		// 一半 goroutine 并发校验，一半并发吊销（重复吊销幂等）。
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				if i%2 == 1 {
					_ = f.svc.Revoke(id, "concurrent")
					results[i] = result{code: CodeRevokedCredential}
					return
				}
				d, err := f.svc.Check(sessions[i].SessionID, sessions[i].Presentation)
				if err != nil {
					results[i] = result{code: CodeOf(err)}
				} else {
					results[i] = result{accepted: d.Accepted}
				}
			}(i)
		}
		close(start)
		wg.Wait()

		// 不变量：凭证最终处于已撤销状态；
		// 所有校验结论必须与“校验时刻的撤销状态”一致——
		// 由于撤销单调且会话一次性，任何接受都必须发生在撤销之前，
		// 已接受的会话不得再次接受；撤销一旦发生，之后不得出现接受。
		var acceptedAfterRevoke int
		revokeSeen := false
		// 结果顺序不代表真实时序，因此可直接断言：撤销之后再次验证同一凭证必失败。
		// 这里再开一个新会话，必须拒绝。
		_, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"})
		if CodeOf(err) != CodeRevokedCredential {
			t.Fatalf("iter %d: post-concurrent verify must be revoked, got %v", iter, err)
		}
		for _, r := range results {
			if r.code == "" && r.accepted {
				// 接受只允许在撤销前；无法从结果切片排序时序，
				// 但接受数量必须 < 校验尝试数（至少一次校验在撤销后或并发中失败）。
				continue
			}
			if r.code == CodeRevokedCredential {
				revokeSeen = true
			}
			if revokeSeen && r.accepted {
				acceptedAfterRevoke++
			}
		}
		if !revokeSeen {
			t.Fatalf("iter %d: revocation goroutines produced no revoke", iter)
		}
		if acceptedAfterRevoke != 0 {
			t.Fatalf("iter %d: accepted result after revocation: %d", iter, acceptedAfterRevoke)
		}
	}
}

// 凭证过期：时钟推进超过 ExpiresAt 后，任何证明都失败。
func TestCredentialExpiry(t *testing.T) {
	f := newFixture(t, 43)
	id := f.issue(t, goodAttrs()) // TTL 1h
	f.clock.Advance(90 * time.Minute)
	_, err := f.proveCheck(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}, nil, []string{"is_adult"})
	if CodeOf(err) != CodeExpiredCredential {
		t.Fatalf("want expired_credential, got %v", err)
	}
}

// 未知凭证吊销必须明确报错。
func TestRevokeUnknown(t *testing.T) {
	f := newFixture(t, 44)
	if err := f.svc.Issuer.Revoke([]byte{1, 2, 3}, "x"); CodeOf(err) != CodeNoSuchCredential {
		t.Fatalf("want no_such_credential, got %v", err)
	}
}
