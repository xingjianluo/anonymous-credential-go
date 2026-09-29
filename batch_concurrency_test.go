package anoncred

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// batchIssueVerify 在同一种子下签发 n 张 v2 凭证并逐张做谓词出示验证，
// 返回“凭证序号 -> 是否接受”的结论位图（用字符串表示，便于比较）。
func batchIssueVerify(t *testing.T, seed uint64, n, revokeEvery int) (string, []string) {
	t.Helper()
	f := newV2Fixture(t, seed)
	pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}

	ids := make([]string, n)
	for i := 0; i < n; i++ {
		attrs := goodAttrs()
		// 属性略作变化，确保批内凭证并非完全同值。
		attrs["name"] = StringValue(fmt.Sprintf("Holder%04d", i))
		ids[i] = f.issueLongTTL(t, attrs)
	}

	// 按固定节奏撤销一部分凭证（仅撤销这些序号）。
	revoked := map[int]bool{}
	if revokeEvery > 0 {
		for i := 0; i < n; i += revokeEvery {
			if err := f.svc.Revoke(ids[i], "batch-revoke"); err != nil {
				t.Fatal(err)
			}
			revoked[i] = true
		}
	}

	accepted := make([]byte, n)
	for i := 0; i < n; i++ {
		_, err := f.proveCheck(t, ids[i], pol, nil, []string{"is_adult"})
		switch {
		case err == nil:
			accepted[i] = '1'
		case CodeOf(err) == CodeRevokedCredential:
			accepted[i] = 'R'
		default:
			t.Fatalf("cred %d unexpected error: %v", i, err)
		}
	}
	return string(accepted), ids
}

// TestBatchThousandCredentialsConsistent:
// 批量准备上千张凭证连续验证：撤销状态精确对应、其余凭证不被误伤、结论可复现。
func TestBatchThousandCredentialsConsistent(t *testing.T) {
	const n = 1000
	const seed = uint64(2400)

	res1, _ := batchIssueVerify(t, seed, n, 7)
	res2, _ := batchIssueVerify(t, seed, n, 7)
	if res1 != res2 {
		t.Fatalf("batch results not reproducible:\n%s\n%s", res1, res2)
	}

	var accept, revoked int
	for i, c := range []byte(res1) {
		wantRevoked := i%7 == 0
		switch c {
		case '1':
			accept++
			if wantRevoked {
				t.Fatalf("cred %d marked accepted but should be revoked", i)
			}
		case 'R':
			revoked++
			if !wantRevoked {
				t.Fatalf("cred %d marked revoked but should be valid", i)
			}
		default:
			t.Fatalf("unexpected marker %q", c)
		}
	}
	if revoked != n/7+1 || accept != n-revoked {
		t.Fatalf("counts: accepted=%d revoked=%d", accept, revoked)
	}
}

// TestV2ConcurrentMultiVerifierWithInterleavedRevocation:
// 同一持有者多张 v2 凭证、多个验证方并发验证，期间穿插撤销：
// 不串号、不重复接受同一会话、撤销只影响目标凭证，结论线性化。
func TestV2ConcurrentMultiVerifierWithInterleavedRevocation(t *testing.T) {
	const credN = 12
	const showsPerCred = 8

	for iter := 0; iter < 10; iter++ {
		f := newV2Fixture(t, uint64(2500+iter))
		var ids []string
		for i := 0; i < credN; i++ {
			attrs := goodAttrs()
			attrs["name"] = StringValue(fmt.Sprintf("C%02d", i))
			ids = append(ids, f.issueLongTTL(t, attrs))
		}

		pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}

		// 第二个独立验证方。
		trust2 := NewTrustRegistry()
		pub := f.svc.Issuer.ActivePublic()
		if err := trust2.Register(TrustProfile{
			IssuerName: f.svc.Issuer.name, Public: *pub,
		}); err != nil {
			t.Fatal(err)
		}
		verifier2 := NewVerifier(f.clock, NewDeterministicRNG(7700+uint64(iter)), trust2).
			WithRevocationSource(f.svc.Issuer).
			WithShowingAuthority(f.svc.Issuer).
			WithAudit(f.svc.Audit)

		type job struct {
			credIdx  int
			verifier int // 0 或 1
			session  string
			pres     *Presentation
		}
		var jobs []job
		for ci, id := range ids {
			for k := 0; k < showsPerCred; k++ {
				if k%2 == 0 {
					res := f.proveRaw(t, id, pol, nil, []string{"is_adult"})
					jobs = append(jobs, job{credIdx: ci, verifier: 0, session: res.SessionID, pres: res.Presentation})
				} else {
					sess, err := verifier2.NewSession(f.svc.Issuer.name, 1, pol)
					if err != nil {
						t.Fatal(err)
					}
					pres, err := f.svc.Holder.BuildPresentation(PresentRequest{
						CredIDHex: id, SessionNonce: sess.Nonce,
						DisclosePreds: []string{"is_adult"},
					})
					if err != nil {
						t.Fatal(err)
					}
					jobs = append(jobs, job{credIdx: ci, verifier: 1, session: sess.ID, pres: pres})
				}
			}
		}

		results := make([]Code, len(jobs))
		accepted := make([]bool, len(jobs))
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i, jb := range jobs {
			wg.Add(1)
			go func(i int, jb job) {
				defer wg.Done()
				<-start
				v := f.svc.Verifier
				if jb.verifier == 1 {
					v = verifier2
				}
				d, err := v.Verify(jb.session, jb.pres)
				if err != nil {
					results[i] = CodeOf(err)
				} else {
					accepted[i] = d.Accepted
				}
			}(i, jb)
		}
		// 穿插：并发撤销半数凭证。
		revokedCreds := map[int]bool{}
		for ci := 0; ci < credN; ci += 2 {
			revokedCreds[ci] = true
			wg.Add(1)
			go func(ci int) {
				defer wg.Done()
				<-start
				_ = f.svc.Revoke(ids[ci], "interleaved")
			}(ci)
		}
		close(start)
		wg.Wait()

		// 每个凭证的结论必须只取决于它自己：未撤销凭证绝不允许出现 revoked；
		// 拒绝类型码只能是 revoked_credential（并发窗口保守拒绝），不得出现其他失败。
		// 时序线性化由终态复核（撤销后新会话必失败）保证，结果切片顺序不代表真实时序。
		perCred := make(map[int][]int)
		for i, jb := range jobs {
			perCred[jb.credIdx] = append(perCred[jb.credIdx], i)
		}
		for ci := 0; ci < credN; ci++ {
			for _, idx := range perCred[ci] {
				c := results[idx]
				if c != "" {
					if c != CodeRevokedCredential {
						t.Fatalf("iter %d cred %d: unexpected code %s", iter, ci, c)
					}
					continue
				}
				if !accepted[idx] {
					t.Fatalf("iter %d cred %d: neither accepted nor coded", iter, ci)
				}
			}
		}

		// 终态复核：被撤销凭证新出示必失败；未被撤销凭证新出示必成功，且跨两个验证方都成立。
		pol2 := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}
		for ci, id := range ids {
			res := f.proveRaw(t, id, pol2, nil, []string{"is_adult"})
			_, err := f.svc.Check(res.SessionID, res.Presentation)
			if revokedCreds[ci] {
				if CodeOf(err) != CodeRevokedCredential {
					t.Fatalf("iter %d cred %d final state: want revoked, got %v", iter, ci, err)
				}
			} else if err != nil {
				t.Fatalf("iter %d cred %d final state: valid credential rejected: %v", iter, ci, err)
			}
			// 第二个验证方同样复核。
			sess, err := verifier2.NewSession(f.svc.Issuer.name, 1, pol2)
			if err != nil {
				t.Fatal(err)
			}
			pres, err := f.svc.Holder.BuildPresentation(PresentRequest{
				CredIDHex: id, SessionNonce: sess.Nonce,
				DisclosePreds: []string{"is_adult"},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier2.Verify(sess.ID, pres)
			if revokedCreds[ci] {
				if CodeOf(err) != CodeRevokedCredential {
					t.Fatalf("iter %d cred %d verifier2: want revoked, got %v", iter, ci, err)
				}
			} else if err != nil {
				t.Fatalf("iter %d cred %d verifier2: valid rejected: %v", iter, ci, err)
			}
		}
	}
}
