package anoncred

import (
	"bytes"
	"runtime"
	"sync"
	"testing"
	"time"
)

// goschedRNG 在每次取随机数前让出调度，放大并发登记时
// “检查-生成-安装”之间的竞争窗口（确定性随机源，不依赖真实等待）。
type goschedRNG struct{ inner RNG }

func (g goschedRNG) RandomBytes(n int) ([]byte, error) {
	runtime.Gosched()
	return g.inner.RandomBytes(n)
}

// newBareService 创建尚未登记任何策略版本的服务（签发方随机源带调度让出，
// 专门用于并发发布用例），返回服务、时钟与策略基准时刻。
func newBareService(seed uint64) (*Service, *FakeClock, time.Time) {
	start := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)
	svc := NewService(ServiceConfig{
		IssuerRNG:   goschedRNG{NewDeterministicRNG(seed)},
		HolderRNG:   NewDeterministicRNG(seed + 1),
		VerifierRNG: NewDeterministicRNG(seed + 2),
		Clock:       clock,
	})
	return svc, clock, start
}

// driftedPolicy 返回与基准策略同版本号但模式不同的策略（新增必填属性）。
func driftedPolicy(base Policy) Policy {
	d := base
	d.Attributes = append(append([]AttributeSpec(nil), base.Attributes...), AttributeSpec{
		Name: "region", Type: AttrString, Required: true, NonEmpty: true,
	})
	return d
}

// stormRegister 并发执行 n 次 publish(i)，返回各次结果；barrier 保证同时起跑。
func stormRegister[T any](n int, publish func(i int) (T, error)) ([]T, []error) {
	outs := make([]T, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	barrier := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-barrier
			outs[i], errs[i] = publish(i)
		}(i)
	}
	close(barrier)
	wg.Wait()
	return outs, errs
}

// TestConcurrentIdenticalRepublishIdempotent: 同一版本号被多个执行流以
// 完全相同的参数同时登记时，全部成功（幂等），且最终只保留首次发布的
// 签名密钥与公开材料；已签发凭证在任意轮重复发布后继续有效。
func TestConcurrentIdenticalRepublishIdempotent(t *testing.T) {
	const n = 32
	for iter := 0; iter < 20; iter++ {
		svc, clock, start := newBareService(uint64(9100 + iter))
		p := v1Policy(start)

		// 第一轮：服务层并发登记（签发方 + 信任库两条路径同时走）。
		if _, errs := stormRegister[struct{}](n, func(int) (struct{}, error) {
			return struct{}{}, svc.RegisterPolicy(p)
		}); hasErr(errs) {
			t.Fatalf("iter %d: identical concurrent republish must all succeed: %v", iter, errs)
		}
		first := svc.Issuer.ActivePublic()
		if first == nil {
			t.Fatalf("iter %d: no active version after publish storm", iter)
		}

		// 第二轮：签发方层并发登记并收集返回材料，所有返回的密钥必须与首次一致。
		pubs, errs := stormRegister(n, func(int) (*IssuerPublic, error) {
			return svc.Issuer.AddPolicyVersion(p)
		})
		if hasErr(errs) {
			t.Fatalf("iter %d: issuer-level identical republish must succeed: %v", iter, errs)
		}
		for i, pub := range pubs {
			if pub == nil || !bytes.Equal(pub.VerifyingKey, first.VerifyingKey) {
				t.Fatalf("iter %d: republish %d returned different key material (first-wins violated)", iter, i)
			}
		}

		// 签发一张凭证，然后再刮一轮发布风暴：密钥不得变化、凭证不得失效。
		if err := svc.Issuer.UseLegacy(true); err != nil {
			t.Fatal(err)
		}
		if err := svc.SetLegacyWindow(1, time.Time{}); err != nil {
			t.Fatal(err)
		}
		f := &fixture{svc: svc, clock: clock, start: start}
		id := f.issue(t, goodAttrs())
		pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}
		if d, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"}); err != nil || !d.Accepted {
			t.Fatalf("iter %d: credential issued after storm must verify: %v", iter, err)
		}

		if _, errs := stormRegister[struct{}](n, func(int) (struct{}, error) {
			return struct{}{}, svc.RegisterPolicy(p)
		}); hasErr(errs) {
			t.Fatalf("iter %d: post-issuance identical republish must succeed: %v", iter, errs)
		}
		after := svc.Issuer.ActivePublic()
		if !bytes.Equal(after.VerifyingKey, first.VerifyingKey) ||
			!bytes.Equal(after.SchemaHash, first.SchemaHash) {
			t.Fatalf("iter %d: republish replaced the in-effect key material", iter)
		}
		if d, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"}); err != nil || !d.Accepted {
			t.Fatalf("iter %d: pre-storm credential must still verify: %v", iter, err)
		}
		id2 := f.issue(t, goodAttrs())
		if d, err := f.proveCheck(t, id2, pol, nil, []string{"is_adult"}); err != nil || !d.Accepted {
			t.Fatalf("iter %d: post-storm credential must verify: %v", iter, err)
		}
	}
}

// TestConcurrentConflictingRepublishSingleWinner: 同一版本号、两族不一致参数
// 并发发布时，只有一族成功；失败方全部得到可区分的 CodeVersionConflict，
// 且不得改动已发布版本的状态（密钥与模式指纹保持赢家首次发布的内容）。
func TestConcurrentConflictingRepublishSingleWinner(t *testing.T) {
	const perFamily = 16
	for iter := 0; iter < 20; iter++ {
		svc, clock, start := newBareService(uint64(9300 + iter))
		pA := v1Policy(start)
		pB := driftedPolicy(pA)
		if bytes.Equal(pA.SchemaHash(), pB.SchemaHash()) {
			t.Fatal("test policies must differ in schema hash")
		}

		pubs, errs := stormRegister(2*perFamily, func(i int) (*IssuerPublic, error) {
			if i%2 == 0 {
				return svc.Issuer.AddPolicyVersion(pA)
			}
			return svc.Issuer.AddPolicyVersion(pB)
		})

		winA, winB := 0, 0
		var winKey []byte
		for i := range pubs {
			if errs[i] == nil {
				if pubs[i] == nil {
					t.Fatalf("iter %d: successful publish returned nil public material", iter)
				}
				if i%2 == 0 {
					winA++
				} else {
					winB++
				}
				if winKey == nil {
					winKey = pubs[i].VerifyingKey
				} else if !bytes.Equal(winKey, pubs[i].VerifyingKey) {
					t.Fatalf("iter %d: two successful publishes disagree on key material", iter)
				}
				continue
			}
			// 冲突失败必须是专属类型码，与签名校验失败/参数不兼容明确区分。
			if CodeOf(errs[i]) != CodeVersionConflict {
				t.Fatalf("iter %d: want version_conflict, got %v", iter, errs[i])
			}
			if CodeOf(errs[i]) == CodeBadIssuerSignature || CodeOf(errs[i]) == CodeIncompatibleParameters {
				t.Fatalf("iter %d: conflict failure must be distinguishable: %v", iter, errs[i])
			}
		}
		if (winA == 0) == (winB == 0) {
			t.Fatalf("iter %d: exactly one parameter family may win (winA=%d winB=%d)", iter, winA, winB)
		}
		winner, loser := pA, pB
		if winB > 0 {
			winner, loser = pB, pA
		}

		// 已发布状态等于赢家首次发布，且未被输家覆盖。
		active := svc.Issuer.ActivePublic()
		if !bytes.Equal(active.VerifyingKey, winKey) ||
			!bytes.Equal(active.SchemaHash, winner.SchemaHash()) {
			t.Fatalf("iter %d: published state does not match the winning family", iter)
		}

		// 串行复查：输家依旧冲突且不改状态；赢家幂等且密钥不变。
		if _, err := svc.Issuer.AddPolicyVersion(loser); CodeOf(err) != CodeVersionConflict {
			t.Fatalf("iter %d: serial loser republish: want version_conflict, got %v", iter, err)
		}
		again, err := svc.Issuer.AddPolicyVersion(winner)
		if err != nil || !bytes.Equal(again.VerifyingKey, winKey) {
			t.Fatalf("iter %d: serial winner republish must be idempotent: %v", iter, err)
		}
		if !bytes.Equal(svc.Issuer.ActivePublic().VerifyingKey, winKey) {
			t.Fatalf("iter %d: loser republish must not alter published state", iter)
		}

		// 端到端：按赢家参数完成信任登记后可正常签发、验证；
		// 服务层再次提交输家参数失败，且已签发凭证不受影响。
		if err := svc.RegisterPolicy(winner); err != nil {
			t.Fatalf("iter %d: register winner policy: %v", iter, err)
		}
		if err := svc.Issuer.UseLegacy(true); err != nil {
			t.Fatal(err)
		}
		if err := svc.SetLegacyWindow(winner.Version, time.Time{}); err != nil {
			t.Fatal(err)
		}
		f := &fixture{svc: svc, clock: clock, start: start}
		attrs := goodAttrs()
		if winB > 0 {
			attrs["region"] = StringValue("EU")
		}
		id, err := svc.IssueAndHold(IssueRequest{
			PolicyName:    winner.Name,
			PolicyVersion: winner.Version,
			Attributes:    attrs,
			TTL:           time.Hour,
		})
		if err != nil {
			t.Fatalf("iter %d: issue under winner policy: %v", iter, err)
		}
		if err := svc.RegisterPolicy(loser); CodeOf(err) != CodeVersionConflict {
			t.Fatalf("iter %d: service-level loser republish: want version_conflict, got %v", iter, err)
		}
		if d, err := f.proveCheck(t, id,
			VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute},
			nil, []string{"is_adult"}); err != nil || !d.Accepted {
			t.Fatalf("iter %d: credential must survive rejected loser republish: %v", iter, err)
		}
	}
}

// TestRepublishInterleavedWithIssueAndVerify: 重复发布（幂等族 + 冲突族）与
// 签发、验证交错进行时，任何验证都不得因“签发密钥与信任密钥不一致”而失败；
// 交错结束后已签发凭证继续有效、新签发凭证可验证、密钥材料保持首次发布。
func TestRepublishInterleavedWithIssueAndVerify(t *testing.T) {
	const (
		publishers  = 8
		conflicters = 4
		issuers     = 4
		issuesEach  = 5
		verifiers   = 4
		verifyEach  = 5
	)
	for iter := 0; iter < 10; iter++ {
		f := newFixture(t, uint64(9500+iter)) // legacy 语义，v1 已登记
		base := f.svc.Issuer.ActivePublic()
		identical := v1Policy(f.start)
		drift := driftedPolicy(identical)
		pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}

		// 交错前已签发的凭证。
		preIDs := []string{f.issue(t, goodAttrs()), f.issue(t, goodAttrs())}

		pubErrs := make([]error, publishers)
		confErrs := make([]error, conflicters)
		issueIDs := make([][]string, issuers)
		issueErrs := make([][]error, issuers)
		verifyErrs := make([][]error, verifiers)

		var wg sync.WaitGroup
		barrier := make(chan struct{})
		for i := 0; i < publishers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-barrier
				pubErrs[i] = f.svc.RegisterPolicy(identical)
			}(i)
		}
		for i := 0; i < conflicters; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-barrier
				confErrs[i] = f.svc.RegisterPolicy(drift)
			}(i)
		}
		for i := 0; i < issuers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-barrier
				for j := 0; j < issuesEach; j++ {
					id, err := f.svc.IssueAndHold(IssueRequest{
						PolicyName:    "driving-entitlement",
						PolicyVersion: 1,
						Attributes:    goodAttrs(),
						TTL:           time.Hour,
					})
					issueIDs[i] = append(issueIDs[i], id)
					issueErrs[i] = append(issueErrs[i], err)
				}
			}(i)
		}
		for i := 0; i < verifiers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-barrier
				for j := 0; j < verifyEach; j++ {
					res, err := f.svc.Prove(preIDs[j%len(preIDs)], pol, nil, []string{"is_adult"})
					if err == nil {
						_, err = f.svc.Check(res.SessionID, res.Presentation)
					}
					verifyErrs[i] = append(verifyErrs[i], err)
				}
			}(i)
		}
		close(barrier)
		wg.Wait()

		for i, err := range pubErrs {
			if err != nil {
				t.Fatalf("iter %d: identical publisher %d must succeed: %v", iter, i, err)
			}
		}
		for i, err := range confErrs {
			if CodeOf(err) != CodeVersionConflict {
				t.Fatalf("iter %d: conflicting publisher %d: want version_conflict, got %v", iter, i, err)
			}
		}
		for i := range issueErrs {
			for j, err := range issueErrs[i] {
				if err != nil {
					t.Fatalf("iter %d: issuer %d issue %d failed: %v", iter, i, j, err)
				}
			}
		}
		for i := range verifyErrs {
			for j, err := range verifyErrs[i] {
				if err != nil {
					t.Fatalf("iter %d: verifier %d check %d failed (key mismatch under interleave?): %v",
						iter, i, j, err)
				}
			}
		}

		// 发布结束后：密钥材料仍是首次发布；交错中签发的凭证全部可验证。
		if now := f.svc.Issuer.ActivePublic(); !bytes.Equal(now.VerifyingKey, base.VerifyingKey) {
			t.Fatalf("iter %d: interleaved republish replaced in-effect key", iter)
		}
		for i := range issueIDs {
			for _, id := range issueIDs[i] {
				if d, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"}); err != nil || !d.Accepted {
					t.Fatalf("iter %d: credential issued during storm must verify: %v", iter, err)
				}
			}
		}
		for _, id := range preIDs {
			if d, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"}); err != nil || !d.Accepted {
				t.Fatalf("iter %d: pre-storm credential must still verify: %v", iter, err)
			}
		}
		if d, err := f.proveCheck(t, f.issue(t, goodAttrs()), pol, nil, []string{"is_adult"}); err != nil || !d.Accepted {
			t.Fatalf("iter %d: post-storm issuance must verify: %v", iter, err)
		}
	}
}

func hasErr(errs []error) bool {
	for _, err := range errs {
		if err != nil {
			return true
		}
	}
	return false
}
