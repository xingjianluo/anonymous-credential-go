package anoncred

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// 本文件覆盖“同一策略版本并发重复发布”的收紧语义：
//   - 相同参数并发发布：幂等，最终只有首次发布的密钥与公开材料，凭证不失效；
//   - 不同参数并发发布：恰好一方成功，其余以 version_conflict 明确失败且不覆盖；
//   - 发布与签发/验证交错：签发所用密钥与验证方信任密钥始终是同一份；
//   - 发布失败不留半更新状态。
//
// 复现手段不依赖真实等待：gateRNG 在“生成版本签名密钥”这一步阻塞。
// 收紧后的实现持签发方锁生成密钥，因此交错形态为：第一个执行流持锁进入
// 密钥生成并停在闸门上，其余执行流全部在签发方锁外排队；测试通过 runtime
// 栈观察到排队者数量后统一放行（带超时保护），从而确定性地制造
// “检查与写入不是原子完成”才能通过的高并发首发场景。

// gateRNG 包装一个确定性随机源；armed 期间，读取会先在 arrived 上报，
// 再阻塞到 release 关闭当前闸门。
type gateRNG struct {
	inner   RNG
	mu      sync.Mutex
	armed   bool
	gate    chan struct{}
	arrived chan struct{}
}

func newGateRNG(inner RNG, capacity int) *gateRNG {
	return &gateRNG{
		inner:   inner,
		gate:    make(chan struct{}),
		arrived: make(chan struct{}, capacity),
	}
}

// reset 在任何被拦截执行流起跑前换好全新闸门并清空到达计数。
func (g *gateRNG) reset() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gate = make(chan struct{})
	g.armed = true
	// arrived 带缓冲且每次场景容量足够；排空残留信号。
	for {
		select {
		case <-g.arrived:
			continue
		default:
			return
		}
	}
}

// release 打开闸门放行阻塞中的首个执行流（锁外排队者随后逐个进入临界区）。
func (g *gateRNG) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.armed {
		close(g.gate)
		g.armed = false
	}
}

// waitFirstArrived 等待持锁的首个执行流进入密钥生成阻塞点。
func (g *gateRNG) waitFirstArrived(t *testing.T) {
	t.Helper()
	select {
	case <-g.arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("gateRNG: first publisher did not reach the key-generation gate")
	}
}

// waitQueuedPublishers 自旋让出调度，直到观察到除首个执行流外的 want 个
// 执行流都已进入登记路径并停下（停在登记临界区的互斥锁上，或停在密钥生成
// 闸门的 channel 上——后者正是旧实现“锁外生成密钥”时的形态）。
// 这是对“同步发生”的观察，不是计时等待。
func waitQueuedPublishers(want int) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		text := string(stack[:n])
		// 栈符号的包名在普通/竞态构建下长短不一（anoncred.* 或全限定路径），
		// 故只匹配方法选择子。每个参赛执行流从进入 RegisterPolicy 到返回前
		// 都带有该栈帧；首个执行流（已在密钥生成闸门内）也包含它，故 -1。
		queued := strings.Count(text, "(*Service).RegisterPolicy") +
			strings.Count(text, "(*Issuer).AddPolicyVersion") - 1
		parked := strings.Contains(text, "[sync.Mutex.Lock]") ||
			strings.Contains(text, "semacquire") ||
			strings.Contains(text, "gateRNG")
		if queued >= want && parked {
			return
		}
		if time.Now().After(deadline) {
			panic("gateRNG: publishers did not reach the registration critical section before deadline")
		}
		runtime.Gosched()
	}
}

func (g *gateRNG) RandomBytes(n int) ([]byte, error) {
	g.mu.Lock()
	armed := g.armed
	gate := g.gate
	g.mu.Unlock()
	if armed {
		select {
		case g.arrived <- struct{}{}:
		default:
		}
		<-gate
	}
	return g.inner.RandomBytes(n)
}

// newRaceService 创建“未登记任何策略”的服务，签发方随机源替换为 gateRNG，
// 以便精确控制并发首次发布的交错。
func newRaceService(t *testing.T, seed uint64) (*Service, *FakeClock, *gateRNG) {
	t.Helper()
	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	clock := NewFakeClock(start)
	gate := newGateRNG(NewDeterministicRNG(seed), 64)
	svc := NewService(ServiceConfig{
		IssuerRNG:   gate,
		HolderRNG:   NewDeterministicRNG(seed + 1),
		VerifierRNG: NewDeterministicRNG(seed + 2),
		Clock:       clock,
	})
	return svc, clock, gate
}

// v1PolicyVariant 返回 v1 策略的一个冲突变体（同版本号、多一个必填属性）。
func v1PolicyVariant(at time.Time) Policy {
	p := v1Policy(at)
	p.Attributes = append(p.Attributes, AttributeSpec{
		Name: "region", Type: AttrString, Required: true, NonEmpty: true,
	})
	return p
}

// stageConcurrentPublish 启动 n 个并发登记执行流并让它们停在“首个执行流持锁
// 生成密钥、其余执行流锁外排队”的临界点上；返回 release 与 wait 两个动作。
//
// 调用前服务必须未登记该版本，且签发方随机源正是 gate。
func stageConcurrentPublish(t *testing.T, svc *Service, gate *gateRNG, p Policy, n int) (release func(), wait func() []error) {
	t.Helper()
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	gate.reset() // 必须在执行流起跑前换好全新闸门。
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = svc.RegisterPolicy(p)
		}(i)
	}
	close(start)
	gate.waitFirstArrived(t)
	waitQueuedPublishers(n - 1)
	return gate.release, func() []error {
		wg.Wait()
		return errs
	}
}

// runConcurrentPublish 让 n 个执行流在同一起跑线并发登记同一策略。
func runConcurrentPublish(svc *Service, p Policy, n int) []error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = svc.RegisterPolicy(p)
		}(i)
	}
	close(start)
	wg.Wait()
	return errs
}

// TestConcurrentRepublishSameParametersIdempotent:
// 多个执行流以完全一致的参数并发登记同一版本，结果必须与串行登记等价：
// 全部成功；签发方与信任库只保留首次发布的同一份密钥；之后新签发的凭证
// （以及发布前已签发的凭证，见交错用例）都能正常验证。
func TestConcurrentRepublishSameParametersIdempotent(t *testing.T) {
	const n = 8
	svc, _, gate := newRaceService(t, 3100)
	p := v1Policy(time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC))

	// 并发首发：所有执行流在临界点停住后统一放行。
	release, wait := stageConcurrentPublish(t, svc, gate, p, n)
	release()
	errs := wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("identical concurrent publish #%d must succeed idempotently: %v", i, err)
		}
	}

	issuerPub, err := svc.Issuer.PublicOf(1)
	if err != nil {
		t.Fatalf("issuer must keep version 1: %v", err)
	}
	tp := svc.Trust.Lookup(svc.Issuer.name, 1)
	if tp == nil {
		t.Fatal("trust registry must keep version 1")
	}
	if !publicKeyEqual(issuerPub.VerifyingKey, tp.Public.VerifyingKey) {
		t.Fatal("issuer signing key and trusted verifying key diverged after concurrent publish")
	}

	// 发布结束后新签发的凭证必须能正常验证（v2 路径）。
	id, err := svc.IssueAndHold(IssueRequest{
		PolicyName:    p.Name,
		PolicyVersion: 1,
		Attributes:    goodAttrs(),
		TTL:           time.Hour,
	})
	if err != nil {
		t.Fatalf("issue after concurrent publish: %v", err)
	}
	res, err := svc.Prove(id, VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute},
		nil, []string{"is_adult"})
	if err != nil {
		t.Fatalf("prove after concurrent publish: %v", err)
	}
	if d, err := svc.Check(res.SessionID, res.Presentation); err != nil || !d.Accepted {
		t.Fatalf("credential issued after concurrent publish must verify: d=%+v err=%v", d, err)
	}

	// 再串行重复登记一次，密钥依旧不变。
	pub2, err := svc.Issuer.AddPolicyVersion(p)
	if err != nil {
		t.Fatalf("serial identical republish: %v", err)
	}
	if !publicKeyEqual(pub2.VerifyingKey, issuerPub.VerifyingKey) {
		t.Fatal("serial republish after concurrent publish must not rotate the key")
	}

	t.Logf("业务=并发相同参数幂等发布: %d 次登记全部成功, 签发方/信任库密钥一致, 发布后新凭证验证通过", n)
}

// TestConcurrentRepublishConflictingParameters:
// 两组执行流以“同版本号、不同参数”并发登记：恰好一种参数发布成功，
// 另一种参数的每次登记都以 version_conflict 明确失败；失败方不得改动
// 已发布版本的状态（密钥、模式指纹、信任材料均保持胜出版本）。
func TestConcurrentRepublishConflictingParameters(t *testing.T) {
	const perGroup = 6
	svc, _, gate := newRaceService(t, 3200)
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	pa := v1Policy(at)
	pb := v1PolicyVariant(at)

	type result struct{ errs []error }
	ra := make(chan result, 1)
	rb := make(chan result, 1)
	stage := func(p Policy, ch chan result) {
		errs := make([]error, perGroup)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < perGroup; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				errs[i] = svc.RegisterPolicy(p)
			}(i)
		}
		close(start)
		wg.Wait()
		ch <- result{errs: errs}
	}

	// 两组在同一道闸门后起跑：首个抢到锁的执行流停在密钥生成点，
	// 其余全部排队；放行后结论必须等价于某种串行顺序。
	gate.reset()
	go stage(pa, ra)
	go stage(pb, rb)
	gate.waitFirstArrived(t)
	waitQueuedPublishers(2*perGroup - 1)
	gate.release()
	errsA := (<-ra).errs
	errsB := (<-rb).errs

	okA, conflictA := countCodes(errsA)
	okB, conflictB := countCodes(errsB)

	// 恰好一方全绿，另一方全部 version_conflict；不得出现第三种结局。
	if !((okA == perGroup && conflictB == perGroup) || (okB == perGroup && conflictA == perGroup)) {
		t.Fatalf("want exactly one parameter set to win: A(ok=%d conflict=%d) B(ok=%d conflict=%d)",
			okA, conflictA, okB, conflictB)
	}
	aWon := okA == perGroup

	issuerPub, err := svc.Issuer.PublicOf(1)
	if err != nil {
		t.Fatalf("issuer must keep the published version: %v", err)
	}
	tp := svc.Trust.Lookup(svc.Issuer.name, 1)
	if tp == nil {
		t.Fatal("trust registry must keep the published version")
	}
	// 签发方与信任库仍然是同一份密钥（绝无分裂）。
	if !publicKeyEqual(issuerPub.VerifyingKey, tp.Public.VerifyingKey) {
		t.Fatal("issuer key and trusted key diverged after conflicting concurrent publish")
	}
	// 已发布版本的策略参数就是胜出参数，失败方没有留下任何痕迹。
	winner, loser := pa, pb
	if !aWon {
		winner, loser = pb, pa
	}
	if !policiesEqual(issuerPub.Policy, winner) {
		t.Fatal("published policy parameters were overwritten by the losing concurrent publish")
	}
	if policiesEqual(issuerPub.Policy, loser) {
		t.Fatal("losing parameters must not appear in the published version")
	}
	if !bytesEqual(issuerPub.SchemaHash, winner.SchemaHash()) {
		t.Fatal("published schema hash does not match the winning parameters")
	}

	// 用胜出版本签发的凭证必须正常验证；冲突失败结论与签名失败、参数不兼容等
	// 其他失败类型码可区分。
	issueAttrs := goodAttrs()
	if !aWon {
		issueAttrs["region"] = StringValue("CN") // 胜出策略多一个必填属性。
	}
	id, err := svc.IssueAndHold(IssueRequest{
		PolicyName:    winner.Name,
		PolicyVersion: 1,
		Attributes:    issueAttrs,
		TTL:           time.Hour,
	})
	if err != nil {
		t.Fatalf("issue under winning publication: %v", err)
	}
	res, err := svc.Prove(id, VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute},
		nil, []string{"is_adult"})
	if err != nil {
		t.Fatalf("prove under winning publication: %v", err)
	}
	if _, err := svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatalf("credential under winning publication must verify: %v", err)
	}

	losingErrs := errsB
	if !aWon {
		losingErrs = errsA
	}
	for i, err := range losingErrs {
		switch CodeOf(err) {
		case CodeVersionConflict:
			// 预期。
		case CodeBadIssuerSignature, CodeIncompatibleParameters, CodeUnknownVersion, "":
			t.Fatalf("losing publish #%d returned %v, want a distinct version_conflict", i, err)
		default:
			t.Fatalf("losing publish #%d returned unexpected code %s", i, CodeOf(err))
		}
	}

	t.Logf("业务=并发冲突参数发布: 胜出版本=%s, 胜出 %d 次成功, 冲突 %d 次 version_conflict, 版本状态未被覆盖, 凭证验证通过",
		winner.Name, perGroup, perGroup)
}

// TestConcurrentPublishInterleavedWithIssueAndVerify:
// 重复发布与签发、验证在同一服务上交错发生时：
//   - 发布完成后新签发的凭证全部可验证（签发密钥 == 信任密钥）；
//   - 发布前已签发的凭证继续有效（相同参数幂等，密钥不变）；
//   - 所有非预期结论都不得出现（只有成功 / 版本冲突 / 会话缺失这类合法结果）。
func TestConcurrentPublishInterleavedWithIssueAndVerify(t *testing.T) {
	cases := []struct {
		name   string
		legacy bool
	}{
		{"v2", false},
		{"legacy_window", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const publishers = 6
			const issuers = 6

			f := newV2Fixture(t, 3300)
			if tc.legacy {
				if err := f.svc.Issuer.UseLegacy(true); err != nil {
					t.Fatal(err)
				}
				if err := f.svc.SetLegacyWindow(1, time.Time{}); err != nil {
					t.Fatal(err)
				}
			}
			pol := VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute}

			// 交错前已有凭证：相同参数的并发幂等发布不得使其失效。
			beforeID := f.issueLongTTL(t, goodAttrs())

			var wg sync.WaitGroup
			start := make(chan struct{})
			pubErrs := make([]error, publishers)
			issueIDs := make([]string, issuers)
			issueErrs := make([]error, issuers)
			for i := 0; i < publishers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					pubErrs[i] = f.svc.RegisterPolicy(v1Policy(f.start))
				}(i)
			}
			for i := 0; i < issuers; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					id, err := f.svc.IssueAndHold(IssueRequest{
						PolicyName:    "driving-entitlement",
						PolicyVersion: 1,
						Attributes:    goodAttrs(),
						TTL:           365 * 24 * time.Hour,
					})
					issueIDs[i] = id
					issueErrs[i] = err
				}(i)
			}
			close(start)
			wg.Wait()

			for i, err := range pubErrs {
				if err != nil {
					t.Fatalf("identical interleaved publish #%d: %v", i, err)
				}
			}
			for i, err := range issueErrs {
				if err != nil {
					t.Fatalf("interleaved issue #%d: %v", i, err)
				}
			}

			// 交错期间签发的凭证，发布结束后逐一验证，必须全部通过。
			for i, id := range issueIDs {
				if _, err := f.proveCheck(t, id, pol, nil, []string{"is_adult"}); err != nil {
					t.Fatalf("interleaved credential #%d must verify after publish settled: %v", i, err)
				}
			}
			// 发布前已存在的凭证同样继续有效。
			if _, err := f.proveCheck(t, beforeID, pol, nil, []string{"is_adult"}); err != nil {
				t.Fatalf("pre-publish credential must remain valid: %v", err)
			}

			// 终态：签发方活动密钥与信任库受信密钥仍是同一份。
			active := f.svc.Issuer.ActivePublic()
			tp := f.svc.Trust.Lookup(f.svc.Issuer.name, 1)
			if tp == nil || !publicKeyEqual(active.VerifyingKey, tp.Public.VerifyingKey) {
				t.Fatal("signing key and trusted key diverged after interleaving")
			}

			t.Logf("业务=发布与签发/验证交错(%s): %d 次幂等发布 + %d 张交错签发凭证, 全部验证通过, 发布前凭证继续有效",
				tc.name, publishers, issuers)
		})
	}
}

// TestFailedPublishLeavesNoHalfUpdatedState:
// 同版本冲突参数的发布（串行或并发）失败后，已发布版本的密钥、模式指纹、
// 信任材料与发布前逐字节一致；失败方不会留下“签发方有、信任库没有”之类
// 的半更新状态。
func TestFailedPublishLeavesNoHalfUpdatedState(t *testing.T) {
	svc, clock, _ := newRaceService(t, 3400)
	p := v1Policy(clock.Now())
	if err := svc.RegisterPolicy(p); err != nil {
		t.Fatal(err)
	}

	pubBefore, _ := svc.Issuer.PublicOf(1)
	tpBefore := svc.Trust.Lookup(svc.Issuer.name, 1)
	keyBefore := append([]byte(nil), pubBefore.VerifyingKey...)
	hashBefore := append([]byte(nil), pubBefore.SchemaHash...)
	trustedBefore := append([]byte(nil), tpBefore.Public.VerifyingKey...)

	conflict := v1PolicyVariant(clock.Now())

	// 串行冲突发布。
	if err := svc.RegisterPolicy(conflict); CodeOf(err) != CodeVersionConflict {
		t.Fatalf("serial conflict want version_conflict, got %v", err)
	}

	// 并发冲突发布：全部必须失败，且无一改动状态。
	errs := runConcurrentPublish(svc, conflict, 6)
	if ok, c := countCodes(errs); ok != 0 || c != 6 {
		t.Fatalf("want 6 conflicts, got ok=%d conflict=%d (errs=%v)", ok, c, errs)
	}

	pubAfter, _ := svc.Issuer.PublicOf(1)
	tpAfter := svc.Trust.Lookup(svc.Issuer.name, 1)
	if !bytesEqual(pubAfter.VerifyingKey, keyBefore) ||
		!bytesEqual(pubAfter.SchemaHash, hashBefore) {
		t.Fatal("issuer publication changed after failed conflicting republish")
	}
	if tpAfter == nil || !bytesEqual(tpAfter.Public.VerifyingKey, trustedBefore) {
		t.Fatal("trusted material changed after failed conflicting republish")
	}
	if !policiesEqual(pubAfter.Policy, p) {
		t.Fatal("published policy parameters changed after failed republish")
	}
	// 用最初版本签发的凭证仍可验证。
	id, err := svc.IssueAndHold(IssueRequest{
		PolicyName:    p.Name,
		PolicyVersion: 1,
		Attributes:    goodAttrs(),
		TTL:           time.Hour,
	})
	if err != nil {
		t.Fatalf("issue after failed republish: %v", err)
	}
	res, err := svc.Prove(id, VerifyPolicy{AllowPredicates: []string{"is_adult"}, TTL: time.Minute},
		nil, []string{"is_adult"})
	if err != nil {
		t.Fatalf("prove after failed republish: %v", err)
	}
	if _, err := svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatalf("credential must verify after failed republish: %v", err)
	}

	t.Log("业务=失败发布不留半更新: 串行+并发冲突发布全部 version_conflict, 密钥/模式指纹/信任材料逐字节不变")
}

// countCodes 统计一组发布结果中的成功数与 version_conflict 数。
func countCodes(errs []error) (ok, conflict int) {
	for _, err := range errs {
		switch CodeOf(err) {
		case "":
			ok++
		case CodeVersionConflict:
			conflict++
		}
	}
	return ok, conflict
}

func policiesEqual(a, b Policy) bool {
	return bytesEqual(a.SchemaHash(), b.SchemaHash()) && a.Name == b.Name && a.Version == b.Version
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
