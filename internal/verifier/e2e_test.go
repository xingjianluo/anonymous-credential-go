package verifier_test

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/xingjianluo/anonymous-credential-go/internal/commitment"
	"github.com/xingjianluo/anonymous-credential-go/internal/credential"
	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
	"github.com/xingjianluo/anonymous-credential-go/internal/holder"
	"github.com/xingjianluo/anonymous-credential-go/internal/issuer"
	"github.com/xingjianluo/anonymous-credential-go/internal/logging"
	"github.com/xingjianluo/anonymous-credential-go/internal/policy"
	"github.com/xingjianluo/anonymous-credential-go/internal/registry"
	"github.com/xingjianluo/anonymous-credential-go/internal/sys"
	"github.com/xingjianluo/anonymous-credential-go/internal/verifier"
)

type fixture struct {
	polreg *policy.Registry
	reg    *registry.Registry
	iss    *issuer.Issuer
	ver    *verifier.Verifier
	clock  *sys.StepClock
	logBuf *bytes.Buffer
}

func pol1() *policy.Policy {
	return &policy.Policy{
		Name: "id", Version: 1, Status: policy.StatusActive,
		Attrs: map[string]*policy.AttrSpec{
			"age":     {Name: "age", Type: policy.AttrInt, Required: true, Disclosable: true, Min: 0, Max: 150},
			"level":   {Name: "level", Type: policy.AttrEnum, Required: true, Disclosable: true, EnumValues: []string{"basic", "premium"}},
			"country": {Name: "country", Type: policy.AttrEnum, Required: true, Disclosable: true, EnumValues: []string{"CN", "US"}},
			"ssn":     {Name: "ssn", Type: policy.AttrString, Required: true, Disclosable: false, MaxLength: 32},
		},
		Rules: []policy.ConsistencyRule{policy.PremiumAgeRule},
	}
}

func pol2() *policy.Policy {
	return &policy.Policy{
		Name: "id", Version: 2, Status: policy.StatusActive,
		Attrs: map[string]*policy.AttrSpec{
			"age":     {Name: "age", Type: policy.AttrInt, Required: true, Disclosable: true, Min: 0, Max: 150},
			"level":   {Name: "level", Type: policy.AttrEnum, Required: true, Disclosable: true, EnumValues: []string{"basic", "premium", "gold"}},
			"country": {Name: "country", Type: policy.AttrEnum, Required: true, Disclosable: true, EnumValues: []string{"CN", "US", "JP"}},
			"ssn":     {Name: "ssn", Type: policy.AttrString, Required: true, Disclosable: false, MaxLength: 64},
		},
		Rules: []policy.ConsistencyRule{policy.PremiumAgeRule},
	}
}

func newFixture(t *testing.T, minV uint32) *fixture {
	t.Helper()
	polreg := policy.NewRegistry()
	if err := polreg.Register(pol1()); err != nil {
		t.Fatal(err)
	}
	if err := polreg.Register(pol2()); err != nil {
		t.Fatal(err)
	}
	reg := registry.New()
	rng := sys.NewSeededRandom(12345)
	clock := sys.NewStepClock(time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC))
	var buf bytes.Buffer
	log := logging.NewWithWriter(&buf)
	key, err := credential.GenerateKey(rng)
	if err != nil {
		t.Fatal(err)
	}
	iss := issuer.New(key, polreg, reg, clock, rng, log)
	ver := verifier.New(key.Public, polreg, reg, clock, rng, log, 5*time.Minute, minV)
	return &fixture{polreg: polreg, reg: reg, iss: iss, ver: ver, clock: clock, logBuf: &buf}
}

func issueToWallet(t *testing.T, f *fixture, holderID string, pv uint32, attrs map[string]any) (*holder.Wallet, *credential.Bundle) {
	t.Helper()
	b, err := f.iss.Issue(&policy.IssuanceRequest{HolderID: holderID, PolicyV: pv, Attrs: attrs})
	if err != nil {
		t.Fatal(err)
	}
	w := holder.NewWallet(holderID)
	w.Add(b)
	return w, b
}

func goodAttrs() map[string]any {
	return map[string]any{"age": 30, "level": "premium", "country": "CN", "ssn": "S-1"}
}

func present(t *testing.T, f *fixture, w *holder.Wallet, s *verifier.Session, pv uint32, disclose []string, preds []holder.Predicate) *holder.Presentation {
	t.Helper()
	p, err := w.Present(f.polreg, &holder.PresentationRequest{
		SessionID: s.ID, Challenge: s.Challenge, PolicyVersion: pv,
		Disclose: disclose, Predicates: preds,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHappyPath(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "alice", 1, goodAttrs())
	s, err := f.ver.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	p := present(t, f, w, s, 1, []string{"age", "country"},
		[]holder.Predicate{{Attr: "age", Op: "gte", Value: 18}, {Attr: "country", Op: "eq", Value: "CN"}})
	res, err := f.ver.Verify(s, p)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.SessionID != s.ID {
		t.Fatalf("bad result %+v", res)
	}
	// 未披露属性的明文/盐不得出现在证明中。
	if _, leak := p.Reveals["ssn"]; leak {
		t.Fatal("ssn leaked into presentation")
	}
	if _, leak := p.Reveals["level"]; leak {
		t.Fatal("level should not be disclosed this time")
	}
}

func TestRepeatedIssuanceUnlinkable(t *testing.T) {
	f := newFixture(t, 1)
	w := holder.NewWallet("bob")
	var bundles []*credential.Bundle
	for k := 0; k < 3; k++ {
		b, err := f.iss.Issue(&policy.IssuanceRequest{HolderID: "bob", PolicyV: 1, Attrs: goodAttrs()})
		if err != nil {
			t.Fatal(err)
		}
		w.Add(b)
		bundles = append(bundles, b)
	}
	b1, b2, b3 := bundles[0], bundles[1], bundles[2]
	if bytes.Equal(b1.ID, b2.ID) || bytes.Equal(b2.ID, b3.ID) {
		t.Fatal("credential ids must differ across repeated issuance")
	}
	if b1.IDCommitment == b2.IDCommitment || b2.IDCommitment == b3.IDCommitment {
		t.Fatal("id commitments must differ")
	}
	if bytes.Equal(b1.Credential.Signature, b2.Credential.Signature) {
		t.Fatal("signatures must differ")
	}
	// 记录可核对（通过标识承诺），且审计视图不回放标识秘密。
	rec, err := f.reg.Audit(b1.IDCommitment)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.CredID) != 0 {
		t.Fatal("audit must not expose raw credential id")
	}
}

func TestReplayWithinSession(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "c", 1, goodAttrs())
	s, _ := f.ver.NewSession()
	p := present(t, f, w, s, 1, []string{"age"}, nil)
	if _, err := f.ver.Verify(s, p); err != nil {
		t.Fatal(err)
	}
	if _, err := f.ver.Verify(s, p); cerr.KindOf(err) != cerr.KindReplay {
		t.Fatalf("second use: got %v", err)
	}
}

func TestCrossSessionReplay(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "d", 1, goodAttrs())
	s1, _ := f.ver.NewSession()
	p := present(t, f, w, s1, 1, []string{"age"}, nil)
	if _, err := f.ver.Verify(s1, p); err != nil {
		t.Fatal(err)
	}
	s2, _ := f.ver.NewSession()
	if _, err := f.ver.Verify(s2, p); cerr.KindOf(err) != cerr.KindReplay {
		t.Fatalf("cross-session replay: got %v", err)
	}
}

func TestTamperedDisclosure(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "e", 1, goodAttrs())
	s, _ := f.ver.NewSession()
	p := present(t, f, w, s, 1, []string{"age"}, nil)
	rv := p.Reveals["age"]
	rv.Value = int64(99)
	p.Reveals["age"] = rv
	_, err := f.ver.Verify(s, p)
	if cerr.KindOf(err) != cerr.KindProofTampered {
		t.Fatalf("got %v", err)
	}
}

func TestForgedSignature(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "g", 1, goodAttrs())
	s, _ := f.ver.NewSession()
	p := present(t, f, w, s, 1, []string{"age"}, nil)
	p.CredSignature[0] ^= 0xFF
	_, err := f.ver.Verify(s, p)
	if cerr.KindOf(err) != cerr.KindProofTampered {
		t.Fatalf("got %v", err)
	}
}

func TestForgedBlindedTag(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "h", 1, goodAttrs())
	s, _ := f.ver.NewSession()
	p := present(t, f, w, s, 1, []string{"age"}, nil)
	p.BlindedRevID[0] ^= 0x01
	_, err := f.ver.Verify(s, p)
	if cerr.KindOf(err) != cerr.KindUnknownCredential {
		t.Fatalf("forged blinded tag: got %v", err)
	}
}

func TestUnauthorizedDisclosure(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "i", 1, goodAttrs())
	s, _ := f.ver.NewSession()
	if _, err := w.Present(f.polreg, &holder.PresentationRequest{
		SessionID: s.ID, Challenge: s.Challenge, PolicyVersion: 1, Disclose: []string{"ssn"},
	}); cerr.KindOf(err) != cerr.KindUnauthorizedDisclosure {
		t.Fatalf("holder-side got %v", err)
	}
}

func TestPredicateOnUndisclosedRejected(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "j", 1, goodAttrs())
	s, _ := f.ver.NewSession()
	if _, err := w.Present(f.polreg, &holder.PresentationRequest{
		SessionID: s.ID, Challenge: s.Challenge, PolicyVersion: 1,
		Disclose:   []string{"country"},
		Predicates: []holder.Predicate{{Attr: "age", Op: "gte", Value: 18}},
	}); cerr.KindOf(err) != cerr.KindUnauthorizedDisclosure {
		t.Fatalf("got %v", err)
	}
}

func TestFalsePredicateRejected(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "k", 1, goodAttrs())
	s, _ := f.ver.NewSession()
	_, err := w.Present(f.polreg, &holder.PresentationRequest{
		SessionID: s.ID, Challenge: s.Challenge, PolicyVersion: 1,
		Disclose:   []string{"age"},
		Predicates: []holder.Predicate{{Attr: "age", Op: "gte", Value: 40}},
	})
	if cerr.KindOf(err) != cerr.KindProofInvalid {
		t.Fatalf("got %v", err)
	}
}

func TestRevocationImmediateAndConcurrent(t *testing.T) {
	f := newFixture(t, 1)
	w, b := issueToWallet(t, f, "m", 1, goodAttrs())

	const n = 60
	var wg sync.WaitGroup
	type outcome struct {
		err error
		seq uint64
	}
	results := make([]outcome, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			// 注意：goroutine 内不得调用 t.Fatal 等 testing.T 方法，
			// 所有失败都通过 results 回收后主 goroutine 统一判定。
			sess, serr := f.ver.NewSession()
			if serr != nil {
				results[i] = outcome{err: serr}
				return
			}
			pp, perr := w.Present(f.polreg, &holder.PresentationRequest{
				SessionID: sess.ID, Challenge: sess.Challenge, PolicyVersion: 1,
				Disclose: []string{"country"},
			})
			if perr != nil {
				results[i] = outcome{err: perr}
				return
			}
			res, verr := f.ver.Verify(sess, pp)
			if verr == nil {
				results[i] = outcome{seq: res.RegistrySeq}
			} else {
				results[i] = outcome{err: verr}
			}
		}(i)
	}
	// 在校验进行中并发提交撤销。
	go func() {
		<-start
		f.clock.Advance(time.Millisecond)
		_ = f.iss.Revoke(b.ID)
	}()
	close(start)
	wg.Wait()

	// 撤销操作的线性化点：记录修订版本 1。
	revSeq, revoked := f.reg.RevokeRevision(b.ID)
	if !revoked {
		t.Fatal("test setup expected credential to be revoked")
	}
	accepts, revokedSeen := 0, 0
	for _, o := range results {
		if o.err == nil {
			accepts++
			// 接受所观察到的状态必须早于撤销线性化点。
			if o.seq >= revSeq {
				t.Fatalf("linearizability violation: accept observed seq %d >= revoke seq %d", o.seq, revSeq)
			}
		} else if cerr.KindOf(o.err) == cerr.KindCredentialRevoked {
			revokedSeen++
		} else {
			t.Fatalf("unexpected concurrent result: %v", o.err)
		}
	}
	t.Logf("accepts=%d revoked=%d revokeSeq=%d", accepts, revokedSeen, revSeq)

	// 撤销后新会话必然失败（立即生效）。
	s2, _ := f.ver.NewSession()
	p2 := present(t, f, w, s2, 1, []string{"country"}, nil)
	if _, err := f.ver.Verify(s2, p2); cerr.KindOf(err) != cerr.KindCredentialRevoked {
		t.Fatalf("post-revocation verify: got %v", err)
	}
}

func TestVersionEvolution(t *testing.T) {
	f := newFixture(t, 1)
	// v2 凭证在 minAccepted=1 下可验证。
	w2, _ := issueToWallet(t, f, "n", 2, map[string]any{
		"age": 40, "level": "gold", "country": "JP", "ssn": "S2",
	})
	s, _ := f.ver.NewSession()
	p := present(t, f, w2, s, 2, []string{"country"}, nil)
	if _, err := f.ver.Verify(s, p); err != nil {
		t.Fatalf("v2 should verify under min=1: %v", err)
	}

	// 未知版本拒绝。
	s2, _ := f.ver.NewSession()
	p2 := present(t, f, w2, s2, 2, []string{"country"}, nil)
	p2.PolicyVersion = 77
	_, err := f.ver.Verify(s2, p2)
	if cerr.KindOf(err) != cerr.KindUnknownPolicyVersion {
		t.Fatalf("unknown version: got %v", err)
	}

	// 提高验证方下界后，历史 v1 凭证被明确拒绝。
	strictVer := verifier.New(f.iss.PublicKey(), f.polreg, f.reg, f.clock, sys.NewSeededRandom(9), logging.Discard(), time.Minute, 2)
	w1, _ := issueToWallet(t, f, "o", 1, goodAttrs())
	s3, _ := strictVer.NewSession()
	p3, err := w1.Present(f.polreg, &holder.PresentationRequest{
		SessionID: s3.ID, Challenge: s3.Challenge, PolicyVersion: 1, Disclose: []string{"country"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strictVer.Verify(s3, p3); cerr.KindOf(err) != cerr.KindIncompatibleVersion {
		t.Fatalf("below minimum: got %v", err)
	}
}

func TestSchemaParamChangeIncompatible(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "p", 1, goodAttrs())
	// 用一个“同版本号但参数不同”的注册表替换，模拟参数被不兼容修改。
	rogue := policy.NewRegistry()
	changed := pol1()
	changed.Attrs["age"].Max = 200
	if err := rogue.Register(changed); err != nil {
		t.Fatal(err)
	}
	v := verifier.New(f.iss.PublicKey(), rogue, f.reg, f.clock, sys.NewSeededRandom(1), logging.Discard(), time.Minute, 1)
	s, _ := v.NewSession()
	// challenge 由新 verifier 生成，需要用它重建证明。
	p, err := w.Present(rogue, &holder.PresentationRequest{
		SessionID: s.ID, Challenge: s.Challenge, PolicyVersion: 1, Disclose: []string{"age"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Verify(s, p)
	if cerr.KindOf(err) != cerr.KindIncompatibleVersion {
		t.Fatalf("schema param change: got %v", err)
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "q", 1, goodAttrs())
	s, _ := f.ver.NewSession()
	p := present(t, f, w, s, 1, []string{"age"}, nil)
	f.clock.Advance(10 * time.Minute)
	if _, err := f.ver.Verify(s, p); cerr.KindOf(err) != cerr.KindReplay {
		t.Fatalf("expired: got %v", err)
	}
}

func TestLogsContainSessionDisclosedBasis(t *testing.T) {
	f := newFixture(t, 1)
	w, _ := issueToWallet(t, f, "r", 1, goodAttrs())
	s, _ := f.ver.NewSession()
	p := present(t, f, w, s, 1, []string{"age", "country"}, nil)
	if _, err := f.ver.Verify(s, p); err != nil {
		t.Fatal(err)
	}
	logs := f.logBuf.String()
	for _, want := range []string{"session=" + s.ID, "disclosed=age,country", "basis=", "decision=accept"} {
		if !bytes.Contains([]byte(logs), []byte(want)) {
			t.Fatalf("log missing %q in:\n%s", want, logs)
		}
	}
	if bytes.Contains([]byte(logs), []byte("ssn")) {
		t.Fatal("logs must not mention undisclosed ssn")
	}
}

func TestMerkleOpeningTamperDirectly(t *testing.T) {
	root := [32]byte{1, 2, 3}
	rv := &commitment.Reveal{Name: "age", Position: 0}
	err := commitment.Verify(root, 4, rv)
	if err == nil {
		t.Fatal("empty siblings for 4-slot tree must fail")
	}
}
