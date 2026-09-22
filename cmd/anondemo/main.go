// Command anondemo 在本地端到端演示匿名凭证的签发、选择性披露、
// 重放/篡改防护、撤销与版本演进。运行：go run ./cmd/anondemo
package main

import (
	"fmt"
	"os"

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

func main() {
	// 生产可用 crypto/rand + 真实时钟；演示日志打到 stderr。
	rng := sys.NewSystemRandom()
	clock := sys.RealClock{}
	log := logging.New()
	polreg := policy.NewRegistry()
	reg := registry.New()

	must(polreg.Register(v1Policy()))
	must(polreg.Register(v2Policy()))

	key, err := credential.GenerateKey(rng)
	must(err)
	iss := issuer.New(key, polreg, reg, clock, rng, log)
	ver := verifier.New(key.Public, polreg, reg, clock, rng, log, 0, 1)

	fmt.Println("==== 1. 正常签发与选择性披露验证 ====")
	w := holder.NewWallet("alice")
	bundle, err := iss.Issue(&policy.IssuanceRequest{
		HolderID: "alice", PolicyV: 1,
		Attrs: map[string]any{"age": 30, "level": "premium", "country": "CN", "ssn": "S-0001"},
	})
	must(err)
	w.Add(bundle)
	fmt.Printf("签发成功（登记记录不含属性明文，当前记录数=%d）\n", reg.Stats().Total)

	sess, err := ver.NewSession()
	must(err)
	// 只披露 age/country；ssn 不可披露，level 可披露但本次不披露。
	pres, err := w.Present(polreg, &holder.PresentationRequest{
		SessionID: sess.ID, Challenge: sess.Challenge, PolicyVersion: 1,
		Disclose:   []string{"age", "country"},
		Predicates: []holder.Predicate{{Attr: "age", Op: "gte", Value: 18}},
	})
	must(err)
	res, err := ver.Verify(sess, pres)
	show(res, err)

	fmt.Println("==== 2. 拒绝：缺失必填 / 越界 / 一致性违规 ====")
	_, e := iss.Issue(&policy.IssuanceRequest{HolderID: "b", PolicyV: 1, Attrs: map[string]any{"level": "basic", "country": "CN", "ssn": "x"}})
	fmt.Printf("缺失 age -> %s\n", cerr.KindOf(e))
	_, e = iss.Issue(&policy.IssuanceRequest{HolderID: "b", PolicyV: 1, Attrs: map[string]any{"age": 200, "level": "basic", "country": "CN", "ssn": "x"}})
	fmt.Printf("age 越界 -> %s\n", cerr.KindOf(e))
	_, e = iss.Issue(&policy.IssuanceRequest{HolderID: "b", PolicyV: 1, Attrs: map[string]any{"age": 10, "level": "premium", "country": "CN", "ssn": "x"}})
	fmt.Printf("premium 但 age<18 -> %s\n", cerr.KindOf(e))

	fmt.Println("==== 3. 拒绝：越权披露 ssn ====")
	sess3, _ := ver.NewSession()
	_, e = w.Present(polreg, &holder.PresentationRequest{
		SessionID: sess3.ID, Challenge: sess3.Challenge, PolicyVersion: 1,
		Disclose: []string{"ssn"},
	})
	fmt.Printf("持有者构造阶段即拒绝 -> %s\n", cerr.KindOf(e))

	fmt.Println("==== 4. 拒绝：重放同一会话 ====")
	sess4, _ := ver.NewSession()
	p4, _ := w.Present(polreg, &holder.PresentationRequest{
		SessionID: sess4.ID, Challenge: sess4.Challenge, PolicyVersion: 1,
		Disclose: []string{"age"},
	})
	_, e = ver.Verify(sess4, p4)
	fmt.Printf("第一次提交 -> %s（预期成功）\n", okKind(e))
	_, e = ver.Verify(sess4, p4)
	fmt.Printf("第二次提交 -> %s\n", cerr.KindOf(e))

	fmt.Println("==== 5. 拒绝：跨会话重放（挑战不匹配） ====")
	sess5, _ := ver.NewSession()
	// p4 绑定的是 sess4 的挑战，拿到 sess5 用。
	_, e = ver.Verify(sess5, p4)
	fmt.Printf("跨会话 -> %s\n", cerr.KindOf(e))

	fmt.Println("==== 6. 拒绝：篡改披露值 ====")
	sess6, _ := ver.NewSession()
	p6, _ := w.Present(polreg, &holder.PresentationRequest{
		SessionID: sess6.ID, Challenge: sess6.Challenge, PolicyVersion: 1,
		Disclose: []string{"age"},
	})
	rv := p6.Reveals["age"]
	rv.Value = int64(99)
	p6.Reveals["age"] = rv
	_, e = ver.Verify(sess6, p6)
	fmt.Printf("篡改 age -> %s\n", cerr.KindOf(e))

	fmt.Println("==== 7. 撤销后立即失败 ====")
	must(iss.Revoke(bundle.ID))
	sess7, _ := ver.NewSession()
	p7, _ := w.Present(polreg, &holder.PresentationRequest{
		SessionID: sess7.ID, Challenge: sess7.Challenge, PolicyVersion: 1,
		Disclose: []string{"country"},
	})
	_, e = ver.Verify(sess7, p7)
	fmt.Printf("已撤销凭证 -> %s\n", cerr.KindOf(e))

	fmt.Println("==== 8. 版本演进与不兼容 ====")
	// v2 是 Active，但验证方下界策略可配置；未知版本直接拒绝。
	w2 := holder.NewWallet("carol")
	b2, e := iss.Issue(&policy.IssuanceRequest{HolderID: "carol", PolicyV: 2,
		Attrs: map[string]any{"age": 40, "level": "gold", "country": "US", "ssn": "y"}})
	must(e)
	w2.Add(b2)
	sess8, _ := ver.NewSession()
	p8, _ := w2.Present(polreg, &holder.PresentationRequest{
		SessionID: sess8.ID, Challenge: sess8.Challenge, PolicyVersion: 2,
		Disclose: []string{"country"},
	})
	r8, e := ver.Verify(sess8, p8)
	show(r8, e)
	// 不存在的版本。
	sess9, _ := ver.NewSession()
	p9, _ := w2.Present(polreg, &holder.PresentationRequest{
		SessionID: sess9.ID, Challenge: sess9.Challenge, PolicyVersion: 2,
		Disclose: []string{"country"},
	})
	p9.PolicyVersion = 99
	_, e = ver.Verify(sess9, p9)
	fmt.Printf("未知版本 -> %s\n", cerr.KindOf(e))
	// 废止版本不允许新签发（状态演进，参数不变）。
	must(polreg.Deprecate(1))
	_, e = iss.Issue(&policy.IssuanceRequest{HolderID: "d", PolicyV: 1,
		Attrs: map[string]any{"age": 20, "level": "basic", "country": "CN", "ssn": "z"}})
	fmt.Printf("废止版本新签发 -> %s\n", cerr.KindOf(e))

	fmt.Println("==== 9. 重复申领不可关联 ====")
	bA, _ := iss.Issue(&policy.IssuanceRequest{HolderID: "erin", PolicyV: 2,
		Attrs: map[string]any{"age": 25, "level": "basic", "country": "DE", "ssn": "e1"}})
	bB, _ := iss.Issue(&policy.IssuanceRequest{HolderID: "erin", PolicyV: 2,
		Attrs: map[string]any{"age": 25, "level": "basic", "country": "DE", "ssn": "e2"}})
	fmt.Printf("同一持有者两次申领：ID不同=%v，签名不同=%v，标识承诺不同=%v\n",
		string(bA.ID) != string(bB.ID),
		string(bA.Credential.Signature) != string(bB.Credential.Signature),
		bA.IDCommitment != bB.IDCommitment)
}

func v1Policy() *policy.Policy {
	return &policy.Policy{
		Name: "identity", Version: 1, Status: policy.StatusActive,
		Attrs: map[string]*policy.AttrSpec{
			"age":     {Name: "age", Type: policy.AttrInt, Required: true, Disclosable: true, Min: 0, Max: 150},
			"level":   {Name: "level", Type: policy.AttrEnum, Required: true, Disclosable: true, EnumValues: []string{"basic", "premium"}},
			"country": {Name: "country", Type: policy.AttrEnum, Required: true, Disclosable: true, EnumValues: []string{"CN", "US", "DE"}},
			"ssn":     {Name: "ssn", Type: policy.AttrString, Required: true, Disclosable: false, MaxLength: 32},
		},
		Rules: []policy.ConsistencyRule{policy.PremiumAgeRule},
	}
}

func v2Policy() *policy.Policy {
	return &policy.Policy{
		Name: "identity", Version: 2, Status: policy.StatusActive,
		Attrs: map[string]*policy.AttrSpec{
			"age":     {Name: "age", Type: policy.AttrInt, Required: true, Disclosable: true, Min: 0, Max: 150},
			"level":   {Name: "level", Type: policy.AttrEnum, Required: true, Disclosable: true, EnumValues: []string{"basic", "premium", "gold"}},
			"country": {Name: "country", Type: policy.AttrEnum, Required: true, Disclosable: true, EnumValues: []string{"CN", "US", "DE", "JP"}},
			"ssn":     {Name: "ssn", Type: policy.AttrString, Required: true, Disclosable: false, MaxLength: 64},
		},
		Rules: []policy.ConsistencyRule{policy.PremiumAgeRule},
	}
}

func okKind(err error) string {
	if err == nil {
		return "accepted"
	}
	return cerr.KindOf(err).String()
}

func show(r *verifier.Result, err error) {
	if err != nil {
		fmt.Printf("验证失败: kind=%s reason=%v\n", cerr.KindOf(err), err)
		return
	}
	fmt.Printf("验证通过: session=%s disclosed=%v basis=%s\n", r.SessionID, r.DisclosedSet, r.Basis)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}
