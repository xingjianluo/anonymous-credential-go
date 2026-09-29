// Command demo 在单进程内模拟签发方、持有者与两个验证方，演示：
//
//  1. v2 不可关联出示：同一持有者多张凭证跨验证方/跨时间出示，公开结果无可复用线索；
//  2. 撤销即时生效，且撤销核对不携带长期标识；
//  3. 旧格式凭证仅在声明兼容窗口内可验证，窗口结束被明确拒绝；
//  4. 同版本重复发布：一致幂等，参数不一致返回 version_conflict。
package main

import (
	"fmt"
	"time"

	ac "github.com/xingjianluo/anonymous-credential-go"
)

func main() {
	start := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	clock := ac.NewFakeClock(start)
	svc := ac.NewService(ac.ServiceConfig{Clock: clock})

	pol := ac.Policy{
		Name:     "driving-entitlement",
		Version:  1,
		IssuedAt: start,
		Attributes: []ac.AttributeSpec{
			{Name: "name", Type: ac.AttrString, Required: true, NonEmpty: true},
			{Name: "level", Type: ac.AttrString, Required: true, NonEmpty: true,
				Allowed: []string{"C1", "C2", "D"}},
			{Name: "age", Type: ac.AttrInt, Required: true, Min: 0, Max: 150},
		},
		Predicates: []ac.PredicateSpec{
			{Name: "is_adult", Attr: "age", Op: ac.PredGreaterEqual, Threshold: 18},
		},
	}
	must(svc.RegisterPolicy(pol))

	attrs := func(name string) map[string]ac.Value {
		return map[string]ac.Value{
			"name": ac.StringValue(name), "level": ac.StringValue("C1"), "age": ac.IntValue(29),
		}
	}
	cred1, err := svc.IssueAndHold(ac.IssueRequest{
		PolicyName: "driving-entitlement", PolicyVersion: 1,
		Attributes: attrs("Alice"), TTL: 365 * 24 * time.Hour,
	})
	must(err)
	cred2, err := svc.IssueAndHold(ac.IssueRequest{
		PolicyName: "driving-entitlement", PolicyVersion: 1,
		Attributes: attrs("Alice"), TTL: 365 * 24 * time.Hour,
	})
	must(err)
	fmt.Println("issued two v2 credentials for the same holder")

	verifyPol := ac.VerifyPolicy{
		AllowAttrs:      []string{"level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             5 * time.Minute,
	}

	// 验证方 1：不同时间两次出示（cred1、cred2）。
	res1, err := svc.Prove(cred1, verifyPol, []string{"level"}, []string{"is_adult"})
	must(err)
	d1, err := svc.Check(res1.SessionID, res1.Presentation)
	must(err)
	clock.Advance(2 * time.Hour)
	res2, err := svc.Prove(cred2, verifyPol, []string{"level"}, []string{"is_adult"})
	must(err)
	d2, err := svc.Check(res2.SessionID, res2.Presentation)
	must(err)
	fmt.Printf("verifier1: accepted=%v cred_id=%q show_id=%s\n", d1.Accepted, d1.CredID, d1.ShowID)
	fmt.Printf("verifier1: accepted=%v cred_id=%q show_id=%s\n", d2.Accepted, d2.CredID, d2.ShowID)
	if d1.ShowID == d2.ShowID || d1.CredID != "" || d2.CredID != "" {
		panic("v2 showings must carry distinct one-time show ids and no cred id")
	}
	fmt.Println("two scenes share no reusable show identifier; verifier decisions carry no cred id")

	// 撤销 cred1：撤销前已完成的 d1 有效；撤销后新出示立即失败。
	must(svc.Revoke(cred1, "user-requested"))
	res3, err := svc.Prove(cred1, ac.VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: 5 * time.Minute,
	}, nil, []string{"is_adult"})
	must(err)
	if _, err := svc.Check(res3.SessionID, res3.Presentation); err != nil {
		fmt.Printf("after revoke cred1: code=%s (decision cred_id=%q)\n",
			string(ac.CodeOf(err)), "")
	}
	// cred2 不受影响。
	d4, err := func() (*ac.Decision, error) {
		r, e := svc.Prove(cred2, ac.VerifyPolicy{
			AllowPredicates: []string{"is_adult"}, TTL: 5 * time.Minute,
		}, nil, []string{"is_adult"})
		if e != nil {
			return nil, e
		}
		return svc.Check(r.SessionID, r.Presentation)
	}()
	must(err)
	fmt.Printf("cred2 still accepted after cred1 revoked: %v\n", d4.Accepted)

	// 重放拒绝。
	if _, err := svc.Check(res2.SessionID, res2.Presentation); err != nil {
		fmt.Printf("replay rejected: code=%s\n", string(ac.CodeOf(err)))
	}

	// 旧格式兼容窗口：单独签发一张 legacy 凭证，窗口 48h。
	must(svc.Issuer.UseLegacy(true))
	must(svc.SetLegacyWindow(1, clock.Now().Add(48*time.Hour)))
	legacyID, err := svc.IssueAndHold(ac.IssueRequest{
		PolicyName: "driving-entitlement", PolicyVersion: 1,
		Attributes: attrs("Legacy"), TTL: 365 * 24 * time.Hour,
	})
	must(err)
	rL, err := svc.Prove(legacyID, ac.VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: 5 * time.Minute,
	}, nil, []string{"is_adult"})
	must(err)
	if _, err := svc.Check(rL.SessionID, rL.Presentation); err != nil {
		fmt.Printf("legacy within window unexpected error: %v\n", err)
	} else {
		fmt.Println("legacy credential accepted within compatibility window")
	}
	clock.Advance(49 * time.Hour)
	rL2, err := svc.Prove(legacyID, ac.VerifyPolicy{
		AllowPredicates: []string{"is_adult"}, TTL: 5 * time.Minute,
	}, nil, []string{"is_adult"})
	must(err)
	if _, err := svc.Check(rL2.SessionID, rL2.Presentation); err != nil {
		fmt.Printf("legacy after window: code=%s\n", string(ac.CodeOf(err)))
	}

	// 同版本重复发布。
	if err := svc.RegisterPolicy(pol); err != nil {
		fmt.Printf("identical republish unexpected error: %v\n", err)
	} else {
		fmt.Println("identical republish: idempotent")
	}
	drift := pol
	drift.Attributes = append(drift.Attributes, ac.AttributeSpec{
		Name: "region", Type: ac.AttrString, Required: true,
	})
	if err := svc.RegisterPolicy(drift); err != nil {
		fmt.Printf("conflicting republish: code=%s\n", string(ac.CodeOf(err)))
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
