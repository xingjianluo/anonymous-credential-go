// Command demo 在单进程内模拟签发方、持有者与验证方，
// 运行一次完整的“签发 - 选择性披露 - 撤销”流程并打印验证结论。
package main

import (
	"fmt"
	"time"

	ac "github.com/xingjianluo/anonymous-credential-go"
)

func main() {
	start := time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC)
	clock := ac.NewFakeClock(start)
	svc := ac.NewService(ac.ServiceConfig{Clock: clock})

	// 策略 v1：姓名（必填非空）、等级（枚举）、年龄（0..150）；
	// 允许谓词：成年（age >= 18）。
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
	if err := svc.RegisterPolicy(pol); err != nil {
		panic(err)
	}

	// 签发：只披露 age 的谓词 is_adult，不披露真实年龄。
	credID, err := svc.IssueAndHold(ac.IssueRequest{
		PolicyName:    "driving-entitlement",
		PolicyVersion: 1,
		Attributes: map[string]ac.Value{
			"name":  ac.StringValue("Alice"),
			"level": ac.StringValue("C1"),
			"age":   ac.IntValue(29),
		},
		TTL: 7 * 24 * time.Hour,
	})
	must(err)
	fmt.Println("issued credential:", credID)

	// 证明：会话仅允许披露 level 与谓词 is_adult。
	res, err := svc.Prove(credID, ac.VerifyPolicy{
		AllowAttrs:      []string{"level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             5 * time.Minute,
	}, []string{"level"}, []string{"is_adult"})
	must(err)

	dec, err := svc.Check(res.SessionID, res.Presentation)
	must(err)
	fmt.Printf("decision 1: accepted=%v disclosed=%v predicates=%v\n",
		dec.Accepted, dec.DisclosedAttrs, dec.Predicates)

	// 重放同一证明：必须被拒绝。
	_, err = svc.Check(res.SessionID, res.Presentation)
	fmt.Printf("decision 2 (replay): code=%s\n", string(ac.CodeOf(err)))

	// 撤销后用新会话出示：必须立即失败。
	must(svc.Revoke(credID, "user-requested"))
	res2, err := svc.Prove(credID, ac.VerifyPolicy{
		AllowPredicates: []string{"is_adult"},
		TTL:             5 * time.Minute,
	}, nil, []string{"is_adult"})
	must(err)
	_, err = svc.Check(res2.SessionID, res2.Presentation)
	fmt.Printf("decision 3 (after revoke): code=%s\n", string(ac.CodeOf(err)))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
