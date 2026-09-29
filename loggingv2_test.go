package anoncred

import (
	"testing"
)

// v2 验证日志：只有 mode=v2 与当次 show_id，绝不含长期 cred_id；
// 多次出示的 show_id 必须不同，无法据此串联。
func TestV2AuditLogUnlinkable(t *testing.T) {
	f := newFixture(t, 2700)
	id := f.issue(t, goodAttrs())
	for i := 0; i < 3; i++ {
		res, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.Check(res.SessionID, res.Presentation); err != nil {
			t.Fatal(err)
		}
	}
	lines := decodeLogLines(t, f.logs.Bytes())
	var showIDs []string
	v2Lines := 0
	for _, m := range lines {
		if m["event"] != "verify" || m["mode"] != "v2" {
			continue
		}
		v2Lines++
		if _, ok := m["cred_id"]; ok {
			t.Fatalf("v2 log must not contain long-term cred_id: %v", m)
		}
		sid, _ := m["show_id"].(string)
		if sid == "" {
			t.Fatalf("v2 log missing one-time show_id: %v", m)
		}
		for _, prev := range showIDs {
			if prev == sid {
				t.Fatalf("show_id repeats across presentations: %s", sid)
			}
		}
		showIDs = append(showIDs, sid)
	}
	if v2Lines != 3 {
		t.Fatalf("expected 3 v2 verify lines, got %d", v2Lines)
	}
	// 逐条确认：长期 CredID 的十六进制不出现在任何一条 v2 验证日志文本中。
	// （签发事件按签发方审计需要仍记录 cred_id，不属于验证侧可关联面。）
	for _, m := range lines {
		if m["event"] != "verify" || m["mode"] != "v2" {
			continue
		}
		for k, v := range m {
			if s, ok := v.(string); ok && s == id {
				t.Fatalf("long-term credential id appeared in v2 verify log field %q", k)
			}
		}
	}
}

// legacy 日志仍保留 cred_id（旧版已知限制），mode=legacy。
func TestLegacyAuditLogMode(t *testing.T) {
	f := newFixture(t, 2701)
	id := f.issue(t, goodAttrs())
	res := f.proveRaw(t, id, v2Pol(), []string{"level"}, []string{"is_adult"})
	if _, err := f.svc.Check(res.SessionID, res.Presentation); err != nil {
		t.Fatal(err)
	}
	lines := decodeLogLines(t, f.logs.Bytes())
	var found bool
	for _, m := range lines {
		if m["event"] == "verify" && m["accepted"] == true {
			if m["mode"] != "legacy" {
				t.Fatalf("legacy mode = %v", m["mode"])
			}
			if m["cred_id"] != id {
				t.Fatalf("legacy log cred_id = %v", m["cred_id"])
			}
			found = true
		}
	}
	if !found {
		t.Fatal("no accepted legacy verify line")
	}
}
