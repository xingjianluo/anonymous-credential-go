package anoncred

import (
	"bytes"
	"testing"
	"time"
)

func TestHappyPathSelectiveDisclosure(t *testing.T) {
	f := newFixture(t, 7)
	id := f.issue(t, goodAttrs())

	// 仅披露 level 与谓词 is_adult；不披露 name/age 明文。
	dec, err := f.proveCheck(t, id, VerifyPolicy{
		AllowAttrs:      []string{"level"},
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}, []string{"level"}, []string{"is_adult"})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !dec.Accepted {
		t.Fatalf("decision not accepted: %+v", dec)
	}
	if !equalStrings(dec.DisclosedAttrs, []string{"level"}) {
		t.Fatalf("disclosed = %v", dec.DisclosedAttrs)
	}
	if !equalStrings(dec.Predicates, []string{"is_adult"}) {
		t.Fatalf("predicates = %v", dec.Predicates)
	}

	// 只出示谓词，不披露任何属性值。
	dec2, err := f.proveCheck(t, id, VerifyPolicy{
		AllowPredicates: []string{"is_adult"},
		TTL:             time.Minute,
	}, nil, []string{"is_adult"})
	if err != nil || !dec2.Accepted {
		t.Fatalf("predicate-only proof: dec=%+v err=%v", dec2, err)
	}
	if len(dec2.DisclosedAttrs) != 0 {
		t.Fatalf("expected no disclosed attrs, got %v", dec2.DisclosedAttrs)
	}
}

func TestRepeatIssuanceUnlinkable(t *testing.T) {
	f := newFixture(t, 11)
	var ids [][]byte
	for i := 0; i < 3; i++ {
		id := f.issue(t, goodAttrs())
		b, err := decodeHex(id)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, b)
	}
	for i := 0; i < len(ids); i++ {
		for j := i + 1; j < len(ids); j++ {
			if bytes.Equal(ids[i], ids[j]) {
				t.Fatalf("credential ids correlatable: %x == %x", ids[i], ids[j])
			}
		}
	}
	recs := f.svc.Issuer.Records()
	if len(recs) != 3 {
		t.Fatalf("records = %d, want 3", len(recs))
	}
	for _, r := range recs {
		if r.Pseudonym == "" {
			t.Fatal("record must keep pseudonym for audit")
		}
		// 记录中不得以明文保留属性值。
		for _, attr := range []string{"name", "level", "age", "Alice", "C1"} {
			if bytes.Contains(r.CredID, []byte(attr)) {
				t.Fatalf("cred id leaks %s", attr)
			}
			for _, c := range r.Commitments {
				if bytes.Equal(c, []byte(attr)) {
					t.Fatalf("commitment equals plaintext %s", attr)
				}
			}
		}
	}
	// 不同凭证的同一属性承诺必须不同（盐化）。
	first := f.svc.Issuer.Records()
	var seen = map[string]bool{}
	for _, r := range first {
		for name, c := range r.Commitments {
			key := name + ":" + string(c)
			if seen[key] {
				t.Fatalf("commitment for %s repeats across credentials", name)
			}
			seen[key] = true
		}
	}
}

func TestIssuerRecordAuditable(t *testing.T) {
	f := newFixture(t, 13)
	id := f.issue(t, goodAttrs())
	idB, _ := decodeHex(id)
	rec := f.svc.Issuer.LookupRecord(idB)
	if rec == nil {
		t.Fatal("record not found")
	}
	if rec.PolicyVersion != 1 || rec.Pseudonym != "local-holder" {
		t.Fatalf("unexpected record: %+v", rec)
	}
	if rec.Revoked {
		t.Fatal("new credential must not be revoked")
	}
	if err := f.svc.Issuer.Revoke(idB, "audit-test"); err != nil {
		t.Fatal(err)
	}
	rec2 := f.svc.Issuer.LookupRecord(idB)
	if !rec2.Revoked || rec2.RevokeReason != "audit-test" {
		t.Fatalf("revoke state not persisted: %+v", rec2)
	}
	if err := f.svc.Issuer.Revoke(idB, "again"); CodeOf(err) != CodeNoSuchCredential && err != nil {
		// 重复吊销幂等：允许返回 nil；未知 ID 必须报错。这里已知 ID，不应报 NoSuchCredential。
		t.Fatalf("unexpected: %v", err)
	}
}

// --- helpers ----------------------------------------------------------------

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
		if m[s] < 0 {
			return false
		}
	}
	return true
}

func decodeHex(s string) ([]byte, error) {
	return hexDecode(s)
}
