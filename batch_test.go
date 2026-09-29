package anoncred

import (
	"sort"
	"testing"
	"time"
)

// batchRun 用固定种子签发 batchN 张凭证并逐张做一次 v2 出示验证，
// 返回“被接受的 ShowID（排序）”与“被拒绝原因（按凭证序号）”。
func batchRun(t *testing.T, seed uint64, batchN int) (accepted []string, codes []Code) {
	t.Helper()
	f := newFixture(t, seed)
	ids := make([]string, batchN)
	for i := 0; i < batchN; i++ {
		attrs := map[string]Value{
			"name":  StringValue("Person-" + itoa(i)),
			"level": StringValue("C1"),
			"age":   IntValue(20 + int64(i%60)),
		}
		ids[i] = f.issue(t, attrs)
	}
	codes = make([]Code, batchN)
	for i, id := range ids {
		r, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
		if err != nil {
			t.Fatalf("batch %d prepare: %v", i, err)
		}
		d, err := f.svc.Check(r.SessionID, r.Presentation)
		if err != nil {
			codes[i] = CodeOf(err)
			continue
		}
		if !d.Accepted {
			codes[i] = d.Reason
			continue
		}
		accepted = append(accepted, d.ShowID)
	}
	sort.Strings(accepted)
	return accepted, codes
}

// TestBatch1000StateConsistency：连续准备/验证上千张凭证，全部接受、
// ShowID 两两不同；两次同种子运行结论可复现（同一批 ShowID 集合）。
func TestBatch1000StateConsistency(t *testing.T) {
	const n = 1000
	accepted1, codes1 := batchRun(t, 2600, n)
	accepted2, codes2 := batchRun(t, 2600, n)

	if len(accepted1) != n {
		var bad int
		for _, c := range codes1 {
			if c != "" {
				bad++
			}
		}
		t.Fatalf("batch1 accepted %d of %d (%d rejections)", len(accepted1), n, bad)
	}
	uniq := map[string]bool{}
	for _, s := range accepted1 {
		if uniq[s] {
			t.Fatalf("duplicate show id in batch: %s", s)
		}
		uniq[s] = true
	}
	// 两次同种子运行：签发与每次出示均确定性，结论集合必须完全一致。
	if len(accepted1) != len(accepted2) {
		t.Fatalf("batch size differs across runs: %d vs %d", len(accepted1), len(accepted2))
	}
	for i := range accepted1 {
		if accepted1[i] != accepted2[i] {
			t.Fatalf("batch result not reproducible at index %d: %s vs %s", i, accepted1[i], accepted2[i])
		}
	}
	// 全部无拒绝码。
	for i, c := range codes2 {
		if c != "" {
			t.Fatalf("batch run 2 credential %d rejected: %s", i, c)
		}
	}
}

// TestBatchWithRevocationSurgical：批量凭证中吊销少数几张，只影响这些凭证，
// 其余结论保持一致且可复现。
func TestBatchWithRevocationSurgical(t *testing.T) {
	const n = 200
	f := newFixture(t, 2601)
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		attrs := map[string]Value{
			"name":  StringValue("Batch-" + itoa(i)),
			"level": StringValue("C2"),
			"age":   IntValue(30),
		}
		ids[i] = f.issue(t, attrs)
	}
	victims := map[int]bool{5: true, 77: true, 199: true}
	for i := range victims {
		if err := f.svc.Revoke(ids[i], "batch-revoke"); err != nil {
			t.Fatal(err)
		}
	}
	rejected := 0
	for i, id := range ids {
		_, err := f.svc.ProveUnlinkable(id, v2Pol(), []string{"level"}, []string{"is_adult"})
		if victims[i] {
			if CodeOf(err) != CodeRevokedCredential {
				t.Fatalf("victim %d prepare should fail revoked, got %v", i, err)
			}
			rejected++
			continue
		}
		if err != nil {
			t.Fatalf("non-victim %d prepare failed: %v", i, err)
		}
	}
	if rejected != len(victims) {
		t.Fatalf("victim count = %d, want %d", rejected, len(victims))
	}

	// 钱包与签发记录数量不变，状态无丢失。
	if len(f.svc.Holder.CredentialIDs()) != n {
		t.Fatalf("wallet lost credentials: %d", len(f.svc.Holder.CredentialIDs()))
	}
	if len(f.svc.Issuer.Records()) != n {
		t.Fatalf("issuer records lost: %d", len(f.svc.Issuer.Records()))
	}
}

var _ = time.Minute
