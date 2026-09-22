package registry

import (
	"bytes"
	"testing"

	"github.com/xingjianluo/anonymous-credential-go/internal/canonical"

	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
)

func idCommit(id []byte) [32]byte {
	// 用与 credential.IDCommit 相同的算法复算（此处直接用 canonical）。
	return canonical.Hash("cred-id-v1", canonical.EncodeBytes(id))
}

func TestRevokeAndBlindedCheck(t *testing.T) {
	r := New()
	id := []byte("cred-id-1")
	c := idCommit(id)
	if err := r.Add(&Record{CredID: id, IDCommitment: c, PolicyVer: 1}); err != nil {
		t.Fatal(err)
	}
	ch := []byte("session-challenge")
	tag := BlindedTag(id, ch)

	st, err := r.CheckBlinded(ch, tag)
	if err != nil || !st.Active || st.Revoked {
		t.Fatalf("active credential expected, got %+v err=%v", st, err)
	}

	// 不同挑战下标签必须不同（不可跨会话关联）。
	tag2 := BlindedTag(id, []byte("other-challenge"))
	if tag2 == tag {
		t.Fatal("blinded tag must vary with challenge")
	}

	// 随机伪造标签无法命中。
	var fake [32]byte
	fake[7] = 3
	if _, err := r.CheckBlinded(ch, fake); cerr.KindOf(err) != cerr.KindUnknownCredential {
		t.Fatalf("unknown tag expected, got %v", err)
	}

	if err := r.Revoke(id); err != nil {
		t.Fatal(err)
	}
	st, err = r.CheckBlinded(ch, tag)
	if err != nil || !st.Revoked || st.Active {
		t.Fatalf("revoked credential expected, got %+v err=%v", st, err)
	}
	if s := r.Stats(); s.Total != 1 || s.Revoked != 1 || s.Active != 0 {
		t.Fatalf("stats wrong: %+v", s)
	}
}

func TestRevokeUnknownID(t *testing.T) {
	r := New()
	if err := r.Revoke([]byte("nope")); cerr.KindOf(err) != cerr.KindUnknownCredential {
		t.Fatalf("got %v", err)
	}
}

func TestAuditHidesCredID(t *testing.T) {
	r := New()
	id := []byte("abc")
	c := idCommit(id)
	must(t, r.Add(&Record{CredID: id, IDCommitment: c, PolicyVer: 3}))
	rec, err := r.Audit(c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.PolicyVer != 3 || rec.Revoked {
		t.Fatalf("audit record wrong: %+v", rec)
	}
	if len(rec.CredID) != 0 {
		t.Fatal("audit view must not expose the raw credential id")
	}
	if _, err := r.Audit([32]byte{}); cerr.KindOf(err) != cerr.KindUnknownCredential {
		t.Fatalf("got %v", err)
	}
}

func TestBlindedTagStable(t *testing.T) {
	a := BlindedTag([]byte("id"), []byte("ch"))
	b := BlindedTag([]byte("id"), []byte("ch"))
	if !bytes.Equal(a[:], b[:]) {
		t.Fatal("tag must be deterministic for same id and challenge")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
