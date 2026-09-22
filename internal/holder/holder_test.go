package holder_test

import (
	"testing"
	"time"

	"github.com/xingjianluo/anonymous-credential-go/internal/commitment"
	"github.com/xingjianluo/anonymous-credential-go/internal/credential"
	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
	"github.com/xingjianluo/anonymous-credential-go/internal/holder"
	"github.com/xingjianluo/anonymous-credential-go/internal/policy"
	"github.com/xingjianluo/anonymous-credential-go/internal/sys"
)

// 手工构造一个直接签名承诺根的凭证包，测试 holder 不依赖 issuer。
func manualBundle(t *testing.T, pv uint32, root [32]byte) *credential.Bundle {
	t.Helper()
	key, err := credential.GenerateKey(sys.NewSeededRandom(11))
	if err != nil {
		t.Fatal(err)
	}
	cred, err := credential.Sign(key, &credential.Body{
		PolicyVersion: pv, CommitRoot: root, IssuedAt: time.Unix(100, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	id := []byte("manual-id")
	return &credential.Bundle{
		Credential:    cred,
		ID:            id,
		IDCommitment:  credential.IDCommit(id),
		PolicyVersion: pv,
	}
}

func TestPresentRejectsUnknownVersion(t *testing.T) {
	polreg := policy.NewRegistry()
	_ = polreg.Register(&policy.Policy{Name: "p", Version: 1, Attrs: map[string]*policy.AttrSpec{
		"a": {Name: "a", Type: policy.AttrInt, Disclosable: true},
	}})
	w := holder.NewWallet("h")
	w.Add(manualBundle(t, 1, [32]byte{}))
	_, err := w.Present(polreg, &holder.PresentationRequest{
		SessionID: "s", Challenge: []byte("c"), PolicyVersion: 9, Disclose: []string{"a"},
	})
	if cerr.KindOf(err) != cerr.KindUnknownPolicyVersion {
		t.Fatalf("got %v", err)
	}
}

func TestPresentRejectsEmptyChallenge(t *testing.T) {
	polreg := policy.NewRegistry()
	w := holder.NewWallet("h")
	_, err := w.Present(polreg, &holder.PresentationRequest{PolicyVersion: 1})
	if cerr.KindOf(err) != cerr.KindMalformed {
		t.Fatalf("got %v", err)
	}
}

func TestPresentationExcludesUndisclosed(t *testing.T) {
	// 用真实 commitment 结构构造可验证的包。
	names := []string{"a", "secret"}
	salt := []byte("01234567890123456789012345678901")
	tree, err := commitment.Build(names, []commitment.SaltedAttr{
		{Name: "a", Value: int64(7), Salt: salt},
		{Name: "secret", Value: "shh", Salt: salt},
	})
	if err != nil {
		t.Fatal(err)
	}
	polreg := policy.NewRegistry()
	_ = polreg.Register(&policy.Policy{Name: "p", Version: 1, Attrs: map[string]*policy.AttrSpec{
		"a":      {Name: "a", Type: policy.AttrInt, Disclosable: true, Min: 0, Max: 100},
		"secret": {Name: "secret", Type: policy.AttrString, Disclosable: false},
	}})
	key, _ := credential.GenerateKey(sys.NewSeededRandom(12))
	cred, err := credential.Sign(key, &credential.Body{
		PolicyVersion: 1, CommitRoot: tree.Root(), SchemaHash: polregMustGet(t, polreg, 1).SchemaHash(),
		IssuedAt: time.Unix(100, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	b := &credential.Bundle{
		Credential: cred, ID: []byte("id"), IDCommitment: credential.IDCommit([]byte("id")),
		PolicyVersion: 1, SpecNames: names,
		Salts: map[string][]byte{"a": salt, "secret": salt},
		Attrs: map[string]any{"a": int64(7), "secret": "shh"},
	}
	w := holder.NewWallet("h")
	w.Add(b)
	p, err := w.Present(polreg, &holder.PresentationRequest{
		SessionID: "s", Challenge: []byte("ch"), PolicyVersion: 1, Disclose: []string{"a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Reveals) != 1 {
		t.Fatalf("expected exactly one reveal, got %d", len(p.Reveals))
	}
	if _, ok := p.Reveals["secret"]; ok {
		t.Fatal("secret must not appear in presentation")
	}
	if p.BlindedRevID == ([32]byte{}) {
		t.Fatal("blinded revocation id must be populated")
	}
	if p.Nullifier == ([32]byte{}) {
		t.Fatal("nullifier must be populated")
	}
}

func polregMustGet(t *testing.T, r *policy.Registry, v uint32) *policy.Policy {
	t.Helper()
	p, err := r.Get(v)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
