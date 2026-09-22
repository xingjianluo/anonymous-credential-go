package credential

import (
	"testing"
	"time"

	cerr "github.com/xingjianluo/anonymous-credential-go/internal/errors"
	"github.com/xingjianluo/anonymous-credential-go/internal/sys"
)

func TestSignVerifyAndTamper(t *testing.T) {
	key, err := GenerateKey(sys.NewSeededRandom(7))
	if err != nil {
		t.Fatal(err)
	}
	body := &Body{PolicyVersion: 1, IssuedAt: time.Unix(1000, 0).UTC()}
	body.CommitRoot[0] = 9
	body.SchemaHash[1] = 8
	cred, err := Sign(key, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(key.Public, cred); err != nil {
		t.Fatal(err)
	}
	// 篡改主体。
	tampered := *cred
	tampered.Body.PolicyVersion = 2
	if err := Verify(key.Public, &tampered); cerr.KindOf(err) != cerr.KindProofTampered {
		t.Fatalf("body tamper: got %v", err)
	}
	// 篡改签名。
	tampered2 := *cred
	tampered2.Signature[0] ^= 1
	if err := Verify(key.Public, &tampered2); cerr.KindOf(err) != cerr.KindProofTampered {
		t.Fatalf("sig tamper: got %v", err)
	}
	// 外来公钥验签失败。
	key2, _ := GenerateKey(sys.NewSeededRandom(8))
	if err := Verify(key2.Public, cred); cerr.KindOf(err) != cerr.KindProofTampered {
		t.Fatalf("foreign key: got %v", err)
	}
}

func TestBodyBytesDeterministic(t *testing.T) {
	b := &Body{PolicyVersion: 1, IssuedAt: time.Unix(123, 0).UTC()}
	if string(BodyBytes(b)) != string(BodyBytes(b)) {
		t.Fatal("body encoding must be deterministic")
	}
	b2 := &Body{PolicyVersion: 2, IssuedAt: time.Unix(123, 0).UTC()}
	if string(BodyBytes(b)) == string(BodyBytes(b2)) {
		t.Fatal("different versions must encode differently")
	}
}

func TestIDCommitBinding(t *testing.T) {
	a := IDCommit([]byte("id-1"))
	b := IDCommit([]byte("id-2"))
	if a == b {
		t.Fatal("distinct ids must have distinct commitments")
	}
	if a != IDCommit([]byte("id-1")) {
		t.Fatal("id commitment must be deterministic")
	}
}
