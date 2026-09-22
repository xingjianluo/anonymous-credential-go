package errors

import (
	"errors"
	"strings"
	"testing"
)

func TestNewAndKindOf(t *testing.T) {
	err := New(KindReplay, "bad thing %d", 1)
	if KindOf(err) != KindReplay {
		t.Fatal("kind mismatch")
	}
	if !strings.Contains(err.Error(), "replay") || !strings.Contains(err.Error(), "bad thing 1") {
		t.Fatalf("error text wrong: %v", err)
	}
	if KindOf(nil) != KindUnknown {
		t.Fatal("nil should map to unknown")
	}
	if KindOf(errors.New("plain")) != KindUnknown {
		t.Fatal("plain error should map to unknown")
	}
}

func TestWrapPreservesKind(t *testing.T) {
	base := New(KindCredentialRevoked, "revoked")
	w := Wrap(base, "during verify")
	if KindOf(w) != KindCredentialRevoked {
		t.Fatal("wrap must preserve kind")
	}
	if !strings.Contains(w.Error(), "during verify") {
		t.Fatalf("wrap text wrong: %v", w)
	}
	if Wrap(nil, "x") != nil {
		t.Fatal("wrapping nil must be nil")
	}
}

func TestKindStrings(t *testing.T) {
	if KindProofTampered.String() != "proof_tampered" {
		t.Fatalf("got %s", KindProofTampered.String())
	}
}
