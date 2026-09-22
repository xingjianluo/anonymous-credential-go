package sys

import (
	"testing"
	"time"
)

func TestSeededRandomDeterministic(t *testing.T) {
	a := NewSeededRandom(42)
	b := NewSeededRandom(42)
	ba := make([]byte, 64)
	bb := make([]byte, 64)
	if _, err := a.Read(ba); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(bb); err != nil {
		t.Fatal(err)
	}
	if string(ba) != string(bb) {
		t.Fatal("same seed must produce same stream")
	}
	c := NewSeededRandom(43)
	bc := make([]byte, 64)
	_, _ = c.Read(bc)
	if string(ba) == string(bc) {
		t.Fatal("different seeds must produce different streams")
	}
}

func TestSeededRandomFullFill(t *testing.T) {
	r := NewSeededRandom(1)
	p := make([]byte, 100)
	n, err := r.Read(p)
	if err != nil || n != 100 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestStepClockAdvance(t *testing.T) {
	base := time.Unix(1000, 0).UTC()
	c := NewStepClock(base)
	if !c.Now().Equal(base) {
		t.Fatal("bad start")
	}
	c.Advance(5 * time.Second)
	if !c.Now().Equal(base.Add(5 * time.Second)) {
		t.Fatal("advance failed")
	}
}

func TestFixedClock(t *testing.T) {
	tm := time.Unix(42, 0)
	if !(FixedClock{T: tm}).Now().Equal(tm.UTC()) {
		t.Fatal("fixed clock mismatch")
	}
}
