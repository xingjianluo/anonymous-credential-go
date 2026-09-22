package commitment

import "testing"

func names() []string { return []string{"age", "country", "level", "ssn"} }

func attrs(salt []byte) []SaltedAttr {
	return []SaltedAttr{
		{Name: "age", Value: int64(30), Salt: salt},
		{Name: "country", Value: "CN", Salt: salt},
		{Name: "level", Value: "premium", Salt: salt},
		{Name: "ssn", Missing: true},
	}
}

func TestBuildOpenVerify(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	tr, err := Build(names(), attrs(salt))
	if err != nil {
		t.Fatal(err)
	}
	root := tr.Root()
	total := len(names())
	for _, n := range []string{"age", "country", "level"} {
		rv, err := tr.Open(n)
		if err != nil {
			t.Fatalf("open %s: %v", n, err)
		}
		if err := Verify(root, total, rv); err != nil {
			t.Fatalf("verify %s: %v", n, err)
		}
	}
	if !tr.IsMissing("ssn") {
		t.Fatal("ssn should be missing")
	}
	rv, err := tr.Open("ssn")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(root, total, rv); err != nil {
		t.Fatalf("verify missing leaf: %v", err)
	}
}

func TestTamperedValueFails(t *testing.T) {
	salt := make([]byte, 32)
	tr, _ := Build(names(), attrs(salt))
	root := tr.Root()
	rv, _ := tr.Open("age")
	rv.Value = int64(31)
	if err := Verify(root, len(names()), rv); err == nil {
		t.Fatal("tampered value must fail")
	}
}

func TestWrongRootFails(t *testing.T) {
	salt := make([]byte, 32)
	tr, _ := Build(names(), attrs(salt))
	rv, _ := tr.Open("age")
	var wrong [32]byte
	wrong[0] = 1
	if err := Verify(wrong, len(names()), rv); err == nil {
		t.Fatal("proof against wrong root must fail")
	}
}

func TestSaltChangesRoot(t *testing.T) {
	s1 := make([]byte, 32)
	s2 := make([]byte, 32)
	s2[0] = 1
	t1, _ := Build(names(), attrs(s1))
	t2, _ := Build(names(), attrs(s2))
	if t1.Root() == t2.Root() {
		t.Fatal("different salts must yield different roots")
	}
}

func TestDepthSpoofingFails(t *testing.T) {
	salt := make([]byte, 32)
	tr, _ := Build(names(), attrs(salt))
	rv, _ := tr.Open("age")
	// 截断兄弟路径。
	rv.Siblings = rv.Siblings[:len(rv.Siblings)-1]
	if err := Verify(tr.Root(), len(names()), rv); err == nil {
		t.Fatal("shortened path must fail depth check")
	}
	// 位置越界。r2
	rv2, _ := tr.Open("age")
	rv2.Position = 99
	if err := Verify(tr.Root(), len(names()), rv2); err == nil {
		t.Fatal("out-of-range position must fail")
	}
}

func TestMissingLeafCarriesNoPlaintext(t *testing.T) {
	salt := make([]byte, 32)
	tr, _ := Build(names(), attrs(salt))
	rv, _ := tr.Open("ssn")
	if rv.Value != nil || len(rv.Salt) != 0 || !rv.Missing {
		t.Fatal("missing reveal must be empty")
	}
	rv.Missing = false
	if err := Verify(tr.Root(), len(names()), rv); err == nil {
		t.Fatal("forged non-missing flag must fail")
	}
}
