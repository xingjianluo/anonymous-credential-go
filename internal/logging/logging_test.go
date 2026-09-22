package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestLogIncludesSessionAndFields(t *testing.T) {
	var buf bytes.Buffer
	l := NewWithWriter(&buf)
	l.Log("sess-1", map[string]string{"disclosed": "age,country", "decision": "accept", "basis": "sig"}, "ok then")
	out := buf.String()
	for _, want := range []string{"session=sess-1", "disclosed=age,country", "decision=accept", "basis=sig", "ok then"} {
		if !strings.Contains(out, want) {
			t.Fatalf("log missing %q: %s", want, out)
		}
	}
}

func TestLogQuotesValuesWithSpaces(t *testing.T) {
	var buf bytes.Buffer
	NewWithWriter(&buf).Log("s", map[string]string{"reason": "bad thing happened"}, "m")
	out := buf.String()
	if !strings.Contains(out, "reason=\"bad thing happened\"") {
		t.Fatalf("expected quoted value: %s", out)
	}
}

func TestSessionHelperNilSafe(t *testing.T) {
	Session{Logger: nil, SessionID: "x"}.Log(map[string]string{"a": "b"}, "should not panic")
}
