package transports

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestTransports_Plain asserts that the default (no --json) output is exactly
// the contract documented in the task: one transport name per line, sorted,
// lower-case. The shipped build has the single syn-tfo transport.
func TestTransports_Plain(t *testing.T) {
	var buf bytes.Buffer
	if err := runTransports(&buf, false); err != nil {
		t.Fatalf("runTransports returned error: %v", err)
	}

	got := buf.String()
	want := "syn-tfo\n"
	if got != want {
		t.Fatalf("plain output mismatch:\n got = %q\nwant = %q", got, want)
	}
}

// TestTransports_JSON asserts that --json mode emits a JSON array of strings
// that contains "syn-tfo". The test is intentionally not fussy about
// whitespace or trailing newlines — it parses the output with encoding/json
// and inspects the resulting slice, which is the contract callers actually
// care about.
func TestTransports_JSON(t *testing.T) {
	var buf bytes.Buffer
	if err := runTransports(&buf, true); err != nil {
		t.Fatalf("runTransports returned error: %v", err)
	}

	var names []string
	if err := json.Unmarshal(buf.Bytes(), &names); err != nil {
		t.Fatalf("output is not a valid JSON array of strings: %v\nraw: %q", err, buf.String())
	}

	found := false
	for _, n := range names {
		if n == "syn-tfo" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected JSON array to contain \"syn-tfo\"; got %v", names)
	}
}
